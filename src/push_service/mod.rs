use std::{io::Write as _, rc::Rc, sync::LazyLock, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    prelude::ServiceConfiguration,
    transport::{
        HttpBody, HttpRequest, HttpResponse, Transport, TransportError,
        TransportErrorKind,
    },
    utils::serde_device_id_vec,
    websocket::{SignalWebSocket, WebSocketType},
};

use base64::{prelude::BASE64_STANDARD, write::EncoderStringWriter};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Method,
};
use libsignal_core::DeviceId;
use reqwest_websocket::Upgrade;
use serde::{Deserialize, Serialize};
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub static DEFAULT_DEVICE_ID: LazyLock<libsignal_core::DeviceId> =
    LazyLock::new(|| libsignal_core::DeviceId::try_from(1).unwrap());

mod account;
mod cdn;
mod error;
pub mod linking;
mod multipart;
pub(crate) mod response;
#[cfg(test)]
mod tests;

pub use account::*;
pub use cdn::*;
pub use error::*;
pub(crate) use response::SignalServiceResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuth {
    pub username: String,
    #[debug(ignore)]
    pub password: String,
}

impl HttpAuth {
    /// The `Authorization` value for basic authentication, marked sensitive.
    fn header_value(&self) -> HeaderValue {
        let mut value = EncoderStringWriter::from_consumer(
            String::from("Basic "),
            &BASE64_STANDARD,
        );
        write!(value, "{}:{}", self.username, self.password)
            .expect("writing to a String");
        let mut value = HeaderValue::try_from(value.into_inner())
            .expect("base64 is a valid header value");
        value.set_sensitive(true);
        value
    }
}

#[derive(Debug, Clone)]
pub enum HttpAuthOverride {
    NoOverride,
    Unidentified,
    Identified(HttpAuth),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AvatarWrite<C> {
    NewAvatar(C),
    RetainAvatar,
    NoAvatar,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    #[serde(with = "serde_device_id_vec")]
    pub missing_devices: Vec<DeviceId>,
    #[serde(with = "serde_device_id_vec")]
    pub extra_devices: Vec<DeviceId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    #[serde(with = "serde_device_id_vec")]
    pub stale_devices: Vec<DeviceId>,
}

#[derive(Clone)]
pub struct PushService {
    cfg: ServiceConfiguration,
    /// The account's `Authorization` value, built once and marked sensitive.
    authorization: Option<HeaderValue>,
    transport: Rc<dyn Transport>,
}

impl PushService {
    pub fn new(
        cfg: ServiceConfiguration,
        credentials: Option<ServiceCredentials>,
        transport: Rc<dyn Transport>,
    ) -> Self {
        Self {
            cfg,
            authorization: credentials
                .and_then(|c| c.authorization())
                .map(|auth| auth.header_value()),
            transport,
        }
    }

    #[tracing::instrument(skip(self), fields(endpoint = %endpoint))]
    pub fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder<'_>, ServiceError> {
        let kind = endpoint.kind();
        let url = endpoint.into_url(&self.cfg)?;

        let authorization = match &auth_override {
            HttpAuthOverride::NoOverride => self.authorization.clone(),
            HttpAuthOverride::Identified(auth) => Some(auth.header_value()),
            HttpAuthOverride::Unidentified => None,
        };
        let mut headers = HeaderMap::new();
        if let Some(authorization) = authorization {
            headers.insert(AUTHORIZATION, authorization);
        }

        Ok(RequestBuilder {
            transport: &*self.transport,
            request: Ok(HttpRequest {
                method,
                url,
                headers,
                body: HttpBody::Empty,
                endpoint: kind,
                timeout: None,
            }),
        })
    }

    pub async fn ws<C: WebSocketType>(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket<C>, ServiceError> {
        let span = debug_span!("websocket");

        let mut url = Endpoint::service(path).into_url(&self.cfg)?;
        url.set_scheme("wss").expect("valid https base url");

        // The WebSocket still connects through reqwest, trusting the
        // configuration's certificate authority, until it moves onto
        // `Transport::websocket`.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let client = reqwest::Certificate::from_pem(
            self.cfg.certificate_authority.as_bytes(),
        )
        .and_then(|root| {
            reqwest::ClientBuilder::new()
                .tls_certs_only([root])
                .connect_timeout(Duration::from_secs(10))
                .read_timeout(Duration::from_secs(65))
                .user_agent(crate::USER_AGENT)
                .http1_only()
                .build()
        })
        .map_err(|e| TransportError::new(TransportErrorKind::Other, e))?;

        let mut builder = client.get(url);
        for (key, value) in additional_headers {
            builder = builder.header(*key, *value);
        }

        if let Some(credentials) = credentials {
            builder =
                builder.basic_auth(credentials.login(), credentials.password);
        }

        let ws = builder
            .upgrade()
            .send()
            .await?
            .into_websocket()
            .instrument(span.clone())
            .await?;

        let unidentified_push_service = PushService {
            cfg: self.cfg.clone(),
            authorization: None,
            transport: self.transport.clone(),
        };
        let (ws, task) = SignalWebSocket::new(
            ws,
            keepalive_path.to_owned(),
            unidentified_push_service,
        );
        let task = task.instrument(span);
        tokio::task::spawn(task);
        Ok(ws)
    }

    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::storage("/v1/groups/"),
            HttpAuthOverride::Identified(credentials),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .protobuf()
        .await
    }
}

impl From<reqwest_websocket::Error> for ServiceError {
    fn from(error: reqwest_websocket::Error) -> Self {
        TransportError::new(TransportErrorKind::Other, error).into()
    }
}

/// A request to a Signal service, sent through the [`Transport`].
#[must_use = "a request does nothing until it is sent"]
pub struct RequestBuilder<'a> {
    transport: &'a dyn Transport,
    request: Result<HttpRequest, ServiceError>,
}

impl RequestBuilder<'_> {
    /// Adds a header; an invalid name or value fails [`send`](Self::send). An
    /// `Authorization` value is marked sensitive.
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        if let Ok(request) = &mut self.request {
            let header = HeaderName::try_from(name)
                .map_err(Into::into)
                .and_then(|name| {
                    Ok((
                        name,
                        HeaderValue::try_from(value).map_err(Into::into)?,
                    ))
                });
            match header {
                Ok((name, mut value)) => {
                    if name == AUTHORIZATION {
                        value.set_sensitive(true);
                    }
                    request.headers.append(name, value);
                },
                Err(error) => {
                    self.request = Err(ServiceError::InvalidHeader(error))
                },
            }
        }
        self
    }

    /// Sets a JSON body and, unless one is set,
    /// `Content-Type: application/json`.
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        if let Ok(request) = &mut self.request {
            match serde_json::to_vec(value) {
                Ok(body) => {
                    request.headers.entry(CONTENT_TYPE).or_insert(
                        HeaderValue::from_static("application/json"),
                    );
                    request.body = body.into();
                },
                Err(error) => self.request = Err(error.into()),
            }
        }
        self
    }

    pub fn body(mut self, body: impl Into<HttpBody>) -> Self {
        if let Ok(request) = &mut self.request {
            request.body = body.into();
        }
        self
    }

    /// Sets how long the transport waits for the response head once the
    /// request is sent ([`HttpRequest::timeout`]), for a request the server
    /// holds, such as a long poll.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if let Ok(request) = &mut self.request {
            request.timeout = Some(timeout);
        }
        self
    }

    pub async fn send(self) -> Result<HttpResponse, ServiceError> {
        Ok(self.transport.request(self.request?).await?)
    }
}
