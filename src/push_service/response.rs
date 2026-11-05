use std::{error::Error, future::Future, time::Duration};

use bytes::{Bytes, BytesMut};
use futures::TryStreamExt;
use http::StatusCode;
use serde::de::DeserializeOwned;

use crate::{
    proto::WebSocketResponseMessage,
    transport::{HttpResponse, TransportError},
};

use super::{ServiceError, ERROR_BODY_LIMIT};

pub(crate) async fn json_or_unhandled<R, T>(
    response: R,
) -> Result<T, ServiceError>
where
    T: DeserializeOwned,
    R: SignalServiceResponse,
{
    let status = response.status_code();
    let body = response.text().await?;
    serde_json::from_str(&body).map_err(move |error| {
        tracing::error!(%error, "JSON decoding in error handling failed; returning UnhandledResponseCode");
        ServiceError::UnhandledResponseCode { status, body }
    })
}

/// A `Retry-After` value as the wait it asks for: `delay-seconds`, a decimal
/// integer of seconds, the form Signal's services send (RFC 9110 §10.2.3).
/// Surrounding spaces and tabs are ignored; anything else, a sign, a fraction
/// or an HTTP-date, is `None`. A delay past `u64::MAX` seconds saturates, as
/// RFC 9111 §1.2.2 asks of an unrepresentable delta, so parsing can't panic
/// on any value a server sends; the caller caps a wait where it applies it,
/// since one this long overflows an `Instant`.
pub(crate) fn parse_retry_after(header: &str) -> Option<Duration> {
    let value = header.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        tracing::warn!(value, "could not parse rate limit duration");
        return None;
    }
    // The digits leave overflow as the one error `parse` can still return.
    Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
}

/// Baseline HTTP→[`ServiceError`] mapping for responses that do not need
/// endpoint-specific decoding.
async fn baseline_decode<R>(response: R) -> Result<R, ServiceError>
where
    R: SignalServiceResponse,
{
    match response.status_code() {
        StatusCode::OK
        | StatusCode::CREATED
        | StatusCode::ACCEPTED
        | StatusCode::NO_CONTENT => Ok(response),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(ServiceError::Unauthorized)
        },
        StatusCode::NOT_FOUND => Err(ServiceError::NotFoundError),
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::TOO_MANY_REQUESTS => {
            Err(ServiceError::RateLimitExceeded {
                retry_after: response
                    .header("retry-after")
                    .and_then(parse_retry_after),
            })
        },
        StatusCode::LOCKED => {
            let locked = json_or_unhandled(response).await?;
            Err(ServiceError::Locked(locked))
        },
        // Signal uses non-standard 499 (deprecated client version) and 508
        // (request rejected); no StatusCode constants exist for these.
        code if code.as_u16() == 499 => Err(ServiceError::DeprecatedVersion),
        code if code.as_u16() == 508 => Err(ServiceError::ServerRejected),
        code => {
            let body = response.error_body().await;
            tracing::debug!(status_code = %code, %body, "unhandled HTTP response");
            Err(ServiceError::UnhandledResponseCode { status: code, body })
        },
    }
}

/// Endpoint-specific HTTP error decoder.
///
/// Generate an async decode function from status → variant arms:
/// - `CODE => Variant(Type)` — decode JSON body via [`json_or_unhandled`].
/// - `CODE => Variant` — unit variant, body discarded.
/// - `CODE => fn helper` — call a helper returning the
///   [`ServiceError`].
///
/// `CODE` is an `http::StatusCode` constant name, or a raw status code
/// like `440` when no dedicated constant exists.
///
/// Unlisted statuses return `Ok(response)` and fall through to
/// [`baseline_decode`]; the result is passed on by
/// [`SignalServiceResponse::service_error_for_status_with`].
macro_rules! error_mapper {
    // tt-muncher: accumulate `pattern => body` arms, then emit one match.
    (@munch $response:ident; [$($out:tt)*] ;) => {
        match $response.status_code() {
            $($out)*
            _ => Ok($response),
        }
    };
    // Named `StatusCode` constants become path patterns…
    (@munch $response:ident; [$($out:tt)*] ; $status:ident => $($rest:tt)*) => {
        error_mapper!(@action $response; [$($out)*] ;
            [http::StatusCode::$status] $($rest)*)
    };
    // …raw codes that have no dedicated `StatusCode` constant (`440 => …`)
    // become guards.
    (@munch $response:ident; [$($out:tt)*] ; $status:literal => $($rest:tt)*) => {
        error_mapper!(@action $response; [$($out)*] ;
            [code if code.as_u16() == $status] $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] fn $helper:path, $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($helper($response).await),] ;
            $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] $variant:ident ( $ty:ty ), $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($crate::push_service::ServiceError::$variant(
                $crate::push_service::response::json_or_unhandled::<R, $ty>($response).await?,
            )),] ;
            $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] $variant:ident, $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($crate::push_service::ServiceError::$variant),] ;
            $($rest)*)
    };
    (
        $( #[$m:meta] )*
        $name:ident: $($arms:tt)*
    ) => {
        $( #[$m] )*
        pub(crate) async fn $name<R>(
            response: R,
        ) -> Result<R, $crate::push_service::ServiceError>
        where
            R: $crate::push_service::response::SignalServiceResponse,
        {
            error_mapper!(@munch response; [] ; $($arms)*)
        }
    };
}

pub(crate) use error_mapper;

pub(crate) async fn device_limit_reached<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
{
    #[derive(Debug, serde::Deserialize)]
    struct LinkedDeviceNumberError {
        current: u32,
        max: u32,
    }
    match json_or_unhandled::<R, LinkedDeviceNumberError>(response).await {
        Ok(error) => ServiceError::DeviceLimitReached {
            current: error.current,
            max: error.max,
        },
        Err(error) => error,
    }
}

/// A response from the chat service, over HTTP or the WebSocket.
pub(crate) trait SignalServiceResponse: Sized {
    fn status_code(&self) -> StatusCode;

    fn header(&self, name: &str) -> Option<&str>;

    async fn json<U: DeserializeOwned>(self) -> Result<U, ServiceError>;

    async fn text(self) -> Result<String, ServiceError>;

    /// At most [`ERROR_BODY_LIMIT`] bytes of the body, for a response whose
    /// status alone is the error. A body that breaks off ends early instead
    /// of failing, so the status stays the error.
    async fn error_body(self) -> String;

    /// Baseline error handling only (specialised codes fall through to
    /// [`UnhandledResponseCode`][ServiceError::UnhandledResponseCode]).
    async fn service_error_for_status(self) -> Result<Self, ServiceError> {
        baseline_decode(self).await
    }

    /// Error handling specialised by a decode function over the response;
    /// every code `decode` does not own falls through to the baseline.
    /// Decoders are typically generated with [`error_mapper!`].
    async fn service_error_for_status_with<F, Fut>(
        self,
        decode: F,
    ) -> Result<Self, ServiceError>
    where
        F: FnOnce(Self) -> Fut,
        Fut: Future<Output = Result<Self, ServiceError>>,
    {
        baseline_decode(decode(self).await?).await
    }
}

impl SignalServiceResponse for HttpResponse {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| {
            v.to_str()
                .inspect_err(|e| {
                    tracing::warn!(?e, "could not read header as string")
                })
                .ok()
        })
    }

    async fn json<U: DeserializeOwned>(self) -> Result<U, ServiceError> {
        Ok(serde_json::from_slice(&self.bytes().await?)?)
    }

    async fn text(self) -> Result<String, ServiceError> {
        Ok(String::from_utf8_lossy(&self.bytes().await?).into_owned())
    }

    async fn error_body(mut self) -> String {
        let mut body = Vec::new();
        while body.len() < ERROR_BODY_LIMIT {
            match self.body.try_next().await {
                Ok(Some(chunk)) => {
                    let take = chunk.len().min(ERROR_BODY_LIMIT - body.len());
                    body.extend_from_slice(&chunk[..take]);
                },
                Ok(None) => break,
                Err(error) => {
                    tracing::debug!(
                        status = %self.status,
                        error = &error as &dyn Error,
                        "error response body broke off"
                    );
                    break;
                },
            }
        }
        String::from_utf8_lossy(&body).into_owned()
    }
}

impl HttpResponse {
    /// The whole body.
    pub(crate) async fn bytes(mut self) -> Result<Bytes, TransportError> {
        let Some(first) = self.body.try_next().await? else {
            return Ok(Bytes::new());
        };
        let Some(second) = self.body.try_next().await? else {
            return Ok(first);
        };
        let mut body = BytesMut::with_capacity(first.len() + second.len());
        body.extend_from_slice(&first);
        body.extend_from_slice(&second);
        while let Some(chunk) = self.body.try_next().await? {
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }

    pub(crate) async fn protobuf<T: prost::Message + Default>(
        self,
    ) -> Result<T, ServiceError> {
        Ok(T::decode(self.bytes().await?)?)
    }

    /// Fails on a 4xx or 5xx status, for services whose codes carry no
    /// Signal meaning, such as the CDNs ([`status_error`](Self::status_error)).
    pub(crate) async fn error_for_status(self) -> Result<Self, ServiceError> {
        if self.status.is_client_error() || self.status.is_server_error() {
            return Err(self.status_error().await);
        }
        Ok(self)
    }

    /// The error of a status from such a service. A 429 is HTTP's own rate
    /// limit (RFC 6585 §4), with its `Retry-After`. Any other status is the
    /// error itself, a 413 too, which is a rate limit only on Signal's chat
    /// service; the start of the body rides along (see
    /// [`error_body`](SignalServiceResponse::error_body)).
    pub(crate) async fn status_error(self) -> ServiceError {
        match self.status {
            StatusCode::TOO_MANY_REQUESTS => ServiceError::RateLimitExceeded {
                retry_after: self
                    .header("retry-after")
                    .and_then(parse_retry_after),
            },
            status => ServiceError::UnhandledResponseCode {
                status,
                body: self.error_body().await,
            },
        }
    }
}

impl SignalServiceResponse for WebSocketResponseMessage {
    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status() as u16).unwrap_or_default()
    }

    async fn json<U: DeserializeOwned>(self) -> Result<U, ServiceError> {
        serde_json::from_slice(self.body()).map_err(Into::into)
    }

    async fn text(self) -> Result<String, ServiceError> {
        Ok(self
            .body
            .map(|body| String::from_utf8_lossy(&body).to_string())
            .unwrap_or_default())
    }

    async fn error_body(self) -> String {
        let body = self.body();
        String::from_utf8_lossy(&body[..body.len().min(ERROR_BODY_LIMIT)])
            .into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        let (_header, value) = self
            .headers
            .iter()
            .filter_map(|hdr| hdr.split_once(":"))
            .find(|(header, _body)| header.trim().eq_ignore_ascii_case(name))?;
        Some(value.trim())
    }
}
