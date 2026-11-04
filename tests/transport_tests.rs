//! lss's HTTP requests and their outcomes, seen through an in-memory
//! [`Transport`].

use std::{
    cell::RefCell, collections::HashMap, collections::VecDeque, error::Error,
    fmt, io, rc::Rc, time::Duration,
};

use base64::prelude::*;
use bytes::Bytes;
use futures::{
    future::LocalBoxFuture, stream, AsyncReadExt as _, StreamExt as _,
    TryStreamExt as _,
};
use http::{header, HeaderMap, Method, StatusCode};
use libsignal_service::{
    configuration::{
        Endpoint, ServiceConfiguration, ServiceCredentials, ServiceUrls,
    },
    master_key::StorageServiceKey,
    prelude::{AttachmentIdentifier, AttachmentPointer, ProtobufMessage},
    proto::{ManifestRecord, ReadOperation, StorageItems, StorageRecord},
    protocol::{DeviceId, KeyPair},
    provisioning::ProvisioningError,
    push_service::{
        linking::{
            LinkAccountAttributes, LinkCapabilities, LinkRequest, LinkResponse,
        },
        AttachmentV2UploadAttributes, HttpAuth, HttpAuthOverride, PushService,
        ServiceError, ERROR_BODY_LIMIT,
    },
    sender::{AttachmentUploadError, MessageSenderError},
    transport::{
        EndpointKind, HttpBody, HttpRequest, HttpResponse, Transport,
        TransportError, TransportErrorKind, WsConnect, WsUpgrade,
    },
    websocket::registration::DeviceActivationRequest,
    zkgroup::ServerSecretParams,
    ProfileManagerError, StorageService, StorageServiceError,
};
use uuid::Uuid;

const ACI: Uuid = Uuid::from_u128(0x0a0b_0c0d_0e0f_4a1b_8c2d_3e4f_5a6b_7c8d);

/// What the transport received.
struct Seen {
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Vec<u8>,
    endpoint: EndpointKind,
    timeout: Option<Duration>,
}

impl Seen {
    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

/// A scripted answer to the next request.
enum Answer {
    Response {
        status: StatusCode,
        headers: Vec<(&'static str, String)>,
        body: Vec<Result<Bytes, TransportErrorKind>>,
    },
    Fail(TransportErrorKind),
}

impl Answer {
    fn status(status: u16) -> Self {
        Self::body(status, Vec::new())
    }

    fn body(status: u16, body: impl Into<Bytes>) -> Self {
        Self::chunks(status, vec![Ok(body.into())])
    }

    /// A body in these chunks; an error breaks it off there.
    fn chunks(
        status: u16,
        body: Vec<Result<Bytes, TransportErrorKind>>,
    ) -> Self {
        Self::Response {
            status: StatusCode::from_u16(status).unwrap(),
            headers: Vec::new(),
            body,
        }
    }

    fn json(status: u16, value: serde_json::Value) -> Self {
        Self::body(status, serde_json::to_vec(&value).unwrap())
            .with_header("content-type", "application/json")
    }

    fn with_header(mut self, name: &'static str, value: &str) -> Self {
        if let Self::Response { headers, .. } = &mut self {
            headers.push((name, value.to_owned()));
        }
        self
    }
}

/// The implementation's own error, which callers must be able to reach.
#[derive(Debug)]
struct FakeNetError;

impl fmt::Display for FakeNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the fake network failed")
    }
}

impl Error for FakeNetError {}

#[derive(Default)]
struct MemoryTransport {
    seen: RefCell<Vec<Seen>>,
    answers: RefCell<VecDeque<Answer>>,
}

impl MemoryTransport {
    fn answer(&self, answer: Answer) {
        self.answers.borrow_mut().push_back(answer);
    }

    fn take_seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.borrow_mut())
    }

    fn take_one(&self) -> Seen {
        let mut seen = self.take_seen();
        assert_eq!(seen.len(), 1, "exactly one request");
        seen.pop().unwrap()
    }
}

impl Transport for MemoryTransport {
    fn request(
        &self,
        request: HttpRequest,
    ) -> LocalBoxFuture<'_, Result<HttpResponse, TransportError>> {
        assert!(
            !request.headers.contains_key(header::CONTENT_LENGTH),
            "framing is the transport's"
        );
        Box::pin(async move {
            let body = match request.body {
                HttpBody::Empty => Vec::new(),
                HttpBody::Bytes(bytes) => bytes.to_vec(),
                HttpBody::Stream { len, stream } => {
                    let body: Vec<u8> = stream
                        .map_ok(|chunk| chunk.to_vec())
                        .try_concat()
                        .await
                        .unwrap();
                    assert_eq!(body.len() as u64, len, "declared length");
                    body
                },
            };
            self.seen.borrow_mut().push(Seen {
                method: request.method,
                url: request.url.to_string(),
                headers: request.headers,
                body,
                endpoint: request.endpoint,
                timeout: request.timeout,
            });
            let answer =
                self.answers.borrow_mut().pop_front().expect("an answer");
            match answer {
                Answer::Fail(kind) => {
                    Err(TransportError::new(kind, FakeNetError))
                },
                Answer::Response {
                    status,
                    headers,
                    body,
                } => Ok(HttpResponse {
                    status,
                    headers: headers
                        .into_iter()
                        .map(|(name, value)| {
                            (
                                header::HeaderName::from_static(name),
                                value.parse().unwrap(),
                            )
                        })
                        .collect(),
                    body: stream::iter(body.into_iter().map(|chunk| {
                        chunk.map_err(|kind| {
                            TransportError::new(kind, FakeNetError)
                        })
                    }))
                    .boxed_local(),
                }),
            }
        })
    }

    fn websocket(
        &self,
        _: WsConnect,
    ) -> LocalBoxFuture<'_, Result<WsUpgrade, TransportError>> {
        unreachable!("these tests make HTTP requests only")
    }
}

/// A test environment, as a fake server would have one.
fn environment() -> ServiceConfiguration {
    ServiceConfiguration::new(
        ServiceUrls {
            chat: "https://chat.test".parse().unwrap(),
            storage: "https://storage.test".parse().unwrap(),
            cdn: HashMap::from([
                (0, "https://cdn0.test".parse().unwrap()),
                (2, "https://cdn2.test".parse().unwrap()),
                (3, "https://cdn3.test".parse().unwrap()),
            ]),
        },
        vec![KeyPair::generate(&mut rand::rng()).public_key],
        ServerSecretParams::generate([7; 32]).get_public_params(),
    )
}

fn push_service() -> (PushService, Rc<MemoryTransport>) {
    let transport = Rc::new(MemoryTransport::default());
    let credentials = ServiceCredentials {
        aci: Some(ACI),
        pni: None,
        phonenumber: "+15550100".parse().unwrap(),
        password: Some("hunter2".into()),
        device_id: Some(DeviceId::new(2).unwrap()),
    };
    let service =
        PushService::new(environment(), Some(credentials), transport.clone());
    (service, transport)
}

fn basic(credentials: &str) -> String {
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

fn link_request() -> LinkRequest {
    use libsignal_service::pre_keys::{KyberPreKeyEntity, SignedPreKeyEntity};
    let signed = |key_id| SignedPreKeyEntity {
        key_id,
        public_key: vec![5; 33],
        signature: vec![6; 64],
    };
    let kyber = |key_id| KyberPreKeyEntity {
        key_id,
        public_key: vec![7; 1569],
        signature: vec![8; 64],
    };
    LinkRequest {
        verification_code: "code".into(),
        account_attributes: LinkAccountAttributes {
            fetches_messages: true,
            name: "name".into(),
            registration_id: 11,
            pni_registration_id: 12,
            capabilities: LinkCapabilities::default(),
        },
        device_activation_request: DeviceActivationRequest {
            aci_signed_pre_key: signed(1),
            pni_signed_pre_key: signed(2),
            aci_pq_last_resort_pre_key: kyber(3),
            pni_pq_last_resort_pre_key: kyber(4),
        },
    }
}

fn link_auth() -> HttpAuth {
    HttpAuth {
        username: ACI.to_string(),
        password: "link password".into(),
    }
}

#[tokio::test]
async fn push_service_builds_requests_without_reqwest() {
    let (mut service, transport) = push_service();
    let account_auth = basic(&format!("{ACI}.2:hunter2"));

    // Linking: identified with the link credentials, JSON body.
    transport.answer(Answer::json(
        200,
        serde_json::json!({
            "uuid": ACI,
            "pni": Uuid::from_u128(9),
            "deviceId": 3,
        }),
    ));
    let LinkResponse {
        aci,
        pni,
        device_id,
    } = service
        .link_device(&link_request(), link_auth())
        .await
        .unwrap();
    assert_eq!(
        (aci, pni, device_id),
        (ACI, Uuid::from_u128(9), DeviceId::new(3).unwrap())
    );
    let link = transport.take_one();
    assert_eq!(link.method, Method::PUT);
    assert_eq!(link.url, "https://chat.test/v1/devices/link");
    assert_eq!(link.endpoint, EndpointKind::Chat);
    assert_eq!(link.timeout, None, "the transport's default");
    assert_eq!(
        link.header(header::AUTHORIZATION),
        Some(&*basic(&format!("{ACI}:link password")))
    );
    assert!(link.headers[header::AUTHORIZATION].is_sensitive());
    assert_eq!(link.header(header::CONTENT_TYPE), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&link.body).unwrap();
    assert_eq!(body["verificationCode"], "code");
    assert_eq!(body["accountAttributes"]["registrationId"], 11);
    assert_eq!(body["aciSignedPreKey"]["keyId"], 1);
    assert_eq!(body["pniPqLastResortPreKey"]["keyId"], 4);

    // Storage: the account's credentials on chat, the storage service's own
    // on storage, protobuf both ways.
    let key = || StorageServiceKey { inner: [3; 32] };
    transport.answer(Answer::json(
        200,
        serde_json::json!({ "username": "su", "password": "sp" }),
    ));
    let storage = StorageService::new(service.clone(), key()).await.unwrap();
    let auth = transport.take_one();
    assert_eq!(
        (&auth.method, &*auth.url, auth.endpoint),
        (
            &Method::GET,
            "https://chat.test/v1/storage/auth",
            EndpointKind::Chat
        )
    );
    assert_eq!(auth.header(header::AUTHORIZATION), Some(&*account_auth));
    assert!(auth.headers[header::AUTHORIZATION].is_sensitive());

    let record = ManifestRecord {
        version: 42,
        source_device: 1,
        identifiers: vec![],
        record_ikm: vec![],
    };
    let manifest = StorageService::encrypt_manifest(&key(), &record);
    transport.answer(Answer::body(200, manifest.encode_to_vec()));
    assert_eq!(storage.manifest().await.unwrap(), record);
    let fetched = transport.take_one();
    assert_eq!(
        (&fetched.method, &*fetched.url, fetched.endpoint),
        (
            &Method::GET,
            "https://storage.test/v1/storage/manifest",
            EndpointKind::Storage
        )
    );
    assert_eq!(
        fetched.header(header::AUTHORIZATION),
        Some(&*basic("su:sp"))
    );

    transport.answer(Answer::status(204));
    assert_eq!(storage.manifest_if_changed(42).await.unwrap(), None);
    assert_eq!(
        transport.take_one().url,
        "https://storage.test/v1/storage/manifest/version/42"
    );

    let item = StorageService::encrypt_item(
        &key(),
        vec![1; 16],
        &StorageRecord { record: None },
        None,
    );
    let items = StorageItems { items: vec![item] };
    transport.answer(Answer::body(200, items.encode_to_vec()));
    assert_eq!(
        storage.read_items(vec![vec![1; 16]], None).await.unwrap(),
        vec![StorageRecord { record: None }]
    );
    let read = transport.take_one();
    assert_eq!(
        (&read.method, &*read.url, read.endpoint),
        (
            &Method::PUT,
            "https://storage.test/v1/storage/read",
            EndpointKind::Storage
        )
    );
    assert_eq!(
        read.header(header::CONTENT_TYPE),
        Some("application/x-protobuf")
    );
    assert_eq!(
        ReadOperation::decode(&*read.body).unwrap().read_key,
        vec![vec![1; 16]]
    );

    // CDN download: unauthenticated, streamed.
    let content: Vec<u8> = (0..=255).cycle().take(3000).collect();
    transport.answer(Answer::Response {
        status: StatusCode::OK,
        headers: vec![("content-length", content.len().to_string())],
        body: content
            .chunks(1024)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect(),
    });
    let pointer = AttachmentPointer {
        cdn_number: Some(2),
        attachment_identifier: Some(AttachmentIdentifier::CdnKey("abc".into())),
        ..Default::default()
    };
    let mut download = service.get_attachment(&pointer).await.unwrap();
    assert_eq!(download.content_length, Some(content.len() as u64));
    let mut downloaded = Vec::new();
    download.stream.read_to_end(&mut downloaded).await.unwrap();
    assert_eq!(downloaded, content);
    let get = transport.take_one();
    assert_eq!(
        (&get.method, &*get.url, get.endpoint),
        (
            &Method::GET,
            "https://cdn2.test/attachments/abc",
            EndpointKind::Cdn(2)
        )
    );
    assert_eq!(get.header(header::AUTHORIZATION), None);
    assert_eq!(get.timeout, None, "no deadline of lss's on a download");

    // A request the server holds sets its own wait for the response head.
    transport.answer(Answer::status(204));
    let held = service
        .request(
            Method::GET,
            Endpoint::service("/v1/devices/transfer_archive?timeout=300"),
            HttpAuthOverride::NoOverride,
        )
        .unwrap()
        .timeout(Duration::from_secs(315))
        .send()
        .await
        .unwrap();
    assert_eq!(held.status, StatusCode::NO_CONTENT);
    let poll = transport.take_one();
    assert_eq!(
        (&poll.method, &*poll.url, poll.endpoint, poll.timeout),
        (
            &Method::GET,
            "https://chat.test/v1/devices/transfer_archive?timeout=300",
            EndpointKind::Chat,
            Some(Duration::from_secs(315))
        )
    );
}

/// reqwest 0.13.5's body for the form lss's CDN0 upload built before the
/// transport seam: the same fields, `avatar.jpg`, and bytes 0..=255 repeated
/// to 1000 bytes. Made once with `multipart::Form::into_stream`.
const REQWEST_FORM: &[u8] =
    include_bytes!("fixtures/cdn0-form-reqwest-0.13.5.bin");
const REQWEST_BOUNDARY: &str =
    "c7f060fe96e10cb4-509eeff7acc2092e-81d36838e415ae8e-a0033a079642a92b";

fn replace_all(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(at) = rest.windows(from.len()).position(|w| w == from) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(to);
        rest = &rest[at + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

#[tokio::test]
async fn cdn_multipart_matches_reqwest_form_bytes() {
    let (mut service, transport) = push_service();
    let attributes: AttachmentV2UploadAttributes =
        serde_json::from_value(serde_json::json!({
            "key": "profiles/Q2RuMFRlc3RLZXk",
            "credential": "AKIAEXAMPLE/20261104/us-east-1/s3/aws4_request",
            "acl": "private",
            "algorithm": "AWS4-HMAC-SHA256",
            "date": "20261104T120000Z",
            "policy": "eyJleHBpcmF0aW9uIjoiMjAyNi0xMS0wNFQxMjowMDowMFoifQ==",
            "signature": "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        }))
        .unwrap();
    let file: Vec<u8> = (0..=255).cycle().take(1000).collect();

    transport.answer(Answer::status(204));
    service
        .upload_to_cdn0(
            "/",
            attributes,
            "avatar.jpg".into(),
            io::Cursor::new(file),
        )
        .await
        .unwrap();

    let upload = transport.take_one();
    assert_eq!(
        (&upload.method, &*upload.url, upload.endpoint),
        (&Method::POST, "https://cdn0.test/", EndpointKind::Cdn(0))
    );
    assert_eq!(
        upload.header(header::AUTHORIZATION),
        None,
        "the CDN gets no account credentials"
    );
    let boundary = upload
        .header(header::CONTENT_TYPE)
        .and_then(|value| value.strip_prefix("multipart/form-data; boundary="))
        .expect("a multipart content type")
        .to_owned();
    assert_eq!(boundary.len(), REQWEST_BOUNDARY.len());
    assert_ne!(boundary, REQWEST_BOUNDARY);
    let expected = replace_all(
        REQWEST_FORM,
        REQWEST_BOUNDARY.as_bytes(),
        boundary.as_bytes(),
    );
    assert_eq!(upload.body, expected);
}

fn assert_send_sync_static<T: Send + Sync + 'static>() {}

#[tokio::test]
async fn errors_carry_no_reqwest_type() {
    // Every public error crosses threads and owns no client type.
    assert_send_sync_static::<TransportError>();
    assert_send_sync_static::<ServiceError>();
    assert_send_sync_static::<StorageServiceError>();
    assert_send_sync_static::<MessageSenderError>();
    assert_send_sync_static::<AttachmentUploadError>();
    assert_send_sync_static::<ProvisioningError>();
    assert_send_sync_static::<ProfileManagerError>();

    let (mut service, transport) = push_service();

    // A failed request is the transport's own error, kind and source intact.
    transport.answer(Answer::Fail(TransportErrorKind::Connect));
    let error = service
        .request(
            Method::GET,
            Endpoint::service("/v1/anything"),
            HttpAuthOverride::NoOverride,
        )
        .unwrap()
        .send()
        .await
        .unwrap_err();
    let ServiceError::Transport(transport_error) = &error else {
        panic!("{error:?}");
    };
    assert_eq!(transport_error.kind(), TransportErrorKind::Connect);
    assert!(transport_error
        .get_ref()
        .is_some_and(|source| source.is::<FakeNetError>()));
    // The source chain ends at the transport's error, and each link displays
    // only its own part, so a chain printer shows each message once.
    let mut link: &(dyn Error + 'static) = &error;
    let mut messages = vec![link.to_string()];
    while let Some(source) = link.source() {
        messages.push(source.to_string());
        link = source;
    }
    assert_eq!(messages, ["could not connect", "the fake network failed"]);
    assert!(link.is::<FakeNetError>());
    transport.take_seen();

    // A body that breaks off fails the decode with the transport's error.
    transport.answer(Answer::chunks(
        200,
        vec![
            Ok(Bytes::from_static(b"{\"username\"")),
            Err(TransportErrorKind::Closed),
        ],
    ));
    let error = StorageService::new(
        service.clone(),
        StorageServiceKey { inner: [0; 32] },
    )
    .await
    .err()
    .expect("a broken body");
    assert!(
        matches!(&error, ServiceError::Transport(e) if e.kind() == TransportErrorKind::Closed),
        "{error:?}"
    );
    transport.take_seen();

    // A streamed download that breaks off is an I/O error over it.
    transport.answer(Answer::chunks(
        200,
        vec![
            Ok(Bytes::from_static(b"part")),
            Err(TransportErrorKind::Timeout),
        ],
    ));
    let pointer = AttachmentPointer {
        cdn_number: Some(3),
        attachment_identifier: Some(AttachmentIdentifier::CdnKey("k".into())),
        ..Default::default()
    };
    let mut download = service.get_attachment(&pointer).await.unwrap();
    let mut buf = Vec::new();
    let error = download.stream.read_to_end(&mut buf).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<TransportError>())
        .is_some_and(|inner| inner.kind() == TransportErrorKind::Timeout));
    assert_eq!(buf, b"part");
}

#[tokio::test]
async fn status_codes_map_to_service_errors() {
    let (mut service, transport) = push_service();

    transport.answer(Answer::status(409));
    assert!(matches!(
        service.link_device(&link_request(), link_auth()).await,
        Err(ServiceError::DeviceCapabilityDowngrade)
    ));

    transport.answer(Answer::json(
        411,
        serde_json::json!({ "current": 5, "max": 5 }),
    ));
    assert!(matches!(
        service.link_device(&link_request(), link_auth()).await,
        Err(ServiceError::DeviceLimitReached { current: 5, max: 5 })
    ));

    transport.answer(Answer::status(429).with_header("retry-after", "30"));
    assert!(matches!(
        service.link_device(&link_request(), link_auth()).await,
        Err(ServiceError::RateLimitExceeded { retry_after: Some(d) })
            if d == chrono::Duration::seconds(30)
    ));

    transport.answer(Answer::status(401));
    assert!(matches!(
        service.link_device(&link_request(), link_auth()).await,
        Err(ServiceError::Unauthorized)
    ));

    // CDN codes carry no Signal meaning: the status and the body come back.
    let pointer = AttachmentPointer {
        cdn_number: Some(2),
        attachment_identifier: Some(AttachmentIdentifier::CdnKey("k".into())),
        ..Default::default()
    };
    transport.answer(Answer::body(404, "gone"));
    assert_eq!(
        unhandled(service.get_attachment(&pointer).await),
        (StatusCode::NOT_FOUND, "gone".to_owned())
    );

    // The status is the error: a body that breaks off only ends what comes
    // back of it, from a CDN and for a chat code lss gives no meaning alike…
    let broken = || {
        vec![
            Ok(Bytes::from_static(b"par")),
            Err(TransportErrorKind::Closed),
        ]
    };
    transport.answer(Answer::chunks(404, broken()));
    assert_eq!(
        unhandled(service.get_attachment(&pointer).await),
        (StatusCode::NOT_FOUND, "par".to_owned())
    );
    transport.answer(Answer::chunks(500, broken()));
    assert_eq!(
        unhandled(service.link_device(&link_request(), link_auth()).await),
        (StatusCode::INTERNAL_SERVER_ERROR, "par".to_owned())
    );

    // …and at most `ERROR_BODY_LIMIT` bytes of it come back.
    transport.answer(Answer::chunks(
        503,
        vec![
            Ok(vec![b'a'; ERROR_BODY_LIMIT - 4].into()),
            Ok(Bytes::from_static(b"bbbbbbbb")),
        ],
    ));
    assert_eq!(
        unhandled(service.get_attachment(&pointer).await),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "a".repeat(ERROR_BODY_LIMIT - 4) + "bbbb"
        )
    );
    assert_eq!(transport.take_seen().len(), 8);
}

/// The status and body of an [`ServiceError::UnhandledResponseCode`].
fn unhandled<T>(result: Result<T, ServiceError>) -> (StatusCode, String) {
    match result {
        Err(ServiceError::UnhandledResponseCode { status, body }) => {
            (status, body)
        },
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("an error status succeeded"),
    }
}

#[tokio::test]
async fn invalid_header_fails_without_a_request() {
    let (service, transport) = push_service();
    let error = service
        .request(
            Method::GET,
            Endpoint::service("/v1/anything"),
            HttpAuthOverride::Unidentified,
        )
        .unwrap()
        .header("not a header name", "value")
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, ServiceError::InvalidHeader(_)), "{error:?}");
    // The cause is the source only, not repeated in the message.
    assert_eq!(error.to_string(), "invalid HTTP header");
    assert!(error.source().is_some());
    assert!(transport.take_seen().is_empty());
}

#[test]
fn an_upload_location_is_logged_without_its_credential() {
    let location: url::Url =
        "https://uploader:secret@cdn2.test:8443/upload/abc?upload_id=secret#secret"
            .parse()
            .unwrap();

    let absolute = Endpoint::absolute(location.clone(), EndpointKind::Cdn(2));
    assert_eq!(
        absolute.to_string(),
        "absolute URL https://cdn2.test:8443/upload/abc"
    );
    assert_eq!(
        format!("{absolute:?}"),
        "Absolute { url: https://cdn2.test:8443/upload/abc, kind: Cdn(2) }"
    );

    let resumable = Endpoint::cdn_url(2, &location);
    assert_eq!(resumable.to_string(), "CDN2 call to /upload/abc");
    assert_eq!(
        format!("{resumable:?}"),
        "Cdn { cdn_id: 2, path: \"/upload/abc\", .. }"
    );
}
