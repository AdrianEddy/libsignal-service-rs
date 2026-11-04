//! lss's HTTP requests and WebSockets and their outcomes, seen through an
//! in-memory [`Transport`].

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    collections::VecDeque,
    error::Error,
    fmt, io,
    pin::{pin, Pin},
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use base64::prelude::*;
use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    executor::LocalPool,
    future::{self, FutureExt as _, LocalBoxFuture},
    poll, stream,
    task::LocalSpawnExt as _,
    AsyncReadExt as _, Stream, StreamExt as _, TryStreamExt as _,
};
use http::{header, HeaderMap, Method, StatusCode};
use libsignal_service::{
    configuration::{
        Endpoint, ServiceConfiguration, ServiceCredentials, ServiceUrls,
    },
    master_key::StorageServiceKey,
    messagepipe::Incoming,
    prelude::{AttachmentIdentifier, AttachmentPointer, ProtobufMessage},
    proto::{
        web_socket_message, Envelope, ManifestRecord, ReadOperation,
        StorageItems, StorageRecord, WebSocketMessage, WebSocketRequestMessage,
        WebSocketResponseMessage,
    },
    protocol::{DeviceId, KeyPair},
    provisioning::ProvisioningError,
    push_service::{
        linking::{
            LinkAccountAttributes, LinkCapabilities, LinkRequest, LinkResponse,
        },
        AttachmentV2UploadAttributes, HttpAuth, HttpAuthOverride, PushService,
        ServiceError, ERROR_BODY_LIMIT,
    },
    receiver::MessageReceiver,
    sender::{AttachmentUploadError, MessageSenderError},
    transport::{
        Clock, EndpointKind, HttpBody, HttpRequest, HttpResponse, Transport,
        TransportError, TransportErrorKind, WsConnect, WsConnection, WsEvent,
        WsUpgrade,
    },
    websocket::{
        registration::DeviceActivationRequest, Identified, SocketEnd,
        Unidentified,
    },
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
    connects: RefCell<Vec<WsConnect>>,
    sockets: RefCell<VecDeque<Result<WsUpgrade, TransportErrorKind>>>,
}

impl MemoryTransport {
    fn answer(&self, answer: Answer) {
        self.answers.borrow_mut().push_back(answer);
    }

    /// Opens a socket at the next handshake, with these upgrade headers, and
    /// returns the server's end of it.
    fn accept_socket(
        &self,
        upgrade_headers: &[(&'static str, &'static str)],
    ) -> FakeServer {
        let (upgrade, server) = socket(upgrade_headers);
        self.sockets.borrow_mut().push_back(Ok(upgrade));
        server
    }

    /// Fails the next handshake.
    fn refuse_socket(&self, kind: TransportErrorKind) {
        self.sockets.borrow_mut().push_back(Err(kind));
    }

    fn take_connect(&self) -> WsConnect {
        let mut connects = std::mem::take(&mut *self.connects.borrow_mut());
        assert_eq!(connects.len(), 1, "exactly one handshake");
        connects.pop().unwrap()
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
        request: WsConnect,
    ) -> LocalBoxFuture<'_, Result<WsUpgrade, TransportError>> {
        self.connects.borrow_mut().push(request);
        let socket = self.sockets.borrow_mut().pop_front().expect("a socket");
        future::ready(
            socket.map_err(|kind| TransportError::new(kind, FakeNetError)),
        )
        .boxed_local()
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

/// The account's credentials: device 2 of `ACI`.
fn credentials() -> ServiceCredentials {
    ServiceCredentials {
        aci: Some(ACI),
        pni: None,
        phonenumber: "+15550100".parse().unwrap(),
        password: Some("hunter2".into()),
        device_id: Some(DeviceId::new(2).unwrap()),
    }
}

fn push_service() -> (PushService, Rc<MemoryTransport>) {
    let transport = Rc::new(MemoryTransport::default());
    let service =
        PushService::new(environment(), Some(credentials()), transport.clone());
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

    // A refused WebSocket upgrade keeps its status, which tells a removed
    // device (403) apart, and the transport's error.
    transport
        .refuse_socket(TransportErrorKind::Rejected(StatusCode::FORBIDDEN));
    let error = service
        .ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            Rc::new(ManualClock::default()),
        )
        .await
        .err()
        .expect("a refused upgrade");
    assert!(
        matches!(&error, ServiceError::Transport(e)
            if e.kind() == TransportErrorKind::Rejected(StatusCode::FORBIDDEN)
                && e.get_ref().is_some_and(|source| source.is::<FakeNetError>())),
        "{error:?}"
    );
    transport.take_connect();
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

    // A WebSocket's header the same, before any handshake.
    let error = service
        .ws::<Unidentified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[("X-Signal-Agent", "line\nbreak")],
            None,
            Rc::new(ManualClock::default()),
        )
        .await
        .err()
        .expect("an invalid header");
    assert!(matches!(error, ServiceError::InvalidHeader(_)), "{error:?}");
    assert!(transport.connects.borrow().is_empty());
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

// WebSockets.

const KEEPALIVE: Duration = Duration::from_secs(55);

/// What lss did on a socket.
#[derive(Debug, PartialEq)]
#[expect(clippy::large_enum_variant, reason = "a test's log")]
enum Sent {
    Frame(WebSocketMessage),
    Close(u16),
}

/// lss's end of an in-memory WebSocket. It holds an `Rc`, so it is `!Send`,
/// as a connection on the lane may be.
struct FakeConnection {
    sent: mpsc::UnboundedSender<Sent>,
    events: mpsc::UnboundedReceiver<Result<WsEvent, TransportErrorKind>>,
    open: Rc<Cell<bool>>,
    /// Set, every send fails with it.
    send_error: Rc<Cell<Option<TransportErrorKind>>>,
}

impl Stream for FakeConnection {
    type Item = Result<WsEvent, TransportError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.events
            .poll_next_unpin(cx)
            .map_err(|kind| TransportError::new(kind, FakeNetError))
    }
}

impl WsConnection for FakeConnection {
    fn send(
        &mut self,
        frame: Bytes,
    ) -> LocalBoxFuture<'_, Result<(), TransportError>> {
        if let Some(kind) = self.send_error.get() {
            return future::err(TransportError::new(kind, FakeNetError))
                .boxed_local();
        }
        let message = WebSocketMessage::decode(frame).expect("a message");
        self.sent.unbounded_send(Sent::Frame(message)).unwrap();
        future::ok(()).boxed_local()
    }

    fn close(
        &mut self,
        code: u16,
    ) -> LocalBoxFuture<'_, Result<(), TransportError>> {
        self.sent.unbounded_send(Sent::Close(code)).unwrap();
        future::ok(()).boxed_local()
    }
}

impl Drop for FakeConnection {
    fn drop(&mut self) {
        self.open.set(false);
    }
}

/// Doesn't compile for a `Send` type: both impls would then apply, and the
/// `_` in `<T as AmbiguousIfSend<_>>` would be ambiguous.
trait AmbiguousIfSend<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfSend<()> for T {}
impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

/// The server's end of an in-memory WebSocket.
struct FakeServer {
    sent: mpsc::UnboundedReceiver<Sent>,
    events: mpsc::UnboundedSender<Result<WsEvent, TransportErrorKind>>,
    open: Rc<Cell<bool>>,
    send_error: Rc<Cell<Option<TransportErrorKind>>>,
}

impl FakeServer {
    /// What lss sent since the last call.
    fn take_sent(&mut self) -> Vec<Sent> {
        std::iter::from_fn(|| self.sent.try_recv().ok()).collect()
    }

    /// The requests lss sent since the last call, which sent nothing else.
    fn take_requests(&mut self) -> Vec<WebSocketRequestMessage> {
        self.take_sent().into_iter().map(sent_request).collect()
    }

    /// The next thing lss sends.
    async fn next_sent(&mut self) -> Sent {
        self.sent.next().await.expect("the connection is open")
    }

    /// Whether lss still holds its end.
    fn is_open(&self) -> bool {
        self.open.get()
    }

    fn event(&self, event: Result<WsEvent, TransportErrorKind>) {
        self.events.unbounded_send(event).unwrap();
    }

    /// Fails every later send on lss's end with `kind`.
    fn fail_sends(&self, kind: TransportErrorKind) {
        self.send_error.set(Some(kind));
    }

    fn frame(&self, message: WebSocketMessage) {
        self.event(Ok(WsEvent::Binary(message.encode_to_vec().into())));
    }

    /// Answers lss's request `id`.
    fn respond(&self, id: u64, status: u32, body: &[u8]) {
        self.frame(WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response.into()),
            response: Some(WebSocketResponseMessage {
                id: Some(id),
                status: Some(status),
                message: Some("OK".into()),
                headers: Vec::new(),
                body: Some(body.to_vec()),
            }),
            ..Default::default()
        });
    }

    /// Sends lss a request of the server's.
    fn request(&self, id: u64, verb: &str, path: &str, body: Vec<u8>) {
        self.frame(WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request.into()),
            request: Some(WebSocketRequestMessage {
                id: Some(id),
                verb: Some(verb.into()),
                path: Some(path.into()),
                body: Some(body),
                headers: Vec::new(),
            }),
            ..Default::default()
        });
    }
}

/// The request in what lss sent.
fn sent_request(sent: Sent) -> WebSocketRequestMessage {
    match sent {
        Sent::Frame(WebSocketMessage {
            r#type: Some(kind),
            request: Some(request),
            response: None,
        }) if kind == web_socket_message::Type::Request as i32 => request,
        other => panic!("not a request: {other:?}"),
    }
}

fn socket(
    upgrade_headers: &[(&'static str, &'static str)],
) -> (WsUpgrade, FakeServer) {
    let (sent_tx, sent) = mpsc::unbounded();
    let (events, events_rx) = mpsc::unbounded();
    let open = Rc::new(Cell::new(true));
    let send_error = Rc::new(Cell::new(None));
    let connection = FakeConnection {
        sent: sent_tx,
        events: events_rx,
        open: open.clone(),
        send_error: send_error.clone(),
    };
    let upgrade = WsUpgrade {
        headers: upgrade_headers
            .iter()
            .map(|&(name, value)| {
                (
                    header::HeaderName::from_static(name),
                    header::HeaderValue::from_static(value),
                )
            })
            .collect(),
        connection: Box::new(connection),
    };
    (
        upgrade,
        FakeServer {
            sent,
            events,
            open,
            send_error,
        },
    )
}

/// A clock the test moves by hand. A wait ends once the clock reaches its
/// deadline, so a zero wait ends at once; a dropped clock ends none.
#[derive(Default)]
struct ManualClock(RefCell<ManualClockState>);

#[derive(Default)]
struct ManualClockState {
    elapsed: Duration,
    waits: Vec<(Duration, oneshot::Sender<()>)>,
    /// Every wait asked for, in order.
    asked: Vec<Duration>,
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(1_700_000_000)
            + self.0.borrow().elapsed
    }

    fn sleep(&self, duration: Duration) -> LocalBoxFuture<'static, ()> {
        let mut state = self.0.borrow_mut();
        state.asked.push(duration);
        if duration.is_zero() {
            return future::ready(()).boxed_local();
        }
        let (wake, woken) = oneshot::channel();
        let deadline = state.elapsed + duration;
        state.waits.push((deadline, wake));
        async move {
            if woken.await.is_err() {
                future::pending::<()>().await;
            }
        }
        .boxed_local()
    }
}

impl ManualClock {
    fn advance(&self, by: Duration) {
        let due: Vec<_> = {
            let mut state = self.0.borrow_mut();
            state.elapsed += by;
            let now = state.elapsed;
            let (due, waiting) = std::mem::take(&mut state.waits)
                .into_iter()
                .partition(|(deadline, _)| *deadline <= now);
            state.waits = waiting;
            due
        };
        for (_, wake) in due {
            let _ = wake.send(());
        }
    }

    fn asked(&self) -> Vec<Duration> {
        self.0.borrow().asked.clone()
    }
}

fn get(path: &str) -> WebSocketRequestMessage {
    WebSocketRequestMessage::new(Method::GET).path(path).build()
}

/// The keepalive on the test clock, responses matched to requests, and
/// Signal's requests through the message pipe, which answers them.
#[test]
fn websocket_keepalive_and_responses() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let (service, transport) = push_service();
    let clock = Rc::new(ManualClock::default());
    let mut server =
        transport.accept_socket(&[("x-signal-alert", "idle-primary-device")]);

    let (pipe, task) = pool
        .run_until(MessageReceiver::new(service).create_message_pipe(
            credentials(),
            true,
            clock.clone(),
        ))
        .unwrap();

    // The handshake: the chat service's socket, the account's credentials
    // marked sensitive, and the caller's header. The User-Agent is the
    // transport's.
    let connect = transport.take_connect();
    assert_eq!(connect.url.as_str(), "wss://chat.test/v1/websocket/");
    assert_eq!(
        connect.headers[header::AUTHORIZATION],
        *basic(&format!("{ACI}.2:hunter2"))
    );
    assert!(connect.headers[header::AUTHORIZATION].is_sensitive());
    assert_eq!(connect.headers["x-signal-receive-stories"], "true");
    assert_eq!(connect.headers.len(), 2);
    // Its `Debug`, for a log line, leaves the credential out.
    let logged = format!("{connect:?}");
    assert!(logged.contains("Sensitive"), "{logged}");
    assert!(
        !logged.contains(&BASE64_STANDARD.encode(format!("{ACI}.2:hunter2")))
    );
    let ws = pipe.ws();
    assert_eq!(
        ws.upgrade_headers()["x-signal-alert"],
        "idle-primary-device"
    );

    let running = spawner.spawn_local_with_handle(task).unwrap();
    pool.run_until_stalled();

    // The first keepalive waits a whole interval, and each arms the next
    // wait.
    assert_eq!(clock.asked(), [KEEPALIVE]);
    clock.advance(KEEPALIVE - Duration::from_secs(1));
    pool.run_until_stalled();
    assert_eq!(server.take_sent(), []);
    clock.advance(Duration::from_secs(1));
    pool.run_until_stalled();
    let [keepalive] = &server.take_requests()[..] else {
        panic!("one keepalive")
    };
    assert_eq!(
        (keepalive.verb(), keepalive.path(), keepalive.body.as_ref()),
        ("GET", "/v1/keepalive", None)
    );
    assert_eq!(clock.asked(), [KEEPALIVE; 2]);
    server.respond(keepalive.id(), 200, b"");
    pool.run_until_stalled();

    // Responses find their requests by id, whatever their order.
    let first = spawner
        .spawn_local_with_handle(ws.clone().request(get("/v1/first")))
        .unwrap();
    let second = spawner
        .spawn_local_with_handle(ws.clone().request(get("/v1/second")))
        .unwrap();
    pool.run_until_stalled();
    let requests = server.take_requests();
    let id = |path: &str| {
        requests
            .iter()
            .find(|request| request.path() == path)
            .expect("sent")
            .id()
    };
    assert_ne!(id("/v1/first"), id("/v1/second"));
    server.respond(id("/v1/second"), 201, b"two");
    server.respond(id("/v1/first"), 200, b"one");
    pool.run_until_stalled();
    let first = first.now_or_never().expect("answered").unwrap();
    let second = second.now_or_never().expect("answered").unwrap();
    assert_eq!((first.status(), first.body()), (200, &b"one"[..]));
    assert_eq!((second.status(), second.body()), (201, &b"two"[..]));

    // Signal's requests reach the pipe, which answers each under its id.
    let envelope = Envelope {
        client_timestamp: Some(1_700_000_000_000),
        ..Default::default()
    };
    server.request(7, "PUT", "/api/v1/message", envelope.encode_to_vec());
    server.request(8, "PUT", "/api/v1/queue/empty", Vec::new());
    let incoming = spawner
        .spawn_local_with_handle(pipe.stream().take(2).collect::<Vec<_>>())
        .unwrap();
    pool.run_until_stalled();
    let incoming = incoming.now_or_never().expect("both delivered");
    assert!(
        matches!(&incoming[..],
            [Ok(Incoming::Envelope(delivered)), Ok(Incoming::QueueEmpty)]
                if *delivered == envelope),
        "{incoming:?}"
    );
    let mut responses: Vec<_> = server
        .take_sent()
        .into_iter()
        .map(|sent| match sent {
            Sent::Frame(WebSocketMessage {
                response: Some(response),
                request: None,
                ..
            }) => (response.id(), response.status()),
            other => panic!("not a response: {other:?}"),
        })
        .collect();
    responses.sort_unstable();
    assert_eq!(responses, [(7, 200), (8, 200)]);

    // A task that stalls through several intervals sends one late keepalive,
    // not a burst whose second would find the first unanswered.
    clock.advance(KEEPALIVE * 3);
    pool.run_until_stalled();
    let [keepalive] = &server.take_requests()[..] else {
        panic!("one keepalive")
    };
    assert_eq!(keepalive.path(), "/v1/keepalive");
    assert!(server.is_open());

    // Unanswered for a whole interval, it closes the socket as going away
    // and ends the task, which says why.
    clock.advance(KEEPALIVE - Duration::from_secs(1));
    pool.run_until_stalled();
    assert_eq!(server.take_sent(), []);
    clock.advance(Duration::from_secs(1));
    pool.run_until_stalled();
    assert_eq!(server.take_sent(), [Sent::Close(1001)]);
    assert_eq!(
        running.now_or_never().expect("the task ended").unwrap(),
        SocketEnd::KeepaliveUnanswered
    );
    assert!(!server.is_open());
    assert!(ws.is_closed());
    assert_eq!(clock.asked(), [KEEPALIVE; 3]);
}

/// The lane's runtime runs the task: lss spawns nothing, so the socket waits
/// for its caller, and its connection need not be `Send`.
#[test]
fn socket_task_is_returned_not_spawned() {
    let _ = <FakeConnection as AmbiguousIfSend<_>>::some_item;

    // As the lane builds it (R1 D-RT-1): one thread, `!Send` tasks.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build_local(tokio::runtime::LocalOptions::default())
        .unwrap();
    runtime.block_on(async {
        let metrics = tokio::runtime::Handle::current().metrics();
        let (service, transport) = push_service();
        let clock = Rc::new(ManualClock::default());
        let mut server = transport.accept_socket(&[]);

        let (mut ws, task) = service
            .ws::<Unidentified>(
                "/v1/websocket/provisioning/",
                "/v1/keepalive/provisioning",
                &[],
                None,
                clock.clone(),
            )
            .await
            .unwrap();
        let connect = transport.take_connect();
        assert_eq!(
            connect.url.as_str(),
            "wss://chat.test/v1/websocket/provisioning/"
        );
        assert!(connect.headers.is_empty(), "no credentials");

        let running = {
            // Until the caller polls the task, nothing runs: no task was
            // spawned, no timer armed, and a request waits in the handle.
            assert_eq!(metrics.num_alive_tasks(), 0);
            let mut request = pin!(ws.request(get("/v1/address")));
            assert!(poll!(request.as_mut()).is_pending());
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(poll!(request.as_mut()).is_pending());
            assert_eq!(server.take_sent(), []);
            assert_eq!(clock.asked(), []);

            // The caller runs it, as the lane's `spawn_critical` does.
            let running = tokio::task::spawn_local(task);
            assert_eq!(metrics.num_alive_tasks(), 1);
            let sent = sent_request(server.next_sent().await);
            assert_eq!(sent.path(), "/v1/address");
            server.respond(sent.id(), 200, b"");
            assert_eq!(request.await.unwrap().status(), 200);
            assert_eq!(clock.asked(), [KEEPALIVE]);
            running
        };

        // Once the last handle is dropped, the task ends, released, and
        // drops the connection.
        drop(ws);
        assert_eq!(running.await.unwrap().unwrap(), SocketEnd::Released);
        assert!(!server.is_open());
    });
}

#[test]
fn dropping_the_task_closes_the_socket() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let (service, transport) = push_service();
    let mut server = transport.accept_socket(&[]);
    let (mut ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            Rc::new(ManualClock::default()),
        ))
        .unwrap();

    let running = spawner.spawn_local_with_handle(task).unwrap();
    let waiting = spawner
        .spawn_local_with_handle(ws.request(get("/v1/devices")))
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(server.take_requests().len(), 1);
    assert!(server.is_open());

    // The caller drops the task, as a lane that ends does.
    drop(running);
    pool.run_until_stalled();
    assert!(
        !server.is_open(),
        "the connection is dropped, which closes it"
    );
    assert_eq!(server.take_sent(), []);
    assert!(ws.is_closed());
    assert!(matches!(
        waiting.now_or_never(),
        Some(Err(ServiceError::WsClosing { .. }))
    ));
    assert!(matches!(
        pool.run_until(ws.request(get("/v1/devices"))),
        Err(ServiceError::WsClosing { .. })
    ));
}

/// The server's close and a connection that breaks each end the task, which
/// says how it ended, and fail the requests waiting on it.
#[test]
fn the_connection_ending_ends_the_task() {
    for (end, ended) in [
        (
            Ok(WsEvent::Close {
                code: 4409,
                reason: "Connected elsewhere".into(),
            }),
            Ok(SocketEnd::Closed {
                code: 4409,
                reason: "Connected elsewhere".into(),
            }),
        ),
        (
            Err(TransportErrorKind::Closed),
            Err(TransportErrorKind::Closed),
        ),
    ] {
        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let (service, transport) = push_service();
        let mut server = transport.accept_socket(&[]);
        let (mut ws, task) = pool
            .run_until(service.ws::<Identified>(
                "/v1/websocket/",
                "/v1/keepalive",
                &[],
                Some(credentials()),
                Rc::new(ManualClock::default()),
            ))
            .unwrap();
        let running = spawner.spawn_local_with_handle(task).unwrap();
        let waiting = spawner
            .spawn_local_with_handle(ws.request(get("/v1/devices")))
            .unwrap();
        pool.run_until_stalled();
        assert_eq!(server.take_requests().len(), 1);

        server.event(end);
        pool.run_until_stalled();
        let result = running.now_or_never().expect("the task ended");
        assert_eq!(result.map_err(transport_kind), ended);
        assert!(!server.is_open());
        assert_eq!(server.take_sent(), [], "the transport closes it");
        assert!(ws.is_closed());
        assert!(matches!(
            waiting.now_or_never(),
            Some(Err(ServiceError::WsClosing { .. }))
        ));
    }
}

/// A keepalive the connection can't send ends the task with the transport's
/// error, not as if the socket had ended cleanly.
#[test]
fn a_keepalive_that_cannot_be_sent_fails_the_task() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let (service, transport) = push_service();
    let clock = Rc::new(ManualClock::default());
    let server = transport.accept_socket(&[]);
    let (ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            clock.clone(),
        ))
        .unwrap();
    let running = spawner.spawn_local_with_handle(task).unwrap();
    pool.run_until_stalled();

    server.fail_sends(TransportErrorKind::Closed);
    clock.advance(KEEPALIVE);
    pool.run_until_stalled();
    let result = running.now_or_never().expect("the task ended");
    assert_eq!(
        result.map_err(transport_kind),
        Err(TransportErrorKind::Closed)
    );
    assert!(!server.is_open());
    assert!(ws.is_closed());
}

/// The kind of the transport's error that ended a socket.
fn transport_kind(error: ServiceError) -> TransportErrorKind {
    match error {
        ServiceError::Transport(error) => error.kind(),
        other => panic!("not the transport's error: {other:?}"),
    }
}
