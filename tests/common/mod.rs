//! What the tests share: an in-memory [`Transport`] whose sockets a test
//! scripts from the server's end, a clock the test moves by hand, and (in
//! [`store`]) a protocol store whose clones share one state.

// Each test crate uses a part of this module.
#![allow(dead_code)]

pub mod store;

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use base64::prelude::*;
use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    future::{self, FutureExt as _, LocalBoxFuture},
    stream, Stream, StreamExt as _, TryStreamExt as _,
};
use http::{header, HeaderMap, Method, StatusCode};
use libsignal_service::{
    configuration::{ServiceConfiguration, ServiceCredentials, ServiceUrls},
    prelude::ProtobufMessage,
    proto::{
        web_socket_message, WebSocketMessage, WebSocketRequestMessage,
        WebSocketResponseMessage,
    },
    protocol::{DeviceId, KeyPair},
    push_service::{PushService, ServiceError},
    transport::{
        Clock, EndpointKind, HttpBody, HttpRequest, HttpResponse, Transport,
        TransportError, TransportErrorKind, WsConnect, WsConnection, WsEvent,
        WsUpgrade,
    },
    zkgroup::ServerSecretParams,
};
use uuid::Uuid;

pub const ACI: Uuid =
    Uuid::from_u128(0x0a0b_0c0d_0e0f_4a1b_8c2d_3e4f_5a6b_7c8d);

/// What the transport received.
pub struct Seen {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub endpoint: EndpointKind,
    pub timeout: Option<Duration>,
}

impl Seen {
    pub fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

/// A scripted answer to the next request.
pub enum Answer {
    Response {
        status: StatusCode,
        headers: Vec<(&'static str, String)>,
        body: Vec<Result<Bytes, TransportErrorKind>>,
    },
    Fail(TransportErrorKind),
}

impl Answer {
    pub fn status(status: u16) -> Self {
        Self::body(status, Vec::new())
    }

    pub fn body(status: u16, body: impl Into<Bytes>) -> Self {
        Self::chunks(status, vec![Ok(body.into())])
    }

    /// A body in these chunks; an error breaks it off there.
    pub fn chunks(
        status: u16,
        body: Vec<Result<Bytes, TransportErrorKind>>,
    ) -> Self {
        Self::Response {
            status: StatusCode::from_u16(status).unwrap(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Self::body(status, serde_json::to_vec(&value).unwrap())
            .with_header("content-type", "application/json")
    }

    pub fn with_header(mut self, name: &'static str, value: &str) -> Self {
        if let Self::Response { headers, .. } = &mut self {
            headers.push((name, value.to_owned()));
        }
        self
    }
}

/// The implementation's own error, which callers must be able to reach.
#[derive(Debug)]
pub struct FakeNetError;

impl fmt::Display for FakeNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the fake network failed")
    }
}

impl Error for FakeNetError {}

#[derive(Default)]
pub struct MemoryTransport {
    seen: RefCell<Vec<Seen>>,
    answers: RefCell<VecDeque<Answer>>,
    connects: RefCell<Vec<WsConnect>>,
    sockets: RefCell<VecDeque<Result<WsUpgrade, TransportErrorKind>>>,
}

impl MemoryTransport {
    pub fn answer(&self, answer: Answer) {
        self.answers.borrow_mut().push_back(answer);
    }

    /// Opens a socket at the next handshake, with these upgrade headers, and
    /// returns the server's end of it.
    pub fn accept_socket(
        &self,
        upgrade_headers: &[(&'static str, &'static str)],
    ) -> FakeServer {
        let (upgrade, server) = socket(upgrade_headers);
        self.sockets.borrow_mut().push_back(Ok(upgrade));
        server
    }

    /// Fails the next handshake.
    pub fn refuse_socket(&self, kind: TransportErrorKind) {
        self.sockets.borrow_mut().push_back(Err(kind));
    }

    /// How many handshakes lss asked for and nobody took yet.
    pub fn handshakes(&self) -> usize {
        self.connects.borrow().len()
    }

    pub fn take_connect(&self) -> WsConnect {
        let mut connects = std::mem::take(&mut *self.connects.borrow_mut());
        assert_eq!(connects.len(), 1, "exactly one handshake");
        connects.pop().unwrap()
    }

    pub fn take_seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.borrow_mut())
    }

    pub fn take_one(&self) -> Seen {
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
pub fn environment() -> ServiceConfiguration {
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
pub fn credentials() -> ServiceCredentials {
    ServiceCredentials {
        aci: Some(ACI),
        pni: None,
        phonenumber: Some("+15550100".parse().unwrap()),
        password: Some("hunter2".into()),
        device_id: Some(DeviceId::new(2).unwrap()),
    }
}

pub fn push_service() -> (PushService, Rc<MemoryTransport>) {
    let transport = Rc::new(MemoryTransport::default());
    let service =
        PushService::new(environment(), Some(credentials()), transport.clone())
            .unwrap();
    (service, transport)
}

pub fn basic(credentials: &str) -> String {
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

pub const KEEPALIVE: Duration = Duration::from_secs(55);

/// What lss did on a socket.
#[derive(Debug, PartialEq)]
#[expect(clippy::large_enum_variant, reason = "a test's log")]
pub enum Sent {
    Frame(WebSocketMessage),
    Close(u16),
}

/// lss's end of an in-memory WebSocket. It holds an `Rc`, so it is `!Send`,
/// as a connection on the lane may be.
pub struct FakeConnection {
    sent: mpsc::UnboundedSender<Sent>,
    events: mpsc::UnboundedReceiver<Result<WsEvent, TransportErrorKind>>,
    open: Rc<Cell<bool>>,
    /// Set, every send fails with it.
    send_error: Rc<Cell<Option<TransportErrorKind>>>,
    /// How many events lss has read.
    read: Rc<Cell<usize>>,
}

impl Stream for FakeConnection {
    type Item = Result<WsEvent, TransportError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let event = self.events.poll_next_unpin(cx);
        if let Poll::Ready(Some(_)) = event {
            self.read.set(self.read.get() + 1);
        }
        event.map_err(|kind| TransportError::new(kind, FakeNetError))
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
pub trait AmbiguousIfSend<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfSend<()> for T {}
impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

/// The same for `Sync`.
pub trait AmbiguousIfSync<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfSync<()> for T {}
impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

/// The server's end of an in-memory WebSocket.
pub struct FakeServer {
    sent: mpsc::UnboundedReceiver<Sent>,
    events: mpsc::UnboundedSender<Result<WsEvent, TransportErrorKind>>,
    open: Rc<Cell<bool>>,
    send_error: Rc<Cell<Option<TransportErrorKind>>>,
    read: Rc<Cell<usize>>,
}

impl FakeServer {
    /// What lss sent since the last call.
    pub fn take_sent(&mut self) -> Vec<Sent> {
        std::iter::from_fn(|| self.sent.try_recv().ok()).collect()
    }

    /// The requests lss sent since the last call, which sent nothing else.
    pub fn take_requests(&mut self) -> Vec<WebSocketRequestMessage> {
        self.take_sent().into_iter().map(sent_request).collect()
    }

    /// The answers lss sent since the last call, which sent nothing else.
    pub fn take_responses(&mut self) -> Vec<WebSocketResponseMessage> {
        self.take_sent().into_iter().map(sent_response).collect()
    }

    /// How many of the events sent so far lss has read.
    pub fn events_read(&self) -> usize {
        self.read.get()
    }

    /// The next thing lss sends.
    pub async fn next_sent(&mut self) -> Sent {
        self.sent.next().await.expect("the connection is open")
    }

    /// Whether lss still holds its end.
    pub fn is_open(&self) -> bool {
        self.open.get()
    }

    pub fn event(&self, event: Result<WsEvent, TransportErrorKind>) {
        self.events.unbounded_send(event).unwrap();
    }

    /// Fails every later send on lss's end with `kind`.
    pub fn fail_sends(&self, kind: TransportErrorKind) {
        self.send_error.set(Some(kind));
    }

    pub fn frame(&self, message: WebSocketMessage) {
        self.event(Ok(WsEvent::Binary(message.encode_to_vec().into())));
    }

    /// Sends lss this request of the server's.
    pub fn request_message(&self, request: WebSocketRequestMessage) {
        self.frame(WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request.into()),
            request: Some(request),
            ..Default::default()
        });
    }

    /// Answers lss's request `id`.
    pub fn respond(&self, id: u64, status: u32, body: &[u8]) {
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
    pub fn request(&self, id: u64, verb: &str, path: &str, body: Vec<u8>) {
        self.request_message(WebSocketRequestMessage {
            id: Some(id),
            verb: Some(verb.into()),
            path: Some(path.into()),
            body: Some(body.into()),
            headers: Vec::new(),
        });
    }
}

/// The request in what lss sent.
pub fn sent_request(sent: Sent) -> WebSocketRequestMessage {
    match sent {
        Sent::Frame(WebSocketMessage {
            r#type: Some(kind),
            request: Some(request),
            response: None,
        }) if kind == web_socket_message::Type::Request as i32 => request,
        other => panic!("not a request: {other:?}"),
    }
}

/// The answer in what lss sent.
pub fn sent_response(sent: Sent) -> WebSocketResponseMessage {
    match sent {
        Sent::Frame(WebSocketMessage {
            r#type: Some(kind),
            request: None,
            response: Some(response),
        }) if kind == web_socket_message::Type::Response as i32 => response,
        other => panic!("not a response: {other:?}"),
    }
}

pub fn socket(
    upgrade_headers: &[(&'static str, &'static str)],
) -> (WsUpgrade, FakeServer) {
    let (sent_tx, sent) = mpsc::unbounded();
    let (events, events_rx) = mpsc::unbounded();
    let open = Rc::new(Cell::new(true));
    let send_error = Rc::new(Cell::new(None));
    let read = Rc::new(Cell::new(0));
    let connection = FakeConnection {
        sent: sent_tx,
        events: events_rx,
        open: open.clone(),
        send_error: send_error.clone(),
        read: read.clone(),
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
            read,
        },
    )
}

/// A clock the test moves by hand. A wait ends once the clock reaches its
/// deadline, so a zero wait ends at once; a dropped clock ends none.
#[derive(Default)]
pub struct ManualClock(RefCell<ManualClockState>);

#[derive(Default)]
pub struct ManualClockState {
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
    pub fn advance(&self, by: Duration) {
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

    pub fn asked(&self) -> Vec<Duration> {
        self.0.borrow().asked.clone()
    }
}

pub fn get(path: &str) -> WebSocketRequestMessage {
    WebSocketRequestMessage::new(Method::GET).path(path).build()
}

/// The kind of the transport's error that ended a socket.
pub fn transport_kind(error: ServiceError) -> TransportErrorKind {
    match error {
        ServiceError::Transport(error) => error.kind(),
        other => panic!("not the transport's error: {other:?}"),
    }
}
