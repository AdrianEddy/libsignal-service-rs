use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;

use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use http::{HeaderMap, Method, StatusCode};
use tracing::debug;

use crate::prelude::PushService;
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::{self, ServiceError, SignalServiceResponse};
use crate::transport::{Clock, WsConnection, WsEvent, WsUpgrade};

pub mod account;
pub mod calling;
#[cfg(feature = "cdsi")]
pub mod directory;
pub mod keys;
pub mod linking;
pub mod profile;
pub mod registration;
mod request;
mod sender;
pub mod stickers;
mod usernames;

pub use request::WebSocketRequestMessageBuilder;

type RequestStreamItem = (
    WebSocketRequestMessage,
    oneshot::Sender<WebSocketResponseMessage>,
);

pub struct SignalRequestStream {
    inner: mpsc::UnboundedReceiver<RequestStreamItem>,
}

impl Stream for SignalRequestStream {
    type Item = RequestStreamItem;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let inner = &mut self.inner;
        futures::pin_mut!(inner);
        Stream::poll_next(inner, cx)
    }
}

#[derive(Debug, Clone)]
pub struct Identified;

#[derive(Debug, Clone)]
pub struct Unidentified;

pub trait WebSocketType: 'static {}

impl WebSocketType for Identified {}

impl WebSocketType for Unidentified {}

/// The close code of a client that leaves (RFC 6455 §7.4.1).
const CLOSE_GOING_AWAY: u16 = 1001;

/// Why a socket's task ended, when no error ended it (see
/// [`SignalWebSocket::new`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketEnd {
    /// The server closed the connection. The chat service closes with 4401
    /// once the socket's credentials are no longer valid, as when the device
    /// was removed from the account, and with 4409 when another connection
    /// with the same credentials took over. The provisioning service closes
    /// with 1000 "Timeout" when no device sent a provisioning message in
    /// time, and with 1000 "Closed" once its message was answered.
    Closed { code: u16, reason: String },
    /// A keepalive went unanswered for a whole interval, so lss closed the
    /// connection as going away (1001).
    KeepaliveUnanswered,
    /// Every handle was dropped, and no request was in flight.
    Released,
}

impl fmt::Display for SocketEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed { code, reason } => {
                write!(f, "closed by the server with {code} {reason:?}")
            },
            Self::KeepaliveUnanswered => {
                f.write_str("a keepalive went unanswered")
            },
            Self::Released => f.write_str("every handle was dropped"),
        }
    }
}

/// A dispatching web socket client for the Signal web socket API.
///
/// This structure can be freely cloned, since this acts as a *facade* for multiple entry and exit
/// points.
#[derive(Clone)]
pub struct SignalWebSocket<C: WebSocketType> {
    _type: PhantomData<C>,
    // XXX: at the end of the migration, this should be CDN operations only
    pub(crate) unidentified_push_service: PushService,
    inner: Rc<SignalWebSocketInner>,
    request_sink: mpsc::Sender<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
}

struct SignalWebSocketInner {
    stream: RefCell<Option<SignalRequestStream>>,
    /// The headers of the response that upgraded the connection.
    upgrade_headers: HeaderMap,
}

struct SignalWebSocketProcess {
    /// Whether to enable keep-alive or not (and send a request to this path)
    keep_alive_path: String,

    /// Receives requests from the application, which we forward to Signal.
    requests: mpsc::Receiver<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
    /// Signal's requests should go in here, to be delivered to the application.
    request_sink: mpsc::UnboundedSender<RequestStreamItem>,

    outgoing_requests: HashMap<
        u64,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    >,

    outgoing_keep_alive_set: HashSet<u64>,

    /// The application's responses to Signal's requests, as they complete.
    outgoing_responses:
        FuturesUnordered<oneshot::Receiver<WebSocketResponseMessage>>,

    ws: Box<dyn WsConnection>,

    /// Times the keepalive.
    clock: Rc<dyn Clock>,
}

impl SignalWebSocketProcess {
    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<(), ServiceError> {
        use prost::Message;
        let msg = WebSocketMessage::decode(frame)?;
        if let Some(request) = &msg.request {
            tracing::trace!(
                msg_type =? msg.r#type(),
                request.id,
                request.verb,
                request.path,
                request_body_size_bytes = request.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?request.headers,
                "decoded WebSocketMessage request"
            );
        } else if let Some(response) = &msg.response {
            tracing::trace!(
                msg_type =? msg.r#type(),
                response.status,
                response.message,
                response_body_size_bytes = response.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?response.headers,
                response.id,
                "decoded WebSocketMessage response"
            );
        } else {
            tracing::debug!("decoded {msg:?}");
        }

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrame {
                reason: "unknown frame type",
            }),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                tracing::trace!("sending request with body");
                self.request_sink.send((request, sink)).await.map_err(
                    |_| ServiceError::WsClosing {
                        reason: "request handler failed",
                    },
                )?;
                self.outgoing_responses.push(recv);

                Ok(())
            },
            (Type::Request, None, _) => Err(ServiceError::InvalidFrame {
                reason: "type was request, but does not contain request",
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) = self.outgoing_requests.remove(&id)
                    {
                        if let Err(e) = responder.send(Ok(response)) {
                            tracing::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else if let Some(_x) =
                        self.outgoing_keep_alive_set.take(&id)
                    {
                        let status =
                            StatusCode::from_u16(response.status() as _)
                                .map_err(|e| {
                                    ServiceError::IO(std::io::Error::other(
                                        format!(
                                            "invalid http status code {} - {e}",
                                            response.status()
                                        ),
                                    ))
                                })?;
                        if !status.is_success() {
                            return Err(ServiceError::UnhandledResponseCode {
                                status,
                                body: String::from_utf8_lossy(response.body())
                                    .into_owned(),
                            });
                        }
                    } else {
                        tracing::warn!(
                            ?response,
                            "response for non existing request"
                        );
                    }
                }

                Ok(())
            },
            (Type::Response, _, None) => Err(ServiceError::InvalidFrame {
                reason: "type was response, but does not contain response",
            }),
        }
    }

    fn next_request_id(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::rng();
        loop {
            let id = rng.random();
            if !self.outgoing_requests.contains_key(&id) {
                return id;
            }
        }
    }

    /// Runs the socket until it ends, and returns why. The caller logs the
    /// end; lss writes no more than a debug line.
    async fn run(mut self) -> Result<SocketEnd, ServiceError> {
        // A keepalive sent before the server registers our presence makes it
        // close the socket, so the first one waits a whole interval too. Each
        // keepalive arms the next wait: a task that stalls sends one late
        // keepalive, not a burst.
        let mut keep_alive = self
            .clock
            .sleep(push_service::KEEPALIVE_TIMEOUT_SECONDS)
            .fuse();

        loop {
            futures::select! {
                () = keep_alive => {
                    use prost::Message;
                    if !self.outgoing_keep_alive_set.is_empty() {
                        tracing::debug!("keepalive unanswered; closing the websocket");
                        if let Err(e) = self.ws.close(CLOSE_GOING_AWAY).await {
                            tracing::debug!("Could not close WebSocket: {:?}", e);
                        }
                        return Ok(SocketEnd::KeepaliveUnanswered);
                    }
                    tracing::debug!("sending keep-alive");
                    let request = WebSocketRequestMessage::new(Method::GET)
                        .id(self.next_request_id())
                        .path(&self.keep_alive_path)
                        .build();
                    self.outgoing_keep_alive_set.insert(request.id.unwrap());
                    let msg = WebSocketMessage {
                        r#type: Some(web_socket_message::Type::Request.into()),
                        request: Some(request),
                        ..Default::default()
                    };
                    let buffer = msg.encode_to_vec();
                    self.ws.send(Bytes::from(buffer)).await?;
                    keep_alive = self
                        .clock
                        .sleep(push_service::KEEPALIVE_TIMEOUT_SECONDS)
                        .fuse();
                },
                // Process requests from the application, forward them to Signal
                x = self.requests.next() => {
                    match x {
                        Some((mut request, responder)) => {
                            use prost::Message;

                            // Regenerate ID if already in the table
                            request.id = Some(
                                request
                                    .id
                                    .filter(|x| !self.outgoing_requests.contains_key(x))
                                    .unwrap_or_else(|| self.next_request_id()),
                            );
                            tracing::trace!(
                                request.id,
                                request.verb,
                                request.path,
                                request_body_size_bytes = request.body.as_ref().map(|x| x.len()),
                                ?request.headers,
                                "sending WebSocketRequestMessage",
                            );

                            self.outgoing_requests.insert(request.id.unwrap(), responder);
                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Request.into()),
                                request: Some(request),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(Bytes::from(buffer)).await?
                        }
                        None => {
                            debug!("end of application request stream; websocket closing");
                            return Ok(SocketEnd::Released);
                        }
                    }
                }
                // Incoming websocket message
                web_socket_item = self.ws.next().fuse() => {
                    match web_socket_item {
                        Some(Ok(WsEvent::Close { code, reason })) => {
                            tracing::debug!(%code, reason, "websocket closed");
                            return Ok(SocketEnd::Closed { code, reason });
                        },
                        Some(Ok(WsEvent::Binary(frame))) => {
                            self.process_frame(frame).await?;
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => {
                            return Err(ServiceError::WsClosing {
                                reason: "end of web request stream; socket closing"
                            });
                        }
                    }
                }
                // The set is terminated while empty, which turns this branch off
                // until the next push.
                response = self.outgoing_responses.select_next_some() => {
                    use prost::Message;
                    match response {
                        Ok(response) => {
                            tracing::trace!("sending response {:?}", response);

                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Response.into()),
                                response: Some(response),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(Bytes::from(buffer)).await?;
                        }
                        Err(error) => {
                            tracing::error!(%error, "could not generate response to a Signal request; responder was canceled. continuing.");
                        }
                    }
                }
            }
        }
    }
}

impl<C: WebSocketType> SignalWebSocket<C> {
    /// The handle of the socket `upgrade` opened, and the socket's task.
    ///
    /// The task runs the socket: it sends a keepalive every
    /// [`KEEPALIVE_TIMEOUT_SECONDS`](push_service::KEEPALIVE_TIMEOUT_SECONDS)
    /// on `clock`, matches responses to requests and passes Signal's requests
    /// to the request stream. lss spawns nothing: the caller runs the task, and
    /// the socket does nothing until it does.
    ///
    /// The task resolves to why the socket ended, which the caller logs. It
    /// ends with:
    /// - [`SocketEnd::Closed`] when the server closes the connection;
    /// - [`SocketEnd::KeepaliveUnanswered`] when a keepalive goes unanswered
    ///   for a whole interval, after closing the connection with 1001;
    /// - [`SocketEnd::Released`] once every handle is dropped and no request
    ///   is in flight;
    /// - [`ServiceError::Transport`] when the connection breaks or a send on it
    ///   fails;
    /// - [`ServiceError::WsClosing`] when the connection ends without the
    ///   server's close, or when Signal sends a request after the request
    ///   stream was dropped, as when a
    ///   [`MessagePipe`](crate::messagepipe::MessagePipe)'s stream is dropped
    ///   while handles live;
    /// - [`ServiceError::ProtobufDecodeError`] for a frame lss cannot decode,
    ///   and [`ServiceError::InvalidFrame`] for one of an unknown type or
    ///   without the request or response its type names;
    /// - [`ServiceError::UnhandledResponseCode`] when a keepalive is answered
    ///   with a status outside 2xx, or [`ServiceError::IO`] when that status
    ///   is not a valid HTTP status.
    ///
    /// However the task ends, and if it is dropped, the connection closes and
    /// requests still waiting fail with [`ServiceError::WsClosing`].
    pub fn new(
        upgrade: WsUpgrade,
        keep_alive_path: String,
        unidentified_push_service: PushService,
        clock: Rc<dyn Clock>,
    ) -> (Self, impl Future<Output = Result<SocketEnd, ServiceError>>) {
        let WsUpgrade {
            headers: upgrade_headers,
            connection,
        } = upgrade;

        // Create process
        let (incoming_request_sink, incoming_request_stream) =
            mpsc::unbounded();
        let (outgoing_request_sink, outgoing_requests) = mpsc::channel(1);

        let process = SignalWebSocketProcess {
            keep_alive_path,
            requests: outgoing_requests,
            request_sink: incoming_request_sink,
            outgoing_requests: HashMap::default(),
            outgoing_keep_alive_set: HashSet::new(),
            outgoing_responses: FuturesUnordered::new(),
            ws: connection,
            clock,
        };

        (
            Self {
                _type: PhantomData,
                request_sink: outgoing_request_sink,
                unidentified_push_service,
                inner: Rc::new(SignalWebSocketInner {
                    stream: RefCell::new(Some(SignalRequestStream {
                        inner: incoming_request_stream,
                    })),
                    upgrade_headers,
                }),
            },
            process.run(),
        )
    }

    /// The headers of the response that upgraded the connection, such as
    /// `X-Signal-Alert`.
    pub fn upgrade_headers(&self) -> &HeaderMap {
        &self.inner.upgrade_headers
    }

    pub fn is_closed(&self) -> bool {
        self.request_sink.is_closed()
    }

    pub fn is_used(&self) -> bool {
        self.inner.stream.borrow().is_none()
    }

    pub(crate) fn take_request_stream(
        &mut self,
    ) -> Option<SignalRequestStream> {
        self.inner.stream.borrow_mut().take()
    }

    pub(crate) fn return_request_stream(&mut self, r: SignalRequestStream) {
        self.inner.stream.borrow_mut().replace(r);
    }

    // XXX Ideally, this should take an *async* closure, then we could get rid of the
    // `take_request_stream` and `return_request_stream`.
    pub async fn with_request_stream<
        R: 'static,
        F: FnOnce(&mut SignalRequestStream) -> R,
    >(
        &mut self,
        f: F,
    ) -> R {
        let mut s = self
            .inner
            .stream
            .borrow_mut()
            .take()
            .expect("request stream invariant");
        let r = f(&mut s);
        self.inner.stream.borrow_mut().replace(s);
        r
    }

    pub fn request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>
    {
        let (sink, recv): (
            oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
            _,
        ) = oneshot::channel();

        let mut request_sink = self.request_sink.clone();
        async move {
            if let Err(_e) = request_sink.send((r, sink)).await {
                return Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while sending request",
                });
            }
            // Handle the oneshot sender error for dropped senders.
            match recv.await {
                Ok(x) => x,
                Err(_) => Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while waiting for a response",
                }),
            }
        }
    }

    pub(crate) async fn request_json_with<T, F, Fut>(
        &mut self,
        r: WebSocketRequestMessage,
        decode: F,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: serde::Deserialize<'de>,
        F: FnOnce(WebSocketResponseMessage) -> Fut,
        Fut: Future<Output = Result<WebSocketResponseMessage, ServiceError>>,
    {
        self.request(r)
            .await?
            .service_error_for_status_with(decode)
            .await?
            .json()
            .await
    }
}

impl WebSocketResponseMessage {
    pub async fn json<T: for<'a> serde::Deserialize<'a>>(
        &self,
    ) -> Result<T, ServiceError> {
        self.body
            .as_ref()
            .ok_or(ServiceError::UnsupportedContent)
            .and_then(|b| serde_json::from_slice(b).map_err(Into::into))
    }
}
