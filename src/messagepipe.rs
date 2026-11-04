use std::{
    fmt,
    num::NonZeroUsize,
    pin::Pin,
    task::{ready, Context, Poll},
};

use futures::{channel::oneshot, future, prelude::*};
use http::StatusCode;
use libsignal_protocol::Timestamp;
use prost::Message;

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::websocket::{self, SignalRequestStream, SignalWebSocket};

/// The header that says when the server delivered a message, in milliseconds
/// since the epoch.
const DELIVERY_TIMESTAMP_HEADER: &str = "x-signal-timestamp";

/// What the server sends the account's socket.
///
/// A delivery stays queued on the server until its [`AckHandle`] answers it.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "an envelope moves once, from the pipe to its decrypt; a box would cost an allocation per message"
)]
pub enum Incoming {
    /// A delivered envelope. Make what it carries durable, then answer it
    /// with [`AckHandle::ok`].
    Envelope {
        envelope: Envelope,
        /// When the server delivered it (its `X-Signal-Timestamp` header), by
        /// the server's clock. `None` if the header is missing or invalid.
        delivered_at: Option<Timestamp>,
        ack: AckHandle,
    },
    /// A delivery whose body doesn't decode as an envelope. Nothing can read
    /// it, now or later: answering it with [`AckHandle::ok`] drops it from the
    /// queue, and any other answer keeps it there.
    Malformed {
        error: prost::DecodeError,
        ack: AckHandle,
    },
    /// The server has delivered every message it held for this device when
    /// the socket opened; what follows arrived since.
    QueueEmpty,
}

/// The answer to one delivery. The server deletes the message once it reads a
/// 2xx answer; after any other answer, or none, it keeps the message queued and
/// sends it again on a later connection, never on this one.
///
/// Dropping the handle answers nothing. While a handle is held, the socket
/// stays open for its answer, even once every [`SignalWebSocket`] handle is
/// gone.
pub struct AckHandle {
    /// The id of the delivery request, which the answer repeats.
    id: Option<u64>,
    responder: oneshot::Sender<WebSocketResponseMessage>,
}

impl AckHandle {
    /// Answers 200: the server deletes the message.
    pub fn ok(self) {
        self.answer(StatusCode::OK);
    }

    /// Answers 500: the server keeps the message queued.
    pub fn fail(self) {
        self.answer(StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn answer(self, status: StatusCode) {
        // The socket's task holds the receiver until it ends; after that, no
        // answer can reach the server, which keeps the message queued.
        let _ = self.responder.send(response(self.id, status));
    }
}

impl fmt::Debug for AckHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AckHandle").field("id", &self.id).finish()
    }
}

/// The answer to request `id` with `status`.
fn response(id: Option<u64>, status: StatusCode) -> WebSocketResponseMessage {
    WebSocketResponseMessage {
        id,
        status: Some(status.as_u16().into()),
        message: status.canonical_reason().map(str::to_owned),
        headers: Vec::new(),
        body: None,
    }
}

/// When the server delivered a message: the last valid `X-Signal-Timestamp`
/// header, read as libsignal-net reads it (`rust/net/src/chat/
/// server_requests.rs`).
fn delivered_at(headers: &[String]) -> Option<Timestamp> {
    headers
        .iter()
        .filter_map(|header| {
            let (name, value) = header.split_once(':')?;
            if name.eq_ignore_ascii_case(DELIVERY_TIMESTAMP_HEADER) {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .next_back()
        .map(Timestamp::from_epoch_millis)
}

/// What a request of Signal's is to the pipe. The pipe answers every request
/// but the deliveries, whose answers are their [`AckHandle`]s'.
fn incoming(
    request: WebSocketRequestMessage,
    responder: oneshot::Sender<WebSocketResponseMessage>,
) -> Option<Incoming> {
    if request.is_signal_service_envelope() {
        let ack = AckHandle {
            id: request.id,
            responder,
        };
        let delivered_at = delivered_at(&request.headers);
        // A delivery without a body decodes as an empty envelope, which
        // carries nothing.
        Some(match Envelope::decode(request.body.unwrap_or_default()) {
            Ok(envelope) => Incoming::Envelope {
                envelope,
                delivered_at,
                ack,
            },
            Err(error) => Incoming::Malformed { error, ack },
        })
    } else if request.is_queue_empty() {
        let _ = responder.send(response(request.id, StatusCode::OK));
        Some(Incoming::QueueEmpty)
    } else {
        tracing::warn!(
            verb = request.verb(),
            path = request.path(),
            "unknown request from Signal; answered 400"
        );
        let _ = responder.send(response(request.id, StatusCode::BAD_REQUEST));
        None
    }
}

/// The account's message pipe: what the server sends its socket, as a
/// [`Stream`] of [`Incoming`] that ends with the socket.
///
/// The pipe answers no delivery itself: each comes with its [`AckHandle`].
pub struct MessagePipe {
    ws: SignalWebSocket<websocket::Identified>,
    requests: SignalRequestStream,
}

impl MessagePipe {
    /// The pipe of `ws`. It takes the socket's request stream.
    ///
    /// # Panics
    ///
    /// If something else has taken the request stream (see
    /// [`SignalWebSocket::is_used`]).
    pub fn from_socket(mut ws: SignalWebSocket<websocket::Identified>) -> Self {
        let requests = ws
            .take_request_stream()
            .expect("web socket request handler not in use");
        MessagePipe { ws, requests }
    }

    /// Return a SignalWebSocket for sending messages and other purposes beyond receiving messages.
    pub fn ws(&self) -> SignalWebSocket<websocket::Identified> {
        self.ws.clone()
    }

    /// The next batch: waits for one item, then takes what is already
    /// buffered, without waiting again, up to `max` items in all. `None` once
    /// the socket has ended and every item was taken.
    ///
    /// A batch keeps the server's order, so an [`Incoming::QueueEmpty`] can
    /// sit between deliveries. Cancel-safe: a batch is taken whole in the poll
    /// that returns it.
    pub async fn next_batch(
        &mut self,
        max: NonZeroUsize,
    ) -> Option<Vec<Incoming>> {
        let first = future::poll_fn(|cx| self.poll_incoming(cx)).await?;
        // One allocation, for what is already buffered. An unknown request,
        // which the pipe answers itself and yields no item for, only leaves
        // a reserved slot unused.
        let buffered = self.requests.size_hint().0;
        let mut batch = Vec::with_capacity(1 + buffered.min(max.get() - 1));
        batch.push(first);
        while batch.len() < max.get() {
            let Some(item) = self.try_next_buffered() else {
                break;
            };
            batch.push(item);
        }
        Some(batch)
    }

    fn poll_incoming(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Incoming>> {
        loop {
            let Some((request, responder)) =
                ready!(self.requests.poll_next_unpin(cx))
            else {
                return Poll::Ready(None);
            };
            if let Some(item) = incoming(request, responder) {
                return Poll::Ready(Some(item));
            }
        }
    }

    /// The next item already buffered, without waiting for one.
    fn try_next_buffered(&mut self) -> Option<Incoming> {
        loop {
            let (request, responder) = self.requests.try_next_buffered()?;
            if let Some(item) = incoming(request, responder) {
                return Some(item);
            }
        }
    }
}

impl Stream for MessagePipe {
    type Item = Incoming;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Incoming>> {
        self.get_mut().poll_incoming(cx)
    }
}
