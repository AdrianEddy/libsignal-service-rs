//! The seams through which lss reaches the network and the clock.
//!
//! lss sends every HTTP request and opens every WebSocket through a
//! [`Transport`] the application provides, and reads the time and waits on
//! timers through a [`Clock`] the application passes in. The transport owns
//! connections, TLS and each service's trust roots, proxies, framing,
//! timeouts and the `User-Agent`; a request the server holds sets its own wait
//! for the response head ([`HttpRequest::timeout`]). lss spawns no task: a
//! socket's task is returned to the caller, who runs it.

use std::{
    error::Error,
    fmt, io,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use futures::{future::LocalBoxFuture, stream::LocalBoxStream, Stream};
use http::{HeaderMap, Method, StatusCode};
use url::{Position, Url};

/// Carries lss's HTTP requests and WebSockets.
///
/// The futures borrow the transport and need not be `Send`, so an
/// implementation may keep `!Send` state.
pub trait Transport: 'static {
    /// Sends `request` and resolves once the response head has arrived; the
    /// body streams after that. Every status comes back as a response, 3xx
    /// included: the transport follows no redirects, so neither the
    /// `Authorization` header nor `endpoint`'s trust reaches another host.
    fn request(
        &self,
        request: HttpRequest,
    ) -> LocalBoxFuture<'_, Result<HttpResponse, TransportError>>;

    /// Opens a WebSocket.
    fn websocket(
        &self,
        request: WsConnect,
    ) -> LocalBoxFuture<'_, Result<WsUpgrade, TransportError>>;
}

/// An HTTP request.
///
/// lss sets no framing headers: the transport sends `Content-Length` from
/// `body`, replacing any in `headers`, and `0` for [`HttpBody::Empty`] only on
/// methods that carry content (POST, PUT, PATCH).
///
/// `Debug` leaves out what can carry a credential: the URL's user
/// information, query and fragment, and every header value marked sensitive,
/// as lss marks each `Authorization` it sets.
#[derive(derive_more::Debug)]
pub struct HttpRequest {
    pub method: Method,
    #[debug("{}", RedactedUrl(url))]
    pub url: Url,
    pub headers: HeaderMap,
    pub body: HttpBody,
    pub endpoint: EndpointKind,
    /// How long the transport waits for the response head once the whole
    /// request, body included, has been sent; `None` is the transport's
    /// default for `endpoint`. A request the server holds, such as a long
    /// poll, sets it above the hold time. Neither the request body nor the
    /// response body has a total deadline: transfers take as long as they
    /// take, and a stalled connection is the transport's to detect.
    pub timeout: Option<Duration>,
}

/// A URL for logs: its scheme, host, port and path, without the user
/// information, query or fragment, where a credential can be; the query of a
/// signed upload location is one.
pub(crate) struct RedactedUrl<'a>(pub(crate) &'a Url);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0[..Position::BeforeUsername])?;
        f.write_str(&self.0[Position::BeforeHost..Position::AfterPath])
    }
}

/// The Signal service a request is for, so the transport can pick its
/// settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    /// The chat service.
    Chat,
    /// The storage service.
    Storage,
    /// A CDN by Signal's number for it, including the upload locations it
    /// hands out.
    Cdn(u32),
}

pub enum HttpBody {
    Empty,
    Bytes(Bytes),
    /// Exactly `len` bytes.
    Stream {
        len: u64,
        stream: LocalBoxStream<'static, io::Result<Bytes>>,
    },
}

impl fmt::Debug for HttpBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            Self::Stream { len, .. } => write!(f, "Stream({len} bytes)"),
        }
    }
}

impl From<Bytes> for HttpBody {
    fn from(bytes: Bytes) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<Vec<u8>> for HttpBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes.into())
    }
}

pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// Ends after the last byte; an error means the body broke off.
    pub body: LocalBoxStream<'static, Result<Bytes, TransportError>>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

/// A WebSocket handshake to a `wss://` URL.
///
/// `Debug` leaves out what can carry a credential, as [`HttpRequest`]'s does.
#[derive(derive_more::Debug)]
pub struct WsConnect {
    #[debug("{}", RedactedUrl(url))]
    pub url: Url,
    pub headers: HeaderMap,
}

/// An open WebSocket, with the headers of the response that upgraded it.
pub struct WsUpgrade {
    pub headers: HeaderMap,
    pub connection: Box<dyn WsConnection>,
}

/// One open WebSocket. Only binary frames and the peer's Close reach lss;
/// the transport answers pings and the peer's Close. The stream yields
/// `None` once the connection has ended. Dropping it closes the connection.
pub trait WsConnection:
    Stream<Item = Result<WsEvent, TransportError>> + Unpin
{
    /// Sends one binary frame.
    fn send(
        &mut self,
        frame: Bytes,
    ) -> LocalBoxFuture<'_, Result<(), TransportError>>;

    /// Sends a Close frame with `code` (RFC 6455 §5.5.1). Resolves once the
    /// frame is handed to the connection, or that fails, and never waits for
    /// the peer's Close: lss drops the connection next.
    fn close(
        &mut self,
        code: u16,
    ) -> LocalBoxFuture<'_, Result<(), TransportError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    Binary(Bytes),
    /// The peer closed the connection.
    Close {
        code: u16,
        reason: String,
    },
}

/// A failure below HTTP: no response came, or it broke off.
///
/// It displays as its kind alone. The implementation's own error, if it gave
/// one, is the [`source`](Error::source) and nowhere else, so a caller can
/// downcast to it and an error-chain printer shows it once.
#[derive(Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// No connection was made (name resolution, TCP, TLS or a proxy,
    /// including a deadline that passed while connecting), so nothing was
    /// sent.
    Connect,
    /// A deadline passed after the connection was made: the request may have
    /// been sent and processed.
    Timeout,
    /// The connection ended after the request had started, or while the
    /// response was read.
    Closed,
    /// The server answered a WebSocket handshake with this status instead of
    /// `101`.
    Rejected(StatusCode),
    /// Any other failure, such as the transport refusing the destination.
    Other,
}

impl TransportError {
    pub fn new(
        kind: TransportErrorKind,
        source: impl Into<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn get_ref(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    pub fn into_inner(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }
}

impl From<TransportErrorKind> for TransportError {
    fn from(kind: TransportErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("could not connect"),
            Self::Timeout => f.write_str("timed out"),
            Self::Closed => f.write_str("connection closed early"),
            Self::Rejected(status) => {
                write!(f, "WebSocket handshake rejected with HTTP {status}")
            },
            Self::Other => f.write_str("transport failed"),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

impl From<TransportError> for io::Error {
    fn from(error: TransportError) -> Self {
        let kind = match error.kind {
            TransportErrorKind::Connect => io::ErrorKind::NotConnected,
            TransportErrorKind::Timeout => io::ErrorKind::TimedOut,
            TransportErrorKind::Closed => io::ErrorKind::ConnectionAborted,
            TransportErrorKind::Rejected(_) | TransportErrorKind::Other => {
                io::ErrorKind::Other
            },
        };
        io::Error::new(kind, error)
    }
}

/// The time, for the timestamps lss writes and its checks of session and
/// prekey age, and the timer of a WebSocket's keepalive.
pub trait Clock {
    fn now(&self) -> SystemTime;

    /// Resolves once `duration` has passed. Dropping the future cancels the
    /// wait.
    fn sleep(&self, duration: Duration) -> LocalBoxFuture<'static, ()>;
}
