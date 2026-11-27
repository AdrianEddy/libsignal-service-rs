//! A socket's request ids come from the caller's generator: a generator of
//! one seed sends one run of ids, the keepalives' included, so a caller that
//! seeds its randomness replays its socket's traffic; what is ready at one
//! poll of the socket's task goes in the socket's order, not in one picked at
//! random; and a caller's id that a request in flight has is drawn again from
//! the generator.

mod common;

use std::{rc::Rc, task::Context};

use futures::{
    executor::LocalPool,
    future::{FutureExt as _, RemoteHandle},
    task::{noop_waker_ref, LocalSpawnExt as _},
    StreamExt as _,
};
use http::Method;
use libsignal_service::{
    proto::{
        WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
    },
    push_service::ServiceError,
    transport::WsEvent,
    websocket::{Identified, SignalWebSocket, SocketEnd},
};
use rand::{rngs::StdRng, SeedableRng as _};

use common::*;

/// The account's authenticated socket, opened with a generator seeded with
/// `seed`, its task running on `pool`.
struct Socket {
    pool: LocalPool,
    clock: Rc<ManualClock>,
    server: FakeServer,
    ws: SignalWebSocket<Identified>,
    /// The socket's task, which resolves to why the socket ended.
    running: RemoteHandle<Result<SocketEnd, ServiceError>>,
    /// The requests in flight, kept so that their ids stay taken.
    waiting: Vec<RemoteHandle<Result<WebSocketResponseMessage, ServiceError>>>,
}

impl Socket {
    fn open(seed: u64) -> Socket {
        let mut pool = LocalPool::new();
        let clock = Rc::new(ManualClock::default());
        let (service, transport) = push_service();
        let server = transport.accept_socket(&[]);
        let (ws, task) = pool
            .run_until(service.ws::<Identified>(
                "/v1/websocket/",
                "/v1/keepalive",
                &[],
                Some(credentials()),
                &mut StdRng::seed_from_u64(seed),
                clock.clone(),
            ))
            .unwrap();
        let running = pool.spawner().spawn_local_with_handle(task).unwrap();
        pool.run_until_stalled();
        Socket {
            pool,
            clock,
            server,
            ws,
            running,
            waiting: Vec::new(),
        }
    }

    /// Sends `request` and leaves it unanswered: the id it went out with.
    fn send(&mut self, request: WebSocketRequestMessage) -> u64 {
        let waiting = self
            .pool
            .spawner()
            .spawn_local_with_handle(self.ws.request(request))
            .unwrap();
        self.waiting.push(waiting);
        self.pool.run_until_stalled();
        let [sent] = &self.server.take_requests()[..] else {
            panic!("one request")
        };
        sent.id()
    }

    /// Lets the keepalive's interval pass: the keepalive's id.
    fn keepalive(&mut self) -> u64 {
        self.clock.advance(KEEPALIVE);
        self.pool.run_until_stalled();
        let [keepalive] = &self.server.take_requests()[..] else {
            panic!("one keepalive")
        };
        assert_eq!(keepalive.path(), "/v1/keepalive");
        keepalive.id()
    }
}

/// A request with the id `id`.
fn with_id(id: u64) -> WebSocketRequestMessage {
    WebSocketRequestMessage::new(Method::GET)
        .id(id)
        .path("/v1/devices")
        .build()
}

/// The ids a socket of `seed` sends: two requests without an id, the
/// keepalive while both are in flight, then the keepalive after it was
/// answered.
fn ids_of(seed: u64) -> Vec<u64> {
    let mut socket = Socket::open(seed);
    let first = socket.send(get("/v1/first"));
    let second = socket.send(get("/v1/second"));
    let keepalive = socket.keepalive();
    socket.server.respond(keepalive, 200, b"");
    socket.pool.run_until_stalled();
    let next = socket.keepalive();
    assert!(
        socket
            .waiting
            .iter_mut()
            .all(|w| w.now_or_never().is_none()),
        "both requests are still in flight"
    );
    vec![first, second, keepalive, next]
}

/// Two sockets opened with generators of one seed send the same ids, the
/// keepalives' included; a socket of another seed sends others.
#[test]
fn a_seeded_socket_sends_the_same_ids() {
    let ids = ids_of(7);
    assert_eq!(ids, ids_of(7), "one seed, one run of ids");
    let mut distinct = ids.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), ids.len(), "every id its own: {ids:?}");
    let other = ids_of(8);
    assert!(
        ids.iter().all(|id| !other.contains(id)),
        "another seed, other ids: {ids:?} and {other:?}"
    );
}

/// A frame the socket sent: a request's path and id, or an answer's id.
#[derive(Debug, PartialEq)]
enum Out {
    Request(String, u64),
    Answer(u64),
}

impl From<Sent> for Out {
    fn from(sent: Sent) -> Out {
        match sent {
            Sent::Frame(WebSocketMessage {
                request: Some(request),
                ..
            }) => Out::Request(request.path().to_owned(), request.id()),
            Sent::Frame(WebSocketMessage {
                response: Some(response),
                ..
            }) => Out::Answer(response.id()),
            other => panic!("not a request or an answer: {other:?}"),
        }
    }
}

/// What a socket of seed 7 sends when its task finds everything ready at
/// one poll: the keepalive due, an answer to Signal's request, the
/// application's request and the server's close; and how the task ended.
fn all_ready_at_one_poll() -> (Vec<Out>, Option<SocketEnd>) {
    // `open` ran the task once, which armed the keepalive's wait.
    let mut socket = Socket::open(7);
    // Signal's request, read by the task and answered by hand: the answer
    // waits for the task.
    socket
        .server
        .request(9, "PUT", "/api/v1/message", Vec::new());
    socket.pool.run_until_stalled();
    let (_, responder) = socket
        .ws
        .with_request_stream(|requests| requests.next().now_or_never())
        .now_or_never()
        .flatten()
        .flatten()
        .expect("Signal's request");
    responder
        .send(WebSocketResponseMessage {
            id: Some(9),
            status: Some(200),
            ..Default::default()
        })
        .unwrap();
    // One poll of the application's request puts it in the socket's
    // channel: the task is woken, not run.
    let mut request = socket.ws.request(get("/v1/first")).boxed_local();
    assert!(request
        .poll_unpin(&mut Context::from_waker(noop_waker_ref()))
        .is_pending());
    socket.clock.advance(KEEPALIVE);
    socket.server.event(Ok(WsEvent::Close {
        code: 1000,
        reason: "Closed".into(),
    }));
    socket.pool.run_until_stalled();
    let sent = socket
        .server
        .take_sent()
        .into_iter()
        .map(Out::from)
        .collect();
    (
        sent,
        (&mut socket.running).now_or_never().map(Result::unwrap),
    )
}

/// What is ready at one poll of the socket's task goes in the socket's
/// order, not in one picked at random: the keepalive, the answer to Signal,
/// the application's request, then the server's frame, here its close. So
/// the keepalive takes the seed's first id and the request its second, in
/// every run.
#[test]
fn what_is_ready_at_one_poll_goes_in_the_sockets_order() {
    // What the generator of seed 7 draws: the keepalive's id, then the next.
    let (first, second) = {
        let mut socket = Socket::open(7);
        (socket.keepalive(), socket.send(get("/v1/next")))
    };
    let order = [
        Out::Request("/v1/keepalive".into(), first),
        Out::Answer(9),
        Out::Request("/v1/first".into(), second),
    ];
    let closed = SocketEnd::Closed {
        code: 1000,
        reason: "Closed".into(),
    };
    // Picked at random, a run would go in this order once in 24.
    for _ in 0..16 {
        let (sent, end) = all_ready_at_one_poll();
        assert_eq!(sent, order, "the keepalive, the answer, the request");
        assert_eq!(end, Some(closed.clone()), "then the server's close");
    }
}

/// A caller's id goes out as it is unless a request in flight has it, the
/// keepalive's included: then the socket's generator draws another, the next
/// id it would have drawn for a request without one.
#[test]
fn a_callers_id_in_flight_is_drawn_again() {
    // What the generator of seed 3 draws: the keepalive's id, then the next.
    let (keepalive, next) = {
        let mut socket = Socket::open(3);
        (socket.keepalive(), socket.send(get("/v1/next")))
    };

    let mut socket = Socket::open(3);
    assert_eq!(socket.send(with_id(42)), 42, "an id no request has");
    assert_eq!(socket.keepalive(), keepalive, "42 drew nothing");
    let again = socket.send(with_id(keepalive));
    assert_ne!(again, keepalive, "the keepalive in flight has it");
    assert_eq!(again, next, "drawn from the socket's generator");
    let twice = socket.send(with_id(42));
    assert!(![42, keepalive, next].contains(&twice), "42 is in flight");

    // Answered, an id is free again.
    socket.server.respond(42, 200, b"");
    socket.pool.run_until_stalled();
    assert_eq!(socket.send(with_id(42)), 42);
}
