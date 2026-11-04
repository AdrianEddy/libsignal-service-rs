//! The message pipe with deferred answers: a delivery stays queued on the
//! server until its handle answers it, batches take what is buffered, and the
//! socket's request stream is bounded.

mod common;

use std::{num::NonZeroUsize, rc::Rc};

use bytes::Bytes;
use futures::{
    executor::LocalPool,
    future::{FutureExt as _, RemoteHandle},
    task::LocalSpawnExt as _,
};
use libsignal_service::{
    messagepipe::{AckHandle, Incoming, MessagePipe},
    prelude::ProtobufMessage,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
    protocol::Timestamp,
    push_service::ServiceError,
    receiver::MessageReceiver,
    transport::WsEvent,
    websocket::{SocketEnd, REQUEST_STREAM_CAPACITY},
};

use common::*;

/// An open account socket, its task running on `pool`.
struct Socket {
    pool: LocalPool,
    pipe: MessagePipe,
    server: FakeServer,
    clock: Rc<ManualClock>,
    running: RemoteHandle<Result<SocketEnd, ServiceError>>,
}

impl Socket {
    fn open() -> Self {
        let mut pool = LocalPool::new();
        let (service, transport) = push_service();
        let clock = Rc::new(ManualClock::default());
        let server = transport.accept_socket(&[]);
        let (pipe, task) = pool
            .run_until(MessageReceiver::new(service).create_message_pipe(
                credentials(),
                false,
                clock.clone(),
            ))
            .unwrap();
        let running = pool.spawner().spawn_local_with_handle(task).unwrap();
        pool.run_until_stalled();
        Self {
            pool,
            pipe,
            server,
            clock,
            running,
        }
    }

    /// Lets the socket's task run until it waits.
    fn settle(&mut self) {
        self.pool.run_until_stalled();
    }

    /// The batch `next_batch(max)` returns once the task has read what the
    /// server sent; `None` if it would wait.
    fn batch(&mut self, max: usize) -> Option<Option<Vec<Incoming>>> {
        self.settle();
        self.pipe
            .next_batch(NonZeroUsize::new(max).unwrap())
            .now_or_never()
    }

    /// The deliveries in the next batch, which holds nothing else.
    fn deliveries(&mut self, max: usize) -> Vec<(Envelope, AckHandle)> {
        self.batch(max)
            .expect("a batch is buffered")
            .expect("the socket is open")
            .into_iter()
            .map(|item| match item {
                Incoming::Envelope { envelope, ack, .. } => (envelope, ack),
                other => panic!("not a delivery: {other:?}"),
            })
            .collect()
    }

    /// The answers lss sent, as (id, status, message).
    fn answers(&mut self) -> Vec<(u64, u32, String)> {
        self.settle();
        self.server
            .take_responses()
            .into_iter()
            .map(|response| {
                (
                    response.id(),
                    response.status(),
                    response.message().to_owned(),
                )
            })
            .collect()
    }

    fn ended(&mut self) -> Option<Result<SocketEnd, ServiceError>> {
        self.settle();
        (&mut self.running).now_or_never()
    }
}

/// A delivery request of the server's, with these headers.
fn delivery(
    id: u64,
    body: Option<Bytes>,
    headers: &[&str],
) -> WebSocketRequestMessage {
    WebSocketRequestMessage {
        id: Some(id),
        verb: Some("PUT".into()),
        path: Some("/api/v1/message".into()),
        body,
        headers: headers.iter().map(|&header| header.to_owned()).collect(),
    }
}

/// The `n`th envelope the server delivers.
fn envelope(n: u64) -> Envelope {
    Envelope {
        server_timestamp: Some(1_700_000_000_000 + n),
        content: Some(Bytes::from(vec![n as u8; 40])),
        ..Default::default()
    }
}

fn deliver(server: &FakeServer, id: u64, envelope: &Envelope) {
    server.request_message(delivery(
        id,
        Some(envelope.encode_to_vec().into()),
        &["X-Signal-Timestamp:1700000001000"],
    ));
}

#[test]
fn no_response_until_ack() {
    let mut socket = Socket::open();
    deliver(&socket.server, 7, &envelope(1));
    let [(delivered, ack)]: [_; 1] = socket.deliveries(32).try_into().unwrap();
    assert_eq!(delivered, envelope(1));
    assert_eq!(socket.answers(), [], "the pipe doesn't answer it");

    // However long the handle is held, the socket answers nothing for it, and
    // goes on.
    socket.clock.advance(KEEPALIVE);
    socket.settle();
    let [keepalive] = &socket.server.take_requests()[..] else {
        panic!("only the keepalive")
    };
    socket.server.respond(keepalive.id(), 200, b"");
    assert_eq!(socket.answers(), []);
    assert!(socket.ended().is_none());

    ack.ok();
    assert_eq!(socket.answers(), [(7, 200, "OK".to_owned())]);
}

#[test]
fn drop_sends_nothing() {
    let mut socket = Socket::open();
    deliver(&socket.server, 7, &envelope(1));
    let [(_, ack)]: [_; 1] = socket.deliveries(32).try_into().unwrap();

    drop(ack);
    assert_eq!(socket.answers(), [], "the server will deliver it again");

    // The socket goes on: the next delivery is answered, and the keepalive
    // still goes out.
    deliver(&socket.server, 8, &envelope(2));
    let [(_, ack)]: [_; 1] = socket.deliveries(32).try_into().unwrap();
    ack.ok();
    assert_eq!(socket.answers(), [(8, 200, "OK".to_owned())]);
    socket.clock.advance(KEEPALIVE);
    socket.settle();
    assert_eq!(socket.server.take_requests()[0].path(), "/v1/keepalive");
    assert!(socket.ended().is_none());
}

#[test]
fn fail_sends_500() {
    let mut socket = Socket::open();
    deliver(&socket.server, 7, &envelope(1));
    let [(_, ack)]: [_; 1] = socket.deliveries(32).try_into().unwrap();

    ack.fail();
    assert_eq!(
        socket.answers(),
        [(7, 500, "Internal Server Error".to_owned())]
    );
}

#[test]
fn next_batch_takes_only_buffered() {
    let mut socket = Socket::open();

    // Nothing buffered: the batch waits.
    assert!(socket.batch(32).is_none());

    // What the server sent in one go comes as one batch, in its order, and no
    // more: the batch doesn't wait to fill up. The pipe answers the requests
    // that aren't deliveries, and yields none for an unknown one.
    deliver(&socket.server, 1, &envelope(1));
    deliver(&socket.server, 2, &envelope(2));
    socket
        .server
        .request(3, "PUT", "/api/v1/queue/empty", Vec::new());
    socket.server.request(4, "PUT", "/v1/unknown", Vec::new());
    deliver(&socket.server, 5, &envelope(3));
    let batch = socket.batch(32).unwrap().unwrap();
    let [Incoming::Envelope {
        envelope: first, ..
    }, Incoming::Envelope {
        envelope: second, ..
    }, Incoming::QueueEmpty, Incoming::Envelope {
        envelope: third, ..
    }] = &batch[..]
    else {
        panic!("{batch:?}")
    };
    assert_eq!(
        [first, second, third],
        [&envelope(1), &envelope(2), &envelope(3)]
    );
    assert_eq!(
        socket.answers(),
        [
            (3, 200, "OK".to_owned()),
            (4, 400, "Bad Request".to_owned())
        ]
    );
    drop(batch);

    // At most `max`, the rest in the next batch.
    for id in 6..9 {
        deliver(&socket.server, id, &envelope(id));
    }
    let two = socket.deliveries(2);
    assert_eq!(two.len(), 2);
    assert_eq!(two[1].0, envelope(7));
    let one = socket.deliveries(32);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].0, envelope(8));
    assert!(socket.batch(32).is_none());

    // A batch that waited takes what arrived.
    deliver(&socket.server, 9, &envelope(9));
    assert_eq!(socket.deliveries(32).len(), 1);

    // Once the socket ends, so does the pipe.
    socket.server.event(Ok(WsEvent::Close {
        code: 4409,
        reason: "Connected elsewhere".into(),
    }));
    assert!(matches!(socket.batch(32), Some(None)));
}

/// A batch is one allocation, of what is buffered or of `max` if that is
/// less.
#[test]
fn a_batch_is_allocated_once() {
    let mut socket = Socket::open();
    for id in 1..=5 {
        deliver(&socket.server, id, &envelope(id));
    }
    for (max, len) in [(3, 3), (32, 2)] {
        let batch = socket.batch(max).unwrap().unwrap();
        assert_eq!((batch.len(), batch.capacity()), (len, len), "max {max}");
    }
}

/// What Signal's server leaves unanswered on a connection, besides one
/// queue-empty: its deliveries in flight (Signal-Server
/// `WebSocketConnection.java`, `MESSAGE_SENDER_MAX_CONCURRENCY`).
const SERVER_WINDOW: u64 = 256;

/// With the server's whole window waiting and nothing taken, the socket still
/// reads frames: the responses to our requests, the keepalive's answers and
/// the server's close.
#[test]
fn a_full_server_window_still_reads_responses() {
    let mut socket = Socket::open();
    let mut ws = socket.pipe.ws();
    for id in 1..=SERVER_WINDOW {
        deliver(&socket.server, id, &envelope(id));
    }
    socket.server.request(
        SERVER_WINDOW + 1,
        "PUT",
        "/api/v1/queue/empty",
        Vec::new(),
    );
    socket.settle();
    assert_eq!(socket.server.events_read(), SERVER_WINDOW as usize + 1);

    // A request of ours is answered, though no delivery was taken.
    let request = socket
        .pool
        .spawner()
        .spawn_local_with_handle(ws.request(get("/v1/devices")))
        .unwrap();
    socket.settle();
    let [sent] = &socket.server.take_requests()[..] else {
        panic!("one request")
    };
    socket.server.respond(sent.id(), 200, b"");
    socket.settle();
    let response = request.now_or_never().expect("answered").unwrap();
    assert_eq!(response.status(), 200);

    // The keepalive's answer is read too: the next interval sends another
    // keepalive instead of closing the socket.
    socket.clock.advance(KEEPALIVE);
    socket.settle();
    let [keepalive] = &socket.server.take_requests()[..] else {
        panic!("the keepalive")
    };
    socket.server.respond(keepalive.id(), 200, b"");
    socket.settle();
    socket.clock.advance(KEEPALIVE);
    socket.settle();
    let [keepalive] = &socket.server.take_requests()[..] else {
        panic!("the next keepalive")
    };
    assert_eq!(keepalive.path(), "/v1/keepalive");

    // And the server's close ends the socket as what it is.
    socket.server.event(Ok(WsEvent::Close {
        code: 4409,
        reason: "Connected elsewhere".into(),
    }));
    assert!(matches!(
        socket.ended(),
        Some(Ok(SocketEnd::Closed { code: 4409, .. }))
    ));
}

/// A full request stream, which only a server beyond its window fills, stops
/// the reading of frames, and nothing else: the keepalive, the answers and the
/// application's requests still go out.
#[test]
fn bounded_backpressure() {
    let mut socket = Socket::open();
    let mut ws = socket.pipe.ws();
    let deliveries = REQUEST_STREAM_CAPACITY as u64 + 44;
    for id in 1..=deliveries {
        deliver(&socket.server, id, &envelope(id));
    }
    socket.settle();
    assert_eq!(socket.server.events_read(), REQUEST_STREAM_CAPACITY);

    // While it is full, the keepalive and a request of ours still go out.
    let request = socket
        .pool
        .spawner()
        .spawn_local_with_handle(ws.request(get("/v1/devices")))
        .unwrap();
    socket.clock.advance(KEEPALIVE);
    socket.settle();
    let sent = socket.server.take_requests();
    let mut paths: Vec<_> = sent.iter().map(|request| request.path()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/v1/devices", "/v1/keepalive"]);
    assert_eq!(socket.server.events_read(), REQUEST_STREAM_CAPACITY);

    // Taking a batch makes room for as many frames, and the batch's answers
    // go out though the stream is full again.
    let batch = socket.deliveries(10);
    socket.settle();
    assert_eq!(socket.server.events_read(), REQUEST_STREAM_CAPACITY + 10);
    for (_, ack) in batch {
        ack.ok();
    }
    let answered: Vec<_> =
        socket.answers().into_iter().map(|(id, ..)| id).collect();
    assert_eq!(answered, (1..=10).collect::<Vec<_>>());

    // The rest arrive in order, then the response that waited behind them.
    for request in &sent {
        socket.server.respond(request.id(), 200, b"");
    }
    let mut next = 11;
    while next <= deliveries {
        for (envelope, ack) in socket.deliveries(32) {
            assert_eq!(envelope, self::envelope(next));
            next += 1;
            ack.ok();
        }
    }
    socket.settle();
    let response = request.now_or_never().expect("answered").unwrap();
    assert_eq!(response.status(), 200);
    assert!(socket.ended().is_none());
}

#[test]
fn delivered_at_from_x_signal_timestamp() {
    let mut socket = Socket::open();
    let body = Some(Bytes::from(envelope(1).encode_to_vec()));
    let cases: [(&[&str], Option<u64>); 5] = [
        (
            &["X-Signal-Timestamp:1700000000123"],
            Some(1_700_000_000_123),
        ),
        // Any case, and the value trimmed.
        (
            &["x-signal-timestamp: 1700000000456 "],
            Some(1_700_000_000_456),
        ),
        (&[], None),
        (&["X-Signal-Timestamp:soon"], None),
        // The last valid one.
        (
            &[
                "X-Signal-Timestamp:1",
                "Content-Type:application/x-protobuf",
                "X-Signal-Timestamp:3",
                "X-Signal-Timestamp:",
            ],
            Some(3),
        ),
    ];
    for (id, (headers, _)) in cases.iter().enumerate() {
        socket.server.request_message(delivery(
            id as u64,
            body.clone(),
            headers,
        ));
    }
    let batch = socket.batch(32).unwrap().unwrap();
    assert_eq!(batch.len(), cases.len());
    for (item, (headers, expected)) in batch.iter().zip(&cases) {
        let Incoming::Envelope { delivered_at, .. } = item else {
            panic!("{item:?}")
        };
        assert_eq!(
            *delivered_at,
            expected.map(Timestamp::from_epoch_millis),
            "{headers:?}"
        );
    }
}

/// From the frame to the ciphertext, nothing is copied.
#[test]
fn envelope_content_is_a_slice_of_the_frame() {
    let mut socket = Socket::open();
    let frame = Bytes::from(
        WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request.into()),
            request: Some(delivery(
                7,
                Some(envelope(1).encode_to_vec().into()),
                &[],
            )),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    socket.server.event(Ok(WsEvent::Binary(frame.clone())));

    let [(delivered, _)] = &socket.deliveries(32)[..] else {
        panic!("one delivery")
    };
    let content = delivered.content.as_ref().expect("content");
    assert_eq!(content, envelope(1).content.as_ref().unwrap());
    let frame = frame.as_ptr_range();
    let content = content.as_ptr_range();
    assert!(
        frame.start <= content.start && content.end <= frame.end,
        "the content is in the frame's buffer"
    );
}

/// A delivery that isn't an envelope is the consumer's to answer too, so that
/// it can drop it from the queue.
#[test]
fn a_malformed_delivery_waits_for_its_answer() {
    let mut socket = Socket::open();
    socket.server.request_message(delivery(
        7,
        Some(Bytes::from_static(&[0xff, 0xff, 0xff])),
        &[],
    ));
    // No body: an empty envelope, which carries nothing.
    socket.server.request_message(delivery(8, None, &[]));
    let batch = socket.batch(32).unwrap().unwrap();
    let [Incoming::Malformed { ack: malformed, .. }, Incoming::Envelope {
        envelope: empty, ..
    }] = &batch[..]
    else {
        panic!("{batch:?}")
    };
    assert_eq!(*empty, Envelope::default());
    assert_eq!(format!("{malformed:?}"), "AckHandle { id: Some(7) }");
    assert_eq!(socket.answers(), []);

    let mut batch = batch.into_iter();
    let Some(Incoming::Malformed { ack, .. }) = batch.next() else {
        unreachable!()
    };
    ack.ok();
    assert_eq!(socket.answers(), [(7, 200, "OK".to_owned())]);
}

/// The socket ends, released, once every handle is gone and each delivery has
/// been answered or its handle dropped: an answer still held reaches the
/// server.
#[test]
fn released_once_every_delivery_is_answered() {
    for answer in [true, false] {
        let mut socket = Socket::open();
        deliver(&socket.server, 7, &envelope(1));
        let [(_, ack)]: [_; 1] = socket.deliveries(32).try_into().unwrap();

        let Socket {
            mut pool,
            pipe,
            mut server,
            running,
            ..
        } = socket;
        drop(pipe);
        pool.run_until_stalled();
        assert!(server.is_open(), "the handle's answer may still come");

        if answer {
            ack.ok();
        } else {
            drop(ack);
        }
        pool.run_until_stalled();
        let answers: Vec<_> = server
            .take_responses()
            .iter()
            .map(WebSocketResponseMessage::id)
            .collect();
        assert_eq!(answers, if answer { vec![7] } else { vec![] });
        assert_eq!(
            running.now_or_never().expect("the task ended").unwrap(),
            SocketEnd::Released
        );
        assert!(!server.is_open());
    }
}

/// With the pipe gone and handles left, Signal's requests go unanswered, so
/// the server keeps them queued, and the socket serves the handles.
#[test]
fn a_delivery_nobody_takes_goes_unanswered() {
    let socket = Socket::open();
    let mut ws = socket.pipe.ws();
    let Socket {
        mut pool,
        pipe,
        mut server,
        mut running,
        ..
    } = socket;
    drop(pipe);
    deliver(&server, 7, &envelope(1));
    pool.run_until_stalled();
    assert_eq!(server.take_sent(), []);
    assert!((&mut running).now_or_never().is_none());

    let request = pool
        .spawner()
        .spawn_local_with_handle(ws.request(get("/v1/devices")))
        .unwrap();
    pool.run_until_stalled();
    let [sent] = &server.take_requests()[..] else {
        panic!("one request")
    };
    server.respond(sent.id(), 200, b"");
    pool.run_until_stalled();
    assert_eq!(request.now_or_never().unwrap().unwrap().status(), 200);

    drop(ws);
    pool.run_until_stalled();
    assert_eq!(
        running.now_or_never().unwrap().unwrap(),
        SocketEnd::Released
    );
}
