//! The capability registration of a linked device.

mod common;

use std::{collections::BTreeMap, rc::Rc};

use futures::{
    executor::LocalPool,
    future::{self, FutureExt as _},
    task::LocalSpawnExt as _,
};
use libsignal_service::{push_service::ServiceError, websocket::Identified};

use common::*;

/// The request is the whole map as Signal-Server's
/// `DeviceController.setCapabilities` reads it, a JSON object of names and
/// booleans, those that are `false` included, and its 204 has no body. A
/// refusal is an error.
#[test]
fn capabilities_go_as_the_map_signal_server_reads() {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let mut server = transport.accept_socket(&[]);
    let (mut ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            &mut rand::rng(),
            Rc::new(ManualClock::default()),
        ))
        .unwrap();
    pool.spawner().spawn_local(task.map(drop)).unwrap();
    let capabilities: BTreeMap<String, bool> = [
        ("attachmentBackfill".to_owned(), false),
        ("optionalPhoneNumber".to_owned(), true),
        ("spqr".to_owned(), true),
    ]
    .into();

    for (status, taken) in [(204, true), (401, false)] {
        let (set, request) = pool.run_until(future::join(
            ws.set_capabilities(&capabilities),
            async {
                let request = sent_request(server.next_sent().await);
                server.respond(request.id(), status, b"");
                request
            },
        ));
        assert_eq!(
            (request.verb(), request.path()),
            ("PUT", "/v1/devices/capabilities")
        );
        assert_eq!(request.headers, ["content-type:application/json"]);
        let body: serde_json::Value =
            serde_json::from_slice(request.body()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "attachmentBackfill": false,
                "optionalPhoneNumber": true,
                "spqr": true,
            })
        );
        if taken {
            set.unwrap();
        } else {
            assert!(matches!(set, Err(ServiceError::Unauthorized)), "{set:?}");
        }
    }
}
