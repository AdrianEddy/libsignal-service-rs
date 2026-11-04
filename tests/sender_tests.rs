//! SF10's send primitives: the sync transcript and the PNI signature as free
//! functions, `ServiceCipher::encrypt` on a store that is not `Sync`, on the
//! sessions the official clients send on, and the prekey fetch of a
//! sealed-sender send.

mod common;

use std::{
    rc::Rc,
    time::{Duration, SystemTime},
};

use base64::prelude::*;
use futures::{
    executor::{block_on, LocalPool},
    future::{self, FutureExt as _},
    task::LocalSpawnExt as _,
};
use http::header;
use libsignal_service::{
    cipher::ServiceCipher,
    content::ContentBody,
    envelope::Envelope,
    prelude::ProtobufMessage,
    proto::{
        self, envelope::Type, DataMessage, EditMessage, SyncMessage,
        WebSocketRequestMessage,
    },
    protocol::{
        process_prekey_bundle, Aci, DeviceId, IdentityKeyPair,
        IdentityKeyStore as _, KeyPair, Pni, PreKeyBundle, SenderCertificate,
        ServerCertificate, ServiceId, SessionRecord, SessionStore as _,
        SessionUsabilityRequirements, SignalProtocolError, Timestamp,
    },
    push_service::ServiceError,
    sender::{pni_signature, sent_transcript, MessageSender, SentMessage},
    session_store::has_usable_session,
    transport::Clock as _,
    unidentified_access::UnidentifiedAccess,
    websocket::{Identified, SignalWebSocket, Unidentified},
    ServiceIdExt as _,
};
use uuid::Uuid;

use common::{
    store::{LocalStore, SyncStore},
    *,
};

fn device(id: u8) -> DeviceId {
    DeviceId::new(id).unwrap()
}

/// The server's answer to `GET /v2/keys/{service id}/*`: the bundle of one
/// device.
fn keys_response(bundle: &PreKeyBundle) -> Vec<u8> {
    let base64 = |bytes: &[u8]| BASE64_STANDARD.encode(bytes);
    serde_json::to_vec(&serde_json::json!({
        "identityKey": base64(&bundle.identity_key().unwrap().serialize()),
        "devices": [{
            "deviceId": u8::from(bundle.device_id().unwrap()),
            "registrationId": bundle.registration_id().unwrap(),
            "signedPreKey": {
                "keyId": u32::from(bundle.signed_pre_key_id().unwrap()),
                "publicKey": base64(&bundle.signed_pre_key_public().unwrap().serialize()),
                "signature": base64(bundle.signed_pre_key_signature().unwrap()),
            },
            "pqPreKey": {
                "keyId": u32::from(bundle.kyber_pre_key_id().unwrap()),
                "publicKey": base64(&bundle.kyber_pre_key_public().unwrap().serialize()),
                "signature": base64(bundle.kyber_pre_key_signature().unwrap()),
            },
        }],
    }))
    .unwrap()
}

/// `sync` without its padding, which must be there: 1 to 512 random bytes.
fn unpadded(mut sync: SyncMessage) -> SyncMessage {
    let padding = sync.padding.take().expect("padding");
    assert!((1..=512).contains(&padding.len()), "{}", padding.len());
    sync
}

/// The transcript the free function makes equals the one `MessageSender`
/// sends our other devices. It ran first against the method the function
/// replaced, on a `Sync` store, as only a `MessageSender` can hold one; the
/// sender now calls the function, and this keeps the two in step. The
/// message goes out after it was composed, and the expiration starts then,
/// at the time of the sender's clock.
#[test]
fn sent_transcript_free_fn_equals_method_output() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let rng = &mut rand::rng();
    let clock = Rc::new(ManualClock::default());
    let timestamp = 1_700_000_000_000;
    clock.advance(Duration::from_secs(90));
    let sent_at = timestamp + 90_000;
    assert_eq!(
        clock.now(),
        SystemTime::UNIX_EPOCH + Duration::from_millis(sent_at)
    );
    let (service, transport) = push_service();
    let mut server = transport.accept_socket(&[]);
    let _unidentified_server = transport.accept_socket(&[]);
    let (identified, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            clock.clone(),
        ))
        .unwrap();
    spawner.spawn_local(task.map(drop)).unwrap();
    let (unidentified, task) = pool
        .run_until(service.ws::<Unidentified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            None,
            clock.clone(),
        ))
        .unwrap();
    spawner.spawn_local(task.map(drop)).unwrap();

    // We are device 2 of our account, whose devices share its identity.
    let our_aci = Aci::from(ACI);
    let account = IdentityKeyPair::generate(rng);
    let ours = SyncStore::new(account, 22);
    let primary = LocalStore::new(account, 11);
    let primary_bundle = pool.run_until(primary.bundle(device(1)));
    let peer_aci = Aci::from(Uuid::from_u128(0x5eed));
    let peer = LocalStore::new(IdentityKeyPair::generate(rng), 33);
    let peer_bundle = pool.run_until(peer.bundle(device(1)));

    let cipher = ServiceCipher::new(
        ours.clone(),
        vec![],
        our_aci.to_protocol_address(device(2)).unwrap(),
        clock.clone(),
    );
    let mut sender = MessageSender::new(
        identified,
        unidentified,
        service,
        cipher,
        ours,
        our_aci,
        Pni::from(Uuid::from_u128(0x9e)),
        account,
        None,
        device(2),
    );
    let message = DataMessage {
        body: Some("hello".into()),
        timestamp: Some(timestamp),
        expire_timer: Some(3600),
        expire_timer_version: Some(2),
        ..Default::default()
    };
    let peer_id = ServiceId::from(peer_aci);
    let sending = spawner
        .spawn_local_with_handle({
            let message = message.clone();
            async move {
                sender
                    .send_message(
                        &peer_id, None, message, timestamp, false, false,
                    )
                    .await
            }
        })
        .unwrap();

    // The server hands out each account's bundle and takes every message.
    let mut transcript = None;
    loop {
        pool.run_until_stalled();
        let requests = server.take_requests();
        if requests.is_empty() {
            break;
        }
        for request in requests {
            let keys =
                |aci: Aci| format!("/v2/keys/{}/*", aci.service_id_string());
            let messages =
                |aci: Aci| format!("/v1/messages/{}", aci.service_id_string());
            let body = match (request.verb(), request.path()) {
                ("GET", path) if path == keys(peer_aci) => {
                    keys_response(&peer_bundle)
                },
                ("GET", path) if path == keys(our_aci) => {
                    keys_response(&primary_bundle)
                },
                ("PUT", path) if path == messages(peer_aci) => {
                    br#"{"needsSync":false}"#.to_vec()
                },
                ("PUT", path) if path == messages(our_aci) => {
                    transcript = Some(request.body().to_vec());
                    br#"{"needsSync":false}"#.to_vec()
                },
                other => panic!("unexpected request {other:?}"),
            };
            server.respond(request.id(), 200, &body);
        }
    }
    let sent = sending.now_or_never().expect("sent").unwrap();

    // Our primary opens what reached it.
    let transcript: serde_json::Value =
        serde_json::from_slice(&transcript.expect("a transcript")).unwrap();
    let [to_primary] = transcript["messages"].as_array().unwrap().as_slice()
    else {
        panic!("{transcript}")
    };
    assert_eq!(to_primary["destinationDeviceId"], 1);
    let envelope = Envelope {
        r#type: Some(to_primary["type"].as_i64().unwrap() as i32),
        source_service_id: Some(our_aci.service_id_string()),
        source_device_id: Some(2),
        destination_service_id: Some(our_aci.service_id_string()),
        client_timestamp: Some(timestamp),
        server_timestamp: Some(timestamp + 1),
        content: Some(
            BASE64_STANDARD
                .decode(to_primary["content"].as_str().unwrap())
                .unwrap()
                .into(),
        ),
        ..Default::default()
    };
    let opened = pool
        .run_until(
            ServiceCipher::new(
                primary,
                vec![],
                our_aci.to_protocol_address(device(1)).unwrap(),
                clock,
            )
            .open_envelope(envelope, rng),
        )
        .unwrap()
        .expect("content");
    let ContentBody::SynchronizeMessage(on_the_wire) = opened.body else {
        panic!("{:?}", opened.body)
    };

    let Some(ContentBody::SynchronizeMessage(made)) = sent_transcript(
        Some(&peer_id),
        ContentBody::DataMessage(message.clone()),
        timestamp,
        sent_at,
        [&sent],
        rng,
    ) else {
        panic!("a data message has a transcript")
    };
    let made = unpadded(made);
    assert_eq!(unpadded(on_the_wire), made);

    let Some(proto::sync_message::Content::Sent(transcript)) = made.content
    else {
        panic!("{made:?}")
    };
    assert_eq!(transcript.parse_destination_service_id(), Some(peer_id));
    assert_eq!(transcript.timestamp, Some(timestamp));
    assert_eq!(transcript.expiration_start_timestamp, Some(sent_at));
    assert_eq!(transcript.message, Some(message));
    let [status] = &transcript.unidentified_status[..] else {
        panic!("{transcript:?}")
    };
    assert_eq!(status.parse_destination_service_id(), Some(peer_id));
    assert_eq!(status.unidentified, Some(false));
}

/// What the official clients put in a transcript: a recipient's identity key
/// only for a PNI, whose key our devices learn from it (Desktop and Android),
/// and an expiration start that is when the message went out, not its
/// timestamp, only for a data message with a running timer (Android).
#[test]
fn sent_transcript_carries_what_the_official_clients_send() {
    let rng = &mut rand::rng();
    let identity_key = *IdentityKeyPair::generate(rng).identity_key();
    let timestamp = 1_700_000_000_000;
    // The message went out a minute and a half after it was composed.
    let sent_at = timestamp + 90_000;
    let sent = |recipient: ServiceId| SentMessage {
        recipient,
        used_identity_key: identity_key,
        unidentified: true,
        needs_sync: false,
    };
    let transcript = |destination: ServiceId, content_body: ContentBody| {
        match sent_transcript(
            Some(&destination),
            content_body,
            timestamp,
            sent_at,
            [&sent(destination)],
            &mut rand::rng(),
        ) {
            Some(ContentBody::SynchronizeMessage(SyncMessage {
                content: Some(proto::sync_message::Content::Sent(sent)),
                ..
            })) => sent,
            other => panic!("{other:?}"),
        }
    };
    let message = |expire_timer: Option<u32>| DataMessage {
        body: Some("hello".into()),
        expire_timer,
        ..Default::default()
    };
    let aci = ServiceId::from(Aci::from(Uuid::from_u128(0xa1)));
    let pni = ServiceId::from(Pni::from(Uuid::from_u128(0x9e)));

    let to_aci = transcript(aci, ContentBody::DataMessage(message(Some(3600))));
    assert_eq!(to_aci.timestamp, Some(timestamp));
    assert_eq!(
        to_aci.unidentified_status[0].destination_pni_identity_key,
        None
    );
    assert_eq!(to_aci.unidentified_status[0].unidentified, Some(true));
    assert_eq!(to_aci.expiration_start_timestamp, Some(sent_at));

    let to_pni = transcript(pni, ContentBody::DataMessage(message(Some(0))));
    assert_eq!(
        to_pni.unidentified_status[0].destination_pni_identity_key,
        Some(identity_key.serialize().to_vec())
    );
    assert_eq!(to_pni.expiration_start_timestamp, None);
    let no_timer = transcript(pni, ContentBody::DataMessage(message(None)));
    assert_eq!(no_timer.expiration_start_timestamp, None);

    // An edit keeps the timer of the message it edits.
    let edit = transcript(
        aci,
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(timestamp - 60_000),
            data_message: Some(message(Some(3600))),
        }),
    );
    assert!(edit.edit_message.is_some());
    assert_eq!(edit.expiration_start_timestamp, None);

    // Content our devices file under no sent message has no transcript.
    assert!(sent_transcript(
        Some(&aci),
        ContentBody::TypingMessage(proto::TypingMessage::default()),
        timestamp,
        sent_at,
        [],
        rng,
    )
    .is_none());
}

/// The signature verifies with our PNI identity over our ACI identity, and
/// a message that carries it tells its recipient that the PNI is ours.
#[test]
fn pni_signature_free_fn_verifies() {
    let rng = &mut rand::rng();
    let aci_identity = IdentityKeyPair::generate(rng);
    let pni_identity = IdentityKeyPair::generate(rng);
    let pni = Pni::from(Uuid::from_u128(0x9e));

    let signature =
        pni_signature(&pni_identity, aci_identity.identity_key(), pni, rng)
            .unwrap();
    assert_eq!(signature.pni.as_deref(), Some(&pni.service_id_binary()[..]));
    let signed = signature.signature();
    assert!(pni_identity
        .identity_key()
        .verify_alternate_identity(aci_identity.identity_key(), signed)
        .unwrap());
    let someone = IdentityKeyPair::generate(rng);
    assert!(!pni_identity
        .identity_key()
        .verify_alternate_identity(someone.identity_key(), signed)
        .unwrap());

    // Alice sends Bob a message with it, from a store that is not `Sync`.
    let _ = <LocalStore as AmbiguousIfSync<_>>::some_item;
    let clock = Rc::new(ManualClock::default());
    let alice_aci = Aci::from(Uuid::from_u128(0xa1));
    let alice = alice_aci.to_protocol_address(device(1)).unwrap();
    let alice_store = LocalStore::new(aci_identity, 1);
    let bob_aci = Aci::from(Uuid::from_u128(0xb0b));
    let bob = bob_aci.to_protocol_address(device(1)).unwrap();
    let bob_store = LocalStore::new(IdentityKeyPair::generate(rng), 2);
    let bob_bundle = block_on(bob_store.bundle(device(1)));
    block_on(process_prekey_bundle(
        &bob,
        &alice,
        &mut alice_store.clone(),
        &mut alice_store.clone(),
        &bob_bundle,
        clock.now(),
        rng,
    ))
    .unwrap();
    // Bob knows Alice's PNI identity, as the server tells it.
    block_on(bob_store.clone().save_identity(
        &pni.to_protocol_address(device(1)).unwrap(),
        pni_identity.identity_key(),
    ))
    .unwrap();

    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(DataMessage {
            body: Some("hi".into()),
            ..Default::default()
        })),
        pni_signature_message: Some(signature),
        ..Default::default()
    };
    let message = block_on(
        ServiceCipher::new(alice_store, vec![], alice.clone(), clock.clone())
            .encrypt(&bob, None, &content.encode_to_vec(), rng),
    )
    .unwrap();
    assert_eq!(message.r#type, Type::PrekeyMessage as u32);
    let envelope = Envelope {
        r#type: Some(message.r#type as i32),
        source_service_id: Some(alice_aci.service_id_string()),
        source_device_id: Some(1),
        destination_service_id: Some(bob_aci.service_id_string()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(BASE64_STANDARD.decode(message.content).unwrap().into()),
        ..Default::default()
    };
    let opened = block_on(
        ServiceCipher::new(bob_store, vec![], bob, clock)
            .open_envelope(envelope, rng),
    )
    .unwrap()
    .expect("content");
    assert_eq!(opened.metadata.pni_verified, Some(pni));
}

/// A protobuf message's fields, as (number, wire type, value), where a
/// length-delimited value is its payload and any other is its raw bytes:
/// libsignal gives no other way to make a session record of an older client.
fn fields(mut bytes: &[u8]) -> Vec<(u64, u8, Vec<u8>)> {
    fn varint(bytes: &mut &[u8]) -> u64 {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = bytes.split_first().unwrap();
            *bytes = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return value;
            }
        }
        panic!("varint too long")
    }
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes);
        let wire_type = (key & 7) as u8;
        let length = match wire_type {
            0 => {
                let start = bytes;
                varint(&mut bytes);
                let length = start.len() - bytes.len();
                bytes = start;
                length
            },
            1 => 8,
            2 => varint(&mut bytes) as usize,
            5 => 4,
            other => panic!("wire type {other}"),
        };
        let (value, rest) = bytes.split_at(length);
        fields.push((key >> 3, wire_type, value.to_vec()));
        bytes = rest;
    }
    fields
}

fn encode(fields: &[(u64, u8, Vec<u8>)]) -> Vec<u8> {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    let mut out = Vec::new();
    for (number, wire_type, value) in fields {
        varint(number << 3 | u64::from(*wire_type), &mut out);
        if *wire_type == 2 {
            varint(value.len() as u64, &mut out);
        }
        out.extend_from_slice(value);
    }
    out
}

/// `record` with its active session's fields (`SessionStructure`, field 1 of
/// `RecordStructure`) changed by `edit`.
fn edit_active_session(
    record: &SessionRecord,
    edit: impl FnOnce(&mut Vec<(u64, u8, Vec<u8>)>),
) -> SessionRecord {
    let mut record_fields = fields(&record.serialize().unwrap());
    let (_, _, session) = record_fields
        .iter_mut()
        .find(|(number, ..)| *number == 1)
        .expect("an active session");
    let mut session_fields = fields(session);
    edit(&mut session_fields);
    *session = encode(&session_fields);
    SessionRecord::deserialize(&encode(&record_fields)).unwrap()
}

/// `encrypt`, and so the sender, uses a session only when the official
/// clients would: one older than PQXDH or without SPQR counts as none, though
/// it is neither stale nor archived, so the sender builds a new one.
#[test]
fn encrypt_needs_a_session_the_official_clients_send_on() {
    let rng = &mut rand::rng();
    let clock = Rc::new(ManualClock::default());
    let now = clock.now();
    let alice = Aci::from(Uuid::from_u128(0xa1))
        .to_protocol_address(device(1))
        .unwrap();
    let alice_store = LocalStore::new(IdentityKeyPair::generate(rng), 1);
    let bob = Aci::from(Uuid::from_u128(0xb0b))
        .to_protocol_address(device(1))
        .unwrap();
    let bob_bundle = block_on(
        LocalStore::new(IdentityKeyPair::generate(rng), 2).bundle(device(1)),
    );
    block_on(process_prekey_bundle(
        &bob,
        &alice,
        &mut alice_store.clone(),
        &mut alice_store.clone(),
        &bob_bundle,
        now,
        rng,
    ))
    .unwrap();
    let built = block_on(alice_store.load_session(&bob)).unwrap().unwrap();
    assert!(
        has_usable_session(&built, now),
        "libsignal builds PQXDH and SPQR"
    );

    let encrypt_on = |record: &SessionRecord| {
        let mut store = alice_store.clone();
        block_on(store.store_session(&bob, record)).unwrap();
        block_on(
            ServiceCipher::new(store, vec![], alice.clone(), clock.clone())
                .encrypt(&bob, None, b"hello", &mut rand::rng()),
        )
    };
    let without_spqr = edit_active_session(&built, |session| {
        // `pq_ratchet_state`.
        session.retain(|(number, ..)| *number != 15);
    });
    let before_pqxdh = edit_active_session(&built, |session| {
        // `session_version`: 3 is X3DH's.
        let (.., version) = session
            .iter_mut()
            .find(|(number, ..)| *number == 1)
            .expect("a version");
        *version = vec![3];
    });
    for record in [&without_spqr, &before_pqxdh] {
        assert!(record
            .has_usable_sender_chain(
                now,
                SessionUsabilityRequirements::NotStale
            )
            .unwrap());
        assert!(!has_usable_session(record, now));
        let refused = encrypt_on(record);
        assert!(
            matches!(
                refused,
                Err(ServiceError::SignalProtocolError(
                    SignalProtocolError::SessionNotFound(_)
                ))
            ),
            "{refused:?}"
        );
    }
    let sent = encrypt_on(&built).unwrap();
    assert_eq!(sent.destination_device_id, device(1));
}

/// A recipient's unidentified access: `key`, and our sender certificate from
/// a fake server, which a prekey fetch doesn't send.
fn unidentified_access(key: [u8; 16]) -> UnidentifiedAccess {
    let rng = &mut rand::rng();
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let certificate = SenderCertificate::new(
        ACI.to_string(),
        None,
        *IdentityKeyPair::generate(rng).public_key(),
        device(2),
        Timestamp::from_epoch_millis(1_800_000_000_000),
        ServerCertificate::new(
            1,
            server_key.public_key,
            &trust_root.private_key,
            rng,
        )
        .unwrap(),
        &server_key.private_key,
        rng,
    )
    .unwrap();
    UnidentifiedAccess {
        key: key.to_vec(),
        certificate,
    }
}

/// An unauthenticated socket, opened without our credentials, and the fake
/// server's end of it.
fn unidentified_socket(
    pool: &mut LocalPool,
) -> (SignalWebSocket<Unidentified>, FakeServer) {
    let (service, transport) = push_service();
    let server = transport.accept_socket(&[]);
    let (ws, task) = pool
        .run_until(service.ws::<Unidentified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            None,
            Rc::new(ManualClock::default()),
        ))
        .unwrap();
    pool.spawner().spawn_local(task.map(drop)).unwrap();
    let connect = transport.take_connect();
    assert!(
        !connect.headers.contains_key(header::AUTHORIZATION),
        "no credentials"
    );
    (ws, server)
}

/// Answers the next request lss sends `server` with `status` and `body`, and
/// returns the request.
async fn answer_next(
    server: &mut FakeServer,
    status: u32,
    body: &[u8],
) -> WebSocketRequestMessage {
    let request = sent_request(server.next_sent().await);
    server.respond(request.id(), status, body);
    request
}

/// A sealed-sender send fetches its recipient's bundles on the
/// unauthenticated socket with the recipient's access key, so the server
/// doesn't learn who asks: every device's for device 1 (`*`), one device's
/// for any other, read as the authenticated fetch reads them.
#[test]
fn unidentified_pre_keys_go_with_the_access_key() {
    let mut pool = LocalPool::new();
    let rng = &mut rand::rng();
    let (mut ws, mut server) = unidentified_socket(&mut pool);
    let peer = ServiceId::from(Aci::from(Uuid::from_u128(0x5eed)));
    let peer_store = LocalStore::new(IdentityKeyPair::generate(rng), 33);
    let key = [0x42; 16];
    let access = unidentified_access(key);
    let access_header =
        format!("Unidentified-Access-Key:{}", BASE64_STANDARD.encode(key));

    for (device_id, path) in [
        (
            device(1),
            format!("/v2/keys/{}/*", peer.service_id_string()),
        ),
        (
            device(3),
            format!("/v2/keys/{}/3", peer.service_id_string()),
        ),
    ] {
        let bundle = pool.run_until(peer_store.bundle(device_id));
        let (fetched, request) = pool.run_until(future::join(
            ws.get_pre_keys(&peer, device_id, &access),
            answer_next(&mut server, 200, &keys_response(&bundle)),
        ));
        assert_eq!(request.verb(), "GET");
        assert_eq!(request.path(), path);
        assert_eq!(request.headers, std::slice::from_ref(&access_header));
        let fetched = fetched.unwrap_or_else(|error| panic!("{error:?}"));
        let [fetched] = &fetched[..] else {
            panic!("{} bundles", fetched.len())
        };
        assert_eq!(fetched.device_id().unwrap(), device_id);
        assert_eq!(
            fetched.registration_id().unwrap(),
            bundle.registration_id().unwrap()
        );
        assert_eq!(
            fetched.identity_key().unwrap(),
            bundle.identity_key().unwrap()
        );
        assert_eq!(
            fetched.signed_pre_key_public().unwrap(),
            bundle.signed_pre_key_public().unwrap()
        );
        assert_eq!(
            fetched.kyber_pre_key_public().unwrap(),
            bundle.kyber_pre_key_public().unwrap()
        );
    }
}

/// A key the server refuses (401, which it also answers for an account that
/// doesn't exist, or 403) comes back as `Unauthorized`: the official clients
/// then fetch on the authenticated socket and send that message unsealed.
#[test]
fn unidentified_pre_keys_refused_key_is_unauthorized() {
    let mut pool = LocalPool::new();
    let (mut ws, mut server) = unidentified_socket(&mut pool);
    let peer = ServiceId::from(Aci::from(Uuid::from_u128(0x5eed)));
    let access = unidentified_access([0x42; 16]);
    for status in [401, 403] {
        let (refused, _) = pool.run_until(future::join(
            ws.get_pre_keys(&peer, device(1), &access),
            answer_next(&mut server, status, b""),
        ));
        assert!(
            matches!(refused, Err(ServiceError::Unauthorized)),
            "{status}: {:?}",
            refused.err()
        );
    }
}
