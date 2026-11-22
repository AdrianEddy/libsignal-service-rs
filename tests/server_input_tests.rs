//! Server input that panicked lss or passed for a success is an error: a
//! prekey answer without devices, a WebSocket response without a valid
//! status, a contacts blob that doesn't download, decrypt or parse, an
//! attachment shorter than its MAC, a provisioning envelope that can't be
//! opened, a profile field shorter than its nonce, and a group key or GroupV1
//! id of the wrong length. The decrypt's checks of an envelope are
//! `src/cipher/tests.rs`'.

mod common;

use std::{io, rc::Rc};

use base64::prelude::*;
use bytes::Bytes;
use futures::{
    executor::{block_on, LocalPool},
    future::{self, FutureExt as _, RemoteHandle},
    task::LocalSpawnExt as _,
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use libsignal_service::{
    attachment_cipher::{
        decrypt_in_place, encrypt_in_place, AttachmentCipherError,
    },
    groups_v2::{
        decrypt_group, utils::derive_v2_migration_master_key,
        GroupDecodingError,
    },
    models::{Contact, ParseContactError},
    prelude::{AttachmentIdentifier, ProfileKey, ProtobufMessage as _},
    profile_cipher::{ProfileCipher, ProfileCipherError},
    proto::{
        contact_details::Avatar, sync_message::Contacts, web_socket_message,
        AttachmentPointer, ContactDetails, Group, WebSocketMessage,
        WebSocketResponseMessage,
    },
    protocol::{
        Aci, DeviceId, IdentityKeyPair, KeyPair, ServiceId, ServiceIdKind,
        SignalProtocolError,
    },
    provisioning::{
        ProvisionEnvelope, ProvisionMessage, ProvisioningCipher,
        ProvisioningError,
    },
    push_service::ServiceError,
    receiver::MessageReceiver,
    transport::TransportErrorKind,
    websocket::{Identified, SignalWebSocket, SocketEnd},
};
use sha2::Sha256;
use uuid::Uuid;

use common::*;

const PEER: Uuid = Uuid::from_u128(0x5eed);
const OTHER: Uuid = Uuid::from_u128(0x0de1);

/// The account's authenticated socket on `clock`, the fake server's end of
/// it, and the handle of its task, which `pool` runs.
fn socket(
    pool: &mut LocalPool,
    clock: Rc<ManualClock>,
) -> (
    SignalWebSocket<Identified>,
    FakeServer,
    RemoteHandle<Result<SocketEnd, ServiceError>>,
) {
    let (service, transport) = push_service();
    let server = transport.accept_socket(&[]);
    let (ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            clock,
        ))
        .unwrap();
    let running = pool.spawner().spawn_local_with_handle(task).unwrap();
    pool.run_until_stalled();
    (ws, server, running)
}

/// Answers lss's request `id` with `status`, or with none.
fn answer(server: &FakeServer, id: u64, status: Option<u32>, body: &[u8]) {
    server.frame(WebSocketMessage {
        r#type: Some(web_socket_message::Type::Response.into()),
        response: Some(WebSocketResponseMessage {
            id: Some(id),
            status,
            message: None,
            headers: Vec::new(),
            body: Some(body.to_vec()),
        }),
        ..Default::default()
    });
}

/// The statuses that aren't one: none, one outside 100 to 999, and one past
/// 65535 whose low 16 bits are 200.
const NOT_STATUSES: [Option<u32>; 4] =
    [None, Some(0), Some(1000), Some(0x1_00C8)];

/// A response without a valid status is no answer, where it read as 200: a
/// refusal could pass for a success.
#[test]
fn a_response_without_a_valid_status_is_an_error() {
    let mut pool = LocalPool::new();
    let (mut ws, mut server, _running) =
        socket(&mut pool, Rc::new(ManualClock::default()));
    for status in NOT_STATUSES {
        let (counted, ()) = pool.run_until(future::join(
            ws.get_pre_key_status(ServiceIdKind::Aci),
            async {
                let request = sent_request(server.next_sent().await);
                answer(
                    &server,
                    request.id(),
                    status,
                    br#"{"count":7,"pqCount":7}"#,
                );
            },
        ));
        assert!(
            matches!(
                counted,
                Err(ServiceError::InvalidFrame {
                    reason: "a response without a valid status"
                })
            ),
            "{status:?}: {counted:?}"
        );
    }
}

/// A keepalive answered without a valid status ends the socket's task with
/// the error, where a status past 65535 whose low 16 bits are 200 passed.
#[test]
fn a_keepalive_answered_without_a_valid_status_fails_the_task() {
    for status in NOT_STATUSES {
        let mut pool = LocalPool::new();
        let clock = Rc::new(ManualClock::default());
        let (_ws, mut server, running) = socket(&mut pool, clock.clone());
        clock.advance(KEEPALIVE);
        pool.run_until_stalled();
        let [keepalive] = &server.take_requests()[..] else {
            panic!("one keepalive")
        };
        assert_eq!(keepalive.path(), "/v1/keepalive");
        answer(&server, keepalive.id(), status, b"");
        pool.run_until_stalled();
        let ended = running.now_or_never().expect("the task ended");
        assert!(
            matches!(
                ended,
                Err(ServiceError::InvalidFrame {
                    reason: "a keepalive response without a valid status"
                })
            ),
            "{status:?}: {ended:?}"
        );
    }
}

/// A prekey answer for one device that holds no device is an error, where the
/// fetch panicked.
#[test]
fn a_prekey_answer_without_devices_is_an_error() {
    let mut pool = LocalPool::new();
    let (mut ws, mut server, _running) =
        socket(&mut pool, Rc::new(ManualClock::default()));
    let peer = ServiceId::from(Aci::from(PEER));
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let body = serde_json::to_vec(&serde_json::json!({
        "identityKey": BASE64_STANDARD.encode(identity.identity_key().serialize()),
        "devices": [],
    }))
    .unwrap();
    let (fetched, request) = pool.run_until(future::join(
        ws.get_pre_key(&peer, DeviceId::new(2).unwrap()),
        async {
            let request = sent_request(server.next_sent().await);
            server.respond(request.id(), 200, &body);
            request
        },
    ));
    assert_eq!(
        request.path(),
        format!("/v2/keys/{}/2", peer.service_id_string())
    );
    assert!(
        matches!(
            fetched,
            Err(ServiceError::InvalidFrame {
                reason: "a prekey answer without devices"
            })
        ),
        "{:?}",
        fetched.err()
    );
}

/// The key a primary device encrypts its contacts blob with.
const BLOB_KEY: [u8; 64] = [0x2c; 64];

/// `plaintext` encrypted under [`BLOB_KEY`], as a primary device uploads its
/// contacts blob.
fn blob(plaintext: &[u8]) -> Vec<u8> {
    let mut blob = plaintext.to_vec();
    encrypt_in_place([0x1d; 16], BLOB_KEY, &mut blob);
    blob
}

/// A contacts blob's entry: the details of `aci`, and an avatar of the bytes
/// given that claims the length given.
fn entry(aci: Option<Uuid>, avatar: Option<(u32, &[u8])>) -> Vec<u8> {
    let details = ContactDetails {
        aci_binary: aci.map(|aci| aci.as_bytes().to_vec()),
        avatar: avatar.map(|(length, _)| Avatar {
            content_type: Some("image/png".into()),
            length: Some(length),
        }),
        ..Default::default()
    };
    let mut entry = details.encode_length_delimited_to_vec();
    if let Some((_, bytes)) = avatar {
        entry.extend_from_slice(bytes);
    }
    entry
}

type Retrieved = Result<Vec<Result<Contact, ParseContactError>>, ServiceError>;

/// The contacts lss retrieves from a blob under `key` on CDN 3, which the CDN
/// answers with `answer`, and the requests it sent.
fn retrieve(key: &[u8], answer: Option<Answer>) -> (Retrieved, Vec<Seen>) {
    let (service, transport) = push_service();
    if let Some(answer) = answer {
        transport.answer(answer);
    }
    let contacts = Contacts {
        blob: Some(AttachmentPointer {
            attachment_identifier: Some(AttachmentIdentifier::CdnKey(
                "contacts".into(),
            )),
            cdn_number: Some(3),
            key: Some(key.to_vec()),
            ..Default::default()
        }),
        complete: Some(true),
    };
    let mut receiver = MessageReceiver::new(service);
    let retrieved: Retrieved = block_on(receiver.retrieve_contacts(&contacts))
        .map(|contacts| contacts.collect());
    (retrieved, transport.take_seen())
}

/// A contacts blob that doesn't download or decrypt is an error, where each
/// of these panicked: a download broken off, a key that isn't 64 bytes
/// (refused before the download), a MAC that doesn't verify, and padding that
/// doesn't verify under a MAC that does.
#[test]
fn a_contacts_blob_that_doesnt_download_or_decrypt_is_an_error() {
    let sealed = blob(&entry(Some(PEER), None));
    let (retrieved, seen) =
        retrieve(&BLOB_KEY, Some(Answer::body(200, sealed.clone())));
    let contacts = retrieved.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].as_ref().unwrap().uuid, PEER);
    let [download] = &seen[..] else {
        panic!("one download")
    };
    assert_eq!(download.url, "https://cdn3.test/attachments/contacts");

    let (retrieved, _) = retrieve(
        &BLOB_KEY,
        Some(Answer::chunks(
            200,
            vec![
                Ok(Bytes::copy_from_slice(&sealed[..20])),
                Err(TransportErrorKind::Closed),
            ],
        )),
    );
    match retrieved {
        Err(ServiceError::IO(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted)
        },
        other => panic!("{other:?}"),
    }

    for key in [&[][..], &BLOB_KEY[..32], &[0x2c; 65][..]] {
        let (retrieved, seen) = retrieve(key, None);
        assert!(
            matches!(
                retrieved,
                Err(ServiceError::InvalidFrame {
                    reason: "an attachment key that isn't 64 bytes"
                })
            ),
            "{}: {retrieved:?}",
            key.len()
        );
        assert!(seen.is_empty(), "nothing downloaded");
    }

    let mut other_key = BLOB_KEY;
    other_key[63] ^= 1;
    let (retrieved, _) =
        retrieve(&other_key, Some(Answer::body(200, sealed.clone())));
    assert!(
        matches!(retrieved, Err(ServiceError::MacError)),
        "{retrieved:?}"
    );

    // One block, whose last plaintext byte is PKCS #7's pad value, 6: the
    // IV's last byte flips it to 0, which pads nothing, and the MAC is made
    // again over the changed IV.
    let mut forged = blob(b"ten bytes!");
    forged.truncate(forged.len() - 32);
    forged[15] ^= 6;
    let mut mac = Hmac::<Sha256>::new_from_slice(&BLOB_KEY[32..]).unwrap();
    mac.update(&forged);
    forged.extend_from_slice(&mac.finalize().into_bytes());
    let (retrieved, _) = retrieve(&BLOB_KEY, Some(Answer::body(200, forged)));
    assert!(
        matches!(retrieved, Err(ServiceError::Padding(_))),
        "{retrieved:?}"
    );
}

/// The contacts iterator yields a contact that doesn't parse as an error and
/// goes on, and ends with the error of an entry that breaks the blob's
/// framing: an avatar past the end, which panicked, and a length past the
/// end, which ended the iteration as if the blob had.
#[test]
fn a_contacts_entry_that_breaks_the_blob_ends_it_with_an_error() {
    let contacts = |entries: Vec<Vec<u8>>| {
        retrieve(&BLOB_KEY, Some(Answer::body(200, blob(&entries.concat()))))
            .0
            .unwrap()
    };

    let read = contacts(vec![
        entry(Some(PEER), Some((4, b"png!"))),
        entry(None, None),
        entry(Some(OTHER), None),
    ]);
    match &read[..] {
        [Ok(first), Err(ParseContactError::MissingUuid), Ok(second)] => {
            assert_eq!(first.uuid, PEER);
            let avatar = first.avatar.as_ref().expect("an avatar");
            assert_eq!(&avatar.reader[..], b"png!");
            assert_eq!(second.uuid, OTHER);
        },
        other => panic!("{other:?}"),
    }

    let read = contacts(vec![
        entry(Some(PEER), None),
        entry(Some(OTHER), Some((10, b"png"))),
    ]);
    assert!(
        matches!(&read[..], [Ok(_), Err(ParseContactError::TruncatedAvatar)]),
        "{read:?}"
    );

    let read = contacts(vec![entry(Some(PEER), None), vec![0x05, 0x01]]);
    assert!(
        matches!(&read[..], [Ok(_), Err(ParseContactError::Protobuf(_))]),
        "{read:?}"
    );
}

/// An attachment shorter than its MAC is a MAC error, where its length less
/// the MAC's underflowed, and it is left as it was.
#[test]
fn an_attachment_shorter_than_its_mac_is_a_mac_error() {
    for len in [0, 1, 31] {
        let mut object = vec![0x5a; len];
        assert_eq!(
            decrypt_in_place(BLOB_KEY, &mut object),
            Err(AttachmentCipherError::MacError),
            "{len}"
        );
        assert_eq!(object, vec![0x5a; len]);
    }
}

/// A provisioning envelope that can't be opened is an error, where a missing
/// key or body, or a body too short for its version, IV and MAC, panicked
/// before the MAC was checked. The link reads one from the provisioning
/// socket.
#[test]
fn a_provisioning_envelope_that_cant_be_opened_is_an_error() {
    let mut rng = rand::rng();
    let device = KeyPair::generate(&mut rng);
    let sealed = ProvisioningCipher::from_public(device.public_key)
        .encrypt(&mut rng, ProvisionMessage::default())
        .unwrap();
    let cipher = ProvisioningCipher::from_key_pair(device);
    assert_eq!(
        cipher.decrypt(sealed.clone()).unwrap(),
        ProvisionMessage::default()
    );
    let body = sealed.body.clone().unwrap();
    let with_body = |body: &[u8]| {
        cipher.decrypt(ProvisionEnvelope {
            body: Some(body.to_vec()),
            ..sealed.clone()
        })
    };

    let opened = cipher.decrypt(ProvisionEnvelope {
        public_key: None,
        ..sealed.clone()
    });
    assert!(
        matches!(opened, Err(ProvisioningError::MissingPublicKey)),
        "{opened:?}"
    );
    let opened = cipher.decrypt(ProvisionEnvelope {
        body: None,
        ..sealed.clone()
    });
    assert!(
        matches!(opened, Err(ProvisioningError::MissingMessage)),
        "{opened:?}"
    );
    let mut other_version = body.clone();
    other_version[0] = 2;
    for body in [&[][..], &other_version] {
        let opened = with_body(body);
        assert!(
            matches!(opened, Err(ProvisioningError::BadVersionNumber)),
            "{}: {opened:?}",
            body.len()
        );
    }
    // The version alone; and the IV; a byte short of the IV and MAC; no
    // ciphertext; the body less its last byte.
    for len in [1, 17, 48, 49, body.len() - 1] {
        let opened = with_body(&body[..len]);
        assert!(
            matches!(opened, Err(ProvisioningError::MismatchedMac)),
            "{len}: {opened:?}"
        );
    }
}

/// A profile field shorter than its nonce doesn't decrypt, where taking the
/// nonce panicked.
#[test]
fn a_profile_field_shorter_than_its_nonce_is_an_error() {
    let cipher = ProfileCipher::new(ProfileKey::generate([7; 32]));
    let about = cipher
        .encrypt_about("about".into(), &mut rand::rng())
        .unwrap();
    assert_eq!(cipher.decrypt_about(&about).unwrap(), "about");
    for len in [0, 11, 12, 27] {
        let bytes = &about[..len];
        let refused = |decrypted: Result<(), ProfileCipherError>| {
            assert!(
                matches!(decrypted, Err(ProfileCipherError::EncryptionError)),
                "{len}: {decrypted:?}"
            )
        };
        refused(cipher.decrypt_name(bytes).map(drop));
        refused(cipher.decrypt_about(bytes).map(drop));
        refused(cipher.decrypt_emoji(bytes).map(drop));
        refused(cipher.decrypt_avatar(bytes).map(drop));
    }
}

/// A group master key that isn't 32 bytes is a wrong blob, as
/// `decrypt_group_context` has it, and a GroupV1 id that isn't 16 bytes an
/// invalid argument, where both panicked.
#[test]
fn a_group_key_or_id_of_the_wrong_length_is_an_error() {
    for len in [0, 31, 33] {
        let decrypted = decrypt_group(&vec![0x11; len], Group::default());
        assert!(
            matches!(
                decrypted,
                Err(ServiceError::GroupsV2DecryptionError(
                    GroupDecodingError::WrongBlob
                ))
            ),
            "{len}: {:?}",
            decrypted.err()
        );
    }
    assert!(derive_v2_migration_master_key(&[0x22; 16]).is_ok());
    for len in [0, 15, 17, 32] {
        let derived = derive_v2_migration_master_key(&vec![0x22; len]);
        assert!(
            matches!(derived, Err(SignalProtocolError::InvalidArgument(_))),
            "{len}: {:?}",
            derived.err()
        );
    }
}
