//! The provisioning pipe's steps: each comes out of the poll that takes its
//! request from the socket, the primary's message reaches the caller whether
//! or not its answer still reaches the server, and it comes with its
//! plaintext, which holds the fields this crate's protos lack.

mod common;

use std::{pin::Pin, rc::Rc};

use aes::{
    cipher::{
        block_padding::Pkcs7,
        consts::{U32, U64},
        Array, BlockModeEncrypt as _, KeyIvInit as _,
    },
    Aes256,
};
use futures::{
    executor::LocalPool,
    future::{FutureExt as _, RemoteHandle},
    task::LocalSpawnExt as _,
    Stream, StreamExt as _,
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use libsignal_service::{
    prelude::ProtobufMessage as _,
    proto::ProvisioningAddress,
    protocol::{KeyPair, PublicKey},
    provisioning::{
        ProvisionEnvelope, ProvisionMessage, ProvisioningCipher,
        ProvisioningError, ProvisioningPipe, ProvisioningStep,
    },
    push_service::ServiceError,
    transport::WsEvent,
    utils::BASE64_RELAXED,
    websocket::{SocketEnd, Unidentified},
};
use rand::Rng as _;
use sha2::Sha256;

use common::*;

type Steps =
    Pin<Box<dyn Stream<Item = Result<ProvisioningStep, ProvisioningError>>>>;

/// A provisioning socket and its pipe's steps, the socket's task running on
/// `pool`; nothing polls the steps but the test.
struct Pipe {
    pool: LocalPool,
    server: FakeServer,
    steps: Steps,
    running: RemoteHandle<Result<SocketEnd, ServiceError>>,
}

impl Pipe {
    fn open() -> Pipe {
        let mut pool = LocalPool::new();
        let (service, transport) = push_service();
        let server = transport.accept_socket(&[]);
        let mut rng = rand::rng();
        let (ws, task) = pool
            .run_until(service.ws::<Unidentified>(
                "/v1/websocket/provisioning/",
                "/v1/keepalive/provisioning",
                &[],
                None,
                &mut rng,
                Rc::new(ManualClock::default()),
            ))
            .unwrap();
        let running = pool.spawner().spawn_local_with_handle(task).unwrap();
        let steps =
            Box::pin(ProvisioningPipe::from_socket(ws, &mut rng, &[]).stream());
        Pipe {
            pool,
            server,
            steps,
            running,
        }
    }

    /// One poll of the steps, after the socket's task has read what the
    /// server sent.
    fn poll_once(
        &mut self,
    ) -> Option<Option<Result<ProvisioningStep, ProvisioningError>>> {
        self.pool.run_until_stalled();
        self.steps.next().now_or_never()
    }

    /// The server gives the socket its address and the steps' first poll
    /// reads the link: the device's provisioning key, as the link carries it.
    fn address(&mut self) -> PublicKey {
        let address = ProvisioningAddress {
            address: Some("an-address".into()),
        };
        self.server
            .request(1, "PUT", "/v1/address", address.encode_to_vec());
        let Some(Some(Ok(ProvisioningStep::Url(url)))) = self.poll_once()
        else {
            panic!("the link, at the first poll")
        };
        let (_, key) = url
            .query_pairs()
            .find(|(name, _)| name == "pub_key")
            .expect("the link's key");
        PublicKey::deserialize(
            &base64::Engine::decode(&BASE64_RELAXED, &*key).unwrap(),
        )
        .unwrap()
    }

    /// The answers the device sent, as (id, status).
    fn answers(&mut self) -> Vec<(u64, u32)> {
        self.pool.run_until_stalled();
        self.server
            .take_responses()
            .iter()
            .map(|response| (response.id(), response.status()))
            .collect()
    }
}

/// A primary's message, sealed for `key`.
fn sealed_for(key: PublicKey) -> (ProvisionMessage, Vec<u8>) {
    let message = ProvisionMessage {
        provisioning_code: Some("code".into()),
        aci_identity_key_private: Some(vec![7; 32]),
        ..Default::default()
    };
    let envelope = ProvisioningCipher::from_public(key)
        .encrypt(&mut rand::rng(), message.clone())
        .unwrap();
    (message, envelope.encode_to_vec())
}

/// `plaintext` sealed for `key` as a primary seals its message's encoding
/// (as [`ProvisioningCipher::encrypt`] does): what a primary whose
/// `Provisioning.proto` names a field this crate's lacks sends.
fn seal(key: PublicKey, plaintext: &[u8]) -> ProvisionEnvelope {
    const VERSION: u8 = 1;
    let mut rng = rand::rng();
    let ours = KeyPair::generate(&mut rng);
    let agreement = ours.calculate_agreement(&key).unwrap();
    let mut secrets = Array::<u8, U64>::default();
    hkdf::Hkdf::<Sha256>::new(None, &agreement)
        .expand(b"TextSecure Provisioning Message", &mut secrets)
        .unwrap();
    let (aes_key, mac_key) = secrets.split_ref::<U32>();
    let iv: [u8; 16] = rng.random();
    let ciphertext = cbc::Encryptor::<Aes256>::new(aes_key, &iv.into())
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    mac.update(&[VERSION]);
    mac.update(&iv);
    mac.update(&ciphertext);
    let mut body = vec![VERSION];
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);
    body.extend_from_slice(&mac.finalize().into_bytes());
    ProvisionEnvelope {
        public_key: Some(ours.public_key.serialize().into()),
        body: Some(body),
    }
}

/// A request the socket holds is a step at the first poll that follows: the
/// address, then the primary's message, each answered as it is handed over.
#[test]
fn a_buffered_step_is_yielded_by_one_poll() {
    let mut pipe = Pipe::open();
    let key = pipe.address();
    assert_eq!(pipe.answers(), [(1, 200)]);

    let (message, envelope) = sealed_for(key);
    pipe.server.request(2, "PUT", "/v1/message", envelope);
    let Some(Some(Ok(ProvisioningStep::Message {
        message: opened, ..
    }))) = pipe.poll_once()
    else {
        panic!("the message, at the first poll")
    };
    assert_eq!(opened, message);
    assert_eq!(pipe.answers(), [(2, 200)]);
}

/// A message whose socket ended before it could be answered, the server's
/// close behind it, still reaches the caller: the link it carries goes over
/// HTTP. The steps end with the socket.
#[test]
fn a_message_whose_socket_ended_before_its_answer_is_yielded() {
    let mut pipe = Pipe::open();
    let key = pipe.address();
    assert_eq!(pipe.answers(), [(1, 200)]);
    let (message, envelope) = sealed_for(key);
    pipe.server.request(2, "PUT", "/v1/message", envelope);
    pipe.server.event(Ok(WsEvent::Close {
        code: 1000,
        reason: "Timeout".into(),
    }));
    pipe.pool.run_until_stalled();
    assert_eq!(
        (&mut pipe.running)
            .now_or_never()
            .expect("the socket ended")
            .unwrap(),
        SocketEnd::Closed {
            code: 1000,
            reason: "Timeout".into()
        }
    );

    let Some(Some(Ok(ProvisioningStep::Message {
        message: opened, ..
    }))) = pipe.poll_once()
    else {
        panic!("the message, though its answer can't go")
    };
    assert_eq!(opened, message);
    assert!(matches!(pipe.poll_once(), Some(None)), "the steps end");
    assert_eq!(pipe.answers(), [], "nothing more went out");
}

/// A link whose address can't be answered any more is of a socket that
/// ended, which links nothing: `WsClosing`, as before.
#[test]
fn an_address_whose_socket_ended_is_ws_closing() {
    let mut pipe = Pipe::open();
    let address = ProvisioningAddress {
        address: Some("an-address".into()),
    };
    pipe.server
        .request(1, "PUT", "/v1/address", address.encode_to_vec());
    pipe.server.event(Ok(WsEvent::Close {
        code: 1000,
        reason: "Timeout".into(),
    }));
    assert!(
        matches!(
            pipe.poll_once(),
            Some(Some(Err(ProvisioningError::WsClosing)))
        ),
        "the address of a closed socket"
    );
    assert!(matches!(pipe.poll_once(), Some(None)));
}

/// Field 99, a string: a field this crate's `Provisioning.proto` doesn't
/// name, as a newer primary's would be. Its key is (99 << 3) | 2, a two-byte
/// varint.
const FIELD_99: [u8; 8] = [0x9a, 0x06, 5, b'n', b'e', b'w', b'e', b'r'];

/// A field this crate's `Provisioning.proto` lacks is in the step's
/// plaintext, the message as the primary encoded it, and not in its
/// decoding.
#[test]
fn a_field_the_proto_lacks_is_in_the_plaintext_alone() {
    let mut pipe = Pipe::open();
    let key = pipe.address();
    let message = ProvisionMessage {
        provisioning_code: Some("code".into()),
        aci_identity_key_private: Some(vec![7; 32]),
        ..Default::default()
    };
    let mut sent = message.encode_to_vec();
    sent.extend_from_slice(&FIELD_99);
    let envelope = seal(key, &sent).encode_to_vec();
    pipe.server.request(2, "PUT", "/v1/message", envelope);
    let Some(Some(Ok(ProvisioningStep::Message {
        message: opened,
        plaintext,
    }))) = pipe.poll_once()
    else {
        panic!("the message")
    };
    assert_eq!(plaintext, sent, "the plaintext holds field 99");
    assert_eq!(opened, message, "the decoding doesn't");
    assert_eq!(
        opened.encode_to_vec().len() + FIELD_99.len(),
        plaintext.len()
    );
    assert_eq!(pipe.answers(), [(1, 200), (2, 200)]);
}
