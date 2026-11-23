use std::{
    rc::Rc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::prelude::*;
use futures::future::{self, FutureExt as _, LocalBoxFuture};
use libsignal_protocol::{
    create_sender_key_distribution_message, kem, process_prekey_bundle,
    sealed_sender_encrypt, sealed_sender_encrypt_from_usmc, Aci,
    CiphertextMessageType, ContentHint, DeviceId, GenericSignedPreKey as _,
    IdentityKeyPair, IdentityKeyStore as _, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore as _, Pni, PreKeyBundle,
    ProtocolAddress, SenderCertificate, SenderKeyStore as _, ServerCertificate,
    ServiceId, SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore as _,
    Timestamp, UnidentifiedSenderMessageContent,
};
use prost::Message as _;
use uuid::Uuid;

use super::{add_padding, ServiceCipher};
use crate::{
    content::{ContentBody, DecryptedEnvelope},
    envelope::Envelope,
    proto::{self, envelope::Type},
    push_service::ServiceError,
    sender::OutgoingPushMessage,
    session_store::SessionStoreExt,
    transport::Clock,
};

/// A clock that stands still, so no wait on it ends.
struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }

    fn sleep(&self, _: Duration) -> LocalBoxFuture<'static, ()> {
        future::pending().boxed_local()
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for InMemSignalProtocolStore {
    async fn get_sub_device_sessions(
        &self,
        _: &ServiceId,
        _: SystemTime,
    ) -> Result<Vec<DeviceId>, SignalProtocolError> {
        unreachable!("encrypt doesn't list sessions")
    }

    async fn delete_session(
        &self,
        _: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError> {
        unreachable!("encrypt doesn't delete sessions")
    }

    async fn delete_all_sessions(
        &self,
        _: &ServiceId,
    ) -> Result<usize, SignalProtocolError> {
        unreachable!("encrypt doesn't delete sessions")
    }
}

/// The device every account here has.
fn device() -> DeviceId {
    DeviceId::new(1).unwrap()
}

/// The account `id`'s ACI.
fn aci(id: u128) -> ServiceId {
    Aci::from(Uuid::from_u128(id)).into()
}

fn address(id: u128) -> ProtocolAddress {
    aci(id).to_protocol_address(device())
}

/// The account `id`'s cipher on `store`, without trust roots.
fn cipher(
    store: InMemSignalProtocolStore,
    id: u128,
    clock: Rc<dyn Clock>,
) -> ServiceCipher<InMemSignalProtocolStore> {
    ServiceCipher::new(store, vec![], aci(id), device(), clock)
}

fn bundle() -> PreKeyBundle {
    let rng = &mut rand::rng();
    let identity = IdentityKeyPair::generate(rng);
    let signed = KeyPair::generate(rng);
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let sign = |key: &[u8]| {
        identity
            .private_key()
            .calculate_signature(key, &mut rand::rng())
            .unwrap()
            .to_vec()
    };
    PreKeyBundle::new(
        1,
        DeviceId::new(1).unwrap(),
        None,
        1.into(),
        signed.public_key,
        sign(&signed.public_key.serialize()),
        1.into(),
        kyber.public_key.clone(),
        sign(&kyber.public_key.serialize()),
        *identity.identity_key(),
    )
    .unwrap()
}

/// What the account 1 encrypts to `remote` at `now`.
async fn encrypt_at(
    store: &InMemSignalProtocolStore,
    remote: &ProtocolAddress,
    now: SystemTime,
) -> Result<OutgoingPushMessage, ServiceError> {
    cipher(store.clone(), 1, Rc::new(FixedClock(now)))
        .encrypt(remote, None, b"hello", &mut rand::rng())
        .await
}

/// A session started from a bundle stays unacknowledged until the peer
/// answers, and libsignal stops sending on it 30 days after it started. The
/// session starts in 2023, so the system clock would call it stale at once.
#[tokio::test]
async fn clock_drives_session_staleness() {
    let (alice, bob) = (address(1), address(2));
    let mut store = InMemSignalProtocolStore::new(
        IdentityKeyPair::generate(&mut rand::rng()),
        1,
    )
    .unwrap();
    let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &bob,
        &alice,
        &mut store.session_store,
        &mut store.identity_store,
        &bundle(),
        started,
        &mut rand::rng(),
    )
    .await
    .unwrap();
    let day = Duration::from_secs(24 * 60 * 60);

    let message = encrypt_at(&store, &bob, started + 29 * day).await.unwrap();
    assert_eq!(message.r#type, Type::PrekeyMessage as u32);

    let stale = encrypt_at(&store, &bob, started + 31 * day).await;
    assert!(
        matches!(
            stale,
            Err(ServiceError::SignalProtocolError(
                SignalProtocolError::SessionNotFound(_)
            ))
        ),
        "{stale:?}"
    );
}

/// A content pads as Signal-Android's `PushTransportDetails` and
/// Signal-Desktop's `padMessage` pad it: a 0x80 terminator, then zeros to one
/// byte short of a multiple of 80, so a message's length on the wire is the
/// official clients' and the cipher adds a single byte of its own.
#[test]
fn contents_pad_as_the_official_clients_pad() {
    for (lengths, padded) in [(0..=78, 79), (79..=158, 159), (159..=238, 239)] {
        for length in lengths {
            let content = vec![0x2a; length];
            let buffer = add_padding(4, &content).unwrap();
            assert_eq!(buffer.len(), padded, "{length}");
            assert_eq!(buffer[..length], content[..]);
            assert_eq!(buffer[length], 0x80);
            assert!(buffer[length + 1..].iter().all(|&byte| byte == 0));
            let mut stripped = buffer;
            super::strip_padding(&mut stripped).unwrap();
            assert_eq!(stripped, content);
        }
    }
}

/// A device that keeps the prekeys its bundle offers, so it can open what is
/// sent to it.
async fn device_with_bundle(
    address: &ProtocolAddress,
) -> (InMemSignalProtocolStore, PreKeyBundle) {
    let rng = &mut rand::rng();
    let identity = IdentityKeyPair::generate(rng);
    let mut store = InMemSignalProtocolStore::new(identity, 7).unwrap();
    let signed = KeyPair::generate(rng);
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let sign = |key: &[u8]| {
        identity
            .private_key()
            .calculate_signature(key, &mut rand::rng())
            .unwrap()
    };
    let signed_signature = sign(&signed.public_key.serialize());
    let kyber_signature = sign(&kyber.public_key.serialize());
    store
        .save_signed_pre_key(
            1.into(),
            &SignedPreKeyRecord::new(
                1.into(),
                Timestamp::from_epoch_millis(0),
                &signed,
                &signed_signature,
            ),
        )
        .await
        .unwrap();
    store
        .save_kyber_pre_key(
            1.into(),
            &KyberPreKeyRecord::new(
                1.into(),
                Timestamp::from_epoch_millis(0),
                &kyber,
                &kyber_signature,
            ),
        )
        .await
        .unwrap();
    let bundle = PreKeyBundle::new(
        7,
        address.device_id(),
        None,
        1.into(),
        signed.public_key,
        signed_signature.to_vec(),
        1.into(),
        kyber.public_key,
        kyber_signature.to_vec(),
        *identity.identity_key(),
    )
    .unwrap();
    (store, bundle)
}

/// A length-delimited protobuf field: its key, its length and `payload`.
fn field(tag: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for mut value in [(u64::from(tag) << 3) | 2, payload.len() as u64] {
        while value >= 0x80 {
            bytes.push((value as u8) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
    }
    bytes.extend_from_slice(payload);
    bytes
}

/// A PNI signature side-car whose PNI doesn't read, which the decrypt
/// ignores.
fn unverifiable_pni_signature() -> Vec<u8> {
    proto::Content {
        pni_signature_message: Some(proto::PniSignatureMessage {
            pni: Some(vec![0x5a; 3]),
            signature: Some(vec![0x33; 64]),
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// Alice's first message to Bob, unsealed, of `plaintext` (a serialized
/// `Content`), as Bob opens it.
async fn bob_opens(
    plaintext: &[u8],
) -> Result<Option<DecryptedEnvelope>, ServiceError> {
    let (mut bob, envelope) = alice_to_bob(plaintext).await;
    bob.open_envelope(&envelope, &mut rand::rng()).await
}

/// Bob's cipher, and Alice's first message to him, unsealed, of `plaintext`
/// (a serialized `Content`).
async fn alice_to_bob(
    plaintext: &[u8],
) -> (ServiceCipher<InMemSignalProtocolStore>, Envelope) {
    let rng = &mut rand::rng();
    let (alice, bob) = (address(1), address(2));
    let (bob_store, bob_bundle) = device_with_bundle(&bob).await;
    let mut alice_store =
        InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), 1)
            .unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &bob,
        &alice,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        now,
        rng,
    )
    .await
    .unwrap();
    let clock = Rc::new(FixedClock(now));
    let sent = cipher(alice_store, 1, clock.clone())
        .encrypt(&bob, None, plaintext, rng)
        .await
        .unwrap();
    let envelope = Envelope {
        r#type: Some(sent.r#type as i32),
        source_service_id: Some(alice.name().to_owned()),
        source_device_id: Some(1),
        destination_service_id: Some(bob.name().to_owned()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(BASE64_STANDARD.decode(&sent.content).unwrap().into()),
        ..Default::default()
    };
    (cipher(bob_store, 2, clock), envelope)
}

/// A sender key distribution message of Alice's, for `distribution_id`.
async fn alice_sender_key(distribution_id: Uuid) -> Vec<u8> {
    let rng = &mut rand::rng();
    let mut store =
        InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), 1)
            .unwrap();
    create_sender_key_distribution_message(
        &address(1),
        distribution_id,
        &mut store,
        rng,
    )
    .await
    .unwrap()
    .serialized()
    .to_vec()
}

/// The plaintext comes back as its sender serialized it, beside the content
/// decoded from it: with the fields this crate's protos don't know, a newer
/// one in the `DataMessage` and a newer kind of content, and with the
/// side-cars.
#[tokio::test]
async fn open_envelope_keeps_the_senders_bytes() {
    let text = proto::Content {
        content: Some(proto::content::Content::DataMessage(
            proto::DataMessage {
                body: Some("kept".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let sent = [
        text.encode_to_vec(),
        field(1, &field(1000, b"a newer field")),
        field(100, b"a newer kind"),
        unverifiable_pni_signature(),
    ]
    .concat();

    let opened = bob_opens(&sent).await.unwrap().expect("opened");
    assert_eq!(opened.plaintext, sent);
    match opened.body {
        Some(ContentBody::DataMessage(message)) => {
            assert_eq!(message.body.as_deref(), Some("kept"))
        },
        other => panic!("{other:?}"),
    }
    assert_eq!(
        opened.metadata.sender.service_id_string(),
        address(1).name()
    );
    assert_eq!(opened.metadata.pni_verified.unwrap(), None);
}

/// A plaintext that holds no content of a kind this crate knows comes back
/// whole, without a body, where it was dropped: a kind newer than its protos,
/// a side-car alone, nothing at all.
#[tokio::test]
async fn open_envelope_passes_on_content_of_no_kind_it_knows() {
    for sent in [
        field(100, b"a newer kind"),
        unverifiable_pni_signature(),
        Vec::new(),
    ] {
        let opened = bob_opens(&sent).await.unwrap().expect("opened");
        assert_eq!(opened.plaintext, sent);
        assert!(opened.body.is_none(), "{:?}", opened.body);
        assert_eq!(
            opened.metadata.sender.service_id_string(),
            address(1).name()
        );
    }
}

/// A sender key distribution beside a message is applied, and one that
/// doesn't parse costs only itself, as Signal-Desktop has it: the message
/// beside it is passed on, where the envelope failed after the decrypt had
/// moved the session on, and the message was lost.
#[tokio::test]
async fn a_sender_key_distribution_that_doesnt_parse_costs_only_itself() {
    let distribution_id = Uuid::from_u128(7);
    let text = proto::Content {
        content: Some(proto::content::Content::DataMessage(
            proto::DataMessage {
                body: Some("beside it".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
    .encode_to_vec();
    for (skdm, applied) in [
        (alice_sender_key(distribution_id).await, true),
        (vec![0x5a; 3], false),
    ] {
        let sent = [text.clone(), field(7, &skdm)].concat();
        let (mut bob, envelope) = alice_to_bob(&sent).await;
        let opened = bob
            .open_envelope(&envelope, &mut rand::rng())
            .await
            .unwrap()
            .expect("opened");
        match opened.body {
            Some(ContentBody::DataMessage(message)) => {
                assert_eq!(message.body.as_deref(), Some("beside it"))
            },
            other => panic!("{other:?}"),
        }
        assert_eq!(opened.plaintext, sent);
        let stored = bob
            .protocol_store
            .load_sender_key(&address(1), distribution_id)
            .await
            .unwrap();
        assert_eq!(stored.is_some(), applied);
    }
}

/// A decryption error that doesn't decode is dropped, as both official
/// clients drop it, where it failed the envelope, which then read as one
/// that didn't decrypt.
#[tokio::test]
async fn a_decryption_error_that_doesnt_decode_is_dropped() {
    // A ratchet key cut short.
    let sent = field(8, &[0x0a, 0x05]);
    let opened = bob_opens(&sent).await;
    assert!(matches!(opened, Ok(None)), "{opened:?}");
}

/// A sender certificate is checked at the time the server took the message,
/// as Desktop and Android check it, not at the time its sender claims: a
/// sender with a fast clock keeps its messages, and a back-dated message
/// can't pass an expired certificate.
#[tokio::test]
async fn sealed_sender_certificate_is_checked_at_the_server_timestamp() {
    let rng = &mut rand::rng();
    let (alice_aci, bob) = (Aci::from(Uuid::from_u128(1)), address(2));
    let alice = ProtocolAddress::new(
        alice_aci.service_id_string(),
        DeviceId::new(1).unwrap(),
    );
    let (bob_store, bob_bundle) = device_with_bundle(&bob).await;
    let alice_identity = IdentityKeyPair::generate(rng);
    let mut alice_store =
        InMemSignalProtocolStore::new(alice_identity, 1).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &bob,
        &alice,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        now,
        rng,
    )
    .await
    .unwrap();

    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let expires: u64 = 1_800_000_000_000;
    let certificate = SenderCertificate::new(
        alice_aci.service_id_string(),
        None,
        *alice_identity.public_key(),
        alice.device_id(),
        Timestamp::from_epoch_millis(expires),
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
    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(
            proto::DataMessage {
                body: Some("sealed".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let sealed = sealed_sender_encrypt(
        &bob,
        &certificate,
        &add_padding(4, &content.encode_to_vec()).unwrap(),
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        now,
        rng,
    )
    .await
    .unwrap();

    let open = |client_timestamp: u64, server_timestamp: u64| {
        let envelope = Envelope {
            r#type: Some(Type::UnidentifiedSender.into()),
            destination_service_id: Some(bob.name().to_owned()),
            client_timestamp: Some(client_timestamp),
            server_timestamp: Some(server_timestamp),
            content: Some(sealed.clone().into()),
            ..Default::default()
        };
        let mut cipher = ServiceCipher::new(
            bob_store.clone(),
            vec![trust_root.public_key],
            aci(2),
            device(),
            Rc::new(FixedClock(now)),
        );
        async move { cipher.open_envelope(&envelope, &mut rand::rng()).await }
    };
    let hour = 60 * 60 * 1000;

    // The sender's clock runs a day fast; the server took the message an
    // hour before the certificate expired.
    let opened = open(expires + 24 * hour, expires - hour).await;
    let body = match opened.unwrap().expect("content").body {
        Some(ContentBody::DataMessage(message)) => message.body,
        other => panic!("{other:?}"),
    };
    assert_eq!(body.as_deref(), Some("sealed"));

    // A message the server took a day after the certificate expired, which
    // claims to be older.
    let refused = open(expires - hour, expires + 24 * hour).await;
    assert!(
        matches!(
            &refused,
            Err(ServiceError::SealedSenderDecryptionError(error))
                if matches!(
                    error.inner,
                    SignalProtocolError::InvalidSealedSenderMessage(_)
                )
        ),
        "{refused:?}"
    );
}

/// A `Content` holding a decryption error alone.
fn decryption_error() -> proto::Content {
    proto::Content {
        content: Some(proto::content::Content::DecryptionErrorMessage(
            proto::DecryptionErrorMessage {
                timestamp: Some(1_700_000_000_000),
                device_id: Some(1),
                ..Default::default()
            }
            .encode_to_vec(),
        )),
        ..Default::default()
    }
}

/// `content` as a serialized `PlaintextContent`, as libsignal makes one:
/// its marker byte, the content and the padding boundary.
fn plaintext_content(content: &proto::Content) -> Vec<u8> {
    [&[0xc0][..], &content.encode_to_vec(), &[0x80]].concat()
}

/// Bob's cipher, and Alice's `PlaintextContent` of `content` to him in an
/// unsealed envelope, whose source only the server vouches for.
async fn unsealed_plaintext(
    content: &proto::Content,
) -> (ServiceCipher<InMemSignalProtocolStore>, Envelope) {
    let bob = address(2);
    let (bob_store, _) = device_with_bundle(&bob).await;
    let envelope = Envelope {
        r#type: Some(Type::PlaintextContent.into()),
        source_service_id: Some(address(1).name().to_owned()),
        source_device_id: Some(1),
        destination_service_id: Some(bob.name().to_owned()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(plaintext_content(content).into()),
        ..Default::default()
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    (cipher(bob_store, 2, Rc::new(FixedClock(now))), envelope)
}

/// Bob's cipher, which trusts the root of Alice's sender certificate, and
/// Alice's `PlaintextContent` of `content` to him in a sealed envelope: a
/// sealed-sender message of the plaintext type, which no session encrypts.
async fn sealed_plaintext(
    content: &proto::Content,
) -> (ServiceCipher<InMemSignalProtocolStore>, Envelope) {
    let rng = &mut rand::rng();
    let (alice, bob) = (address(1), address(2));
    let (bob_store, bob_bundle) = device_with_bundle(&bob).await;
    let alice_identity = IdentityKeyPair::generate(rng);
    let mut alice_store =
        InMemSignalProtocolStore::new(alice_identity, 1).unwrap();
    alice_store
        .save_identity(&bob, bob_bundle.identity_key().unwrap())
        .await
        .unwrap();
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let certificate = SenderCertificate::new(
        alice.name().to_owned(),
        None,
        *alice_identity.public_key(),
        alice.device_id(),
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
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        certificate,
        plaintext_content(content),
        ContentHint::Default,
        None,
    )
    .unwrap();
    let sealed =
        sealed_sender_encrypt_from_usmc(&bob, &usmc, &alice_store, rng)
            .await
            .unwrap();
    let envelope = Envelope {
        r#type: Some(Type::UnidentifiedSender.into()),
        destination_service_id: Some(bob.name().to_owned()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(sealed.into()),
        ..Default::default()
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let cipher = ServiceCipher::new(
        bob_store,
        vec![trust_root.public_key],
        aci(2),
        device(),
        Rc::new(FixedClock(now)),
    );
    (cipher, envelope)
}

/// A plaintext in a sealed envelope is a plaintext, as Signal-Desktop reads
/// it and Signal-Android by its inner type: no session authenticates it, so
/// it is passed on only as a decryption error, where whatever it held passed
/// for a message from its certificate's sender.
#[tokio::test]
async fn a_sealed_plaintext_is_passed_on_only_as_a_decryption_error() {
    let forged = proto::Content {
        content: Some(proto::content::Content::DataMessage(
            proto::DataMessage {
                body: Some("forged".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let (mut bob, envelope) = sealed_plaintext(&forged).await;
    let opened = bob.open_envelope(&envelope, &mut rand::rng()).await;
    assert!(matches!(opened, Ok(None)), "{opened:?}");

    let (mut bob, envelope) = sealed_plaintext(&decryption_error()).await;
    let opened = bob
        .open_envelope(&envelope, &mut rand::rng())
        .await
        .unwrap()
        .expect("a decryption error");
    assert!(
        matches!(opened.body, Some(ContentBody::DecryptionErrorMessage(_))),
        "{:?}",
        opened.body
    );
    assert!(opened.metadata.was_plaintext);
    assert!(opened.metadata.unidentified_sender);
    assert_eq!(
        opened.metadata.sender.service_id_string(),
        address(1).name()
    );
}

/// A plaintext, sealed or not, that carries a side-car beside its decryption
/// error is dropped, and its sender key distribution isn't applied: only the
/// server's word names its sender, so a sender key taken from one would pass
/// the server's forgeries as that sender's group messages, or evict the
/// sender's own key. The decryption error alone is passed on.
#[tokio::test]
async fn a_plaintext_with_a_side_car_is_dropped_and_its_sender_key_not_stored()
{
    let distribution_id = Uuid::from_u128(7);
    let with_sender_key = proto::Content {
        sender_key_distribution_message: Some(
            alice_sender_key(distribution_id).await,
        ),
        ..decryption_error()
    };
    let with_pni_signature = proto::Content {
        pni_signature_message: Some(proto::PniSignatureMessage {
            pni: Some(vec![0x5a; 3]),
            signature: Some(vec![0x33; 64]),
        }),
        ..decryption_error()
    };
    for (content, passed_on) in [
        (decryption_error(), true),
        (with_sender_key, false),
        (with_pni_signature, false),
    ] {
        for (mut bob, envelope) in [
            unsealed_plaintext(&content).await,
            sealed_plaintext(&content).await,
        ] {
            let opened = bob
                .open_envelope(&envelope, &mut rand::rng())
                .await
                .unwrap();
            assert_eq!(opened.is_some(), passed_on, "{content:?}");
            let stored = bob
                .protocol_store
                .load_sender_key(&address(1), distribution_id)
                .await
                .unwrap();
            assert!(stored.is_none());
        }
    }
}

/// An unsealed envelope (PreKey, whisper or plaintext) without a source to
/// decrypt it from, or with one that doesn't read, is an invalid frame, where
/// the decrypt panicked. Signal-Server's sealed path queues one for anyone
/// holding the account's access key: it checks only the key and the type's
/// number.
#[tokio::test]
async fn an_identified_envelope_without_a_source_is_an_invalid_frame() {
    let bob = address(2);
    let (bob_store, _) = device_with_bundle(&bob).await;
    let mut cipher =
        cipher(bob_store, 2, Rc::new(FixedClock(SystemTime::UNIX_EPOCH)));
    let unreadable = [
        (None, None),
        (Some("not a service id".to_owned()), None),
        (None, Some(vec![0x5a; 3])),
    ];
    for kind in [
        Type::PrekeyMessage,
        Type::DoubleRatchet,
        Type::PlaintextContent,
    ] {
        for (source, source_binary) in unreadable.clone() {
            let envelope = Envelope {
                r#type: Some(kind.into()),
                source_service_id: source,
                source_service_id_binary: source_binary,
                source_device_id: Some(1),
                destination_service_id: Some(bob.name().to_owned()),
                client_timestamp: Some(1_700_000_000_000),
                server_timestamp: Some(1_700_000_000_001),
                content: Some(vec![0x33; 64].into()),
                ..Default::default()
            };
            match cipher.decrypt(&envelope, &mut rand::rng()).await {
                Err(ServiceError::InvalidFrame { reason }) => assert_eq!(
                    reason,
                    "an identified envelope without a valid source service id",
                    "{kind:?}"
                ),
                Err(error) => panic!("{kind:?}: {error:?}"),
                Ok(_) => panic!("{kind:?}: decrypted"),
            }
        }
    }
}

/// A sender certificate whose sender isn't a UUID, though a trust root
/// signed it, is an invalid sealed-sender message, where the decrypt
/// panicked.
#[tokio::test]
async fn a_sealed_sender_that_isnt_a_uuid_is_refused() {
    let rng = &mut rand::rng();
    let (alice, bob) = (address(1), address(2));
    let (bob_store, bob_bundle) = device_with_bundle(&bob).await;
    let alice_identity = IdentityKeyPair::generate(rng);
    let mut alice_store =
        InMemSignalProtocolStore::new(alice_identity, 1).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &bob,
        &alice,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        now,
        rng,
    )
    .await
    .unwrap();
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let certificate = SenderCertificate::new(
        "not a uuid".to_owned(),
        None,
        *alice_identity.public_key(),
        alice.device_id(),
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
    let sealed = sealed_sender_encrypt(
        &bob,
        &certificate,
        &add_padding(4, &[]).unwrap(),
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        now,
        rng,
    )
    .await
    .unwrap();
    let envelope = Envelope {
        r#type: Some(Type::UnidentifiedSender.into()),
        destination_service_id: Some(bob.name().to_owned()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_000),
        content: Some(sealed.into()),
        ..Default::default()
    };
    let mut cipher = ServiceCipher::new(
        bob_store,
        vec![trust_root.public_key],
        aci(2),
        device(),
        Rc::new(FixedClock(now)),
    );
    match cipher.decrypt(&envelope, rng).await {
        Err(ServiceError::SealedSenderDecryptionError(error)) => assert!(
            matches!(
                &error.inner,
                SignalProtocolError::InvalidSealedSenderMessage(reason)
                    if reason == "invalid sender UUID"
            ),
            "{error:?}"
        ),
        Err(error) => panic!("{error:?}"),
        Ok(_) => panic!("decrypted"),
    }
}

/// Bob's cipher, which trusts the root of the sender's certificate, and a
/// sealed message of `plaintext` (a serialized `Content`) to him from the
/// account `sender`'s device.
async fn sealed_to_bob(
    sender: u128,
    plaintext: &[u8],
) -> (ServiceCipher<InMemSignalProtocolStore>, Envelope) {
    let rng = &mut rand::rng();
    let (from, bob) = (address(sender), address(2));
    let (bob_store, bob_bundle) = device_with_bundle(&bob).await;
    let identity = IdentityKeyPair::generate(rng);
    let mut store = InMemSignalProtocolStore::new(identity, 1).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &bob,
        &from,
        &mut store.session_store,
        &mut store.identity_store,
        &bob_bundle,
        now,
        rng,
    )
    .await
    .unwrap();
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let certificate = SenderCertificate::new(
        from.name().to_owned(),
        None,
        *identity.public_key(),
        from.device_id(),
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
    let sealed = sealed_sender_encrypt(
        &bob,
        &certificate,
        &add_padding(4, plaintext).unwrap(),
        &mut store.session_store,
        &mut store.identity_store,
        now,
        rng,
    )
    .await
    .unwrap();
    let envelope = Envelope {
        r#type: Some(Type::UnidentifiedSender.into()),
        destination_service_id: Some(bob.name().to_owned()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(sealed.into()),
        ..Default::default()
    };
    let cipher = ServiceCipher::new(
        bob_store,
        vec![trust_root.public_key],
        aci(2),
        device(),
        Rc::new(FixedClock(now)),
    );
    (cipher, envelope)
}

/// A cipher is of the identity and the device it is given, as typed: it opens
/// what names that identity, ACI or PNI, and nothing else, and knows its own
/// device in a sealed message's certificate.
#[tokio::test]
async fn a_cipher_is_of_the_identity_and_device_it_is_given() {
    let rng = &mut rand::rng();
    let pni = ServiceId::from(Pni::from(Uuid::from_u128(2)));
    let third = DeviceId::new(3).unwrap();
    let local = pni.to_protocol_address(third);
    let (store, bundle) = device_with_bundle(&local).await;
    let mut alice =
        InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), 1)
            .unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    process_prekey_bundle(
        &local,
        &address(1),
        &mut alice.session_store,
        &mut alice.identity_store,
        &bundle,
        now,
        rng,
    )
    .await
    .unwrap();
    let clock = Rc::new(FixedClock(now));
    let sent = cipher(alice, 1, clock.clone())
        .encrypt(&local, None, &[], rng)
        .await
        .unwrap();
    let mut ours = ServiceCipher::new(store, vec![], pni, third, clock);
    assert!(format!("{ours:?}").contains(&format!("{local:?}")));
    for (destination, opens) in [(aci(2), false), (pni, true)] {
        let envelope = Envelope {
            r#type: Some(sent.r#type as i32),
            source_service_id: Some(address(1).name().to_owned()),
            source_device_id: Some(1),
            destination_service_id: Some(destination.service_id_string()),
            content: Some(
                BASE64_STANDARD.decode(&sent.content).unwrap().into(),
            ),
            ..Default::default()
        };
        match ours.open_envelope(&envelope, rng).await {
            Ok(Some(opened)) => {
                assert!(opens);
                assert_eq!(opened.metadata.destination, pni);
            },
            Err(ServiceError::InvalidFrame { reason }) => {
                assert!(!opens, "{reason}");
                assert_eq!(reason, "mismatch destination service id");
            },
            other => panic!("{other:?}"),
        }
    }

    for (sender, self_send) in [(1, false), (2, true)] {
        let (mut bob, envelope) = sealed_to_bob(sender, &[]).await;
        match bob.open_envelope(&envelope, rng).await {
            Ok(Some(_)) => assert!(!self_send),
            Err(ServiceError::SealedSenderDecryptionError(error)) => {
                assert!(self_send, "{error:?}");
                assert!(matches!(
                    error.inner,
                    SignalProtocolError::SealedSenderSelfSend
                ));
            },
            other => panic!("{other:?}"),
        }
    }
}

/// A timestamp past what chrono holds (about 8.21e15 ms), which a sender may
/// state, since Signal-Server takes one up to 8.64e15, costs nothing: the
/// envelope opens, sealed or not, and says what it said, where it failed after
/// the decrypt had moved the session on, and the message was lost.
#[tokio::test]
async fn a_timestamp_past_chronos_range_keeps_the_message() {
    let text = proto::Content {
        content: Some(proto::content::Content::DataMessage(
            proto::DataMessage {
                body: Some("from the far future".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
    .encode_to_vec();
    // Signal-Server's `MessageController.MAX_TIMESTAMP`, then what an `i64`
    // holds as negative.
    for timestamp in [8_640_000_000_000_000, 1 << 63, u64::MAX] {
        for (mut bob, envelope) in
            [alice_to_bob(&text).await, sealed_to_bob(1, &text).await]
        {
            let envelope = Envelope {
                client_timestamp: Some(timestamp),
                ..envelope
            };
            let opened = bob
                .open_envelope(&envelope, &mut rand::rng())
                .await
                .unwrap()
                .expect("opened");
            assert_eq!(opened.plaintext, text);
            assert_eq!(opened.metadata.client_timestamp, timestamp);
            assert_eq!(opened.metadata.server_timestamp, 1_700_000_000_001);
            match opened.body {
                Some(ContentBody::DataMessage(message)) => assert_eq!(
                    message.body.as_deref(),
                    Some("from the far future")
                ),
                other => panic!("{other:?}"),
            }
        }

        // The server's own, at which a sealed sender's certificate is checked.
        let (mut bob, envelope) = alice_to_bob(&text).await;
        let envelope = Envelope {
            server_timestamp: Some(timestamp),
            ..envelope
        };
        let opened = bob
            .open_envelope(&envelope, &mut rand::rng())
            .await
            .unwrap()
            .expect("opened");
        assert_eq!(opened.metadata.server_timestamp, timestamp);
    }
}
