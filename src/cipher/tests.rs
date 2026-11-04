use std::{
    rc::Rc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use futures::future::{self, FutureExt as _, LocalBoxFuture};
use libsignal_protocol::{
    kem, process_prekey_bundle, sealed_sender_encrypt, Aci, DeviceId,
    GenericSignedPreKey as _, IdentityKeyPair, InMemSignalProtocolStore,
    KeyPair, KyberPreKeyRecord, KyberPreKeyStore as _, PreKeyBundle,
    ProtocolAddress, SenderCertificate, ServerCertificate, ServiceId,
    SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore as _, Timestamp,
};
use prost::Message as _;
use uuid::Uuid;

use super::{add_padding, ServiceCipher};
use crate::{
    content::ContentBody,
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

fn address(id: u128) -> ProtocolAddress {
    ProtocolAddress::new(
        Aci::from(Uuid::from_u128(id)).service_id_string(),
        DeviceId::new(1).unwrap(),
    )
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

async fn encrypt_at(
    store: &InMemSignalProtocolStore,
    local: &ProtocolAddress,
    remote: &ProtocolAddress,
    now: SystemTime,
) -> Result<OutgoingPushMessage, ServiceError> {
    ServiceCipher::new(
        store.clone(),
        vec![],
        local.clone(),
        Rc::new(FixedClock(now)),
    )
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

    let message = encrypt_at(&store, &alice, &bob, started + 29 * day)
        .await
        .unwrap();
    assert_eq!(message.r#type, Type::PrekeyMessage as u32);

    let stale = encrypt_at(&store, &alice, &bob, started + 31 * day).await;
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
            bob.clone(),
            Rc::new(FixedClock(now)),
        );
        async move { cipher.open_envelope(envelope, &mut rand::rng()).await }
    };
    let hour = 60 * 60 * 1000;

    // The sender's clock runs a day fast; the server took the message an
    // hour before the certificate expired.
    let opened = open(expires + 24 * hour, expires - hour).await;
    let body = match opened.unwrap().expect("content").body {
        ContentBody::DataMessage(message) => message.body,
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
