use std::{
    rc::Rc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use futures::future::{self, FutureExt as _, LocalBoxFuture};
use libsignal_protocol::{
    kem, process_prekey_bundle, Aci, DeviceId, IdentityKeyPair,
    InMemSignalProtocolStore, KeyPair, PreKeyBundle, ProtocolAddress,
    ServiceId, SignalProtocolError,
};
use uuid::Uuid;

use super::ServiceCipher;
use crate::{
    proto::envelope::Type, push_service::ServiceError,
    sender::OutgoingPushMessage, session_store::SessionStoreExt,
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
