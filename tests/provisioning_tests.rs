//! The provisioning socket: what the server's requests make of a link.

mod common;

use std::rc::Rc;

use async_trait::async_trait;
use futures::{
    channel::mpsc, executor::LocalPool, future::FutureExt as _,
    task::LocalSpawnExt as _, StreamExt as _,
};
use libsignal_service::{
    pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
    prelude::ProtobufMessage,
    proto::{ProvisioningAddress, WebSocketRequestMessage},
    protocol::{
        IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord, SignalProtocolError,
        SignedPreKeyId,
    },
    provisioning::{
        link_device, ProvisioningError, SecondaryDeviceProvisioning,
    },
};

use common::{store::LocalStore, *};

type StoreResult<T> = Result<T, SignalProtocolError>;

/// Links a device over a provisioning socket on which the server sends these
/// requests, each a path and a body. Returns how the link ended and the
/// links it showed.
fn link(
    requests: &[(&str, Option<Vec<u8>>)],
) -> (Result<(), ProvisioningError>, Vec<String>) {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let server = transport.accept_socket(&[]);
    for (id, (path, body)) in (1..).zip(requests) {
        server.request_message(WebSocketRequestMessage {
            id: Some(id),
            verb: Some("PUT".into()),
            path: Some((*path).into()),
            body: body.clone().map(Into::into),
            headers: Vec::new(),
        });
    }
    let mut rng = rand::rng();
    let mut aci = LocalStore::new(IdentityKeyPair::generate(&mut rng), 1);
    let mut pni = LocalStore::new(IdentityKeyPair::generate(&mut rng), 2);
    let (tx, rx) = mpsc::channel(1);
    let link = pool
        .spawner()
        .spawn_local_with_handle(async move {
            link_device(
                &mut aci,
                &mut pni,
                &mut rng,
                Rc::new(ManualClock::default()),
                service,
                "password",
                "device",
                tx,
            )
            .await
        })
        .unwrap();
    pool.run_until_stalled();
    let ended = link.now_or_never().expect("the link ended");
    let shown = rx
        .map(|step| match step {
            SecondaryDeviceProvisioning::Url(url) => url.into(),
            other => panic!("not a link: {other:?}"),
        })
        .collect()
        .now_or_never()
        .expect("the link ended");
    (ended, shown)
}

/// A request of the server's without a body fails the link with the step it
/// stood for, instead of a panic.
#[test]
fn a_request_without_a_body_fails_the_link() {
    let (ended, shown) = link(&[("/v1/address", None)]);
    assert!(
        matches!(ended, Err(ProvisioningError::MissingUrl)),
        "{ended:?}"
    );
    assert_eq!(shown, Vec::<String>::new());

    let address = ProvisioningAddress {
        address: Some("an-address".into()),
    };
    let (ended, shown) = link(&[
        ("/v1/address", Some(address.encode_to_vec())),
        ("/v1/message", None),
    ]);
    assert!(
        matches!(ended, Err(ProvisioningError::MissingMessage)),
        "{ended:?}"
    );
    let [shown] = &shown[..] else {
        panic!("one link: {shown:?}")
    };
    assert!(
        shown.starts_with("sgnl://linkdevice?uuid=an-address&pub_key="),
        "{shown}"
    );
}

// The link fails before it makes or uploads keys, so it asks the stores
// nothing beyond what `LocalStore` implements.

#[async_trait(?Send)]
impl PreKeysStore for LocalStore {
    async fn next_pre_key_id(&self) -> StoreResult<u32> {
        unreachable!("the link makes no keys")
    }

    async fn next_signed_pre_key_id(&self) -> StoreResult<u32> {
        unreachable!("the link makes no keys")
    }

    async fn next_pq_pre_key_id(&self) -> StoreResult<u32> {
        unreachable!("the link makes no keys")
    }

    async fn signed_pre_keys_count(&self) -> StoreResult<usize> {
        unreachable!("the link makes no keys")
    }

    async fn kyber_pre_keys_count(&self, _: bool) -> StoreResult<usize> {
        unreachable!("the link makes no keys")
    }

    async fn signed_prekey_id(&self) -> StoreResult<Option<SignedPreKeyId>> {
        unreachable!("the link makes no keys")
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> StoreResult<Option<KyberPreKeyId>> {
        unreachable!("the link makes no keys")
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for LocalStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        _: KyberPreKeyId,
        _: &KyberPreKeyRecord,
    ) -> StoreResult<()> {
        unreachable!("the link makes no keys")
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> StoreResult<Vec<KyberPreKeyRecord>> {
        unreachable!("the link makes no keys")
    }

    async fn remove_kyber_pre_key(
        &mut self,
        _: KyberPreKeyId,
    ) -> StoreResult<()> {
        unreachable!("the link makes no keys")
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> StoreResult<()> {
        unreachable!("the link makes no keys")
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
    ) -> StoreResult<()> {
        unreachable!("the link makes no keys")
    }
}
