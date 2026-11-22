//! The ids `replenish_pre_keys` gives a batch, which go round a cycle of
//! 1 to 0xFFFFFE.

mod common;

use std::time::SystemTime;

use async_trait::async_trait;
use futures::FutureExt as _;
use libsignal_service::{
    pre_keys::{replenish_pre_keys, KyberPreKeyStoreExt, PreKeysStore},
    protocol::{
        GenericSignedPreKey as _, IdentityKeyPair, IdentityKeyStore as _,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore as _,
        PreKeyStore as _, SignalProtocolError, SignedPreKeyId,
    },
};

use common::{store::LocalStore, ManualClock};

type StoreResult<T> = Result<T, SignalProtocolError>;

/// A batch that ends on the cycle's last id puts its last-resort Kyber key at
/// 1, where an assert panicked; one that crosses the end goes on from 1; and
/// an offset beyond the cycle, which no store should give, overflows nothing.
#[test]
fn a_batch_goes_round_the_cycle_of_ids() {
    for (offset, count, one_time, last_resort) in [
        (0xFF_FFFC, 2, vec![0xFF_FFFD, 0xFF_FFFE], 1),
        (0xFF_FFFC, 3, vec![0xFF_FFFD, 0xFF_FFFE, 1], 2),
        (u32::MAX, 2, vec![512, 513], 514),
    ] {
        let rng = &mut rand::rng();
        let identity = IdentityKeyPair::generate(rng);
        let mut store = LocalStore::new(identity, offset);
        let (pre_keys, _, kyber, last) = replenish_pre_keys(
            &mut store,
            rng,
            &ManualClock::default(),
            &identity,
            true,
            count,
            count,
        )
        .now_or_never()
        .expect("the store doesn't wait")
        .unwrap();

        let ids: Vec<u32> = pre_keys
            .iter()
            .map(|key| key.id().unwrap().into())
            .collect();
        assert_eq!(ids, one_time, "{offset:#x}, {count}");
        let ids: Vec<u32> =
            kyber.iter().map(|key| key.id().unwrap().into()).collect();
        assert_eq!(ids, one_time, "{offset:#x}, {count}");
        let last = last.expect("requested");
        assert_eq!(u32::from(last.id().unwrap()), last_resort);
        for &id in &one_time {
            stored(store.get_pre_key(id.into()));
            stored(store.get_kyber_pre_key(id.into()));
        }
        stored(store.get_kyber_pre_key(last_resort.into()));
    }
}

/// What the store answered at once.
fn stored<T>(read: impl std::future::Future<Output = StoreResult<T>>) -> T {
    read.now_or_never()
        .expect("the store doesn't wait")
        .expect("stored")
}

// A batch numbers its EC and Kyber keys from the store's registration id, so a
// test picks where a batch starts by the store it makes.

#[async_trait(?Send)]
impl PreKeysStore for LocalStore {
    async fn next_pre_key_id(&self) -> StoreResult<u32> {
        self.get_local_registration_id().await
    }

    async fn next_signed_pre_key_id(&self) -> StoreResult<u32> {
        Ok(1)
    }

    async fn next_pq_pre_key_id(&self) -> StoreResult<u32> {
        self.get_local_registration_id().await
    }

    async fn signed_pre_keys_count(&self) -> StoreResult<usize> {
        unreachable!("a batch counts no keys")
    }

    async fn kyber_pre_keys_count(&self, _: bool) -> StoreResult<usize> {
        unreachable!("a batch counts no keys")
    }

    async fn signed_prekey_id(&self) -> StoreResult<Option<SignedPreKeyId>> {
        unreachable!("a batch counts no keys")
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> StoreResult<Option<KyberPreKeyId>> {
        unreachable!("a batch counts no keys")
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for LocalStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> StoreResult<()> {
        self.save_kyber_pre_key(id, record).await
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> StoreResult<Vec<KyberPreKeyRecord>> {
        unreachable!("a batch loads no keys")
    }

    async fn remove_kyber_pre_key(
        &mut self,
        _: KyberPreKeyId,
    ) -> StoreResult<()> {
        unreachable!("a batch removes no keys")
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _: SystemTime,
    ) -> StoreResult<()> {
        unreachable!("a batch marks no keys")
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _: SystemTime,
        _: usize,
    ) -> StoreResult<()> {
        unreachable!("a batch deletes no keys")
    }
}
