//! What `replenish_pre_keys` makes: the ids it gives a batch, which go round a
//! cycle of 1 to 0xFFFFFE, and a batch without a signed prekey.

mod common;

use std::{cell::Cell, time::SystemTime};

use async_trait::async_trait;
use futures::FutureExt as _;
use libsignal_service::{
    pre_keys::{
        replenish_pre_keys, KyberPreKeyStoreExt, PreKeyState, PreKeysStore,
        SignedPreKeyEntity,
    },
    protocol::{
        GenericSignedPreKey as _, IdentityKeyPair, IdentityKeyStore as _,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore as _,
        PreKeyStore as _, SignalProtocolError, SignedPreKeyId,
        SignedPreKeyStore as _,
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

/// A refill makes a signed prekey only when asked for one, as the official
/// clients do: without it none is generated or saved, the store is asked no id
/// for one, and the upload leaves `signedPreKey` out, which keeps the server's.
#[test]
fn a_batch_without_a_signed_prekey_saves_and_uploads_none() {
    for rotate in [false, true] {
        let rng = &mut rand::rng();
        let identity = IdentityKeyPair::generate(rng);
        let mut store = LocalStore::new(identity, 7);
        let (pre_keys, signed, kyber, last_resort) = replenish_pre_keys(
            &mut store,
            rng,
            &ManualClock::default(),
            &identity,
            rotate,
            false,
            2,
            2,
        )
        .now_or_never()
        .expect("the store doesn't wait")
        .unwrap();
        assert_eq!((pre_keys.len(), kyber.len()), (2, 2));
        assert!(last_resort.is_none());

        assert_eq!(signed.is_some(), rotate);
        assert_eq!(SIGNED_IDS_ASKED.take(), u32::from(rotate));
        let saved = store
            .get_signed_pre_key(SIGNED_ID.into())
            .now_or_never()
            .expect("the store doesn't wait");
        assert_eq!(saved.is_ok(), rotate, "{:?}", saved.err());

        let upload = PreKeyState {
            pre_keys: Vec::new(),
            signed_pre_key: signed
                .map(SignedPreKeyEntity::try_from)
                .transpose()
                .unwrap(),
            identity_key: *identity.identity_key(),
            pq_last_resort_key: None,
            pq_pre_keys: Vec::new(),
        };
        let upload = serde_json::to_value(&upload).unwrap();
        assert_eq!(upload.get("signedPreKey").is_some(), rotate, "{upload}");
    }
}

/// What the store answered at once.
fn stored<T>(read: impl std::future::Future<Output = StoreResult<T>>) -> T {
    read.now_or_never()
        .expect("the store doesn't wait")
        .expect("stored")
}

/// The id the store gives the next signed prekey.
const SIGNED_ID: u32 = 1;

thread_local! {
    /// How many times the store was asked for it, on this test's thread.
    static SIGNED_IDS_ASKED: Cell<u32> = const { Cell::new(0) };
}

// A batch numbers its EC and Kyber keys from the store's registration id, so a
// test picks where a batch starts by the store it makes.

#[async_trait(?Send)]
impl PreKeysStore for LocalStore {
    async fn next_pre_key_id(&self) -> StoreResult<u32> {
        self.get_local_registration_id().await
    }

    async fn next_signed_pre_key_id(&self) -> StoreResult<u32> {
        SIGNED_IDS_ASKED.set(SIGNED_IDS_ASKED.get() + 1);
        Ok(SIGNED_ID)
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
