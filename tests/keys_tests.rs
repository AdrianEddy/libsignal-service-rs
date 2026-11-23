//! The prekey upload as Signal-Server reads it, and the last-resort key a
//! refresh sends.

mod common;

use std::{collections::BTreeSet, future::Future, rc::Rc, time::SystemTime};

use async_trait::async_trait;
use base64::prelude::*;
use futures::{
    executor::LocalPool,
    future::{self, FutureExt as _},
    task::LocalSpawnExt as _,
};
use libsignal_service::{
    pre_keys::{
        KyberPreKeyEntity, KyberPreKeyStoreExt, PreKeyState, PreKeysStore,
        SignedPreKeyEntity,
    },
    protocol::{
        kem, GenericSignedPreKey as _, IdentityKeyPair, KeyPair, KyberPreKeyId,
        KyberPreKeyRecord, KyberPreKeyStore as _, ServiceIdKind,
        SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
        SignedPreKeyStore as _, Timestamp,
    },
    websocket::Identified,
    AccountManager,
};
use sha2::{Digest as _, Sha256};

use common::{store::LocalStore, *};

type StoreResult<T> = Result<T, SignalProtocolError>;

/// The upload names its fields as Signal-Server's `SetKeysRequest` does
/// (`preKeys`, `signedPreKey`, `pqPreKeys`, `pqLastResortPreKey`; it ignores
/// `identityKey`), and it ignores a field it doesn't know: under another name
/// the last-resort key answered 204 and changed nothing. A key left out keeps
/// the server's: no signed prekey goes when its rotation isn't due.
#[test]
fn the_upload_names_its_keys_as_signal_server_reads_them() {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let mut server = transport.accept_socket(&[]);
    let (mut ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            Rc::new(ManualClock::default()),
        ))
        .unwrap();
    pool.spawner().spawn_local(task.map(drop)).unwrap();
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let (public_key, signature) = (vec![0x0b; 1569], vec![0x0c; 64]);
    let last_resort = || KyberPreKeyEntity {
        key_id: 4,
        public_key: public_key.clone(),
        signature: signature.clone(),
    };
    let signed = || SignedPreKeyEntity {
        key_id: 3,
        public_key: vec![0x05; 33],
        signature: vec![0x0a; 64],
    };
    let state = |signed_pre_key, pq_last_resort_key| PreKeyState {
        pre_keys: Vec::new(),
        signed_pre_key,
        identity_key: *identity.identity_key(),
        pq_last_resort_key,
        pq_pre_keys: Vec::new(),
    };

    for (signed_pre_key, pq_last_resort_key, names) in [
        (
            Some(signed()),
            Some(last_resort()),
            vec![
                "identityKey",
                "pqLastResortPreKey",
                "pqPreKeys",
                "preKeys",
                "signedPreKey",
            ],
        ),
        (
            Some(signed()),
            None,
            vec!["identityKey", "pqPreKeys", "preKeys", "signedPreKey"],
        ),
        (None, None, vec!["identityKey", "pqPreKeys", "preKeys"]),
    ] {
        let (uploaded, request) = pool.run_until(future::join(
            ws.register_pre_keys(
                ServiceIdKind::Aci,
                state(signed_pre_key, pq_last_resort_key),
            ),
            async {
                let request = sent_request(server.next_sent().await);
                server.respond(request.id(), 204, b"");
                request
            },
        ));
        uploaded.unwrap();
        assert_eq!(
            (request.verb(), request.path()),
            ("PUT", &*format!("/v2/keys?identity={}", ServiceIdKind::Aci))
        );
        let body: serde_json::Value =
            serde_json::from_slice(request.body()).unwrap();
        let fields: BTreeSet<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(fields, names.into_iter().collect());
        if fields.contains("pqLastResortPreKey") {
            assert_eq!(
                body["pqLastResortPreKey"],
                serde_json::json!({
                    "keyId": 4,
                    "publicKey": BASE64_STANDARD.encode(&public_key),
                    "signature": BASE64_STANDARD.encode(&signature),
                })
            );
        }
    }
}

/// The store's last-resort Kyber keys: it lists the older first and names the
/// newer current, as a store does that kept its old key through a rotation.
const OLDER: u32 = 1;
const CURRENT: u32 = 2;
/// The store's current signed key.
const SIGNED: u32 = 1;

/// A refresh uploads the last-resort key the store names current, the one
/// `check_pre_keys` hashes, not the first the store lists: Signal-Server
/// keeps whichever key it is sent, so the older one would undo the rotation
/// and fail every later check.
#[test]
fn a_refresh_uploads_the_current_last_resort_key() {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let mut server = transport.accept_socket(&[]);
    let clock = Rc::new(ManualClock::default());
    let (ws, task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials()),
            clock.clone(),
        ))
        .unwrap();
    pool.spawner().spawn_local(task.map(drop)).unwrap();
    let mut manager = AccountManager::new(service, ws, None, clock);

    let rng = &mut rand::rng();
    let identity = IdentityKeyPair::generate(rng);
    let mut store = LocalStore::new(identity, 1);
    let signed = KeyPair::generate(rng);
    let signature = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), rng)
        .unwrap();
    now(store.save_signed_pre_key(
        SIGNED.into(),
        &SignedPreKeyRecord::new(
            SIGNED.into(),
            Timestamp::from_epoch_millis(0),
            &signed,
            &signature,
        ),
    ));
    let mut last_resort = Vec::new();
    for id in [OLDER, CURRENT] {
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let signature = identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), rng)
            .unwrap();
        now(store.save_kyber_pre_key(
            id.into(),
            &KyberPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(0),
                &kyber,
                &signature,
            ),
        ));
        last_resort.push((kyber.public_key.clone(), signature));
    }
    let (current, current_signature) = &last_resort[1];

    let (refreshed, (status, check, upload)) = pool.run_until(future::join(
        manager.update_pre_key_bundle(&mut store, ServiceIdKind::Aci, true),
        async {
            let status = sent_request(server.next_sent().await);
            server.respond(status.id(), 200, br#"{"count":0,"pqCount":0}"#);
            let check = sent_request(server.next_sent().await);
            server.respond(check.id(), 409, b"");
            let upload = sent_request(server.next_sent().await);
            server.respond(upload.id(), 204, b"");
            (status, check, upload)
        },
    ));
    refreshed.unwrap();
    let keys = format!("/v2/keys?identity={}", ServiceIdKind::Aci);
    assert_eq!((status.verb(), status.path()), ("GET", &*keys));
    assert_eq!((check.verb(), check.path()), ("POST", "/v2/keys/check"));
    assert_eq!((upload.verb(), upload.path()), ("PUT", &*keys));

    let mut digest = Sha256::new();
    digest.update(identity.public_key().serialize());
    digest.update(u64::from(SIGNED).to_be_bytes());
    digest.update(signed.public_key.serialize());
    digest.update(u64::from(CURRENT).to_be_bytes());
    digest.update(current.serialize());
    let check: serde_json::Value =
        serde_json::from_slice(check.body()).unwrap();
    assert_eq!(
        check["digest"],
        BASE64_STANDARD.encode(digest.finalize().as_slice())
    );
    let upload: serde_json::Value =
        serde_json::from_slice(upload.body()).unwrap();
    assert_eq!(
        upload["pqLastResortPreKey"],
        serde_json::json!({
            "keyId": CURRENT,
            "publicKey": BASE64_STANDARD.encode(current.serialize()),
            "signature": BASE64_STANDARD.encode(current_signature),
        })
    );
}

/// What the store answered at once.
fn now<T>(answer: impl Future<Output = StoreResult<T>>) -> T {
    answer
        .now_or_never()
        .expect("the store doesn't wait")
        .expect("the store's answer")
}

// The store of `a_refresh_uploads_the_current_last_resort_key`: its keys are
// the test's, and a refresh numbers its batch after them.

#[async_trait(?Send)]
impl PreKeysStore for LocalStore {
    async fn next_pre_key_id(&self) -> StoreResult<u32> {
        Ok(CURRENT)
    }

    async fn next_signed_pre_key_id(&self) -> StoreResult<u32> {
        Ok(SIGNED + 1)
    }

    async fn next_pq_pre_key_id(&self) -> StoreResult<u32> {
        Ok(CURRENT)
    }

    async fn signed_pre_keys_count(&self) -> StoreResult<usize> {
        Ok(1)
    }

    async fn kyber_pre_keys_count(
        &self,
        last_resort: bool,
    ) -> StoreResult<usize> {
        Ok(if last_resort { 2 } else { 0 })
    }

    async fn signed_prekey_id(&self) -> StoreResult<Option<SignedPreKeyId>> {
        Ok(Some(SIGNED.into()))
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> StoreResult<Option<KyberPreKeyId>> {
        Ok(Some(CURRENT.into()))
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

    /// The older key first.
    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> StoreResult<Vec<KyberPreKeyRecord>> {
        Ok(vec![
            self.get_kyber_pre_key(OLDER.into()).await?,
            self.get_kyber_pre_key(CURRENT.into()).await?,
        ])
    }

    async fn remove_kyber_pre_key(
        &mut self,
        _: KyberPreKeyId,
    ) -> StoreResult<()> {
        unreachable!("a refresh removes no key")
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _: SystemTime,
    ) -> StoreResult<()> {
        unreachable!("a refresh marks no key")
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _: SystemTime,
        _: usize,
    ) -> StoreResult<()> {
        unreachable!("a refresh deletes no key")
    }
}
