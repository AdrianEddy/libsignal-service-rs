//! A protocol store whose clones share one state, over libsignal's in-memory
//! store: [`ServiceCipher`](libsignal_service::cipher::ServiceCipher) and
//! [`MessageSender`](libsignal_service::sender::MessageSender) clone their
//! store for every call, so a session they store must outlive the clone.

use std::{ops::Deref, rc::Rc, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;
use libsignal_service::{
    protocol::{
        kem, DeviceId, Direction, GenericSignedPreKey as _, IdentityChange,
        IdentityKey, IdentityKeyPair, IdentityKeyStore,
        InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
        KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeyStore,
        ProtocolAddress, ProtocolStore, PublicKey, SenderKeyRecord,
        SenderKeyStore, ServiceId, SessionRecord, SessionStore,
        SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
        SignedPreKeyStore, Timestamp,
    },
    session_store::SessionStoreExt,
};
use uuid::Uuid;

type StoreResult<T> = Result<T, SignalProtocolError>;

/// A store whose clones share one state behind `P`.
#[derive(Clone)]
pub struct SharedStore<P>(P);

/// Not `Sync`, as MultiChat's `SignalStore<'_>` isn't.
pub type LocalStore = SharedStore<Rc<Mutex<InMemSignalProtocolStore>>>;

/// `Sync`, as a `MessageSender` needs.
pub type SyncStore = SharedStore<Arc<Mutex<InMemSignalProtocolStore>>>;

impl<P: From<Mutex<InMemSignalProtocolStore>>> SharedStore<P> {
    pub fn new(identity: IdentityKeyPair, registration_id: u32) -> Self {
        Self(P::from(Mutex::new(
            InMemSignalProtocolStore::new(identity, registration_id).unwrap(),
        )))
    }
}

impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> SharedStore<P> {
    /// Generates a signed and a Kyber prekey, both with id 1, keeps them,
    /// and returns the bundle of device `device` that offers them.
    pub async fn bundle(&self, device: DeviceId) -> PreKeyBundle {
        let rng = &mut rand::rng();
        let mut store = self.0.lock().await;
        let identity = store.get_identity_key_pair().await.unwrap();
        let registration_id = store.get_local_registration_id().await.unwrap();
        let signed = KeyPair::generate(rng);
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), rng)
            .unwrap();
        let kyber_signature = identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), rng)
            .unwrap();
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
        PreKeyBundle::new(
            registration_id,
            device,
            None,
            1.into(),
            signed.public_key,
            signed_signature.to_vec(),
            1.into(),
            kyber.public_key,
            kyber_signature.to_vec(),
            *identity.identity_key(),
        )
        .unwrap()
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> SessionStore
    for SharedStore<P>
{
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> StoreResult<Option<SessionRecord>> {
        self.0.lock().await.load_session(address).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> StoreResult<()> {
        self.0.lock().await.store_session(address, record).await
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> IdentityKeyStore
    for SharedStore<P>
{
    async fn get_identity_key_pair(&self) -> StoreResult<IdentityKeyPair> {
        self.0.lock().await.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> StoreResult<u32> {
        self.0.lock().await.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> StoreResult<IdentityChange> {
        self.0.lock().await.save_identity(address, identity).await
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> StoreResult<bool> {
        self.0
            .lock()
            .await
            .is_trusted_identity(address, identity, direction)
            .await
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> StoreResult<Option<IdentityKey>> {
        self.0.lock().await.get_identity(address).await
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> PreKeyStore
    for SharedStore<P>
{
    async fn get_pre_key(&self, id: PreKeyId) -> StoreResult<PreKeyRecord> {
        self.0.lock().await.get_pre_key(id).await
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> StoreResult<()> {
        self.0.lock().await.save_pre_key(id, record).await
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> StoreResult<()> {
        self.0.lock().await.remove_pre_key(id).await
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> SignedPreKeyStore
    for SharedStore<P>
{
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> StoreResult<SignedPreKeyRecord> {
        self.0.lock().await.get_signed_pre_key(id).await
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> StoreResult<()> {
        self.0.lock().await.save_signed_pre_key(id, record).await
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> KyberPreKeyStore
    for SharedStore<P>
{
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> StoreResult<KyberPreKeyRecord> {
        self.0.lock().await.get_kyber_pre_key(id).await
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> StoreResult<()> {
        self.0.lock().await.save_kyber_pre_key(id, record).await
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        signed_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> StoreResult<()> {
        self.0
            .lock()
            .await
            .mark_kyber_pre_key_used(id, signed_id, base_key)
            .await
    }
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> SenderKeyStore
    for SharedStore<P>
{
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> StoreResult<()> {
        self.0
            .lock()
            .await
            .store_sender_key(sender, distribution_id, record)
            .await
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> StoreResult<Option<SenderKeyRecord>> {
        self.0
            .lock()
            .await
            .load_sender_key(sender, distribution_id)
            .await
    }
}

impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> ProtocolStore
    for SharedStore<P>
{
}

#[async_trait(?Send)]
impl<P: Deref<Target = Mutex<InMemSignalProtocolStore>>> SessionStoreExt
    for SharedStore<P>
{
    /// None: no account in these tests has a session with a device but 1.
    async fn get_sub_device_sessions(
        &self,
        _: &ServiceId,
    ) -> StoreResult<Vec<DeviceId>> {
        Ok(Vec::new())
    }

    async fn delete_session(&self, _: &ProtocolAddress) -> StoreResult<()> {
        unreachable!("these tests delete no session")
    }

    async fn delete_all_sessions(&self, _: &ServiceId) -> StoreResult<usize> {
        unreachable!("these tests delete no session")
    }
}
