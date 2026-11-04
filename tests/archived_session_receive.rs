//! `ServiceCipher::open_envelope` when a successful decrypt leaves the record
//! with no active session.
//!
//! libsignal never promotes an archived session, and its deadlock breaker
//! archives the active session during a receive. By then the ratchet has moved
//! and the record is stored, so a failure after the decrypt loses the message
//! for good. Padding must therefore never depend on the record.

use std::{rc::Rc, time::SystemTime};

use async_trait::async_trait;
use futures::lock::Mutex;
use libsignal_protocol::{
    initiate_session, kem, message_decrypt, message_encrypt, Aci,
    CiphertextMessage, CiphertextMessageType, DeviceId, Direction,
    GenericSignedPreKey as _, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeyStore, ProtocolAddress, ProtocolStore, PublicKey, SenderKeyRecord,
    SenderKeyStore, ServiceId, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp,
};
use libsignal_service::{
    cipher::ServiceCipher,
    content::{Content, ContentBody},
    envelope::Envelope,
    proto::{self, envelope::Type},
    push_service::ServiceError,
    session_store::SessionStoreExt,
};
use prost::Message as _;
use rand::rng;
use uuid::Uuid;

type StoreResult<T> = Result<T, SignalProtocolError>;

/// `ServiceCipher` clones its store for every call, so the clones must share
/// one state for a stored session to survive the call.
#[derive(Clone)]
struct SharedStore(Rc<Mutex<InMemSignalProtocolStore>>);

#[async_trait(?Send)]
impl SessionStore for SharedStore {
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
impl IdentityKeyStore for SharedStore {
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
impl PreKeyStore for SharedStore {
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
impl SignedPreKeyStore for SharedStore {
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
impl KyberPreKeyStore for SharedStore {
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
impl SenderKeyStore for SharedStore {
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

impl ProtocolStore for SharedStore {}

#[async_trait(?Send)]
impl SessionStoreExt for SharedStore {
    async fn get_sub_device_sessions(
        &self,
        _: &ServiceId,
    ) -> StoreResult<Vec<DeviceId>> {
        Ok(vec![])
    }

    async fn delete_session(&self, _: &ProtocolAddress) -> StoreResult<()> {
        Ok(())
    }

    async fn delete_all_sessions(&self, _: &ServiceId) -> StoreResult<usize> {
        Ok(0)
    }
}

struct Peer {
    aci: Aci,
    address: ProtocolAddress,
    store: SharedStore,
    bundle: PreKeyBundle,
}

impl Peer {
    async fn new() -> Self {
        let rng = &mut rng();
        let identity = IdentityKeyPair::generate(rng);
        let signed_key = KeyPair::generate(rng);
        let kyber_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_key.public_key.serialize(), rng)
            .unwrap();
        let kyber_signature = identity
            .private_key()
            .calculate_signature(&kyber_key.public_key.serialize(), rng)
            .unwrap();

        let mut store = InMemSignalProtocolStore::new(identity, 1).unwrap();
        store
            .save_signed_pre_key(
                1.into(),
                &SignedPreKeyRecord::new(
                    1.into(),
                    Timestamp::from_epoch_millis(0),
                    &signed_key,
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
                    &kyber_key,
                    &kyber_signature,
                ),
            )
            .await
            .unwrap();

        let device = DeviceId::new(1).unwrap();
        let bundle = PreKeyBundle::new(
            1,
            device,
            None,
            1.into(),
            signed_key.public_key,
            signed_signature.to_vec(),
            1.into(),
            kyber_key.public_key,
            kyber_signature.to_vec(),
            *identity.identity_key(),
        )
        .unwrap();
        let aci = Aci::from(Uuid::from_bytes(rand::random()));
        Self {
            aci,
            address: ProtocolAddress::new(
                ServiceId::from(aci).service_id_string(),
                device,
            ),
            store: SharedStore(Rc::new(Mutex::new(store))),
            bundle,
        }
    }

    async fn initiate(&self, peer: &Self) {
        initiate_session(
            &peer.address,
            &self.address,
            &mut self.store.clone(),
            &mut self.store.clone(),
            &peer.bundle,
            SystemTime::now(),
            &mut rng(),
        )
        .await
        .unwrap();
    }

    async fn encrypt(&self, peer: &Self, text: &str) -> CiphertextMessage {
        let content = proto::Content {
            content: Some(proto::content::Content::DataMessage(
                proto::DataMessage {
                    body: Some(text.to_owned()),
                    timestamp: Some(1),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        let mut padded = content.encode_to_vec();
        let length = padded.len();
        padded.push(0x80);
        padded.resize((length + 1).div_ceil(160) * 160, 0);

        message_encrypt(
            &padded,
            &peer.address,
            &self.address,
            &mut self.store.clone(),
            &mut self.store.clone(),
            SystemTime::now(),
            &mut rng(),
        )
        .await
        .unwrap()
    }

    /// An unsealed envelope from `self` to `to`.
    fn envelope(&self, to: &Self, message: &CiphertextMessage) -> Envelope {
        let envelope_type = match message.message_type() {
            CiphertextMessageType::PreKey => Type::PrekeyMessage,
            CiphertextMessageType::Whisper => Type::DoubleRatchet,
            other => panic!("unexpected message type {other:?}"),
        };
        Envelope {
            r#type: Some(envelope_type as i32),
            source_service_id: Some(
                ServiceId::from(self.aci).service_id_string(),
            ),
            source_device_id: Some(1),
            destination_service_id: Some(
                ServiceId::from(to.aci).service_id_string(),
            ),
            client_timestamp: Some(1_700_000_000_000),
            server_timestamp: Some(1_700_000_000_001),
            content: Some(message.serialize().to_vec()),
            ..Default::default()
        }
    }

    async fn open(
        &self,
        envelope: Envelope,
    ) -> Result<Option<Content>, ServiceError> {
        ServiceCipher::new(self.store.clone(), vec![], self.address.clone())
            .open_envelope(envelope, &mut rng())
            .await
    }

    /// A plain libsignal decrypt, standing in for the peer's own client.
    async fn decrypt(&self, from: &Self, message: &CiphertextMessage) {
        message_decrypt(
            message,
            &from.address,
            &self.address,
            &mut self.store.clone(),
            &mut self.store.clone(),
            &mut self.store.clone(),
            &self.store.clone(),
            &mut self.store.clone(),
            &mut rng(),
        )
        .await
        .unwrap();
    }

    async fn record(&self, peer: &Self) -> SessionRecord {
        self.store
            .load_session(&peer.address)
            .await
            .unwrap()
            .expect("a session record")
    }

    async fn has_active_session(&self, peer: &Self) -> bool {
        self.record(peer).await.session_version().is_ok()
    }

    async fn archive_active_session(&self, peer: &Self) {
        let mut record = self.record(peer).await;
        record.archive_current_state().unwrap();
        self.store
            .clone()
            .store_session(&peer.address, &record)
            .await
            .unwrap();
    }
}

fn text_of(opened: Result<Option<Content>, ServiceError>) -> String {
    match opened.expect("decrypted").expect("some content").body {
        ContentBody::DataMessage(message) => message.body.expect("a body"),
        other => panic!("unexpected content {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn whisper_opens_on_an_archived_session_with_no_active_session() {
    let (alice, bob) = (Peer::new().await, Peer::new().await);
    alice.initiate(&bob).await;

    let first = alice.encrypt(&bob, "first").await;
    assert_eq!(first.message_type(), CiphertextMessageType::PreKey);
    assert_eq!(
        text_of(bob.open(alice.envelope(&bob, &first)).await),
        "first"
    );

    // Bob replies, so Alice stops wrapping her messages as PreKey messages.
    let reply = bob.encrypt(&alice, "reply").await;
    alice.decrypt(&bob, &reply).await;

    bob.archive_active_session(&alice).await;

    let late = alice.encrypt(&bob, "late").await;
    assert_eq!(late.message_type(), CiphertextMessageType::Whisper);
    let envelope = alice.envelope(&bob, &late);
    assert_eq!(text_of(bob.open(envelope.clone()).await), "late");
    assert!(!bob.has_active_session(&alice).await);

    // The ratchet has moved, so a redelivery can't give the plaintext again:
    // this is why an error after the decrypt loses the message.
    assert!(matches!(
        bob.open(envelope).await,
        Err(ServiceError::SignalProtocolError(
            SignalProtocolError::DuplicatedMessage(..)
        ))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn prekey_opens_on_an_archived_session_with_no_active_session() {
    let (alice, bob) = (Peer::new().await, Peer::new().await);
    alice.initiate(&bob).await;

    let first = alice.encrypt(&bob, "first").await;
    assert_eq!(
        text_of(bob.open(alice.envelope(&bob, &first)).await),
        "first"
    );

    bob.archive_active_session(&alice).await;

    // Alice has heard nothing back, so this is still a PreKey message.
    let late = alice.encrypt(&bob, "late").await;
    assert_eq!(late.message_type(), CiphertextMessageType::PreKey);
    assert_eq!(text_of(bob.open(alice.envelope(&bob, &late)).await), "late");
    assert!(!bob.has_active_session(&alice).await);
}

/// Pure protocol traffic, with no local archive call. Both sides initiate, the
/// tiebreak loser keeps sending, and the winner's replies never arrive, so
/// libsignal's deadlock breaker empties the active slot during a receive.
#[tokio::test(flavor = "current_thread")]
async fn deadlock_breaker_loses_no_unsealed_message() {
    let (mut loser, mut winner) = (Peer::new().await, Peer::new().await);
    loser.initiate(&winner).await;
    winner.initiate(&loser).await;

    // The higher session id takes the active slot.
    let loser_session = loser.record(&winner).await;
    let winner_session = winner.record(&loser).await;
    if loser_session.alice_base_key().unwrap()
        > winner_session.alice_base_key().unwrap()
    {
        std::mem::swap(&mut loser, &mut winner);
    }

    for round in 0..6 {
        let text = format!("round {round}");
        let message = loser.encrypt(&winner, &text).await;
        let opened = winner.open(loser.envelope(&winner, &message)).await;
        assert_eq!(text_of(opened), text);

        if winner.has_active_session(&loser).await {
            let _undelivered = winner.encrypt(&loser, "undelivered").await;
        }
    }

    assert!(
        !winner.has_active_session(&loser).await,
        "the deadlock breaker didn't fire, so this test proves nothing"
    );
}
