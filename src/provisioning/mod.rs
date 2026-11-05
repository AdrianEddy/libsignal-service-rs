mod cipher;
mod pipe;

use std::array::TryFromSliceError;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::pin::pin;
use std::rc::Rc;

use libsignal_account_keys::{AccountEntropyPool, InvalidAccountEntropyPool};

pub use cipher::ProvisioningCipher;

use base64::Engine;
use futures::future::{self, Either};
use futures::StreamExt;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt};
use libsignal_core::curve::CurveError;
use libsignal_core::E164;
use libsignal_protocol::{
    DeviceId, IdentityKey, IdentityKeyPair, PrivateKey, PublicKey,
};
use prost::Message;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

pub use pipe::{ProvisioningPipe, ProvisioningStep};

use crate::messagepipe::ServiceCredentials;
use crate::prelude::ServiceError;
use crate::push_service::linking::{
    LinkAccountAttributes, LinkRequest, LinkResponse,
};
use crate::utils::BASE64_RELAXED;
use crate::websocket::registration::{DeviceActivationRequest, PniPreKeys};
use crate::{
    account_manager::encrypt_device_name,
    pre_keys::PreKeysStore,
    push_service::{HttpAuth, PushService, ServiceIds},
    transport::Clock,
    websocket::{self, SignalWebSocket, SocketEnd},
};

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

pub struct ProvisioningSecrets {
    pub credentials: ServiceCredentials,
    pub ephemeral_backup_key: Option<[u8; 32]>,
    pub account_entropy_pool: AccountEntropyPool,
    pub media_root_backup_key: Option<[u8; 32]>,
    /// The account's auth credential salt, which an account without a phone
    /// number has and a device linked to it needs for group credentials.
    pub auth_credential_salt: Option<[u8; 16]>,
}

#[derive(thiserror::Error, Debug)]
pub enum ProvisioningError {
    #[error("no provisioning URL received")]
    MissingUrl,
    #[error("bad version number (unsupported)")]
    BadVersionNumber,
    #[error("missing public key")]
    MissingPublicKey,
    #[error("missing private key")]
    MissingPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey(InvalidKeyError),
    #[error("invalid privat key")]
    InvalidPrivateKey(InvalidKeyError),
    #[error("missing UUID")]
    MissingUuid,
    #[error("missing ACI")]
    MissingAci,
    #[error("invalid ACI: {0}")]
    InvalidAci(uuid::Error),
    #[error("invalid PNI: {0}")]
    InvalidPni(uuid::Error),
    /// A provisioning message with a PNI private key but no PNI, which
    /// Signal-Desktop refuses too (`ProvisioningCipher.node.ts`).
    #[error("PNI identity key without a PNI")]
    PniKeyWithoutPni,
    /// A provisioning message without a PNI, so for an account without a
    /// phone number, that lacks the salt such an account's group credentials
    /// need.
    #[error("missing auth credential salt")]
    MissingAuthCredentialSalt,
    #[error("no provisioning message received")]
    MissingMessage,
    #[error("missing profile key")]
    MissingProfileKey,
    #[error("missing phone number")]
    MissingPhoneNumber,
    #[error("invalid phone number: {0}")]
    InvalidPhoneNumber(<E164 as std::str::FromStr>::Err),
    #[error("missing provisioning code")]
    MissingProvisioningCode,
    #[error("mismatched MAC")]
    MismatchedMac,
    #[error("AES CBC padding error: {0}")]
    AesPaddingError(aes::cipher::block_padding::Error),

    #[error("invalid provisioning step received")]
    InvalidStep,

    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Websocket error: {reason}")]
    WsError { reason: String },
    #[error("Websocket closing")]
    WsClosing,
    /// The provisioning socket ended before the steps that need it were done:
    /// the server closed it, with 1000 "Timeout" when no device sent a
    /// provisioning message in time, or a keepalive went unanswered. A socket
    /// that failed is a [`ServiceError`](Self::ServiceError).
    #[error("provisioning socket ended: {0}")]
    SocketEnded(SocketEnd),
    #[error("Service error: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::SignalProtocolError),
    #[error("invalid device ID: {0}")]
    InvalidDeviceId(#[from] libsignal_core::InvalidDeviceId),
    #[error("ProvisioningCipher in encrypt-only mode")]
    EncryptOnlyProvisioningCipher,
    #[error("invalid profile key bytes")]
    InvalidProfileKey(TryFromSliceError),
    #[error("invalid account entropy pool: {0}")]
    InvalidAccountEntropyPool(#[from] InvalidAccountEntropyPool),
    #[error("invalid ephemeral backup key length: expected 32 bytes, got {0}")]
    InvalidEphemeralBackupKey(usize),
    #[error("invalid auth credential salt length: expected 16 bytes, got {0}")]
    InvalidAuthCredentialSalt(usize),
    /// The server's answer to a link request names another account than the
    /// provisioning message ([`ProvisionedAccount::check_link_response`]).
    #[error("the link response is for another account than the message")]
    MismatchedLinkResponse,
}

impl ProvisioningError {
    pub fn invalid_public_key(e: impl Into<InvalidKeyError>) -> Self {
        ProvisioningError::InvalidPublicKey(e.into())
    }

    pub fn invalid_private_key(e: impl Into<InvalidKeyError>) -> Self {
        ProvisioningError::InvalidPrivateKey(e.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidKeyError {
    #[error("curve error: {0}")]
    Curve(#[from] CurveError),
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protocol error: {0}")]
    Protocol(#[from] libsignal_protocol::SignalProtocolError),
}

pub fn generate_registration_id<R: rand::Rng + rand::CryptoRng>(
    csprng: &mut R,
) -> u32 {
    csprng.random_range(1..16380)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeResponse {
    pub uuid: Uuid,
    pub storage_capable: bool,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration(NewDeviceRegistration),
}

/// A linked device's registration. The phone number, PNI and its keys are
/// `None` for an account without a phone number, which has
/// `auth_credential_salt` instead.
#[derive(derive_more::Debug)]
pub struct NewDeviceRegistration {
    pub phone_number: Option<E164>,
    pub device_id: DeviceId,
    pub registration_id: u32,
    pub pni_registration_id: Option<u32>,
    pub service_ids: ServiceIds,
    #[debug(ignore)]
    pub aci_private_key: PrivateKey,
    pub aci_public_key: IdentityKey,
    #[debug(ignore)]
    pub pni_private_key: Option<PrivateKey>,
    pub pni_public_key: Option<IdentityKey>,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    /// Account Entropy Pool — the modern `accountEntropyPool` field 15.
    /// 64-character alphanumeric string from which the canonical master
    /// key is derived (`AccountEntropyPool::derive_svr_key`). When present,
    /// it should be preferred over the deprecated `master_key` field.
    #[debug(ignore)]
    pub account_entropy_pool: Option<AccountEntropyPool>,
    /// One-time key for an initial linked-device message-history transfer.
    #[debug(ignore)]
    pub ephemeral_backup_key: Option<[u8; 32]>,
    /// The salt group credentials need on an account without a phone number
    /// (`AuthCredentialWithPniResponse::receive_without_pni`).
    #[debug(ignore)]
    pub auth_credential_salt: Option<[u8; 16]>,
}

/// Links this device to an account: opens the provisioning socket, sends its
/// link to `tx`, waits for the primary device's provisioning message and
/// registers the device. The socket's task runs beside these steps, timed by
/// `clock`, and ends with them. If the socket ends before the steps that need
/// it, the error is why it ended: [`ProvisioningError::SocketEnded`], or the
/// socket's failure as a [`ProvisioningError::ServiceError`].
///
/// The link carries `link_capabilities` (see [`ProvisioningPipe::from_socket`]).
/// `capabilities` is the device's capability record for the server
/// ([`LinkAccountAttributes::capabilities`]); the link sets its
/// `optionalPhoneNumber` to whether the account has no phone number, which
/// the server requires of a device on such an account. An account without a
/// phone number, one whose provisioning message has no PNI, links without
/// PNI keys, and its registration carries the auth credential salt instead
/// (Signal-Desktop `Provisioner.preload.ts`).
#[allow(clippy::too_many_arguments)]
pub async fn link_device<
    R: rand::Rng + rand::CryptoRng,
    Aci: PreKeysStore,
    Pni: PreKeysStore,
>(
    aci_store: &mut Aci,
    pni_store: &mut Pni,
    csprng: &mut R,
    clock: Rc<dyn Clock>,
    push_service: PushService,
    password: &str,
    device_name: &str,
    link_capabilities: &[&str],
    capabilities: BTreeMap<String, bool>,
    tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), ProvisioningError> {
    // open a websocket without authentication, to receive a tsurl://
    let (ws, socket) = push_service
        .ws(
            "/v1/websocket/provisioning/",
            "/v1/keepalive/provisioning",
            &[],
            None,
            clock.clone(),
        )
        .await?;

    // If the socket ends first, its request stream ends, and so do the steps
    // waiting on it, which then report why the socket ended; a step that
    // doesn't wait on it, such as the final HTTP request, still runs to its
    // end.
    let steps = pin!(link_steps(
        ws,
        aci_store,
        pni_store,
        csprng,
        &*clock,
        push_service,
        password,
        device_name,
        link_capabilities,
        capabilities,
        tx,
    ));
    match future::select(pin!(socket), steps).await {
        Either::Left((end, steps)) => match steps.await {
            // What a step sees once the socket under it has ended: no more
            // requests, or no way to answer one.
            Err(
                ProvisioningError::MissingUrl
                | ProvisioningError::MissingMessage
                | ProvisioningError::WsClosing,
            ) => Err(match end {
                Ok(end) => ProvisioningError::SocketEnded(end),
                Err(e) => ProvisioningError::ServiceError(e),
            }),
            result => result,
        },
        Either::Right((result, _socket)) => result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn link_steps<
    R: rand::Rng + rand::CryptoRng,
    Aci: PreKeysStore,
    Pni: PreKeysStore,
>(
    ws: SignalWebSocket<websocket::Unidentified>,
    aci_store: &mut Aci,
    pni_store: &mut Pni,
    csprng: &mut R,
    clock: &dyn Clock,
    mut push_service: PushService,
    password: &str,
    device_name: &str,
    link_capabilities: &[&str],
    mut capabilities: BTreeMap<String, bool>,
    mut tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), ProvisioningError> {
    let registration_id = generate_registration_id(csprng);

    let provisioning_pipe =
        ProvisioningPipe::from_socket(ws, csprng, link_capabilities);
    let provision_stream = provisioning_pipe.stream();
    pin_mut!(provision_stream);

    if let ProvisioningStep::Url(url) = provision_stream
        .next()
        .await
        .ok_or(ProvisioningError::MissingUrl)??
    {
        tx.send(SecondaryDeviceProvisioning::Url(url))
            .await
            .expect("failed to send provisioning Url in channel");
    } else {
        return Err(ProvisioningError::InvalidStep);
    }

    if let ProvisioningStep::Message(message) =
        provision_stream
            .next()
            .await
            .ok_or(ProvisioningError::MissingMessage)??
    {
        let account = ProvisionedAccount::try_from(message)?;

        let (
            _aci_pre_keys,
            aci_signed_pre_key,
            _aci_pq_pre_keys,
            aci_pq_last_resort_pre_key,
        ) = crate::pre_keys::replenish_pre_keys(
            aci_store,
            csprng,
            clock,
            &account.aci_key_pair,
            true,
            0,
            0,
        )
        .await?;

        let aci_pq_last_resort_pre_key =
            aci_pq_last_resort_pre_key.expect("requested last resort key");
        assert!(_aci_pre_keys.is_empty());
        assert!(_aci_pq_pre_keys.is_empty());

        // The PNI's registration id and prekeys, for an account with a phone
        // number only. The id goes in the attributes and the keys beside
        // them, so no wire type can hold them together.
        let pni_keys = match &account.phone_number_identity {
            Some(identity) => {
                let (
                    _pni_pre_keys,
                    signed_pre_key,
                    _pni_pq_pre_keys,
                    pq_last_resort_pre_key,
                ) = crate::pre_keys::replenish_pre_keys(
                    pni_store,
                    csprng,
                    clock,
                    &identity.key_pair,
                    true,
                    0,
                    0,
                )
                .await?;

                let pq_last_resort_pre_key =
                    pq_last_resort_pre_key.expect("requested last resort key");
                assert!(_pni_pre_keys.is_empty());
                assert!(_pni_pq_pre_keys.is_empty());
                Some((
                    generate_registration_id(csprng),
                    PniPreKeys {
                        pni_signed_pre_key: signed_pre_key.try_into()?,
                        pni_pq_last_resort_pre_key: pq_last_resort_pre_key
                            .try_into()?,
                    },
                ))
            },
            None => None,
        };
        let (pni_registration_id, pni) = pni_keys.unzip();

        let encrypted_device_name = BASE64_RELAXED.encode(
            encrypt_device_name(
                csprng,
                device_name,
                account.aci_key_pair.identity_key(),
            )?
            .encode_to_vec(),
        );

        // Signal-Desktop `getCapabilities.std.ts`: `optionalPhoneNumber` says
        // whether the account has no phone number.
        capabilities.insert(
            "optionalPhoneNumber".to_owned(),
            account.phone_number_identity.is_none(),
        );
        let request = LinkRequest {
            verification_code: account.provisioning_code.clone(),
            account_attributes: LinkAccountAttributes {
                registration_id,
                pni_registration_id,
                fetches_messages: true,
                capabilities,
                name: encrypted_device_name,
            },
            device_activation_request: DeviceActivationRequest {
                aci_signed_pre_key: aci_signed_pre_key.try_into()?,
                aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key
                    .try_into()?,
                pni,
            },
        };

        // The server reads only the password; the user name is the bare ACI
        // for every account, as Signal-Desktop sends it (`WebAPI.preload.ts`
        // `linkDevice`).
        let response = push_service
            .link_device(
                &request,
                HttpAuth {
                    username: account.aci.to_string(),
                    password: password.to_owned(),
                },
            )
            .await?;
        account.check_link_response(&response)?;

        let service_ids = account.service_ids();
        let (phone_number, pni_key_pair) = account
            .phone_number_identity
            .map(|identity| (identity.phone_number, identity.key_pair))
            .unzip();
        tx.send(SecondaryDeviceProvisioning::NewDeviceRegistration(
            NewDeviceRegistration {
                phone_number,
                service_ids,
                device_id: response.device_id,
                registration_id,
                pni_registration_id,
                aci_private_key: *account.aci_key_pair.private_key(),
                aci_public_key: *account.aci_key_pair.identity_key(),
                pni_private_key: pni_key_pair
                    .as_ref()
                    .map(|pair| *pair.private_key()),
                pni_public_key: pni_key_pair
                    .as_ref()
                    .map(|pair| *pair.identity_key()),
                profile_key: account.profile_key,
                account_entropy_pool: account.account_entropy_pool,
                ephemeral_backup_key: account.ephemeral_backup_key,
                auth_credential_salt: account.auth_credential_salt,
            },
        ))
        .await
        .expect("failed to send provisioning message in rx channel");
    } else {
        return Err(ProvisioningError::InvalidStep);
    }

    Ok(())
}

/// What an account with a phone number has and one without lacks: the PNI, the
/// number and the PNI's identity.
#[derive(derive_more::Debug)]
pub struct PhoneNumberIdentity {
    pub pni: Uuid,
    #[debug(ignore)]
    pub phone_number: E164,
    #[debug(ignore)]
    pub key_pair: IdentityKeyPair,
}

/// The account a primary device's [`ProvisionMessage`] describes, read and
/// checked. [`ProvisioningStep::Message`] hands the message over raw: a client
/// that drives the link's steps itself reads it with this `TryFrom`, before it
/// makes any prekey, and passes the server's answer to
/// [`check_link_response`](Self::check_link_response), as [`link_device`] does.
///
/// An account without a phone number is one whose message has no PNI: it has
/// no phone number or PNI identity, a PNI private key in such a message is
/// refused, and the salt is required (Signal-Desktop
/// `ProvisioningCipher.node.ts`, `Provisioner.preload.ts`).
#[derive(derive_more::Debug)]
pub struct ProvisionedAccount {
    pub aci: Uuid,
    #[debug(ignore)]
    pub aci_key_pair: IdentityKeyPair,
    /// `None` for an account without a phone number.
    pub phone_number_identity: Option<PhoneNumberIdentity>,
    /// Required on an account without a phone number.
    #[debug(ignore)]
    pub auth_credential_salt: Option<[u8; 16]>,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    #[debug(ignore)]
    pub account_entropy_pool: Option<AccountEntropyPool>,
    #[debug(ignore)]
    pub ephemeral_backup_key: Option<[u8; 32]>,
    #[debug(ignore)]
    pub provisioning_code: String,
}

impl ProvisionedAccount {
    /// The account's ids, as its message gives them.
    pub fn service_ids(&self) -> ServiceIds {
        ServiceIds {
            aci: self.aci,
            pni: self
                .phone_number_identity
                .as_ref()
                .map(|identity| identity.pni),
        }
    }

    /// Checks the server's answer to this account's link request: it must name
    /// the account in the message, the PNI's absence included, since the keys
    /// and the phone number come from the message (Signal-Desktop
    /// `AccountManager.preload.ts`). After an error the new device stays on
    /// the account, unused, and nothing of this link should be kept.
    pub fn check_link_response(
        &self,
        response: &LinkResponse,
    ) -> Result<(), ProvisioningError> {
        let ServiceIds { aci, pni } = self.service_ids();
        if response.aci == aci && response.pni == pni {
            Ok(())
        } else {
            Err(ProvisioningError::MismatchedLinkResponse)
        }
    }
}

impl TryFrom<ProvisionMessage> for ProvisionedAccount {
    type Error = ProvisioningError;

    fn try_from(message: ProvisionMessage) -> Result<Self, Self::Error> {
        let aci = provisioned_id(&message.aci_binary, &message.aci)
            .map_err(ProvisioningError::InvalidAci)?
            .ok_or(ProvisioningError::MissingAci)?;
        let pni = provisioned_id(&message.pni_binary, &message.pni)
            .map_err(ProvisioningError::InvalidPni)?;

        let aci_key_pair = provisioned_key_pair(
            message.aci_identity_key_public,
            message.aci_identity_key_private,
        )?;

        // Empty means absent, as Signal-Desktop reads it. The server's salt is
        // always 16 bytes (`AccountsManager.AUTH_CREDENTIAL_SALT_SIZE`).
        let auth_credential_salt: Option<[u8; 16]> = message
            .auth_credential_salt
            .filter(|salt| !salt.is_empty())
            .map(|salt| {
                salt.try_into().map_err(|salt: Vec<u8>| {
                    ProvisioningError::InvalidAuthCredentialSalt(salt.len())
                })
            })
            .transpose()?;

        let phone_number_identity = if let Some(pni) = pni {
            let key_pair = provisioned_key_pair(
                message.pni_identity_key_public,
                message.pni_identity_key_private,
            )?;
            let phone_number = message
                .number
                .ok_or(ProvisioningError::MissingPhoneNumber)?
                .parse()
                .map_err(ProvisioningError::InvalidPhoneNumber)?;
            Some(PhoneNumberIdentity {
                pni,
                phone_number,
                key_pair,
            })
        } else if message
            .pni_identity_key_private
            .is_some_and(|key| !key.is_empty())
        {
            // The private key alone decides, as in Signal-Desktop.
            return Err(ProvisioningError::PniKeyWithoutPni);
        } else if auth_credential_salt.is_none() {
            return Err(ProvisioningError::MissingAuthCredentialSalt);
        } else {
            None
        };

        let profile_key = ProfileKey::create(
            message
                .profile_key
                .ok_or(ProvisioningError::MissingProfileKey)?
                .as_slice()
                .try_into()
                .map_err(ProvisioningError::InvalidProfileKey)?,
        );

        // Optional in the proto (field 13 deprecated, field 15 modern).
        // presage prefers AEP if both are present.
        let account_entropy_pool = message
            .account_entropy_pool
            .map(|s| s.parse())
            .transpose()?;
        let ephemeral_backup_key = message
            .ephemeral_backup_key
            .map(|key| {
                key.try_into().map_err(|key: Vec<u8>| {
                    ProvisioningError::InvalidEphemeralBackupKey(key.len())
                })
            })
            .transpose()?;

        let provisioning_code = message
            .provisioning_code
            .ok_or(ProvisioningError::MissingProvisioningCode)?;

        Ok(Self {
            aci,
            aci_key_pair,
            phone_number_identity,
            auth_credential_salt,
            profile_key,
            account_entropy_pool,
            ephemeral_backup_key,
            provisioning_code,
        })
    }
}

/// An id in a provisioning message: its binary form if set, else its string,
/// as Signal-Desktop reads them (`ProvisioningCipher.node.ts`). Empty means
/// absent.
fn provisioned_id(
    binary: &Option<Vec<u8>>,
    string: &Option<String>,
) -> Result<Option<Uuid>, uuid::Error> {
    match (binary, string) {
        (Some(binary), _) if !binary.is_empty() => {
            Uuid::from_slice(binary).map(Some)
        },
        (_, Some(string)) if !string.is_empty() => {
            Uuid::parse_str(string).map(Some)
        },
        _ => Ok(None),
    }
}

fn provisioned_key_pair(
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
) -> Result<IdentityKeyPair, ProvisioningError> {
    let public_key = PublicKey::deserialize(
        &public_key.ok_or(ProvisioningError::MissingPublicKey)?,
    )
    .map_err(ProvisioningError::invalid_public_key)?;
    let private_key = PrivateKey::deserialize(
        &private_key.ok_or(ProvisioningError::MissingPrivateKey)?,
    )
    .map_err(ProvisioningError::invalid_private_key)?;
    Ok(IdentityKeyPair::new(
        IdentityKey::new(public_key),
        private_key,
    ))
}
