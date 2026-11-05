use std::time::Duration;

use aes::cipher::block_padding;
use http::StatusCode;
use libsignal_core::{curve::CurveError, ServiceId};
use libsignal_protocol::{
    FingerprintError, ServiceIdKind, SignalProtocolError,
};
use serde::Deserialize;
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::{
    cipher::SealedSenderDecryptionError,
    groups_v2::GroupDecodingError,
    transport::TransportError,
    utils::deserialize_service_id,
    websocket::registration::{
        RegistrationLockFailure, RegistrationSessionMetadataResponse,
    },
};

use super::{MismatchedDevices, ProofRequired, StaleDevices};

#[derive(Debug, Deserialize)]
pub struct AccountMismatchedDevices {
    #[serde(deserialize_with = "deserialize_service_id")]
    pub uuid: ServiceId,
    pub devices: MismatchedDevices,
}

#[derive(Debug, Deserialize)]
pub struct AccountStaleDevices {
    #[serde(deserialize_with = "deserialize_service_id")]
    pub uuid: ServiceId,
    pub devices: StaleDevices,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationDeliveryFailure {
    #[serde(default)]
    pub reason: String,
    pub permanent_failure: bool,
}

/// The most of an error response's body lss keeps for diagnostics when the
/// status alone is the error. A body that breaks off earlier ends there; the
/// status stays the error.
pub const ERROR_BODY_LIMIT: usize = 4096;

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("Service request timed out: {reason}")]
    Timeout { reason: &'static str },

    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("wrong address type: {0}")]
    InvalidAddressType(ServiceIdKind),

    #[error("invalid phone number")]
    InvalidPhoneNumber,

    #[error("Error sending request: {reason}")]
    SendError { reason: String },

    #[error("i/o error")]
    IO(#[from] std::io::Error),

    #[error("Error decoding JSON: {0}")]
    JsonDecodeError(#[from] serde_json::Error),
    #[error("Error decoding protobuf frame: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("error encoding or decoding bincode: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("error decoding base64 string: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Rate limit exceeded: retry after {}", retry_after.map(|a| format!("{a:?}")).unwrap_or_else(|| "unspecified".into()))]
    RateLimitExceeded {
        /// The server's `Retry-After`, saturated at `u64::MAX` seconds: a
        /// caller caps it where it holds requests back.
        retry_after: Option<Duration>,
    },
    #[error("Authorization failed")]
    Unauthorized,
    /// Credentials that can't authenticate: no password, or neither an ACI
    /// nor a phone number to log in with.
    #[error("credentials without a login or a password")]
    MissingCredentials,
    #[error("Registration lock is set: {0:?}")]
    Locked(RegistrationLockFailure),

    /// A status lss doesn't handle, or an error body it couldn't decode.
    /// Where the status alone is the error, `body` holds at most
    /// [`ERROR_BODY_LIMIT`] bytes of the response's body.
    #[error("Unexpected response: HTTP {status}: {body}")]
    UnhandledResponseCode { status: StatusCode, body: String },

    #[error("Websocket closing: {reason}")]
    WsClosing { reason: &'static str },

    #[error("Invalid padding: {0}")]
    Padding(#[from] block_padding::Error),

    #[error("unknown padding version {0}")]
    PaddingVersion(u32),

    #[error("Invalid frame: {reason}")]
    InvalidFrame { reason: &'static str },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] SignalProtocolError),

    #[error("Sealed sender decryption error: {0}")]
    SealedSenderDecryptionError(#[from] SealedSenderDecryptionError),

    #[error("invalid device id: {0}")]
    InvalidDeviceId(#[from] libsignal_core::InvalidDeviceId),

    #[error("Proof required: {0:?}")]
    ProofRequiredError(ProofRequired),

    #[error("{0:?}")]
    MismatchedDevicesException(MismatchedDevices),

    #[error("{0:?}")]
    StaleDevices(StaleDevices),

    #[error(transparent)]
    CredentialsCacheError(#[from] crate::groups_v2::CredentialsCacheError),

    #[error("groups v2 (zero-knowledge) error")]
    GroupsV2Error,

    /// Group credentials for an account without a phone number are received
    /// with its auth credential salt, which `GroupsManager` doesn't take.
    #[error("no group credentials for an account without a PNI")]
    GroupCredentialsWithoutPni,

    #[error(transparent)]
    GroupsV2DecryptionError(#[from] GroupDecodingError),

    #[error(transparent)]
    ZkGroupDeserializationFailure(#[from] ZkGroupDeserializationFailure),

    #[error(transparent)]
    ZkGroupVerificationFailure(#[from] ZkGroupVerificationFailure),

    #[error("unsupported content")]
    UnsupportedContent,

    #[error("Not found.")]
    NotFoundError,

    #[error("failed to decrypt field from device info: {0}")]
    DecryptDeviceInfoFieldError(&'static str),

    #[error("Unknown CDN version {0}")]
    UnknownCdnVersion(u32),

    #[error("Device limit reached: {current} out of {max} devices.")]
    DeviceLimitReached { current: u32, max: u32 },

    #[error("client version too old; upgrade required")]
    DeprecatedVersion,
    #[error("request rejected by the server")]
    ServerRejected,
    #[error("recipient is not registered")]
    UnregisteredRecipient,
    #[error("message too large")]
    MessageTooLarge,
    #[error("multi-recipient mismatched devices: {0:?}")]
    MultiRecipientMismatchedDevices(Vec<AccountMismatchedDevices>),
    #[error("multi-recipient stale devices: {0:?}")]
    MultiRecipientStaleDevices(Vec<AccountStaleDevices>),
    #[error("invalid device verification code")]
    InvalidDeviceVerificationCode,
    #[error("device capabilities are a downgrade")]
    DeviceCapabilityDowngrade,
    /// The server found the link request invalid (422): a prekey signature
    /// that doesn't verify, PNI keys on an account without a PNI or missing
    /// on one with it, no capabilities, or a body that fails validation. A
    /// bug in the request, never the user's doing. `body` holds at most
    /// [`ERROR_BODY_LIMIT`] bytes of what the server said, often nothing.
    #[error("the server found the link request invalid: {body}")]
    InvalidLinkRequest { body: String },
    #[error("no such verification session")]
    NoSuchSession,
    #[error("invalid or malformed verification session id")]
    InvalidVerificationSessionId,
    #[error("verification token rejected: {0:?}")]
    TokenNotAccepted(RegistrationSessionMetadataResponse),
    #[error("verification session conflict: {0:?}")]
    RegistrationSessionConflict(RegistrationSessionMetadataResponse),
    #[error("verification session rate limited: {session:?}")]
    VerificationSessionRateLimited {
        session: RegistrationSessionMetadataResponse,
        retry_after: Option<Duration>,
    },
    #[error("verification transport not allowed: {0:?}")]
    InvalidTransportMode(RegistrationSessionMetadataResponse),
    #[error("verification code delivery failed: {0:?}")]
    VerificationDeliveryFailed(VerificationDeliveryFailure),
    #[error("device transfer required")]
    DeviceTransferAvailable,
    #[error("no username hash is set for this account")]
    UsernameHashNotSet,
    #[error("attachment too large")]
    AttachmentTooLarge,
    #[error("challenge token not accepted")]
    ChallengeNotAccepted,

    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error("invalid HTTP header")]
    InvalidHeader(#[from] http::Error),

    #[error(transparent)]
    Curve(#[from] CurveError),

    // HpkeError does not implement StdError, so we need a manual display,
    // and manual From impl.
    #[error("Cryptographic error: {0}")]
    Hpke(signal_crypto::HpkeError),

    // FingerprintError does not implement StdError, so we need a manual display,
    // and manual From impl.
    #[error("Fingerprint error: {0}")]
    Fingerprint(FingerprintError),

    #[error("CDSI lookup error: {0}")]
    #[cfg(feature = "cdsi")]
    CdsiLookupError(#[from] libsignal_net::cdsi::LookupError),
}

impl From<signal_crypto::HpkeError> for ServiceError {
    fn from(value: signal_crypto::HpkeError) -> Self {
        ServiceError::Hpke(value)
    }
}

impl From<FingerprintError> for ServiceError {
    fn from(value: FingerprintError) -> Self {
        ServiceError::Fingerprint(value)
    }
}
