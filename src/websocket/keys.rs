use std::collections::HashMap;

use base64::Engine as _;
use http::Method;
use libsignal_core::DeviceId;
use libsignal_protocol::{
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey, SenderCertificate, ServiceId,
    ServiceIdKind, SignalProtocolError,
};
use serde::Deserialize;

use crate::{
    pre_keys::{
        KyberPreKeyEntity, PreKeyEntity, PreKeyState, SignedPreKeyEntity,
    },
    proto::WebSocketRequestMessage,
    push_service::response::SignalServiceResponse,
    push_service::DEFAULT_DEVICE_ID,
    sender::OutgoingPushMessage,
    unidentified_access::UnidentifiedAccess,
    utils::{serde_base64, serde_device_id, BASE64_RELAXED},
    websocket::{self, registration::VerifyAccountResponse, SignalWebSocket},
};

use super::ServiceError;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
    pub pq_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponse {
    #[serde(with = "serde_base64")]
    pub identity_key: Vec<u8>,
    pub devices: Vec<PreKeyResponseItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    #[serde(with = "serde_device_id")]
    pub device_id: DeviceId,
    pub registration_id: u32,
    pub signed_pre_key: SignedPreKeyEntity,
    pub pre_key: Option<PreKeyEntity>,
    pub pq_pre_key: KyberPreKeyEntity,
}

impl PreKeyResponse {
    fn into_bundles(self) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let identity = IdentityKey::decode(&self.identity_key)?;
        self.devices
            .into_iter()
            .map(|device| device.into_bundle(identity))
            .collect()
    }
}

/// The path of a prekey fetch: every device's bundle for device 1
/// (`/v2/keys/{service id}/*`), only that device's for any other.
fn pre_keys_path(destination: &ServiceId, device_id: DeviceId) -> String {
    let destination = destination.service_id_string();
    if device_id == *DEFAULT_DEVICE_ID {
        format!("/v2/keys/{destination}/*")
    } else {
        format!("/v2/keys/{destination}/{device_id}")
    }
}

impl PreKeyResponseItem {
    pub(crate) fn into_bundle(
        self,
        identity: IdentityKey,
    ) -> Result<PreKeyBundle, ServiceError> {
        let pre_key_bundle = PreKeyBundle::new(
            self.registration_id,
            self.device_id,
            self.pre_key
                .map(|pk| -> Result<_, SignalProtocolError> {
                    Ok((
                        pk.key_id.into(),
                        PublicKey::deserialize(&pk.public_key)?,
                    ))
                })
                .transpose()?,
            // pre_key: Option<(u32, PublicKey)>,
            self.signed_pre_key.key_id.into(),
            PublicKey::deserialize(&self.signed_pre_key.public_key)?,
            self.signed_pre_key.signature,
            self.pq_pre_key.key_id.into(),
            Key::<Public>::deserialize(&self.pq_pre_key.public_key)?,
            self.pq_pre_key.signature,
            identity,
        )?;

        Ok(pre_key_bundle)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SenderCertificateJson {
    #[serde(with = "serde_base64")]
    certificate: Vec<u8>,
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn get_pre_key_status(
        &mut self,
        service_id_kind: ServiceIdKind,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.http_request(
            Method::GET,
            format!("/v2/keys?identity={}", service_id_kind),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }

    /// Checks for consistency of the repeated-use keys
    ///
    /// Supply the digest as follows:
    /// `SHA256(identityKeyBytes || signedEcPreKeyId || signedEcPreKeyIdBytes || lastResortKeyId ||
    /// lastResortKeyBytes)`
    ///
    /// The IDs are represented as 8-byte big endian ints.
    ///
    /// Retuns `Ok(true)` if the view is consistent, `Ok(false)` if the view is inconsistent.
    pub async fn check_pre_keys(
        &mut self,
        service_id_kind: ServiceIdKind,
        digest: &[u8; 32],
    ) -> Result<bool, ServiceError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CheckPreKeysRequest<'a> {
            identity_type: String,
            #[serde(with = "serde_base64")]
            digest: &'a [u8; 32],
        }

        let req = CheckPreKeysRequest {
            identity_type: service_id_kind.to_string(),
            digest,
        };

        let res = self
            .http_request(Method::POST, "/v2/keys/check")?
            .send_json(&req)
            .await?;

        if res.status_code() == Some(http::StatusCode::CONFLICT) {
            return Ok(false);
        }

        res.service_error_for_status().await?;

        Ok(true)
    }

    pub async fn register_pre_keys(
        &mut self,
        service_id_kind: ServiceIdKind,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        self.http_request(
            Method::PUT,
            format!("/v2/keys?identity={}", service_id_kind),
        )?
        .send_json(&pre_key_state)
        .await?
        .service_error_for_status()
        .await?;

        Ok(())
    }

    pub async fn get_pre_key(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<PreKeyBundle, ServiceError> {
        let path = format!(
            "/v2/keys/{}/{}",
            destination.service_id_string(),
            device_id
        );

        let mut pre_key_response: PreKeyResponse = self
            .http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        assert!(!pre_key_response.devices.is_empty());

        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        let device = pre_key_response.devices.remove(0);
        device.into_bundle(identity)
    }

    /// The prekey bundles of `destination`'s devices, to build sessions from:
    /// every device's for device 1 (`GET /v2/keys/{service id}/*`), only that
    /// device's for any other.
    ///
    /// The server learns who asks for whose keys. For a sealed-sender send,
    /// fetch on the unauthenticated socket with the recipient's access key
    /// instead (`SignalWebSocket::<Unidentified>::get_pre_keys`).
    pub async fn get_pre_keys(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        self.http_request(Method::GET, pre_keys_path(destination, device_id))?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json::<PreKeyResponse>()
            .await?
            .into_bundles()
    }

    pub async fn get_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .http_request(Method::GET, "/v1/certificate/delivery")?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    pub async fn get_uuid_only_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .http_request(
                Method::GET,
                "/v1/certificate/delivery?includeE164=false",
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    pub async fn distribute_pni_keys(
        &mut self,
        pni_identity_key: &IdentityKey,
        device_messages: Vec<OutgoingPushMessage>,
        device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
        device_pni_last_resort_kyber_prekeys: HashMap<
            String,
            KyberPreKeyEntity,
        >,
        pni_registration_ids: HashMap<String, u32>,
        signature_valid_on_each_signed_pre_key: bool,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct PniKeyDistributionRequest {
            #[serde(with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            device_messages: Vec<OutgoingPushMessage>,
            device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
            #[serde(rename = "devicePniPqLastResortPrekeys")]
            device_pni_last_resort_kyber_prekeys:
                HashMap<String, KyberPreKeyEntity>,
            pni_registration_ids: HashMap<String, u32>,
            signature_valid_on_each_signed_pre_key: bool,
        }
        self.http_request(
            Method::PUT,
            "/v2/accounts/phone_number_identity_key_distribution",
        )?
        .send_json(&PniKeyDistributionRequest {
            pni_identity_key: pni_identity_key.serialize().into(),
            device_messages,
            device_pni_signed_prekeys,
            device_pni_last_resort_kyber_prekeys,
            pni_registration_ids,
            signature_valid_on_each_signed_pre_key,
        })
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }
}

impl SignalWebSocket<websocket::Unidentified> {
    /// The prekey bundles of `destination`'s devices, as the authenticated
    /// socket's `get_pre_keys` gives them, fetched with `destination`'s access
    /// key so that the server doesn't learn who asks: the fetch for a
    /// sealed-sender send, as Desktop and Android make it.
    ///
    /// A key the server refuses (401 or 403, also for an account that doesn't
    /// exist) is [`ServiceError::Unauthorized`]; the official clients then
    /// fetch on the authenticated socket and send that recipient's message
    /// unsealed.
    pub async fn get_pre_keys(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
        access: &UnidentifiedAccess,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::GET)
            .path(pre_keys_path(destination, device_id))
            .header(
                "Unidentified-Access-Key",
                BASE64_RELAXED.encode(&access.key),
            )
            .build();
        self.request(request)
            .await?
            .service_error_for_status()
            .await?
            .json::<PreKeyResponse>()
            .await?
            .into_bundles()
    }
}
