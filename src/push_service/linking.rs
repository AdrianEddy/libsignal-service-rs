use std::collections::BTreeMap;

use http::Method;
use libsignal_core::DeviceId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    configuration::Endpoint, utils::serde_device_id,
    websocket::registration::DeviceActivationRequest,
};

use super::response::{
    device_limit_reached, error_mapper, SignalServiceResponse,
};
use super::{HttpAuth, HttpAuthOverride, PushService, ServiceError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAccountAttributes {
    pub fetches_messages: bool,
    pub name: String,
    pub registration_id: u32,
    /// Only for an account with a phone number (Signal-Desktop
    /// `WebAPI.preload.ts` `linkDevice`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pni_registration_id: Option<u32>,
    /// The device's capabilities by name, the caller's record: Signal-Server
    /// reads a `Map<String, Boolean>` (`DeviceCapabilityAdapter`). It refuses
    /// a link without `spqr` or, on an account without a phone number,
    /// without `optionalPhoneNumber` (409), and one that drops a capability
    /// the account can't lose (409, `DeviceCapability`).
    pub capabilities: BTreeMap<String, bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    /// `None` for an account without a phone number.
    #[serde(default)]
    pub pni: Option<Uuid>,
    #[serde(with = "serde_device_id")]
    pub device_id: DeviceId,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequest {
    pub verification_code: String,
    pub account_attributes: LinkAccountAttributes,
    #[serde(flatten)]
    pub device_activation_request: DeviceActivationRequest,
}

// 422: the request failed the server's validation. The body carries bean
// validation's errors, if that is what failed; the controller's own 422s
// have an empty body.
async fn invalid_link_request<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
{
    ServiceError::InvalidLinkRequest {
        body: response.error_body().await,
    }
}

// Signal-Server: controllers/DeviceController.java:231
// (PUT /v1/devices/link)
error_mapper! {
    link_device_errors:
        // 403: invalid device verification code, DeviceController.java:238
        FORBIDDEN => InvalidDeviceVerificationCode,
        // 409: a capability missing (`optionalPhoneNumber` on an account
        // without a phone number) or downgraded, DeviceController.java:248, 279
        CONFLICT => DeviceCapabilityDowngrade,
        // 411: device limit reached, DeviceController.java:260
        LENGTH_REQUIRED => fn device_limit_reached,
        // 422: bad prekey signatures, PNI keys on an account without a PNI
        // or missing on one with it, no capabilities, or a body that fails
        // validation, DeviceController.java:271, 277
        UNPROCESSABLE_ENTITY => fn invalid_link_request,
}

impl PushService {
    pub async fn link_device(
        &mut self,
        link_request: &LinkRequest,
        http_auth: HttpAuth,
    ) -> Result<LinkResponse, ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::service("/v1/devices/link"),
            HttpAuthOverride::Identified(http_auth),
        )?
        .json(link_request)
        .send()
        .await?
        .service_error_for_status_with(link_device_errors)
        .await?
        .json()
        .await
    }
}
