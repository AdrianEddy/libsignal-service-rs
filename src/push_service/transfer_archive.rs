//! The transfer archive a primary device uploads for a device it just linked
//! (link and sync): `GET /v1/devices/transfer_archive`, a long poll on the
//! chat service.

use std::time::Duration;

use http::{Method, StatusCode};
use serde::Deserialize;

use crate::configuration::Endpoint;

use super::{
    response::{error_mapper, SignalServiceResponse},
    HttpAuthOverride, PushService, ServiceError,
};

/// The longest wait the server takes: `timeout` is 1 to 3600 seconds
/// (Signal-Server `DeviceController.java`, `waitForTransferArchive`).
const TRANSFER_ARCHIVE_MAX_WAIT: Duration = Duration::from_secs(3600);

/// How much longer than the server's wait the request waits for its answer,
/// Signal-Desktop's leeway for the server to answer (`getTransferArchive`).
const ANSWER_LEEWAY: Duration = Duration::from_secs(15);

/// What the primary device did with this device's transfer archive.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum TransferArchive {
    /// Uploaded: the encrypted archive is `key` on CDN `cdn`
    /// ([`PushService::get_attachment_range`]). `Debug` leaves out `key`,
    /// which is all it takes to fetch the object.
    Ready {
        cdn: u32,
        #[debug(ignore)]
        key: String,
    },
    /// The primary asks this device to link again.
    RelinkRequested,
    /// The primary won't upload one: go on without the history.
    ContinueWithoutUpload,
    /// None within the wait: ask again.
    NotYet,
}

/// The server's `TransferArchiveResult`: a `RemoteAttachment` or a
/// `RemoteAttachmentError`.
#[derive(Deserialize)]
#[serde(untagged)]
enum TransferArchiveResult {
    Uploaded { cdn: u32, key: String },
    Failed { error: RemoteAttachmentError },
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RemoteAttachmentError {
    RelinkRequested,
    ContinueWithoutUpload,
}

// Signal-Server: controllers/DeviceController.java:515
// (GET /v1/devices/transfer_archive)
error_mapper! {
    wait_for_transfer_archive_errors:
        // 400: `timeout` out of 1..=3600, DeviceController.java:535-536
        BAD_REQUEST => InvalidTransferArchiveTimeout,
}

impl PushService {
    /// Waits for this device's transfer archive, as the account's linked
    /// device: the server holds the request until the primary device uploads
    /// the archive or gives up, or until `wait` has passed
    /// ([`TransferArchive::NotYet`]).
    ///
    /// The server takes whole seconds from 1 to 3600, so `wait` is cut to
    /// whole seconds within those bounds; the request waits that long plus
    /// 15 s for its answer ([`RequestBuilder::timeout`]), as Signal-Desktop's
    /// does. A rate limit (10 requests, then one per 30 s on Signal's
    /// servers) is [`ServiceError::RateLimitExceeded`].
    ///
    /// [`RequestBuilder::timeout`]: super::RequestBuilder::timeout
    pub async fn wait_for_transfer_archive(
        &mut self,
        wait: Duration,
    ) -> Result<TransferArchive, ServiceError> {
        let seconds =
            wait.as_secs().clamp(1, TRANSFER_ARCHIVE_MAX_WAIT.as_secs());
        let response = self
            .request(
                Method::GET,
                Endpoint::service(format!(
                    "/v1/devices/transfer_archive?timeout={seconds}"
                )),
                HttpAuthOverride::NoOverride,
            )?
            .timeout(Duration::from_secs(seconds) + ANSWER_LEEWAY)
            .send()
            .await?
            .service_error_for_status_with(wait_for_transfer_archive_errors)
            .await?;
        if response.status == StatusCode::NO_CONTENT {
            return Ok(TransferArchive::NotYet);
        }
        Ok(match response.json().await? {
            TransferArchiveResult::Uploaded { cdn, key } => {
                TransferArchive::Ready { cdn, key }
            },
            TransferArchiveResult::Failed {
                error: RemoteAttachmentError::RelinkRequested,
            } => TransferArchive::RelinkRequested,
            TransferArchiveResult::Failed {
                error: RemoteAttachmentError::ContinueWithoutUpload,
            } => TransferArchive::ContinueWithoutUpload,
        })
    }
}
