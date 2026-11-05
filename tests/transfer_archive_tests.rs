//! `GET /v1/devices/transfer_archive`: the linked device's long poll for the
//! transfer archive its primary uploads.

mod common;

use std::time::Duration;

use http::{header, Method};
use libsignal_service::{
    push_service::{ServiceError, TransferArchive},
    transport::EndpointKind,
};

use common::*;

/// Waits `wait` for the archive against a server that answers `answer`;
/// returns the outcome and the request.
async fn wait_for(
    wait: Duration,
    answer: Answer,
) -> (Result<TransferArchive, ServiceError>, Seen) {
    let (mut service, transport) = push_service();
    transport.answer(answer);
    let outcome = service.wait_for_transfer_archive(wait).await;
    (outcome, transport.take_one())
}

/// The primary uploaded the archive: where it is. The request is the
/// account's, on the chat service.
#[tokio::test]
async fn ready() {
    let (outcome, request) = wait_for(
        Duration::from_secs(300),
        Answer::json(200, serde_json::json!({ "cdn": 3, "key": "abc-_=" })),
    )
    .await;
    let archive = outcome.unwrap();
    assert_eq!(
        archive,
        TransferArchive::Ready {
            cdn: 3,
            key: "abc-_=".into()
        }
    );
    assert_eq!(format!("{archive:?}"), "Ready { cdn: 3, .. }");
    assert_eq!(request.method, Method::GET);
    assert_eq!(
        request.url,
        "https://chat.test/v1/devices/transfer_archive?timeout=300"
    );
    assert_eq!(request.endpoint, EndpointKind::Chat);
    assert_eq!(
        request.header(header::AUTHORIZATION),
        Some(&*basic(&format!("{ACI}.2:hunter2")))
    );
    assert!(request.body.is_empty());
}

#[tokio::test]
async fn relink_requested() {
    let (outcome, _) = wait_for(
        Duration::from_secs(300),
        Answer::json(200, serde_json::json!({ "error": "RELINK_REQUESTED" })),
    )
    .await;
    assert_eq!(outcome.unwrap(), TransferArchive::RelinkRequested);
}

#[tokio::test]
async fn continue_without_upload() {
    let (outcome, _) = wait_for(
        Duration::from_secs(300),
        Answer::json(
            200,
            serde_json::json!({ "error": "CONTINUE_WITHOUT_UPLOAD" }),
        ),
    )
    .await;
    assert_eq!(outcome.unwrap(), TransferArchive::ContinueWithoutUpload);

    // An error the server doesn't have is not read as either.
    let (outcome, _) = wait_for(
        Duration::from_secs(300),
        Answer::json(200, serde_json::json!({ "error": "SOMETHING_ELSE" })),
    )
    .await;
    assert!(
        matches!(outcome, Err(ServiceError::JsonDecodeError(_))),
        "{outcome:?}"
    );
}

/// Nothing within the wait: 204, ask again. The request waits for its answer
/// the server's wait plus 15 s, Signal-Desktop's leeway; the wait is whole
/// seconds from 1 to 3600, as the server takes it.
#[tokio::test]
async fn timeout_204() {
    for (wait, seconds) in [
        (Duration::from_secs(300), 300),
        (Duration::from_millis(30_999), 30),
        (Duration::ZERO, 1),
        (Duration::from_millis(400), 1),
        (Duration::from_secs(3600), 3600),
        (Duration::from_secs(86_400), 3600),
    ] {
        let (outcome, request) = wait_for(wait, Answer::status(204)).await;
        assert_eq!(outcome.unwrap(), TransferArchive::NotYet, "{wait:?}");
        assert_eq!(
            request.url,
            format!(
                "https://chat.test/v1/devices/transfer_archive?timeout={seconds}"
            )
        );
        assert_eq!(
            request.timeout,
            Some(Duration::from_secs(seconds + 15)),
            "{wait:?}"
        );
    }
}

/// The server's limit (10 requests, then one per 30 s): the wait it asks
/// for.
#[tokio::test]
async fn rate_limited_429() {
    let (outcome, _) = wait_for(
        Duration::from_secs(300),
        Answer::status(429).with_header("retry-after", "30"),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(ServiceError::RateLimitExceeded { retry_after: Some(wait) })
                if wait == Duration::from_secs(30)
        ),
        "{outcome:?}"
    );
}

/// A wait the server refuses is its own error, not an archive's absence.
#[tokio::test]
async fn invalid_timeout_400() {
    let (outcome, _) =
        wait_for(Duration::from_secs(300), Answer::status(400)).await;
    assert!(
        matches!(outcome, Err(ServiceError::InvalidTransferArchiveTimeout)),
        "{outcome:?}"
    );
}
