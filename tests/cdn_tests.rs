//! CDN downloads that continue where an earlier one stopped.

mod common;

use std::time::Duration;

use bytes::Bytes;
use futures::TryStreamExt as _;
use http::{header, Method, StatusCode};
use libsignal_service::{
    prelude::AttachmentIdentifier,
    proto::AttachmentPointer,
    push_service::{RangedDownload, ServiceError},
    transport::EndpointKind,
};

use common::*;

/// Downloads `key` from CDN 3 from byte `from` against a CDN that answers
/// `answer`; returns the outcome and the request.
async fn fetch(
    key: &str,
    from: u64,
    answer: Answer,
) -> (Result<RangedDownload, ServiceError>, Seen) {
    let (mut service, transport) = push_service();
    transport.answer(answer);
    let outcome = service.get_attachment_range(3, key, from).await;
    (outcome, transport.take_one())
}

async fn body(download: RangedDownload) -> Vec<Bytes> {
    download.body.try_collect().await.unwrap()
}

/// A download that resumes at byte 4 asks for `bytes=4-` and gets the rest
/// of the object from there, chunk by chunk as the transport received them,
/// with the object's length.
#[tokio::test]
async fn range_request_resumes() {
    let chunks = [Bytes::from_static(b"efgh"), Bytes::from_static(b"ij")];
    let (outcome, request) = fetch(
        "key",
        4,
        Answer::chunks(206, chunks.iter().cloned().map(Ok).collect())
            .with_header("content-range", "bytes 4-9/10"),
    )
    .await;
    assert_eq!(request.method, Method::GET);
    assert_eq!(request.url, "https://cdn3.test/attachments/key");
    assert_eq!(request.endpoint, EndpointKind::Cdn(3));
    assert_eq!(request.header(header::RANGE), Some("bytes=4-"));
    assert_eq!(request.header(header::AUTHORIZATION), None, "unidentified");

    let download = outcome.unwrap();
    assert_eq!((download.start, download.total_len), (4, Some(10)));
    let received = body(download).await;
    assert_eq!(received, chunks);
    for (received, sent) in received.iter().zip(&chunks) {
        assert_eq!(received.as_ptr(), sent.as_ptr(), "not copied");
    }

    // A complete length the CDN doesn't know.
    let (outcome, _) = fetch(
        "key",
        4,
        Answer::body(206, "efgh").with_header("content-range", "bytes 4-7/*"),
    )
    .await;
    let download = outcome.unwrap();
    assert_eq!((download.start, download.total_len), (4, None));
}

/// From byte 0 the download asks for the whole object, without a range, as
/// Signal-Desktop does.
#[tokio::test]
async fn a_download_from_the_start_asks_for_the_whole_object() {
    let (outcome, request) = fetch(
        "key",
        0,
        Answer::body(200, "abcdefghij").with_header("content-length", "10"),
    )
    .await;
    assert_eq!(request.header(header::RANGE), None);
    let download = outcome.unwrap();
    assert_eq!((download.start, download.total_len), (0, Some(10)));
    assert_eq!(body(download).await, [Bytes::from_static(b"abcdefghij")]);
}

/// A CDN may answer a range with the whole object (RFC 9110 §14.2): the
/// download then starts at 0, so the caller starts over instead of
/// appending the object's head to what it kept.
#[tokio::test]
async fn a_whole_answer_to_a_range_starts_at_zero() {
    let (outcome, request) = fetch(
        "key",
        4,
        Answer::body(200, "abcdefghij").with_header("content-length", "10"),
    )
    .await;
    assert_eq!(request.header(header::RANGE), Some("bytes=4-"));
    let download = outcome.unwrap();
    assert_eq!((download.start, download.total_len), (0, Some(10)));
}

/// A partial answer that doesn't continue at the byte asked for, or doesn't
/// say where it starts, can't be appended.
#[tokio::test]
async fn a_partial_answer_elsewhere_is_refused() {
    for content_range in [
        Some("bytes 0-9/10"),
        Some("bytes 5-9/10"),
        Some("bytes 4-9/9"),
        Some("bytes 9-4/10"),
        Some("items 4-9/10"),
        Some("bytes 4-9"),
        Some("bytes */10"),
        None,
    ] {
        let mut answer = Answer::body(206, "efghij");
        if let Some(value) = content_range {
            answer = answer.with_header("content-range", value);
        }
        let (outcome, _) = fetch("key", 4, answer).await;
        match outcome {
            Err(ServiceError::InvalidContentRange {
                from: 4,
                content_range: got,
            }) => assert_eq!(got.as_deref(), content_range),
            other => panic!("{content_range:?}: {other:?}"),
        }
    }
}

/// Resuming a download that already has every byte: the CDN's 416 says the
/// object is as long as what was kept, or says nothing, and the download is
/// empty.
#[tokio::test]
async fn a_complete_download_resumes_empty() {
    for answer in [
        Answer::status(416).with_header("content-range", "bytes */10"),
        Answer::status(416),
        // CDN3 on a cache miss: R2 refuses the range and the worker answers
        // with this, no `Content-Range` (signalapp/tus-server, `getHandler`).
        Answer::body(416, r#"{"status":416,"error":"Unknown Error"}"#)
            .with_header("content-type", "application/json; charset=utf-8"),
    ] {
        let (outcome, _) = fetch("key", 10, answer).await;
        let download = outcome.unwrap();
        assert_eq!((download.start, download.total_len), (10, Some(10)));
        assert!(body(download).await.is_empty());
    }

    // Kept more than the object has, a length that isn't what was kept, or
    // one that can't be read: the CDN's answer stands.
    for (from, content_range) in [
        (12, "bytes */10"),
        (10, "bytes */9"),
        (10, "bytes */11"),
        (10, "bytes */*"),
        (10, "garbage"),
    ] {
        let (outcome, _) = fetch(
            "key",
            from,
            Answer::status(416).with_header("content-range", content_range),
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(ServiceError::UnhandledResponseCode { status, .. })
                    if status == StatusCode::RANGE_NOT_SATISFIABLE
            ),
            "{from} {content_range}: {outcome:?}"
        );
    }
}

/// A CDN's 429 is the error a chat-service 429 is, with its `Retry-After`
/// when it sends one, so a caller has one rate limit to handle.
#[tokio::test]
async fn rate_limited_429() {
    let answer = || Answer::body(429, "slow down");
    let (outcome, _) =
        fetch("key", 4, answer().with_header("retry-after", "120")).await;
    assert!(
        matches!(
            outcome,
            Err(ServiceError::RateLimitExceeded { retry_after: Some(wait) })
                if wait == Duration::from_secs(120)
        ),
        "{outcome:?}"
    );

    let (outcome, _) = fetch("key", 4, answer()).await;
    assert!(
        matches!(
            outcome,
            Err(ServiceError::RateLimitExceeded { retry_after: None })
        ),
        "{outcome:?}"
    );
}

/// `get_attachment` shares the rule, as every CDN call does.
#[tokio::test]
async fn a_whole_download_keeps_a_429s_wait() {
    let (mut service, transport) = push_service();
    let pointer = AttachmentPointer {
        cdn_number: Some(3),
        attachment_identifier: Some(AttachmentIdentifier::CdnKey("key".into())),
        ..Default::default()
    };
    transport.answer(Answer::status(429).with_header("retry-after", "120"));
    let error = service.get_attachment(&pointer).await.err().unwrap();
    assert!(
        matches!(
            error,
            ServiceError::RateLimitExceeded { retry_after: Some(wait) }
                if wait == Duration::from_secs(120)
        ),
        "{error:?}"
    );
}

/// On a CDN a 413 means what HTTP says, not the chat service's rate limit,
/// and a `Retry-After` beside another status names no rate limit either.
#[tokio::test]
async fn only_a_429_is_a_rate_limit() {
    for status in [413, 503] {
        let (outcome, _) = fetch(
            "key",
            4,
            Answer::body(status, "nope").with_header("retry-after", "120"),
        )
        .await;
        match outcome {
            Err(ServiceError::UnhandledResponseCode { status: got, body }) => {
                assert_eq!(got.as_u16(), status);
                assert_eq!(body, "nope");
            },
            other => panic!("{status}: {other:?}"),
        }
    }
}

/// An object the CDN no longer has, or any other status, comes back as the
/// CDN's status.
#[tokio::test]
async fn a_missing_object_is_the_cdns_status() {
    for status in [404, 500, 204, 302] {
        let (outcome, _) = fetch("key", 4, Answer::body(status, "nope")).await;
        match outcome {
            Err(ServiceError::UnhandledResponseCode { status: got, body }) => {
                assert_eq!(got.as_u16(), status);
                assert_eq!(body, "nope");
            },
            other => panic!("{status}: {other:?}"),
        }
    }
}

/// The key is one path segment, encoded as `encodeURIComponent` encodes it.
#[tokio::test]
async fn the_key_is_one_path_segment() {
    let (_, request) = fetch(
        "a/b?c#d e=",
        0,
        Answer::body(200, "").with_header("content-length", "0"),
    )
    .await;
    assert_eq!(
        request.url,
        "https://cdn3.test/attachments/a%2Fb%3Fc%23d%20e%3D"
    );
}
