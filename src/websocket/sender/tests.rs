use std::time::Duration;

use super::{put_messages_errors, put_multi_recipient_messages_errors};
use crate::{
    proto::WebSocketResponseMessage,
    push_service::{ProofRequired, ServiceError},
};

/// A 428's answer, with these headers.
fn challenge(headers: &[&str]) -> WebSocketResponseMessage {
    WebSocketResponseMessage {
        id: Some(1),
        status: Some(428),
        message: None,
        headers: headers.iter().map(|&header| header.to_owned()).collect(),
        body: Some(br#"{"token":"a","options":["pushChallenge"]}"#.to_vec()),
    }
}

/// The 428's `Retry-After` is the wait that lifts the challenge on its own, as
/// libsignal-net's chat client reads it, and both message PUTs keep it: one
/// without the header, or with one that isn't a number of seconds, names none.
#[tokio::test]
async fn a_428_keeps_its_retry_after() {
    for (headers, wait) in [
        (&["Retry-After: 42"][..], Some(Duration::from_secs(42))),
        (
            &["Content-Type: application/json", "retry-after:0"],
            Some(Duration::ZERO),
        ),
        (
            &["Retry-After: 99999999999999999999"],
            Some(Duration::from_secs(u64::MAX)),
        ),
        (&["Retry-After: soon"], None),
        (&[], None),
    ] {
        for answered in [
            put_messages_errors(challenge(headers)).await,
            put_multi_recipient_messages_errors(challenge(headers)).await,
        ] {
            match answered {
                Err(ServiceError::ProofRequiredError(ProofRequired {
                    token,
                    options,
                    retry_after,
                })) => {
                    assert_eq!(token, "a");
                    assert_eq!(options, ["pushChallenge"]);
                    assert_eq!(retry_after, wait, "{headers:?}");
                },
                other => panic!("{headers:?}: {other:?}"),
            }
        }
    }
}
