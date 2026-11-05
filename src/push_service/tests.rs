use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    io::Cursor,
    rc::Rc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use futures::{future::LocalBoxFuture, stream, StreamExt, TryStreamExt};
use http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode};
use sha2::{Digest, Sha256};

use super::{
    multipart, response::parse_retry_after, AttachmentUploadForm,
    AttachmentV2UploadAttributes, PushService,
};
use crate::{
    configuration::{ServiceConfiguration, SignalServers},
    transport::{
        EndpointKind, HttpBody, HttpRequest, HttpResponse, Transport,
        TransportError, WsConnect, WsUpgrade,
    },
};

#[test]
fn create_configurations() {
    for env in [SignalServers::Staging, SignalServers::Production] {
        let _ = ServiceConfiguration::from(env);
    }
}

#[test]
fn serde_json_from_empty_reader() {
    // serde_json rejects an empty body, so `SignalServiceResponse::json`
    // (response.rs) fails on a response without one.
    let bytes: Bytes = "".into();
    assert!(
        serde_json::from_reader::<bytes::buf::Reader<Bytes>, String>(
            bytes.reader()
        )
        .is_err()
    );
}

#[test]
fn serde_json_form_empty_vec() {
    // If we're trying to send and empty payload, serde_json must be able to make a Vec out of it
    assert!(serde_json::to_vec(b"").is_ok());
}

/// A server's `Retry-After` is `delay-seconds` or nothing: no value panics,
/// and a delay too long for a `Duration` saturates (RFC 9111 §1.2.2). chrono's
/// `Duration::seconds` panicked from 2^63 / 1000 seconds on.
#[test]
fn retry_after_is_whole_seconds_and_saturates() {
    for (header, wait) in [
        ("30", Some(Duration::from_secs(30))),
        (" \t0 ", Some(Duration::ZERO)),
        (
            "9300000000000000",
            Some(Duration::from_secs(9_300_000_000_000_000)),
        ),
        ("18446744073709551615", Some(Duration::from_secs(u64::MAX))),
        (
            "99999999999999999999999999",
            Some(Duration::from_secs(u64::MAX)),
        ),
        ("", None),
        ("-5", None),
        ("+5", None),
        ("1.5", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", None),
    ] {
        assert_eq!(parse_retry_after(header), wait, "{header:?}");
    }
}

/// A status and headers, with an empty body.
type Answer = (u16, Vec<(&'static str, &'static str)>);

/// Records each request and answers from a script.
#[derive(Default)]
struct Script {
    seen: RefCell<Vec<(HttpRequest, Bytes)>>,
    answers: RefCell<VecDeque<Answer>>,
}

impl Transport for Script {
    fn request(
        &self,
        mut request: HttpRequest,
    ) -> LocalBoxFuture<'_, Result<HttpResponse, TransportError>> {
        let body = match std::mem::replace(&mut request.body, HttpBody::Empty) {
            HttpBody::Empty => Bytes::new(),
            HttpBody::Bytes(bytes) => bytes,
            HttpBody::Stream { .. } => unreachable!("v4 uploads send bytes"),
        };
        self.seen.borrow_mut().push((request, body));
        let (status, headers) =
            self.answers.borrow_mut().pop_front().expect("an answer");
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(name, value.parse().unwrap());
        }
        Box::pin(async move {
            Ok(HttpResponse {
                status: StatusCode::from_u16(status).unwrap(),
                headers: map,
                body: stream::empty().boxed_local(),
            })
        })
    }

    fn websocket(
        &self,
        _: WsConnect,
    ) -> LocalBoxFuture<'_, Result<WsUpgrade, TransportError>> {
        unreachable!("HTTP only")
    }
}

fn service(answers: Vec<Answer>) -> (PushService, Rc<Script>) {
    let script = Rc::new(Script::default());
    script.answers.borrow_mut().extend(answers);
    let cfg = ServiceConfiguration::from(SignalServers::Staging);
    (PushService::new(cfg, None, script.clone()).unwrap(), script)
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.headers.get(name).map(|v| v.to_str().unwrap())
}

fn form(cdn: u32, headers: &[(&str, &str)]) -> AttachmentUploadForm {
    serde_json::from_value(serde_json::json!({
        "cdn": cdn,
        "key": "attachment-key",
        "headers": headers.iter().copied().collect::<HashMap<_, _>>(),
        "signedUploadLocation": "https://upload.test/start?signature=secret",
    }))
    .unwrap()
}

#[tokio::test]
async fn cdn2_upload_is_a_gcs_resumable_upload() {
    let content: Vec<u8> = (0..=255).cycle().take(2000).collect();
    let (mut service, script) = service(vec![
        (
            200,
            vec![(
                "location",
                "https://cdn2-staging.signal.org/resumable/abc?upload_id=1",
            )],
        ),
        (308, vec![]),
        (200, vec![]),
    ]);
    let form = form(2, &[("x-goog-resumable", "start")]);

    let location = service
        .get_attachment_resumable_upload_url(&form)
        .await
        .unwrap();
    let digest = service
        .upload_attachment_v4(
            2,
            &location,
            content.len() as u64,
            form.headers.clone(),
            Cursor::new(&content),
        )
        .await
        .unwrap();
    assert_eq!(digest.digest, Sha256::digest(&content).to_vec());

    let seen = script.seen.borrow();
    let [(start, start_body), (status, _), (upload, upload_body)] = &seen[..]
    else {
        panic!("three requests, got {}", seen.len());
    };
    assert_eq!(start.method, Method::POST);
    assert_eq!(
        start.url.as_str(),
        "https://upload.test/start?signature=secret"
    );
    assert_eq!(start.endpoint, EndpointKind::Cdn(2));
    assert_eq!(header(start, "x-goog-resumable"), Some("start"));
    // Framing is the transport's: an empty POST gets its `Content-Length: 0`
    // there (`HttpRequest`).
    assert_eq!(header(start, "content-length"), None);
    assert_eq!(
        header(start, "content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(header(start, "authorization"), None);
    assert!(start_body.is_empty());

    assert_eq!(status.method, Method::PUT);
    assert_eq!(
        status.url.as_str(),
        "https://cdn2-staging.signal.org/resumable/abc?upload_id=1"
    );
    assert_eq!(header(status, "content-range"), Some("bytes */2000"));

    assert_eq!(upload.method, Method::PUT);
    assert_eq!(upload.endpoint, EndpointKind::Cdn(2));
    assert_eq!(header(upload, "content-range"), Some("bytes 0-1999/2000"));
    assert_eq!(&upload_body[..], &content[..]);
}

#[tokio::test]
async fn cdn3_upload_is_a_tus_upload() {
    let content: Vec<u8> = (0..=255).cycle().take(1500).collect();
    let (mut service, script) = service(vec![
        (
            201,
            vec![("location", "https://cdn3-staging.signal.org/files/abc")],
        ),
        (200, vec![("upload-offset", "0")]),
        (204, vec![]),
    ]);
    let form = form(3, &[("authorization", "Basic dHVz")]);

    let location = service
        .get_attachment_resumable_upload_url(&form)
        .await
        .unwrap();
    let digest = service
        .upload_attachment_v4(
            3,
            &location,
            content.len() as u64,
            form.headers.clone(),
            Cursor::new(&content),
        )
        .await
        .unwrap();
    assert_eq!(digest.digest, Sha256::digest(&content).to_vec());

    let seen = script.seen.borrow();
    let [(create, _), (head, _), (patch, patch_body)] = &seen[..] else {
        panic!("three requests, got {}", seen.len());
    };
    assert_eq!(create.method, Method::POST);
    assert_eq!(create.endpoint, EndpointKind::Cdn(3));
    assert_eq!(header(create, "upload-defer-length"), Some("1"));
    assert_eq!(header(create, "tus-resumable"), Some("1.0.0"));
    assert_eq!(header(create, "authorization"), Some("Basic dHVz"));

    assert_eq!(head.method, Method::HEAD);
    assert_eq!(
        head.url.as_str(),
        "https://cdn3-staging.signal.org/files/abc"
    );
    assert_eq!(head.endpoint, EndpointKind::Cdn(3));
    assert_eq!(header(head, "tus-resumable"), Some("1.0.0"));

    assert_eq!(patch.method, Method::PATCH);
    assert_eq!(
        patch.url.as_str(),
        "https://cdn3-staging.signal.org/files/abc"
    );
    assert_eq!(header(patch, "upload-offset"), Some("0"));
    assert_eq!(header(patch, "upload-length"), Some("1500"));
    assert_eq!(
        header(patch, "content-type"),
        Some("application/offset+octet-stream")
    );
    assert_eq!(header(patch, "authorization"), Some("Basic dHVz"));
    assert_eq!(&patch_body[..], &content[..]);
}

#[tokio::test]
async fn upload_credentials_stay_out_of_debug_output() {
    let (mut service, script) = service(vec![(
        201,
        vec![("location", "https://cdn3-staging.signal.org/files/abc")],
    )]);
    // `dHVzOnNlY3JldA==` is `tus:secret`.
    let form = AttachmentUploadForm {
        cdn: 3,
        key: "attachment-key".into(),
        headers: HashMap::from([(
            "Authorization".into(),
            "Basic dHVzOnNlY3JldA==".into(),
        )]),
        signed_upload_location:
            "https://uploader:secret@upload.test:8443/start?signature=secret#secret"
                .parse()
                .unwrap(),
    };
    assert_eq!(
        format!("{form:?}"),
        "AttachmentUploadForm { cdn: 3, key: \"attachment-key\", \
         headers: [\"Authorization\"], \
         signed_upload_location: https://upload.test:8443/start }"
    );

    service
        .get_attachment_resumable_upload_url(&form)
        .await
        .unwrap();
    let seen = script.seen.borrow();
    let [(create, _)] = &seen[..] else {
        panic!("one request, got {}", seen.len());
    };
    assert!(create.headers[AUTHORIZATION].is_sensitive());
    assert_eq!(
        format!("{create:?}"),
        "HttpRequest { method: POST, url: https://upload.test:8443/start, \
         headers: {\"authorization\": Sensitive, \
         \"upload-defer-length\": \"1\", \"tus-resumable\": \"1.0.0\"}, \
         body: Empty, endpoint: Cdn(3), timeout: None }"
    );

    let attributes: AttachmentV2UploadAttributes =
        serde_json::from_value(serde_json::json!({
            "key": "profiles/key",
            "credential": "AKIAEXAMPLE/20261104/us-east-1/s3/aws4_request",
            "acl": "private",
            "algorithm": "AWS4-HMAC-SHA256",
            "date": "20261104T120000Z",
            "policy": "eyJ9",
            "signature": "secret",
        }))
        .unwrap();
    assert_eq!(
        format!("{attributes:?}"),
        "AttachmentV2UploadAttributes { key: \"profiles/key\", \
         credential: \"AKIAEXAMPLE/20261104/us-east-1/s3/aws4_request\", \
         acl: \"private\", algorithm: \"AWS4-HMAC-SHA256\", \
         date: \"20261104T120000Z\", policy: \"eyJ9\", .. }"
    );
}

#[tokio::test]
async fn multipart_escapes_file_names() {
    let (content_type, body) = multipart::Form::new().file(
        "file",
        "a\"b\r\nc.jpg",
        "image/jpeg",
        Bytes::from_static(b"data"),
    );
    let boundary = content_type
        .to_str()
        .unwrap()
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap()
        .to_owned();
    let HttpBody::Stream { len, stream } = body else {
        panic!("a streamed body");
    };
    let body: Vec<u8> = stream
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
        .unwrap();
    assert_eq!(body.len() as u64, len);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"a%22b%0D%0Ac.jpg\"\r\n\
             Content-Type: image/jpeg\r\n\r\n\
             data\r\n\
             --{boundary}--\r\n"
        )
    );
}
