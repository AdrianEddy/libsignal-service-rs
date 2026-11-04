//! `multipart/form-data` bodies (RFC 7578) for the CDN0 upload, which S3
//! reads as a POST policy form.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use futures::{stream, StreamExt};
use http::HeaderValue;
use rand::Rng;

use crate::transport::HttpBody;

/// Text fields in the order they are added, then one file part.
pub(crate) struct Form {
    boundary: String,
    head: BytesMut,
}

impl Form {
    pub(crate) fn new() -> Self {
        let mut rng = rand::rng();
        let boundary = format!(
            "{:016x}-{:016x}-{:016x}-{:016x}",
            rng.random::<u64>(),
            rng.random::<u64>(),
            rng.random::<u64>(),
            rng.random::<u64>()
        );
        Self {
            boundary,
            head: BytesMut::new(),
        }
    }

    pub(crate) fn text(mut self, name: &str, value: &str) -> Self {
        self.part_head(name);
        self.head.put_slice(b"\r\n\r\n");
        self.head.put_slice(value.as_bytes());
        self.head.put_slice(b"\r\n");
        self
    }

    /// Ends the form with a file part, and returns the form's `Content-Type`
    /// and its body. The content is not copied.
    pub(crate) fn file(
        mut self,
        name: &str,
        file_name: &str,
        content_type: &str,
        content: Bytes,
    ) -> (HeaderValue, HttpBody) {
        self.part_head(name);
        self.head.put_slice(b"; filename=\"");
        // Escaped as browsers do (HTML's multipart/form-data encoding).
        for byte in file_name.bytes() {
            match byte {
                b'"' => self.head.put_slice(b"%22"),
                b'\r' => self.head.put_slice(b"%0D"),
                b'\n' => self.head.put_slice(b"%0A"),
                byte => self.head.put_u8(byte),
            }
        }
        self.head.put_slice(b"\"\r\nContent-Type: ");
        self.head.put_slice(content_type.as_bytes());
        self.head.put_slice(b"\r\n\r\n");

        let head = self.head.freeze();
        let tail = Bytes::from(format!("\r\n--{}--\r\n", self.boundary));
        let len = (head.len() + content.len() + tail.len()) as u64;
        let content_type = HeaderValue::try_from(format!(
            "multipart/form-data; boundary={}",
            self.boundary
        ))
        .expect("the boundary is a valid header value");
        let stream =
            stream::iter([head, content, tail].map(Ok::<_, io::Error>))
                .boxed_local();
        (content_type, HttpBody::Stream { len, stream })
    }

    /// `name` is one of our field names, which need no escaping.
    fn part_head(&mut self, name: &str) {
        debug_assert!(!name.contains(['"', '\r', '\n']));
        self.head.put_slice(b"--");
        self.head.put_slice(self.boundary.as_bytes());
        self.head
            .put_slice(b"\r\nContent-Disposition: form-data; name=\"");
        self.head.put_slice(name.as_bytes());
        self.head.put_u8(b'"');
    }
}
