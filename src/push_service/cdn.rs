use std::{
    collections::HashMap,
    io::{self, Read, SeekFrom},
};

use bytes::Bytes;
use futures::{stream::LocalBoxStream, TryStreamExt};
use http::{
    header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE},
    HeaderMap, Method, StatusCode,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Deserialize;
use tracing::{debug, trace};
use url::Url;

use super::response::error_mapper;
use crate::{
    configuration::Endpoint,
    prelude::AttachmentIdentifier,
    proto::AttachmentPointer,
    push_service::HttpAuthOverride,
    transport::{EndpointKind, RedactedUrl, TransportError},
};

use super::{
    multipart, response::SignalServiceResponse, PushService, ServiceError,
};

/// The S3 POST policy for a CDN0 upload. `Debug` leaves out the signature,
/// which authorizes the upload.
#[derive(derive_more::Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV2UploadAttributes {
    key: String,
    credential: String,
    acl: String,
    algorithm: String,
    date: String,
    policy: String,
    #[debug(ignore)]
    signature: String,
}

/// Where and how to upload an attachment. `Debug` leaves out the upload's
/// credential: the headers' values (a CDN3 form's `Authorization`) and the
/// location's query (a CDN2 form's signature).
#[derive(derive_more::Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUploadForm {
    pub cdn: u32,
    pub key: String,
    #[debug("{:?}", headers.keys())]
    pub headers: HashMap<String, String>,
    #[debug("{}", RedactedUrl(signed_upload_location))]
    pub signed_upload_location: Url,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDigest {
    pub digest: Vec<u8>,
    pub incremental_digest: Option<Vec<u8>>,
    pub incremental_mac_chunk_size: u64,
}

#[derive(Debug)]
pub struct ResumeInfo {
    pub content_range: Option<String>,
    pub content_start: u64,
}

pub struct AttachmentDownload<R> {
    pub stream: R,
    pub content_length: Option<u64>,
}

/// A CDN download that may continue one already begun
/// ([`PushService::get_attachment_range`]).
#[derive(derive_more::Debug)]
pub struct RangedDownload {
    /// Where in the object the body starts: the byte the download asked to
    /// continue from, or 0 when the CDN sent the whole object instead, as a
    /// server may (RFC 9110 §14.2).
    pub start: u64,
    /// The object's whole length, when it is known: a whole response's
    /// `Content-Length`, a partial one's complete length, `start` for a 416.
    /// A whole response is complete at the body's clean end. A partial one
    /// may end before the object does (RFC 9110 §15.3.7): the download is
    /// complete once `start` plus the bytes received reach this length.
    /// Without it a partial answer proves nothing, so ask again from there;
    /// the 416 ends the download.
    pub total_len: Option<u64>,
    /// The body from `start` on, in the chunks the transport received them.
    #[debug(ignore)]
    pub body: LocalBoxStream<'static, Result<Bytes, TransportError>>,
}

/// What `encodeURIComponent` leaves alone, as Signal-Desktop encodes a CDN
/// key into a path (`getEphemeralBackupStream`).
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// A `Content-Length` that is a number; one that isn't is logged and
/// ignored.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(CONTENT_LENGTH)?;
    let length = value.to_str().ok().and_then(|value| value.parse().ok());
    if length.is_none() {
        tracing::warn!("invalid Content-Length header");
    }
    length
}

/// A byte `Content-Range` (RFC 9110 §14.4).
#[derive(Debug, PartialEq)]
enum ContentRange {
    /// `bytes first-last/complete`, with `complete` `None` for `*`.
    Partial { first: u64, complete: Option<u64> },
    /// An unsatisfied range's `bytes */complete`.
    Unsatisfied { complete: u64 },
}

/// Parses a byte `Content-Range`; `None` if it is neither form.
fn parse_content_range(value: &str) -> Option<ContentRange> {
    let (unit, range) = value.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (range, complete) = range.split_once('/')?;
    let number = |digits: &str| -> Option<u64> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let complete = match complete {
        "*" => None,
        complete => Some(number(complete)?),
    };
    if range == "*" {
        return Some(ContentRange::Unsatisfied {
            complete: complete?,
        });
    }
    let (first, last) = range.split_once('-')?;
    let (first, last) = (number(first)?, number(last)?);
    if first > last || complete.is_some_and(|complete| last >= complete) {
        return None;
    }
    Some(ContentRange::Partial { first, complete })
}

// Signal-Server: controllers/AttachmentControllerV4.java:102
// (GET /v4/attachments/form/upload)
error_mapper! {
    get_attachment_upload_form_errors:
        // 413: attachment too large, AttachmentControllerV4.java:111
        PAYLOAD_TOO_LARGE => AttachmentTooLarge,
}

impl PushService {
    pub async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<
        AttachmentDownload<impl futures::io::AsyncRead + Unpin>,
        ServiceError,
    > {
        let path = match ptr.attachment_identifier.as_ref() {
            Some(AttachmentIdentifier::CdnId(id)) => {
                format!("attachments/{}", id)
            },
            Some(AttachmentIdentifier::CdnKey(key)) => {
                format!("attachments/{}", key)
            },
            None => {
                return Err(ServiceError::InvalidFrame {
                    reason: "no attachment identifier in pointer",
                });
            },
        };
        self.get_from_cdn(ptr.cdn_number(), &path).await
    }

    #[tracing::instrument(skip(self, path))]
    pub(crate) async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<
        AttachmentDownload<impl futures::io::AsyncRead + Unpin>,
        ServiceError,
    > {
        let response = self
            .request(
                Method::GET,
                Endpoint::cdn(cdn_id, path),
                HttpAuthOverride::Unidentified, // CDN requests are always without authentication
            )?
            .send()
            .await?
            .error_for_status()
            .await?;
        let content_length = content_length(&response.headers);
        let response_stream =
            response.body.map_err(io::Error::from).into_async_read();

        Ok(AttachmentDownload {
            stream: response_stream,
            content_length,
        })
    }

    /// Downloads `key` from CDN `cdn` from byte `from` on, to continue a
    /// download whose first `from` bytes are kept: `GET /attachments/{key}`
    /// with `Range: bytes={from}-`, or without a range from 0, as
    /// Signal-Desktop downloads a transfer archive
    /// (`getEphemeralBackupStream`). The body streams in the transport's
    /// chunks, uncopied.
    ///
    /// A partial answer (206) must continue at `from`, or the download is
    /// [`ServiceError::InvalidContentRange`], and may stop before the object
    /// does ([`RangedDownload::total_len`]); a whole one (200) starts at 0
    /// ([`RangedDownload::start`]).
    ///
    /// A 416 means `from` isn't before the object's end, and the kept bytes
    /// are a prefix of the object, so `from` is its length: the download is
    /// complete, an empty body at `from`. The 416's `Content-Range` is only a
    /// SHOULD (RFC 9110 §15.5.17), and CDN3 sends none on a cache miss. One
    /// that gives another length, or can't be read, is the CDN's status.
    ///
    /// A 429 is [`ServiceError::RateLimitExceeded`]. Any other status is
    /// [`ServiceError::UnhandledResponseCode`]: 404 once the CDN no longer
    /// has the object.
    #[tracing::instrument(skip(self, key))]
    pub async fn get_attachment_range(
        &mut self,
        cdn: u32,
        key: &str,
        from: u64,
    ) -> Result<RangedDownload, ServiceError> {
        let path =
            format!("/attachments/{}", utf8_percent_encode(key, URI_COMPONENT));
        let mut request = self.request(
            Method::GET,
            Endpoint::cdn(cdn, path),
            HttpAuthOverride::Unidentified,
        )?;
        if from > 0 {
            request = request.header(RANGE, format!("bytes={from}-"));
        }
        let response = request.send().await?;
        let content_range = || {
            response
                .headers
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_content_range)
        };
        match response.status {
            StatusCode::OK => Ok(RangedDownload {
                start: 0,
                total_len: content_length(&response.headers),
                body: response.body,
            }),
            StatusCode::PARTIAL_CONTENT => match content_range() {
                Some(ContentRange::Partial { first, complete })
                    if first == from =>
                {
                    Ok(RangedDownload {
                        start: from,
                        total_len: complete,
                        body: response.body,
                    })
                },
                _ => Err(ServiceError::InvalidContentRange {
                    from,
                    content_range: response.headers.get(CONTENT_RANGE).map(
                        |value| {
                            String::from_utf8_lossy(value.as_bytes())
                                .into_owned()
                        },
                    ),
                }),
            },
            StatusCode::RANGE_NOT_SATISFIABLE
                if !response.headers.contains_key(CONTENT_RANGE)
                    || content_range()
                        == Some(ContentRange::Unsatisfied {
                            complete: from,
                        }) =>
            {
                Ok(RangedDownload {
                    start: from,
                    total_len: Some(from),
                    body: Box::pin(futures::stream::empty()),
                })
            },
            _ => Err(response.status_error().await),
        }
    }

    pub(crate) async fn get_attachment_v4_upload_attributes(
        &mut self,
    ) -> Result<AttachmentUploadForm, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::service("/v4/attachments/form/upload"),
            HttpAuthOverride::NoOverride,
        )?
        .send()
        .await?
        .service_error_for_status_with(get_attachment_upload_form_errors)
        .await?
        .json()
        .await
    }

    #[tracing::instrument(
        skip_all,
        fields(cdn = attachment_upload_form.cdn),
        level = tracing::Level::TRACE
    )]
    pub(crate) async fn get_attachment_resumable_upload_url(
        &mut self,
        attachment_upload_form: &AttachmentUploadForm,
    ) -> Result<Url, ServiceError> {
        let mut request = self.request(
            Method::POST,
            Endpoint::absolute(
                attachment_upload_form.signed_upload_location.clone(),
                EndpointKind::Cdn(attachment_upload_form.cdn),
            ),
            HttpAuthOverride::Unidentified,
        )?;

        for (key, value) in &attachment_upload_form.headers {
            request = request.header(key, value);
        }

        if attachment_upload_form.cdn == 2 {
            request = request.header(CONTENT_TYPE, "application/octet-stream");
        } else if attachment_upload_form.cdn == 3 {
            request = request
                .header("Upload-Defer-Length", "1")
                .header("Tus-Resumable", "1.0.0");
        } else {
            return Err(ServiceError::UnknownCdnVersion(
                attachment_upload_form.cdn,
            ));
        };

        Ok(request
            .send()
            .await?
            .error_for_status()
            .await?
            .headers
            .get(LOCATION)
            .ok_or(ServiceError::InvalidFrame {
                reason: "missing location header in HTTP response",
            })?
            .to_str()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid location header bytes in HTTP response",
            })?
            .parse()?)
    }

    #[tracing::instrument(skip(self, resumable_url))]
    async fn get_attachment_resume_info_cdn2(
        &mut self,
        resumable_url: &Url,
        content_length: u64,
    ) -> Result<ResumeInfo, ServiceError> {
        let response = self
            .request(
                Method::PUT,
                Endpoint::cdn_url(2, resumable_url),
                HttpAuthOverride::Unidentified,
            )?
            .header(CONTENT_RANGE, format!("bytes */{content_length}"))
            .send()
            .await?
            .error_for_status()
            .await?;

        let status = response.status;

        if status.is_success() {
            Ok(ResumeInfo {
                content_range: None,
                content_start: content_length,
            })
        } else if status == StatusCode::PERMANENT_REDIRECT {
            let offset =
                match response.headers.get(RANGE) {
                    Some(range) => range
                        .to_str()
                        .map_err(|_| ServiceError::InvalidFrame {
                            reason: "invalid format for Range HTTP header",
                        })?
                        .split('-')
                        .nth(1)
                        .ok_or(ServiceError::InvalidFrame {
                            reason:
                                "invalid value format for Range HTTP header",
                        })?
                        .parse::<u64>()
                        .map_err(|_| ServiceError::InvalidFrame {
                            reason:
                                "invalid number format for Range HTTP header",
                        })?
                        + 1,
                    None => 0,
                };

            Ok(ResumeInfo {
                content_range: Some(format!(
                    "bytes {}-{}/{}",
                    offset,
                    content_length - 1,
                    content_length
                )),
                content_start: offset,
            })
        } else {
            Err(ServiceError::InvalidFrame {
                reason: "failed to get resumable upload data from CDN2",
            })
        }
    }

    #[tracing::instrument(skip_all)]
    async fn get_attachment_resume_info_cdn3(
        &mut self,
        resumable_url: &Url,
        headers: &HashMap<String, String>,
    ) -> Result<ResumeInfo, ServiceError> {
        let mut request = self
            .request(
                Method::HEAD,
                Endpoint::cdn_url(3, resumable_url),
                HttpAuthOverride::Unidentified,
            )?
            .header("Tus-Resumable", "1.0.0");

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request.send().await?.error_for_status().await?;

        let upload_offset = response
            .headers
            .get("upload-offset")
            .ok_or(ServiceError::InvalidFrame {
                reason: "no Upload-Offset header in response",
            })?
            .to_str()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid upload-offset header bytes in HTTP response",
            })?
            .parse()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid integer value for Upload-Offset header",
            })?;

        Ok(ResumeInfo {
            content_range: None,
            content_start: upload_offset,
        })
    }

    /// Upload attachment
    ///
    /// Returns attachment ID and the attachment digest
    #[tracing::instrument(skip(self, resumable_url, headers, content))]
    pub(crate) async fn upload_attachment_v4(
        &mut self,
        cdn_id: u32,
        resumable_url: &Url,
        content_length: u64,
        headers: HashMap<String, String>,
        content: impl std::io::Read + std::io::Seek,
    ) -> Result<AttachmentDigest, ServiceError> {
        if cdn_id == 2 {
            self.upload_to_cdn2(resumable_url, content_length, content)
                .await
        } else {
            self.upload_to_cdn3(
                resumable_url,
                &headers,
                content_length,
                content,
            )
            .await
        }
    }

    #[tracing::instrument(skip(self, upload_attributes, reader))]
    pub async fn upload_to_cdn0(
        &mut self,
        path: &str,
        upload_attributes: AttachmentV2UploadAttributes,
        filename: String,
        mut reader: impl Read,
    ) -> Result<(), ServiceError> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        // Amazon S3 expects multipart fields in a very specific order
        // DO NOT CHANGE THIS (or do it, but feel the wrath of the gods)
        let (content_type, body) = multipart::Form::new()
            .text("acl", &upload_attributes.acl)
            .text("key", &upload_attributes.key)
            .text("policy", &upload_attributes.policy)
            .text("Content-Type", "application/octet-stream")
            .text("x-amz-algorithm", &upload_attributes.algorithm)
            .text("x-amz-credential", &upload_attributes.credential)
            .text("x-amz-date", &upload_attributes.date)
            .text("x-amz-signature", &upload_attributes.signature)
            .file("file", &filename, "application/octet-stream", buf.into());

        // The CDN gets no account credentials: the policy authorizes the
        // upload.
        let response = self
            .request(
                Method::POST,
                Endpoint::cdn(0, path),
                HttpAuthOverride::Unidentified,
            )?
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await?
            .error_for_status()
            .await?;

        debug!(status = %response.status, "CDN0 upload finished");

        Ok(())
    }

    #[tracing::instrument(skip(self, resumable_url, content))]
    async fn upload_to_cdn2(
        &mut self,
        resumable_url: &Url,
        content_length: u64,
        mut content: impl std::io::Read + std::io::Seek,
    ) -> Result<AttachmentDigest, ServiceError> {
        let resume_info = self
            .get_attachment_resume_info_cdn2(resumable_url, content_length)
            .await?;

        let mut digester =
            crate::digeststream::DigestingReader::new(&mut content);

        let mut buf = Vec::new();
        digester.read_to_end(&mut buf)?;

        trace!("digested content");

        let mut request = self.request(
            Method::PUT,
            Endpoint::cdn_url(2, resumable_url),
            HttpAuthOverride::Unidentified,
        )?;

        if let Some(content_range) = resume_info.content_range {
            request = request.header(CONTENT_RANGE, content_range);
        }

        request.body(buf).send().await?.error_for_status().await?;

        Ok(AttachmentDigest {
            digest: digester.finalize(),
            incremental_digest: None,
            incremental_mac_chunk_size: 0,
        })
    }

    #[tracing::instrument(skip(self, resumable_url, headers, content))]
    async fn upload_to_cdn3(
        &mut self,
        resumable_url: &Url,
        headers: &HashMap<String, String>,
        content_length: u64,
        mut content: impl std::io::Read + std::io::Seek,
    ) -> Result<AttachmentDigest, ServiceError> {
        let resume_info = self
            .get_attachment_resume_info_cdn3(resumable_url, headers)
            .await?;

        trace!(?resume_info, "got resume info");

        if resume_info.content_start == content_length {
            let mut digester =
                crate::digeststream::DigestingReader::new(&mut content);
            let mut buf = Vec::new();
            digester.read_to_end(&mut buf)?;
            return Ok(AttachmentDigest {
                digest: digester.finalize(),
                incremental_digest: None,
                incremental_mac_chunk_size: 0,
            });
        }

        let mut digester =
            crate::digeststream::DigestingReader::new(&mut content);
        digester.seek(SeekFrom::Start(resume_info.content_start))?;

        let mut buf = Vec::new();
        digester.read_to_end(&mut buf)?;

        trace!("digested content");

        let mut request = self.request(
            Method::PATCH,
            Endpoint::cdn(3, resumable_url.path()),
            HttpAuthOverride::Unidentified,
        )?;

        for (key, value) in headers {
            request = request.header(key, value);
        }

        request
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Offset", resume_info.content_start)
            .header("Upload-Length", buf.len())
            .header(CONTENT_TYPE, "application/offset+octet-stream")
            .body(buf)
            .send()
            .await?
            .error_for_status()
            .await?;

        trace!("attachment uploaded");

        Ok(AttachmentDigest {
            digest: digester.finalize(),
            incremental_digest: None,
            incremental_mac_chunk_size: 0,
        })
    }
}
