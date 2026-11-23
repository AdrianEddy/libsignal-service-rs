use bytes::Bytes;
use libsignal_core::DeviceId;
use libsignal_protocol::{Pni, ProtocolAddress, ServiceId};
use prost::Message;
use std::fmt;
use uuid::Uuid;

pub use crate::{
    proto::{
        attachment_pointer::Flags as AttachmentPointerFlags,
        data_message::Flags as DataMessageFlags, data_message::Reaction,
        sync_message, AttachmentPointer, CallMessage, DataMessage,
        DecryptionErrorMessage, EditMessage, GroupContextV2, NullMessage,
        ReceiptMessage, StoryMessage, SyncMessage, TypingMessage,
    },
    push_service::ServiceError,
    ServiceIdExt,
};

mod data_message;
mod story_message;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub sender: ServiceId,
    pub destination: ServiceId,
    pub sender_device: DeviceId,
    /// Contains the PNI of the sender if verification was succesfull
    pub pni_verified: Option<Pni>,

    /// When the sender says it sent the message, in milliseconds since the
    /// epoch: its word as the envelope carries it, so any `u64`.
    /// Signal-Server takes up to 8.64e15, more than a calendar type may hold.
    pub client_timestamp: u64,
    /// When the server says it took the message, the same way.
    pub server_timestamp: u64,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,
    pub was_plaintext: bool,

    /// A unique UUID for this specific message, produced by the Signal servers.
    ///
    /// The server GUID is used to report spam messages.
    pub server_guid: Option<Uuid>,
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Metadata {{ sender: {}, guid: {}, server timestamp: {} }}",
            self.sender.service_id_string(),
            // XXX: should this still be optional?
            self.server_guid
                .map(|u| u.to_string())
                .as_deref()
                .unwrap_or("None"),
            self.server_timestamp,
        )
    }
}

impl Metadata {
    pub(crate) fn protocol_address(
        &self,
    ) -> Result<ProtocolAddress, libsignal_core::InvalidDeviceId> {
        self.sender.to_protocol_address(self.sender_device)
    }
}

#[derive(Clone, Debug)]
pub struct Content {
    pub metadata: Metadata,
    pub body: ContentBody,
}

/// An envelope [`ServiceCipher::open_envelope`](crate::cipher::ServiceCipher::open_envelope)
/// decrypted.
#[derive(Clone, derive_more::Debug)]
pub struct DecryptedEnvelope {
    pub metadata: Metadata,
    /// The content `plaintext` holds; `None` when it holds none of a kind
    /// this crate knows: side-cars alone, or a kind newer than its protos.
    pub body: Option<ContentBody>,
    /// The `Content` as its sender serialized it, unpadded: its side-cars and
    /// the fields this crate's protos don't know included.
    #[debug("{} bytes", plaintext.len())]
    pub plaintext: Bytes,
}

impl Content {
    pub fn from_body(body: impl Into<ContentBody>, metadata: Metadata) -> Self {
        Self {
            metadata,
            body: body.into(),
        }
    }

    /// Converts a proto::Content into a public Content, including metadata.
    pub fn from_proto(
        p: crate::proto::Content,
        metadata: Metadata,
    ) -> Result<Self, ServiceError> {
        let content = p.content.ok_or(ServiceError::UnsupportedContent)?;
        Ok(Self {
            metadata,
            body: content.try_into()?,
        })
    }
}

impl TryFrom<crate::proto::content::Content> for ContentBody {
    type Error = prost::DecodeError;

    /// A decryption error is the one kind whose body is decoded here, so the
    /// only one that can fail.
    fn try_from(
        content: crate::proto::content::Content,
    ) -> Result<Self, Self::Error> {
        use crate::proto::content::Content;
        Ok(match content {
            Content::DataMessage(msg) => Self::DataMessage(msg),
            Content::SyncMessage(msg) => Self::SynchronizeMessage(msg),
            Content::CallMessage(msg) => Self::CallMessage(msg),
            Content::NullMessage(msg) => Self::NullMessage(msg),
            Content::ReceiptMessage(msg) => Self::ReceiptMessage(msg),
            Content::TypingMessage(msg) => Self::TypingMessage(msg),
            Content::DecryptionErrorMessage(msg) => {
                Self::DecryptionErrorMessage(DecryptionErrorMessage::decode(
                    msg.as_ref(),
                )?)
            },
            Content::StoryMessage(msg) => Self::StoryMessage(msg),
            Content::EditMessage(msg) => Self::EditMessage(msg),
        })
    }
}

impl fmt::Display for ContentBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullMessage(_) => write!(f, "NullMessage"),
            Self::DataMessage(m) => {
                match (&m.body, &m.reaction, m.attachments.len()) {
                    (Some(body), _, 0) => {
                        write!(f, "DataMessage({})", body)
                    },
                    (Some(body), _, n) => {
                        write!(f, "DataMessage({}, attachments: {n})", body)
                    },
                    (None, Some(emoji), _) => {
                        write!(
                            f,
                            "DataMessage(reaction: {})",
                            emoji.emoji.as_deref().unwrap_or("None")
                        )
                    },
                    (None, _, n) if n > 0 => {
                        write!(f, "DataMessage(attachments: {n})")
                    },
                    _ => {
                        write!(f, "{self:?}")
                    },
                }
            },
            Self::SynchronizeMessage(_) => write!(f, "SynchronizeMessage"),
            Self::CallMessage(_) => write!(f, "CallMessage"),
            Self::ReceiptMessage(_) => write!(f, "ReceiptMessage"),
            Self::TypingMessage(_) => write!(f, "TypingMessage"),
            // Self::SenderKeyDistributionMessage(_) => write!(f, "SenderKeyDistributionMessage"),
            Self::DecryptionErrorMessage(_) => {
                write!(f, "DecryptionErrorMessage")
            },
            Self::StoryMessage(_) => write!(f, "StoryMessage"),
            Self::EditMessage(_) => write!(f, "EditMessage"),
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ContentBody {
    NullMessage(NullMessage),
    DataMessage(DataMessage),
    SynchronizeMessage(SyncMessage),
    CallMessage(CallMessage),
    ReceiptMessage(ReceiptMessage),
    TypingMessage(TypingMessage),
    // SenderKeyDistributionMessage(SenderKeyDistributionMessage),
    DecryptionErrorMessage(DecryptionErrorMessage),
    StoryMessage(StoryMessage),
    EditMessage(EditMessage),
}

impl NullMessage {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        // Random length between 1 and 140 bytes
        let padding_length = (rng.next_u64() % 140) as usize + 1;
        let mut padding = vec![0; padding_length];
        rng.fill(padding.as_mut_slice());
        NullMessage {
            padding: Some(padding),
        }
    }
}

impl ContentBody {
    pub fn into_proto(self) -> crate::proto::Content {
        use crate::proto::content::Content;

        let inner = match self {
            Self::NullMessage(msg) => Content::NullMessage(msg),
            Self::DataMessage(msg) => Content::DataMessage(msg),
            Self::SynchronizeMessage(msg) => Content::SyncMessage(msg),
            Self::CallMessage(msg) => Content::CallMessage(msg),
            Self::ReceiptMessage(msg) => Content::ReceiptMessage(msg),
            Self::TypingMessage(msg) => Content::TypingMessage(msg),
            Self::DecryptionErrorMessage(msg) => {
                Content::DecryptionErrorMessage(msg.encode_to_vec())
            },
            Self::StoryMessage(msg) => Content::StoryMessage(msg),
            Self::EditMessage(msg) => Content::EditMessage(msg),
        };
        crate::proto::Content {
            content: Some(inner),
            // TODO: handle SKDM; ideally this is also "tacked on" when needed,
            // and not handled as a separate message.
            sender_key_distribution_message: None,
            // PNI signature gets added down the message sender stream
            pni_signature_message: None,
        }
    }
}

macro_rules! impl_from_for_content_body {
    ($enum:ident ($t:ty)) => {
        impl From<$t> for ContentBody {
            fn from(inner: $t) -> ContentBody {
                ContentBody::$enum(inner)
            }
        }
    };
}

impl_from_for_content_body!(NullMessage(NullMessage));
impl_from_for_content_body!(DataMessage(DataMessage));
impl_from_for_content_body!(SynchronizeMessage(SyncMessage));
impl_from_for_content_body!(CallMessage(CallMessage));
impl_from_for_content_body!(ReceiptMessage(ReceiptMessage));
impl_from_for_content_body!(TypingMessage(TypingMessage));
// impl_from_for_content_body!(SenderKeyDistributionMessage(
//     SenderKeyDistributionMessage
// ));
// impl_from_for_content_body!(DecryptionErrorMessage(DecryptionErrorMessage));
impl_from_for_content_body!(StoryMessage(StoryMessage));
impl_from_for_content_body!(EditMessage(EditMessage));

macro_rules! impl_from_for_sync_message {
    ($t:ident) => {
        impl From<$crate::proto::sync_message::$t> for SyncMessage {
            fn from(inner: sync_message::$t) -> SyncMessage {
                SyncMessage {
                    content: Some($crate::proto::sync_message::Content::$t(
                        inner,
                    )),
                    ..SyncMessage::with_padding(&mut rand::rng())
                }
            }
        }
    };
}

impl_from_for_sync_message!(Sent);
impl_from_for_sync_message!(Contacts);
impl_from_for_sync_message!(Request);
impl_from_for_sync_message!(Blocked);
// impl_from_for_sync_message!(Verified); // maps on crate::proto::Verified instead?
impl_from_for_sync_message!(Configuration);
impl_from_for_sync_message!(ViewOnceOpen);
impl_from_for_sync_message!(FetchLatest);
impl_from_for_sync_message!(Keys);
impl_from_for_sync_message!(MessageRequestResponse);
impl_from_for_sync_message!(OutgoingPayment);
impl_from_for_sync_message!(PniChangeNumber);
impl_from_for_sync_message!(CallEvent);
impl_from_for_sync_message!(CallLinkUpdate);
impl_from_for_sync_message!(CallLogEvent);
impl_from_for_sync_message!(DeleteForMe);
impl_from_for_sync_message!(DeviceNameChange);
impl_from_for_sync_message!(AttachmentBackfillRequest);
impl_from_for_sync_message!(AttachmentBackfillResponse);
impl_from_for_sync_message!(UsernameChange);
