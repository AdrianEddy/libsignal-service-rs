use std::{convert::TryFrom, fmt, rc::Rc};

use aes::cipher::block_padding::{Iso7816, Padding};
use base64::prelude::*;
use bytes::Bytes;
use libsignal_core::ServiceIdKind;
use libsignal_protocol::{
    group_decrypt, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
    CiphertextMessageType, DeviceId, IdentityKeyStore, KyberPreKeyStore,
    PlaintextContent, Pni, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    ProtocolStore, PublicKey, SealedSenderDecryptionResult, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyStore, ServiceId, SessionNotFound,
    SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyStore,
    Timestamp, UnidentifiedSenderMessageContent,
};
use prost::Message;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

use crate::{
    content::{ContentBody, DecryptedEnvelope, Metadata},
    envelope::Envelope,
    proto::PniSignatureMessage,
    push_service::{ServiceError, DEFAULT_DEVICE_ID},
    sender::OutgoingPushMessage,
    session_store::{has_usable_session, SessionStoreExt},
    transport::Clock,
    utils::BASE64_RELAXED,
    ServiceIdExt,
};

/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
#[derive(Clone)]
pub struct ServiceCipher<S> {
    protocol_store: S,
    trust_roots: Vec<PublicKey>,
    local_service: ServiceId,
    /// Our device's address under `local_service`.
    local_address: ProtocolAddress,
    pub(crate) clock: Rc<dyn Clock>,
}

impl<S> fmt::Debug for ServiceCipher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCipher")
            .field("protocol_store", &"...")
            .field("trust_root", &"...")
            .field("local_address", &self.local_address)
            .finish()
    }
}

fn debug_envelope(envelope: &Envelope) -> String {
    if envelope.content.is_none() {
        "Envelope { empty }".to_string()
    } else {
        format!(
            "Envelope {{ \
                 source_address: {:?}, \
                 source_device: {:?}, \
                 server_guid: {:?}, \
                 client_timestamp: {:?}, \
                 content: {} bytes, \
             }}",
            envelope.parse_source_service_id(),
            envelope.source_device_id(),
            envelope.server_guid(),
            envelope.client_timestamp(),
            envelope.content().len(),
        )
    }
}

/// An unsealed envelope is decrypted from its sender's session, so one without
/// a source to read it from can't be opened. Signal-Server queues one for
/// anyone holding the recipient's access key (its sealed path checks only the
/// key and the type's number), and Signal-Desktop drops it.
fn missing_source() -> ServiceError {
    ServiceError::InvalidFrame {
        reason: "an identified envelope without a valid source service id",
    }
}

impl<S> ServiceCipher<S>
where
    S: ProtocolStore + SenderKeyStore + SessionStoreExt + Clone,
{
    /// The cipher of our device `local_device` under the identity
    /// `local_service`, our ACI or PNI, whose store `protocol_store` is.
    ///
    /// Encryption, and the session checks before it, read the time from
    /// `clock`.
    pub fn new(
        protocol_store: S,
        trust_roots: Vec<PublicKey>,
        local_service: ServiceId,
        local_device: DeviceId,
        clock: Rc<dyn Clock>,
    ) -> Self {
        Self {
            protocol_store,
            trust_roots,
            local_service,
            local_address: ServiceId::to_protocol_address(
                &local_service,
                local_device,
            ),
            clock,
        }
    }

    /// Opens ("decrypts") an envelope: its sender, the plaintext and the
    /// content decoded from it.
    ///
    /// `Ok(None)` for an envelope without content, and for content that isn't
    /// passed on: a plaintext, sealed or not, that holds anything but a
    /// decryption error alone, a decryption error that doesn't decode, or a
    /// sync message that doesn't come from our own ACI.
    ///
    /// The plaintext is the `Content` as its sender serialized it, unpadded,
    /// side-cars and the fields this crate's protos don't know included, so a
    /// caller that keeps it loses nothing. Its `body` is `None` when it holds
    /// no content of a kind this crate knows: side-cars alone, or a kind newer
    /// than its protos.
    ///
    /// # Side-cars
    ///
    /// A sender key distribution is applied to the store before the content
    /// is passed on. One that doesn't parse is skipped with a warning, and
    /// the content beside it is still passed on.
    ///
    /// A PNI signature is verified during decryption and, when valid, its
    /// PNI is exposed as `Metadata::pni_verified`, on a message without a
    /// `body` too.
    ///
    /// A plaintext's side-cars are never taken: no session authenticates
    /// them.
    ///
    /// **NOTE**: must process `Metadata::pni_verified` to confirm the sender's
    /// PNI, not the raw side-car message.
    #[tracing::instrument(
        skip(envelope, csprng),
        fields(envelope = debug_envelope(envelope), envelope_metadata)
    )]
    pub async fn open_envelope<R: Rng + CryptoRng>(
        &mut self,
        envelope: &Envelope,
        csprng: &mut R,
    ) -> Result<Option<DecryptedEnvelope>, ServiceError> {
        if envelope.content.is_none() {
            return Ok(None);
        }

        let Plaintext {
            metadata,
            message,
            bytes: plaintext,
        } = self.decrypt(envelope, csprng).await?;

        tracing::Span::current()
            .record("envelope_metadata", tracing::field::display(&metadata));

        // A plaintext, sealed or not, is authenticated by no session, only by
        // the server's word (an unsealed one's source, a sealed one's sender
        // certificate), so it may carry a decryption error alone, and no
        // side-car (Signal-Android's `EnvelopeContentValidator`). This runs
        // before the side-cars are applied, so a plaintext's never are.
        if metadata.was_plaintext {
            let crate::proto::Content {
                content:
                    Some(crate::proto::content::Content::DecryptionErrorMessage(
                        dme,
                    )),
                sender_key_distribution_message: None,
                pni_signature_message: None,
            } = &message
            else {
                tracing::error!(
                    ?envelope,
                    "Received a plaintext envelope that isn't a decryption error alone."
                );
                return Ok(None);
            };
            tracing::warn!(
                ?envelope,
                len = dme.len(),
                "Received a decryption error message."
            );
        }

        // Ingest side-car messages *before* processing content (which possibly triggers an early `return Ok(None)`)

        // A sender key distribution that doesn't parse costs only itself, as
        // Signal-Desktop has it, not the content the decrypt has already
        // moved the session on for. Once it parsed, applying it fails only in
        // the store, and that fails the envelope.
        let skdm = message
            .sender_key_distribution_message
            .as_deref()
            .and_then(|bytes| {
                SenderKeyDistributionMessage::try_from(bytes)
                    .inspect_err(|error| {
                        tracing::warn!(
                            %error,
                            "ignoring a sender key distribution message that doesn't parse"
                        )
                    })
                    .ok()
            });
        if let Some(skdm) = skdm {
            let sender = metadata.protocol_address()?;
            process_sender_key_distribution_message(
                &sender,
                &skdm,
                &mut self.protocol_store,
            )
            .await?;
            tracing::info!(
                distribution_id = %skdm.distribution_id()?,
                sender = %sender,
                "applied sender key distribution message"
            );
        }

        // Now, process actual content, *after* side-car messages such as SKDM or PNI
        // signatures.

        // Filter out SyncMessages that don't come from our own ACI.
        if matches!(
            message.content,
            Some(crate::proto::content::Content::SyncMessage(_))
        ) && (metadata.sender.aci() != self.local_service.aci()
            || self.local_service.kind() == ServiceIdKind::Pni)
        {
            tracing::warn!("Source is not ourself.");
            return Ok(None);
        }

        // A decryption error is the one kind whose body is decoded here, so
        // the only one that can fail: it is dropped, as both official clients
        // drop it, where failing the envelope would read as one that didn't
        // decrypt.
        let body = match message.content.map(ContentBody::try_from).transpose()
        {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "dropping a decryption error message that doesn't decode"
                );
                return Ok(None);
            },
        };
        if body.is_none() {
            tracing::debug!("decrypted content of no kind this crate knows");
        }
        Ok(Some(DecryptedEnvelope {
            metadata,
            body,
            plaintext,
        }))
    }

    /// Verify a `PniSignatureMessage` sidecar against the sender's stored identity keys.
    async fn verify_pni_signature(
        &self,
        sender: ServiceId,
        sender_device: DeviceId,
        pni_signature: &PniSignatureMessage,
    ) -> Option<Pni> {
        let Some(sender_aci) = sender.aci() else {
            tracing::warn!("ignoring PNI signature: source is not an ACI");
            return None;
        };

        let Some(pni) =
            Pni::parse_from_service_id_binary(pni_signature.pni.as_deref()?)
        else {
            tracing::warn!("ignoring PNI signature: unparseable PNI");
            return None;
        };
        let signature = pni_signature.signature.as_deref()?;

        let aci_address = sender_aci.to_protocol_address(sender_device).ok()?;
        let aci_identity = self
            .protocol_store
            .get_identity(&aci_address)
            .await
            .ok()
            .flatten()?;

        let pni_address = pni.to_protocol_address(sender_device).ok()?;
        let pni_identity =
            match self.protocol_store.get_identity(&pni_address).await {
                Ok(Some(id)) => id,
                _ => {
                    if sender_device == *DEFAULT_DEVICE_ID {
                        tracing::warn!(
                            "ignoring PNI signature: no PNI identity known"
                        );
                        return None;
                    }
                    // The PNI identity is recorded under the primary device.
                    let primary =
                        pni.to_protocol_address(*DEFAULT_DEVICE_ID).ok()?;
                    match self.protocol_store.get_identity(&primary).await {
                        Ok(Some(id)) => id,
                        _ => {
                            tracing::warn!(
                                "ignoring PNI signature: no PNI identity known"
                            );
                            return None;
                        },
                    }
                },
            };

        let verified = pni_identity
            .verify_alternate_identity(&aci_identity, signature)
            .inspect_err(|e| {
                tracing::warn!(?e, "PNI signature verification error");
            })
            .ok()?;

        if verified {
            tracing::info!(
                aci = %sender_aci.service_id_string(),
                pni = %pni.service_id_string(),
                "verified PNI signature"
            );
            Some(pni)
        } else {
            tracing::warn!(
                aci = %sender_aci.service_id_string(),
                pni = %pni.service_id_string(),
                "invalid PNI signature"
            );
            None
        }
    }

    /// Equivalent of decrypt(Envelope, ciphertext)
    ///
    /// Triage of legacy messages happens inside this method, as opposed to the
    /// Java implementation, because it makes the borrow checker and the
    /// author happier.
    #[tracing::instrument(skip(envelope, csprng), fields(envelope = debug_envelope(envelope)))]
    async fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        envelope: &Envelope,
        csprng: &mut R,
    ) -> Result<Plaintext, ServiceError> {
        let ciphertext = if let Some(msg) = envelope.content.as_ref() {
            msg
        } else {
            return Err(ServiceError::InvalidFrame {
                reason:
                    "envelope should have either a legacy message or content.",
            });
        };

        let server_guid = envelope.parse_server_guid();

        let Some(destination_service_id) =
            envelope.parse_destination_service_id()
        else {
            tracing::warn!(
                "missing destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "missing destination service id",
            });
        };

        if destination_service_id != self.local_service {
            tracing::warn!(
                "mismatching destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "mismatch destination service id",
            });
        }

        let source_service_id = envelope.parse_source_service_id();

        if destination_service_id.kind() == ServiceIdKind::Pni
            && source_service_id.is_none()
        {
            tracing::warn!("received sealed sender message to our PNI; ignoring invalid message");
            return Err(ServiceError::InvalidFrame {
                reason: "sealed sender received on our PNI",
            });
        }

        // TODO: let chain in edition 2024
        if let Some(source_service_id) = source_service_id {
            if source_service_id.kind() == ServiceIdKind::Pni
                && envelope.r#type() != Type::ServerDeliveryReceipt
            {
                tracing::warn!("got a message from a PNI that was not a ServerDeliveryReceipt; ignoring invalid message");
                return Err(ServiceError::InvalidFrame {
                    reason: "PNI received a non-ServerDeliveryReceipt",
                });
            }
        }

        // Extract both kinds of timestamps.
        // Note that we do not `?` here, but rather only later, in case we ever have a branch which
        // is not concerned with envelope metadata.
        let client_timestamp = chrono::DateTime::from_timestamp_millis(
            envelope.client_timestamp() as i64,
        )
        .ok_or(ServiceError::InvalidFrame {
            reason: "unparseable timestamp",
        });
        let server_timestamp = chrono::DateTime::from_timestamp_millis(
            envelope.server_timestamp() as i64,
        )
        .ok_or(ServiceError::InvalidFrame {
            reason: "unparseable server timestamp",
        });

        /// Decrypted bytes plus the [`Metadata`] fields that vary by envelope type.
        struct DecryptedPayload {
            data: Vec<u8>,
            sender: ServiceId,
            sender_device: DeviceId,
            was_plaintext: bool,
            unidentified_sender: bool,
            needs_receipt: bool,
        }

        use crate::proto::envelope::Type;
        let parts = match envelope.r#type() {
            Type::PrekeyMessage => {
                let source_service_id =
                    source_service_id.ok_or_else(missing_source)?;
                let sender_device = envelope.source_device_id().try_into()?;
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &source_service_id,
                    sender_device,
                )
                .await?;

                let mut data = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &self.local_address,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    csprng,
                )
                .await?
                .plaintext;

                strip_padding(&mut data)?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device,
                    was_plaintext: false,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::PlaintextContent => {
                tracing::warn!(?envelope, "Envelope with plaintext content.  This usually indicates a decryption retry.");
                let source_service_id =
                    source_service_id.ok_or_else(missing_source)?;
                // Unsealed envelope wrapping a PlaintextContent.
                // Should contain a DecryptionErrorMessage.
                let plaintext_content =
                    PlaintextContent::try_from(&ciphertext[..])?;
                let mut data = plaintext_content.body().to_vec();
                strip_padding(&mut data)?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device: envelope.source_device_id().try_into()?,
                    was_plaintext: true,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::DoubleRatchet => {
                let source_service_id =
                    source_service_id.ok_or_else(missing_source)?;
                let sender_device = envelope.source_device_id().try_into()?;
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &source_service_id,
                    sender_device,
                )
                .await?;

                let mut data = message_decrypt_signal(
                    &SignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &self.local_address,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    csprng,
                )
                .await?;

                strip_padding(&mut data)?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device,
                    was_plaintext: false,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::UnidentifiedSender => {
                let (
                    SealedSenderDecryptionResult {
                        sender_uuid,
                        sender_e164: _,
                        device_id,
                        mut message,
                    },
                    message_type,
                ) = sealed_sender_decrypt(
                    ciphertext,
                    &self.trust_roots,
                    // When the server took the message, as Desktop and
                    // Android check it: the sender chooses the client
                    // timestamp, so a back-dated one would pass an expired
                    // certificate, and a fast clock would fail a valid one.
                    Timestamp::from_epoch_millis(envelope.server_timestamp()),
                    None,
                    self.local_service,
                    &self.local_address,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store,
                    csprng,
                )
                .await?;

                let Some(sender) =
                    ServiceId::parse_from_service_id_string(&sender_uuid)
                else {
                    return Err(
                        SignalProtocolError::InvalidSealedSenderMessage(
                            "invalid sender UUID".to_string(),
                        )
                        .into(),
                    );
                };

                let needs_receipt = if source_service_id.is_some() {
                    tracing::warn!(?envelope, "Received an unidentified delivery over an identified channel.  Marking needs_receipt=false");
                    false
                } else {
                    true
                };

                if sender.kind() == ServiceIdKind::Pni {
                    tracing::warn!(
                        "sealed sender used for PNI; ignoring invalid message"
                    );
                    return Err(ServiceError::InvalidFrame {
                        reason: "sealed sender used for PNI",
                    });
                }

                strip_padding(&mut message)?;

                DecryptedPayload {
                    data: message,
                    sender,
                    sender_device: device_id,
                    // A sealed `PlaintextContent` is no more authenticated
                    // than an unsealed one: no session encrypts it, and its
                    // certificate is the server's word. Signal-Desktop reads
                    // it as not encrypted, Signal-Android by its inner type.
                    was_plaintext: message_type
                        == CiphertextMessageType::Plaintext,
                    unidentified_sender: true,
                    needs_receipt,
                }
            },
            _ => {
                // else
                return Err(ServiceError::InvalidFrame {
                    reason: "envelope has unknown type",
                });
            },
        };

        let message = crate::proto::Content::decode(parts.data.as_slice())?;
        // A plaintext's side-car is never taken (`open_envelope`), so it
        // isn't verified either.
        let pni_verified = match &message.pni_signature_message {
            Some(msg) if !parts.was_plaintext => {
                self.verify_pni_signature(
                    parts.sender,
                    parts.sender_device,
                    msg,
                )
                .await
            },
            _ => None,
        };
        let metadata = Metadata {
            destination: destination_service_id,
            sender: parts.sender,
            sender_device: parts.sender_device,
            client_timestamp: client_timestamp?,
            server_timestamp: server_timestamp?,
            needs_receipt: parts.needs_receipt,
            unidentified_sender: parts.unidentified_sender,
            was_plaintext: parts.was_plaintext,
            server_guid,
            pni_verified,
        };
        Ok(Plaintext {
            metadata,
            message,
            bytes: Bytes::from(parts.data),
        })
    }

    /// Encrypts `content` (a serialized `Content`, which this pads) for one
    /// device, through the store's session with `address`, and stores the
    /// session the encryption moved on. With `unidentified_access`, the
    /// sender certificate, the message is sealed (sealed sender).
    ///
    /// A device without a session that passes [`has_usable_session`] at the
    /// clock's time fails with [`SignalProtocolError::SessionNotFound`]: build
    /// one from the device's prekey bundle first.
    #[tracing::instrument(
        skip(address, unidentified_access, content, csprng),
        fields(
            address = %address,
            with_unidentified_access = unidentified_access.is_some(),
            content_length = content.len(),
        )
    )]
    pub async fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        address: &ProtocolAddress,
        unidentified_access: Option<&SenderCertificate>,
        content: &[u8],
        csprng: &mut R,
    ) -> Result<OutgoingPushMessage, ServiceError> {
        let now = self.clock.now();

        let session_record = self
            .protocol_store
            .load_session(address)
            .await?
            .filter(|record| has_usable_session(record, now))
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::new(
                    address.clone(),
                    "encrypt",
                ))
            })?;

        let padded_content =
            add_padding(session_record.session_version()?, content)?;

        if let Some(unindentified_access) = unidentified_access {
            let destination_registration_id =
                session_record.remote_registration_id()?;

            let message = sealed_sender_encrypt(
                address,
                unindentified_access,
                &padded_content,
                &mut self.protocol_store.clone(),
                &mut self.protocol_store,
                now,
                csprng,
            )
            .await?;

            use crate::proto::envelope::Type;
            Ok(OutgoingPushMessage {
                r#type: Type::UnidentifiedSender as u32,
                destination_device_id: address.device_id(),
                destination_registration_id,
                content: BASE64_RELAXED.encode(message),
            })
        } else {
            let message = message_encrypt(
                &padded_content,
                address,
                &self.local_address,
                &mut self.protocol_store.clone(),
                &mut self.protocol_store.clone(),
                now,
                csprng,
            )
            .await?;

            let destination_registration_id =
                session_record.remote_registration_id()?;

            let body = BASE64_RELAXED.encode(message.serialize());

            use crate::proto::envelope::Type;
            let message_type = match message.message_type() {
                CiphertextMessageType::PreKey => Type::PrekeyMessage,
                CiphertextMessageType::Whisper => Type::DoubleRatchet,
                t => panic!("Bad type: {:?}", t),
            } as u32;
            Ok(OutgoingPushMessage {
                r#type: message_type,
                destination_device_id: address.device_id(),
                destination_registration_id,
                content: body,
            })
        }
    }
}

struct Plaintext {
    metadata: Metadata,
    message: crate::proto::Content,
    /// The unpadded plaintext `message` was decoded from.
    bytes: Bytes,
}

/// The official clients' padding block (Signal-Android's
/// `PushTransportDetails`, Signal-Desktop's `padMessage`).
const PADDING_BLOCK_SIZE: usize = 80;

/// Pads `contents` as the official clients do: a 0x80 terminator, then zeros
/// to one byte short of a whole number of blocks, so the cipher's own padding
/// adds a single byte rather than a block.
#[expect(clippy::comparison_chain)]
fn add_padding(version: u32, contents: &[u8]) -> Result<Vec<u8>, ServiceError> {
    if version < 2 {
        Err(ServiceError::PaddingVersion(version))
    } else if version == 2 {
        Ok(contents.to_vec())
    } else {
        let message_length = contents.len();
        let padded_length = (message_length + 2).div_ceil(PADDING_BLOCK_SIZE)
            * PADDING_BLOCK_SIZE
            - 1;

        let mut buffer = vec![0u8; padded_length];
        buffer[..message_length].copy_from_slice(contents);
        Iso7816::raw_pad(&mut buffer, message_length);
        Ok(buffer)
    }
}

fn strip_padding(contents: &mut Vec<u8>) -> Result<(), ServiceError> {
    let new_length = Iso7816::raw_unpad(contents)?.len();
    contents.resize(new_length, 0);
    Ok(())
}

/// Equivalent of `SignalServiceCipher::getPreferredProtocolAddress`
pub async fn get_preferred_protocol_address<S: SessionStore>(
    session_store: &S,
    address: &ServiceId,
    device_id: DeviceId,
) -> Result<ProtocolAddress, libsignal_protocol::error::SignalProtocolError> {
    let address = address.to_protocol_address(device_id);
    if session_store.load_session(&address).await?.is_some() {
        return Ok(address);
    }

    Ok(address)
}

/// Error thrown when the sealed sending decryption fails.
///
/// The USMC sender field is only populated when the USMC could be validated against the trust roots;
/// hence the sender information can be trusted, give or take an active attacker on the Signal
/// side.
#[derive(thiserror::Error)]
#[error("error: {inner}, usmc: {}", sender.is_some())]
pub struct SealedSenderDecryptionError {
    pub inner: SignalProtocolError,
    pub sender: Option<ProtocolAddress>,
}

impl fmt::Debug for SealedSenderDecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSenderDecryptionError")
            .field("inner", &self.inner)
            .field("sender", &self.sender)
            .finish()
    }
}

impl From<SignalProtocolError> for SealedSenderDecryptionError {
    fn from(e: SignalProtocolError) -> Self {
        SealedSenderDecryptionError {
            inner: e,
            sender: None,
        }
    }
}

/// Decrypt a Sealed Sender message `ciphertext` in either the v1 or v2 format, validate its sender
/// certificate, and then decrypt the inner message payload.
///
/// This method calls [`sealed_sender_decrypt_to_usmc`] to extract the sender information, including
/// the embedded [`SenderCertificate`]. The sender certificate (signed by the [`ServerCertificate`])
/// is then validated against the `trust_root` baked into the client to ensure that the sender's
/// identity was not forged.
///
/// The inner message's type comes back with it: a `Plaintext` one is a `PlaintextContent`'s
/// body, which no session authenticates.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip(
        ciphertext,
        trust_roots,
        local_service,
        identity_store,
        session_store,
        pre_key_store,
        signed_pre_key_store,
        sender_key_store,
        kyber_pre_key_store,
        csprng
    ),
    fields(
        ciphertext = ciphertext.len(),
    )
)]
async fn sealed_sender_decrypt<R: Rng + CryptoRng>(
    ciphertext: &[u8],
    trust_roots: &[PublicKey],
    timestamp: Timestamp,
    local_e164: Option<String>,
    local_service: ServiceId,
    local_address: &ProtocolAddress,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
) -> Result<
    (SealedSenderDecryptionResult, CiphertextMessageType),
    SealedSenderDecryptionError,
> {
    let usmc =
        sealed_sender_decrypt_to_usmc(ciphertext, identity_store).await?;

    if !usmc
        .sender()?
        .validate_with_trust_roots(trust_roots, timestamp)?
    {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "trust root validation failed".to_string(),
        )
        .into());
    }

    let sender_uuid: Uuid =
        usmc.sender()?.sender_uuid()?.parse().map_err(|_| {
            SignalProtocolError::InvalidSealedSenderMessage(
                "invalid sender UUID".to_string(),
            )
        })?;
    let is_local_uuid = local_service.raw_uuid() == sender_uuid;

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid)
        && usmc.sender()?.sender_device_id()? == local_address.device_id()
    {
        return Err(SignalProtocolError::SealedSenderSelfSend.into());
    }

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );
    let message_type = usmc.msg_type()?;

    sealed_sender_decrypt_with_validated_usmc(
        &usmc,
        &remote_address,
        local_address,
        identity_store,
        session_store,
        pre_key_store,
        signed_pre_key_store,
        sender_key_store,
        kyber_pre_key_store,
        csprng,
    )
    .await
    .map(|result| (result, message_type))
    .map_err(|inner| SealedSenderDecryptionError {
        inner,
        sender: Some(remote_address),
    })
}

#[allow(clippy::too_many_arguments)]
async fn sealed_sender_decrypt_with_validated_usmc<R: Rng + CryptoRng>(
    usmc: &UnidentifiedSenderMessageContent,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
) -> Result<SealedSenderDecryptionResult, SignalProtocolError> {
    let message = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            message_decrypt_signal(
                &ctext,
                remote_address,
                local_address,
                session_store,
                identity_store,
                csprng,
            )
            .await?
        },
        CiphertextMessageType::PreKey => {
            let ctext = PreKeySignalMessage::try_from(usmc.contents()?)?;
            message_decrypt_prekey(
                &ctext,
                remote_address,
                local_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                kyber_pre_key_store,
                csprng,
            )
            .await?
            .plaintext
        },
        CiphertextMessageType::SenderKey => {
            group_decrypt(usmc.contents()?, sender_key_store, remote_address)
                .await?
        },
        CiphertextMessageType::Plaintext => {
            // Sealed sender envelope wrapping a PlaintextContent.
            // Should contain a DecryptionErrorMessage.
            let plaintext_content =
                PlaintextContent::try_from(usmc.contents()?)?;
            plaintext_content.body().to_vec()
        },
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}

#[cfg(test)]
mod tests;
