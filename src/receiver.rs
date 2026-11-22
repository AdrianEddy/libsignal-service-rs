use std::{future::Future, rc::Rc};

use aes::cipher::block_padding;
use bytes::{Buf, Bytes};

use crate::{
    attachment_cipher::{decrypt_in_place, AttachmentCipherError},
    configuration::ServiceCredentials,
    messagepipe::MessagePipe,
    models::{Contact, ParseContactError},
    push_service::*,
    transport::Clock,
    websocket::SocketEnd,
};

/// Equivalent of Java's `SignalServiceMessageReceiver`.
#[derive(Clone)]
pub struct MessageReceiver {
    service: PushService,
}

impl MessageReceiver {
    // TODO: to avoid providing the wrong service/wrong credentials
    // change it like LinkingManager or ProvisioningManager
    pub fn new(service: PushService) -> Self {
        MessageReceiver { service }
    }

    /// Opens the account's WebSocket and its message pipe. The caller runs
    /// the socket's task (see [`SignalWebSocket::new`]).
    ///
    /// [`SignalWebSocket::new`]: crate::websocket::SignalWebSocket::new
    pub async fn create_message_pipe(
        &self,
        credentials: ServiceCredentials,
        allow_stories: bool,
        clock: Rc<dyn Clock>,
    ) -> Result<
        (
            MessagePipe,
            impl Future<Output = Result<SocketEnd, ServiceError>> + 'static,
        ),
        ServiceError,
    > {
        let headers = &[(
            "X-Signal-Receive-Stories",
            if allow_stories { "true" } else { "false" },
        )];
        let (ws, task) = self
            .service
            .ws(
                "/v1/websocket/",
                "/v1/keepalive",
                headers,
                Some(credentials),
                clock,
            )
            .await?;
        Ok((MessagePipe::from_socket(ws), task))
    }

    /// Downloads and decrypts the contacts blob of a primary device's
    /// `SyncMessage.Contacts`, and iterates over its contacts.
    ///
    /// A blob whose key isn't 64 bytes, whose download fails, or that doesn't
    /// decrypt is an error. The iterator yields a contact that doesn't parse
    /// as an error and goes on; an entry that breaks the blob's framing ends
    /// it after its error, since nothing after it can be found.
    pub async fn retrieve_contacts(
        &mut self,
        contacts: &crate::proto::sync_message::Contacts,
    ) -> Result<
        impl Iterator<Item = Result<Contact, ParseContactError>>,
        ServiceError,
    > {
        if let Some(ref blob) = contacts.blob {
            use futures::io::AsyncReadExt;

            let key: [u8; 64] = blob.key().try_into().map_err(|_| {
                ServiceError::InvalidFrame {
                    reason: "an attachment key that isn't 64 bytes",
                }
            })?;

            const MAX_DOWNLOAD_RETRIES: u8 = 3;
            let mut retries = 0;

            let mut stream = loop {
                let r = self.service.get_attachment(blob).await;
                match r {
                    Ok(download) => break download.stream,
                    Err(ServiceError::Timeout { .. }) => {
                        tracing::warn!("get_attachment timed out, retrying");
                        retries += 1;
                        if retries >= MAX_DOWNLOAD_RETRIES {
                            return Err(ServiceError::Timeout {
                                reason: "too many retries",
                            });
                        }
                    },
                    Err(e) => return Err(e),
                }
            };

            let mut ciphertext = Vec::new();
            stream.read_to_end(&mut ciphertext).await?;

            decrypt_in_place(key, &mut ciphertext).map_err(|e| match e {
                AttachmentCipherError::MacError => ServiceError::MacError,
                AttachmentCipherError::PaddingError => {
                    ServiceError::Padding(block_padding::Error)
                },
            })?;

            Ok(DeviceContactsIterator::new(Bytes::from(ciphertext)))
        } else {
            Ok(DeviceContactsIterator::default())
        }
    }
}

#[derive(Default)]
struct DeviceContactsIterator {
    decrypted_buffer: Bytes,
}

impl DeviceContactsIterator {
    fn new(decrypted_buffer: Bytes) -> Self {
        Self { decrypted_buffer }
    }
}

impl Iterator for DeviceContactsIterator {
    type Item = Result<Contact, ParseContactError>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::proto::{contact_details::Avatar, ContactDetails};

        if !self.decrypted_buffer.has_remaining() {
            return None;
        }

        // An entry that breaks the framing leaves the next one nowhere to be
        // found: its error ends the iteration.
        let contact_details: ContactDetails =
            match prost::Message::decode_length_delimited(
                &mut self.decrypted_buffer,
            ) {
                Ok(contact_details) => contact_details,
                Err(e) => {
                    self.decrypted_buffer.clear();
                    return Some(Err(ParseContactError::Protobuf(e)));
                },
            };

        let avatar_data = if let Some(Avatar {
            length: Some(length),
            ..
        }) = contact_details.avatar
        {
            let length = length as usize;
            if length > self.decrypted_buffer.remaining() {
                self.decrypted_buffer.clear();
                return Some(Err(ParseContactError::TruncatedAvatar));
            }
            Some(self.decrypted_buffer.copy_to_bytes(length))
        } else {
            None
        };

        Some(Contact::from_proto(contact_details, avatar_data))
    }
}
