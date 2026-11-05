use base64::Engine;
use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
};
use libsignal_protocol::KeyPair;
use rand::{CryptoRng, Rng};
use url::Url;

pub use crate::proto::{ProvisionEnvelope, ProvisionMessage};

use crate::{
    proto::{
        ProvisioningAddress, WebSocketRequestMessage, WebSocketResponseMessage,
    },
    provisioning::ProvisioningError,
    utils::BASE64_RELAXED,
    websocket::{self, SignalWebSocket},
};

use super::cipher::ProvisioningCipher;

/// A new device's end of the provisioning socket: it turns the server's
/// requests into the link to show and the primary device's provisioning
/// message.
pub struct ProvisioningPipe {
    ws: SignalWebSocket<websocket::Unidentified>,
    provisioning_cipher: ProvisioningCipher,
    /// The link's `capabilities` value, comma-separated; empty for none.
    capabilities: String,
}

#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ProvisioningStep {
    Url(Url),
    /// The primary device's message, raw:
    /// [`ProvisionedAccount`](super::ProvisionedAccount) reads and checks it.
    Message(ProvisionMessage),
}

impl ProvisioningPipe {
    /// A pipe over a provisioning socket, with a new provisioning key pair.
    ///
    /// The link carries `capabilities`, which tell the primary device what
    /// this device can do: Signal-Desktop sends `nopni` and `nopni2` (it can
    /// link an account without a phone number) and `backup5` (it can import
    /// a transfer archive). Signal-Android won't link a device that doesn't
    /// say `nopni2` to an account without a phone number, and links one that
    /// doesn't say `backup5` without history. No capabilities, no
    /// `capabilities` parameter.
    pub fn from_socket<R: Rng + CryptoRng>(
        ws: SignalWebSocket<websocket::Unidentified>,
        csprng: &mut R,
        capabilities: &[&str],
    ) -> Self {
        let key_pair = KeyPair::generate(csprng);
        ProvisioningPipe {
            ws,
            provisioning_cipher: ProvisioningCipher::from_key_pair(key_pair),
            capabilities: capabilities.join(","),
        }
    }

    /// Worker task that
    async fn run(
        mut self,
        mut sink: Sender<Result<ProvisioningStep, ProvisioningError>>,
    ) -> Result<(), mpsc::SendError> {
        let mut ws = self.ws.clone();
        let mut stream = ws
            .take_request_stream()
            .expect("web socket request handler not in use");
        while let Some((req, responder)) = stream.next().await {
            let env = self.process_request(req, responder).await.transpose();
            if let Some(env) = env {
                sink.send(env).await?;
            }
        }
        ws.return_request_stream(stream);

        Ok(())
    }

    async fn process_request(
        &mut self,
        request: WebSocketRequestMessage,
        responder: oneshot::Sender<WebSocketResponseMessage>,
    ) -> Result<Option<ProvisioningStep>, ProvisioningError> {
        let ok = WebSocketResponseMessage {
            id: request.id,
            status: Some(200),
            message: Some("OK".into()),
            body: None,
            headers: vec![],
        };

        match request {
            // step 1: we get a ProvisioningUUID that we need to build a
            // registration link
            WebSocketRequestMessage {
                id: _,
                verb,
                path,
                body,
                ..
            } if verb == Some("PUT".into())
                && path == Some("/v1/address".into()) =>
            {
                // TODO: This is most likely wrong, check the SD code
                let address: ProvisioningAddress = prost::Message::decode(
                    body.ok_or(ProvisioningError::MissingUrl)?,
                )?;

                let mut provisioning_url = Url::parse("sgnl://linkdevice")
                    .map_err(|e| ProvisioningError::WsError {
                        reason: e.to_string(),
                    })?;
                provisioning_url
                    .query_pairs_mut()
                    .append_pair("uuid", address.address())
                    .append_pair(
                        "pub_key",
                        &BASE64_RELAXED.encode(
                            self.provisioning_cipher.public_key().serialize(),
                        ),
                    );
                // Form-encoded as Signal-Desktop's `URLSearchParams` does
                // (`signalRoutes.std.ts`): the commas become `%2C`.
                if !self.capabilities.is_empty() {
                    provisioning_url
                        .query_pairs_mut()
                        .append_pair("capabilities", &self.capabilities);
                }

                // acknowledge
                responder
                    .send(ok)
                    .map_err(|_| ProvisioningError::WsClosing)?;

                Ok(Some(ProvisioningStep::Url(provisioning_url)))
            },
            // step 2: once the QR code is scanned by the (already
            // validated) main device
            // we get a ProvisionMessage, that contains a bunch of
            // useful things
            WebSocketRequestMessage {
                id: _,
                verb,
                path,
                body,
                ..
            } if verb == Some("PUT".into())
                && path == Some("/v1/message".into()) =>
            {
                let provision_envelope: ProvisionEnvelope =
                    prost::Message::decode(
                        body.ok_or(ProvisioningError::MissingMessage)?,
                    )?;
                let provision_message =
                    self.provisioning_cipher.decrypt(provision_envelope)?;

                // acknowledge
                responder
                    .send(ok)
                    .map_err(|_| ProvisioningError::WsClosing)?;

                Ok(Some(ProvisioningStep::Message(provision_message)))
            },
            _ => Err(ProvisioningError::WsError {
                reason: "Incorrect request".into(),
            }),
        }
    }

    pub fn stream(
        self,
    ) -> impl Stream<Item = Result<ProvisioningStep, ProvisioningError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|_| {
            tracing::info!("Sink closed, provisioning is done!");
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}
