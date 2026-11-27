use std::fmt::{self, Debug};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::consts::{U32, U64};
use aes::cipher::{
    Array, BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit,
};
use aes::Aes256;
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use libsignal_protocol::{KeyPair, PublicKey};
use prost::Message;
use rand::{CryptoRng, Rng};
use sha2::Sha256;

pub use crate::proto::{ProvisionEnvelope, ProvisionMessage};

use crate::{envelope::IV_LENGTH, provisioning::ProvisioningError};

enum CipherMode {
    DecryptAndEncrypt(KeyPair),
    EncryptOnly(PublicKey),
}

impl Debug for CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            CipherMode::DecryptAndEncrypt(key_pair) => f
                .debug_tuple("CipherMode::DecryptAndEncrypt")
                .field(&key_pair.public_key)
                .finish(),
            CipherMode::EncryptOnly(public) => f
                .debug_tuple("CipherMode::EncryptOnly")
                .field(&public)
                .finish(),
        }
    }
}

impl CipherMode {
    fn public(&self) -> &PublicKey {
        match self {
            CipherMode::DecryptAndEncrypt(pair) => &pair.public_key,
            CipherMode::EncryptOnly(pub_key) => pub_key,
        }
    }
}

const VERSION: u8 = 1;
/// An HMAC-SHA256.
const MAC_LENGTH: usize = 32;

/// A primary device's envelope, opened by [`ProvisioningCipher::decrypt`].
/// Its `Debug` prints no byte of the message, which holds the account's keys:
/// neither the message's fields nor its plaintext, only the plaintext's
/// length.
#[derive(derive_more::Debug)]
pub struct DecryptedProvisionMessage {
    /// The message, decoded with this crate's `Provisioning.proto`.
    pub message: ProvisionMessage,
    /// The message as the primary encoded it, decrypted: the fields this
    /// crate's `Provisioning.proto` lacks included, which `message` leaves
    /// out.
    #[debug("{} bytes", plaintext.len())]
    pub plaintext: Bytes,
}

#[derive(Debug)]
pub struct ProvisioningCipher {
    key_material: CipherMode,
}

impl ProvisioningCipher {
    pub fn from_public(key: PublicKey) -> Self {
        Self {
            key_material: CipherMode::EncryptOnly(key),
        }
    }

    pub fn from_key_pair(key_pair: KeyPair) -> Self {
        Self {
            key_material: CipherMode::DecryptAndEncrypt(key_pair),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.key_material.public()
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        csprng: &mut R,
        msg: ProvisionMessage,
    ) -> Result<ProvisionEnvelope, ProvisioningError> {
        let msg = msg.encode_to_vec();

        let our_key_pair = libsignal_protocol::KeyPair::generate(csprng);
        let agreement = our_key_pair
            .calculate_agreement(self.public_key())
            .map_err(ProvisioningError::invalid_public_key)?;

        let mut shared_secrets = Array::<u8, U64>::default();
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement)
            .expand(b"TextSecure Provisioning Message", &mut shared_secrets)
            .expect("valid output length");

        let (aes_key, mac_key) = shared_secrets.split_ref::<U32>();
        let iv: [u8; IV_LENGTH] = csprng.random();

        let cipher = cbc::Encryptor::<Aes256>::new(aes_key, &iv.into());
        let ciphertext = cipher.encrypt_padded_vec::<Pkcs7>(&msg);
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
            .expect("HMAC can take any size key");
        mac.update(&[VERSION]);
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes();

        let body: Vec<u8> = std::iter::once(VERSION)
            .chain(iv.iter().cloned())
            .chain(ciphertext)
            .chain(mac)
            .collect();

        Ok(ProvisionEnvelope {
            public_key: Some(our_key_pair.public_key.serialize().into()),
            body: Some(body),
        })
    }

    /// Opens a primary device's envelope: its message, decoded, and the
    /// plaintext it was decoded from, the message as the primary encoded it.
    /// A field this crate's `Provisioning.proto` lacks is in the plaintext
    /// alone: the decoding keeps no field it doesn't know.
    pub fn decrypt(
        &self,
        provision_envelope: ProvisionEnvelope,
    ) -> Result<DecryptedProvisionMessage, ProvisioningError> {
        let key_pair = match self.key_material {
            CipherMode::DecryptAndEncrypt(ref key_pair) => key_pair,
            CipherMode::EncryptOnly(_) => {
                return Err(ProvisioningError::EncryptOnlyProvisioningCipher);
            },
        };
        let master_ephemeral = PublicKey::deserialize(
            &provision_envelope
                .public_key
                .ok_or(ProvisioningError::MissingPublicKey)?,
        )
        .map_err(ProvisioningError::invalid_public_key)?;
        let body = provision_envelope
            .body
            .ok_or(ProvisioningError::MissingMessage)?;

        // The version, the IV, the ciphertext and the MAC of the three, as
        // `encrypt` writes them: a body too short to hold an IV and a MAC
        // can't verify.
        let (&version, body) = body
            .split_first()
            .ok_or(ProvisioningError::BadVersionNumber)?;
        if version != VERSION {
            return Err(ProvisioningError::BadVersionNumber);
        }
        let (iv, body) = body
            .split_first_chunk::<IV_LENGTH>()
            .ok_or(ProvisioningError::MismatchedMac)?;
        let (cipher_text, mac) = body
            .split_last_chunk::<MAC_LENGTH>()
            .ok_or(ProvisioningError::MismatchedMac)?;

        let agreement = key_pair
            .calculate_agreement(&master_ephemeral)
            .map_err(ProvisioningError::invalid_private_key)?;

        let mut shared_secrets = Array::<u8, U64>::default();
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement)
            .expand(b"TextSecure Provisioning Message", &mut shared_secrets)
            .expect("valid output length");

        let (parts1, parts2) = shared_secrets.split_ref::<U32>();

        let mut verifier = Hmac::<Sha256>::new_from_slice(parts2)
            .expect("HMAC can take any size key");
        verifier.update(&[version]);
        verifier.update(iv);
        verifier.update(cipher_text);
        verifier
            .verify_slice(mac)
            .map_err(|_| ProvisioningError::MismatchedMac)?;

        // libsignal-service-java uses Pkcs5,
        // but that should not matter.
        // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
        let cipher = cbc::Decryptor::<Aes256>::new(parts1, iv.into());
        let plaintext = Bytes::from(
            cipher
                .decrypt_padded_vec::<Pkcs7>(cipher_text)
                .map_err(ProvisioningError::AesPaddingError)?,
        );

        // From the `Bytes` (its clone is a reference count) prost copies each
        // `bytes` field once; from a slice it would copy each twice.
        let message = ProvisionMessage::decode(plaintext.clone())?;
        Ok(DecryptedProvisionMessage { message, plaintext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_provisioning_roundtrip() -> anyhow::Result<()> {
        let mut rng = rand::rng();
        let key_pair = KeyPair::generate(&mut rng);
        let cipher = ProvisioningCipher::from_key_pair(key_pair);
        let encrypt_cipher: ProvisioningCipher =
            ProvisioningCipher::from_public(*cipher.public_key());

        assert_eq!(
            cipher.public_key(),
            encrypt_cipher.public_key(),
            "copy public key"
        );

        let msg = ProvisionMessage::default();
        let encrypted = encrypt_cipher.encrypt(&mut rng, msg.clone())?;

        assert!(matches!(
            encrypt_cipher.decrypt(encrypted.clone()),
            Err(ProvisioningError::EncryptOnlyProvisioningCipher)
        ));

        let DecryptedProvisionMessage {
            message: decrypted,
            plaintext,
        } = cipher.decrypt(encrypted)?;
        assert_eq!(msg, decrypted);
        assert_eq!(plaintext, msg.encode_to_vec());

        Ok(())
    }
}
