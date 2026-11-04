use std::time::SystemTime;

use async_trait::async_trait;
use libsignal_core::DeviceId;
use libsignal_protocol::{
    ProtocolAddress, ServiceId, SessionRecord, SessionStore,
    SessionUsabilityRequirements, SignalProtocolError,
};

use crate::{content::ServiceError, push_service::DEFAULT_DEVICE_ID};

/// What a session must meet for lss to encrypt on it: not stale, established
/// with PQXDH and ratcheting with SPQR. It is the official clients' check
/// (libsignal's `SessionRecord_HasUsableSenderChain`, through which Desktop's
/// `hasCurrentState` and Android's `hasSenderChain` decide whether a device has
/// a session); libsignal v0.106 builds every new session to meet it.
pub const USABLE_SESSION: SessionUsabilityRequirements =
    SessionUsabilityRequirements::NotStale
        .union(SessionUsabilityRequirements::EstablishedWithPqxdh)
        .union(SessionUsabilityRequirements::Spqr);

/// Whether `record`'s active session is one lss encrypts on at `now`
/// ([`USABLE_SESSION`]).
///
/// A record that fails it counts as no session, whether it has no active
/// session (only archived ones), a stale one, or one without PQXDH or SPQR:
/// the sender builds a new session from a prekey bundle, which archives the
/// active one. It never deletes the record for it, since an archived session
/// still decrypts the messages sent on it.
pub fn has_usable_session(record: &SessionRecord, now: SystemTime) -> bool {
    // An error reads an unreadable session, which is no usable one either.
    record
        .has_usable_sender_chain(now, USABLE_SESSION)
        .unwrap_or(false)
}

/// This is additional functions required to handle
/// session deletion. It might be a candidate for inclusion into
/// the bigger `SessionStore` trait.
#[async_trait(?Send)]
pub trait SessionStoreExt: SessionStore {
    /// Get the IDs of all known sub devices with active sessions for a recipient.
    ///
    /// This should return every device except for the main device [DEFAULT_DEVICE_ID],
    /// and only devices whose record passes [`has_usable_session`] at `now`,
    /// the check [`ServiceCipher::encrypt`](crate::cipher::ServiceCipher::encrypt)
    /// makes. `now` is the caller's clock, the one its `ServiceCipher` reads.
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
        now: SystemTime,
    ) -> Result<Vec<DeviceId>, SignalProtocolError>;

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    async fn delete_all_sessions(
        &self,
        address: &ServiceId,
    ) -> Result<usize, SignalProtocolError>;

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_service_addr_device_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<usize, SignalProtocolError> {
        let mut count = 0;
        match self.delete_session(address).await {
            Ok(()) => {
                count += 1;
            },
            Err(SignalProtocolError::SessionNotFound(_)) => (),
            Err(e) => return Err(e),
        }

        Ok(count)
    }

    async fn compute_safety_number(
        &self,
        local_address: &ServiceId,
        address: &ServiceId,
    ) -> Result<String, ServiceError>
    where
        Self: Sized + libsignal_protocol::IdentityKeyStore,
    {
        let addr = crate::cipher::get_preferred_protocol_address(
            self,
            address,
            *DEFAULT_DEVICE_ID,
        )
        .await?;
        let ident = self
            .get_identity(&addr)
            .await?
            .ok_or(SignalProtocolError::UntrustedIdentity(addr))?;
        let local = self
            .get_identity_key_pair()
            .await
            .expect("valid local identity");
        let fp = libsignal_protocol::Fingerprint::new(
            2,
            5200,
            local_address.raw_uuid().as_bytes(),
            local.identity_key(),
            address.raw_uuid().as_bytes(),
            &ident,
        )?;
        Ok(fp.display_string()?)
    }
}
