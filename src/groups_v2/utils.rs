use libsignal_protocol::error::SignalProtocolError;
use zkgroup::groups::GroupMasterKey;
use zkgroup::GROUP_MASTER_KEY_LEN;

/// Given a 16-byte GroupV1 ID, derive the migration key.
///
/// A `group_id` that isn't 16 bytes long is
/// [`SignalProtocolError::InvalidArgument`].
pub fn derive_v2_migration_master_key(
    group_id: &[u8],
) -> Result<GroupMasterKey, SignalProtocolError> {
    if group_id.len() != 16 {
        return Err(SignalProtocolError::InvalidArgument(format!(
            "a GroupV1 id is 16 bytes, not {}",
            group_id.len()
        )));
    }

    let mut bytes = [0; GROUP_MASTER_KEY_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, group_id)
        .expand(b"GV2 Migration", &mut bytes)
        .expect("valid output length");
    Ok(GroupMasterKey::new(bytes))
}
