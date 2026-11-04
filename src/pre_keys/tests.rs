use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyPair, KyberPreKeyRecord, Timestamp,
};
use rand::{rngs::StdRng, SeedableRng};

use super::generate_kyber_pre_key;

/// The record carries the caller's timestamp, through serialization too, and
/// its Kyber1024 public key is signed by the identity key.
#[test]
fn kyber_pre_key_carries_the_given_timestamp() {
    let rng = &mut rand::rng();
    let identity = IdentityKeyPair::generate(rng);
    // 2023-11-14: far from the system clock, so a wall-clock stamp shows.
    let created = Timestamp::from_epoch_millis(1_700_000_000_000);

    let record =
        generate_kyber_pre_key(7.into(), &identity, created, rng).unwrap();
    let stored =
        KyberPreKeyRecord::deserialize(&record.serialize().unwrap()).unwrap();

    for record in [&record, &stored] {
        assert_eq!(u32::from(record.id().unwrap()), 7);
        assert_eq!(record.timestamp().unwrap(), created);
        let public_key = record.public_key().unwrap();
        assert_eq!(public_key.key_type(), kem::KeyType::Kyber1024);
        assert!(identity.public_key().verify_signature(
            &public_key.serialize(),
            &record.signature().unwrap(),
        ));
    }
}

/// The key pair and the signature come from the caller's CSPRNG alone: the
/// same seed gives the same record, byte for byte.
#[test]
fn kyber_pre_key_draws_from_the_given_csprng() {
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let created = Timestamp::from_epoch_millis(1_700_000_000_000);
    let generate = |seed: u64| {
        generate_kyber_pre_key(
            1.into(),
            &identity,
            created,
            &mut StdRng::seed_from_u64(seed),
        )
        .unwrap()
        .serialize()
        .unwrap()
    };

    assert_eq!(generate(1), generate(1));
    assert_ne!(generate(1), generate(2));
}
