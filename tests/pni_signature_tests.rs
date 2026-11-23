//! A PNI signature beside a message, verified from the recipient's store.

mod common;

use std::{error::Error, rc::Rc};

use base64::prelude::*;
use libsignal_service::{
    cipher::ServiceCipher,
    content::{ContentBody, DecryptedEnvelope},
    envelope::Envelope,
    prelude::ProtobufMessage,
    proto::{self, DataMessage},
    protocol::{
        process_prekey_bundle, Aci, DeviceId, IdentityKeyPair,
        IdentityKeyStore as _, KeyPair, Pni, ProtocolAddress,
        SenderCertificate, ServerCertificate, ServiceId, SignalProtocolError,
        Timestamp,
    },
    sender::pni_signature,
    transport::Clock as _,
};
use uuid::Uuid;

use common::{
    store::{LocalStore, StoreFailure},
    *,
};

fn device(id: u8) -> DeviceId {
    DeviceId::new(id).unwrap()
}

fn alice() -> ServiceId {
    Aci::from(Uuid::from_u128(0xa1)).into()
}

fn alice_pni() -> Pni {
    Pni::from(Uuid::from_u128(0x9e))
}

fn address(id: impl Into<ServiceId>, at: u8) -> ProtocolAddress {
    id.into().to_protocol_address(device(at))
}

/// Alice's first message to Bob from her device `from`, sealed or not, with
/// her PNI signature beside it, as Bob opens it: he reads its text. When
/// `known`, he knows her PNI's identity, under her primary device; his store
/// fails to read the identity of `fails`.
async fn bob_opens(
    from: u8,
    sealed: bool,
    known: bool,
    fails: Option<ProtocolAddress>,
) -> DecryptedEnvelope {
    let rng = &mut rand::rng();
    let clock = Rc::new(ManualClock::default());
    let account = IdentityKeyPair::generate(rng);
    let pni_identity = IdentityKeyPair::generate(rng);
    let alice_store = LocalStore::new(account, 1);
    let bob = ServiceId::from(Aci::from(Uuid::from_u128(0xb0b)));
    let mut bob_store = LocalStore::new(IdentityKeyPair::generate(rng), 2);
    let bundle = bob_store.bundle(device(1)).await;
    process_prekey_bundle(
        &address(bob, 1),
        &address(alice(), from),
        &mut alice_store.clone(),
        &mut alice_store.clone(),
        &bundle,
        clock.now(),
        rng,
    )
    .await
    .unwrap();
    if known {
        bob_store
            .save_identity(
                &address(alice_pni(), 1),
                pni_identity.identity_key(),
            )
            .await
            .unwrap();
    }
    if let Some(address) = fails {
        bob_store.fail_identity_of(address);
    }

    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(DataMessage {
            body: Some("hi".into()),
            ..Default::default()
        })),
        pni_signature_message: Some(
            pni_signature(
                &pni_identity,
                account.identity_key(),
                alice_pni(),
                rng,
            )
            .unwrap(),
        ),
        ..Default::default()
    };
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let certificate = SenderCertificate::new(
        alice().service_id_string(),
        None,
        *account.public_key(),
        device(from),
        Timestamp::from_epoch_millis(1_800_000_000_000),
        ServerCertificate::new(
            1,
            server_key.public_key,
            &trust_root.private_key,
            rng,
        )
        .unwrap(),
        &server_key.private_key,
        rng,
    )
    .unwrap();
    let sent = ServiceCipher::new(
        alice_store,
        vec![],
        alice(),
        device(from),
        clock.clone(),
    )
    .encrypt(
        &address(bob, 1),
        sealed.then_some(&certificate),
        &content.encode_to_vec(),
        rng,
    )
    .await
    .unwrap();
    let envelope = Envelope {
        r#type: Some(sent.r#type as i32),
        source_service_id: (!sealed).then(|| alice().service_id_string()),
        source_device_id: (!sealed).then(|| from.into()),
        destination_service_id: Some(bob.service_id_string()),
        client_timestamp: Some(1_700_000_000_000),
        server_timestamp: Some(1_700_000_000_001),
        content: Some(BASE64_STANDARD.decode(sent.content).unwrap().into()),
        ..Default::default()
    };
    let opened = ServiceCipher::new(
        bob_store,
        vec![trust_root.public_key],
        bob,
        device(1),
        clock,
    )
    .open_envelope(&envelope, rng)
    .await
    .unwrap()
    .expect("opened");
    assert_eq!(opened.metadata.unidentified_sender, sealed);
    match &opened.body {
        Some(ContentBody::DataMessage(message)) => {
            assert_eq!(message.body.as_deref(), Some("hi"))
        },
        other => panic!("{other:?}"),
    }
    opened
}

/// A PNI signature is verified with the identities the store holds, the PNI's
/// under the sender's primary device; one whose PNI it doesn't know isn't. A
/// store that fails to read one of them costs neither the message, which is
/// decrypted, nor the PNI: the store's error is passed on beside the message,
/// where it read as "no identity" and the verified PNI was lost for good.
#[tokio::test]
async fn a_store_failure_under_a_pni_signature_goes_with_the_message() {
    for sealed in [false, true] {
        for from in [1, 2] {
            for (known, verified) in [(true, Some(alice_pni())), (false, None)]
            {
                let opened = bob_opens(from, sealed, known, None).await;
                assert_eq!(
                    opened.metadata.pni_verified.unwrap(),
                    verified,
                    "{from}, sealed: {sealed}"
                );
            }
        }

        for (from, fails) in [
            (1, address(alice(), 1)),
            (1, address(alice_pni(), 1)),
            (2, address(alice(), 2)),
            (2, address(alice_pni(), 2)),
            (2, address(alice_pni(), 1)),
        ] {
            let opened =
                bob_opens(from, sealed, true, Some(fails.clone())).await;
            let error = opened.metadata.pni_verified.unwrap_err();
            match &*error {
                SignalProtocolError::ApplicationCallbackError(_, source) => {
                    let source: &(dyn Error + 'static) = &**source;
                    assert!(
                        source.is::<StoreFailure>(),
                        "{fails}, sealed: {sealed}: {source:?}"
                    );
                },
                other => panic!("{fails}, sealed: {sealed}: {other:?}"),
            }
        }
    }
}
