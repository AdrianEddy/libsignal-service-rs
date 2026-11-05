//! The provisioning socket: what the server's requests make of a link, and
//! the link of an account with and without a phone number.

mod common;

use std::{collections::BTreeMap, rc::Rc};

use async_trait::async_trait;
use futures::{
    channel::mpsc, executor::LocalPool, future::FutureExt as _,
    task::LocalSpawnExt as _, StreamExt as _,
};
use http::{header, Method};
use libsignal_service::{
    configuration::ServiceCredentials,
    pre_keys::{
        replenish_pre_keys, KyberPreKeyEntity, KyberPreKeyStoreExt,
        PreKeysStore, SignedPreKeyEntity,
    },
    prelude::ProtobufMessage,
    proto::{ProvisioningAddress, WebSocketRequestMessage},
    protocol::{
        DeviceId, GenericSignedPreKey as _, IdentityKeyPair, KeyPair,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PublicKey,
        SignalProtocolError, SignedPreKeyId, SignedPreKeyStore, Timestamp,
    },
    provisioning::{
        link_device, NewDeviceRegistration, ProvisionEnvelope,
        ProvisionMessage, ProvisionedAccount, ProvisioningCipher,
        ProvisioningError, ProvisioningSecrets, ProvisioningStep,
        SecondaryDeviceProvisioning,
    },
    push_service::{linking::LinkResponse, ServiceError},
    utils::BASE64_RELAXED,
    websocket::Identified,
    AccountManager,
};
use uuid::Uuid;

use common::{store::LocalStore, *};

type StoreResult<T> = Result<T, SignalProtocolError>;

const ADDRESS: &str = "an-address";
const PNI: Uuid = Uuid::from_u128(0x9e9e_9e9e_9e9e_4e9e_9e9e_9e9e_9e9e_9e9e);
const SALT: [u8; 16] = [0x5a; 16];

/// Signal-Desktop's link capabilities (`Provisioner.preload.ts`).
const QR_CAPABILITIES: [&str; 3] = ["nopni", "nopni2", "backup5"];

/// The caller's capability record, without `optionalPhoneNumber`, which the
/// link sets.
fn capabilities() -> BTreeMap<String, bool> {
    [
        ("attachmentBackfill", false),
        ("spqr", true),
        ("usernameChangeSyncMessage", true),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

fn address() -> Vec<u8> {
    ProvisioningAddress {
        address: Some(ADDRESS.into()),
    }
    .encode_to_vec()
}

/// Links a device over a provisioning socket on which the server sends these
/// requests, each a path and a body. Returns how the link ended and the
/// links it showed.
fn link(
    requests: &[(&str, Option<Vec<u8>>)],
    link_capabilities: &'static [&'static str],
) -> (Result<(), ProvisioningError>, Vec<String>) {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let server = transport.accept_socket(&[]);
    for (id, (path, body)) in (1..).zip(requests) {
        server.request_message(WebSocketRequestMessage {
            id: Some(id),
            verb: Some("PUT".into()),
            path: Some((*path).into()),
            body: body.clone().map(Into::into),
            headers: Vec::new(),
        });
    }
    let mut rng = rand::rng();
    let mut aci = LocalStore::new(IdentityKeyPair::generate(&mut rng), 1);
    let mut pni = LocalStore::new(IdentityKeyPair::generate(&mut rng), 2);
    let (tx, rx) = mpsc::channel(1);
    let link = pool
        .spawner()
        .spawn_local_with_handle(async move {
            link_device(
                &mut aci,
                &mut pni,
                &mut rng,
                Rc::new(ManualClock::default()),
                service,
                "password",
                "device",
                link_capabilities,
                capabilities(),
                tx,
            )
            .await
        })
        .unwrap();
    pool.run_until_stalled();
    let ended = link.now_or_never().expect("the link ended");
    let shown = rx
        .map(|step| match step {
            SecondaryDeviceProvisioning::Url(url) => url.into(),
            other => panic!("not a link: {other:?}"),
        })
        .collect()
        .now_or_never()
        .expect("the link ended");
    (ended, shown)
}

/// A request of the server's without a body fails the link with the step it
/// stood for, instead of a panic.
#[test]
fn a_request_without_a_body_fails_the_link() {
    let (ended, shown) = link(&[("/v1/address", None)], &[]);
    assert!(
        matches!(ended, Err(ProvisioningError::MissingUrl)),
        "{ended:?}"
    );
    assert_eq!(shown, Vec::<String>::new());

    let (ended, shown) = link(
        &[("/v1/address", Some(address())), ("/v1/message", None)],
        &[],
    );
    assert!(
        matches!(ended, Err(ProvisioningError::MissingMessage)),
        "{ended:?}"
    );
    let [shown] = &shown[..] else {
        panic!("one link: {shown:?}")
    };
    assert!(
        shown.starts_with("sgnl://linkdevice?uuid=an-address&pub_key="),
        "{shown}"
    );
    assert!(!shown.contains("capabilities"), "none asked for: {shown}");
}

/// The link names the capabilities the caller gives, form-encoded as
/// Signal-Desktop's `URLSearchParams` encodes them.
#[test]
fn url_carries_capabilities() {
    let (_, shown) = link(
        &[("/v1/address", Some(address())), ("/v1/message", None)],
        &QR_CAPABILITIES,
    );
    let [shown] = &shown[..] else {
        panic!("one link: {shown:?}")
    };
    let (start, capabilities) = shown
        .split_once("&capabilities=")
        .expect("a capabilities parameter");
    assert!(
        start.starts_with("sgnl://linkdevice?uuid=an-address&pub_key="),
        "{shown}"
    );
    assert_eq!(capabilities, "nopni%2Cnopni2%2Cbackup5");

    let url = url::Url::parse(shown).unwrap();
    let names: Vec<_> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert_eq!(names, ["uuid", "pub_key", "capabilities"]);
    let (_, decoded) = url
        .query_pairs()
        .find(|(name, _)| name == "capabilities")
        .unwrap();
    assert_eq!(decoded.split(',').collect::<Vec<_>>(), QR_CAPABILITIES);
}

/// Field 19 of a provisioning message is the auth credential salt, as in
/// Signal-Android's and Signal-Desktop's `Provisioning.proto`.
#[test]
fn auth_credential_salt_parsed() {
    // Tag 19, length-delimited: (19 << 3) | 2 = 154, a two-byte varint.
    let mut wire = vec![0x9a, 0x01, SALT.len() as u8];
    wire.extend_from_slice(&SALT);
    let message = ProvisionMessage::decode(&wire[..]).unwrap();
    assert_eq!(message.auth_credential_salt.as_deref(), Some(&SALT[..]));
    assert_eq!(message.encode_to_vec(), wire);

    // And through the provisioning cipher, as a primary device sends it.
    let mut rng = rand::rng();
    let device = KeyPair::generate(&mut rng);
    let envelope = ProvisioningCipher::from_public(device.public_key)
        .encrypt(&mut rng, message)
        .unwrap();
    let opened = ProvisioningCipher::from_key_pair(device)
        .decrypt(envelope)
        .unwrap();
    assert_eq!(opened.auth_credential_salt.as_deref(), Some(&SALT[..]));
}

/// What a primary device knows of the account it links.
struct Primary {
    aci: IdentityKeyPair,
    /// The PNI's identity, for an account with a phone number.
    pni: Option<IdentityKeyPair>,
}

impl Primary {
    fn new(with_phone_number: bool) -> Self {
        let mut rng = rand::rng();
        Self {
            aci: IdentityKeyPair::generate(&mut rng),
            pni: with_phone_number.then(|| IdentityKeyPair::generate(&mut rng)),
        }
    }

    /// The provisioning message: an account without a phone number has no
    /// PNI, PNI keys or number, and has the salt (Signal-Desktop
    /// `ProvisioningCipher.node.ts`).
    fn message(&self) -> ProvisionMessage {
        ProvisionMessage {
            aci_identity_key_public: Some(
                self.aci.public_key().serialize().into_vec(),
            ),
            aci_identity_key_private: Some(self.aci.private_key().serialize()),
            pni_identity_key_public: self
                .pni
                .map(|pni| pni.public_key().serialize().into_vec()),
            pni_identity_key_private: self
                .pni
                .map(|pni| pni.private_key().serialize()),
            aci: Some(ACI.to_string()),
            pni: self.pni.map(|_| PNI.to_string()),
            number: self.pni.map(|_| "+15550100".into()),
            provisioning_code: Some("code".into()),
            profile_key: Some(vec![9; 32]),
            provisioning_version: Some(1),
            aci_binary: Some(ACI.into_bytes().to_vec()),
            pni_binary: self.pni.map(|_| PNI.into_bytes().to_vec()),
            auth_credential_salt: self.pni.is_none().then(|| SALT.to_vec()),
            ..Default::default()
        }
    }
}

/// How a link to a primary's account went.
struct Linked {
    ended: Result<(), ProvisioningError>,
    registration: Option<NewDeviceRegistration>,
    /// The link request, if one was sent.
    request: Option<Seen>,
}

/// Links a device to `primary`'s account: the primary scans the link and
/// sends `message`, and the server answers the link request with `answer`.
fn link_to(
    primary: &Primary,
    message: impl FnOnce(&Primary) -> ProvisionMessage,
    answer: Answer,
) -> Linked {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let server = transport.accept_socket(&[]);
    server.request(1, "PUT", "/v1/address", address());
    transport.answer(answer);
    let mut rng = rand::rng();
    let mut aci = LocalStore::new(IdentityKeyPair::generate(&mut rng), 1);
    let mut pni = LocalStore::new(IdentityKeyPair::generate(&mut rng), 2);
    let (tx, mut rx) = mpsc::channel(1);
    let link = pool
        .spawner()
        .spawn_local_with_handle(async move {
            link_device(
                &mut aci,
                &mut pni,
                &mut rng,
                Rc::new(ManualClock::default()),
                service,
                "password",
                "device",
                &QR_CAPABILITIES,
                capabilities(),
                tx,
            )
            .await
        })
        .unwrap();
    pool.run_until_stalled();

    // The primary scans the link and answers with the provisioning message,
    // sealed to the link's key.
    let Some(Some(SecondaryDeviceProvisioning::Url(url))) =
        rx.next().now_or_never()
    else {
        panic!("a link first");
    };
    let (_, pub_key) = url
        .query_pairs()
        .find(|(name, _)| name == "pub_key")
        .unwrap();
    let pub_key = PublicKey::deserialize(
        &base64::Engine::decode(&BASE64_RELAXED, &*pub_key).unwrap(),
    )
    .unwrap();
    let envelope = ProvisioningCipher::from_public(pub_key)
        .encrypt(&mut rand::rng(), message(primary))
        .unwrap();
    server.request(2, "PUT", "/v1/message", envelope.encode_to_vec());
    pool.run_until_stalled();

    let ended = link.now_or_never().expect("the link ended");
    let registration = match rx.next().now_or_never() {
        Some(Some(SecondaryDeviceProvisioning::NewDeviceRegistration(
            registration,
        ))) => Some(registration),
        Some(Some(other)) => panic!("not a registration: {other:?}"),
        Some(None) | None => None,
    };
    let request = transport.take_seen().pop();
    Linked {
        ended,
        registration,
        request,
    }
}

/// The server's check of a prekey's signature (Signal-Server
/// `PreKeySignatureValidator`): the serialized key, signed by the identity.
fn signed_by(identity: &IdentityKeyPair, key: &serde_json::Value) -> bool {
    let key: SignedPreKeyEntity =
        serde_json::from_str(&key.to_string()).unwrap();
    identity
        .public_key()
        .verify_signature(&key.public_key, &key.signature)
}

fn kyber_signed_by(
    identity: &IdentityKeyPair,
    key: &serde_json::Value,
) -> bool {
    let key: KyberPreKeyEntity =
        serde_json::from_str(&key.to_string()).unwrap();
    identity
        .public_key()
        .verify_signature(&key.public_key, &key.signature)
}

/// An account without a phone number: its provisioning message has no PNI,
/// so the link checks no PNI keys or number, sends none, says
/// `optionalPhoneNumber`, and keeps the salt.
#[test]
fn numberless_message_links_without_pni_keys() {
    let primary = Primary::new(false);
    let linked = link_to(
        &primary,
        Primary::message,
        Answer::json(200, serde_json::json!({ "uuid": ACI, "deviceId": 3 })),
    );
    linked.ended.unwrap();

    let request = linked.request.expect("a link request");
    assert_eq!(request.method, Method::PUT);
    assert_eq!(request.url, "https://chat.test/v1/devices/link");
    assert_eq!(
        request.header(header::AUTHORIZATION),
        Some(&*basic(&format!("{ACI}:password"))),
        "the bare ACI as the user name"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).unwrap();
    let attributes = &body["accountAttributes"];
    assert_eq!(
        attributes["capabilities"],
        serde_json::json!({
            "attachmentBackfill": false,
            "optionalPhoneNumber": true,
            "spqr": true,
            "usernameChangeSyncMessage": true,
        })
    );
    assert_eq!(attributes["fetchesMessages"], true);
    assert!(
        attributes.get("pniRegistrationId").is_none(),
        "{attributes}"
    );
    assert!(body.get("pniSignedPreKey").is_none(), "{body}");
    assert!(body.get("pniPqLastResortPreKey").is_none(), "{body}");
    assert!(signed_by(&primary.aci, &body["aciSignedPreKey"]));
    assert!(kyber_signed_by(
        &primary.aci,
        &body["aciPqLastResortPreKey"]
    ));

    let registration = linked.registration.expect("a registration");
    assert_eq!(registration.phone_number, None);
    assert_eq!(registration.service_ids.aci, ACI);
    assert_eq!(registration.service_ids.pni, None);
    assert_eq!(registration.service_ids.pni(), None);
    assert_eq!(registration.pni_registration_id, None);
    assert!(registration.pni_private_key.is_none());
    assert!(registration.pni_public_key.is_none());
    assert_eq!(registration.aci_public_key, *primary.aci.identity_key());
    assert_eq!(registration.auth_credential_salt, Some(SALT));
}

/// Without a PNI the salt is required, as Signal-Desktop requires it: the
/// account's group credentials can't be had without it. Empty means absent.
#[test]
fn numberless_message_without_salt_is_refused() {
    let primary = Primary::new(false);
    for auth_credential_salt in [None, Some(Vec::new())] {
        let linked = link_to(
            &primary,
            |primary| ProvisionMessage {
                auth_credential_salt,
                ..primary.message()
            },
            Answer::status(500),
        );
        assert!(
            matches!(
                linked.ended,
                Err(ProvisioningError::MissingAuthCredentialSalt)
            ),
            "{:?}",
            linked.ended
        );
        assert!(linked.request.is_none(), "no link request");
        assert!(linked.registration.is_none());
    }
}

/// The server's salt is always 16 bytes: any other length would fail only
/// later, in the group credentials of a device already on the account. A
/// message with a PNI doesn't get to carry one either.
#[test]
fn malformed_salt_is_refused() {
    for (with_phone_number, length) in [(false, 15), (false, 17), (true, 15)] {
        let linked = link_to(
            &Primary::new(with_phone_number),
            |primary| ProvisionMessage {
                auth_credential_salt: Some(vec![0x5a; length]),
                ..primary.message()
            },
            Answer::status(500),
        );
        assert!(
            matches!(
                linked.ended,
                Err(ProvisioningError::InvalidAuthCredentialSalt(got))
                    if got == length
            ),
            "{:?}",
            linked.ended
        );
        assert!(linked.request.is_none(), "no link request");
        assert!(linked.registration.is_none());
    }
}

/// A PNI key without a PNI is refused, as Signal-Desktop refuses it.
#[test]
fn a_pni_key_without_a_pni_is_refused() {
    let primary = Primary::new(false);
    let linked = link_to(
        &primary,
        |primary| ProvisionMessage {
            pni_identity_key_private: Some(
                primary.aci.private_key().serialize(),
            ),
            ..primary.message()
        },
        Answer::status(500),
    );
    assert!(
        matches!(linked.ended, Err(ProvisioningError::PniKeyWithoutPni)),
        "{:?}",
        linked.ended
    );
    assert!(linked.request.is_none(), "no link request");
    assert!(linked.registration.is_none());

    // The private key alone decides, as in Signal-Desktop: a public key, or
    // an empty private key, is no key pair.
    let public_key = primary.aci.public_key().serialize().into_vec();
    for (pni_identity_key_public, pni_identity_key_private) in
        [(Some(public_key), None), (None, Some(Vec::new()))]
    {
        let message = ProvisionMessage {
            pni_identity_key_public,
            pni_identity_key_private,
            ..primary.message()
        };
        let account = ProvisionedAccount::try_from(message).unwrap();
        assert!(account.phone_number_identity.is_none());
    }
}

/// An account with a phone number links as it always did, with PNI keys
/// signed by the PNI identity and a PNI registration id, and says
/// `optionalPhoneNumber: false`.
#[test]
fn numbered_message_links_with_pni_keys() {
    let primary = Primary::new(true);
    let linked = link_to(
        &primary,
        Primary::message,
        Answer::json(
            200,
            serde_json::json!({ "uuid": ACI, "pni": PNI, "deviceId": 3 }),
        ),
    );
    linked.ended.unwrap();

    let request = linked.request.expect("a link request");
    assert_eq!(
        request.header(header::AUTHORIZATION),
        Some(&*basic(&format!("{ACI}:password")))
    );
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).unwrap();
    let attributes = &body["accountAttributes"];
    assert_eq!(attributes["capabilities"]["optionalPhoneNumber"], false);
    let pni_registration_id = attributes["pniRegistrationId"]
        .as_u64()
        .expect("a PNI registration id");
    let pni = primary.pni.unwrap();
    assert!(signed_by(&primary.aci, &body["aciSignedPreKey"]));
    assert!(kyber_signed_by(
        &primary.aci,
        &body["aciPqLastResortPreKey"]
    ));
    assert!(signed_by(&pni, &body["pniSignedPreKey"]));
    assert!(kyber_signed_by(&pni, &body["pniPqLastResortPreKey"]));

    let registration = linked.registration.expect("a registration");
    assert_eq!(
        registration.phone_number,
        Some("+15550100".parse().unwrap())
    );
    assert_eq!(registration.service_ids.pni, Some(PNI));
    assert_eq!(
        registration.pni_registration_id.map(u64::from),
        Some(pni_registration_id)
    );
    assert_eq!(registration.pni_public_key, Some(*pni.identity_key()));
    assert_eq!(registration.auth_credential_salt, None);
}

/// A message with a PNI still needs the PNI keys and the phone number.
#[test]
fn numbered_message_needs_pni_keys_and_number() {
    let primary = Primary::new(true);
    let linked = link_to(
        &primary,
        |primary| ProvisionMessage {
            pni_identity_key_public: None,
            ..primary.message()
        },
        Answer::status(500),
    );
    assert!(
        matches!(linked.ended, Err(ProvisioningError::MissingPublicKey)),
        "{:?}",
        linked.ended
    );
    assert!(linked.request.is_none(), "no link request");

    let linked = link_to(
        &primary,
        |primary| ProvisionMessage {
            number: None,
            ..primary.message()
        },
        Answer::status(500),
    );
    assert!(
        matches!(linked.ended, Err(ProvisioningError::MissingPhoneNumber)),
        "{:?}",
        linked.ended
    );
    assert!(linked.request.is_none(), "no link request");
}

/// The link logs in as the message's ACI: `aciBinary`, else the `aci` string,
/// as Signal-Desktop reads them; without either it can't link.
#[test]
fn the_link_logs_in_as_the_messages_aci() {
    let primary = Primary::new(false);
    let answer =
        || Answer::json(200, serde_json::json!({ "uuid": ACI, "deviceId": 3 }));
    // The string alone, and `aciBinary` over a string that differs.
    let only_the_string = link_to(
        &primary,
        |primary| ProvisionMessage {
            aci_binary: None,
            ..primary.message()
        },
        answer(),
    );
    let both = link_to(
        &primary,
        |primary| ProvisionMessage {
            aci: Some(Uuid::from_u128(1).to_string()),
            ..primary.message()
        },
        answer(),
    );
    for linked in [only_the_string, both] {
        linked.ended.unwrap();
        assert_eq!(
            linked.request.unwrap().header(header::AUTHORIZATION),
            Some(&*basic(&format!("{ACI}:password")))
        );
    }

    for (aci, aci_binary, refused) in [
        (None, None, "missing"),
        (None, Some(vec![1, 2, 3]), "invalid"),
        (Some("not-a-uuid".to_owned()), None, "invalid"),
    ] {
        let linked = link_to(
            &primary,
            |primary| ProvisionMessage {
                aci,
                aci_binary,
                ..primary.message()
            },
            Answer::status(500),
        );
        match (refused, &linked.ended) {
            ("missing", Err(ProvisioningError::MissingAci))
            | ("invalid", Err(ProvisioningError::InvalidAci(_))) => {},
            (refused, ended) => panic!("{refused}: {ended:?}"),
        }
        assert!(linked.request.is_none(), "no link request");
    }
}

/// A PNI that can't be read is refused, not taken for a PNI, whose keys would
/// go to the server with an id nobody checked.
#[test]
fn an_invalid_pni_is_refused() {
    let primary = Primary::new(true);
    for (pni, pni_binary) in [
        (Some("not-a-uuid".to_owned()), None),
        (None, Some(vec![1, 2, 3])),
    ] {
        let linked = link_to(
            &primary,
            |primary| ProvisionMessage {
                pni,
                pni_binary,
                ..primary.message()
            },
            Answer::status(500),
        );
        assert!(
            matches!(linked.ended, Err(ProvisioningError::InvalidPni(_))),
            "{:?}",
            linked.ended
        );
        assert!(linked.request.is_none(), "no link request");
    }
}

/// The server's answer must name the account in the message, the PNI's
/// absence included: the keys and the number kept come from the message, the
/// ids from the answer.
#[test]
fn a_link_answer_for_another_account_is_refused() {
    let other = Uuid::from_u128(1);
    for (with_phone_number, answer) in [
        (
            true,
            serde_json::json!({ "uuid": other, "pni": PNI, "deviceId": 3 }),
        ),
        (
            true,
            serde_json::json!({ "uuid": ACI, "pni": other, "deviceId": 3 }),
        ),
        (true, serde_json::json!({ "uuid": ACI, "deviceId": 3 })),
        (false, serde_json::json!({ "uuid": other, "deviceId": 3 })),
        (
            false,
            serde_json::json!({ "uuid": ACI, "pni": PNI, "deviceId": 3 }),
        ),
    ] {
        let primary = Primary::new(with_phone_number);
        let linked =
            link_to(&primary, Primary::message, Answer::json(200, answer));
        assert!(
            matches!(
                linked.ended,
                Err(ProvisioningError::MismatchedLinkResponse)
            ),
            "{:?}",
            linked.ended
        );
        assert!(linked.request.is_some());
        assert!(linked.registration.is_none());
    }
}

/// A client that drives the steps itself reads an account with a phone number
/// from the bare message, with no socket or server.
#[test]
fn provisioned_account_of_a_numbered_message() {
    let primary = Primary::new(true);
    let account = ProvisionedAccount::try_from(primary.message()).unwrap();

    assert_eq!(account.aci, ACI);
    assert_eq!(
        account.aci_key_pair.identity_key(),
        primary.aci.identity_key()
    );
    assert_eq!(
        account.aci_key_pair.private_key().serialize(),
        primary.aci.private_key().serialize()
    );
    assert_eq!(account.auth_credential_salt, None);
    assert_eq!(account.provisioning_code, "code");
    assert_eq!(account.profile_key.bytes, [9; 32]);

    let service_ids = account.service_ids();
    assert_eq!(service_ids.aci, ACI);
    assert_eq!(service_ids.pni, Some(PNI));

    let identity = account.phone_number_identity.expect("a phone number");
    let pni = primary.pni.unwrap();
    assert_eq!(identity.pni, PNI);
    assert_eq!(identity.phone_number, "+15550100".parse().unwrap());
    assert_eq!(identity.key_pair.identity_key(), pni.identity_key());
    assert_eq!(
        identity.key_pair.private_key().serialize(),
        pni.private_key().serialize()
    );
}

/// The same for an account without a phone number.
#[test]
fn provisioned_account_of_a_numberless_message() {
    let primary = Primary::new(false);
    let account = ProvisionedAccount::try_from(primary.message()).unwrap();

    assert_eq!(account.aci, ACI);
    assert!(account.phone_number_identity.is_none());
    assert_eq!(account.auth_credential_salt, Some(SALT));

    let service_ids = account.service_ids();
    assert_eq!(service_ids.aci, ACI);
    assert_eq!(service_ids.pni, None);
}

/// The PNI is read as the ACI is, as Signal-Desktop reads them: `pniBinary`,
/// else the `pni` string, and empty means absent.
#[test]
fn provisioned_account_reads_the_pni_as_signal_desktop_does() {
    let binary = || PNI.into_bytes().to_vec();
    let string = || PNI.to_string();
    let other = Uuid::from_u128(1).to_string();
    let primary = Primary::new(true);
    for (pni, pni_binary) in [
        (Some(string()), None),
        (Some(string()), Some(Vec::new())),
        (None, Some(binary())),
        (Some(String::new()), Some(binary())),
        (Some(other), Some(binary())),
    ] {
        let message = ProvisionMessage {
            pni,
            pni_binary,
            ..primary.message()
        };
        let account = ProvisionedAccount::try_from(message).unwrap();
        assert_eq!(account.service_ids().pni, Some(PNI));
    }

    let primary = Primary::new(false);
    for (pni, pni_binary) in [
        (None, None),
        (Some(String::new()), None),
        (None, Some(Vec::new())),
        (Some(String::new()), Some(Vec::new())),
    ] {
        let message = ProvisionMessage {
            pni,
            pni_binary,
            ..primary.message()
        };
        let account = ProvisionedAccount::try_from(message).unwrap();
        assert_eq!(account.service_ids().pni, None);
    }
}

/// What `link_device` checks of the server's answer, for a client that sends
/// the link request itself.
#[test]
fn check_link_response_compares_both_ids() {
    let other = Uuid::from_u128(1);
    let answer = |aci, pni| LinkResponse {
        aci,
        pni,
        device_id: DeviceId::new(3).unwrap(),
    };
    let numbered =
        ProvisionedAccount::try_from(Primary::new(true).message()).unwrap();
    let numberless =
        ProvisionedAccount::try_from(Primary::new(false).message()).unwrap();

    numbered
        .check_link_response(&answer(ACI, Some(PNI)))
        .unwrap();
    numberless.check_link_response(&answer(ACI, None)).unwrap();

    for (account, answer) in [
        (&numbered, answer(other, Some(PNI))),
        (&numbered, answer(ACI, Some(other))),
        (&numbered, answer(ACI, None)),
        (&numberless, answer(other, None)),
        (&numberless, answer(ACI, Some(PNI))),
    ] {
        let checked = account.check_link_response(&answer);
        assert!(
            matches!(checked, Err(ProvisioningError::MismatchedLinkResponse)),
            "{checked:?}"
        );
    }
}

/// `Debug` shows the ids and no other part of the account: exactly this
/// text, so a field added later has to choose.
#[test]
fn provisioned_account_debug_prints_no_secret() {
    let message = ProvisionMessage {
        auth_credential_salt: Some(SALT.to_vec()),
        account_entropy_pool: Some("a".repeat(64)),
        ephemeral_backup_key: Some(vec![7; 32]),
        ..Primary::new(true).message()
    };
    let account = ProvisionedAccount::try_from(message).unwrap();
    assert_eq!(
        format!("{account:?}"),
        format!(
            "ProvisionedAccount {{ aci: {ACI}, phone_number_identity: \
             Some(PhoneNumberIdentity {{ pni: {PNI}, .. }}), .. }}"
        )
    );

    let account =
        ProvisionedAccount::try_from(Primary::new(false).message()).unwrap();
    assert_eq!(
        format!("{account:?}"),
        format!(
            "ProvisionedAccount {{ aci: {ACI}, phone_number_identity: None, \
             .. }}"
        )
    );
}

/// The message holds the account's private keys, so it prints no field, and
/// neither does the step that hands it over.
#[test]
fn a_provision_message_prints_no_field() {
    let message = ProvisionMessage {
        aci_identity_key_private: Some(vec![7; 32]),
        ..Default::default()
    };
    assert_eq!(format!("{message:?}"), "ProvisionMessage { .. }");
    assert_eq!(
        format!("{:?}", ProvisioningStep::Message(message)),
        "Message(ProvisionMessage { .. })"
    );
}

/// What `AccountManager::link_device` sends a new device, as a primary with
/// these credentials and this salt.
fn sent_by_primary(
    credentials: ServiceCredentials,
    salt: Option<[u8; 16]>,
) -> ProvisionMessage {
    let mut pool = LocalPool::new();
    let (service, transport) = push_service();
    let _server = transport.accept_socket(&[]);
    let (websocket, _task) = pool
        .run_until(service.ws::<Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(common::credentials()),
            Rc::new(ManualClock::default()),
        ))
        .unwrap();
    let mut manager = AccountManager::new(
        service,
        websocket,
        None,
        Rc::new(ManualClock::default()),
    );

    let mut rng = rand::rng();
    let device = KeyPair::generate(&mut rng);
    let mut url = url::Url::parse("sgnl://linkdevice").unwrap();
    url.query_pairs_mut()
        .append_pair("uuid", ADDRESS)
        .append_pair(
            "pub_key",
            &base64::Engine::encode(
                &BASE64_RELAXED,
                device.public_key.serialize(),
            ),
        );
    transport.answer(Answer::json(
        200,
        serde_json::json!({ "verificationCode": "code" }),
    ));
    transport.answer(Answer::status(204));
    let aci = LocalStore::new(IdentityKeyPair::generate(&mut rng), 1);
    let pni = LocalStore::new(IdentityKeyPair::generate(&mut rng), 2);
    pool.run_until(manager.link_device(
        &mut rng,
        url,
        &aci,
        &pni,
        ProvisioningSecrets {
            credentials,
            ephemeral_backup_key: None,
            account_entropy_pool: "a".repeat(64).parse().unwrap(),
            media_root_backup_key: None,
            auth_credential_salt: salt,
        },
    ))
    .unwrap();

    let sent = transport.take_seen().pop().unwrap();
    assert_eq!(
        sent.url,
        format!("https://chat.test/v1/provisioning/{ADDRESS}")
    );
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    let envelope =
        base64::Engine::decode(&BASE64_RELAXED, body["body"].as_str().unwrap())
            .unwrap();
    ProvisioningCipher::from_key_pair(device)
        .decrypt(ProvisionEnvelope::decode(&envelope[..]).unwrap())
        .unwrap()
}

/// A primary without a phone number sends what a new device needs of such an
/// account: the salt, and no PNI, PNI identity or number, which
/// Signal-Desktop refuses to find without a PNI.
#[test]
fn a_primary_sends_its_pni_identity_only_with_a_pni() {
    let numberless = sent_by_primary(
        ServiceCredentials {
            pni: None,
            phonenumber: None,
            ..credentials()
        },
        Some(SALT),
    );
    assert_eq!(numberless.auth_credential_salt, Some(SALT.to_vec()));
    assert_eq!(numberless.pni, None);
    assert_eq!(numberless.pni_binary, None);
    assert_eq!(numberless.pni_identity_key_public, None);
    assert_eq!(numberless.pni_identity_key_private, None);
    assert_eq!(numberless.number, None);
    assert_eq!(numberless.aci.as_deref(), Some(&*ACI.to_string()));

    let numbered = sent_by_primary(
        ServiceCredentials {
            pni: Some(PNI),
            ..credentials()
        },
        None,
    );
    assert_eq!(numbered.auth_credential_salt, None);
    assert_eq!(numbered.pni.as_deref(), Some(&*PNI.to_string()));
    assert!(numbered.pni_identity_key_public.is_some());
    assert!(numbered.pni_identity_key_private.is_some());
    assert_eq!(numbered.number.as_deref(), Some("+15550100"));
}

/// A refused link request ends the link with the server's reason.
#[test]
fn refused_link_request_ends_the_link() {
    let primary = Primary::new(false);
    let linked = link_to(&primary, Primary::message, Answer::status(409));
    assert!(
        matches!(
            linked.ended,
            Err(ProvisioningError::ServiceError(
                ServiceError::DeviceCapabilityDowngrade
            ))
        ),
        "{:?}",
        linked.ended
    );
    assert!(linked.request.is_some());
    assert!(linked.registration.is_none());
}

/// A client that drives the steps makes its keys itself, to commit them before
/// the link call or an upload, so the generator is public. The keys are in the
/// store when it returns, made at the caller's time.
#[test]
fn replenish_pre_keys_works_from_outside_the_crate() {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let mut store = LocalStore::new(identity, 1);
    let (pre_keys, signed, pq_pre_keys, last_resort) = replenish_pre_keys(
        &mut store,
        &mut rng,
        &ManualClock::default(),
        &identity,
        true,
        0,
        0,
    )
    .now_or_never()
    .expect("the store doesn't wait")
    .unwrap();
    assert!(pre_keys.is_empty());
    assert!(pq_pre_keys.is_empty());
    let last_resort = last_resort.expect("requested");

    let created = Timestamp::from_epoch_millis(1_700_000_000_000);
    assert_eq!(signed.timestamp().unwrap(), created);
    assert_eq!(last_resort.timestamp().unwrap(), created);
    let stored = store
        .get_signed_pre_key(signed.id().unwrap())
        .now_or_never()
        .expect("the store doesn't wait")
        .unwrap();
    assert_eq!(stored.serialize().unwrap(), signed.serialize().unwrap());
    let stored = store
        .get_kyber_pre_key(last_resort.id().unwrap())
        .now_or_never()
        .expect("the store doesn't wait")
        .unwrap();
    assert_eq!(
        stored.serialize().unwrap(),
        last_resort.serialize().unwrap()
    );
}

// The link and `replenish_pre_keys` make one signed and one last-resort Kyber
// prekey per identity, which `LocalStore` keeps in libsignal's in-memory
// store; they ask the stores nothing else.

#[async_trait(?Send)]
impl PreKeysStore for LocalStore {
    async fn next_pre_key_id(&self) -> StoreResult<u32> {
        Ok(1)
    }

    async fn next_signed_pre_key_id(&self) -> StoreResult<u32> {
        Ok(1)
    }

    async fn next_pq_pre_key_id(&self) -> StoreResult<u32> {
        Ok(1)
    }

    async fn signed_pre_keys_count(&self) -> StoreResult<usize> {
        unreachable!("the link counts no keys")
    }

    async fn kyber_pre_keys_count(&self, _: bool) -> StoreResult<usize> {
        unreachable!("the link counts no keys")
    }

    async fn signed_prekey_id(&self) -> StoreResult<Option<SignedPreKeyId>> {
        unreachable!("the link counts no keys")
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> StoreResult<Option<KyberPreKeyId>> {
        unreachable!("the link counts no keys")
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for LocalStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> StoreResult<()> {
        self.save_kyber_pre_key(id, record).await
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> StoreResult<Vec<KyberPreKeyRecord>> {
        unreachable!("the link loads no keys")
    }

    async fn remove_kyber_pre_key(
        &mut self,
        _: KyberPreKeyId,
    ) -> StoreResult<()> {
        unreachable!("the link removes no keys")
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> StoreResult<()> {
        unreachable!("the link marks no keys")
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
    ) -> StoreResult<()> {
        unreachable!("the link deletes no keys")
    }
}
