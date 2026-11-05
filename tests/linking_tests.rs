//! `PUT /v1/devices/link`, and an account without a phone number in the
//! requests that follow a link.

mod common;

use base64::prelude::*;
use libsignal_service::{
    pre_keys::{KyberPreKeyEntity, SignedPreKeyEntity},
    push_service::{
        linking::{LinkAccountAttributes, LinkRequest},
        HttpAuth, ServiceError, ERROR_BODY_LIMIT,
    },
    websocket::{
        account::{AccountAttributes, WhoAmIResponse},
        registration::DeviceActivationRequest,
    },
};
use uuid::Uuid;

use common::*;

/// A link request for an account without a phone number.
fn numberless_request() -> LinkRequest {
    LinkRequest {
        verification_code: "code".into(),
        account_attributes: LinkAccountAttributes {
            fetches_messages: true,
            name: "name".into(),
            registration_id: 11,
            pni_registration_id: None,
            capabilities: [
                ("optionalPhoneNumber".to_owned(), true),
                ("spqr".to_owned(), true),
            ]
            .into(),
        },
        device_activation_request: DeviceActivationRequest {
            aci_signed_pre_key: SignedPreKeyEntity {
                key_id: 1,
                public_key: vec![5; 33],
                signature: vec![6; 64],
            },
            aci_pq_last_resort_pre_key: KyberPreKeyEntity {
                key_id: 2,
                public_key: vec![7; 1569],
                signature: vec![8; 64],
            },
            pni: None,
        },
    }
}

fn auth() -> HttpAuth {
    HttpAuth {
        username: ACI.to_string(),
        password: "link password".into(),
    }
}

/// A 422 is the server finding the request invalid, a bug of the caller's
/// (bad prekey signatures, PNI keys on an account without a PNI): its own
/// error, with what the server said, never a capability or rate error.
#[tokio::test]
async fn status_422_is_its_own_error() {
    let (mut service, transport) = push_service();

    // The controller's own 422s have no body.
    transport.answer(Answer::status(422));
    match service.link_device(&numberless_request(), auth()).await {
        Err(ServiceError::InvalidLinkRequest { body }) => assert_eq!(body, ""),
        other => panic!("{other:?}"),
    }

    // Bean validation says what failed.
    let errors = r#"{"errors":["deviceActivationRequest must not be null"]}"#;
    transport.answer(Answer::body(422, errors));
    match service.link_device(&numberless_request(), auth()).await {
        Err(ServiceError::InvalidLinkRequest { body }) => {
            assert_eq!(body, errors)
        },
        other => panic!("{other:?}"),
    }

    // What it said is kept up to the limit.
    transport.answer(Answer::body(422, vec![b'x'; ERROR_BODY_LIMIT + 10]));
    match service.link_device(&numberless_request(), auth()).await {
        Err(ServiceError::InvalidLinkRequest { body }) => {
            assert_eq!(body.len(), ERROR_BODY_LIMIT)
        },
        other => panic!("{other:?}"),
    }

    // The request omitted the PNI's fields rather than sending them null.
    let body: serde_json::Value =
        serde_json::from_slice(&transport.take_seen()[0].body).unwrap();
    assert_eq!(
        body["accountAttributes"]["capabilities"],
        serde_json::json!({ "optionalPhoneNumber": true, "spqr": true })
    );
    let request = body.as_object().unwrap();
    let attributes = body["accountAttributes"].as_object().unwrap();
    assert!(!request.contains_key("pniSignedPreKey"), "{body}");
    assert!(!request.contains_key("pniPqLastResortPreKey"), "{body}");
    assert!(!attributes.contains_key("pniRegistrationId"), "{body}");
}

/// A link without a PNI in the answer, as the server answers for an account
/// without a phone number (`LinkDeviceResponse(uuid, Optional<UUID> pni,
/// deviceId)`), and with `"pni": null`.
#[tokio::test]
async fn a_link_response_may_have_no_pni() {
    let (mut service, transport) = push_service();
    for answer in [
        serde_json::json!({ "uuid": ACI, "deviceId": 3 }),
        serde_json::json!({ "uuid": ACI, "pni": null, "deviceId": 3 }),
    ] {
        transport.answer(Answer::json(200, answer));
        let response = service
            .link_device(&numberless_request(), auth())
            .await
            .unwrap();
        assert_eq!((response.aci, response.pni), (ACI, None));
        assert_eq!(u8::from(response.device_id), 3);
    }
}

/// `GET /v1/accounts/whoami` of an account without a phone number (Signal-Server
/// `AccountIdentityResponse`): no number, no PNI, and its salt.
#[test]
fn whoami_of_a_numberless_account() {
    let whoami: WhoAmIResponse = serde_json::from_str(
        &serde_json::json!({
            "uuid": ACI,
            "number": null,
            "pni": null,
            "usernameHash": null,
            "usernameLinkHandle": null,
            "storageCapable": true,
            "entitlements": {},
            "authCredentialSalt": BASE64_STANDARD.encode([0x5a; 16]),
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(whoami.aci, ACI);
    assert_eq!(whoami.number, None);
    assert_eq!(whoami.pni, None);
    assert_eq!(whoami.auth_credential_salt, Some(vec![0x5a; 16]));
    assert!(!format!("{whoami:?}").contains("auth_credential_salt"));

    let pni = Uuid::from_u128(9);
    let whoami: WhoAmIResponse = serde_json::from_str(
        &serde_json::json!({ "uuid": ACI, "number": "+15550100", "pni": pni })
            .to_string(),
    )
    .unwrap();
    assert_eq!(whoami.number, Some("+15550100".parse().unwrap()));
    assert_eq!(whoami.pni, Some(pni));
    assert_eq!(whoami.auth_credential_salt, None);
}

/// The attributes of a device on an account without a phone number: the
/// caller's capabilities, which replace the device's on the server, and a
/// `null` PNI registration id, as Signal-Desktop sends it.
#[test]
fn account_attributes_of_a_numberless_account() {
    let attributes = AccountAttributes {
        registration_id: 11,
        voice: false,
        video: false,
        fetches_messages: true,
        registration_lock: None,
        unidentified_access_key: None,
        unrestricted_unidentified_access: false,
        discoverable_by_phone_number: false,
        capabilities: Some(
            [
                ("optionalPhoneNumber".to_owned(), true),
                ("spqr".to_owned(), true),
            ]
            .into(),
        ),
        name: None,
        pni_registration_id: None,
        recovery_password: None,
    };
    let json = serde_json::to_value(&attributes).unwrap();
    assert_eq!(
        json["capabilities"],
        serde_json::json!({ "optionalPhoneNumber": true, "spqr": true })
    );
    assert_eq!(json["pniRegistrationId"], serde_json::Value::Null);
    assert!(json.as_object().unwrap().contains_key("pniRegistrationId"));
}
