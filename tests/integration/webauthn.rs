use crate::common::{truncate, setup_user};
use base64::prelude::*;
use pg_pool::pg;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::Url
};

use auth_shards::webauthn::{
    WebAuthnError,
    generate_challenge_register,
    generate_challenge_authentication,
    insert_passkey,
    delete_password_on_register,
    delete_passkey
};

#[tokio::test]
async fn it_generates_challenge_register() {
    truncate().await;

    let wa = create_webauthn();
    let uid = Uuid::parse_str("018ff896-70f2-778d-a862-d8df3d694134").unwrap();
    let max_count: u8 = 1;

    let res1 = generate_challenge_register(&wa, uid.clone(), max_count).await;
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err(), WebAuthnError::NoIdRegistered);

    setup_user().await;
    let res2 = generate_challenge_register(&wa, uid.clone(), max_count).await;
    assert!(res2.is_ok());
    let (challenge, reg_state) = res2.unwrap();
    assert!(serde_json::to_string(&challenge).is_ok());
    assert!( ! reg_state.is_empty());

    insert_sample_passkey().await;
    let res3 = generate_challenge_register(&wa, uid.clone(), max_count).await;
    assert!(res3.is_err());
    assert_eq!(res3.unwrap_err(), WebAuthnError::Exceeded);

    let max_count: u8 = 2;
    let res4 = generate_challenge_register(&wa, uid.clone(), max_count).await;
    assert!(res4.is_ok());
    let (challenge2, reg_state2) = res4.unwrap();
    assert!(serde_json::to_string(&challenge2).is_ok());
    assert!( ! reg_state2.is_empty());

    truncate().await;
}

#[tokio::test]
async fn it_limits_inserting_keys() {
    truncate().await;

    let max_count: i8 = 2;
    let uid = Uuid::now_v7();
    let device_name = "test device";
    let passkey_json = json!({ "name": "dummy" });
    pg::execute("insert into users (id, name, email) values ($1, 'pass key', 'passkey@example.com')", &[&uid]).await.unwrap();

    let res1 = insert_passkey(&[1u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res1.is_ok());

    let row = pg::query_one("SELECT id, user_id, credential from webauthns where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row.get::<_, &[u8]>("id"), [1u8]);
    assert_eq!(row.get::<_, Uuid>("user_id"), uid);
    assert_eq!(row.get::<_, serde_json::Value>("credential"), passkey_json);
    let id_str = BASE64_URL_SAFE_NO_PAD.encode(&[1u8]);

    let res2 = insert_passkey(&[2u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res2.is_ok());

    let res3 = insert_passkey(&[3u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res3.is_err());
    assert_eq!(res3.unwrap_err(), WebAuthnError::Exceeded);

    let row2 = pg::query_one("SELECT count(id) from webauthns where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row2.get::<_, i64>(0), 2);

    let res4 = delete_passkey(&id_str, &uid).await;
    assert!(res4.is_ok());

    let res5 = insert_passkey(&[3u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res5.is_ok());

    let row3 = pg::query_one("SELECT count(id) from webauthns where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row3.get::<_, i64>(0), 2);

    truncate().await;
}

#[tokio::test]
async fn it_deletes_password_on_1st_register() {
    truncate().await;
    let uid = Uuid::now_v7();
    pg::execute("insert into users (id, name, email) values ($1, 'pass key', 'passkey@example.com')", &[&uid]).await.unwrap();

    // No ideneties yet
    let count1 = delete_password_on_register(&uid).await.unwrap();
    assert_eq!(count1, 0);

    pg::execute("insert into identities (user_id, digest_argon) values ($1, 'dummy_password_digest')", &[&uid]).await.unwrap();

    // No passkeys guards from password deletion
    let count2 = delete_password_on_register(&uid).await.unwrap();
    assert_eq!(count2, 0);

    let row1 = pg::query_one("select count(user_id) from identities where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row1.get::<_, i64>(0), 1);

    let max_count: i8 = 2;
    let device_name = "test device";
    let passkey_json = json!({ "name": "dummy" });

    insert_passkey(&[1u8], &uid, &passkey_json, &device_name, max_count).await.unwrap();

    // Normal deletion
    let count_normal = delete_password_on_register(&uid).await.unwrap();
    assert_eq!(count_normal, 1);

    let row2 = pg::query_one("select count(user_id) from identities where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row2.get::<_, i64>(0), 0);

    // No ideneties left
    let count4 = delete_password_on_register(&uid).await.unwrap();
    assert_eq!(count4, 0);

    insert_passkey(&[2u8], &uid, &passkey_json, &device_name, max_count).await.unwrap();
    pg::execute("insert into identities (user_id, digest_argon) values ($1, 'dummy_password_digest')", &[&uid]).await.unwrap();

    // Having >1 passkeys guards from password deletion
    let count5 = delete_password_on_register(&uid).await.unwrap();
    assert_eq!(count5, 0);

    let row3 = pg::query_one("select count(user_id) from identities where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row3.get::<_, i64>(0), 1);

    truncate().await;
}

#[tokio::test]
async fn it_guards_last_passkey_deletion() {
    truncate().await;
    let max_count: i8 = 2;
    let uid = Uuid::now_v7();
    let device_name = "test device";
    let passkey_json = json!({ "name": "dummy" });
    pg::execute("insert into users (id, name, email) values ($1, 'pass key', 'passkey@example.com')", &[&uid]).await.unwrap();
    let id_str = BASE64_URL_SAFE_NO_PAD.encode(&[1u8]);

    let res1 = insert_passkey(&[1u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res1.is_ok());

    let res15 = delete_passkey(&id_str, &uid).await;
    assert!(res15.is_err());
    assert_eq!(res15.unwrap_err(), WebAuthnError::Rejected);

    let res2 = insert_passkey(&[2u8], &uid, &passkey_json, &device_name, max_count).await;
    assert!(res2.is_ok());

    let res25 = delete_passkey(&id_str, &uid).await;
    assert!(res25.is_ok());

    let row = pg::query_one("SELECT id from webauthns where user_id = $1", &[&uid]).await.unwrap();
    assert_eq!(row.get::<_, &[u8]>("id"), [2u8]);

    truncate().await;
}

#[tokio::test]
async fn it_generates_challenge_authentication() {
    truncate().await;

    let wa = create_webauthn();

    // Discoverable authentication
    let res1 = generate_challenge_authentication(&wa, None).await;
    assert!(res1.is_ok());
    let (challenge, auth_state) = res1.unwrap();
    assert!(serde_json::to_string(&challenge).is_ok());
    assert!( ! auth_state.is_empty());

    // Passkey authentication
    setup_user().await;
    let email = "common@example.com";
    let res2 = generate_challenge_authentication(&wa, Some(email)).await;
    assert!(res2.is_err());
    assert_eq!(res2.unwrap_err(), WebAuthnError::NoIdRegistered);

    /* TODO: valid passkey for webauthn-rs v0.5 required
    insert_sample_passkey().await;
    let res3 = generate_challenge_authentication(&wa, Some(email)).await;
    assert!(res3.is_ok());
    let (challenge2, auth_state2) = res3.unwrap();
    assert!(serde_json::to_string(&challenge2).is_ok());
    assert!( ! auth_state2.is_empty());
    */

    truncate().await;
}


async fn insert_sample_passkey() {
    pg::execute("INSERT INTO webauthns (id, credential, user_id)
              VALUES ($1, $2, '018ff896-70f2-778d-a862-d8df3d694134')",
        &[&vec![20u8,155,80,76,89,36,70,91,24,29,145,81,89,40,184,74,167,144,182,192,98,106,56,226,167,234,196,242,156,213,42,200],
      &json!({"cred": {"key": {"EC_EC2": {
           "x":[48,57,158,151,89,214,123,55,99,153,51,57,11,120,153,198,220,109,25,196,147,41,71,181,92,197,218,19,9,113,241,73],
           "y":[0,232,83,131,222,111,6,49,6,237,144,18,41,167,222,105,118,158,119,152,22,228,252,185,251,80,205,168,150,108,158,150],
        "curve": "SECP256R1"}}, "type_": "ES256"},
        "counter": 1,
        "cred_id":[20,155,80,76,89,36,70,91,24,29,145,81,89,40,184,74,167,144,182,192,98,106,56,226,167,234,196,242,156,213,42,200],
        "verified": true,
        "registration_policy": "required"})]).await.unwrap();
}

pub fn create_webauthn () -> Webauthn {
    let origin = Url::parse("http://localhost/").expect("Invalid origin URL");
    let builder = WebauthnBuilder::new("localhost", &origin)
        .expect("Invalid configuration");
    builder.build().expect("Invalid configuration")
}
