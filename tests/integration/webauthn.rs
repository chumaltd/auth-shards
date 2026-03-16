use crate::common::{setup_user, setup};
use async_session::Session;
use base64::prelude::*;
use pg_pool::pg;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Passkey, Url}
};

use auth_shards::webauthn::{
    PasskeyRecord,
    WebAuthnError,
    generate_challenge_register,
    generate_challenge_authentication,
    insert_passkey,
    list_passkeys,
    rename_passkey,
    replace_passkey,
    delete_password_on_register,
    delete_passkey
};

crate::test! {
    async fn it_generates_challenge_register() {
        let _pool = setup().await;
        let wa = create_webauthn();
        let max_count: u8 = 1;
        let uid = Uuid::now_v7();

        let res1 = generate_challenge_register(&wa, true, uid.clone(), max_count).await;
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err(), WebAuthnError::NoIdRegistered);

        let (uid, _uname) = setup_user().await;
        let res2 = generate_challenge_register(&wa, true, uid.clone(), max_count).await;
        assert!(res2.is_ok());
        let (challenge, reg_state) = res2.unwrap();
        assert!(serde_json::to_string(&challenge).is_ok());
        assert!( ! reg_state.is_empty());

        insert_sample_passkey(&uid).await;
        let res3 = generate_challenge_register(&wa, true, uid.clone(), max_count).await;
        assert!(res3.is_err());
        assert_eq!(res3.unwrap_err(), WebAuthnError::Exceeded);

        let res35 = generate_challenge_register(&wa, false, uid.clone(), max_count).await;
        assert!(res35.is_ok());
        let (challenge_replace, reg_state_replace) = res35.unwrap();
        let challenge_replace_json = serde_json::to_value(&challenge_replace).unwrap();
        let duplicate_check_replace = challenge_replace_json.get("publicKey")
            .and_then(|v| v.get("excludeCredentials"))
            .and_then(|v| v.as_array());
        assert!(duplicate_check_replace.is_none() || duplicate_check_replace.unwrap().is_empty());
        assert!(!reg_state_replace.is_empty());

        let max_count: u8 = 2;
        let res4 = generate_challenge_register(&wa, true, uid.clone(), max_count).await;
        assert!(res4.is_ok());
        let (challenge2, reg_state2) = res4.unwrap();
        assert!(serde_json::to_string(&challenge2).is_ok());
        assert!( ! reg_state2.is_empty());

        let res5 = generate_challenge_register(&wa, false, uid.clone(), max_count).await;
        assert!(res5.is_ok());
        let (challenge3, reg_state3) = res5.unwrap();
        let challenge3_json = serde_json::to_value(&challenge3).unwrap();
        let duplicate_check = challenge3_json.get("publicKey")
            .and_then(|v| v.get("excludeCredentials"))
            .and_then(|v| v.as_array());
        assert!(duplicate_check.is_none() || duplicate_check.unwrap().is_empty());
        assert!(!reg_state3.is_empty());
    }

    async fn it_limits_inserting_keys() {
        let _pool = setup().await;
        let max_count: i8 = 2;
        let uid = Uuid::now_v7();
        let device_name = "test device";
        let passkey_json = json!({ "name": "dummy" });
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let cred_id_1 = Uuid::now_v7().into_bytes().to_vec();
        let cred_id_2 = Uuid::now_v7().into_bytes().to_vec();
        let cred_id_3 = Uuid::now_v7().into_bytes().to_vec();

        let res1 = insert_passkey(&cred_id_1, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res1.is_ok());

        let row = pg::query_one("SELECT id, user_id, credential from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row.get::<_, &[u8]>("id"), &cred_id_1[..]);
        assert_eq!(row.get::<_, Uuid>("user_id"), uid);
        assert_eq!(row.get::<_, serde_json::Value>("credential"), passkey_json);
        let id_str = BASE64_URL_SAFE_NO_PAD.encode(&cred_id_1);

        let res2 = insert_passkey(&cred_id_2, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res2.is_ok());

        let res3 = insert_passkey(&cred_id_3, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res3.is_err());
        assert_eq!(res3.unwrap_err(), WebAuthnError::Exceeded);

        let row2 = pg::query_one("SELECT count(id) from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row2.get::<_, i64>(0), 2);

        let res4 = delete_passkey(&id_str, &uid).await;
        assert!(res4.is_ok());

        let res5 = insert_passkey(&cred_id_3, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res5.is_ok());

        let row3 = pg::query_one("SELECT count(id) from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row3.get::<_, i64>(0), 2);
    }

    async fn it_rejects_duplicated_insert_passkey() {
        let _pool = setup().await;
        let max_count: i8 = 2;
        let uid = Uuid::now_v7();
        let device_name = "test device";
        let passkey_json = json!({ "name": "dummy" });
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let cred_id = Uuid::now_v7().into_bytes().to_vec();

        let res1 = insert_passkey(&cred_id, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res1.is_ok());

        let res2 = insert_passkey(&cred_id, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), WebAuthnError::Rejected);

        let row = pg::query_one("SELECT count(id) from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
    }

    async fn it_deletes_password_on_1st_register() {
        let _pool = setup().await;
        let uid = Uuid::now_v7();
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

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

        let cred_id_1 = Uuid::now_v7().into_bytes().to_vec();
        let cred_id_2 = Uuid::now_v7().into_bytes().to_vec();

        insert_passkey(&cred_id_1, &uid, &passkey_json, &device_name, max_count).await.unwrap();

        // Normal deletion
        let count_normal = delete_password_on_register(&uid).await.unwrap();
        assert_eq!(count_normal, 1);

        let row2 = pg::query_one("select count(user_id) from identities where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row2.get::<_, i64>(0), 0);

        // No ideneties left
        let count4 = delete_password_on_register(&uid).await.unwrap();
        assert_eq!(count4, 0);

        insert_passkey(&cred_id_2, &uid, &passkey_json, &device_name, max_count).await.unwrap();
        pg::execute("insert into identities (user_id, digest_argon) values ($1, 'dummy_password_digest')", &[&uid]).await.unwrap();

        // Having >1 passkeys guards from password deletion
        let count5 = delete_password_on_register(&uid).await.unwrap();
        assert_eq!(count5, 0);

        let row3 = pg::query_one("select count(user_id) from identities where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row3.get::<_, i64>(0), 1);
    }

    async fn it_guards_last_passkey_deletion() {
        let _pool = setup().await;
        let max_count: i8 = 2;
        let uid = Uuid::now_v7();
        let device_name = "test device";
        let passkey_json = json!({ "name": "dummy" });
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();
        let cred_id_1 = Uuid::now_v7().into_bytes().to_vec();
        let cred_id_2 = Uuid::now_v7().into_bytes().to_vec();
        let id_str = BASE64_URL_SAFE_NO_PAD.encode(&cred_id_1);

        let res1 = insert_passkey(&cred_id_1, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res1.is_ok());

        let res15 = delete_passkey(&id_str, &uid).await;
        assert!(res15.is_err());
        assert_eq!(res15.unwrap_err(), WebAuthnError::Rejected);

        let res2 = insert_passkey(&cred_id_2, &uid, &passkey_json, &device_name, max_count).await;
        assert!(res2.is_ok());

        let res25 = delete_passkey(&id_str, &uid).await;
        assert!(res25.is_ok());

        let row = pg::query_one("SELECT id from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row.get::<_, &[u8]>("id"), &cred_id_2[..]);
    }

    async fn it_replaces_passkey() {
        let _pool = setup().await;
        let max_count: u8 = 1;
        let uid = Uuid::now_v7();
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let old_cred_id = Uuid::now_v7().into_bytes().to_vec();
        let old_id_str = BASE64_URL_SAFE_NO_PAD.encode(&old_cred_id);
        let old_passkey_json = json!({ "name": "dummy" });
        insert_passkey(&old_cred_id, &uid, &old_passkey_json, "old device", max_count as i8).await.unwrap();

        let new_passkey = sample_passkey(Uuid::now_v7().into_bytes().to_vec());
        let mut session = Session::new();
        session.insert_raw("pk", old_id_str.clone());
        let res1 = replace_passkey(&mut session, &old_id_str, &uid, &new_passkey, "new device").await;
        assert!(res1.is_ok());

        let row = pg::query_one("SELECT id, description from webauthns where user_id = $1", &[&uid]).await.unwrap();
        assert_eq!(row.get::<_, &[u8]>("id"), new_passkey.cred_id().as_slice());
        assert_eq!(row.get::<_, String>("description"), "new device");
        assert_eq!(session.get_raw("pk").unwrap(), BASE64_URL_SAFE_NO_PAD.encode(new_passkey.cred_id().as_slice()));

        let res2 = replace_passkey(&mut session, &old_id_str, &uid, &new_passkey, "new device").await;
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), WebAuthnError::NoIdRegistered);
    }

    async fn it_rejects_replace_with_duplicated_new_id() {
        let _pool = setup().await;
        let max_count: u8 = 2;
        let uid = Uuid::now_v7();
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let old_cred_id = Uuid::now_v7().into_bytes().to_vec();
        let existing_cred_id = Uuid::now_v7().into_bytes().to_vec();
        let old_id_str = BASE64_URL_SAFE_NO_PAD.encode(&old_cred_id);
        let passkey_json = json!({ "name": "dummy" });
        insert_passkey(&old_cred_id, &uid, &passkey_json, "old device", max_count as i8).await.unwrap();
        insert_passkey(&existing_cred_id, &uid, &passkey_json, "existing device", max_count as i8).await.unwrap();

        let new_passkey = sample_passkey(existing_cred_id.clone());
        let mut session = Session::new();
        session.insert_raw("pk", old_id_str.clone());
        let res = replace_passkey(&mut session, &old_id_str, &uid, &new_passkey, "duplicated device").await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), WebAuthnError::Rejected);
        assert_eq!(session.get_raw("pk").unwrap(), old_id_str);

        let listed = list_passkeys(&uid).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, BASE64_URL_SAFE_NO_PAD.encode(&existing_cred_id));
        assert_eq!(listed[0].description, "existing device");
    }

    async fn it_lists_passkeys() {
        let _pool = setup().await;
        let uid = Uuid::now_v7();
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let cred_id_1 = Uuid::now_v7().into_bytes().to_vec();
        let cred_id_2 = Uuid::now_v7().into_bytes().to_vec();
        let passkey_json = json!({ "name": "dummy" });
        insert_passkey(&cred_id_1, &uid, &passkey_json, "first device", 5).await.unwrap();
        insert_passkey(&cred_id_2, &uid, &passkey_json, "second device", 5).await.unwrap();

        let listed = list_passkeys(&uid).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, BASE64_URL_SAFE_NO_PAD.encode(&cred_id_2));
        assert_eq!(listed[0].description, "second device");
        assert_eq!(listed[1].id, BASE64_URL_SAFE_NO_PAD.encode(&cred_id_1));
        assert_eq!(listed[1].description, "first device");
        assert!(listed.iter().all(|row: &PasskeyRecord| row.updated_at >= row.created_at));
    }

    async fn it_renames_passkey() {
        let _pool = setup().await;
        let uid = Uuid::now_v7();
        let email = format!("passkey-{uid}@example.com");
        pg::execute("insert into users (id, name, email) values ($1, 'pass key', $2)", &[&uid, &email]).await.unwrap();

        let cred_id = Uuid::now_v7().into_bytes().to_vec();
        let id_str = BASE64_URL_SAFE_NO_PAD.encode(&cred_id);
        let passkey_json = json!({ "name": "dummy" });
        insert_passkey(&cred_id, &uid, &passkey_json, "old label", 5).await.unwrap();

        let res1 = rename_passkey(&id_str, &uid, "new label").await;
        assert!(res1.is_ok());

        let listed = list_passkeys(&uid).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].description, "new label");

        let res2 = rename_passkey(&id_str, &uid, "   ").await;
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), WebAuthnError::Rejected);

        let res3 = rename_passkey(&BASE64_URL_SAFE_NO_PAD.encode(Uuid::now_v7().into_bytes()), &uid, "x").await;
        assert!(res3.is_err());
        assert_eq!(res3.unwrap_err(), WebAuthnError::NoIdRegistered);
    }

    async fn it_generates_challenge_authentication() {
        let _pool = setup().await;
        let wa = create_webauthn();

        // Discoverable authentication
        let res1 = generate_challenge_authentication(&wa, None).await;
        assert!(res1.is_ok());
        let (challenge, auth_state) = res1.unwrap();
        assert!(serde_json::to_string(&challenge).is_ok());
        assert!( ! auth_state.is_empty());

        // Passkey authentication
        let (_uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        let res2 = generate_challenge_authentication(&wa, Some(&email)).await;
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), WebAuthnError::NoIdRegistered);

        /* TODO: valid passkey for webauthn-rs v0.5 required
        insert_sample_passkey(&_uid).await;
        let res3 = generate_challenge_authentication(&wa, Some(&email)).await;
        assert!(res3.is_ok());
        let (challenge2, auth_state2) = res3.unwrap();
        assert!(serde_json::to_string(&challenge2).is_ok());
        assert!( ! auth_state2.is_empty());
        */
    }
}

async fn insert_sample_passkey(user_id: &Uuid) {
    let cred_id = Uuid::now_v7().into_bytes().to_vec();
    pg::execute("INSERT INTO webauthns (id, credential, user_id)
              VALUES ($1, $2, $3)",
        &[&cred_id,
      &json!({"cred": {"key": {"EC_EC2": {
           "x":[48,57,158,151,89,214,123,55,99,153,51,57,11,120,153,198,220,109,25,196,147,41,71,181,92,197,218,19,9,113,241,73],
           "y":[0,232,83,131,222,111,6,49,6,237,144,18,41,167,222,105,118,158,119,152,22,228,252,185,251,80,205,168,150,108,158,150],
        "curve": "SECP256R1"}}, "type_": "ES256"},
        "counter": 1,
        "cred_id":[20,155,80,76,89,36,70,91,24,29,145,81,89,40,184,74,167,144,182,192,98,106,56,226,167,234,196,242,156,213,42,200],
        "verified": true,
        "registration_policy": "required"}), user_id]).await.unwrap();
}

fn sample_passkey(cred_id: Vec<u8>) -> Passkey {
    serde_json::from_value(json!({
        "cred": {
            "cred_id": cred_id,
            "cred": {
                "type_": "ES256",
                "key": { "EC_EC2": {
                    "curve": "SECP256R1",
                    "x": [48,57,158,151,89,214,123,55,99,153,51,57,11,120,153,198,220,109,25,196,147,41,71,181,92,197,218,19,9,113,241,73],
                    "y": [0,232,83,131,222,111,6,49,6,237,144,18,41,167,222,105,118,158,119,152,22,228,252,185,251,80,205,168,150,108,158,150]
                } }
            },
            "counter": 1,
            "user_verified": true,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {
                "data": "None",
                "metadata": { "None": null }
            },
            "attestation_format": "none"
        }
    })).unwrap()
}

pub fn create_webauthn() -> Webauthn {
    let origin = Url::parse("http://localhost/").expect("Invalid origin URL");
    let builder = WebauthnBuilder::new("localhost", &origin).expect("Invalid configuration");
    builder.build().expect("Invalid configuration")
}
