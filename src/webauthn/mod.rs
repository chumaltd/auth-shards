use base64::prelude::*;
use tokio_postgres::{types::Type, row::Row};
use log::{debug, error};
use pg_pool::{pg, pgr};
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{
        CredentialID, Passkey, DiscoverableKey,
        CreationChallengeResponse,
        RequestChallengeResponse,
        PasskeyRegistration, DiscoverableAuthentication, AuthenticationResult,
        PublicKeyCredential, RegisterPublicKeyCredential
    }
};
use crate::AuthType;

#[derive(Error, Debug, PartialEq)]
pub enum WebAuthnError {
    #[error("db access aborted")]
    Db,
    #[error("cannot add keys for the user")]
    Exceeded,
    #[error("condition unmet")]
    Rejected,
    #[error("cannot be converted")]
    Serde,
    #[error("no ID registered")]
    NoIdRegistered,
}

pub async fn generate_challenge_register(
    wa: &Webauthn,
    uid: Uuid,
    max_count: u8,
) -> Result<(CreationChallengeResponse, String), WebAuthnError> {
    let row = pgr::query_one(r#"SELECT u.name, u.email, count(w.id)::smallint AS keys
         FROM users u LEFT JOIN webauthns w on u.id = w.user_id
         where u.id = $1 group by u.id"#, &[&uid]).await
        .map_err(|_e| WebAuthnError::NoIdRegistered)?;
    if row.get::<_, i16>("keys") >= max_count as i16 {
        return Err(WebAuthnError::Exceeded);
    }

    let uname = row.get::<_, String>("email");
    let _webauthn_id = uname.as_bytes().to_vec();
    let udisp = row.get::<_, String>("name");
    let credentials = list_cred_ids(&uid).await;

    let (challenge_res, reg_state) = wa.start_passkey_registration(uid, &uname, &udisp, credentials)
        .map_err(|e| {
            debug!("{:?}", e);
            WebAuthnError::Rejected
        })?;
    // NOTE: feature danger-allow-state-serialisation required
    let reg_json = serde_json::to_string(&reg_state)
        .map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, reg_json))
}

pub async fn try_generate_passkey(
    wa: &Webauthn,
    reg: &RegisterPublicKeyCredential,
    reg_json: &str
) -> Result<Passkey, WebAuthnError> {
    let registration_st: PasskeyRegistration = serde_json::from_str(&reg_json)
        .map_err(|_e| WebAuthnError::Serde)?;

    wa.finish_passkey_registration(reg, &registration_st)
        .map_err(|e| {
            debug!("{:?}", e);
            WebAuthnError::Rejected
        })
}

pub async fn register_passkey(
    uid: &Uuid,
    pass_key: &Passkey,
    device_name: &str,
    max_count: u8
) -> Result<(), WebAuthnError> {
    let passkey_json = serde_json::to_value(&pass_key)
        .map_err(|e| {
            error!("{:?}", e);
            WebAuthnError::Serde
        })?;
    insert_passkey(
        &pass_key.cred_id().as_slice(),
        &uid,
        &passkey_json,
        &device_name,
        max_count as i8
    ).await
}

pub async fn insert_passkey(
    id: &[u8],
    uid: &Uuid,
    passkey_json: &serde_json::Value,
    device_name: &str,
    max_count: i8
) -> Result<(), WebAuthnError> {
    let rows = pg::query(r#"insert into webauthns
        (user_id, id, credential, description)
        select u.id, $2, $3, $4 from users u
        left join webauthns w on u.id = w.user_id
        where u.id = $1
        group by u.id having count(w.id) < $5
        returning id"#,
        &[&uid, &id, &passkey_json, &device_name, &(max_count as i64)])
        .await
        .map_err(|e| {
            error!("insert_passkey: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::Exceeded);
    }

    Ok(())
}

pub async fn delete_passkey(
    id: &str,
    uid: &Uuid,
) -> Result<(), WebAuthnError> {
    let id_bytes: Vec<u8> = BASE64_URL_SAFE_NO_PAD.decode(id)
        .map_err(|_e| WebAuthnError::Serde)?;

    let rows = pg::query(
        include_str!("delete_passkey.sql"),
        &[&id_bytes, &uid]).await
        .map_err(|e| {
            error!("delete_passkey: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::Rejected);
    }

    Ok(())
}

pub fn can_delete_passkey(passkey_count: usize, via: &AuthType) -> bool {
    if *via == AuthType::Unknown || *via == AuthType::PasswordWeakUnmet {
        return false;
    }

    match passkey_count {
        1 => (),
        0 => return false,
        _ => return true,
    };

    match via {
        AuthType::PassKey => false,
        AuthType::Mail => false,
        _ => true
    }
}

pub async fn generate_challenge_authentication(
    wa: &Webauthn,
    email: Option<&str>
) -> Result<(RequestChallengeResponse, String), WebAuthnError> {
    if email.is_none() {
        return generate_challenge_authentication_discoverable(wa).await;
    }

    let email = email.unwrap();
    let rows = pgr::query_pp(sql_list_credentials(),
                             &[Type::VARCHAR], &[&email]).await
        .map_err(|e| {
            error!("generate_challenge_authentication: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered)
    }

    let credentials: Vec<Passkey> = rows.iter()
        .map(|row| {
            serde_json::from_value(row.get::<_, serde_json::Value>("credential"))
                .map_err(|_e| WebAuthnError::Serde).unwrap()
        }).collect();

    let (challenge_res, auth_state) = wa.start_passkey_authentication(&credentials)
        .map_err(|_e| WebAuthnError::Rejected)?;
    let auth_json = serde_json::to_string(&auth_state)
        .map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, auth_json))
}

async fn generate_challenge_authentication_discoverable(
    wa: &Webauthn,
) -> Result<(RequestChallengeResponse, String), WebAuthnError> {
    let (challenge_res, auth_state) = wa.start_discoverable_authentication()
        .map_err(|_e| WebAuthnError::Rejected)?;
    let auth_json = serde_json::to_string(&auth_state)
        .map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, auth_json))
}

pub async fn authenticate_passkey(
    wa: &Webauthn,
    rsp: &PublicKeyCredential,
    auth_json: &str,
) -> Result<(AuthenticationResult, Row), WebAuthnError> {
    let auth_st: DiscoverableAuthentication = serde_json::from_str(&auth_json)
        .map_err(|e| {
            debug!("Cannot parse PasskeyAuthentication: {:?}", &e);
            WebAuthnError::Serde
        })?;

    let (_uuid, raw_id) = wa.identify_discoverable_authentication(rsp)
        .map_err(|e| {
            error!("cannot extract discoverable key id: {:?}", &e);
            WebAuthnError::Serde
        })?;

    let rows = pgr::query_pp(sql_find_user_by_credential(),
                             &[Type::BYTEA], &[&raw_id]).await
        .map_err(|e| {
            error!("webauthn::authenticate: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered);
    }

    let cred_str = rows[0].get::<_, serde_json::Value>("credential");
    let cred: DiscoverableKey = serde_json::from_value(cred_str.clone())
        .map_err(|e| {
            debug!("Stored credential broken: {:?}", &e);
            WebAuthnError::Serde
        })?;
    let auth_result = wa.finish_discoverable_authentication(&rsp, auth_st, &vec![cred.into()])
        .map_err(|e| {
            debug!("Passkey auth err: {:?}", &e);
            WebAuthnError::Rejected
        })?;
    debug!("AuthenticationResult reported internal count: {:?}", auth_result.counter());
    if ! auth_result.user_verified() {
        debug!("AuthenticationResult reported not user_verified");
        return Err(WebAuthnError::Rejected);
    }

    Ok((auth_result, rows[0].clone()))
}

// NOTE: If hard_pass is not set, abort silently.
pub async fn try_update_passkey(
    passkey_json: serde_json::Value,
    auth_result: &AuthenticationResult,
    hard_pass: bool
) -> Result<(), WebAuthnError> {
    if ! auth_result.needs_update() { return Ok(()); }

    let try_passkey: Result<Passkey, _> = serde_json::from_value(passkey_json);
    if ! hard_pass && try_passkey.is_err() { return Ok(()); }

    let mut passkey = try_passkey.map_err(|e| {
        error!("Stored credential broken: {:?}", &e);
        WebAuthnError::Serde
    })?;
    let res = passkey.update_credential(&auth_result);
    match res {
        None => return match hard_pass {
            true => Err(WebAuthnError::Serde),
            false => Ok(())
        },
        Some(false) => return Ok(()),
        _ => ()
    };

    let try_serialized = serde_json::to_value(&passkey);
    if ! hard_pass && try_serialized.is_err() { return Ok(()); }

    let serialized = try_serialized.map_err(|e| {
        error!("Passkey cannot be serialized: {:?}", e);
        WebAuthnError::Serde
    })?;
    let try_update = pg::execute(r#"UPDATE webauthns
                  SET credential = $1, updated_at = now()
                  WHERE id = $2"#, &[
                           &serialized,
                           &auth_result.cred_id().as_slice()
                  ]).await;
    if ! hard_pass && try_update.is_err() { return Ok(()); }

    try_update.map(|_res| ())
        .map_err(|e| {
            error!("Passkey update: {e}");
            WebAuthnError::Db
        })
}

async fn list_cred_ids(uid: &Uuid) -> Option<Vec<CredentialID>> {
    let rows = pgr::query(r#"SELECT id FROM webauthns
       WHERE user_id = $1"#, &[&uid]).await.ok()?;
    if rows.is_empty() { return None }

    Some(rows.iter().map(|row| {
        let cred_id = row.get::<_, Vec<u8>>("id");
        cred_id.try_into()
            .unwrap_or(CredentialID::from(Vec::<u8>::new()))
    })
         .collect())
}

fn sql_list_credentials<'a>() -> &'a str {
    r#"SELECT u.email, w.credential FROM users u
         INNER JOIN webauthns w ON w.user_id = u.id
         WHERE u.email = $1"#
}

fn sql_find_user_by_credential<'a>() -> &'a str {
    r#"SELECT u.id AS uid, u.org_id AS oid, u.superuser AS su,
         w.credential, coalesce(o.hard_pass, false) AS hard_pass
         FROM webauthns w
         INNER JOIN users u ON u.id = w.user_id
         LEFT JOIN orgs o ON o.id = u.org_id
         WHERE w.id = $1 LIMIT 1"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_delete_passkey() {
        // Cannot delete when ambiguous authentication state
        assert_eq!(false, can_delete_passkey(0, &AuthType::Unknown));
        assert_eq!(false, can_delete_passkey(1, &AuthType::Unknown));
        assert_eq!(false, can_delete_passkey(2, &AuthType::Unknown));
        assert_eq!(false, can_delete_passkey(0, &AuthType::PasswordWeakUnmet));
        assert_eq!(false, can_delete_passkey(1, &AuthType::PasswordWeakUnmet));
        assert_eq!(false, can_delete_passkey(2, &AuthType::PasswordWeakUnmet));

        // Cannot delete when no passkeys
        assert_eq!(false, can_delete_passkey(0, &AuthType::PasswordWeak));
        assert_eq!(false, can_delete_passkey(0, &AuthType::PassKey));

        // Can delete when 1 passkey w/other identities
        assert_eq!(true, can_delete_passkey(1, &AuthType::PasswordStrong));
        assert_eq!(true, can_delete_passkey(1, &AuthType::PasswordWeak));
        assert_eq!(true, can_delete_passkey(1, &AuthType::OpenidGoog));
        assert_eq!(true, can_delete_passkey(1, &AuthType::AccessToken));
        assert_eq!(false, can_delete_passkey(1, &AuthType::Mail));
        assert_eq!(false, can_delete_passkey(1, &AuthType::PassKey));

        // Can delete when 2 passkeys
        assert_eq!(true, can_delete_passkey(2, &AuthType::PasswordWeak));
        assert_eq!(true, can_delete_passkey(2, &AuthType::PassKey));
        assert_eq!(true, can_delete_passkey(2, &AuthType::Mail));
    }
}
