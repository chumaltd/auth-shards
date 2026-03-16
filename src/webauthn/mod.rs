use crate::{
    AuthType, RegisterMode,
    account::{AccountError, login_trace},
    session::sync_passkey_replace,
};
use async_session::Session;
use base64::prelude::*;
use chrono::NaiveDateTime;
use log::{debug, error};
use pg_pool::{pg, pgr};
use serde::{Deserialize, de::IgnoredAny};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_postgres::{row::Row, types::Type};
use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{
        AuthenticationResult, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
        DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential, RequestChallengeResponse,
    },
};

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

#[derive(Debug, PartialEq)]
pub struct PasskeyRecord {
    pub id: String,
    pub description: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

// Generate a registration challenge for either ordinary registration (`check_duplicate = true`)
// or replace flows (`check_duplicate = false`).
pub async fn generate_challenge_register(
    wa: &Webauthn,
    check_duplicate: bool,
    uid: Uuid,
    max_count: u8,
) -> Result<(CreationChallengeResponse, String), WebAuthnError> {
    generate_challenge_register_with_mode(
        wa,
        check_duplicate,
        uid,
        max_count,
        RegisterMode::PlatformPasskey,
    )
    .await
}

pub async fn generate_challenge_register_with_mode(
    wa: &Webauthn,
    check_duplicate: bool,
    uid: Uuid,
    max_count: u8,
    mode: RegisterMode,
) -> Result<(CreationChallengeResponse, String), WebAuthnError> {
    let rows = pgr::query(
        r#"SELECT u.name, u.email, count(w.id)::smallint AS keys
         FROM users u LEFT JOIN webauthns w on u.id = w.user_id
         where u.id = $1 group by u.id"#,
        &[&uid],
    )
    .await
    .map_err(|e| {
        debug!("{:?}", e);
        WebAuthnError::Db
    })?;
    let row = rows.first().ok_or(WebAuthnError::NoIdRegistered)?;
    if check_duplicate && row.get::<_, i16>("keys") >= max_count as i16 {
        return Err(WebAuthnError::Exceeded);
    }

    let uname = row.get::<_, String>("email");
    let _webauthn_id = uname.as_bytes().to_vec();
    let udisp = row.get::<_, String>("name");
    let credentials = match check_duplicate {
        true => list_cred_ids(&uid).await,
        false => None,
    };

    let registration = match mode {
        RegisterMode::PlatformPasskey => {
            wa.start_passkey_registration(uid, &uname, &udisp, credentials)
        }
        RegisterMode::AndroidGooglePasswordManager => wa
            .start_google_passkey_in_google_password_manager_only_registration(
                uid,
                &uname,
                &udisp,
                credentials,
            ),
    };

    let (challenge_res, reg_state) = registration.map_err(|e| {
        debug!("{:?}", e);
        WebAuthnError::Rejected
    })?;
    // NOTE: feature danger-allow-state-serialisation required
    let reg_json = serde_json::to_string(&reg_state).map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, reg_json))
}

pub async fn try_generate_passkey(
    wa: &Webauthn,
    reg: &RegisterPublicKeyCredential,
    reg_json: &str,
) -> Result<Passkey, WebAuthnError> {
    let registration_st: PasskeyRegistration =
        serde_json::from_str(&reg_json).map_err(|_e| WebAuthnError::Serde)?;

    wa.finish_passkey_registration(reg, &registration_st)
        .map_err(|e| {
            debug!("{:?}", e);
            WebAuthnError::Rejected
        })
}

// Passkey { cred: Credential { attestation: ParsedAttestation { metadata: AttestationMetadata { ... } } } }
// Enums are externally tagged by default: {"Packed": {"aaguid": "..."}}
pub fn get_aaguid(passkey: &Passkey) -> Option<Uuid> {
    #[derive(Deserialize)]
    struct StoredPasskey {
        cred: StoredCredential,
    }

    #[derive(Deserialize)]
    struct StoredCredential {
        attestation: StoredAttestation,
    }

    #[derive(Deserialize)]
    struct StoredAttestation {
        metadata: Option<StoredAttestationMetadata>,
        data: Option<StoredAttestationData>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StoredAttestationMetadata {
        Tagged(StoredTaggedAttestationMetadata),
        Other(IgnoredAny),
    }

    #[derive(Deserialize)]
    struct StoredTaggedAttestationMetadata {
        #[serde(rename = "Packed")]
        packed: Option<StoredAaguidField>,
        #[serde(rename = "Tpm")]
        tpm: Option<StoredAaguidField>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StoredAttestationData {
        Tagged(StoredTaggedAttestationData),
        Other(IgnoredAny),
    }

    #[derive(Deserialize)]
    struct StoredTaggedAttestationData {
        #[serde(rename = "Basic")]
        basic: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    struct StoredAaguidField {
        aaguid: Option<Uuid>,
    }

    fn extract_aaguid_from_metadata(metadata: StoredAttestationMetadata) -> Option<Uuid> {
        match metadata {
            StoredAttestationMetadata::Tagged(metadata) => metadata
                .packed
                .and_then(|packed| packed.aaguid)
                .or_else(|| metadata.tpm.and_then(|tpm| tpm.aaguid)),
            StoredAttestationMetadata::Other(_) => None,
        }
    }

    fn extract_aaguid_from_attestation_data(data: StoredAttestationData) -> Option<Uuid> {
        let cert = match data {
            StoredAttestationData::Tagged(data) => {
                data.basic.and_then(|basic| basic.into_iter().next())?
            }
            StoredAttestationData::Other(_) => return None,
        };
        let cert = BASE64_URL_SAFE_NO_PAD.decode(cert).ok()?;
        let (_, cert) = x509_parser::parse_x509_certificate(&cert).ok()?;

        extract_aaguid_from_x509(&cert)
    }

    let passkey: StoredPasskey =
        serde_json::from_value(serde_json::to_value(passkey).ok()?).ok()?;

    passkey
        .cred
        .attestation
        .metadata
        .and_then(extract_aaguid_from_metadata)
        .or_else(|| {
            passkey
                .cred
                .attestation
                .data
                .and_then(extract_aaguid_from_attestation_data)
        })
}

fn extract_aaguid_from_x509(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<Uuid> {
    const FIDO_AAGUID_EXTENSION_OID: &str = "1.3.6.1.4.1.45724.1.1.4";

    cert.extensions().iter().find_map(|ext| {
        if ext.oid.to_id_string() != FIDO_AAGUID_EXTENSION_OID {
            return None;
        }

        parse_der_octet_string(ext.value).and_then(|bytes| Uuid::from_slice(bytes).ok())
    })
}

fn parse_der_octet_string(bytes: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x04 {
        return None;
    }

    let (&len_first, rest) = rest.split_first()?;
    let (len, value) = if len_first & 0x80 == 0 {
        (len_first as usize, rest)
    } else {
        let len_len = (len_first & 0x7f) as usize;
        if len_len == 0 || len_len > std::mem::size_of::<usize>() || rest.len() < len_len {
            return None;
        }

        let len = rest[..len_len]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | (*byte as usize));
        (len, &rest[len_len..])
    };

    if value.len() != len {
        return None;
    }

    Some(value)
}

// Callers may use helpers such as `ClientContext::device_name` to build `device_note`,
// This layer stores the provided value as-is.
pub async fn register_passkey(
    uid: &Uuid,
    pass_key: &Passkey,
    device_note: &str,
    max_count: u8,
) -> Result<(), WebAuthnError> {
    let passkey_json = serde_json::to_value(&pass_key).map_err(|e| {
        error!("{:?}", e);
        WebAuthnError::Serde
    })?;
    insert_passkey(
        &pass_key.cred_id().as_slice(),
        &uid,
        &passkey_json,
        device_note,
        max_count as i8,
    )
    .await
}

pub async fn insert_passkey(
    id: &[u8],
    uid: &Uuid,
    passkey_json: &serde_json::Value,
    device_name: &str,
    max_count: i8,
) -> Result<(), WebAuthnError> {
    let row = pg::query_one(
        r#"WITH existing AS (
            SELECT count(w.id) AS key_count
              FROM users u
              LEFT JOIN webauthns w ON u.id = w.user_id
             WHERE u.id = $1
             GROUP BY u.id
        ),
        inserted AS (
            INSERT INTO webauthns (user_id, id, credential, description)
            SELECT $1, $2, $3, $4
             WHERE EXISTS (SELECT 1 FROM existing WHERE key_count < $5)
            ON CONFLICT (id) DO NOTHING
            RETURNING id
        )
        SELECT
            COALESCE((SELECT key_count FROM existing), 0) AS key_count,
            (SELECT count(*) FROM inserted) AS inserted_count"#,
        &[&uid, &id, &passkey_json, &device_name, &(max_count as i64)],
    )
    .await
    .map_err(|e| {
        error!("insert_passkey: {e}");
        WebAuthnError::Db
    })?;
    let key_count = row.get::<_, i64>("key_count");
    let inserted_count = row.get::<_, i64>("inserted_count");
    if inserted_count == 0 && key_count >= max_count as i64 {
        return Err(WebAuthnError::Exceeded);
    }
    if inserted_count == 0 {
        return Err(WebAuthnError::Rejected);
    }

    Ok(())
}

// Replace an existing passkey with `new_key`.
// `new_key` is expected to come from a valid WebAuthn registration ceremony;
// session/challenge binding is guarded by the upper layer and `webauthn_rs`.
pub async fn replace_passkey(
    session_ref: &mut Session,
    delete_id: &str,
    uid: &Uuid,
    new_key: &Passkey,
    device_note: &str,
) -> Result<(), WebAuthnError> {
    let delete_id_bytes: Vec<u8> = BASE64_URL_SAFE_NO_PAD
        .decode(delete_id)
        .map_err(|_e| WebAuthnError::Serde)?;

    let passkey_json = serde_json::to_value(&new_key).map_err(|e| {
        error!("{:?}", e);
        WebAuthnError::Serde
    })?;

    let row = pg::query_one(
        r#"WITH deleted AS (
               DELETE FROM webauthns
               WHERE user_id = $1 AND id = $2
               RETURNING user_id
           ),
           inserted AS (
               INSERT INTO webauthns (user_id, id, credential, description)
               SELECT u.id, $3, $4, $5
                 FROM users u
                WHERE u.id = $1
                  AND EXISTS (SELECT 1 FROM deleted)
               ON CONFLICT (id) DO NOTHING
               RETURNING id
           )
           SELECT
               (SELECT count(*) FROM deleted) AS deleted_count,
               (SELECT count(*) FROM inserted) AS inserted_count"#,
        &[
            &uid,
            &delete_id_bytes,
            &new_key.cred_id().as_slice(),
            &passkey_json,
            &device_note,
        ],
    )
    .await
    .map_err(|e| {
        error!("replace_passkey: {e}");
        WebAuthnError::Db
    })?;
    let deleted_count = row.get::<_, i64>("deleted_count");
    let inserted_count = row.get::<_, i64>("inserted_count");
    if deleted_count == 0 {
        return Err(WebAuthnError::NoIdRegistered);
    }
    if inserted_count == 0 {
        return Err(WebAuthnError::Rejected);
    }

    let new_id = BASE64_URL_SAFE_NO_PAD.encode(new_key.cred_id().as_slice());
    sync_passkey_replace(session_ref, delete_id, &new_id);

    Ok(())
}

pub async fn rename_passkey(id: &str, uid: &Uuid, device_note: &str) -> Result<(), WebAuthnError> {
    let trimmed = device_note.trim();
    if trimmed.is_empty() {
        return Err(WebAuthnError::Rejected);
    }

    let id_bytes: Vec<u8> = BASE64_URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_e| WebAuthnError::Serde)?;

    let rows = pg::query(
        r#"UPDATE webauthns
           SET description = $3, updated_at = now()
           WHERE id = $1 AND user_id = $2
           RETURNING id"#,
        &[&id_bytes, &uid, &trimmed],
    )
    .await
    .map_err(|e| {
        error!("rename_passkey: {e}");
        WebAuthnError::Db
    })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered);
    }

    Ok(())
}

pub async fn delete_password_on_register(uid: &Uuid) -> Result<usize, WebAuthnError> {
    let rows = pg::query(
        r#"With passkeys as
        (select count(user_id) from webauthns where user_id = $1)
        Delete from identities using passkeys
          where passkeys.count = 1 and identities.user_id = $1
          returning identities.user_id"#,
        &[&uid],
    )
    .await
    .map_err(|e| {
        error!("delete_password_on_register: {e}");
        WebAuthnError::Db
    })?;

    Ok(rows.len())
}

pub async fn delete_passkey(id: &str, uid: &Uuid) -> Result<(), WebAuthnError> {
    let id_bytes: Vec<u8> = BASE64_URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_e| WebAuthnError::Serde)?;

    let rows = pg::query(include_str!("delete_passkey.sql"), &[&id_bytes, &uid])
        .await
        .map_err(|e| {
            error!("delete_passkey: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::Rejected);
    }

    Ok(())
}

pub async fn list_passkeys(uid: &Uuid) -> Result<Vec<PasskeyRecord>, WebAuthnError> {
    let rows = pgr::query(
        r#"SELECT id, description, created_at, updated_at
           FROM webauthns
           WHERE user_id = $1
           ORDER BY created_at DESC"#,
        &[&uid],
    )
    .await
    .map_err(|e| {
        error!("list_passkeys: {e}");
        WebAuthnError::Db
    })?;

    Ok(rows
        .iter()
        .map(|row| PasskeyRecord {
            id: BASE64_URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("id")),
            description: row.try_get("description").unwrap_or_default(),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect())
}

pub fn can_delete_passkey(passkey_count: usize, via: &AuthType) -> bool {
    if matches!(via, AuthType::Unknown | AuthType::PasswordWeakUnmet) {
        return false;
    }

    match passkey_count {
        1 => (),
        0 => return false,
        _ => return true,
    };

    match via {
        AuthType::PassKey(_) => false,
        AuthType::Mail => false,
        _ => true,
    }
}

pub async fn generate_challenge_authentication(
    wa: &Webauthn,
    email: Option<&str>,
) -> Result<(RequestChallengeResponse, String), WebAuthnError> {
    if email.is_none() || email.unwrap().is_empty() {
        return generate_challenge_authentication_discoverable(wa).await;
    }

    let email = email.unwrap();
    let rows = pgr::query_pp(SQL_LIST_CREDENTIALS, &[Type::VARCHAR], &[&email])
        .await
        .map_err(|e| {
            error!("generate_challenge_authentication: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered);
    }

    let credentials: Vec<Passkey> = rows
        .iter()
        .map(|row| {
            serde_json::from_value(row.get::<_, serde_json::Value>("credential"))
                .map_err(|_e| WebAuthnError::Serde)
                .unwrap()
        })
        .collect();

    let (challenge_res, auth_state) = wa
        .start_passkey_authentication(&credentials)
        .map_err(|_e| WebAuthnError::Rejected)?;
    let auth_json = serde_json::to_string(&auth_state).map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, auth_json))
}

async fn generate_challenge_authentication_discoverable(
    wa: &Webauthn,
) -> Result<(RequestChallengeResponse, String), WebAuthnError> {
    let (challenge_res, auth_state) = wa
        .start_discoverable_authentication()
        .map_err(|_e| WebAuthnError::Rejected)?;
    let auth_json = serde_json::to_string(&auth_state).map_err(|_e| WebAuthnError::Serde)?;

    Ok((challenge_res, auth_json))
}

// NOTE: authenticated with `DiscoverableAuthentication` state (generated by `start_discoverable_authentication`).
pub async fn authenticate_discoverable_passkey(
    wa: &Webauthn,
    rsp: &PublicKeyCredential,
    auth_json: &str,
) -> Result<(AuthenticationResult, Row), WebAuthnError> {
    let auth_st: DiscoverableAuthentication = serde_json::from_str(&auth_json).map_err(|e| {
        debug!("Cannot parse PasskeyAuthentication: {:?}", &e);
        WebAuthnError::Serde
    })?;

    let (_uuid, raw_id) = wa.identify_discoverable_authentication(rsp).map_err(|e| {
        error!("cannot extract discoverable key id: {:?}", &e);
        WebAuthnError::Serde
    })?;

    let rows = pgr::query_pp(SQL_FIND_USER_BY_CREDENTIAL, &[Type::BYTEA], &[&raw_id])
        .await
        .map_err(|e| {
            error!("webauthn::authenticate: {e}");
            WebAuthnError::Db
        })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered);
    }

    let uid = rows[0].get::<_, Uuid>("uid");
    let hard_pass = rows[0].get::<_, bool>("hard_pass");
    let cred_str = rows[0].get::<_, serde_json::Value>("credential");

    let cred: DiscoverableKey = serde_json::from_value(cred_str.clone()).map_err(|e| {
        debug!("Stored credential broken: {:?}", &e);
        WebAuthnError::Serde
    })?;
    let cred_id = BASE64_URL_SAFE_NO_PAD.encode(raw_id.as_ref() as &[u8]);
    let authorization = wa.finish_discoverable_authentication(&rsp, auth_st, &vec![cred.into()]);
    if authorization.is_err() {
        login_trace(
            uid.clone(),
            AuthType::PassKey(cred_id.clone()),
            false,
            hard_pass,
        )
        .await
        .ok();
    }
    let auth_result = authorization.map_err(|e| {
        debug!("Passkey auth err: {:?}", &e);
        WebAuthnError::Rejected
    })?;
    let user_verified = auth_result.user_verified();
    debug!(
        "AuthenticationResult reported internal count: {:?}",
        auth_result.counter()
    );

    let at = AuthType::PassKey(cred_id);
    let uid_c = uid.clone();
    let jh: JoinHandle<Result<(), AccountError>> =
        tokio::spawn(async move { login_trace(uid_c, at, user_verified, hard_pass).await });
    if hard_pass {
        let _ = jh.await.map_err(|e| {
            error!("webauthn::authenticate: {e}");
            WebAuthnError::Db
        })?;
    }

    if !user_verified {
        debug!("AuthenticationResult reported not user_verified");
        return Err(WebAuthnError::Rejected);
    }

    Ok((auth_result, rows[0].clone()))
}

// NOTE: authenticated with `PasskeyAuthentication` state (generated by `start_passkey_authentication`).
pub async fn authenticate_named_passkey(
    wa: &Webauthn,
    rsp: &PublicKeyCredential,
    auth_json: &str,
) -> Result<(AuthenticationResult, Row), WebAuthnError> {
    let auth_st: PasskeyAuthentication = serde_json::from_str(&auth_json).map_err(|e| {
        debug!("Cannot parse PasskeyAuthentication: {:?}", &e);
        WebAuthnError::Serde
    })?;

    let raw_id = &rsp.raw_id; // NOTE `raw_id: Base64UrlSafeData`.
    let cred_id_bytes: &[u8] = raw_id.as_ref();

    let rows = pgr::query_pp(
        SQL_FIND_USER_BY_CREDENTIAL,
        &[Type::BYTEA],
        &[&cred_id_bytes],
    )
    .await
    .map_err(|e| {
        error!("webauthn::authenticate: {e}");
        WebAuthnError::Db
    })?;
    if rows.is_empty() {
        return Err(WebAuthnError::NoIdRegistered);
    }

    let uid = rows[0].get::<_, Uuid>("uid");
    let hard_pass = rows[0].get::<_, bool>("hard_pass");
    let _cred_str = rows[0].get::<_, serde_json::Value>("credential");

    // let cred: Passkey = serde_json::from_value(cred_str.clone())
    //     .map_err(|e| {
    //         debug!("Stored credential broken: {:?}", &e);
    //         WebAuthnError::Serde
    //     })?;

    let cred_id = BASE64_URL_SAFE_NO_PAD.encode(cred_id_bytes as &[u8]);
    let authorization = wa.finish_passkey_authentication(&rsp, &auth_st);

    if authorization.is_err() {
        login_trace(
            uid.clone(),
            AuthType::PassKey(cred_id.clone()),
            false,
            hard_pass,
        )
        .await
        .ok();
    }
    let auth_result = authorization.map_err(|e| {
        debug!("Passkey auth err: {:?}", &e);
        WebAuthnError::Rejected
    })?;
    let user_verified = auth_result.user_verified();
    debug!(
        "AuthenticationResult reported internal count: {:?}",
        auth_result.counter()
    );

    let at = AuthType::PassKey(cred_id);
    let uid_c = uid.clone();
    let jh: JoinHandle<Result<(), AccountError>> =
        tokio::spawn(async move { login_trace(uid_c, at, user_verified, hard_pass).await });
    if hard_pass {
        let _ = jh.await.map_err(|e| {
            error!("webauthn::authenticate: {e}");
            WebAuthnError::Db
        })?;
    }

    if !user_verified {
        debug!("AuthenticationResult reported not user_verified");
        return Err(WebAuthnError::Rejected);
    }

    Ok((auth_result, rows[0].clone()))
}

// NOTE: If hard_pass is not set, abort silently.
pub async fn try_update_passkey(
    passkey_json: serde_json::Value,
    auth_result: &AuthenticationResult,
    hard_pass: bool,
) -> Result<(), WebAuthnError> {
    if !auth_result.needs_update() {
        return Ok(());
    }

    let try_passkey: Result<Passkey, _> = serde_json::from_value(passkey_json);
    if !hard_pass && try_passkey.is_err() {
        return Ok(());
    }

    let mut passkey = try_passkey.map_err(|e| {
        error!("Stored credential broken: {:?}", &e);
        WebAuthnError::Serde
    })?;
    let res = passkey.update_credential(&auth_result);
    match res {
        None => {
            return match hard_pass {
                true => Err(WebAuthnError::Serde),
                false => Ok(()),
            };
        }
        Some(false) => return Ok(()),
        _ => (),
    };

    let try_serialized = serde_json::to_value(&passkey);
    if !hard_pass && try_serialized.is_err() {
        return Ok(());
    }

    let serialized = try_serialized.map_err(|e| {
        error!("Passkey cannot be serialized: {:?}", e);
        WebAuthnError::Serde
    })?;
    let try_update = pg::execute(
        r#"UPDATE webauthns
                  SET credential = $1, updated_at = now()
                  WHERE id = $2"#,
        &[&serialized, &auth_result.cred_id().as_slice()],
    )
    .await;
    if !hard_pass && try_update.is_err() {
        return Ok(());
    }

    try_update.map(|_res| ()).map_err(|e| {
        error!("Passkey update: {e}");
        WebAuthnError::Db
    })
}

async fn list_cred_ids(uid: &Uuid) -> Option<Vec<CredentialID>> {
    let rows = pgr::query(
        r#"SELECT id FROM webauthns
       WHERE user_id = $1"#,
        &[&uid],
    )
    .await
    .ok()?;
    if rows.is_empty() {
        return None;
    }

    Some(
        rows.iter()
            .map(|row| {
                let cred_id = row.get::<_, Vec<u8>>("id");
                cred_id
                    .try_into()
                    .unwrap_or(CredentialID::from(Vec::<u8>::new()))
            })
            .collect(),
    )
}

const SQL_LIST_CREDENTIALS: &str = r#"
SELECT u.email, w.credential FROM users u
  INNER JOIN webauthns w ON w.user_id = u.id
  WHERE u.email = $1"#;

const SQL_FIND_USER_BY_CREDENTIAL: &str = r#"
SELECT u.id AS uid, u.org_id AS oid, u.superuser AS su,
       w.credential, coalesce(o.hard_pass, false) AS hard_pass
  FROM webauthns w
    INNER JOIN users u ON u.id = w.user_id
    LEFT JOIN orgs o ON o.id = u.org_id
  WHERE w.id = $1"#;

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::{Asn1Object, Asn1OctetString, Asn1Time},
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509Extension, X509NameBuilder},
    };

    fn build_test_attestation_cert(aaguid: &Uuid) -> String {
        let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("failed to create key");

        let mut builder = X509::builder().expect("failed to create x509 builder");
        builder.set_version(2).expect("failed to set x509 version");

        let mut serial = BigNum::new().expect("failed to create serial");
        serial
            .rand(64, MsbOption::MAYBE_ZERO, false)
            .expect("failed to randomize serial");
        let serial = serial.to_asn1_integer().expect("failed to convert serial");
        builder
            .set_serial_number(&serial)
            .expect("failed to set serial");

        let mut name = X509NameBuilder::new().expect("failed to create subject");
        name.append_entry_by_nid(Nid::COMMONNAME, "auth-shards test attestation")
            .expect("failed to set CN");
        let name = name.build();
        builder
            .set_subject_name(&name)
            .expect("failed to set subject");
        builder
            .set_issuer_name(&name)
            .expect("failed to set issuer");
        builder.set_pubkey(&pkey).expect("failed to set pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("failed to create not_before");
        builder
            .set_not_before(&not_before)
            .expect("failed to apply not_before");
        let not_after = Asn1Time::days_from_now(1).expect("failed to create not_after");
        builder
            .set_not_after(&not_after)
            .expect("failed to apply not_after");

        let oid = Asn1Object::from_str("1.3.6.1.4.1.45724.1.1.4").expect("failed to create oid");
        let mut der = vec![0x04, 0x10];
        der.extend_from_slice(aaguid.as_bytes());
        let octets =
            Asn1OctetString::new_from_bytes(&der).expect("failed to create extension payload");
        let extension = X509Extension::new_from_der(&oid, false, &octets)
            .expect("failed to create aaguid extension");
        builder
            .append_extension(extension)
            .expect("failed to append extension");

        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("failed to sign cert");
        BASE64_URL_SAFE_NO_PAD.encode(builder.build().to_der().expect("failed to encode cert"))
    }

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
        assert_eq!(
            false,
            can_delete_passkey(0, &AuthType::PassKey("".to_string()))
        );

        // Can delete when 1 passkey w/other identities
        assert_eq!(true, can_delete_passkey(1, &AuthType::PasswordStrong));
        assert_eq!(true, can_delete_passkey(1, &AuthType::PasswordWeak));
        assert_eq!(true, can_delete_passkey(1, &AuthType::OpenidGoog));
        assert_eq!(true, can_delete_passkey(1, &AuthType::AccessToken));
        assert_eq!(false, can_delete_passkey(1, &AuthType::Mail));
        assert_eq!(
            false,
            can_delete_passkey(1, &AuthType::PassKey("".to_string()))
        );

        // Can delete when 2 passkeys
        assert_eq!(true, can_delete_passkey(2, &AuthType::PasswordWeak));
        assert_eq!(
            true,
            can_delete_passkey(2, &AuthType::PassKey("".to_string()))
        );
        assert_eq!(true, can_delete_passkey(2, &AuthType::Mail));
    }

    #[test]
    fn test_get_aaguid() {
        let aaguid_str = "c53933c1-5369-4299-b1d7-d5804910ae99";
        let mut val = serde_json::json!({
            "cred": {
                "cred_id": "YWJj",
                "cred": {
                    "type_": "ES256",
                    "key": { "EC_EC2": { "curve": "SECP256R1", "x": "YWJj", "y": "YWJj" } }
                },
                "counter": 0,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {
                    "data": "None",
                    "metadata": {
                        "Packed": {
                            "aaguid": aaguid_str
                        }
                    }
                },
                "attestation_format": "none"
            }
        });

        let passkey: Passkey =
            serde_json::from_value(val.clone()).expect("Failed to parse Packed Passkey");
        let extracted = get_aaguid(&passkey).expect("Should extract AAGUID");
        assert_eq!(extracted.to_string(), aaguid_str);

        // Test with Tpm
        val["cred"]["attestation"]["metadata"] = serde_json::json!({
            "Tpm": { "aaguid": aaguid_str, "firmware_version": 123 }
        });
        let passkey_tpm: Passkey =
            serde_json::from_value(val.clone()).expect("Failed to parse Tpm Passkey");
        let extracted_tpm = get_aaguid(&passkey_tpm).expect("Should extract TPM AAGUID");
        assert_eq!(extracted_tpm.to_string(), aaguid_str);

        // Test with None
        val["cred"]["attestation"]["metadata"] = serde_json::json!({ "None": null });
        let passkey_none: Passkey =
            serde_json::from_value(val).expect("Failed to parse None Passkey");
        assert!(get_aaguid(&passkey_none).is_none());
    }

    #[test]
    fn test_get_aaguid_from_attestation_certificate_extension() {
        let aaguid = Uuid::parse_str("53414d53-554e-4700-0000-000000000000").unwrap();
        let cert = build_test_attestation_cert(&aaguid);
        let val = serde_json::json!({
            "cred": {
                "cred_id": "YWJj",
                "cred": {
                    "type_": "ES256",
                    "key": { "EC_EC2": { "curve": "SECP256R1", "x": "YWJj", "y": "YWJj" } }
                },
                "counter": 0,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {
                    "data": {
                        "Basic": [cert]
                    },
                    "metadata": "None"
                },
                "attestation_format": "none"
            }
        });

        let passkey: Passkey =
            serde_json::from_value(val).expect("Failed to parse cert-backed Passkey");
        assert_eq!(get_aaguid(&passkey), Some(aaguid));
    }
}
