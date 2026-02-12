use async_session::{Session, SessionStore};
use pg_pool::Row;
use uuid::Uuid;
use crate::AuthType;
use crate::util::ClientContext;

pub struct SessionAccount {
    pub id: Uuid,
    pub group: Option<Uuid>,
    pub superuser: bool,
    pub hard_pass: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("database error")]
    Db(#[from] pg_pool::Error),
    #[error("not logged in")]
    NoLogin,
    #[error("security mismatch")]
    SecurityMismatch,
    #[error("invalid integrity data")]
    InvalidIntegrity,
    #[error("serialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("session store error")]
    Store(#[from] anyhow::Error),
}

impl TryFrom<&Row> for SessionAccount {
    type Error = SessionError;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.try_get("uid")?,
            group: row.try_get("oid").ok(),
            superuser: row.try_get("su")?,
            hard_pass: row.try_get("hard_pass").unwrap_or(false),
        })
    }
}

pub struct SessionKeys {
    pub id: &'static str,
    pub group: &'static str,
    pub superuser: &'static str,
    pub mailauth: &'static str,
    pub passkey: &'static str,
    pub via: &'static str,
    pub locked: &'static str,
    pub integrity: &'static str,
}

pub struct SessionManager {
    pub keys: &'static SessionKeys,
}

impl Default for SessionManager {
    fn default() -> Self {
        static DEFAULT: SessionKeys = SessionKeys {
            id: "uid",
            group: "org_id",
            superuser: "su",
            mailauth: "mailauth",
            passkey: "passkey",
            via: "via",
            locked: "locked",
            integrity: "integrity",
        };
        Self::new(&DEFAULT)
    }
}

impl SessionManager {
    pub const fn new(keys: &'static SessionKeys) -> Self {
        Self { keys }
    }

    /// Logs in a session, binding it to the derived fingerprint from `ClientContext`.
    ///
    /// # Arguments
    /// * `client` - The client context containing UA and UA-CH signals.
    pub async fn login<S: SessionStore>(
        &self,
        (store, session): (&S, &mut Session),
        account: &SessionAccount,
        auth_type: AuthType,
        client: &ClientContext,
    ) -> Result<(), SessionError> {
        let integrity = client.compute_hash();

        let via_pre = session.get_raw(self.keys.via);

        store.destroy_session(session.clone()).await?;
        session.regenerate();

        session.insert_raw(self.keys.id, account.id.to_string());

        session.insert_raw(self.keys.integrity, integrity);

        self.setup_group(session, account)?;
        self.setup_via(session, account, via_pre, auth_type)?;
        Ok(())
    }

    pub fn id(&self, session: &Session) -> Result<Uuid, SessionError> {
        session.get_raw(self.keys.id)
            .ok_or(SessionError::NoLogin)?
            .parse()
            .map_err(|_| SessionError::NoLogin)
    }

    pub fn group(&self, session: &Session) -> Option<Uuid> {
        if session.get_raw(self.keys.locked).is_some() {
            return None;
        }
        session.get_raw(self.keys.group)
            .and_then(|s| s.parse().ok())
    }

    /// Validates session integrity against the client context.
    /// This prevents session hijacking by tied-down fingerprints (Detecting cookie reuse on different devices/browsers).
    pub fn validate(&self, session: &Session, client: &ClientContext) -> Result<(), SessionError> {
        // If integrity data exists, it MUST match the current client.
        let stored = session.get_raw(self.keys.integrity).ok_or(SessionError::NoLogin)?;
        let verifier = client.compute_hash();

        use subtle::ConstantTimeEq;
        if stored.as_bytes().ct_eq(verifier.as_bytes()).unwrap_u8() != 1 {
            return Err(SessionError::SecurityMismatch);
        }

        let _uid = session.get_raw(self.keys.id)
            .ok_or(SessionError::NoLogin)?
            .parse::<Uuid>()
            .map_err(|_| SessionError::NoLogin)?;

        Ok(())
    }

    fn setup_group(
        &self,
        session: &mut Session,
        account: &SessionAccount,
    ) -> Result<(), SessionError> {
        match account.group {
            Some(group_id) => session.insert_raw(self.keys.group, group_id.to_string()),
            None => session.remove(self.keys.group),
        };

        match account.superuser {
            true => session.insert_raw(self.keys.superuser, "true".to_string()),
            false => session.remove(self.keys.superuser),
        };
        Ok(())
    }

    fn setup_via(
        &self,
        session: &mut Session,
        account: &SessionAccount,
        via_pre: Option<String>,
        auth_type: AuthType,
    ) -> Result<(), SessionError> {
        if matches!(auth_type, AuthType::Mail) {
            session.insert_raw(self.keys.mailauth, "1".to_string());
        }

        if let AuthType::PassKey(ref id) = auth_type {
            if !id.is_empty() {
                session.insert_raw(self.keys.passkey, id.clone());
            }
        }

        if matches!(auth_type, AuthType::PasswordWeakUnmet) || (matches!(auth_type, AuthType::PasswordWeak) && account.hard_pass) {
            session.insert_raw(self.keys.locked, "1".to_string());
            session.insert_raw(self.keys.via, AuthType::PasswordWeakUnmet.to_u8().to_string());
        } else {
            if via_pre.is_none() {
                session.insert_raw(self.keys.via, auth_type.to_u8().to_string());
            }
        }
        Ok(())
    }
}

pub async fn session_login<S: SessionStore>(
    ctx: (&S, &mut Session),
    account: &SessionAccount,
    auth_type: AuthType,
    client: &ClientContext,
) -> Result<(), SessionError> {
    SessionManager::default().login(ctx, account, auth_type, client).await
}

pub fn get_id(session: &Session) -> Result<Uuid, SessionError> {
    SessionManager::default().id(session)
}

pub fn get_group(session: &Session) -> Option<Uuid> {
    SessionManager::default().group(session)
}

pub fn validate(session: &Session, client: &ClientContext) -> Result<(), SessionError> {
    SessionManager::default().validate(session, client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_session::MemoryStore;

    #[tokio::test]
    async fn test_session_login_basic() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id = Uuid::now_v7();
        let account = SessionAccount {
            id,
            group: None,
            superuser: false,
            hard_pass: false,
        };

        session_login((&store, &mut session), &account, AuthType::PasswordStrong, &ClientContext {
            brands: None, platform: None, model: None, ua: Some("ua".to_string())
        }).await.unwrap();

        assert_eq!(session.get_raw("uid").unwrap().parse::<Uuid>().unwrap(), id);
        assert_eq!(session.get_raw("via").unwrap(), AuthType::PasswordStrong.to_u8().to_string());
        assert!(session.get_raw("org_id").is_none());
        assert!(session.get_raw("su").is_none());
    }

    #[tokio::test]
    async fn test_session_login_org_su() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id = Uuid::now_v7();
        let group_id = Uuid::now_v7();
        let account = SessionAccount {
            id,
            group: Some(group_id),
            superuser: true,
            hard_pass: false,
        };

        session_login((&store, &mut session), &account, AuthType::PasswordStrong, &ClientContext {
            brands: None, platform: None, model: None, ua: Some("ua".to_string())
        }).await.unwrap();

        assert_eq!(session.get_raw("org_id").unwrap().parse::<Uuid>().unwrap(), group_id);
        assert_eq!(session.get_raw("su").unwrap(), "true");
    }

    #[tokio::test]
    async fn test_session_login_mfa_flags() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id = Uuid::now_v7();

        // Test Mail auth
        let account = SessionAccount { id, group: None, superuser: false, hard_pass: false };
        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("ua".to_string()),
        };
        session_login((&store, &mut session), &account, AuthType::Mail, &ctx).await.unwrap();
        assert_eq!(session.get_raw("mailauth").unwrap(), "1");

        // Test PassKey
        let mut session = Session::new();
        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("ua".to_string()),
        };
        session_login((&store, &mut session), &account, AuthType::PassKey("key_id".into()), &ctx).await.unwrap();
        assert_eq!(session.get_raw("passkey").unwrap(), "key_id");
    }

    #[tokio::test]
    async fn test_session_login_hard_pass_lock() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id = Uuid::now_v7();

        // Org requires hard_pass, but user uses PasswordWeak
        let account = SessionAccount {
            id,
            group: None,
            superuser: false,
            hard_pass: true,
        };

        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("ua".to_string()),
        };
        session_login((&store, &mut session), &account, AuthType::PasswordWeak, &ctx).await.unwrap();

        assert_eq!(session.get_raw("locked").unwrap(), "1");
        // via should be set to PasswordWeakUnmet (4)
        assert_eq!(session.get_raw("via").unwrap(), AuthType::PasswordWeakUnmet.to_u8().to_string());
    }

    #[tokio::test]
    async fn test_session_login_via_preservation() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        // Set via_pre
        session.insert_raw("via", "99".to_string());

        let account = SessionAccount {
            id: Uuid::now_v7(),
            group: None,
            superuser: false,
            hard_pass: false,
        };

        session_login((&store, &mut session), &account, AuthType::PasswordStrong, &ClientContext {
            brands: None, platform: None, model: None, ua: Some("ua".to_string())
        }).await.unwrap();

        // via should NOT be updated because via_pre existed
        assert_eq!(session.get_raw("via").unwrap(), "99");
    }

    #[tokio::test]
    async fn test_session_login_custom_keys() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id = Uuid::now_v7();
        let account = SessionAccount {
            id,
            group: None,
            superuser: false,
            hard_pass: false,
        };

        static CUSTOM: SessionKeys = SessionKeys {
            id: "u",
            via: "v",
            group: "o",
            superuser: "s",
            mailauth: "m",
            passkey: "p",
            locked: "l",
            integrity: "i",
        };
        let manager = SessionManager::new(&CUSTOM);

        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("valid-ua".to_string()),
        };
        manager.login((&store, &mut session), &account, AuthType::PasswordStrong, &ctx).await.unwrap();

        // Verify with custom keys
        assert_eq!(session.get_raw("u").unwrap(), id.to_string());
        assert_eq!(session.get_raw("v").unwrap(), AuthType::PasswordStrong.to_u8().to_string());
        let expected = ctx.compute_hash();
        assert_eq!(session.get_raw("i").unwrap(), expected);

        // Verify default keys are NOT used
        assert!(session.get_raw("uid").is_none());

        // Verify validation with custom manager
        assert!(manager.validate(&session, &ctx).is_ok());

        let ctx_invalid = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("invalid".to_string()),
        };
        assert!(matches!(manager.validate(&session, &ctx_invalid), Err(SessionError::SecurityMismatch)));
    }

    #[tokio::test]
    async fn test_session_getters() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id_val = Uuid::now_v7();
        let group_id = Uuid::now_v7();

        // 1. Test failure before login
        assert!(matches!(get_id(&session), Err(SessionError::NoLogin)));
        assert!(get_group(&session).is_none());

        // 2. Test success after login
        let account = SessionAccount {
            id: id_val,
            group: Some(group_id),
            superuser: false,
            hard_pass: false,
        };
        session_login((&store, &mut session), &account, AuthType::PasswordStrong, &ClientContext {
            brands: None, platform: None, model: None, ua: Some("ua".to_string())
        }).await.unwrap();

        assert_eq!(get_id(&session).unwrap(), id_val);
        assert_eq!(get_group(&session).unwrap(), group_id);

        // 3. Test group() returns None when locked
        let mut session_locked = Session::new();
        let account_locked = SessionAccount {
            id: id_val,
            group: Some(group_id),
            superuser: false,
            hard_pass: true,
        };
        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("ua".to_string()),
        };
        session_login((&store, &mut session_locked), &account_locked, AuthType::PasswordWeak, &ctx).await.unwrap();

        assert_eq!(get_id(&session_locked).unwrap(), id_val);
        assert!(get_group(&session_locked).is_none()); // Locked!
    }

    #[tokio::test]
    async fn test_session_integrity() {
        let store = MemoryStore::new();
        let mut session = Session::new();
        let id_val = Uuid::now_v7();
        let account = SessionAccount {
            id: id_val,
            group: None,
            superuser: false,
            hard_pass: false,
        };

        // Login with "browser-A"
        let ctx_a = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("browser-A".to_string()),
        };
        session_login((&store, &mut session), &account, AuthType::PasswordStrong, &ctx_a).await.unwrap();

        // Validation success
        assert!(validate(&session, &ctx_a).is_ok());

        // Validation failure (hijacking attempt using same SID but different UA)
        let ctx_b = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("browser-B".to_string()),
        };
        assert!(matches!(validate(&session, &ctx_b), Err(SessionError::SecurityMismatch)));

        // Validation failure (missing integrity key in session - e.g. manual insertion or old session)
        let session_empty = Session::new();
        assert!(matches!(validate(&session_empty, &ctx_a), Err(SessionError::NoLogin)));
    }
}
