use argon2::{
    Argon2,
    password_hash::{
        self,
        rand_core::OsRng,
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        SaltString
    }
};
use log::error;
use passwords::PasswordGenerator;
use pg_pool::{pg, pgr, Row};
use regex::Regex;
use thiserror::Error;
use tokio_postgres::types::Type;
use uuid::Uuid;

use crate::{
    AuthType,
    account::login_trace
};

#[cfg(feature="compat-rails")]
use bcrypt;

#[derive(Error, Debug, PartialEq)]
pub enum PasswordError {
    #[error("db access aborted")]
    Db,
    #[error("condition unmet")]
    Rejected,
    #[error("cannot be converted")]
    Serde,
    #[error("no ID registered")]
    NoIdRegistered,
    #[error("account locked")]
    Locked,
    #[error("need to change phrase")]
    Duplicated
}

pub async fn authenticate_password(
    id_key: &str,
    password: &str,
) -> Result<(AuthType, Row), PasswordError> {
    let row = search_identity(&id_key).await?;

    let uid = row.get::<_, Uuid>("uid");
    let digest = row.get::<_, String>("password_digest");
    let must_hardpass = row.get::<_, bool>("hard_pass");
    let auth_type = match is_weak_password(&password) {
        true => match must_hardpass {
            true => AuthType::PasswordWeakUnmet,
            false => AuthType::PasswordWeak,
        },
        false => AuthType::PasswordStrong
    };

    if row.get::<_, i16>("fail") >= 5 {
        return Err(PasswordError::Locked);
    }
    let authenticated = verify_argon2(&password, &digest).is_ok();

    login_trace(&uid, auth_type, authenticated, must_hardpass)
        .await.map_err(|_e| PasswordError::Db)?;

    match authenticated {
        true => Ok((auth_type, row)),
        false => Err(PasswordError::Rejected)
    }
}

pub async fn try_update_password(
    uid: &Uuid,
    password: &str,
    must_hardpass: bool
) -> Result<AuthType, PasswordError> {
    let auth_type = match is_weak_password(&password) {
        true => AuthType::PasswordWeak,
        false => AuthType::PasswordStrong
    };
    if must_hardpass && auth_type == AuthType::PasswordWeak {
        return Err(PasswordError::Rejected);
    }

    let row = pgr::query_one(sql_get_settings(), &[&uid]).await
        .map_err(|e| {
            error!("try_update_password: {e}");
            PasswordError::Db
        })?;
    if row.get::<_, bool>("hard_pass") && auth_type == AuthType::PasswordWeak {
        return Err(PasswordError::Rejected);
    }
    // NOTE: reject the same password
    if let Ok(digest) = row.try_get::<_, String>("password_digest") {
        if verify_argon2(&password, &digest).is_ok() {
            return Err(PasswordError::Duplicated);
        }
    }

    let digest = digest_argon2(&password).map_err(|e| {
        error!("try_update_password: {e}");
        PasswordError::Serde
    })?;
    let _count = pg::execute(sql_update_password(), &[&uid, &digest]).await
        .map_err(|e| {
            error!("try_update_password: {e}");
            PasswordError::Db
        })?;

    Ok(auth_type)
}

pub fn verify_argon2<'a>(
    password: &'a str,
    stored_digest: &'a str
) -> Result<(), password_hash::errors::Error> {
    let parsed_hash = PasswordHash::new(&stored_digest)?;
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash)
}

pub fn digest_argon2<'a>(
    password: &'a str
) -> Result<String, password_hash::errors::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;

    Ok(hash.to_string())
}

#[cfg(feature="compat-rails")]
pub fn verify_bcrypt<'a>(
    password: &'a str,
    stored_digest: &'a str
) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, stored_digest)
}

pub fn generate_hard_password(count: usize) -> Option<Vec<String>> {
    let generator = PasswordGenerator {
        length: 12,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true
    };
    generator.generate(count).ok()
}

pub fn is_weak_password<'a>(pass: &'a str) -> bool {
    if pass.chars().count() < 12 {
        return true;
    }
    let lower = Regex::new(r"[[:lower:]]+").unwrap();
    let upper = Regex::new(r"[[:upper:]]+").unwrap();
    let digit = Regex::new(r"[[:digit:]]+").unwrap();
    let symbol = Regex::new(r#"[`~!@#$%^&*()_+-={}|:;"'<>,.?/\[\]\\]+"#).unwrap();

    if lower.is_match(pass) && upper.is_match(pass)
        && digit.is_match(pass) && symbol.is_match(pass) {
        return false;
    }

    true
}

pub fn generate_passdigits() -> Option<String> {
    let generator = PasswordGenerator {
        length: 6,
        numbers: true,
        lowercase_letters: false,
        uppercase_letters: false,
        symbols: false,
        spaces: false,
        exclude_similar_characters: false,
        strict: true
    };
    generator.generate_one().ok()
}

async fn search_identity(id_key: &str) -> Result<Row, PasswordError>{
    let rows = pgr::query_pp(
        include_str!("get_identity.sql"),
        &[Type::VARCHAR], &[&id_key]
    ).await.map_err(|e| {
        error!("search_identity: {e}");
        PasswordError::Db
    })?;

    match rows.len() == 1 {
        true => Ok(rows[0].clone()),
        false => Err(PasswordError::NoIdRegistered),
    }
}

fn sql_get_settings<'a>() -> &'a str {
    r#"SELECT coalesce(o.hard_pass, false) AS hard_pass, i.digest_argon AS password_digest
         FROM users u
         LEFT JOIN identities i ON u.id = i.user_id
         LEFT JOIN orgs o ON o.id = u.org_id
         WHERE u.id = $1"#
}

fn sql_update_password<'a>() -> &'a str {
    r#"INSERT INTO identities (user_id, digest_argon, created_at, updated_at)
       SELECT $1, $2, now(), now()
       FROM users WHERE id = $1
       ON CONFLICT (user_id)
       DO UPDATE SET digest_argon = $2, fail = 0, updated_at = now()"#
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_symbols() {
        assert_eq!(false, is_weak_password(r#"`1Cdefghijklm"#)); // over 12 letters
        assert_eq!(false, is_weak_password(r#"`1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"~1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"!1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"@1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"#1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"$1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"%1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"^1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"&1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"*1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"(1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#")1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"_1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"+1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"-1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"=1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"{1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"}1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"|1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#":1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#";1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#""1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"'1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"<1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#">1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#",1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#".1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"?1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"/1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"[1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"]1Cdefghijkl"#));
        assert_eq!(false, is_weak_password(r#"\1Cdefghijkl"#));
    }

    #[test]
    fn test_invalid_passwords() {
        assert_eq!(true, is_weak_password(r#"0B!defghijk"#)); // 11 letters
        assert_eq!(true, is_weak_password(r#"0b!defghijkl"#)); // no upper letters
        assert_eq!(true, is_weak_password(r#"0B!DEFGHIJKL"#)); // no lower letters
        assert_eq!(true, is_weak_password(r#"aB!defghijkl"#)); // no digits
    }

    #[test]
    fn test_valid_argon2_password() {
        assert_eq!((), verify_argon2(
            "c3WDGKmr",
            "$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw"
        ).unwrap());
        assert_eq!((), verify_argon2(
            "m2Sjsqz7",
            "$argon2id$v=19$m=19456,t=2,p=1$HF/DKVcHVxpeWTFAaylahw$qZcWddw4Yov6f/zP4uGUtwqoeqK1ItJ85BExoxxXDDM"
        ).unwrap());
        assert_eq!((), verify_argon2(
            "U2uZJgjB",
            "$argon2id$v=19$m=19456,t=2,p=1$sbIluJgxM4QAb26oJ+UmoA$FanPwQizff/Jje2YuHmaJJ7FGjwJG6LjSN/a3RAcWXo"
        ).unwrap());
        assert_eq!((), verify_argon2(
            "L5pJ69Rr",
            "$argon2id$v=19$m=19456,t=2,p=1$8PWi8pHNy3H12CBMNCQRKQ$IxzIospZHhlSrYt6/7SmHduAw7JduwcU70jSb6sjM7E"
        ).unwrap());
        assert_eq!((), verify_argon2(
            "J3mgcTSB",
            "$argon2id$v=19$m=19456,t=2,p=1$iydFM976CW8BuNDmVJSZVQ$yUAOPMXWJF1a9rwI2lgc7daTn8LREhhw/GkRiTy4e/M"
        ).unwrap());
    }

    #[test]
    fn test_invalid_argon2_password() {
        assert!(verify_argon2(
            "invalidpassword",
            "$argon2id$v=19$m=19456,t=2,p=1$sbIluJgxM4QAb26oJ+UmoA$FanPwQizff/Jje2YuHmaJJ7FGjwJG6LjSN/a3RAcWXo"
        ).is_err());
    }

    #[cfg(feature="compat-rails")]
    #[test]
    fn test_valid_bcrypt_password() {
        assert_eq!(true, verify_bcrypt(
            "f5MYugyB",
            "$2a$12$8kDiVU02DvDcSrCnuynNIeQB6vDdd.tzb1eA3M1B63aWbMflfmLpO"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "X8gU2ECK",
            "$2a$12$F0M.CbTZK5udhEusVpIdpeUwdJQFE9zhlYq1jy1rOvH/yMnBzdkDi"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "xD9RP4Tg",
            "$2a$12$tWEafvuXlNTtth8l/al3XOMadvl.nhVBVKznhqZboQE2itxEm57bG"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "mG5XrE78",
            "$2a$12$/R1.4jO/g.8owfhQ4oMVJuq85HuzBiq1nPrYFNPSG6ld48r/74IJC"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "mU5rJiVe",
            "$2a$12$I6s7IMojFIZDCORl6RmKO.JSeqkmClPO1073CsA2ezRYX7prkK5zm"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "c3WDGKmr",
            "$2a$12$P9gqdJUT4wll/OBQSvd7yOSZeBAPMIpLPYl6O9y.FSPV8Hmuff5RW"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "m2Sjsqz7",
            "$2a$12$IDGcvtK5xia6Maj1MF/7eumNhSnG8xFV8Q1cH7SM0uQpPJdbGEKlm"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "U2uZJgjB",
            "$2a$12$PjCQ56q5r6AA/YS/0EkM9ucIZ7AWI4.libP/4Hj3wX6kRSitP6OtS"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "L5pJ69Rr",
            "$2a$12$/pKqVTj14gAkpVNQDz31HOorQitxT/9T71Fx2cbQlVeEGBbhTrW8K"
        ).unwrap());
        assert_eq!(true, verify_bcrypt(
            "J3mgcTSB",
            "$2a$12$zIfbQqhy4geKJCZC5xf8o.xCObXQe8OAxSmLD5iRqAjqQZaBCXGbC"
        ).unwrap());
    }

    #[cfg(feature="compat-rails")]
    #[test]
    fn test_invalid_bcrypt_password() {
        assert_eq!(false, verify_bcrypt(
            "invalidpassword",
            "$2a$12$8kDiVU02DvDcSrCnuynNIeQB6vDdd.tzb1eA3M1B63aWbMflfmLpO"
        ).unwrap());
    }
}
