use crate::common::{truncate, setup_user, setup_org};
use pg_pool::pg;
use uuid::Uuid;

use auth_shards::{
    AuthType,
    password::{
        PasswordError,
        authenticate_password,
        try_update_password,
    }
};

#[tokio::test]
async fn it_responds_argon2_verification() {
    truncate().await;
    setup_user().await;
    pg::execute("insert into identities (user_id, digest_argon) values
                 ('018ff896-70f2-778d-a862-d8df3d694134', '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
        &[]).await.unwrap();

    let res1 = authenticate_password("common@example.com", "invalid").await;
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

    let res2 = authenticate_password("common@example.com", "c3WDGKmr").await;
    assert!(res2.is_ok());
    let (auth_type, _) = res2.unwrap();
    assert_eq!(auth_type, AuthType::PasswordWeak);

    let rows = pg::query("select user_id from actlogs",
        &[]).await.unwrap();
    assert!(rows.is_empty());

    truncate().await;
}

#[tokio::test]
async fn it_records_auditlogs_for_hardpass_org() {
    truncate().await;
    setup_user().await;
    setup_org().await;
    pg::execute("update orgs set hard_pass = true
                 where id = '01911c74-34bd-7f19-b8bb-9abf2a432336'",
        &[]).await.unwrap();
    pg::execute("update users set org_id = '01911c74-34bd-7f19-b8bb-9abf2a432336'
                 where id = '018ff896-70f2-778d-a862-d8df3d694134'",
        &[]).await.unwrap();
    pg::execute("insert into identities (user_id, digest_argon) values
                 ('018ff896-70f2-778d-a862-d8df3d694134', '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
        &[]).await.unwrap();

    let res1 = authenticate_password("common@example.com", "invalid").await;
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

    let rows1 = pg::query("select user_id, success from actlogs",
        &[]).await.unwrap();
    assert_eq!(rows1.len(), 1);
    assert_eq!(rows1[0].get::<_, bool>("success"), false);

    let res2 = authenticate_password("common@example.com", "c3WDGKmr").await;
    assert!(res2.is_ok());
    let (auth_type, _) = res2.unwrap();
    assert_eq!(auth_type, AuthType::PasswordWeakUnmet);

    let rows2 = pg::query("select user_id from actlogs",
        &[]).await.unwrap();
    assert_eq!(rows2.len(), 2);

    truncate().await;
}

#[tokio::test]
async fn it_updates_password() {
    truncate().await;
    setup_user().await;
    pg::execute("insert into identities (user_id, digest_argon) values
                 ('018ff896-70f2-778d-a862-d8df3d694134', '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
        &[]).await.unwrap();

    let uid = Uuid::parse_str("018ff896-70f2-778d-a862-d8df3d694134").unwrap();
    let res1 = try_update_password(&uid, "Updated", false).await;
    assert!(res1.is_ok());
    assert_eq!(res1.unwrap(), AuthType::PasswordWeak);

    let res2 = authenticate_password("common@example.com", "c3WDGKmr").await;
    assert!(res2.is_err());
    assert_eq!(res2.unwrap_err(), PasswordError::Rejected);

    let res3 = authenticate_password("common@example.com", "Updated").await;
    assert!(res3.is_ok());
    let (auth_type, _) = res3.unwrap();
    assert_eq!(auth_type, AuthType::PasswordWeak);

    truncate().await;
}

#[tokio::test]
async fn it_rejects_update_with_same() {
    truncate().await;
    setup_user().await;
    pg::execute("insert into identities (user_id, digest_argon) values
                 ('018ff896-70f2-778d-a862-d8df3d694134', '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
        &[]).await.unwrap();

    let uid = Uuid::parse_str("018ff896-70f2-778d-a862-d8df3d694134").unwrap();
    let res1 = try_update_password(&uid, "c3WDGKmr", false).await;
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err(), PasswordError::Duplicated);

    // Previous password is still alive
    let res2 = authenticate_password("common@example.com", "c3WDGKmr").await;
    assert!(res2.is_ok());
    let (auth_type, _) = res2.unwrap();
    assert_eq!(auth_type, AuthType::PasswordWeak);

    truncate().await;
}

#[tokio::test]
async fn it_rejects_weak_password() {
    truncate().await;
    setup_user().await;
    pg::execute("insert into identities (user_id, digest_argon) values
                 ('018ff896-70f2-778d-a862-d8df3d694134', '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
        &[]).await.unwrap();

    let uid = Uuid::parse_str("018ff896-70f2-778d-a862-d8df3d694134").unwrap();
    let res1 = try_update_password(&uid, "Updated", true).await;
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

    // Previous password is still alive
    let res2 = authenticate_password("common@example.com", "c3WDGKmr").await;
    assert!(res2.is_ok());
    let (auth_type, _) = res2.unwrap();
    assert_eq!(auth_type, AuthType::PasswordWeak);

    truncate().await;
}
