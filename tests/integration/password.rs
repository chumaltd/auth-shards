use crate::common::{setup_user, setup_org, setup};
use pg_pool::pg;

use auth_shards::{
    AuthType,
    password::{
        PasswordError,
        authenticate_password,
        try_update_password,
    }
};


crate::test! {
    async fn it_responds_argon2_verification() {
        let _pool = setup().await;
        let (uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        pg::execute("insert into identities (user_id, digest_argon) values
                     ($1, '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
            &[&uid]).await.unwrap();

        let res1 = authenticate_password(&email, "invalid").await;
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

        let res2 = authenticate_password(&email, "c3WDGKmr").await;
        assert!(res2.is_ok());
        let (auth_type, _) = res2.unwrap();
        assert_eq!(auth_type, AuthType::PasswordWeak);
    }

    async fn it_records_auditlogs_for_hardpass_org() {
        let _pool = setup().await;
        let (uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        let (oid, _oname) = setup_org().await;
        pg::execute("update orgs set hard_pass = true
                     where id = $1",
            &[&oid]).await.unwrap();
        pg::execute("update users set org_id = $1
                     where id = $2",
            &[&oid, &uid]).await.unwrap();
        pg::execute("insert into identities (user_id, digest_argon) values
                     ($1, '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
            &[&uid]).await.unwrap();

        let res1 = authenticate_password(&email, "invalid").await;
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

        let rows1 = pg::query("select user_id, success, action from actlogs where user_id = $1",
            &[&uid]).await.unwrap();
        assert_eq!(rows1.len(), 1);
        assert_eq!(rows1[0].get::<_, bool>("success"), false);

        let res2 = authenticate_password(&email, "c3WDGKmr").await;
        assert!(res2.is_ok());
        let (auth_type, _) = res2.unwrap();
        assert_eq!(auth_type, AuthType::PasswordWeakUnmet);

        let rows2 = pg::query("select user_id from actlogs where user_id = $1",
            &[&uid]).await.unwrap();
        assert_eq!(rows2.len(), 2);
    }

    async fn it_updates_password() {
        let _pool = setup().await;
        let (uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        pg::execute("insert into identities (user_id, digest_argon) values
                     ($1, '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
            &[&uid]).await.unwrap();

        let res1 = try_update_password(&uid, "Updated", false).await;
        assert!(res1.is_ok());
        assert_eq!(res1.unwrap(), AuthType::PasswordWeak);

        let res2 = authenticate_password(&email, "c3WDGKmr").await;
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), PasswordError::Rejected);

        let res3 = authenticate_password(&email, "Updated").await;
        assert!(res3.is_ok());
        let (auth_type, _) = res3.unwrap();
        assert_eq!(auth_type, AuthType::PasswordWeak);
    }

    async fn it_rejects_update_with_same() {
        let _pool = setup().await;
        let (uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        pg::execute("insert into identities (user_id, digest_argon) values
                     ($1, '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
            &[&uid]).await.unwrap();

        let res1 = try_update_password(&uid, "c3WDGKmr", false).await;
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err(), PasswordError::Duplicated);

        let res2 = authenticate_password(&email, "c3WDGKmr").await;
        assert!(res2.is_ok());
        let (auth_type, _) = res2.unwrap();
        assert_eq!(auth_type, AuthType::PasswordWeak);
    }

    async fn it_rejects_weak_password() {
        let _pool = setup().await;
        let (uid, uname) = setup_user().await;
        let email = format!("{uname}@example.com");
        pg::execute("insert into identities (user_id, digest_argon) values
                     ($1, '$argon2id$v=19$m=19456,t=2,p=1$5TO9/7vXRV2YnnSW3jVSXQ$abP3pLnU4L1Prx5rbX63RuAiseWZif9N2z0Oyn3f2qw')",
            &[&uid]).await.unwrap();

        let res1 = try_update_password(&uid, "Updated", true).await;
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err(), PasswordError::Rejected);

        // Previous password is still alive
        let res2 = authenticate_password(&email, "c3WDGKmr").await;
        assert!(res2.is_ok(), "Failed to authenticate with original password: {:?}", res2.err());
        let (auth_type, _) = res2.unwrap();
        assert_eq!(auth_type, AuthType::PasswordWeak);
    }
}

