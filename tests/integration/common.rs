#![allow(dead_code)]
use pg_pool::pg;

pub async fn truncate() {
    pg::execute("TRUNCATE users, a_users, orgs, a_orgs,
                 webauthns,
                 identities, a_identities, google_identities, a_google_identities",
        &[]).await.unwrap();
}

pub async fn setup_user() {
    pg::execute("INSERT INTO users (email, id, name) VALUES
                 ('common@example.com', '018ff896-70f2-778d-a862-d8df3d694134', 'user1')",
                &[]).await.unwrap();
}
