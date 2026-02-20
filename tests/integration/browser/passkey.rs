use crate::common::{get_chromium_page, setup, setup_user};
use auth_shards::webauthn::{
    delete_passkey,
    generate_challenge_authentication,
    generate_challenge_register,
    WebAuthnError,
};
use base64::prelude::*;
use pg_pool::pg;
use serde_json::json;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use warp::Filter;
use webauthn_rs::prelude::{
    CreationChallengeResponse as Challenge,
    Passkey
};

// Mock State to hold challenge data between requests
pub(crate) struct MockState {
    pub challenge: Option<Challenge>,
    pub reg_state: Option<String>, // RegState is String in generate_challenge_register
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
}

#[derive(Debug)]
pub(crate) struct WebAuthnTestError;
impl warp::reject::Reject for WebAuthnTestError {}

crate::test! {
    async fn it_registers_and_authenticates_passkey() {
        let _pool = setup().await;
        let (uid1, uname1) = setup_user().await;
        let email1 = format!("{uname1}@example.com");
        let (uid2, uname2) = setup_user().await;
        let email2 = format!("{uname2}@example.com");

        let state = Arc::new(Mutex::new(MockState {
            challenge: None,
            reg_state: None,
            user_id: Some(uid1),
            username: Some(email1.clone()),
        }));

        let (port, _wa) = start_webauthn_server(state.clone()).await;

        let (page, cdp_port) = match get_chromium_page().await {
            Some(p) => p,
            None => return,
        };

        // --- REGISTRATION ---
        let reg_url = format!("http://localhost:{port}/register.html");


        page.goto(&reg_url, None).await.unwrap();
        let _ws_stream = crate::common::setup_chromium_virtual_authenticator(cdp_port, Some("localhost")).await;

        // --- L3 path (User 1) ---
        page.goto(&reg_url, None).await.unwrap();
        let btn_l3 = page.locator("#btn-l3").await;
        btn_l3.click(None).await.unwrap();
        for _ in 0..60 {
            if page.url().contains("passkey_registered") { break; }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(page.url().contains("passkey_registered"), "[L3] Redirect failed, stuck on {}", page.url());
        let row1 = pg::query_one("select credential from webauthns where user_id = $1",
                                 &[&uid1]).await.unwrap();
        let passkey: Passkey = serde_json::from_value(row1.get::<_, serde_json::Value>(0)).unwrap();
        assert!(passkey.get_public_key().get_openssl_pkey().is_ok());


        // --- Fallback path (User 2) ---
        {
            let mut lock = state.lock().unwrap();
            lock.user_id = Some(uid2);
            lock.username = Some(email2.clone());
            lock.challenge = None;
            lock.reg_state = None;
        }
        page.goto(&reg_url, None).await.unwrap();
        let btn_fb = page.locator("#btn-fb").await;
        btn_fb.click(None).await.unwrap();
        for _ in 0..60 {
            if page.url().contains("passkey_registered") { break; }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        assert!(page.url().contains("passkey_registered"), "[Fallback] Redirect failed, stuck on {}", page.url());
        let row2 = pg::query_one("select credential from webauthns where user_id = $1",
                                 &[&uid2]).await.unwrap();
        let passkey2: Passkey = serde_json::from_value(row2.get::<_, serde_json::Value>(0)).unwrap();
        assert!(passkey2.get_public_key().get_openssl_pkey().is_ok());

        // --- Authentication (User 1) ---
        {
            let mut lock = state.lock().unwrap();
            lock.username = Some(email1.clone());
        }
        let auth_url = format!("http://localhost:{port}/login.html");
        page.goto(&auth_url, None).await.unwrap();
        let btn_auth = page.locator("#btn-auth").await;
        btn_auth.click(None).await.unwrap();
        for _ in 0..60 {
            if page.url().contains("authenticated") { break; }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(page.url().contains("authenticated"), "Auth 1 redirect failed, stuck on {}", page.url());

        // --- Guard from deletion (User 1) ---
        let id = BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice());
        assert_eq!(Err(WebAuthnError::Rejected), delete_passkey(&id, &uid1).await);
        let row1 = pg::query_one("select credential from webauthns where user_id = $1",
                                 &[&uid1]).await.unwrap();
        let passkey: Passkey = serde_json::from_value(row1.get::<_, serde_json::Value>(0)).unwrap();
        assert!(passkey.get_public_key().get_openssl_pkey().is_ok());

        // --- Authentication (User 2) ---
        {
            let mut lock = state.lock().unwrap();
            lock.username = Some(email2.clone());
        }
        page.goto(&auth_url, None).await.unwrap();
        let btn_auth2 = page.locator("#btn-auth2").await;
        if btn_auth2.count().await.unwrap_or(0) > 0 {
            btn_auth2.click(None).await.unwrap();
        } else {
            // If btn-auth is reused
            page.locator("#btn-auth").await.click(None).await.unwrap();
        }
        for _ in 0..60 {
            if page.url().contains("authenticated") { break; }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        assert!(page.url().contains("authenticated"), "Auth 2 redirect failed, stuck on {}", page.url());

        // --- Guard from deletion (User 2) ---
        let id = BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice());
        assert_eq!(Err(WebAuthnError::Rejected), delete_passkey(&id, &uid2).await);
        let row2 = pg::query_one("select credential from webauthns where user_id = $1",
                                 &[&uid2]).await.unwrap();
        let passkey2: Passkey = serde_json::from_value(row2.get::<_, serde_json::Value>(0)).unwrap();
        assert!(passkey.get_public_key().get_openssl_pkey().is_ok());
    }
}

pub(crate) async fn start_webauthn_server(state: Arc<Mutex<MockState>>) -> (u16, webauthn_rs::Webauthn) {
    let html_reg = r#"
        <!DOCTYPE html><html><body>
        <input id="agent" value="test-device">
        <span id="err"></span>
        <button id="btn-l3">Register L3</button>
        <button id="btn-fb">Register Fallback</button>
        <script src="/passkey-client-register.js"></script>
        <script>
            // WebAuthn stripping – essential for virtual authenticator in headless mode
            if (navigator.credentials && navigator.credentials.create) {
                const _orig = navigator.credentials.create;
                navigator.credentials.create = async function(options) {
                    if (options && options.publicKey) {
                        if (options.publicKey.authenticatorSelection) {
                            delete options.publicKey.authenticatorSelection.authenticatorAttachment;
                        }
                        if (options.publicKey.extensions) {
                            delete options.publicKey.extensions.credentialProtectionPolicy;
                        }
                    }
                    return await _orig.call(navigator.credentials, options);
                };
            }
            if (navigator.credentials && navigator.credentials.get) {
                const _origGet = navigator.credentials.get;
                navigator.credentials.get = async function(options) {
                    if (options && options.publicKey && options.publicKey.extensions) {
                        delete options.publicKey.extensions.credentialProtectionPolicy;
                    }
                    return await _origGet.call(navigator.credentials, options);
                };
            }
            if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
                const _origParse = PublicKeyCredential.parseCreationOptionsFromJSON;
                PublicKeyCredential.parseCreationOptionsFromJSON = function(json) {
                    if (json && json.authenticatorSelection) {
                        delete json.authenticatorSelection.authenticatorAttachment;
                    }
                    if (json && json.extensions) {
                        delete json.extensions.credentialProtectionPolicy;
                        delete json.extensions.enforceCredentialProtectionPolicy;
                    }
                    return _origParse.call(PublicKeyCredential, json);
                };
            }

            document.getElementById('btn-l3').addEventListener('click', function() {
                register_passkey(false).catch(function(e) {
                    document.getElementById('err').innerText = String(e);
                });
            });
            document.getElementById('btn-fb').addEventListener('click', function() {
                register_passkey(true).catch(function(e) {
                    document.getElementById('err').innerText = String(e);
                });
            });
        </script>
    </body></html>"#;
    let html_login = r#"<!DOCTYPE html><html><body>
        <span id="err"></span>
        <button id="btn-auth">Authenticate</button>
        <script src="/passkey-client-authn.js"></script>
        <script>
            document.getElementById('btn-auth').addEventListener('click', function() {
                load_challenge('/auth/webauthn/login/challenge').then(function(challenge) {
                    return webauthn_auth('/auth/webauthn/login/apply', challenge);
                }).then(function(res) {
                    if (res && res.ok) { location = '/auth/account?authenticated'; }
                    else { document.getElementById('err').innerText = 'auth failed: ' + (res ? res.status : 'null'); }
                }).catch(function(e) {
                    document.getElementById('err').innerText = String(e);
                });
            });
        </script>
    </body></html>"#;

    let route_html_reg = warp::path("register.html").map(move || warp::reply::html(html_reg));
    let route_html_login = warp::path("login.html").map(move || warp::reply::html(html_login));

    let js_reg = std::fs::read_to_string("javascript/passkey-client-register.js").expect("Failed to read JS");
    let route_js_reg = warp::path("passkey-client-register.js")
        .map(move || warp::reply::with_header(js_reg.clone(), "Content-Type", "application/javascript"));

    let js_auth = std::fs::read_to_string("javascript/passkey-client-authn.js").expect("Failed to read JS");
    let route_js_auth = warp::path("passkey-client-authn.js")
        .map(move || warp::reply::with_header(js_auth.clone(), "Content-Type", "application/javascript"));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let origin = reqwest::Url::parse(&format!("http://localhost:{port}")).unwrap();
    let builder = webauthn_rs::WebauthnBuilder::new("localhost", &origin).unwrap();
    let wa = builder.build().unwrap();
    
    let state_clone = state.clone();
    let wa_reg = wa.clone();
    let route_reg_challenge = warp::path!("auth" / "webauthn" / "register" / "challenge")
        .and(warp::post())
        .and_then(move || {
            let state = state_clone.clone();
            let wa = wa_reg.clone();
            async move {
                let uid = state.lock().unwrap().user_id.unwrap();
                let (challenge, reg_state) = generate_challenge_register(&wa, uid, 1)
                    .await
                    .map_err(|_| warp::reject::custom(WebAuthnTestError))?;
                let mut lock = state.lock().unwrap();
                lock.challenge = Some(challenge.clone());
                lock.reg_state = Some(reg_state);
                let json_val = serde_json::to_value(&challenge).unwrap();
                Ok::<_, warp::Rejection>(warp::reply::json(&json_val))
            }
        });

    let wa_reg_apply = wa.clone();
    let state_reg_apply = state.clone();
    let route_reg_apply = warp::path!("auth" / "webauthn" / "register" / "apply")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::header::<String>("X-Register-Device"))
        .and_then(move |body: serde_json::Value, device: String| {
            let state = state_reg_apply.clone();
            let wa = wa_reg_apply.clone();
            async move {
                let (uid, reg_state) = {
                    let mut lock = state.lock().unwrap();
                    let uid = lock.user_id.unwrap();
                    let reg_state = lock.reg_state.take().expect("No reg state");
                    (uid, reg_state)
                };

                let reg: webauthn_rs::prelude::RegisterPublicKeyCredential = match serde_json::from_value(body.clone()) {
                    Ok(r) => r,
                    Err(_) => return Err(warp::reject::custom(WebAuthnTestError)),
                };

                let passkey = auth_shards::webauthn::try_generate_passkey(&wa, &reg, &reg_state).await
                    .map_err(|_| warp::reject::custom(WebAuthnTestError))?;

                auth_shards::webauthn::register_passkey(&uid, &passkey, &device, 10).await
                    .map_err(|_| warp::reject::custom(WebAuthnTestError))?;

                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "status": "ok" })))
            }
        });

    let state_clone2 = state.clone();
    let wa_auth = wa.clone();
    let route_auth_challenge = warp::path!("auth" / "webauthn" / "login" / "challenge")
        .and(warp::post())
        .and_then(move || {
            let state = state_clone2.clone();
            let wa = wa_auth.clone();
            async move {
                let email = state.lock().unwrap().username.clone();
                let (challenge, auth_state) = generate_challenge_authentication(&wa, email.as_deref())
                    .await
                    .map_err(|_| warp::reject::custom(WebAuthnTestError))?;
                let mut lock = state.lock().unwrap();
                lock.reg_state = Some(auth_state);
                Ok::<_, warp::Rejection>(warp::reply::json(&challenge))
            }
        });

    let wa_auth_apply = wa.clone();
    let state_auth_apply = state.clone();
    let route_auth_apply = warp::path!("auth" / "webauthn" / "login" / "apply")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |body: serde_json::Value| {
            let state = state_auth_apply.clone();
            let wa = wa_auth_apply.clone();
            async move {
                let auth_state = {
                    let mut lock = state.lock().unwrap();
                    lock.reg_state.take().expect("No auth state")
                };

                let cred: webauthn_rs::prelude::PublicKeyCredential = match serde_json::from_value(body.clone()) {
                    Ok(c) => c,
                    Err(_) => return Err(warp::reject::custom(WebAuthnTestError)),
                };

                let _ = auth_shards::webauthn::authenticate_named_passkey(&wa, &cred, &auth_state).await
                    .map_err(|_| warp::reject::custom(WebAuthnTestError))?;

                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "status": "ok" })))
            }
        });

    let route_account = warp::path!("auth" / "account")
        .map(|| warp::reply::html("<html><body>Account Page (Stub)</body></html>"));

    let routes = route_html_reg.or(route_html_login).or(route_js_reg).or(route_js_auth)
        .or(route_reg_challenge)
        .or(route_reg_apply)
        .or(route_auth_challenge)
        .or(route_auth_apply)
        .or(route_account);

    crate::common::start_server_on_port(routes, port);
    (port, wa)
}
