use crate::common::{get_chromium_page, setup, setup_user, setup_console_tracker};
use auth_shards::webauthn::{
    delete_passkey,
    generate_challenge_authentication,
    generate_challenge_register,
    WebAuthnError,
};
use base64::prelude::*;
use log::debug;
use pg_pool::pg;
use playwright_rs::expect;
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
    async fn it_registers_and_authenticates_passkey_l3() {
        test_registers_and_authenticates_passkey(false).await;
    }

    async fn it_registers_and_authenticates_passkey_fallback() {
        test_registers_and_authenticates_passkey(true).await;
    }
}

async fn test_registers_and_authenticates_passkey(fallback: bool) {
    let fallback_param = match fallback {
        true => "&force_fallback=1",
        false => ""
    };
    let _pool = setup().await;
    let (uid1, uname1) = setup_user().await;
    let email1 = format!("{uname1}@example.com");

    let state = Arc::new(Mutex::new(MockState {
        challenge: None,
        reg_state: None,
        user_id: Some(uid1),
        username: Some(email1.clone()),
    }));

    let (port, _wa) = start_webauthn_server(state.clone()).await;
    let (page, cdp_port) = get_chromium_page()
        .await
        .expect("Chromium browser is required for passkey browser tests");

    // --- REGISTRATION ---
    let reg_url = format!("http://localhost:{port}/register.html?{fallback_param}");

    page.goto(&reg_url, None).await.unwrap();
    setup_console_tracker(&page).await;
    let _ws_stream = crate::common::setup_chromium_virtual_authenticator(cdp_port, Some("localhost")).await;

    page.goto(&reg_url, None).await.unwrap();
    let btn_l3 = page.locator("#btn-register").await;
    btn_l3.click(None).await.unwrap();

    // Check for errors early before expect timeout
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    crate::assert_no_console_errors!(&page);

    expect(page.locator("body#account").await)
        .to_be_visible().await.unwrap();
    assert!(page.url().contains("passkey_registered"), "[L3] Redirect failed, stuck on {}", page.url());
    let row1 = pg::query_one("select credential from webauthns where user_id = $1",
                             &[&uid1]).await.unwrap();
    let passkey: Passkey = serde_json::from_value(row1.get::<_, serde_json::Value>(0)).unwrap();
    assert!(passkey.get_public_key().get_openssl_pkey().is_ok());

    // --- Authentication - EXPLICIT BUTTON CLICK ---
    let auth_url = format!("http://localhost:{port}/login.html?disable_conditional=1{fallback_param}");
    {
        let mut lock = state.lock().unwrap();
        lock.username = Some(email1.clone());
    }
    page.goto(&auth_url, None).await.unwrap();
    expect(page.locator("#btn-auth").await).to_be_enabled().await.unwrap();
    let btn_auth = page.locator("#btn-auth").await;
    btn_auth.click(None).await.unwrap();

    // Check for errors early
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    crate::assert_no_console_errors!(&page);

    expect(page.locator("body#account").await)
        .to_be_visible().await.unwrap();

    assert!(page.url().contains("authenticated"), "Auth 1 redirect failed, stuck on {}", page.url());

    // --- Guard from deletion ---
    let id = BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice());
    assert_eq!(Err(WebAuthnError::Rejected), delete_passkey(&id, &uid1).await);
    let row1 = pg::query_one("select credential from webauthns where user_id = $1",
                             &[&uid1]).await.unwrap();
    let passkey: Passkey = serde_json::from_value(row1.get::<_, serde_json::Value>(0)).unwrap();
    assert!(passkey.get_public_key().get_openssl_pkey().is_ok());

    // --- Authentication - CONDITIONAL UI ---
    {
        let mut lock = state.lock().unwrap();
        lock.username = Some(email1.clone());
    }
    let auth_url2 = format!("http://localhost:{port}/login.html?{fallback_param}");
    page.goto(&auth_url2, None).await.unwrap();

    // Wait for conditional UI to finish automatically due to CPD
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    crate::assert_no_console_errors!(&page);

    expect(page.locator("body#account").await)
        .to_be_visible().await.unwrap();

    assert!(page.url().contains("authenticated"), "Auth 2 redirect failed, stuck on {}", page.url());

    crate::assert_no_console_errors!(&page);
}

pub(crate) async fn start_webauthn_server(state: Arc<Mutex<MockState>>) -> (u16, webauthn_rs::Webauthn) {
    let html_reg = r#"<html><body>
        <input id="agent" value="test-device">
        <span id="err"></span>
        <button id="btn-register">Register</button>
        <script>
            const params = new URLSearchParams(globalThis.location.search);
            const forceFallback = params.has('force_fallback');
            if (forceFallback) {
              globalThis.PublicKeyCredential.parseCreationOptionsFromJSON = undefined;
            }
            // WebAuthn stripping – essential for virtual authenticator in headless mode
            if (navigator.credentials?.create) {
                const _orig = navigator.credentials.create;
                navigator.credentials.create = async function(options) {
                    if (options?.publicKey) {
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
            if (navigator.credentials?.get) {
                const _origGet = navigator.credentials.get;
                navigator.credentials.get = async function(options) {
                    if (options?.publicKey && options.publicKey.extensions) {
                        delete options.publicKey.extensions.credentialProtectionPolicy;
                    }
                    try {
                        const __res = await _origGet.call(navigator.credentials, options);
                        if (!__res) document.getElementById('err').innerText += ' | get() returned ' + __res;
                        return __res;
                    } catch (e) {
                        document.getElementById('err').innerText += ' | get() threw ' + e.name;
                        throw e;
                    }
                };
            }
            if (globalThis?.PublicKeyCredential.parseCreationOptionsFromJSON) {
                const _origParse = PublicKeyCredential.parseCreationOptionsFromJSON;
                PublicKeyCredential.parseCreationOptionsFromJSON = function(json) {
                    if (json?.authenticatorSelection) {
                        delete json.authenticatorSelection.authenticatorAttachment;
                    }
                    if (json?.extensions) {
                        delete json.extensions.credentialProtectionPolicy;
                        delete json.extensions.enforceCredentialProtectionPolicy;
                    }
                    return _origParse.call(PublicKeyCredential, json);
                };
            }
        </script>
        <script type="module">
          import { load_challenge, register_passkey } from "/passkey-client-register.js";

          const t = await load_challenge('/auth/webauthn/register/challenge');
          document.querySelector('#btn-register').addEventListener('click', function() {
            register_passkey('/auth/webauthn/register/apply')
            .then(function(res) {
              location = '/auth/account?passkey_registered';
            }).catch(function(e) {
              console.error(e);
            });
          })
        </script>
    </body></html>"#;
    let html_login = r#"<html><body>
        <span id="err"></span>
        <button id="btn-auth" disabled>Authenticate</button>
        <script type="module">
          import { load_challenge, setup_conditional, passkey_btn_handler } from "/passkey-client-authn.js";

          const params = new URLSearchParams(globalThis.location.search);
          const disableConditional = params.has('disable_conditional');

          const forceFallback = params.has('force_fallback');
          if (forceFallback) {
            globalThis.PublicKeyCredential.parseRequestOptionsFromJSON = undefined;
          }
          await load_challenge('/auth/webauthn/login/challenge');
          if (!disableConditional) {
             setup_conditional('/auth/webauthn/login/apply').then(async function(res) {
                 if (res && res.ok) { location = '/auth/account?authenticated'; }
             }).catch(console.error);
          }

          document.getElementById('btn-auth').addEventListener('click', function() {
                passkey_btn_handler('/auth/webauthn/login/apply')
                  .then(async function(res) {
                    if (res && res.ok) { location = '/auth/account?authenticated'; }
                    else { document.getElementById('err').innerText = 'auth failed: ' + (res ? `${res.status} ${await res.text()}` : 'null'); }
                })
                  .catch(function(e) {
                    document.getElementById('err').innerText = String(e);
                })
          });

          document.querySelector('#btn-auth').disabled = false;
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
                    let reg_state = match lock.reg_state.take() {
                        Some(s) => s,
                        None => return Err(warp::reject::custom(WebAuthnTestError)),
                    };
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
                    match lock.reg_state.take() {
                        Some(s) => s,
                        None => return Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "status": "ok" }))),
                    }
                };

                let cred: webauthn_rs::prelude::PublicKeyCredential = match serde_json::from_value(body.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("[Server] JSON Parse Error: {:?}", e);
                        return Err(warp::reject::custom(WebAuthnTestError));
                    }
                };

                if let Err(e) = auth_shards::webauthn::authenticate_named_passkey(&wa, &cred, &auth_state).await {
                    panic!("[Server] EXACT AUTH FAILED REASON: {:#?}", e);
                }

                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "status": "ok" })))
            }
        });

    let route_account = warp::path!("auth" / "account")
        .map(|| warp::reply::html("<html><body id=\"account\">Account Page (Stub)</body></html>"));

    let routes = route_html_reg.or(route_html_login).or(route_js_reg).or(route_js_auth)
        .or(route_reg_challenge)
        .or(route_reg_apply)
        .or(route_auth_challenge)
        .or(route_auth_apply)
        .or(route_account);

    crate::common::start_server_on_port(routes, port).await;
    (port, wa)
}
