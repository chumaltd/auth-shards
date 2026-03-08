use log::debug;
use pg_pool::pg;
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use tokio::net::TcpListener;
use fs4::fs_std::FileExt;


pub struct TestPool;

/// A custom test macro that ensures the Tokio runtime is multi-threaded.
/// This is REQUIRED to prevent deadlocks during `TestPool::drop`.
///
/// DEADLOCK EXPLANATION:
/// `TestPool::drop` cleans up the database by running `TRUNCATE`.
/// Since `Drop` is synchronous, it spawns a thread and blocks waiting for it (`join`).
/// If we use the default single-threaded runtime (`current_thread`), the `Drop` block
/// prevents the runtime from polling the I/O reactor, causing the cleanup task (which
/// uses the global `pg` connection bound to that reactor) to hang indefinitely.
///
/// Using `multi_thread` runtime ensures the reactor runs on a separate worker thread,
/// allowing I/O to complete even while the main test thread is blocked in `drop`.
#[macro_export]
macro_rules! test {
    ($($item:item)*) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            $item
        )*
    }
}

const LOCK_FILE: &str = "target/cargo-test.lock";

fn with_lock<F, R>(f: F) -> R
where F: FnOnce(&mut File) -> R
{
    loop {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(LOCK_FILE)
            .expect("Failed to open lock file");

        if file.lock_exclusive().is_err() {
            panic!("Failed to lock file");
        }

        if std::fs::metadata(LOCK_FILE).is_ok() {
             let result = f(&mut file);
             file.unlock().ok();
             return result;
        } else {
             file.unlock().ok();
             continue;
        }
    }
}

/// Reads PIDs from file, filters out dead ones, and returns the (clean_pids, my_pid_exists).
fn read_and_clean_pids(file: &mut File) -> Vec<u32> {
    let mut content = String::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    if file.read_to_string(&mut content).is_err() {
        return Vec::new();
    }

    let my_pid = std::process::id();
    let pids: Vec<u32> = content
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect();

    // Filter dead PIDs
    // On Linux, checking /proc/<pid> is a safe and standard way to check process existence.
    let active_pids: Vec<u32> = pids.into_iter().filter(|&pid| {
        if pid == my_pid { return true; }
        std::path::Path::new("/proc").join(pid.to_string()).exists()
    }).collect();

    active_pids
}

fn write_pids(file: &mut File, pids: &[u32]) {
    file.seek(SeekFrom::Start(0)).unwrap();
    file.set_len(0).unwrap();
    for pid in pids {
        writeln!(file, "{}", pid).unwrap();
    }
}

pub async fn setup() -> Arc<TestPool> {
    tokio::task::spawn_blocking(move || {
        with_lock(|file| {
            let mut pids = read_and_clean_pids(file);
            let my_pid = std::process::id();

            // If pids is empty, we are the first!
            if pids.is_empty() {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create init runtime");
                rt.block_on(truncate());
            }

            // Track each active test instance, even within the same PID.
            pids.push(my_pid);
            write_pids(file, &pids);
        });
    }).await.expect("Task failed");

    Arc::new(TestPool)
}

impl Drop for TestPool {
    fn drop(&mut self) {
        let _ = std::thread::spawn(|| {
            with_lock(|file| {
                let mut pids = read_and_clean_pids(file);
                let my_pid = std::process::id();

                // Remove self
                if let Some(pos) = pids.iter().position(|&p| p == my_pid) {
                    pids.remove(pos);
                }
                write_pids(file, &pids);

                if pids.is_empty() {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("Failed to create cleanup runtime");
                    rt.block_on(truncate());

                    // Do NOT remove file. Empty file means count=0.
                }
            });
        }).join();
    }
}

pub async fn truncate() {
    pg::execute("TRUNCATE users, orgs,
                 webauthns,
                 identities, google_identities,
                 actlogs",
        &[]).await.unwrap();
}

pub async fn setup_user() -> (uuid::Uuid, String) {
    let id = uuid::Uuid::now_v7();
    let name = format!("user-{id}");
    let email = format!("{name}@example.com");

    pg::execute("INSERT INTO users (email, id, name) VALUES ($1, $2, $3)",
                &[&email, &id, &name]).await.unwrap();
    (id, name)
}

pub async fn setup_org() -> (uuid::Uuid, String) {
    let id = uuid::Uuid::now_v7();
    let name = format!("org-{id}");

    pg::execute("INSERT INTO orgs (id, name) VALUES ($1, $2)",
                &[&id, &name]).await.unwrap();
    (id, name)
}

use playwright_rs::Playwright;
use playwright_rs::{Browser, Page};

// Singletons for Playwright driver and Browser instances
static GLOBAL_PLAYWRIGHT: tokio::sync::OnceCell<Result<Playwright, String>> = tokio::sync::OnceCell::const_new();
static GLOBAL_CHROMIUM: tokio::sync::OnceCell<Result<(Browser, u16), String>> = tokio::sync::OnceCell::const_new();
static GLOBAL_WEBKIT: tokio::sync::OnceCell<Result<Browser, String>> = tokio::sync::OnceCell::const_new();

async fn get_playwright() -> Result<&'static Playwright, &'static str> {
    GLOBAL_PLAYWRIGHT.get_or_init(|| async {
        Playwright::launch()
            .await
            .map_err(|e| format!("Failed to init playwright: {e:?}"))
    }).await
    .as_ref()
    .map_err(|e| e.as_str())
}

fn allocate_local_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind dynamic local port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("Failed to read dynamic local port: {e}"))
}

pub async fn get_chromium_page() -> Result<(Page, u16), String> {
    let browser_entry = GLOBAL_CHROMIUM.get_or_init(|| async {
        let p = get_playwright()
            .await
            .map_err(|e| format!("Playwright unavailable: {e}"))?;
        let headless = std::env::var("HEADLESS").map(|v| v != "0").unwrap_or(true);
        let slow_mo = std::env::var("SLOW_MO").ok().and_then(|v| v.parse().ok());
        let mut last_err = String::from("unknown launch failure");

        for attempt in 1..=5 {
            let port = allocate_local_port()?;
            let mut options = playwright_rs::api::LaunchOptions::default()
                .headless(headless)
                .args(vec![
                    format!("--remote-debugging-port={port}")
                ]);

            if let Some(ms) = slow_mo {
                options = options.slow_mo(ms);
            }

            match p.chromium().launch_with_options(options).await {
                Ok(b) => return Ok((b, port)),
                Err(e) => {
                    last_err = format!("{e:?}");
                    log::warn!(
                        "Chromium launch attempt {attempt}/5 failed on CDP port {port}: {last_err}"
                    );
                }
            }
        }

        Err(format!("Failed to launch chromium after 5 attempts: {last_err}"))
    }).await;

    let (browser, port) = browser_entry
        .as_ref()
        .map_err(|e| e.clone())?;

    let page = browser
        .new_page()
        .await
        .map_err(|e| format!("Failed to create chromium page: {e:?}"))?;

    Ok((page, *port))
}

pub async fn get_webkit_page() -> Result<Page, String> {
    let browser_entry = GLOBAL_WEBKIT.get_or_init(|| async {
        let p = get_playwright()
            .await
            .map_err(|e| format!("Playwright unavailable: {e}"))?;
        match p.webkit().launch().await {
            Ok(b) => Ok(b),
            Err(e) => Err(format!("Failed to launch webkit browser: {e:?}")),
        }
    }).await;

    let browser = browser_entry.as_ref().map_err(|e| e.clone())?;
    browser
        .new_page()
        .await
        .map_err(|e| format!("Failed to create webkit page: {e:?}"))
}

pub async fn start_server<F>(filter: F) -> u16
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = warp::serve(filter)
        .incoming(listener)
        .graceful(async {
            std::future::pending::<()>().await;
        }).run();
    tokio::spawn(server);

    port
}

pub async fn start_server_on_port<F>(filter: F, port: u16) -> u16
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    let server = warp::serve(filter)
        .bind(([127, 0, 0, 1], port)).await
        .graceful(async {
            std::future::pending::<()>().await;
        }).run();
    tokio::spawn(server);

    port
}

pub async fn setup_chromium_virtual_authenticator(cdp_port: u16, url_hint: Option<&str>) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use futures_util::{SinkExt, StreamExt};

    let client = reqwest::Client::new();
    let resp = client.get(format!("http://127.0.0.1:{cdp_port}/json")).send().await.expect("Failed to reach CDP json endpoint");
    let pages: Vec<serde_json::Value> = resp.json().await.expect("Failed to parse CDP json response");

    let target = if let Some(hint) = url_hint {
        pages.iter()
            .find(|p| p["type"].as_str() == Some("page") && p["url"].as_str().map(|u| u.contains(hint)).unwrap_or(false))
            .or_else(|| {
                debug!("[CDP] Warning: Could not find page matching hint '{hint}', falling back to first page");
                pages.iter().find(|p| p["type"].as_str() == Some("page"))
            })
    } else {
        pages.iter().find(|p| p["type"].as_str() == Some("page"))
    };

    let target = target.expect("No suitable page found in CDP");
    let ws_url = target["webSocketDebuggerUrl"].as_str().expect("No webSocketDebuggerUrl found").to_string();
    let target_url = target["url"].as_str().unwrap_or("unknown");
    debug!("[CDP] Targeting page: {}", target_url);

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&ws_url).await.expect("Failed to connect to CDP WebSocket");
    debug!("[CDP] Connected to WebSocket: {}", ws_url);

    // Helper: send a CDP command and wait for the response with the matching id,
    // discarding any interleaved browser events (which have no "id" field).
    async fn cdp_command(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        cmd: serde_json::Value,
    ) -> serde_json::Value {
        let id = cmd["id"].as_u64().expect("CDP command must have an id");
        ws.send(tokio_tungstenite::tungstenite::Message::Text(cmd.to_string().into()))
            .await.expect("Failed to send CDP command");

        // Drain messages until we find one with the matching id
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
                .await
                .expect("Timeout waiting for CDP response")
                .expect("CDP stream ended")
                .expect("CDP WebSocket error");

            let text = msg.to_text().expect("CDP message is not text");
            let val: serde_json::Value = serde_json::from_str(text).expect("Invalid CDP JSON");

            if val.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return val;
            }
            // Otherwise it's a browser event — discard and keep waiting
        }
    }

    // Enable WebAuthn virtual authenticator environment
    let enable_resp = cdp_command(&mut ws_stream, serde_json::json!({
        "id": 1,
        "method": "WebAuthn.enable",
        "params": { "enableUI": false }
    })).await;
    if enable_resp.get("error").is_some() {
        panic!("CDP WebAuthn.enable failed: {:?}", enable_resp);
    }
    debug!("[CDP] WebAuthn.enable OK");

    // Add virtual authenticator
    let add_resp = cdp_command(&mut ws_stream, serde_json::json!({
        "id": 2,
        "method": "WebAuthn.addVirtualAuthenticator",
        "params": {
            "options": {
                "protocol": "ctap2",
                "transport": "usb",
                "hasResidentKey": true,
                "hasUserVerification": true,
                "isUserVerified": true,
                "automaticPresenceSimulation": true
            }
        }
    })).await;
    if add_resp.get("error").is_some() {
        panic!("CDP WebAuthn.addVirtualAuthenticator failed: {:?}", add_resp);
    }
    debug!("[CDP] WebAuthn.addVirtualAuthenticator OK: {:?}", add_resp["result"].get("authenticatorId"));

    ws_stream
}

pub async fn setup_console_tracker(page: &Page) {
    // Clear any previous errors from sessionStorage at the start of a test run
    let _ = page.evaluate::<serde_json::Value, ()>("sessionStorage.removeItem('playwright-console-errors')", None).await;

    let script = r#"
        (function() {
            // Re-intercept console.error
            const _error = console.error;
            console.error = function(...args) {
                const msg = args.map(a => {
                    try {
                        if (a instanceof Error) {
                            return a.stack || a.message || String(a);
                        }
                        return (typeof a === 'object') ? JSON.stringify(a) : String(a);
                    } catch(e) { return String(a); }
                }).join(' ');

                let errors = sessionStorage.getItem('playwright-console-errors') || '';
                errors += (errors ? '\n' : '') + msg;
                sessionStorage.setItem('playwright-console-errors', errors);

                const div = document.getElementById('playwright-console-errors');
                if (div) div.innerText = errors;

                _error.apply(console, args);
            };

            window.addEventListener('error', e => {
                if (e.error) {
                    console.error('Global Error:', e.error);
                } else {
                    console.error('Global Error:', e.message);
                }
            });
            window.addEventListener('unhandledrejection', e => {
                console.error('Unhandled Promise Rejection:', e.reason);
            });

            // Create/update div if it doesn't exist (e.g. after navigation)
            function updateDiv() {
                let parent = document.body || document.documentElement;
                if (!parent) return;
                let div = document.getElementById('playwright-console-errors');
                if (!div) {
                    div = document.createElement('div');
                    div.id = 'playwright-console-errors';
                    div.style.display = 'none';
                    parent.appendChild(div);
                }
                div.innerText = sessionStorage.getItem('playwright-console-errors') || '';
            }

            if (document.body) updateDiv();
            const observer = new MutationObserver(() => {
                if (document.body && !document.getElementById('playwright-console-errors')) {
                    updateDiv();
                }
            });
            observer.observe(document, { childList: true, subtree: true });
            updateDiv();
        })();
    "#;
    page.add_init_script(script).await.expect("Failed to add init script");
    // Ensure it's injected if already on a page
    let _ = page.evaluate::<(), ()>(script, None).await;
}

pub async fn get_console_errors(page: &Page) -> String {
    page.evaluate::<serde_json::Value, String>("sessionStorage.getItem('playwright-console-errors') || ''", None)
        .await
        .unwrap_or_default()
}

#[macro_export]
macro_rules! assert_no_console_errors {
    ($page:expr) => {
        let text = crate::common::get_console_errors($page).await;
        if !text.is_empty() {
            panic!("Console errors detected:\n{}", text);
        }
    }
}
