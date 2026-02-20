use pg_pool::pg;
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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

            if !pids.contains(&my_pid) {
                pids.push(my_pid);
            }
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
static GLOBAL_PLAYWRIGHT: tokio::sync::OnceCell<Playwright> = tokio::sync::OnceCell::const_new();
static GLOBAL_CHROMIUM: tokio::sync::OnceCell<Option<Browser>> = tokio::sync::OnceCell::const_new();
static GLOBAL_WEBKIT: tokio::sync::OnceCell<Option<Browser>> = tokio::sync::OnceCell::const_new();
static GLOBAL_CHROMIUM_PORT: tokio::sync::OnceCell<u16> = tokio::sync::OnceCell::const_new();

async fn get_playwright() -> &'static Playwright {
    GLOBAL_PLAYWRIGHT.get_or_init(|| async {
        Playwright::launch().await.expect("Failed to init playwright")
    }).await
}

pub async fn get_chromium_page() -> Option<(Page, u16)> {
    let port = *GLOBAL_CHROMIUM_PORT.get_or_init(|| async {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind for dynamic CDP port");
        listener.local_addr().unwrap().port()
    }).await;

    let browser_opt = GLOBAL_CHROMIUM.get_or_init(|| async {
        let p = get_playwright().await;
        let headless = std::env::var("HEADLESS").map(|v| v != "0").unwrap_or(true);
        let slow_mo = std::env::var("SLOW_MO").ok().and_then(|v| v.parse().ok());

        let mut options = playwright_rs::api::LaunchOptions::default()
            .headless(headless)
            .args(vec![
                format!("--remote-debugging-port={}", port)
            ]);

        if let Some(ms) = slow_mo {
            options = options.slow_mo(ms);
        }

        match p.chromium().launch_with_options(options).await {
            Ok(b) => Some(b),
            Err(e) => {
                log::info!("Skipping chromium tests: Failed to launch browser: {:?}", e);
                None
            }
        }
    }).await;

    if let Some(browser) = browser_opt {
        let page = browser.new_page().await.expect("Failed to create chromium page");
        Some((page, port))
    } else {
        None
    }
}

pub async fn get_webkit_page() -> Option<Page> {
    let browser_opt = GLOBAL_WEBKIT.get_or_init(|| async {
        let p = get_playwright().await;
        match p.webkit().launch().await {
            Ok(b) => Some(b),
            Err(e) => {
                log::info!("Skipping webkit tests: Failed to launch browser: {:?}", e);
                None
            }
        }
    }).await;

    if let Some(browser) = browser_opt {
        Some(browser.new_page().await.expect("Failed to create webkit page"))
    } else {
        None
    }
}

pub fn start_server<F>(filter: F) -> u16
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    let (addr, server) = warp::serve(filter)
        .bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
            std::future::pending::<()>().await;
        });

    tokio::spawn(server);
    addr.port()
}

pub fn start_server_on_port<F>(filter: F, port: u16) -> u16
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    let (addr, server) = warp::serve(filter)
        .bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
            std::future::pending::<()>().await;
        });

    tokio::spawn(server);
    addr.port()
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
                println!("[CDP] Warning: Could not find page matching hint '{hint}', falling back to first page");
                pages.iter().find(|p| p["type"].as_str() == Some("page"))
            })
    } else {
        pages.iter().find(|p| p["type"].as_str() == Some("page"))
    };

    let target = target.expect("No suitable page found in CDP");
    let ws_url = target["webSocketDebuggerUrl"].as_str().expect("No webSocketDebuggerUrl found").to_string();
    let target_url = target["url"].as_str().unwrap_or("unknown");
    println!("[CDP] Targeting page: {}", target_url);

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&ws_url).await.expect("Failed to connect to CDP WebSocket");
    println!("[CDP] Connected to WebSocket: {}", ws_url);

    // Helper: send a CDP command and wait for the response with the matching id,
    // discarding any interleaved browser events (which have no "id" field).
    async fn cdp_command(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        cmd: serde_json::Value,
    ) -> serde_json::Value {
        let id = cmd["id"].as_u64().expect("CDP command must have an id");
        ws.send(tokio_tungstenite::tungstenite::Message::Text(cmd.to_string()))
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
    println!("[CDP] WebAuthn.enable OK");

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
    println!("[CDP] WebAuthn.addVirtualAuthenticator OK: {:?}", add_resp["result"].get("authenticatorId"));

    ws_stream
}
