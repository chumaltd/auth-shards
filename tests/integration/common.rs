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

async fn get_playwright() -> &'static Playwright {
    GLOBAL_PLAYWRIGHT.get_or_init(|| async {
        Playwright::launch().await.expect("Failed to init playwright")
    }).await
}

pub async fn get_chromium_page() -> Option<Page> {
    let browser_opt = GLOBAL_CHROMIUM.get_or_init(|| async {
        let p = get_playwright().await;
        match p.chromium().launch().await {
            Ok(b) => Some(b),
            Err(e) => {
                log::info!("Skipping chromium tests: Failed to launch browser: {:?}", e);
                None
            }
        }
    }).await;

    if let Some(browser) = browser_opt {
        Some(browser.new_page().await.expect("Failed to create chromium page"))
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
