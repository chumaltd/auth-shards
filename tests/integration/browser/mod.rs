use crate::common::{get_chromium_page, get_webkit_page};
use playwright_rs::Page;
use warp::Filter;

mod passkey; // Register the new module

async fn check_redirect(page: Page, port: u16) {
    let url = format!("http://127.0.0.1:{}/redirect", port);
    page.goto(&url, None).await.expect("Failed to goto");
    let current_url = page.url();

    assert_eq!(current_url, "https://example.com/target");
}

crate::test! {
    async fn it_redirects_external_chromium() {
        let (page, _cdp_port) = match get_chromium_page().await {
            Some(p) => p,
            None => return, // Skip test
        };

        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/target").unwrap());

        let port = crate::common::start_server(route);

        check_redirect(page, port).await;
    }

    async fn it_redirects_external_webkit() {
        let page = match get_webkit_page().await {
            Some(p) => p,
            None => return,
        };

        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/target").unwrap());

        let port = crate::common::start_server(route);

        check_redirect(page, port).await;
    }
}
