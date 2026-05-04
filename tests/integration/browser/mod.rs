use crate::common::{get_chromium_page, get_webkit_page};
use playwright_rs::{Page, expect_page};
use warp::Filter;

mod passkey; // Register the new module

async fn check_redirect(page: Page, port: u16) {
    let url = format!("http://127.0.0.1:{}/redirect", port);
    page.goto(&url, None).await.expect("Failed to goto");
    expect_page(&page)
        .to_have_url("https://example.com/target")
        .await
        .expect("redirect URL");
}

crate::test! {
    async fn it_redirects_external_chromium() {
        let page = get_chromium_page()
            .await
            .expect("Chromium browser is required for this test");

        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/target").unwrap());

        let port = crate::common::start_server(route).await;

        check_redirect(page, port).await;
    }

    async fn it_redirects_external_webkit() {
        let page = get_webkit_page()
            .await
            .expect("WebKit browser is required for this test");

        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/target").unwrap());

        let port = crate::common::start_server(route).await;

        check_redirect(page, port).await;
    }
}
