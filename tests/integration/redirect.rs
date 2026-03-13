use reqwest::header::{CACHE_CONTROL, EXPIRES, LOCATION, PRAGMA};
use reqwest::redirect::Policy;
use warp::Filter;

fn assert_common_redirect_headers(headers: &reqwest::header::HeaderMap, expected_location: &str) {
    assert_eq!(headers.get(LOCATION).unwrap(), expected_location);
    assert_eq!(
        headers.get(CACHE_CONTROL).unwrap(),
        "no-store, max-age=0, must-revalidate"
    );
    assert_eq!(headers.get(PRAGMA).unwrap(), "no-cache");
    assert_eq!(headers.get(EXPIRES).unwrap(), "0");
}

async fn get_redirect_response<F>(route: F) -> reqwest::Response
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    let port = crate::common::start_server(route).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();

    client
        .get(format!("http://127.0.0.1:{port}/redirect"))
        .send()
        .await
        .unwrap()
}

crate::test! {
    async fn redirect_internal_from_relative_path_returns_expected_headers() {
        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_internal("/account?authenticated=1#ok").unwrap());
        let res = get_redirect_response(route).await;

        assert_eq!(res.status(), reqwest::StatusCode::SEE_OTHER);
        assert_common_redirect_headers(res.headers(), "/account?authenticated=1#ok");
    }

    async fn redirect_internal_from_absolute_url_returns_path_headers() {
        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_internal("https://foo.example/path?q=1#frag").unwrap());
        let res = get_redirect_response(route).await;

        assert_eq!(res.status(), reqwest::StatusCode::SEE_OTHER);
        assert_common_redirect_headers(res.headers(), "/path?q=1#frag");
    }

    async fn redirect_external_https_url_returns_expected_headers() {
        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/target").unwrap());
        let res = get_redirect_response(route).await;

        assert_eq!(res.status(), reqwest::StatusCode::SEE_OTHER);
        assert_common_redirect_headers(res.headers(), "https://example.com/target");
    }

    async fn redirect_external_with_query_and_fragment_returns_expected_headers() {
        let route = warp::path("redirect")
            .map(|| auth_shards::warp::redirect_external("https://example.com/path/to?p=1#ok").unwrap());
        let res = get_redirect_response(route).await;

        assert_eq!(res.status(), reqwest::StatusCode::SEE_OTHER);
        assert_common_redirect_headers(res.headers(), "https://example.com/path/to?p=1#ok");
    }

    async fn redirect_subdomain_returns_expected_headers() {
        let route = warp::path("redirect").map(|| {
            auth_shards::warp::redirect_subdomain(
                "https://tenant.dev.example.com/path/to?p=1#ok",
                "dev.example.com",
            )
            .unwrap()
        });
        let res = get_redirect_response(route).await;

        assert_eq!(res.status(), reqwest::StatusCode::SEE_OTHER);
        assert_common_redirect_headers(
            res.headers(),
            "https://tenant.dev.example.com/path/to?p=1#ok"
        );
    }
}
