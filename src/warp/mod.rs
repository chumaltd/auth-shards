use log::error;
use warp::{
    reject,
    reply::{self, Reply},
    http::{header, status::StatusCode},
    Filter, Rejection
};
pub mod rejection;

use crate::util::ClientContext;
use crate::util::normalize_redirect_url;
use crate::session::{SessionManager, SessionError};
use crate::normalize_return_path;
use crate::normalize_return_url;
use self::rejection::{NoLogin, NoLoginA};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use async_session::Session;

/// Shared filter to extract ClientContext from request headers.
///
/// Rejects with a simple rejection if ClientContext validation fails.
pub fn client_context() -> impl Filter<Extract = (ClientContext,), Error = Rejection> + Clone {
    warp::header::optional::<String>("sec-ch-ua")
        .and(warp::header::optional::<String>("sec-ch-ua-platform"))
        .and(warp::header::optional::<String>("sec-ch-ua-model"))
        .and(warp::header::optional::<String>("user-agent"))
        .and_then(|brands, platform, model, ua| async move {
            ClientContext::new(brands, platform, model, ua)
                .map_err(|_| reject::reject())
        })
}

pub fn validate(
    session: &Session,
    client: &ClientContext,
    path: &str,
    manager: &'static SessionManager,
) -> Result<(), Rejection> {
    match manager.validate(session, client) {
        Ok(_) => Ok(()),
        Err(e) => {
            if let SessionError::NoLogin = e {
                // No log for expected NoLogin
            } else {
                error!("Session Validation Error: {:?}", e);
            }
            Err(reject::custom(NoLogin {
                path: utf8_percent_encode(path, NON_ALPHANUMERIC).to_string(),
            }))
        }
    }
}

pub fn validate_api(
    session: &Session,
    client: &ClientContext,
    manager: &'static SessionManager,
) -> Result<(), Rejection> {
    match manager.validate(session, client) {
        Ok(_) => Ok(()),
        Err(e) => {
            if let SessionError::NoLogin = e {
                // No log for expected NoLogin
            } else {
                error!("Session Validation Error (API): {:?}", e);
            }
            Err(reject::custom(NoLoginA))
        }
    }
}

pub fn redirect_internal(path: impl Into<String>) -> Result<reply::Response, Rejection> {
    let redirect_path = normalize_return_path(&path.into(), None).ok_or_else(|| {
        error!("invalid redirect path");
        reject::reject()
    })?;

    let reply = reply::with_header(
        StatusCode::SEE_OTHER,
        header::LOCATION,
        redirect_path
    );
    Ok(append_no_cache_headers(reply).into_response())
}

pub fn redirect_external(url: impl Into<String>) -> Result<reply::Response, Rejection> {
    let redirect_url = normalize_redirect_url(&url.into()).map_err(|e| {
        error!("{e}");
        reject::reject()
    })?;

    let reply = reply::with_header(
        StatusCode::SEE_OTHER,
        header::LOCATION,
        String::from(redirect_url)
    );
    Ok(append_no_cache_headers(reply).into_response())
}

pub fn redirect_subdomain(
    url: impl Into<String>,
    domain: impl AsRef<str>,
) -> Result<reply::Response, Rejection> {
    let redirect_url = normalize_return_url(&url.into(), domain.as_ref()).ok_or_else(|| {
        error!("invalid subdomain redirect url");
        reject::reject()
    })?;

    let reply = reply::with_header(
        StatusCode::SEE_OTHER,
        header::LOCATION,
        redirect_url
    );
    Ok(append_no_cache_headers(reply).into_response())
}

pub fn append_no_cache_headers(reply: impl Reply) -> impl Reply {
    let reply = reply::with_header(
        reply,
        header::CACHE_CONTROL,
        "no-store, max-age=0, must-revalidate"
    );
    let reply = reply::with_header(reply, "Pragma", "no-cache");
    let reply = reply::with_header(reply, header::EXPIRES, "0");
    reply::with_header(reply, "X-Content-Type-Options", "nosniff")
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode as HttpStatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_client_context_modern() {
        let filter = client_context();
        let ctx = request()
            .header("sec-ch-ua", "Chromium;v=121")
            .header("sec-ch-ua-platform", "Windows")
            .header("sec-ch-ua-model", "Pixel 7")
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(ctx.brands, Some("Chromium;v=121".to_string()));
        assert_eq!(ctx.platform, Some("Windows".to_string()));
        assert_eq!(ctx.model, Some("Pixel 7".to_string()));
    }

    #[tokio::test]
    async fn test_client_context_legacy() {
        let filter = client_context();
        let ctx = request()
            .header("user-agent", "Mozilla/5.0")
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(ctx.ua, Some("Mozilla/5.0".to_string()));
        assert!(ctx.brands.is_none());
    }

    #[tokio::test]
    async fn test_client_context_mixed() {
        let filter = client_context();
        let ctx = request()
            .header("sec-ch-ua", "Chromium;v=121")
            .header("user-agent", "Mozilla/5.0")
            .filter(&filter)
            .await
            .unwrap();

        // Both should be captured; logic in compute_hash handles priority
        assert_eq!(ctx.brands, Some("Chromium;v=121".to_string()));
        assert_eq!(ctx.ua, Some("Mozilla/5.0".to_string()));
    }

    #[tokio::test]
    async fn test_client_context_missing_success() {
        let filter = client_context();
        let res = request()
            .filter(&filter)
            .await;

        assert!(res.is_ok(), "Should NOT reject even if both brands and ua are missing");
    }

    #[tokio::test]
    async fn test_redirect_subdomain_accepts_allowed_subdomain() {
        let response = redirect_subdomain(
            "https://tenant.dev.example.com/path?q=1#frag",
            "dev.example.com",
        )
        .unwrap();

        assert_eq!(response.status(), HttpStatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://tenant.dev.example.com/path?q=1#frag"
        );
    }

    #[tokio::test]
    async fn test_redirect_subdomain_rejects_foreign_domain() {
        let response = redirect_subdomain(
            "https://example.com/path?q=1#frag",
            "dev.example.com",
        );

        assert!(response.is_err());
    }
}
