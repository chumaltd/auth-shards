use log::error;
use regex::Regex;
use warp::{
    redirect::see_other,
    reject,
    reply::{self, Reply},
    http::Uri,
    Filter, Rejection
};
pub mod rejection;

use crate::util::ClientContext;
use crate::session::{SessionManager, SessionError};
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

pub fn redirect_no_cache(path: impl Into<String>) -> Result<reply::Response, Rejection> {
    let redirect_path: Uri = ensure_abs(path).try_into().map_err(|e| {
        error!("{e}");
        reject::reject()
    })?;

    Ok(reply::with_header(
        see_other(redirect_path),
        "cache-control",
        "no-cache"
    ).into_response())
}

pub fn redirect_external(url: impl Into<String>) -> Result<reply::Response, Rejection> {
    let redirect_url: Uri = url.into().try_into().map_err(|e| {
        error!("{e}");
        reject::reject()
    })?;

    Ok(reply::with_header(
        see_other(redirect_url),
        "cache-control",
        "no-cache"
    ).into_response())
}


fn ensure_abs(path: impl Into<String>) -> String {
    let re = Regex::new(r"^/*([^/].*)$").unwrap();
    let path = path.into();
    let path = re.captures(&path)
        .and_then(|cap| cap.get(1).map(|m| m.as_str()))
        .unwrap_or("");
    format!("/{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
