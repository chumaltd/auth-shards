use log::error;
use regex::Regex;
use warp::{
    redirect::see_other,
    reject,
    reply::{self, Reply},
    http::Uri,
    Rejection
};

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
