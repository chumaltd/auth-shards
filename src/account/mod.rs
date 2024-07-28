use log::error;
use pg_pool::pg;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug, PartialEq)]
pub enum AccountError {
    #[error("db access aborted")]
    Db,
}

pub async fn login_trace(
    uid: &Uuid,
    password_login: bool,
    success: bool,
    force: bool
) -> Result<(), AccountError> {
    let trace = pg::execute("CALL login_trace($1, $2, $3)", &[&uid, &password_login, &success])
        .await
        .map_err(|e| {
            error!("login_trace: {e}");
            AccountError::Db
        });
    match force {
        true => trace?,
        false => trace.unwrap_or(0)
    };

    Ok(())
}
