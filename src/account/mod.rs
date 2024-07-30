use log::error;
use pg_pool::pg;
use thiserror::Error;
use uuid::Uuid;
use crate::AuthType;

#[derive(Error, Debug, PartialEq)]
pub enum AccountError {
    #[error("db access aborted")]
    Db,
}

pub async fn login_trace(
    uid: &Uuid,
    authn: AuthType,
    success: bool,
    force: bool
) -> Result<(), AccountError> {
    let trace = pg::execute("CALL login_trace($1, $2, $3, $4)",
                            &[&uid, &(authn as i16), &success, &force])
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
