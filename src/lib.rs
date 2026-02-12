pub mod account;
pub mod password;
pub mod session;
pub mod webauthn;
mod util;

pub use util::abs_path;
pub use util::ClientContext;
pub use util::resolve_aaguid_name;

#[cfg(feature = "google-openid")]
pub mod google;

#[cfg(feature = "warp")]
pub mod warp;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthType {
    Unknown,
    Mail,
    PasswordStrong,
    PasswordWeak,
    PasswordWeakUnmet, // Org requires PasswordStrong
    OpenidGoog,
    PassKey(String),
    AccessToken,
}

impl AuthType {
    pub fn to_u8(&self) -> u8 {
        match self {
            AuthType::Unknown => 0,
            AuthType::Mail => 1,
            AuthType::PasswordStrong => 2,
            AuthType::PasswordWeak => 3,
            AuthType::PasswordWeakUnmet => 4,
            AuthType::OpenidGoog => 5,
            AuthType::PassKey(_) => 6,
            AuthType::AccessToken => 7,
        }
    }
}

impl From<u8> for AuthType {
    fn from(origin: u8) -> Self {
        match origin {
            0 => AuthType::Unknown,
            1 => AuthType::Mail,
            2 => AuthType::PasswordStrong,
            3 => AuthType::PasswordWeak,
            4 => AuthType::PasswordWeakUnmet,
            5 => AuthType::OpenidGoog,
            6 => AuthType::PassKey("".into()),
            7 => AuthType::AccessToken,
            _ => AuthType::Unknown
        }
    }
}

impl From<&str> for AuthType {
    fn from(origin: &str) -> Self {
        origin.parse::<u8>().unwrap_or(0)
            .into()
    }
}

impl From<Option<String>> for AuthType {
    fn from(origin: Option<String>) -> Self {
        match origin {
            Some(via) => via.parse::<u8>().unwrap_or(0)
                .into(),
            None => AuthType::Unknown
        }
    }
}
