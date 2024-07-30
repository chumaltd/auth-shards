pub mod account;
pub mod password;
pub mod webauthn;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum AuthType {
    Unknown = 0,
    Mail = 1,
    PasswordStrong = 2,
    PasswordWeak = 3,
    PasswordWeakUnmet = 4, // Org requires PasswordStrong
    OpenidGoog = 5,
    PassKey = 6,
    AccessToken = 7,
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
            6 => AuthType::PassKey,
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
