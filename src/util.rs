use server_conf::abs_path_with_default;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Position, Url};
use uuid::Uuid;
use webauthn_rs_device_catalog::Data;

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub brands: Option<String>,   // Sec-CH-UA
    pub platform: Option<String>, // Sec-CH-UA-Platform
    pub model: Option<String>,    // Sec-CH-UA-Model (Useful for WebAuthn)
    pub ua: Option<String>,       // User-Agent (Legacy/Fallback)
}

const BRAND_ALLOWLIST: &[&str] = &[
    "\"Chromium\"",
    "\"Google Chrome\"",
    "\"Microsoft Edge\"",
    "\"Edge\"",
    "\"Opera\"",
    "\"Brave\"",
];

// Source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// Intentionally trimmed to major cloud/platform authenticators and password managers.
const KNOWN_PASSKEY_AAGUIDS: &[(&str, &str, &str)] = &[
    ("adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac", "Apple Passwords"),
    ("dd4ec289-e01d-41c9-bb89-70fa845d4bf2", "iCloud Keychain (Managed)", "Apple Passwords"),
    ("fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "Apple Passwords", "Apple Passwords"),
    ("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "Google Password Manager", "Google Password Manager"),
    ("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello", "Windows Hello"),
    ("9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "Windows Hello", "Windows Hello"),
    ("6028b017-b1d4-4c02-b4b3-afcdafc96bb2", "Windows Hello", "Windows Hello"),
    ("53414d53-554e-4700-0000-000000000000", "Samsung Pass", "Samsung Pass"),
    ("bada5566-a7aa-401f-bd96-45619a55120d", "1Password", "1Password"),
    ("531126d6-e717-415c-9320-3d9aa6981239", "Dashlane", "Dashlane"),
    ("d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden", "Bitwarden"),
    ("0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6", "Keeper", "Keeper"),
    ("50726f74-6f6e-5061-7373-50726f746f6e", "Proton Pass", "Proton Pass"),
    ("b84e4048-15dc-4dd0-8640-f4f60813c8af", "NordPass", "NordPass"),
    ("b78a0a55-6ef8-d246-a042-ba0f6d55050c", "LastPass", "LastPass"),
    ("f3809540-7f14-49c1-a8b3-8f813b225541", "Enpass", "Enpass"),
];

impl ClientContext {
    /// Constructs a new `ClientContext` with validation and normalization.
    ///
    /// > [!NOTE]
    /// > **Conditions for UA-CH Transmission**:
    /// > - **HTTPS**: Required for all Client Hints. Browsers omit them on insecure connections.
    /// > - **Low Entropy** (`brands`, `platform`): Sent by default on HTTPS.
    /// > - **High Entropy** (`model`): Sent only if the server requests it via `Accept-CH: Sec-CH-UA-Model`.
    ///
    /// # Arguments
    ///
    /// * `brands` - **Brands & Versions** (`Sec-CH-UA` header).
    ///   - *Source*: `Sec-CH-UA`. (e.g. `"Chromium";v="121", "Not A(Brand";v="99"`).
    ///   - *Role*: The discriminator for the **Modern Path**. If present, it triggers UA-CH binding.
    ///
    /// * `platform` - **Platform** (`Sec-CH-UA-Platform` header).
    ///   - *Source*: `Sec-CH-UA-Platform`. (e.g. `"Windows"`, `"Android"`).
    ///   - *Role*: Essential for distinguishing OS in the Modern Path.
    ///
    /// * `model` - **Device Model** (`Sec-CH-UA-Model` header).
    ///   - *Source*: `Sec-CH-UA-Model`. (e.g. `"Pixel 7"`).
    ///   - *Role*: Used for high-fidelity binding and **WebAuthn credential hints**.
    ///
    /// * `ua` - **User-Agent** (`User-Agent` header).
    ///   - *Source*: The standard `User-Agent` HTTP header.
    ///   - *Role*: Used as the primary identifier for Legacy clients (Safari/Firefox).
    ///
    /// # Errors
    /// Returns an error if both `ua` and `brands` are missing or empty.
    pub fn new(
        brands: Option<String>,
        platform: Option<String>,
        model: Option<String>,
        ua: Option<String>,
    ) -> Result<Self, &'static str> {
        // Normalize: Trim whitespace and Truncate to 256 chars (Unicode-safe) for DoS protection
        let normalize = |s: String| -> Option<String> {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                // Take up to 256 chars. This might be less than 256 bytes or more, but prevents massive strings.
                Some(trimmed.chars().take(256).collect())
            }
        };

        let brands = brands.and_then(normalize.clone());
        let platform = platform.and_then(normalize.clone());
        let model = model.and_then(normalize.clone());
        let ua = ua.and_then(normalize);

        Ok(Self {
            brands,
            platform,
            model,
            ua,
        })
    }

    /// Computes the integrity hash using Zero-Allocation Incremental Hashing.
    /// This avoids creating temporary strings, adhering to the "Performance First" policy.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();

        // Stable Format: v1|{sorted_brands}|{platform}|{ua}
        // This ensures consistent hashing regardless of whether brands are present or not (no flip-flopping prefix).
        // It also sorts brands to handle implementation differences (Grease).
        hasher.update(b"v1|");

        if let Some(brands) = &self.brands {
            let mut parts: Vec<&str> = brands
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.split(';').next().unwrap_or(s).trim()) // Strip version
                // Grease Protection:
                // Browsers intentionally send randomized "Grease" brands (e.g., "Not A;Brand") to prevent ossification.
                // Binding to these values would break persistent sessions on browser restart.
                // We use a strict allowlist to only hash known stable brands.
                .filter(|s| BRAND_ALLOWLIST.contains(s))
                .collect();
            parts.sort();
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    hasher.update(b",");
                }
                hasher.update(part.as_bytes());
            }
        }
        hasher.update(b"|");

        if let Some(p) = &self.platform {
            hasher.update(p.as_bytes());
        }
        hasher.update(b"|");

        if let Some(ua) = &self.ua {
            hasher.update(ua.as_bytes());
        }
        // trailing pipe not strictly needed but keeps pattern consistent if we add more
        hasher.update(b"|");

        hex::encode(hasher.finalize())
    }

    /// Helper for callers that want a human-readable passkey/device label.
    /// Lower layers may accept arbitrary caller-provided `device_note` values.
    pub fn device_name(&self, aaguid: Option<&Uuid>) -> String {
        let provider = aaguid.and_then(resolve_passkey_provider);
        let device_info = self.get_device_info(provider);

        match (provider, device_info) {
            (Some(auth), Some(device)) => format!("{auth} / {device}"),
            (Some(auth), None) => auth.to_string(),
            (None, Some(device)) => device,
            (None, None) => "Unknown Device".to_string(),
        }
    }

    fn get_device_info(&self, provider: Option<&str>) -> Option<String> {
        let platform = self.platform_family(provider);
        let browser = self.browser_family();

        match (platform, browser) {
            (Some(platform), Some(browser)) => Some(format!("{platform}, {browser}")),
            (Some(platform), None) => Some(platform),
            (None, Some(browser)) => Some(browser),
            (None, None) => None,
        }
    }

    fn platform_family(&self, provider: Option<&str>) -> Option<String> {
        if matches!(provider, Some("Apple Passwords")) {
            return Some("macOS/iOS".to_string());
        }

        if let Some(ua) = &self.ua {
            if let Some(platform) = Self::parse_ua_platform(ua) {
                return Some(platform.to_string());
            }
        }

        self.platform
            .as_deref()
            .and_then(Self::normalize_platform_hint)
            .map(str::to_string)
    }

    fn browser_family(&self) -> Option<String> {
        self.brands
            .as_deref()
            .and_then(Self::parse_brands_browser)
            .or_else(|| self.ua.as_deref().and_then(Self::parse_ua_browser))
            .map(str::to_string)
    }

    fn normalize_platform_hint(platform: &str) -> Option<&str> {
        let trimmed = platform.trim();
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(trimmed);
        let lowered = unquoted.to_ascii_lowercase();

        match lowered.as_str() {
            "android" => Some("Android"),
            "windows" => Some("Windows"),
            "macos" | "mac os" | "mac os x" | "macintosh" => Some("macOS"),
            "ios" | "ipados" | "iphone" | "ipad" | "ipod" => Some("iOS"),
            "linux" => Some("Linux"),
            _ if unquoted.is_empty() => None,
            _ => Some(unquoted),
        }
    }

    fn parse_brands_browser(brands: &str) -> Option<&str> {
        let mut saw_chromium = false;

        for part in brands.split(',') {
            let brand = part.split(';').next().unwrap_or(part).trim();
            let brand = brand
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(brand);
            let lowered = brand.to_ascii_lowercase();

            if lowered.is_empty() || lowered.contains("not a") {
                continue;
            }

            match lowered.as_str() {
                "microsoft edge" | "edge" => return Some("Edge"),
                "google chrome" => return Some("Chrome"),
                "brave" => return Some("Brave"),
                "opera" => return Some("Opera"),
                "firefox" => return Some("Firefox"),
                "safari" => return Some("Safari"),
                "chromium" => saw_chromium = true,
                _ => {}
            }
        }

        if saw_chromium { Some("Chrome") } else { None }
    }

    fn parse_ua_platform(ua: &str) -> Option<&str> {
        let ua_parsed = ua.to_lowercase(); // Simple case-insensitive check

        if ua_parsed.contains("iphone") || ua_parsed.contains("ipad") || ua_parsed.contains("ipod")
        {
            Some("iOS")
        } else if ua_parsed.contains("android") {
            Some("Android")
        } else if ua_parsed.contains("windows") {
            Some("Windows")
        } else if ua_parsed.contains("mac os x") || ua_parsed.contains("macintosh") {
            Some("macOS")
        } else if ua_parsed.contains("linux") {
            Some("Linux")
        } else {
            None
        }
    }

    fn parse_ua_browser(ua: &str) -> Option<&str> {
        let ua_parsed = ua.to_lowercase();

        if ua_parsed.contains("edg/")
            || ua_parsed.contains("edga/")
            || ua_parsed.contains("edgios/")
            || ua_parsed.contains("edge")
        {
            Some("Edge")
        } else if ua_parsed.contains("opr/") || ua_parsed.contains("opera") {
            Some("Opera")
        } else if ua_parsed.contains("brave") {
            Some("Brave")
        } else if ua_parsed.contains("samsungbrowser") {
            Some("Samsung Internet")
        } else if ua_parsed.contains("firefox") || ua_parsed.contains("fxios") {
            Some("Firefox")
        } else if ua_parsed.contains("crios")
            || (ua_parsed.contains("chrome") && !ua_parsed.contains("chromium"))
        {
            Some("Chrome")
        } else if ua_parsed.contains("safari") {
            Some("Safari")
        } else if ua_parsed.contains("android") {
            Some("Android Browser")
        } else {
            None
        }
    }
}

pub fn abs_path(path: &str) -> String {
    abs_path_with_default(path, "/auth")
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedirectPathError {
    #[error("invalid redirect path")]
    InvalidUrl(#[from] url::ParseError),
    #[error("redirect path must be relative or an absolute http(s) URL")]
    UnsupportedScheme,
}

fn normalize_relative_redirect_target(path: &str) -> Result<Url, RedirectPathError> {
    let disposal_base = Url::parse("https://example.com").unwrap();
    let url = disposal_base.join(path)?;

    if url.cannot_be_a_base() {
        Err(RedirectPathError::UnsupportedScheme)
    } else {
        Ok(url)
    }
}

fn normalize_absolute_redirect_target(url: Url) -> Result<Url, RedirectPathError> {
    if url.cannot_be_a_base() || url.host_str().is_none() {
        Err(RedirectPathError::UnsupportedScheme)
    } else {
        Ok(url)
    }
}

pub fn normalize_return_path(path: &str, domain: Option<&str>) -> Option<String> {
    let Ok(absolute_url) = Url::parse(path) else {
        let relative_url = normalize_relative_redirect_target(path).ok()?;
        return Some(relative_url[Position::BeforePath..].to_string());
    };

    let absolute_url = normalize_absolute_redirect_target(absolute_url).ok()?;
    if let Some(domain) = domain {
        if absolute_url.host_str()? != domain {
            return None;
        }
    }

    Some(absolute_url[Position::BeforePath..].to_string())
}

pub fn normalize_return_url(url: &str, domain: &str) -> Option<String> {
    let absolute_url = Url::parse(url).ok()?;
    let absolute_url = normalize_absolute_redirect_target(absolute_url).ok()?;
    let host = absolute_url.host_str()?;

    if host != domain && !host.ends_with(&format!(".{domain}")) {
        return None;
    }

    Some(absolute_url.into())
}

pub(crate) fn normalize_redirect_url(url: &str) -> Result<String, RedirectPathError> {
    let absolute_url = Url::parse(url)?;
    Ok(normalize_absolute_redirect_target(absolute_url)?.into())
}

pub fn resolve_aaguid_name(uuid: &Uuid) -> Option<String> {
    if let Some((_, name, _)) = KNOWN_PASSKEY_AAGUIDS.iter().find(|(id, _, _)| *id == uuid.to_string()) {
        return Some((*name).to_string());
    }

    // 2. Try to find the device in the webauthn-rs catalog
    let catalog = Data::all_known_devices();
    let device = catalog.iter().find(|d| d.aaguid.id == *uuid);

    if let Some(device) = device {
        let mfr = &device.mfr.display_name;
        let model = device
            .skus
            .first()
            .map(|s| s.display_name.as_str())
            .unwrap_or("Security Key");
        return Some(format!("{mfr} {model}"));
    }

    // 3. Fallback for known platform authenticators not present in either catalog.
    match uuid.to_string().as_str() {
        "08987058-cadc-4b81-b6e1-30de50dcbe96" => Some("Windows Hello".to_string()),
        "9ddd1817-af5a-4672-a2b9-3e3dd95000a9" => Some("Windows Hello".to_string()),
        "6028b017-b1d4-4c02-b4b3-afcdafc96bb2" => Some("Windows Hello".to_string()),
        "6028b017-b1d4-4c02-b4b3-afcdafc96e63" => Some("Windows Hello".to_string()),
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" => Some("Google Password Manager".to_string()),
        "49960de5-8809-4563-a5d2-03c01f6f1405" => Some("Android Keystore".to_string()),
        _ => None,
    }
}

pub fn resolve_passkey_provider(uuid: &Uuid) -> Option<&'static str> {
    KNOWN_PASSKEY_AAGUIDS.iter()
        .find(|(id, _, _)| *id == uuid.to_string())
        .map(|(_, _, provider)| *provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_abs_dir_with_default_prefix() {
        assert_eq!(abs_path("dir"), "/auth/dir");
        assert_eq!(abs_path("/dir"), "/auth/dir");
        assert_eq!(abs_path("/"), "/auth/");
        assert_eq!(abs_path(""), "/auth/");
    }

    #[test]
    fn normalize_return_path_accepts_relative_path() {
        assert_eq!(
            normalize_return_path("/account?authenticated=1#ok", None),
            Some("/account?authenticated=1#ok".to_string())
        );
    }

    #[test]
    fn normalize_return_path_accepts_same_domain_absolute_url() {
        assert_eq!(
            normalize_return_path(
                "https://dev.example.com/test?query#frag",
                Some("dev.example.com")
            ),
            Some("/test?query#frag".to_string())
        );
    }

    #[test]
    fn normalize_return_path_rejects_foreign_domain() {
        assert_eq!(
            normalize_return_path("https://example.com/test", Some("dev.example.com")),
            None
        );
    }

    #[test]
    fn normalize_return_path_rejects_unsupported_scheme() {
        assert_eq!(normalize_return_path("javascript:alert(1)", None), None);
    }

    #[test]
    fn normalize_return_url_accepts_same_domain_absolute_url() {
        assert_eq!(
            normalize_return_url("https://dev.example.com/test?query#frag", "dev.example.com"),
            Some("https://dev.example.com/test?query#frag".to_string())
        );
    }

    #[test]
    fn normalize_return_url_accepts_subdomain_absolute_url() {
        assert_eq!(
            normalize_return_url(
                "https://tenant.dev.example.com/test?query#frag",
                "dev.example.com"
            ),
            Some("https://tenant.dev.example.com/test?query#frag".to_string())
        );
    }

    #[test]
    fn normalize_return_url_rejects_foreign_domain() {
        assert_eq!(
            normalize_return_url("https://example.com/test", "dev.example.com"),
            None
        );
    }

    #[test]
    fn normalize_return_url_rejects_unsupported_scheme() {
        assert_eq!(
            normalize_return_url("mailto:test@example.com", "example.com"),
            None
        );
    }

    #[test]
    fn normalize_redirect_url_rejects_unsupported_scheme() {
        assert_eq!(
            normalize_redirect_url("mailto:test@example.com"),
            Err(RedirectPathError::UnsupportedScheme)
        );
    }

    #[test]
    fn test_client_context_hash_legacy() {
        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("Mozilla/5.0 (Legacy)".to_string()),
        };
        // Expected: v1|||Mozilla/5.0 (Legacy)|
        let expected = hex::encode(Sha256::digest(b"v1|||Mozilla/5.0 (Legacy)|"));
        assert_eq!(ctx.compute_hash(), expected);
    }

    #[test]
    fn test_client_context_hash_modern() {
        let ctx = ClientContext {
            brands: Some("\"Chromium\";v=\"121\", \"Not A(Brand\";v=\"99\"".to_string()),
            platform: Some("Windows".to_string()),
            model: Some("Pixel 7".to_string()),
            ua: Some("Mozilla/5.0 (Baseline)".to_string()),
        };
        // Expected: v1|"Chromium"|Windows|Mozilla/5.0 (Baseline)|
        // Note: "Not A(Brand" is Grease (or unknown) and filtered out. Version is stripped.
        let expected = hex::encode(Sha256::digest(
            b"v1|\"Chromium\"|Windows|Mozilla/5.0 (Baseline)|",
        ));
        assert_eq!(ctx.compute_hash(), expected);

        // Test Brand Sorting Stability
        let ctx_shuffled = ClientContext {
            brands: Some("\"Not A(Brand\";v=\"99\", \"Chromium\";v=\"121\"".to_string()),
            platform: Some("Windows".to_string()),
            model: Some("Pixel 7".to_string()),
            ua: Some("Mozilla/5.0 (Baseline)".to_string()),
        };
        assert_eq!(
            ctx_shuffled.compute_hash(),
            expected,
            "Hash must be stable regardless of brand order"
        );
    }

    #[test]
    fn test_client_context_hash_modern_no_model_stability() {
        let ctx = ClientContext {
            brands: Some("\"Chromium\";v=\"121\"".to_string()),
            platform: Some("macOS".to_string()),
            model: Some("MacBook".to_string()),
            ua: Some("Mozilla/5.0".to_string()),
        };
        // Expected: v1|"Chromium"|macOS|Mozilla/5.0|
        let expected = hex::encode(Sha256::digest(b"v1|\"Chromium\"|macOS|Mozilla/5.0|"));
        assert_eq!(ctx.compute_hash(), expected);

        let ctx_no_model = ClientContext {
            brands: Some("\"Chromium\";v=\"121\"".to_string()),
            platform: Some("macOS".to_string()),
            model: None, // Missing model should NOT change hash
            ua: Some("Mozilla/5.0".to_string()),
        };
        assert_eq!(
            ctx_no_model.compute_hash(),
            expected,
            "Hash must be stable regardless of high-entropy model hint"
        );
    }

    #[test]
    fn test_client_context_truncation() {
        let long_str = "a".repeat(300);
        let ctx = ClientContext::new(
            Some(long_str.clone()), // Brands
            Some(long_str.clone()), // Platform
            Some(long_str.clone()), // Model
            Some(long_str.clone()), // UA
        )
        .unwrap();

        let truncated = "a".repeat(256);
        assert_eq!(ctx.brands.unwrap(), truncated, "Brands must be truncated");
        assert_eq!(
            ctx.platform.unwrap(),
            truncated,
            "Platform must be truncated"
        );
        assert_eq!(ctx.model.unwrap(), truncated, "Model must be truncated");
        assert_eq!(ctx.ua.unwrap(), truncated, "UA must be truncated");
    }

    #[test]
    fn test_client_context_empty_success() {
        // Success: Even if both are empty/missing
        assert!(ClientContext::new(None, None, None, None).is_ok());
        assert!(
            ClientContext::new(Some(" ".to_string()), None, None, Some(" ".to_string())).is_ok()
        );
    }

    #[test]
    fn test_client_context_new_normalization() {
        let ctx = ClientContext::new(
            Some("".to_string()),
            Some("  ".to_string()),
            Some("\n".to_string()),
            Some("ua".to_string()),
        )
        .unwrap();

        assert_eq!(ctx.ua, Some("ua".to_string()));
        assert!(ctx.brands.is_none());
        assert!(ctx.platform.is_none());
        assert!(ctx.model.is_none());
    }

    #[test]
    fn test_device_name_with_aaguid_yubikey() {
        let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string()),
        };
        let aaguid = Uuid::parse_str("2c49b6a3-05b6-4f40-b6f7-ad6d3d920000").unwrap(); // YubiKey 5 NFC
        assert_eq!(ctx.device_name(Some(&aaguid)), "macOS, Chrome");
    }

    #[test]
    fn test_device_name_with_aaguid_icloud() {
        let ctx = ClientContext {
            brands: Some("\"Safari\";v=\"17\"".into()),
            platform: Some("\"macOS\"".into()),
            model: None,
            ua: Some("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1".into()),
        };
        let aaguid = Uuid::parse_str("adce0002-35bc-c60a-648b-0b25f1f05503").unwrap(); // iCloud Keychain
        assert_eq!(ctx.device_name(Some(&aaguid)), "Apple Passwords / macOS/iOS, Safari");
    }

    #[test]
    fn test_device_name_modern_hints() {
        let ctx = ClientContext {
            brands: Some("\"Chromium\";v=\"121\", \"Google Chrome\";v=\"121\"".into()),
            platform: Some("\"Android\"".into()),
            model: Some("Pixel 7".into()),
            ua: None,
        };
        assert_eq!(ctx.device_name(None), "Android, Chrome");
    }

    #[test]
    fn test_device_name_legacy_ua() {
        let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string()),
        };
        assert_eq!(ctx.device_name(None), "Windows, Chrome");
    }

    #[test]
    fn test_device_name_fallback() {
        let ctx = ClientContext {
            brands: None,
            platform: None,
            model: None,
            ua: Some("Unknown/1.0".to_string()),
        };
        assert_eq!(ctx.device_name(None), "Unknown Device");
    }

    #[test]
    fn test_device_name_with_aaguid_yubikey_catalog() {
        let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string()),
        };
        // Yubico YubiKey 5 FIPS Series: 73bb0cd4-e502-49b8-9c6f-b59445bf720b (In catalog)
        let aaguid = Uuid::parse_str("73bb0cd4-e502-49b8-9c6f-b59445bf720b").unwrap();
        assert_eq!(ctx.device_name(Some(&aaguid)), "macOS, Chrome");
    }

    #[test]
    fn test_device_name_with_provider_and_quoted_platform() {
        let ctx = ClientContext {
            brands: Some("\"Google Chrome\";v=\"135\", \"Chromium\";v=\"135\"".into()),
            platform: Some("\"Android\"".into()),
            model: Some("\"Pixel 9\"".into()),
            ua: Some("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36".into()),
        };
        let aaguid = Uuid::parse_str("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert_eq!(
            ctx.device_name(Some(&aaguid)),
            "Google Password Manager / Android, Chrome"
        );
    }

    #[test]
    fn test_resolve_aaguid_name_uses_embedded_catalog() {
        let aaguid = Uuid::parse_str("bada5566-a7aa-401f-bd96-45619a55120d").unwrap();
        assert_eq!(resolve_aaguid_name(&aaguid).as_deref(), Some("1Password"));
    }

    #[test]
    fn test_resolve_passkey_provider_uses_embedded_catalog() {
        let aaguid = Uuid::parse_str("531126d6-e717-415c-9320-3d9aa6981239").unwrap();
        assert_eq!(resolve_passkey_provider(&aaguid), Some("Dashlane"));
    }

    #[test]
    fn test_resolve_passkey_provider_normalizes_apple_family() {
        let aaguid = Uuid::parse_str("adce0002-35bc-c60a-648b-0b25f1f05503").unwrap();
        assert_eq!(
            resolve_aaguid_name(&aaguid).as_deref(),
            Some("Chrome on Mac")
        );
        assert_eq!(resolve_passkey_provider(&aaguid), Some("Apple Passwords"));
    }

    #[test]
    fn test_device_name_ipad_prefers_ios_family() {
        let ctx = ClientContext {
            brands: None,
            platform: Some("\"macOS\"".into()),
            model: None,
            ua: Some("Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1".into()),
        };
        assert_eq!(ctx.device_name(None), "iOS, Safari");
    }

    #[test]
    fn test_apple_provider_uses_family_platform_label() {
        let ctx = ClientContext {
            brands: Some("\"Google Chrome\";v=\"135\", \"Chromium\";v=\"135\"".into()),
            platform: Some("\"macOS\"".into()),
            model: None,
            ua: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36".into()),
        };
        let aaguid = Uuid::parse_str("fbfc3007-154e-4ecc-8c0b-6e020557d7bd").unwrap();
        assert_eq!(ctx.device_name(Some(&aaguid)), "Apple Passwords / macOS/iOS, Chrome");
    }

    #[test]
    fn test_client_context_hash_grease_filtering() {
        let ctx = ClientContext {
            brands: Some("\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"121\"".to_string()),
            platform: Some("Windows".to_string()),
            model: Some("Pixel 7".to_string()),
            ua: Some("Mozilla/5.0".to_string()),
        };
        // "Not A;Brand" should be filtered out. "Chromium" should remain.
        // Expected: v1|"Chromium"|Windows|Mozilla/5.0|
        let expected = hex::encode(Sha256::digest(b"v1|\"Chromium\"|Windows|Mozilla/5.0|"));
        assert_eq!(ctx.compute_hash(), expected);
    }

    #[test]
    fn test_client_context_hash_unknown_browser() {
        let ctx = ClientContext {
            brands: Some("\"MyUnknownBrowser\";v=\"1\"".to_string()), // Not in Allowlist
            platform: Some("Linux".to_string()),
            model: None,
            ua: Some("Mozilla/5.0 (Unknown)".to_string()),
        };
        // Brand should be filtered out completely -> Empty brands section
        // Expected: v1||Linux|Mozilla/5.0 (Unknown)|
        let expected = hex::encode(Sha256::digest(b"v1||Linux|Mozilla/5.0 (Unknown)|"));
        assert_eq!(ctx.compute_hash(), expected);
    }

    #[test]
    fn test_client_context_hash_mixed_brands() {
        let ctx = ClientContext {
            brands: Some(
                "\"MyBrowser\";v=\"1\", \"Google Chrome\";v=\"121\", \"Not A;Brand\";v=\"8\""
                    .to_string(),
            ),
            platform: Some("macOS".to_string()),
            model: None,
            ua: Some("Mozilla/5.0".to_string()),
        };
        // Only "Google Chrome" should remain.
        // Expected: v1|"Google Chrome"|macOS|Mozilla/5.0|
        let expected = hex::encode(Sha256::digest(b"v1|\"Google Chrome\"|macOS|Mozilla/5.0|"));
        assert_eq!(ctx.compute_hash(), expected);
    }
}
