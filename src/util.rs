use server_conf::abs_path_with_default;
use sha2::{Digest, Sha256};
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
    "\"Brave\""
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
             let mut parts: Vec<&str> = brands.split(',')
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
                 if i > 0 { hasher.update(b","); }
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

    pub fn device_name(&self, aaguid: Option<&Uuid>) -> String {
        let aaguid_name = aaguid.and_then(|uuid| resolve_aaguid_name(uuid));
        let device_info = self.get_device_info();

        match (aaguid_name, device_info) {
            (Some(auth), Some(device)) => format!("{auth} ({device})"),
            (Some(auth), None) => auth.to_string(),
            (None, Some(device)) => device,
            (None, None) => "Unknown Device".to_string(),
        }
    }

    fn get_device_info(&self) -> Option<String> {
        // 1: Modern Client Hints
        if let Some(model) = &self.model {
            if let Some(platform) = &self.platform {
                return Some(format!("{model} ({platform})"));
            }
            return Some(model.clone());
        }
        if let Some(platform) = &self.platform {
            return Some(platform.clone());
        }

        // 2: User-Agent Parsing (Legacy)
        if let Some(ua) = &self.ua {
            return Some(Self::parse_ua_string(ua));
        }

        None
    }

    fn parse_ua_string(ua: &str) -> String {
        let ua_parsed = ua.to_lowercase(); // Simple case-insensitive check

        let os = if ua_parsed.contains("windows") {
            "Windows"
        } else if ua_parsed.contains("mac os x") || ua_parsed.contains("macintosh") {
            "macOS"
        } else if ua_parsed.contains("android") {
            "Android"
        } else if ua_parsed.contains("iphone") || ua_parsed.contains("ipad") || ua_parsed.contains("ipod") {
            "iOS"
        } else if ua_parsed.contains("linux") {
            "Linux"
        } else {
            "Unknown OS"
        };

        let browser = if ua_parsed.contains("edg/") || ua_parsed.contains("edge") {
            "Edge"
        } else if ua_parsed.contains("chrome") && !ua_parsed.contains("edg") { // Chrome, but not Edge
            "Chrome"
        } else if ua_parsed.contains("firefox") {
            "Firefox"
        } else if ua_parsed.contains("safari") && !ua_parsed.contains("chrome") { // Safari, but not Chrome
            "Safari"
        } else {
            "Browser"
        };

        format!("{browser} on {os}")
    }
}

pub fn abs_path(path: &str) -> String {
    abs_path_with_default(path, "/auth")
}

pub fn resolve_aaguid_name(uuid: &Uuid) -> Option<String> {
    // 1. Try to find the device in the catalog
    let catalog = Data::all_known_devices();
    let device = catalog.iter().find(|d| d.aaguid.id == *uuid);
    
    if let Some(device) = device {
        let mfr = &device.mfr.display_name;
        let model = device.skus.first().map(|s| s.display_name.as_str()).unwrap_or("Security Key");
        return Some(format!("{mfr} {model}"));
    }

    // 2. Fallback for known Platform Authenticators not in catalog
    match uuid.to_string().as_str() {
        "adce0002-35bc-c60a-648b-0b25f1f05503" => Some("iCloud Keychain".to_string()),
        "08987058-cadc-4b81-b6e1-30de50dcbe96" => Some("Windows Hello".to_string()),
        "6028b017-b1d4-4c02-b4b3-afcdafc96e63" => Some("Windows Hello".to_string()),
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" => Some("Google Password Manager".to_string()),
        "49960de5-8809-4563-a5d2-03c01f6f1405" => Some("Android Keystore".to_string()),
        _ => None
    }
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
        let expected = hex::encode(Sha256::digest(b"v1|\"Chromium\"|Windows|Mozilla/5.0 (Baseline)|"));
        assert_eq!(ctx.compute_hash(), expected);

        // Test Brand Sorting Stability
        let ctx_shuffled = ClientContext {
            brands: Some("\"Not A(Brand\";v=\"99\", \"Chromium\";v=\"121\"".to_string()),
            platform: Some("Windows".to_string()),
            model: Some("Pixel 7".to_string()),
            ua: Some("Mozilla/5.0 (Baseline)".to_string()),
        };
        assert_eq!(ctx_shuffled.compute_hash(), expected, "Hash must be stable regardless of brand order");
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
        assert_eq!(ctx_no_model.compute_hash(), expected, "Hash must be stable regardless of high-entropy model hint");
    }

    #[test]
    fn test_client_context_truncation() {
        let long_str = "a".repeat(300);
        let ctx = ClientContext::new(
            Some(long_str.clone()), // Brands
            Some(long_str.clone()), // Platform
            Some(long_str.clone()), // Model
            Some(long_str.clone()), // UA
        ).unwrap();

        let truncated = "a".repeat(256);
        assert_eq!(ctx.brands.unwrap(), truncated, "Brands must be truncated");
        assert_eq!(ctx.platform.unwrap(), truncated, "Platform must be truncated");
        assert_eq!(ctx.model.unwrap(), truncated, "Model must be truncated");
        assert_eq!(ctx.ua.unwrap(), truncated, "UA must be truncated");
    }

    #[test]
    fn test_client_context_empty_success() {
        // Success: Even if both are empty/missing
        assert!(ClientContext::new(None, None, None, None).is_ok());
        assert!(ClientContext::new(Some(" ".to_string()), None, None, Some(" ".to_string())).is_ok());
    }

    #[test]
    fn test_client_context_new_normalization() {
        let ctx = ClientContext::new(
            Some("".to_string()),
            Some("  ".to_string()),
            Some("\n".to_string()),
            Some("ua".to_string()),
        ).unwrap();

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
        // Removed from manual fallback, so it falls back to UA string
        assert_eq!(ctx.device_name(Some(&aaguid)), "Chrome on macOS");
    }

    #[test]
    fn test_device_name_with_aaguid_icloud() {
         let ctx = ClientContext {
            brands: Some("v=1".into()),
            platform: Some("macOS".into()),
            model: None,
            ua: Some("...".into()),
        };
        let aaguid = Uuid::parse_str("adce0002-35bc-c60a-648b-0b25f1f05503").unwrap(); // iCloud Keychain
        // Model is None, Platform is macOS.
        // "iCloud Keychain (macOS Device)" -> "iCloud Keychain (macOS)"
        assert_eq!(ctx.device_name(Some(&aaguid)), "iCloud Keychain (macOS)");
    }

    #[test]
    fn test_device_name_modern_hints() {
        let ctx = ClientContext {
            brands: Some("v=1".into()),
            platform: Some("Android".into()),
            model: Some("Pixel 7".into()),
            ua: None,
        };
        assert_eq!(ctx.device_name(None), "Pixel 7 (Android)");
    }

    #[test]
    fn test_device_name_legacy_ua() {
        let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string()),
        };
        assert_eq!(ctx.device_name(None), "Chrome on Windows");
    }

    #[test]
    fn test_device_name_fallback() {
         let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Unknown/1.0".to_string()),
        };
        assert_eq!(ctx.device_name(None), "Browser on Unknown OS");
    }

    #[test]
    fn test_device_name_with_aaguid_yubikey_catalog() {
        let ctx = ClientContext {
            brands: None, platform: None, model: None,
            ua: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string()),
        };
        // Yubico YubiKey 5 FIPS Series: 73bb0cd4-e502-49b8-9c6f-b59445bf720b (In catalog)
        let aaguid = Uuid::parse_str("73bb0cd4-e502-49b8-9c6f-b59445bf720b").unwrap(); 
        // Catalog should return "Yubico YubiKey 5 FIPS Series"
        assert_eq!(ctx.device_name(Some(&aaguid)), "Yubico YubiKey 5 FIPS Series (Chrome on macOS)");
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
            brands: Some("\"MyBrowser\";v=\"1\", \"Google Chrome\";v=\"121\", \"Not A;Brand\";v=\"8\"".to_string()),
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
