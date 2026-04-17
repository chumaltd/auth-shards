use addr_spec::AddrSpec;
use std::sync::LazyLock;
use std::time::Duration;
use hickory_resolver::{TokioResolver, net::NetError};

static DNS_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    let mut builder = TokioResolver::builder_tokio()
        .expect("failed to load system DNS config");

    let opts = builder.options_mut();
    opts.cache_size = 10_000;
    opts.positive_min_ttl = Some(Duration::from_secs(60));
    opts.positive_max_ttl = Some(Duration::from_secs(300));
    opts.negative_min_ttl = Some(Duration::from_secs(60));
    opts.negative_max_ttl = Some(Duration::from_secs(300));

    builder.build().expect("DNS resolver couldn't be built")
});

pub async fn check_valid_email(address: &str) -> Result<(bool, String), &'static str> {
    let addr = parse_email(address);
    if let Err(message) = addr {
        return Ok((false, message));
    }
    let addr = addr.unwrap();

    let valid_mx = resolve_mx_status(addr.domain())
        .await.map_err(|_| "NetWorkError")?;

    Ok(valid_mx)
}

fn parse_email(address: &str) -> Result<AddrSpec, String> {
    let addr: AddrSpec = address.parse().map_err(|_| "invalid addr-spec")?;
    if !addr.local_part().is_ascii() || !addr.domain().is_ascii() {
        return Err("non-ASCII addresses are not accepted".to_string());
    }

    let domain = addr.domain().to_string();

    if domain.starts_with('[') && domain.ends_with(']') {
        return Err(format!("domain literal not allowed: {domain}"));
    }

    if !domain.contains('.') {
        return Err(format!("single-label domain not allowed: {domain}"));
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return Err(format!("empty domain label: {domain}"));
    }

    Ok(addr)
}

async fn resolve_mx_status(
    domain: &str,
) -> Result<(bool, String), NetError> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let fqdn = format!("{normalized}.");
    let lookup = DNS_RESOLVER.mx_lookup(fqdn).await;

    match lookup {
        Ok(_) => {
            // TODO handle Null MX, inspecting low level RDATA
            Ok((true, domain.to_string()))
        },
        Err(e) if e.is_no_records_found() => Ok((false, format!("No records found: {domain}"))),
        Err(e) if e.is_nx_domain() => Ok((false, format!("NX domain: {domain}"))),
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_valid_email_returns_false_for_invalid_tld() {
        assert_eq!(Ok((false, "No records found: example.invalid".to_string())), check_valid_email("user@example.invalid").await);
    }

    #[tokio::test]
    async fn check_valid_email_returns_false_for_invalid_subdomain() {
        assert_eq!(Ok((false, "No records found: mail.example.invalid".to_string())), check_valid_email("user@mail.example.invalid").await);
    }

    #[tokio::test]
    async fn check_valid_email_returns_false_for_missing_local_part() {
        assert_eq!(Ok((false, "invalid addr-spec".to_string())), check_valid_email("@example.com").await);
    }

    #[tokio::test]
    async fn check_valid_email_returns_false_for_invalid_local_part_syntax() {
        assert_eq!(Ok((false, "invalid addr-spec".to_string())), check_valid_email("user..name@example.com").await);
    }
}
