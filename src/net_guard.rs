//! Shared SSRF-safe outbound URL validation, DNS pinning, redirect blocking,
//! and bounded streaming HTTP response reads.
//!
//! Used across inbox rule webhooks, RFC 8058 one-click unsubscribe requests,
//! Resend presigned download fetches, AWS SNS signing certificate / SES S3 fetches,
//! and inbound HTTP filters (`RspamdFilter`, `LlmTriageFilter`).

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use url::{Host, Url};

use crate::error::{AppError, AppResult};

/// Default hard timeout for DNS resolution during SSRF validation.
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum HTTP response size for inbound filter API calls (2 MiB).
pub const DEFAULT_FILTER_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum response size for fetching an AWS SNS X.509 signing certificate (64 KiB).
pub const MAX_SNS_CERT_BYTES: usize = 64 * 1024;

/// Policy options governing static and DNS-level SSRF URL validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UrlGuardOptions<'a> {
    /// Allow private/loopback/local IPs and domains. Must remain `false` in production;
    /// enable only via explicit dev/test opt-in (`NOGML_ALLOW_PRIVATE_ENDPOINTS=true`)
    /// or for same-origin requests targeting an explicitly configured local mock endpoint.
    pub allow_private_endpoints: bool,
    /// Allow `http://` in addition to `https://`. Honored ONLY when `allow_private_endpoints`
    /// is also `true`; in production (`allow_private_endpoints == false`), `https://` is
    /// always strictly required.
    pub allow_http: bool,
    /// Optional host allowlist (exact domain or `*.domain` wildcard suffix).
    /// Empty means any host passing SSRF checks is permitted.
    pub allowed_hosts: &'a [String],
    /// Short human-readable label for error messages (e.g. `"webhook_url"`, `"Resend download"`).
    pub context: &'a str,
}

/// A URL that has passed static SSRF validation and DNS resolution, carrying the exact
/// validated [`SocketAddr`] set to pin into `reqwest::ClientBuilder::resolve_to_addrs`.
#[derive(Debug, Clone)]
pub struct PinnedUrl {
    pub url: Url,
    pub domain: Option<String>,
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Construct a standardized `ssrf_blocked` [`AppError::PolicyDenied`].
pub fn ssrf_error(message: impl Into<String>, hint: impl Into<String>) -> AppError {
    AppError::PolicyDenied {
        code: "ssrf_blocked".to_string(),
        message: message.into(),
        hint: Some(hint.into()),
        details: None,
    }
}

/// Return `true` only if `ip` is a globally routable unicast address.
///
/// Rejects loopback (`127.0.0.0/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`),
/// link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`),
/// ULA (`fc00::/7`), unspecified (`0.0.0.0/8`, `::`), multicast, broadcast, documentation,
/// benchmarking, reserved ranges, IPv4-mapped IPv6 (`::ffff:0:0/96`), IPv4-compatible IPv6
/// (`::/96`), NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), Teredo, and 6to4 private targets.
pub fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_ipv4(v4),
        IpAddr::V6(v6) => is_globally_routable_ipv6(v6),
    }
}

fn is_globally_routable_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 0.0.0.0/8 ("This network", including 0.0.0.0 unspecified)
    if octets[0] == 0 {
        return false;
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 private)
    if v4.is_private() {
        return false;
    }
    // 100.64.0.0/10 (RFC 6598 CGNAT / shared address space)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return false;
    }
    // 127.0.0.0/8 (loopback)
    if v4.is_loopback() {
        return false;
    }
    // 169.254.0.0/16 (link-local & cloud metadata 169.254.169.254)
    if v4.is_link_local() {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (documentation)
    if v4.is_documentation() {
        return false;
    }
    // 198.18.0.0/15 (benchmarking)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    // 224.0.0.0/4 (multicast)
    if v4.is_multicast() {
        return false;
    }
    // 240.0.0.0/4 (reserved / future use + 255.255.255.255 broadcast)
    if octets[0] >= 240 || v4.is_broadcast() {
        return false;
    }
    true
}

fn is_globally_routable_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped_v4) = v6.to_ipv4_mapped() {
        return is_globally_routable_ipv4(mapped_v4);
    }

    let segs = v6.segments();

    // ::/96 covers unspecified (::), loopback (::1), and deprecated IPv4-compatible (::a.b.c.d).
    if segs[0..6] == [0, 0, 0, 0, 0, 0] {
        return false;
    }
    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
        return false;
    }
    // Unique Local Addresses (ULA): fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Link-local unicast: fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Deprecated site-local: fec0::/10
    if (segs[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // Discard-only: 100::/64
    if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
        return false;
    }
    // Documentation: 2001:db8::/32
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return false;
    }
    // Teredo tunneling: 2001::/32
    if segs[0] == 0x2001 && segs[1] == 0x0000 {
        return false;
    }
    // NAT64 well-known prefix: 64:ff9b::/96 (check embedded IPv4)
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6] == [0, 0, 0, 0] {
        let embedded = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return is_globally_routable_ipv4(embedded);
    }
    // NAT64 local-use prefix: 64:ff9b:1::/48
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
        return false;
    }
    // 6to4: 2002::/16 (check embedded IPv4)
    if segs[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        );
        return is_globally_routable_ipv4(embedded);
    }

    true
}

/// Check whether `host` matches a configured host allowlist.
///
/// An empty allowlist permits any host. Each entry may be an exact hostname/IP
/// (case-insensitive, e.g. `hooks.example.com`) or a wildcard subdomain pattern
/// (`*.example.com` or `.example.com`, matching `a.example.com` and `a.b.example.com`).
pub fn host_matches_allowlist(host: &str, allowed_hosts: &[String]) -> bool {
    let non_empty: Vec<&str> = allowed_hosts
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if non_empty.is_empty() {
        return true;
    }

    let normalized_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized_host.is_empty() {
        return false;
    }

    for entry in non_empty {
        let pat = entry
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pat.is_empty() {
            continue;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            if !suffix.is_empty()
                && normalized_host.len() > suffix.len() + 1
                && normalized_host.ends_with(suffix)
                && normalized_host.as_bytes()[normalized_host.len() - suffix.len() - 1] == b'.'
            {
                return true;
            }
        } else if let Some(suffix) = pat.strip_prefix('.') {
            if !suffix.is_empty()
                && normalized_host.len() > suffix.len() + 1
                && normalized_host.ends_with(suffix)
                && normalized_host.as_bytes()[normalized_host.len() - suffix.len() - 1] == b'.'
            {
                return true;
            }
        } else if normalized_host == pat {
            return true;
        }
    }

    false
}

/// Return `true` when `url` shares the exact scheme, host, and effective port of `base_url`.
///
/// Used so local `wiremock` endpoints explicitly configured as `resend_base_url` or
/// `ses_s3_endpoint` can serve same-origin mock downloads without relaxing SSRF checks
/// for arbitrary private IPs or other localhost ports.
pub fn same_origin(url: &Url, base_url: &str) -> bool {
    let Ok(base) = Url::parse(base_url.trim()) else {
        return false;
    };
    if !url.scheme().eq_ignore_ascii_case(base.scheme()) {
        return false;
    }
    if url.port_or_known_default() != base.port_or_known_default() {
        return false;
    }
    match (url.host_str(), base.host_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// Perform zero-network static SSRF validation on an outbound URL.
pub fn validate_url_static(raw_url: &str, opts: UrlGuardOptions<'_>) -> AppResult<Url> {
    let ctx = if opts.context.is_empty() {
        "URL"
    } else {
        opts.context
    };
    let trimmed = raw_url.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(AppError::validation(
            format!("{ctx} must be non-empty and free of control characters"),
            None,
        ));
    }

    let parsed = Url::parse(trimmed).map_err(|err| {
        AppError::validation(
            format!("Invalid {ctx}: {err}"),
            Some("Provide a valid https:// URL.".to_string()),
        )
    })?;

    let allow_http_effective = opts.allow_private_endpoints && opts.allow_http;
    let scheme_ok = parsed.scheme().eq_ignore_ascii_case("https")
        || (allow_http_effective && parsed.scheme().eq_ignore_ascii_case("http"));
    if !scheme_ok {
        return Err(ssrf_error(
            format!(
                "{ctx} scheme '{}' is forbidden; strictly https:// is required",
                parsed.scheme()
            ),
            "Only https:// URLs are permitted by SSRF policy.",
        ));
    }

    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or("");
    if after_scheme.is_empty() || after_scheme.starts_with('/') {
        return Err(AppError::validation(
            format!("Invalid {ctx}: missing host"),
            Some("Provide a complete https:// URL including a host.".to_string()),
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ssrf_error(
            format!("{ctx} must not contain embedded username or password credentials"),
            "Remove userinfo credentials from the URL.",
        ));
    }

    let Some(host) = parsed.host() else {
        return Err(AppError::validation(
            format!("{ctx} is missing a host"),
            None,
        ));
    };

    match host {
        Host::Ipv4(v4) => {
            if !opts.allow_private_endpoints && !is_globally_routable_ip(IpAddr::V4(v4)) {
                return Err(ssrf_error(
                    format!("{ctx} target IP {v4} is not a globally routable address"),
                    "Private, loopback, link-local, CGNAT, and metadata IP ranges are blocked.",
                ));
            }
            if !host_matches_allowlist(&v4.to_string(), opts.allowed_hosts) {
                return Err(ssrf_error(
                    format!("{ctx} host '{v4}' is not in the configured host allowlist"),
                    "Use an allowed host or update NOGML_WEBHOOK_ALLOWED_HOSTS.",
                ));
            }
        }
        Host::Ipv6(v6) => {
            if !opts.allow_private_endpoints && !is_globally_routable_ip(IpAddr::V6(v6)) {
                return Err(ssrf_error(
                    format!("{ctx} target IP [{v6}] is not a globally routable address"),
                    "Private, loopback, link-local, ULA, and IPv4-mapped internal IP ranges are blocked.",
                ));
            }
            if !host_matches_allowlist(&v6.to_string(), opts.allowed_hosts) {
                return Err(ssrf_error(
                    format!("{ctx} host '[{v6}]' is not in the configured host allowlist"),
                    "Use an allowed host or update NOGML_WEBHOOK_ALLOWED_HOSTS.",
                ));
            }
        }
        Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(AppError::validation(
                    format!("{ctx} host must not be empty"),
                    None,
                ));
            }
            if !opts.allow_private_endpoints {
                if normalized == "localhost"
                    || normalized.ends_with(".localhost")
                    || normalized.ends_with(".local")
                    || normalized.ends_with(".internal")
                {
                    return Err(ssrf_error(
                        format!("{ctx} host '{domain}' targets a local or internal domain"),
                        "Local and internal domains are blocked by SSRF policy.",
                    ));
                }
                if let Ok(ip) = normalized.parse::<IpAddr>()
                    && !is_globally_routable_ip(ip)
                {
                    return Err(ssrf_error(
                        format!("{ctx} target IP {ip} is not a globally routable address"),
                        "Private, loopback, link-local, CGNAT, and metadata IP ranges are blocked.",
                    ));
                }
            }
            if !host_matches_allowlist(&normalized, opts.allowed_hosts) {
                return Err(ssrf_error(
                    format!("{ctx} host '{domain}' is not in the configured host allowlist"),
                    "Use an allowed host or update NOGML_WEBHOOK_ALLOWED_HOSTS.",
                ));
            }
        }
    }

    Ok(parsed)
}

/// Validate an outbound URL statically, resolve its DNS addresses via `tokio::net::lookup_host`,
/// verify every resolved IP is globally routable (unless `allow_private_endpoints` is enabled),
/// and return a [`PinnedUrl`] ready for `reqwest::ClientBuilder::resolve_to_addrs`.
pub async fn validate_and_pin_url(
    raw_url: &str,
    opts: UrlGuardOptions<'_>,
) -> AppResult<PinnedUrl> {
    let ctx = if opts.context.is_empty() {
        "URL"
    } else {
        opts.context
    };
    let parsed = validate_url_static(raw_url, opts)?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    match parsed.host() {
        Some(Host::Ipv4(v4)) => Ok(PinnedUrl {
            resolved_addrs: vec![SocketAddr::new(IpAddr::V4(v4), port)],
            domain: None,
            url: parsed,
        }),
        Some(Host::Ipv6(v6)) => Ok(PinnedUrl {
            resolved_addrs: vec![SocketAddr::new(IpAddr::V6(v6), port)],
            domain: None,
            url: parsed,
        }),
        Some(Host::Domain(domain)) => {
            let domain_owned = domain.to_string();
            let lookup_res = tokio::time::timeout(
                DEFAULT_DNS_TIMEOUT,
                tokio::net::lookup_host((domain_owned.as_str(), port)),
            )
            .await
            .map_err(|_| AppError::Upstream {
                status: 504,
                message: format!("DNS lookup timed out for {ctx} host '{domain_owned}'"),
            })?
            .map_err(|err| AppError::Upstream {
                status: 502,
                message: format!("DNS lookup failed for {ctx} host '{domain_owned}': {err}"),
            })?;

            let resolved_addrs: Vec<SocketAddr> = lookup_res.collect();
            if resolved_addrs.is_empty() {
                return Err(AppError::Upstream {
                    status: 502,
                    message: format!(
                        "DNS lookup returned no addresses for {ctx} host '{domain_owned}'"
                    ),
                });
            }

            if !opts.allow_private_endpoints {
                for addr in &resolved_addrs {
                    if !is_globally_routable_ip(addr.ip()) {
                        return Err(ssrf_error(
                            format!(
                                "{ctx} host '{domain_owned}' resolved to non-global IP {}",
                                addr.ip()
                            ),
                            "Private, loopback, link-local, CGNAT, ULA, and metadata IP ranges are blocked.",
                        ));
                    }
                }
            }

            Ok(PinnedUrl {
                url: parsed,
                domain: Some(domain_owned),
                resolved_addrs,
            })
        }
        None => Err(AppError::validation(
            format!("{ctx} is missing a host"),
            None,
        )),
    }
}

/// Build an SSRF-hardened `reqwest::Client` pinned to `pinned.resolved_addrs` with
/// automatic redirects disabled (`Policy::none()`) and system proxies disabled (`.no_proxy()`).
pub fn build_pinned_http_client(
    pinned: &PinnedUrl,
    timeout: Duration,
    connect_timeout: Option<Duration>,
) -> AppResult<reqwest::Client> {
    crate::ensure_crypto_provider();
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout)
        .user_agent(concat!("nogml/", env!("CARGO_PKG_VERSION")));

    if let Some(ct) = connect_timeout {
        builder = builder.connect_timeout(ct);
    }

    if let Some(ref domain) = pinned.domain {
        builder = builder.resolve_to_addrs(domain, &pinned.resolved_addrs);
    }

    builder
        .build()
        .map_err(|err| AppError::Internal(format!("Failed to build pinned HTTP client: {err}")))
}

/// Stream an HTTP response body into memory while strictly enforcing `max_bytes`.
///
/// Rejects responses whose `Content-Length` header or streamed byte count exceeds
/// `max_bytes` with [`AppError::PayloadTooLarge`].
pub async fn read_bounded_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> AppResult<Vec<u8>> {
    if let Some(content_len) = resp.content_length()
        && content_len > max_bytes as u64
    {
        return Err(AppError::PayloadTooLarge(format!(
            "{context} response length ({content_len} bytes) exceeds maximum allowed size ({max_bytes} bytes)"
        )));
    }

    let initial_cap = resp
        .content_length()
        .and_then(|n| usize::try_from(n).ok())
        .map(|n| n.min(max_bytes).min(64 * 1024))
        .unwrap_or(0);
    let mut out = Vec::with_capacity(initial_cap);

    while let Some(chunk) = resp.chunk().await? {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(AppError::PayloadTooLarge(format!(
                "{context} response exceeded maximum allowed size ({max_bytes} bytes)"
            )));
        }
        out.extend_from_slice(&chunk);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globally_routable_ip_rejects_private_and_special_ranges() {
        let blocked = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::10.0.0.1",
            "2002:0a00:0001::1",
        ];
        for raw in blocked {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(!is_globally_routable_ip(ip), "expected blocked: {raw}");
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ];
        for raw in allowed {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(is_globally_routable_ip(ip), "expected allowed: {raw}");
        }
    }

    #[test]
    fn host_allowlist_supports_exact_and_wildcards() {
        let list = vec!["hooks.example.com".to_string(), "*.trusted.org".to_string()];
        assert!(host_matches_allowlist("hooks.example.com", &list));
        assert!(host_matches_allowlist("HOOKS.EXAMPLE.COM.", &list));
        assert!(host_matches_allowlist("a.trusted.org", &list));
        assert!(host_matches_allowlist("a.b.trusted.org", &list));
        assert!(!host_matches_allowlist("trusted.org", &list));
        assert!(!host_matches_allowlist("evil-trusted.org", &list));
        assert!(!host_matches_allowlist("evil.com", &list));
    }

    #[test]
    fn validate_url_static_enforces_https_and_blocks_ssrf() {
        let strict = UrlGuardOptions {
            context: "webhook",
            ..Default::default()
        };
        assert!(validate_url_static("https://hooks.example.com/in", strict).is_ok());
        assert!(validate_url_static("https://93.184.216.34/in", strict).is_ok());

        for bad in [
            "http://hooks.example.com/in",
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/internal",
            "https://[::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://localhost/hook",
            "https://metadata.google.internal/hook",
            "https://user:pass@hooks.example.com/hook",
            "ftp://hooks.example.com/hook",
        ] {
            assert!(
                validate_url_static(bad, strict).is_err(),
                "expected SSRF rejection for {bad}"
            );
        }

        // Private toggle with allow_http allows local test mock.
        let dev = UrlGuardOptions {
            allow_private_endpoints: true,
            allow_http: true,
            allowed_hosts: &[],
            context: "webhook",
        };
        assert!(validate_url_static("http://127.0.0.1:8080/hook", dev).is_ok());

        // allow_http without allow_private_endpoints MUST NOT allow http://!
        let bad_combo = UrlGuardOptions {
            allow_private_endpoints: false,
            allow_http: true,
            allowed_hosts: &[],
            context: "webhook",
        };
        assert!(validate_url_static("http://hooks.example.com/hook", bad_combo).is_err());
    }
}
