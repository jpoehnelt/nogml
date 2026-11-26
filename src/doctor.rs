//! Live operational diagnostics for `nogml doctor [--config <PATH>]`.
//!
//! Runs structured health, permission, storage, blob, IMAP TLS certificate expiry,
//! transport credential, and security posture checks without ever printing secrets.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    blob::open_blob_store,
    config::{BlobBackend, Config, TransportBackend, validate_config},
    imap::build_tls_acceptor,
    secrets::{SecretResolutionReport, check_secret_file_permissions},
    storage::open_store_async,
    transport::{GmailTransportConfig, SesConfig, SmtpConfig},
};

/// Non-mutating probe key used to verify `BlobStore` reachability.
const DOCTOR_BLOB_PROBE_KEY: &str = "__nogml_doctor_probe__";

/// Warn when an IMAP TLS certificate has fewer than this many days remaining.
pub const TLS_EXPIRY_WARN_DAYS: i64 = 30;

/// Diagnostic check severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

/// Individual diagnostic check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorStatus,
    pub detail: String,
}

/// Aggregate check counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorSummary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

/// Top-level structured report emitted by `nogml doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub summary: DoctorSummary,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Construct a report from a completed list of checks.
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let mut summary = DoctorSummary::default();
        for check in &checks {
            match check.status {
                DoctorStatus::Pass => summary.pass += 1,
                DoctorStatus::Warn => summary.warn += 1,
                DoctorStatus::Fail => summary.fail += 1,
            }
        }
        Self {
            ok: summary.fail == 0,
            summary,
            checks,
        }
    }

    /// Build a report when loading/parsing the configuration file fails before live checks can run.
    pub fn config_load_failure(detail: impl Into<String>) -> Self {
        Self::from_checks(vec![DoctorCheck {
            name: "config".to_string(),
            status: DoctorStatus::Fail,
            detail: detail.into(),
        }])
    }
}

/// Run all live diagnostics against a resolved [`Config`].
pub async fn run_doctor(
    config: &Config,
    config_file: Option<PathBuf>,
    resolution: SecretResolutionReport,
) -> DoctorReport {
    let mut checks = Vec::with_capacity(7);

    // 1. config (config file + secret URI resolution + validation)
    checks.push(check_config(config, config_file, &resolution));

    // 2. secret_permissions (Unix mode & 0o077 != 0 on file://, *_FILE, and IMAP TLS key)
    checks.push(check_secret_permissions(config, &resolution));

    // 3. storage (MailStore connectivity + history_id + mailbox count)
    checks.push(check_storage(config).await);

    // 4. blobs (BlobStore reachability + fs writability)
    checks.push(check_blobs(config).await);

    // 5. imap_tls (PEM cert/key validation + X.509 expiry check)
    checks.push(check_imap_tls(config, Utc::now()));

    // 6. transport (active outbound transport credentials/config)
    checks.push(check_transport(config));

    // 7. security_posture (auth, insecure webhooks, private endpoints)
    checks.push(check_security_posture(config));

    DoctorReport::from_checks(checks)
}

fn is_imap_tls_validation_error(err: &str) -> bool {
    err.contains("IMAP TLS") || err.contains("imap.tls_")
}

fn check_config(
    config: &Config,
    config_file: Option<PathBuf>,
    resolution: &SecretResolutionReport,
) -> DoctorCheck {
    let report = validate_config(config, config_file.clone(), resolution.clone());
    let non_tls_errors: Vec<String> = report
        .errors
        .into_iter()
        .filter(|e| !is_imap_tls_validation_error(e))
        .collect();

    if !non_tls_errors.is_empty() {
        return DoctorCheck {
            name: "config".to_string(),
            status: DoctorStatus::Fail,
            detail: non_tls_errors.join("; "),
        };
    }

    let source = match config_file {
        Some(path) => format!("config file '{}'", path.display()),
        None => "CLI/environment defaults".to_string(),
    };
    let secret_note = if resolution.loaded_files.is_empty() {
        "no secret files loaded".to_string()
    } else {
        format!("{} secret file(s) resolved", resolution.loaded_files.len())
    };
    DoctorCheck {
        name: "config".to_string(),
        status: DoctorStatus::Pass,
        detail: format!("Loaded {source} and validated configuration ({secret_note})"),
    }
}

fn check_secret_permissions(config: &Config, resolution: &SecretResolutionReport) -> DoctorCheck {
    let mut checked_paths: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    for path in &resolution.loaded_files {
        if seen.insert(path.clone()) {
            checked_paths.push(path.clone());
        }
    }
    if let Some(ref key_path) = config.imap_tls_key
        && key_path.exists()
        && seen.insert(key_path.clone())
    {
        checked_paths.push(key_path.clone());
    }

    let mut warnings: Vec<String> = Vec::new();
    for path in &checked_paths {
        if let Some(warn) = check_secret_file_permissions(path)
            && !warnings.contains(&warn)
        {
            warnings.push(warn);
        }
    }
    for warn in &resolution.warnings {
        if warn.contains("permissive permissions") && !warnings.contains(warn) {
            warnings.push(warn.clone());
        }
    }

    if !warnings.is_empty() {
        return DoctorCheck {
            name: "secret_permissions".to_string(),
            status: DoctorStatus::Warn,
            detail: warnings.join("; "),
        };
    }

    if checked_paths.is_empty() {
        DoctorCheck {
            name: "secret_permissions".to_string(),
            status: DoctorStatus::Pass,
            detail: "No file:// or *_FILE secret files configured".to_string(),
        }
    } else {
        DoctorCheck {
            name: "secret_permissions".to_string(),
            status: DoctorStatus::Pass,
            detail: format!(
                "Checked {} secret file(s); permissions are restricted (no group/other access)",
                checked_paths.len()
            ),
        }
    }
}

fn sanitize_storage_error(err: &str, config: &Config) -> String {
    let mut sanitized = err.to_string();
    if let Some(ref db_url) = config.database_url
        && !db_url.is_empty()
        && sanitized.contains(db_url.as_str())
    {
        sanitized = sanitized.replace(db_url.as_str(), crate::secrets::REDACTED);
    }
    sanitized
}

async fn check_storage(config: &Config) -> DoctorCheck {
    let store = match open_store_async(config).await {
        Ok(s) => s,
        Err(err) => {
            return DoctorCheck {
                name: "storage".to_string(),
                status: DoctorStatus::Fail,
                detail: sanitize_storage_error(&err.to_string(), config),
            };
        }
    };

    let history_id = match store.current_history_id().await {
        Ok(hid) => hid,
        Err(err) => {
            return DoctorCheck {
                name: "storage".to_string(),
                status: DoctorStatus::Fail,
                detail: format!(
                    "{} store probe failed: {}",
                    store.backend_name(),
                    sanitize_storage_error(&err.to_string(), config)
                ),
            };
        }
    };

    let mailbox_count = match store.list_mailbox_ids().await {
        Ok(ids) if !ids.is_empty() => ids.len(),
        _ => config.known_mailboxes().len(),
    };

    DoctorCheck {
        name: "storage".to_string(),
        status: DoctorStatus::Pass,
        detail: format!(
            "{} store reachable (history_id={history_id}, mailboxes={mailbox_count})",
            store.backend_name()
        ),
    }
}

fn verify_dir_writable(dir: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(format!("'{}' is not a directory", dir.display()));
    }
    let probe_path = dir.join(format!(".nogml_doctor_probe_{}", Uuid::new_v4().simple()));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
        .map_err(|e| format!("Blob directory '{}' is not writable: {e}", dir.display()))?;
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

async fn check_blobs(config: &Config) -> DoctorCheck {
    if config.blob_backend == BlobBackend::Inline {
        return DoctorCheck {
            name: "blobs".to_string(),
            status: DoctorStatus::Pass,
            detail: "inline blob store active (blobs stored in MailStore)".to_string(),
        };
    }

    let blobs = match open_blob_store(config) {
        Ok(b) => b,
        Err(err) => {
            return DoctorCheck {
                name: "blobs".to_string(),
                status: DoctorStatus::Fail,
                detail: err.to_string(),
            };
        }
    };

    if let Err(err) = blobs.get(DOCTOR_BLOB_PROBE_KEY).await {
        return DoctorCheck {
            name: "blobs".to_string(),
            status: DoctorStatus::Fail,
            detail: format!("{} blob store probe failed: {err}", blobs.backend_name()),
        };
    }

    if config.blob_backend == BlobBackend::Fs {
        if let Err(err) = verify_dir_writable(&config.blob_dir) {
            return DoctorCheck {
                name: "blobs".to_string(),
                status: DoctorStatus::Fail,
                detail: err,
            };
        }
        return DoctorCheck {
            name: "blobs".to_string(),
            status: DoctorStatus::Pass,
            detail: format!(
                "fs blob store reachable and writable at '{}'",
                config.blob_dir.display()
            ),
        };
    }

    DoctorCheck {
        name: "blobs".to_string(),
        status: DoctorStatus::Pass,
        detail: format!("{} blob store reachable", blobs.backend_name()),
    }
}

fn check_imap_tls(config: &Config, now: DateTime<Utc>) -> DoctorCheck {
    match (
        config.imap_tls_cert.as_deref(),
        config.imap_tls_key.as_deref(),
    ) {
        (None, None) => {
            if config.imap_tls_bind.is_some() {
                DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Fail,
                    detail: "imap.tls_bind requires both imap.tls_cert and imap.tls_key"
                        .to_string(),
                }
            } else {
                DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Pass,
                    detail: "IMAP TLS not configured".to_string(),
                }
            }
        }
        (Some(_), None) | (None, Some(_)) => DoctorCheck {
            name: "imap_tls".to_string(),
            status: DoctorStatus::Fail,
            detail: "Both imap.tls_cert and imap.tls_key must be set together".to_string(),
        },
        (Some(cert_path), Some(key_path)) => {
            if let Err(err) = build_tls_acceptor(cert_path, key_path) {
                return DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Fail,
                    detail: err.to_string(),
                };
            }

            let leaf_der = match load_leaf_cert_der(cert_path) {
                Ok(der) => der,
                Err(err) => {
                    return DoctorCheck {
                        name: "imap_tls".to_string(),
                        status: DoctorStatus::Fail,
                        detail: err,
                    };
                }
            };

            let (not_before, not_after) = match parse_x509_validity(leaf_der.as_ref()) {
                Ok(v) => v,
                Err(err) => {
                    return DoctorCheck {
                        name: "imap_tls".to_string(),
                        status: DoctorStatus::Fail,
                        detail: format!(
                            "Failed to parse X.509 validity from '{}': {err}",
                            cert_path.display()
                        ),
                    };
                }
            };

            if now < not_before {
                return DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Fail,
                    detail: format!(
                        "IMAP TLS certificate '{}' is not valid until {}",
                        cert_path.display(),
                        not_before.to_rfc3339()
                    ),
                };
            }

            if now >= not_after {
                return DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Fail,
                    detail: format!(
                        "IMAP TLS certificate '{}' expired at {}",
                        cert_path.display(),
                        not_after.to_rfc3339()
                    ),
                };
            }

            let remaining = not_after - now;
            let remaining_days = remaining.num_days();
            if remaining < Duration::days(TLS_EXPIRY_WARN_DAYS) {
                return DoctorCheck {
                    name: "imap_tls".to_string(),
                    status: DoctorStatus::Warn,
                    detail: format!(
                        "IMAP TLS certificate '{}' expires in {} day(s) (notAfter {})",
                        cert_path.display(),
                        remaining_days,
                        not_after.to_rfc3339()
                    ),
                };
            }

            DoctorCheck {
                name: "imap_tls".to_string(),
                status: DoctorStatus::Pass,
                detail: format!(
                    "IMAP TLS certificate and key valid (expires in {} day(s), notAfter {})",
                    remaining_days,
                    not_after.to_rfc3339()
                ),
            }
        }
    }
}

fn load_leaf_cert_der(cert_path: &Path) -> Result<CertificateDer<'static>, String> {
    let mut iter = CertificateDer::pem_file_iter(cert_path).map_err(|e| {
        format!(
            "Failed to open IMAP TLS cert '{}': {e}",
            cert_path.display()
        )
    })?;
    match iter.next() {
        Some(Ok(cert)) => Ok(cert),
        Some(Err(e)) => Err(format!(
            "Failed to decode IMAP TLS cert '{}': {e}",
            cert_path.display()
        )),
        None => Err(format!(
            "No PEM certificates found in '{}'",
            cert_path.display()
        )),
    }
}

fn check_transport(config: &Config) -> DoctorCheck {
    match config.transport {
        TransportBackend::Resend => {
            if let Err(err) = Url::parse(config.resend_base_url.trim()) {
                return DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Fail,
                    detail: format!("Invalid resend.base_url: {err}"),
                };
            }
            let has_key = config
                .resend_api_key
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty());
            if has_key {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Pass,
                    detail: "resend transport configured (api_key present)".to_string(),
                }
            } else {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Warn,
                    detail:
                        "resend transport active, but resend.api_key (RESEND_API_KEY) is not set"
                            .to_string(),
                }
            }
        }
        TransportBackend::Ses => {
            if let Err(err) = SesConfig::from_config(config) {
                return DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Fail,
                    detail: err.to_string(),
                };
            }
            let has_key_id = config
                .ses_access_key_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty());
            let has_secret = config
                .ses_secret_access_key
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty());
            if has_key_id && has_secret {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Pass,
                    detail: format!(
                        "ses transport configured (region={}, credentials present)",
                        config.ses_region
                    ),
                }
            } else {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Warn,
                    detail: "ses transport active, but ses.access_key_id or ses.secret_access_key is not set"
                        .to_string(),
                }
            }
        }
        TransportBackend::Smtp => {
            let smtp_cfg = match SmtpConfig::from_config(config) {
                Ok(c) => c,
                Err(err) => {
                    return DoctorCheck {
                        name: "transport".to_string(),
                        status: DoctorStatus::Fail,
                        detail: err.to_string(),
                    };
                }
            };
            let has_user = config
                .smtp_username
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let has_pass = config
                .smtp_password
                .as_deref()
                .is_some_and(|s| !s.is_empty());
            if smtp_cfg.oauth2.is_none() && has_user != has_pass {
                return DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Warn,
                    detail: "smtp transport has only one of smtp.username or smtp.password set; SMTP AUTH requires both"
                        .to_string(),
                };
            }
            let auth_desc = if smtp_cfg.oauth2.is_some() {
                ", auth=XOAUTH2"
            } else if has_user {
                ", auth=PLAIN/LOGIN"
            } else {
                ""
            };
            DoctorCheck {
                name: "transport".to_string(),
                status: DoctorStatus::Pass,
                detail: format!(
                    "smtp transport configured ({}:{}, tls={:?}{auth_desc})",
                    config.smtp_host, config.smtp_port, config.smtp_tls_mode
                ),
            }
        }
        TransportBackend::Gmail => {
            let gmail_cfg = match GmailTransportConfig::from_config(config) {
                Ok(c) => c,
                Err(err) => {
                    return DoctorCheck {
                        name: "transport".to_string(),
                        status: DoctorStatus::Fail,
                        detail: err.to_string(),
                    };
                }
            };
            if gmail_cfg.has_credentials() {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Pass,
                    detail: format!(
                        "gmail transport configured (user_id={}, OAuth2 credentials present)",
                        gmail_cfg.user_id
                    ),
                }
            } else {
                DoctorCheck {
                    name: "transport".to_string(),
                    status: DoctorStatus::Warn,
                    detail: "gmail transport active, but Gmail OAuth2 credentials are not set"
                        .to_string(),
                }
            }
        }
    }
}

fn check_security_posture(config: &Config) -> DoctorCheck {
    let mut warnings = Vec::new();

    if config.auth_tokens.is_empty() && config.scoped_tokens.is_empty() && !config.oauth2_enabled()
    {
        warnings.push(
            "Open dev mode: auth_tokens and scoped_tokens are both empty (HTTP API is unauthenticated)"
                .to_string(),
        );
    }
    if config.allow_insecure_webhooks {
        warnings.push(
            "allow_insecure_webhooks is enabled: unsigned webhook requests will be accepted"
                .to_string(),
        );
    }
    if config.allow_private_endpoints {
        warnings.push(
            "allow_private_endpoints is enabled: SSRF private IP protections are relaxed"
                .to_string(),
        );
    }

    if !warnings.is_empty() {
        return DoctorCheck {
            name: "security_posture".to_string(),
            status: DoctorStatus::Warn,
            detail: warnings.join("; "),
        };
    }

    DoctorCheck {
        name: "security_posture".to_string(),
        status: DoctorStatus::Pass,
        detail: "Authentication is enabled; allow_insecure_webhooks and allow_private_endpoints are disabled"
            .to_string(),
    }
}

// ============================================================================
// Minimal ASN.1 DER parser for X.509 Certificate Validity (RFC 5280)
// ============================================================================

/// Read one ASN.1 DER TLV element, returning `(tag, value_slice, remaining_slice)`.
fn read_der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let &tag = input
        .first()
        .ok_or_else(|| "Unexpected EOF reading DER tag".to_string())?;
    let mut idx = 1usize;

    // Handle high-tag-number form if present (low 5 bits all set).
    if tag & 0x1f == 0x1f {
        loop {
            let &b = input
                .get(idx)
                .ok_or_else(|| "Unexpected EOF reading high DER tag".to_string())?;
            idx += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    let &first_len = input
        .get(idx)
        .ok_or_else(|| "Unexpected EOF reading DER length".to_string())?;
    idx += 1;

    let content_len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let len_bytes = (first_len & 0x7f) as usize;
        if len_bytes == 0 || len_bytes > 4 {
            return Err(format!(
                "Unsupported DER length encoding (len_bytes={len_bytes})"
            ));
        }
        let slice = input
            .get(idx..idx + len_bytes)
            .ok_or_else(|| "Unexpected EOF reading multi-byte DER length".to_string())?;
        idx += len_bytes;
        let mut val = 0usize;
        for &b in slice {
            val = (val << 8) | (b as usize);
        }
        val
    };

    let end = idx
        .checked_add(content_len)
        .ok_or_else(|| "DER length overflow".to_string())?;
    if end > input.len() {
        return Err("DER element exceeds input buffer".to_string());
    }

    Ok((tag, &input[idx..end], &input[end..]))
}

fn parse_ascii_digits(bytes: &[u8]) -> Result<u32, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "Non-UTF8 ASN.1 time".to_string())?;
    s.parse::<u32>()
        .map_err(|_| format!("Invalid numeric component '{s}' in ASN.1 time"))
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Result<DateTime<Utc>, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "Non-UTF8 X.509 time value".to_string())?;
    let trimmed = s
        .strip_suffix('Z')
        .ok_or_else(|| format!("X.509 time '{s}' is not in UTC ('Z') format"))?;

    // Strip optional fractional seconds if present on GeneralizedTime.
    let core = match trimmed.split_once('.') {
        Some((before, _)) => before,
        None => trimmed,
    };

    let (year, rest) = match tag {
        // UTCTime: YYMMDDHHMMSS
        0x17 => {
            if core.len() != 12 {
                return Err(format!("Unexpected UTCTime length in '{s}'"));
            }
            let yy = parse_ascii_digits(&core.as_bytes()[0..2])? as i32;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &core.as_bytes()[2..])
        }
        // GeneralizedTime: YYYYMMDDHHMMSS
        0x18 => {
            if core.len() != 14 {
                return Err(format!("Unexpected GeneralizedTime length in '{s}'"));
            }
            let year = parse_ascii_digits(&core.as_bytes()[0..4])? as i32;
            (year, &core.as_bytes()[4..])
        }
        other => {
            return Err(format!(
                "Expected ASN.1 Time tag (0x17/0x18), got 0x{other:02x}"
            ));
        }
    };

    let month = parse_ascii_digits(&rest[0..2])?;
    let day = parse_ascii_digits(&rest[2..4])?;
    let hour = parse_ascii_digits(&rest[4..6])?;
    let minute = parse_ascii_digits(&rest[6..8])?;
    let second = parse_ascii_digits(&rest[8..10])?;

    let date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| format!("Invalid calendar date in X.509 time '{s}'"))?;
    let naive = date
        .and_hms_opt(hour, minute, second)
        .ok_or_else(|| format!("Invalid clock time in X.509 time '{s}'"))?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

/// Extract `(notBefore, notAfter)` UTC timestamps from a DER-encoded X.509 certificate.
pub fn parse_x509_validity(cert_der: &[u8]) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_tag, cert_body, _) = read_der_tlv(cert_der)?;
    if cert_tag != 0x30 {
        return Err(format!(
            "Expected Certificate SEQUENCE (0x30), got 0x{cert_tag:02x}"
        ));
    }

    // TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer, validity, ... }
    let (tbs_tag, mut tbs_body, _) = read_der_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return Err(format!(
            "Expected TBSCertificate SEQUENCE (0x30), got 0x{tbs_tag:02x}"
        ));
    }

    // Optional [0] EXPLICIT version (tag 0xA0)
    if tbs_body.first() == Some(&0xA0) {
        let (_, _, rest) = read_der_tlv(tbs_body)?;
        tbs_body = rest;
    }

    // serialNumber (INTEGER)
    let (serial_tag, _, rest) = read_der_tlv(tbs_body)?;
    if serial_tag != 0x02 {
        return Err(format!(
            "Expected serialNumber INTEGER (0x02), got 0x{serial_tag:02x}"
        ));
    }
    // signature (AlgorithmIdentifier SEQUENCE)
    let (sig_tag, _, rest) = read_der_tlv(rest)?;
    if sig_tag != 0x30 {
        return Err(format!(
            "Expected signature SEQUENCE (0x30), got 0x{sig_tag:02x}"
        ));
    }
    // issuer (Name SEQUENCE)
    let (issuer_tag, _, rest) = read_der_tlv(rest)?;
    if issuer_tag != 0x30 {
        return Err(format!(
            "Expected issuer SEQUENCE (0x30), got 0x{issuer_tag:02x}"
        ));
    }
    // validity (Validity SEQUENCE { notBefore, notAfter })
    let (validity_tag, validity_body, _) = read_der_tlv(rest)?;
    if validity_tag != 0x30 {
        return Err(format!(
            "Expected validity SEQUENCE (0x30), got 0x{validity_tag:02x}"
        ));
    }

    let (nb_tag, nb_bytes, rest) = read_der_tlv(validity_body)?;
    let not_before = parse_asn1_time(nb_tag, nb_bytes)?;
    let (na_tag, na_bytes, _) = read_der_tlv(rest)?;
    let not_after = parse_asn1_time(na_tag, na_bytes)?;

    Ok((not_before, not_after))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use rcgen::{CertificateParams, KeyPair, date_time_ymd};

    use super::*;
    use crate::secrets::write_secret_file;

    fn write_test_cert(
        dir: &Path,
        prefix: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> (PathBuf, PathBuf) {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_path = dir.join(format!("{prefix}.crt"));
        let key_path = dir.join(format!("{prefix}.key"));
        fs::write(&cert_path, cert.pem()).unwrap();
        write_secret_file(&key_path, &key_pair.serialize_pem(), true).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn parse_x509_validity_reads_utctime_and_generalized_time() {
        let dir = tempfile::tempdir().unwrap();

        // UTCTime range (before 2050)
        let (cert_path, _) = write_test_cert(dir.path(), "utc", (2025, 1, 15), (2030, 6, 20));
        let der = load_leaf_cert_der(&cert_path).unwrap();
        let (nb, na) = parse_x509_validity(der.as_ref()).unwrap();
        assert_eq!(nb, Utc.with_ymd_and_hms(2025, 1, 15, 0, 0, 0).unwrap());
        assert_eq!(na, Utc.with_ymd_and_hms(2030, 6, 20, 0, 0, 0).unwrap());

        // GeneralizedTime range (>= 2050)
        let (cert_path2, _) = write_test_cert(dir.path(), "gen", (2025, 1, 1), (2055, 12, 31));
        let der2 = load_leaf_cert_der(&cert_path2).unwrap();
        let (_, na2) = parse_x509_validity(der2.as_ref()).unwrap();
        assert_eq!(na2, Utc.with_ymd_and_hms(2055, 12, 31, 0, 0, 0).unwrap());
    }

    #[test]
    fn imap_tls_check_detects_valid_expiring_expired_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) =
            write_test_cert(dir.path(), "srv", (2026, 1, 1), (2026, 12, 31));

        let mut cfg = Config::for_test();
        cfg.imap_tls_cert = Some(cert_path);
        cfg.imap_tls_key = Some(key_path);

        // Well before expiry (> 30 days remaining) -> pass
        let check_ok = check_imap_tls(&cfg, Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        assert_eq!(check_ok.status, DoctorStatus::Pass, "{check_ok:?}");

        // Within 30 days of expiry -> warn
        let check_warn = check_imap_tls(&cfg, Utc.with_ymd_and_hms(2026, 12, 15, 0, 0, 0).unwrap());
        assert_eq!(check_warn.status, DoctorStatus::Warn, "{check_warn:?}");
        assert!(check_warn.detail.contains("expires in"));

        // Expired -> fail
        let check_expired =
            check_imap_tls(&cfg, Utc.with_ymd_and_hms(2027, 1, 5, 0, 0, 0).unwrap());
        assert_eq!(
            check_expired.status,
            DoctorStatus::Fail,
            "{check_expired:?}"
        );
        assert!(check_expired.detail.contains("expired"));

        // Invalid path -> fail
        cfg.imap_tls_cert = Some(dir.path().join("does-not-exist.pem"));
        let check_missing =
            check_imap_tls(&cfg, Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        assert_eq!(check_missing.status, DoctorStatus::Fail);
    }

    #[tokio::test]
    async fn run_doctor_reports_healthy_sqlite_fs_config_without_leaking_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("auth_token");
        let secret_val = "nogml_super_secret_token_never_leak_999";
        write_secret_file(&secret_path, secret_val, true).unwrap();

        let mut cfg = Config::for_test();
        cfg.storage = crate::config::StorageBackend::Sqlite;
        cfg.db_path = dir.path().join("doctor.db");
        cfg.blob_backend = BlobBackend::Fs;
        cfg.blob_dir = dir.path().join("blobs");
        cfg.auth_tokens = vec![secret_val.to_string()];
        cfg.resend_api_key = Some("re_super_secret_api_key_never_leak".to_string());

        let mut resolution = SecretResolutionReport::default();
        resolution.record_loaded_file(secret_path);

        let report = run_doctor(&cfg, None, resolution).await;
        assert!(report.ok, "expected healthy report: {report:?}");
        assert_eq!(report.summary.fail, 0);
        assert_eq!(report.summary.warn, 0);
        assert_eq!(report.summary.pass, 7);

        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains(secret_val));
        assert!(!rendered.contains("re_super_secret_api_key_never_leak"));
    }

    #[tokio::test]
    async fn run_doctor_redacts_malformed_webhook_urls_with_userinfo_and_query() {
        let mut cfg = Config::for_test();
        cfg.approval_webhook_url = Some(
            "https://alice:super_secret_pw@bad host/approve?token=approval_leak_123#frag"
                .to_string(),
        );
        cfg.watch_webhook_url = Some(
            "http://bob:watch_pw_456@exa mple.com:badport/watch?api_key=watch_leak_789".to_string(),
        );

        let report = run_doctor(&cfg, None, SecretResolutionReport::default()).await;
        assert!(!report.ok);
        let config_check = report
            .checks
            .iter()
            .find(|c| c.name == "config")
            .expect("config check");
        assert_eq!(config_check.status, DoctorStatus::Fail);
        assert!(config_check.detail.contains("safety.approval_webhook_url"));
        assert!(config_check.detail.contains("watch.webhook_url"));

        let rendered = serde_json::to_string(&report).unwrap();
        for forbidden in [
            "alice",
            "super_secret_pw",
            "approval_leak_123",
            "frag",
            "bob",
            "watch_pw_456",
            "watch_leak_789",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "doctor output leaked '{forbidden}': {rendered}"
            );
        }
    }
}
