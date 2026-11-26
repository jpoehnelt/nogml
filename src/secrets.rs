//! Secret reference resolution (`file://`, `env://`, and `*_FILE` environment variables),
//! Unix permission checks, redaction helpers, and token generation.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Placeholder emitted in `Debug` output and redacted config diagnostics for every secret field.
pub const REDACTED: &str = "[REDACTED]";

/// Redact credentials, path, query string, and fragment from a webhook or secret-bearing URL,
/// returning `scheme://host[:port]/[REDACTED]` (or `[REDACTED]` when unparseable).
pub fn redact_url_for_log(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match url::Url::parse(trimmed) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            match (parsed.host_str(), parsed.port()) {
                (Some(host), Some(port)) => format!("{scheme}://{host}:{port}/{REDACTED}"),
                (Some(host), None) => format!("{scheme}://{host}/{REDACTED}"),
                (None, _) => REDACTED.to_string(),
            }
        }
        Err(_) => REDACTED.to_string(),
    }
}

/// Origin of a field value before `*_FILE` environment variable resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueOrigin {
    /// Explicitly supplied via a CLI flag.
    Cli,
    /// Explicitly supplied via the direct environment variable (e.g. `RESEND_API_KEY`).
    DirectEnv,
    /// Not supplied on CLI or direct environment variable (may come from `nogml.toml` or defaults).
    Unset,
}

/// Diagnostics accumulated while resolving `file://`, `env://`, and `*_FILE` secrets.
#[derive(Debug, Clone, Default)]
pub struct SecretResolutionReport {
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub loaded_files: Vec<PathBuf>,
}

impl SecretResolutionReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn push_warning_unique(&mut self, warning: String) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    pub fn record_loaded_file(&mut self, path: PathBuf) {
        if !self.loaded_files.contains(&path) {
            self.loaded_files.push(path);
        }
    }

    /// Convert accumulated secret errors into a single `AppError::Config` if any occurred.
    pub fn into_result(self) -> AppResult<Self> {
        if self.errors.is_empty() {
            Ok(self)
        } else {
            Err(AppError::Config(self.errors.join("; ")))
        }
    }
}

/// Default process environment variable lookup.
pub fn system_env_lookup(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Check if a secret file has overly permissive Unix mode bits (`mode & 0o077 != 0`).
///
/// Returns a non-fatal operator warning message when group or other read/write/exec bits are set.
pub fn check_secret_file_permissions(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Some(format!(
                    "Secret file '{}' has permissive permissions ({:04o}); restrict with chmod 0600",
                    path.display(),
                    mode & 0o777
                ));
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Expand a `file://` URI into a filesystem path.
///
/// Supports:
/// - `file:///absolute/path`
/// - `file://relative/path` (resolved relative to `base_dir` when provided)
/// - `file://$CREDENTIALS_DIRECTORY/secret` and `file://${CREDENTIALS_DIRECTORY}/secret`
///   for systemd `LoadCredential=` units.
pub fn parse_file_uri(
    field_name: &str,
    raw_uri: &str,
    base_dir: Option<&Path>,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<PathBuf, String> {
    let rest = raw_uri
        .strip_prefix("file://")
        .ok_or_else(|| format!("Secret '{field_name}' is not a valid file:// URI"))?;

    if rest.is_empty() {
        return Err(format!("Secret '{field_name}' has an empty file:// path"));
    }

    let expanded = if let Some(after) = rest
        .strip_prefix("$CREDENTIALS_DIRECTORY")
        .or_else(|| rest.strip_prefix("${CREDENTIALS_DIRECTORY}"))
    {
        let creds_dir = env_lookup("CREDENTIALS_DIRECTORY")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "Secret '{field_name}' references $CREDENTIALS_DIRECTORY in '{raw_uri}', \
                     but CREDENTIALS_DIRECTORY is not set"
                )
            })?;
        let suffix = after.trim_start_matches('/');
        if suffix.is_empty() {
            return Err(format!(
                "Secret '{field_name}' references $CREDENTIALS_DIRECTORY without a file name"
            ));
        }
        PathBuf::from(creds_dir).join(suffix)
    } else {
        let candidate = PathBuf::from(rest);
        if candidate.is_relative() {
            if let Some(dir) = base_dir {
                dir.join(candidate)
            } else {
                candidate
            }
        } else {
            candidate
        }
    };

    Ok(expanded)
}

/// Read a UTF-8 secret file from disk, trimming trailing CR/LF characters and recording
/// Unix permission warnings and diagnostics on `report`.
pub fn read_secret_file(
    field_name: &str,
    path: &Path,
    report: &mut SecretResolutionReport,
) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            if let Some(warn) = check_secret_file_permissions(path) {
                report.push_warning_unique(warn);
            }
            report.record_loaded_file(path.to_path_buf());
            Some(contents.trim_end_matches(&['\r', '\n'][..]).to_string())
        }
        Err(err) => {
            report.errors.push(format!(
                "Failed to read secret file '{}' for '{field_name}': {err}",
                path.display()
            ));
            None
        }
    }
}

/// Resolve a single secret value supporting `file://`, `env://`, or a literal string.
pub fn resolve_secret_value(
    field_name: &str,
    raw: &str,
    base_dir: Option<&Path>,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    report: &mut SecretResolutionReport,
) -> Option<String> {
    if raw.starts_with("file://") {
        match parse_file_uri(field_name, raw, base_dir, env_lookup) {
            Ok(path) => read_secret_file(field_name, &path, report),
            Err(err) => {
                report.errors.push(err);
                None
            }
        }
    } else if let Some(var_name) = raw.strip_prefix("env://") {
        let trimmed = var_name.trim();
        if trimmed.is_empty() {
            report.errors.push(format!(
                "Secret '{field_name}' has an empty env:// variable name"
            ));
            return None;
        }
        match env_lookup(trimmed) {
            Some(val) => Some(val),
            None => {
                report.errors.push(format!(
                    "Secret '{field_name}' references unset environment variable 'env://{trimmed}'"
                ));
                None
            }
        }
    } else {
        Some(raw.to_string())
    }
}

/// Split a token list string (comma- and/or newline-delimited) into non-empty trimmed tokens.
pub fn split_token_list(raw: &str) -> Vec<String> {
    raw.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Resolve a list of bearer token entries where each entry may be a literal token,
/// `file://...` (single token or newline/comma-separated list), or `env://VAR`.
pub fn resolve_secret_tokens(
    field_name: &str,
    raw_entries: &[String],
    base_dir: Option<&Path>,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    report: &mut SecretResolutionReport,
) -> Vec<String> {
    let mut resolved = Vec::new();
    for entry in raw_entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("file://") || trimmed.starts_with("env://") {
            if let Some(val) =
                resolve_secret_value(field_name, trimmed, base_dir, env_lookup, report)
            {
                resolved.extend(split_token_list(&val));
            }
        } else {
            resolved.push(trimmed.to_string());
        }
    }
    resolved
}

/// Generate a cryptographically random bearer token (`nogml_<64 hex chars>`).
pub fn generate_bearer_token() -> String {
    format!(
        "nogml_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

/// Write a secret value to `path` with mode `0600` on Unix.
///
/// Refuses to overwrite an existing file unless `force` is `true`.
pub fn write_secret_file(path: &Path, secret: &str, force: bool) -> AppResult<()> {
    if path.exists() && !force {
        return Err(AppError::Config(format!(
            "Secret file '{}' already exists; pass --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            AppError::Config(format!(
                "Failed to create directory '{}' for secret file: {e}",
                parent.display()
            ))
        })?;
    }

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                AppError::Config(format!(
                    "Failed to create secret file '{}': {e}",
                    path.display()
                ))
            })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            AppError::Config(format!(
                "Failed to set 0600 permissions on secret file '{}': {e}",
                path.display()
            ))
        })?;
        f
    };

    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| {
            AppError::Config(format!(
                "Failed to create secret file '{}': {e}",
                path.display()
            ))
        })?;

    writeln!(file, "{secret}").map_err(|e| {
        AppError::Config(format!(
            "Failed to write secret file '{}': {e}",
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn resolve_file_uri_trims_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("api.key");
        write_secret_file(&secret_path, "re_live_12345\r", false).unwrap();

        let env = |_: &str| None;
        let mut report = SecretResolutionReport::default();
        let uri = format!("file://{}", secret_path.display());
        let val = resolve_secret_value("resend.api_key", &uri, None, &env, &mut report);
        assert_eq!(val.as_deref(), Some("re_live_12345"));
        assert!(report.errors.is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn resolve_env_uri_and_missing_env_error() {
        let vars: HashMap<&str, &str> = [("MY_SECRET", "s3cr3t")].into_iter().collect();
        let env = |k: &str| vars.get(k).map(|v| (*v).to_string());
        let mut report = SecretResolutionReport::default();

        assert_eq!(
            resolve_secret_value("resend.api_key", "env://MY_SECRET", None, &env, &mut report)
                .as_deref(),
            Some("s3cr3t")
        );
        assert!(report.errors.is_empty());

        assert_eq!(
            resolve_secret_value(
                "resend.api_key",
                "env://MISSING_VAR",
                None,
                &env,
                &mut report
            ),
            None
        );
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("MISSING_VAR"));
    }

    #[test]
    fn resolve_credentials_directory_uri() {
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("resend_key");
        write_secret_file(&cred, "re_systemd_cred", false).unwrap();

        let creds_dir = dir.path().to_string_lossy().to_string();
        let env = |k: &str| {
            if k == "CREDENTIALS_DIRECTORY" {
                Some(creds_dir.clone())
            } else {
                None
            }
        };

        let mut report = SecretResolutionReport::default();
        let val = resolve_secret_value(
            "resend.api_key",
            "file://$CREDENTIALS_DIRECTORY/resend_key",
            None,
            &env,
            &mut report,
        );
        assert_eq!(val.as_deref(), Some("re_systemd_cred"));
        assert!(report.errors.is_empty());
    }

    #[test]
    fn resolve_tokens_from_multiline_and_comma_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        write_secret_file(&path, "tok_one, tok_two\ntok_three\n", false).unwrap();

        let env = |_: &str| None;
        let mut report = SecretResolutionReport::default();
        let uri = format!("file://{}", path.display());
        let tokens = resolve_secret_tokens("auth.tokens", &[uri], None, &env, &mut report);
        assert_eq!(tokens, vec!["tok_one", "tok_two", "tok_three"]);
        assert!(report.errors.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn warns_on_permissive_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("open_secret");
        fs::write(&path, "topsecret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let mut report = SecretResolutionReport::default();
        let val = read_secret_file("resend.api_key", &path, &mut report);
        assert_eq!(val.as_deref(), Some("topsecret"));
        assert!(report.errors.is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("0644"));
    }

    #[test]
    fn generated_token_has_expected_format_and_uniqueness() {
        let a = generate_bearer_token();
        let b = generate_bearer_token();
        assert!(a.starts_with("nogml_"));
        assert_eq!(a.len(), "nogml_".len() + 64);
        assert_ne!(a, b);
    }
}
