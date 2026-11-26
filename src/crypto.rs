//! Pure-Rust AES-256-GCM encryption at rest for stored secrets and credentials.
//!
//! Uses `ring::aead::AES_256_GCM` with fresh random 96-bit nonces from
//! `ring::rand::SystemRandom` and versioned envelopes:
//!
//! ```text
//! enc:v1:<kid>:<nonce_b64url>:<ciphertext_and_tag_b64url>
//! ```
//!
//! Associated authenticated data (AAD) binds `v1:<kid>` to the authentication tag
//! so key ID substitution or envelope tampering fails decryption.

use std::{collections::HashSet, fmt};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    config::{Config, StorageBackend, normalize_mailbox_id},
    error::{AppError, AppResult},
    secrets::split_token_list,
    storage::{InboxRulePatch, SqliteStore},
};

/// Envelope prefix identifying AES-256-GCM v1 encrypted secrets.
pub const ENVELOPE_PREFIX: &str = "enc:v1:";

/// Default key identifier used when a key specification omits `<kid>:`.
pub const DEFAULT_KEY_ID: &str = "k1";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAX_KEY_ID_LEN: usize = 64;

/// Validate a key identifier (`kid`) so envelope parsing on `:` is unambiguous.
pub fn validate_key_id(kid: &str) -> AppResult<String> {
    let trimmed = kid.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config(
            "Encryption key ID (kid) must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_KEY_ID_LEN {
        return Err(AppError::Config(format!(
            "Encryption key ID exceeds maximum length of {MAX_KEY_ID_LEN} characters"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::Config(
            "Encryption key ID must contain only ASCII letters, digits, '-', or '_'".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn decode_hex_key(raw: &str) -> Option<[u8; KEY_LEN]> {
    if raw.len() != KEY_LEN * 2 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    let bytes = raw.as_bytes();
    for i in 0..KEY_LEN {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_key_material(raw: &str, label: &str) -> AppResult<[u8; KEY_LEN]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config(format!(
            "Encryption key material for {label} must not be empty"
        )));
    }

    if let Some(hex_bytes) = decode_hex_key(trimmed) {
        return Ok(hex_bytes);
    }

    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| {
            AppError::Config(format!(
                "Invalid encryption key for {label}: expected a 32-byte key encoded as base64 (44 chars) or hex (64 chars)"
            ))
        })?;

    if decoded.len() != KEY_LEN {
        return Err(AppError::Config(format!(
            "Invalid encryption key length for {label}: expected {KEY_LEN} bytes (256 bits), got {} bytes",
            decoded.len()
        )));
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Parse an encryption key specification (`<kid>:<key>` or bare `<key>` defaulting to `k1`).
pub fn parse_key_spec(raw: &str, label: &str) -> AppResult<(String, [u8; KEY_LEN])> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config(format!(
            "Encryption key specification for {label} must not be empty"
        )));
    }
    if let Some((raw_kid, raw_key)) = trimmed.split_once(':') {
        let kid = validate_key_id(raw_kid)?;
        let key_bytes = decode_key_material(raw_key, label)?;
        Ok((kid, key_bytes))
    } else {
        let key_bytes = decode_key_material(trimmed, label)?;
        Ok((DEFAULT_KEY_ID.to_string(), key_bytes))
    }
}

/// Generate a cryptographically random 32-byte key encoded as standard base64 (44 chars).
pub fn generate_key_base64() -> AppResult<String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; KEY_LEN];
    rng.fill(&mut bytes).map_err(|_| {
        AppError::Internal("System CSPRNG failed to generate key bytes".to_string())
    })?;
    Ok(STANDARD.encode(bytes))
}

/// Generate a `<kid>:<base64_key>` string using `ring::rand::SystemRandom`.
pub fn generate_formatted_key(kid: &str) -> AppResult<(String, String)> {
    let validated_kid = validate_key_id(kid)?;
    let b64 = generate_key_base64()?;
    let formatted = format!("{validated_kid}:{b64}");
    Ok((validated_kid, formatted))
}

struct KeySlot {
    kid: String,
    key: LessSafeKey,
}

impl KeySlot {
    fn new(kid: String, key_bytes: [u8; KEY_LEN]) -> AppResult<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| AppError::Config("Failed to initialize AES-256-GCM key".to_string()))?;
        Ok(Self {
            kid,
            key: LessSafeKey::new(unbound),
        })
    }
}

/// AES-256-GCM secret cipher supporting transparent legacy plaintext reads and
/// zero-downtime multi-key rotation.
pub struct SecretCipher {
    primary: Option<KeySlot>,
    previous: Vec<KeySlot>,
    rng: SystemRandom,
}

impl fmt::Debug for SecretCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let primary_kid = self.primary.as_ref().map(|k| k.kid.as_str());
        let previous_kids: Vec<&str> = self.previous.iter().map(|k| k.kid.as_str()).collect();
        f.debug_struct("SecretCipher")
            .field("enabled", &self.primary.is_some())
            .field("primary_kid", &primary_kid)
            .field("previous_kids", &previous_kids)
            .finish()
    }
}

impl Default for SecretCipher {
    fn default() -> Self {
        Self::disabled()
    }
}

impl SecretCipher {
    /// Create a disabled cipher where `encrypt` and `decrypt` act as transparent passthroughs.
    pub fn disabled() -> Self {
        Self {
            primary: None,
            previous: Vec::new(),
            rng: SystemRandom::new(),
        }
    }

    /// Construct a [`SecretCipher`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        Self::from_raw_keys(
            config.encryption_key.as_deref(),
            &config.encryption_previous_keys,
        )
    }

    /// Construct a [`SecretCipher`] from raw primary and previous key specifications.
    pub fn from_raw_keys(primary: Option<&str>, previous: &[String]) -> AppResult<Self> {
        let primary_trimmed = primary.map(str::trim).filter(|s| !s.is_empty());
        let previous_entries: Vec<String> = previous
            .iter()
            .flat_map(|entry| split_token_list(entry))
            .collect();

        let Some(primary_raw) = primary_trimmed else {
            if !previous_entries.is_empty() {
                return Err(AppError::Config(
                    "security.encryption_previous_keys requires security.encryption_key (NOGML_ENCRYPTION_KEY) to be configured"
                        .to_string(),
                ));
            }
            return Ok(Self::disabled());
        };

        let mut seen_kids = HashSet::new();
        let (primary_kid, primary_bytes) = parse_key_spec(primary_raw, "security.encryption_key")?;
        seen_kids.insert(primary_kid.clone());
        let primary_slot = KeySlot::new(primary_kid, primary_bytes)?;

        let mut prev_slots = Vec::with_capacity(previous_entries.len());
        for (idx, raw) in previous_entries.iter().enumerate() {
            let label = format!("security.encryption_previous_keys[{idx}]");
            let (kid, key_bytes) = parse_key_spec(raw, &label)?;
            if !seen_kids.insert(kid.clone()) {
                return Err(AppError::Config(format!(
                    "Duplicate encryption key ID '{kid}' across encryption_key and encryption_previous_keys"
                )));
            }
            prev_slots.push(KeySlot::new(kid, key_bytes)?);
        }

        Ok(Self {
            primary: Some(primary_slot),
            previous: prev_slots,
            rng: SystemRandom::new(),
        })
    }

    /// Returns `true` when encryption at rest is enabled with a primary key.
    pub fn is_enabled(&self) -> bool {
        self.primary.is_some()
    }

    /// Return the active primary key ID (`kid`) when encryption is enabled.
    pub fn primary_kid(&self) -> Option<&str> {
        self.primary.as_ref().map(|k| k.kid.as_str())
    }

    /// Returns `true` if `value` carries the `enc:v1:` envelope prefix.
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENVELOPE_PREFIX)
    }

    /// Extract the `<kid>` from a well-formed `enc:v1:<kid>:...` prefix, if present.
    pub fn envelope_kid(value: &str) -> Option<&str> {
        let rest = value.strip_prefix(ENVELOPE_PREFIX)?;
        let (kid, _) = rest.split_once(':')?;
        (!kid.is_empty()).then_some(kid)
    }

    /// Encrypt `plaintext` under the current primary key.
    ///
    /// Returns `plaintext` unchanged when encryption at rest is disabled.
    pub fn encrypt(&self, plaintext: &str) -> AppResult<String> {
        let Some(slot) = self.primary.as_ref() else {
            return Ok(plaintext.to_string());
        };

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes).map_err(|_| {
            AppError::Internal("System CSPRNG failed to generate AES-GCM nonce".to_string())
        })?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad_str = format!("v1:{}", slot.kid);

        let mut in_out = plaintext.as_bytes().to_vec();
        slot.key
            .seal_in_place_append_tag(nonce, Aad::from(aad_str.as_bytes()), &mut in_out)
            .map_err(|_| AppError::Internal("AES-256-GCM encryption failed".to_string()))?;

        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce_bytes);
        let ct_b64 = URL_SAFE_NO_PAD.encode(&in_out);
        Ok(format!(
            "{ENVELOPE_PREFIX}{}:{nonce_b64}:{ct_b64}",
            slot.kid
        ))
    }

    /// Decrypt an `enc:v1:...` envelope using the matching `kid` from the primary or
    /// previous keys.
    ///
    /// Values that do NOT start with `enc:v1:` are returned unchanged for transparent
    /// backward compatibility with legacy plaintext rows.
    pub fn decrypt(&self, value: &str) -> AppResult<String> {
        let Some(rest) = value.strip_prefix(ENVELOPE_PREFIX) else {
            return Ok(value.to_string());
        };

        let mut parts = rest.split(':');
        let (Some(kid), Some(nonce_b64), Some(ct_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AppError::Config(
                "Malformed enc:v1 ciphertext envelope".to_string(),
            ));
        };

        if kid.is_empty() || nonce_b64.is_empty() || ct_b64.is_empty() {
            return Err(AppError::Config(
                "Malformed enc:v1 ciphertext envelope".to_string(),
            ));
        }

        let slot = self
            .primary
            .iter()
            .chain(self.previous.iter())
            .find(|k| k.kid == kid)
            .ok_or_else(|| {
                AppError::Config(format!(
                    "Cannot decrypt secret encrypted with unknown key ID '{kid}'; configure NOGML_ENCRYPTION_KEY or NOGML_ENCRYPTION_PREVIOUS_KEYS"
                ))
            })?;

        let nonce_vec = URL_SAFE_NO_PAD
            .decode(nonce_b64.trim_end_matches('='))
            .map_err(|_| {
                AppError::Config(format!(
                    "Malformed nonce encoding in secret encrypted with key ID '{kid}'"
                ))
            })?;
        if nonce_vec.len() != NONCE_LEN {
            return Err(AppError::Config(format!(
                "Invalid nonce length in secret encrypted with key ID '{kid}'"
            )));
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce_vec);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut ct = URL_SAFE_NO_PAD
            .decode(ct_b64.trim_end_matches('='))
            .map_err(|_| {
                AppError::Config(format!(
                    "Malformed ciphertext encoding in secret encrypted with key ID '{kid}'"
                ))
            })?;
        if ct.len() < AES_256_GCM.tag_len() {
            return Err(AppError::Config(format!(
                "Truncated ciphertext in secret encrypted with key ID '{kid}'"
            )));
        }

        let aad_str = format!("v1:{kid}");
        let plain_bytes = slot
            .key
            .open_in_place(nonce, Aad::from(aad_str.as_bytes()), &mut ct)
            .map_err(|_| {
                AppError::Config(format!(
                    "Failed to decrypt secret with key ID '{kid}': authentication tag mismatch or tampered ciphertext"
                ))
            })?;

        String::from_utf8(plain_bytes.to_vec()).map_err(|_| {
            AppError::Config(format!(
                "Decrypted secret for key ID '{kid}' is not valid UTF-8"
            ))
        })
    }

    /// Returns `true` when encryption is enabled and `value` is either plaintext
    /// or encrypted under a non-primary `kid`.
    pub fn needs_reencrypt(&self, value: &str) -> bool {
        let Some(primary) = self.primary.as_ref() else {
            return false;
        };
        match Self::envelope_kid(value) {
            Some(kid) => kid != primary.kid,
            None => true,
        }
    }
}

/// Per-mailbox counts returned by [`rotate_secrets`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxRotationSummary {
    pub mailbox_id: String,
    pub send_as_rotated: u64,
    pub rules_rotated: u64,
}

/// Aggregate JSON summary returned by `nogml crypto rotate-key`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationReport {
    pub ok: bool,
    pub primary_kid: String,
    pub mailboxes_scanned: usize,
    pub send_as_rotated: u64,
    pub rules_rotated: u64,
    pub mailboxes: Vec<MailboxRotationSummary>,
}

/// Re-encrypt all stored `sendAs.smtp_msa.password` and `inbox_rules.webhook_secret`
/// values across all known mailboxes under the active primary key.
pub async fn rotate_secrets(state: &AppState) -> AppResult<KeyRotationReport> {
    let primary_kid = state
        .cipher
        .primary_kid()
        .ok_or_else(|| {
            AppError::Config(
                "Encryption at rest is not enabled; set NOGML_ENCRYPTION_KEY, NOGML_ENCRYPTION_KEY_FILE, or [security].encryption_key before running `nogml crypto rotate-key`"
                    .to_string(),
            )
        })?
        .to_string();

    let mut mailboxes = state.config.known_mailboxes();
    if state.config.storage == StorageBackend::Sqlite
        && state.config.db_path.exists()
        && let Ok(db_mailboxes) = SqliteStore::list_mailbox_ids(&state.config.db_path)
    {
        for raw_mb in db_mailboxes {
            let norm = normalize_mailbox_id(&raw_mb);
            if !norm.is_empty() && !mailboxes.contains(&norm) {
                mailboxes.push(norm);
            }
        }
    }

    let mut per_mailbox = Vec::with_capacity(mailboxes.len());
    let mut total_send_as = 0u64;
    let mut total_rules = 0u64;

    for mb in &mailboxes {
        let mb_state = state.for_mailbox(mb);
        let mut send_as_rotated = 0u64;
        let mut rules_rotated = 0u64;

        let mut settings = mb_state.store.get_settings().await?;
        let mut settings_dirty = false;
        for entry in &mut settings.send_as {
            if let Some(ref mut msa) = entry.smtp_msa
                && let Some(ref raw_pw) = msa.password
                && !raw_pw.is_empty()
                && mb_state.cipher.needs_reencrypt(raw_pw)
            {
                let plain = mb_state.cipher.decrypt(raw_pw)?;
                msa.password = Some(mb_state.cipher.encrypt(&plain)?);
                settings_dirty = true;
                send_as_rotated += 1;
            }
        }
        if settings_dirty {
            mb_state.store.save_settings(settings).await?;
        }

        let rules = mb_state.store.list_inbox_rules().await?;
        for rule in rules {
            if let Some(ref raw_secret) = rule.actions.webhook_secret
                && !raw_secret.is_empty()
                && mb_state.cipher.needs_reencrypt(raw_secret)
            {
                let plain = mb_state.cipher.decrypt(raw_secret)?;
                let encrypted = mb_state.cipher.encrypt(&plain)?;
                let mut next_actions = rule.actions.clone();
                next_actions.webhook_secret = Some(encrypted);
                let patch = InboxRulePatch {
                    actions: Some(next_actions),
                    ..Default::default()
                };
                mb_state.store.patch_inbox_rule(&rule.id, &patch).await?;
                rules_rotated += 1;
            }
        }

        total_send_as += send_as_rotated;
        total_rules += rules_rotated;
        per_mailbox.push(MailboxRotationSummary {
            mailbox_id: mb.clone(),
            send_as_rotated,
            rules_rotated,
        });
    }

    Ok(KeyRotationReport {
        ok: true,
        primary_kid,
        mailboxes_scanned: mailboxes.len(),
        send_as_rotated: total_send_as,
        rules_rotated: total_rules,
        mailboxes: per_mailbox,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip_and_unique_nonces() {
        let (_, k1) = generate_formatted_key("k1").unwrap();
        let cipher = SecretCipher::from_raw_keys(Some(&k1), &[]).unwrap();
        assert!(cipher.is_enabled());
        assert_eq!(cipher.primary_kid(), Some("k1"));

        let c1 = cipher.encrypt("super-secret-password").unwrap();
        let c2 = cipher.encrypt("super-secret-password").unwrap();
        assert!(c1.starts_with("enc:v1:k1:"));
        assert!(c2.starts_with("enc:v1:k1:"));
        assert_ne!(c1, c2, "fresh 96-bit nonces must produce unique envelopes");
        assert!(!c1.contains("super-secret-password"));

        assert_eq!(cipher.decrypt(&c1).unwrap(), "super-secret-password");
        assert_eq!(cipher.decrypt(&c2).unwrap(), "super-secret-password");
        assert!(!cipher.needs_reencrypt(&c1));
    }

    #[test]
    fn key_formats_base64_urlsafe_hex_and_default_kid() {
        let b64 = generate_key_base64().unwrap();
        assert_eq!(b64.len(), 44);
        let cipher_default = SecretCipher::from_raw_keys(Some(&b64), &[]).unwrap();
        assert_eq!(cipher_default.primary_kid(), Some("k1"));
        let enc = cipher_default.encrypt("hello").unwrap();
        assert!(enc.starts_with("enc:v1:k1:"));
        assert_eq!(cipher_default.decrypt(&enc).unwrap(), "hello");

        // 64-char hex key with explicit kid
        let hex_key = format!("prod_2026:{}", "a1".repeat(32));
        let cipher_hex = SecretCipher::from_raw_keys(Some(&hex_key), &[]).unwrap();
        assert_eq!(cipher_hex.primary_kid(), Some("prod_2026"));
        let enc_hex = cipher_hex.encrypt("hex-secret").unwrap();
        assert!(enc_hex.starts_with("enc:v1:prod_2026:"));
        assert_eq!(cipher_hex.decrypt(&enc_hex).unwrap(), "hex-secret");

        // URL-safe base64 without padding
        let raw_bytes = [0xfbu8; 32];
        let b64url = URL_SAFE_NO_PAD.encode(raw_bytes);
        let cipher_url = SecretCipher::from_raw_keys(Some(&format!("u1:{b64url}")), &[]).unwrap();
        let enc_url = cipher_url.encrypt("url-secret").unwrap();
        assert_eq!(cipher_url.decrypt(&enc_url).unwrap(), "url-secret");
    }

    #[test]
    fn tamper_detection_on_ciphertext_and_kid() {
        let (_, k1) = generate_formatted_key("k1").unwrap();
        let (_, k2) = generate_formatted_key("k2").unwrap();
        let cipher = SecretCipher::from_raw_keys(Some(&k2), std::slice::from_ref(&k1)).unwrap();
        let cipher_k1 = SecretCipher::from_raw_keys(Some(&k1), &[]).unwrap();

        let enc = cipher_k1.encrypt("webhook-secret-xyz").unwrap();
        let parts: Vec<&str> = enc.split(':').collect();
        assert_eq!(parts.len(), 5);

        // Tamper with ciphertext byte
        let mut ct = URL_SAFE_NO_PAD.decode(parts[4]).unwrap();
        ct[0] ^= 0xff;
        let tampered_ct = format!(
            "enc:v1:{}:{}:{}",
            parts[2],
            parts[3],
            URL_SAFE_NO_PAD.encode(&ct)
        );
        let err = cipher.decrypt(&tampered_ct).unwrap_err();
        assert!(matches!(err, AppError::Config(_)));

        // Tamper with kid (re-tag envelope from k1 to k2 -> AAD mismatch / wrong key)
        let tampered_kid = format!("enc:v1:k2:{}:{}", parts[3], parts[4]);
        let err = cipher.decrypt(&tampered_kid).unwrap_err();
        assert!(matches!(err, AppError::Config(_)));

        // Same key bytes under a different kid must still fail due to AAD binding `v1:<kid>`
        let b64 = generate_key_base64().unwrap();
        let c_a = SecretCipher::from_raw_keys(Some(&format!("ka:{b64}")), &[]).unwrap();
        let c_b = SecretCipher::from_raw_keys(Some(&format!("kb:{b64}")), &[]).unwrap();
        let enc_a = c_a.encrypt("aad-check").unwrap();
        let swapped = enc_a.replacen("enc:v1:ka:", "enc:v1:kb:", 1);
        let err = c_b.decrypt(&swapped).unwrap_err();
        assert!(matches!(err, AppError::Config(_)));
    }

    #[test]
    fn legacy_plaintext_passthrough_and_disabled_mode() {
        let disabled = SecretCipher::disabled();
        assert!(!disabled.is_enabled());
        assert_eq!(disabled.encrypt("plain-pw").unwrap(), "plain-pw");
        assert_eq!(disabled.decrypt("plain-pw").unwrap(), "plain-pw");
        assert!(!disabled.needs_reencrypt("plain-pw"));

        let (_, k1) = generate_formatted_key("k1").unwrap();
        let enabled = SecretCipher::from_raw_keys(Some(&k1), &[]).unwrap();
        assert_eq!(
            enabled.decrypt("legacy-plaintext").unwrap(),
            "legacy-plaintext"
        );
        assert!(enabled.needs_reencrypt("legacy-plaintext"));

        // Disabled cipher cannot decrypt encrypted envelopes
        let enc = enabled.encrypt("top-secret").unwrap();
        let err = disabled.decrypt(&enc).unwrap_err();
        assert!(matches!(err, AppError::Config(_)));
        assert!(err.to_string().contains("unknown key ID 'k1'"));
    }

    #[test]
    fn multi_key_rotation_and_debug_redaction() {
        let (_, k1) = generate_formatted_key("k1").unwrap();
        let (_, k2) = generate_formatted_key("k2").unwrap();

        let c1 = SecretCipher::from_raw_keys(Some(&k1), &[]).unwrap();
        let enc_k1 = c1.encrypt("rotate-me").unwrap();
        assert!(enc_k1.starts_with("enc:v1:k1:"));

        let c2 = SecretCipher::from_raw_keys(Some(&k2), std::slice::from_ref(&k1)).unwrap();
        assert!(c2.needs_reencrypt(&enc_k1));
        assert_eq!(c2.decrypt(&enc_k1).unwrap(), "rotate-me");

        let enc_k2 = c2.encrypt("rotate-me").unwrap();
        assert!(enc_k2.starts_with("enc:v1:k2:"));
        assert!(!c2.needs_reencrypt(&enc_k2));

        // After dropping k1, k2-only cipher still decrypts enc_k2 and rejects enc_k1
        let c2_only = SecretCipher::from_raw_keys(Some(&k2), &[]).unwrap();
        assert_eq!(c2_only.decrypt(&enc_k2).unwrap(), "rotate-me");
        assert!(c2_only.decrypt(&enc_k1).is_err());

        // Debug output must never leak key material
        let k1_secret_part = k1.split_once(':').unwrap().1;
        let k2_secret_part = k2.split_once(':').unwrap().1;
        let dbg = format!("{c2:?}");
        assert!(dbg.contains("k2"));
        assert!(dbg.contains("k1"));
        assert!(!dbg.contains(k1_secret_part));
        assert!(!dbg.contains(k2_secret_part));
    }

    #[test]
    fn rejects_invalid_keys_and_duplicate_kids() {
        assert!(SecretCipher::from_raw_keys(Some("k1:not-valid-key"), &[]).is_err());
        assert!(SecretCipher::from_raw_keys(Some("k1:AAAA"), &[]).is_err());
        assert!(SecretCipher::from_raw_keys(Some("bad kid:a1".repeat(32).as_str()), &[]).is_err());

        let (_, k1a) = generate_formatted_key("k1").unwrap();
        let (_, k1b) = generate_formatted_key("k1").unwrap();
        assert!(SecretCipher::from_raw_keys(Some(&k1a), &[k1b]).is_err());
        assert!(SecretCipher::from_raw_keys(None, &[k1a]).is_err());
    }
}
