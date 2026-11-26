//! Shared BYOD domain lifecycle operations used by `/v1/domains` REST handlers and CLI.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    AppState,
    ai::safety::validate_single_recipient,
    auth::Principal,
    config::normalize_mailbox_id,
    domains::{
        DnsRecord, DomainProviderKind, DomainRecord, DomainStatus, DomainUpdate, NewDomainInput,
        normalize_and_validate_domain,
    },
    error::{AppError, AppResult},
};

/// Request body for `POST /v1/domains`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    #[serde(default)]
    pub provider: Option<DomainProviderKind>,
    #[serde(default)]
    pub mailbox_id: Option<String>,
    #[serde(default)]
    pub catch_all_mailbox: Option<String>,
}

/// Request body for `PATCH /v1/domains/{domain}`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PatchDomainRequest {
    /// Set or clear (`""` / `null`) the catch-all mailbox for verified inbound routing.
    /// Deserialized as double-`Option` so omitting the field leaves it unchanged.
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub catch_all_mailbox: Option<Option<String>>,
    /// Admin-only manual override for `provider == manual` domains.
    #[serde(default)]
    pub status: Option<DomainStatus>,
    #[serde(default)]
    pub dkim_verified: Option<bool>,
    #[serde(default)]
    pub spf_verified: Option<bool>,
    #[serde(default)]
    pub dmarc_verified: Option<bool>,
    #[serde(default)]
    pub mx_verified: Option<bool>,
    #[serde(default)]
    pub dns_records: Option<Vec<DnsRecord>>,
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(deserializer)?))
}

fn is_global_admin_principal(principal: Option<&Principal>) -> bool {
    principal.is_none_or(Principal::is_global_admin)
}

fn authorize_mailbox_access(
    principal: Option<&Principal>,
    target_mailbox: &str,
    context: &str,
) -> AppResult<()> {
    if is_global_admin_principal(principal) {
        return Ok(());
    }
    if let Some(p) = principal
        && p.can_access_mailbox(target_mailbox)
    {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "Access denied for {context} '{target_mailbox}'"
    )))
}

fn authorize_domain_access(principal: Option<&Principal>, record: &DomainRecord) -> AppResult<()> {
    if is_global_admin_principal(principal) {
        return Ok(());
    }
    if let Some(p) = principal
        && p.can_access_mailbox(&record.mailbox_id)
    {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "Access denied for domain '{}'",
        record.domain
    )))
}

fn validate_catch_all_mailbox(raw: &str) -> AppResult<String> {
    let parsed = validate_single_recipient(raw)?;
    let norm = normalize_mailbox_id(&parsed.email);
    if norm.is_empty() {
        return Err(AppError::validation(
            "catch_all_mailbox must be a valid email address",
            None,
        ));
    }
    Ok(norm)
}

/// Register a new custom BYOD domain, request DNS records from the configured provider,
/// and persist the domain record in `MailStore`.
pub async fn execute_create_domain(
    state: &AppState,
    req: CreateDomainRequest,
    principal: Option<&Principal>,
    channel: &str,
) -> AppResult<DomainRecord> {
    let domain = normalize_and_validate_domain(&req.domain)?;
    let provider_kind = req
        .provider
        .unwrap_or_else(|| DomainProviderKind::from_transport(state.config.transport));

    let mailbox_id = match req
        .mailbox_id
        .as_deref()
        .map(normalize_mailbox_id)
        .filter(|s| !s.is_empty())
    {
        Some(mb) => {
            authorize_mailbox_access(principal, &mb, "mailbox")?;
            mb
        }
        None => normalize_mailbox_id(state.mailbox_id()),
    };

    let catch_all_mailbox = match req
        .catch_all_mailbox
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let validated = validate_catch_all_mailbox(raw)?;
            authorize_mailbox_access(principal, &validated, "catch_all_mailbox")?;
            Some(validated)
        }
        None => None,
    };

    // Prevent cross-tenant domain hijacking before calling any upstream provider.
    if state.store.get_domain(&domain).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "Domain '{domain}' is already registered"
        )));
    }

    let provider = state.domain_providers.get(provider_kind)?;
    let prov_res = provider.create_domain(&domain).await?;
    let provider_domain_id = prov_res.provider_domain_id.clone();

    let input = NewDomainInput {
        id: None,
        domain: domain.clone(),
        mailbox_id,
        provider: provider_kind,
        provider_domain_id: prov_res.provider_domain_id,
        status: prov_res.status,
        dns_records: prov_res.dns_records,
        dkim_verified: prov_res.dkim_verified,
        spf_verified: prov_res.spf_verified,
        dmarc_verified: prov_res.dmarc_verified,
        mx_verified: prov_res.mx_verified,
        catch_all_mailbox,
        last_error: prov_res.last_error,
    };

    let created = match state.store.create_domain(input).await {
        Ok(created) => created,
        Err(err) => {
            if let Err(cleanup_err) = provider
                .delete_domain(&domain, provider_domain_id.as_deref())
                .await
            {
                tracing::warn!(
                    domain = %domain,
                    provider = %provider_kind.as_str(),
                    cleanup_error = %cleanup_err,
                    store_error = %err,
                    "Compensating upstream domain delete failed after store insert error"
                );
            }
            return Err(err);
        }
    };
    state
        .record_audit(
            principal,
            channel,
            "domain_create",
            vec![created.domain.clone()],
            created.status.as_str(),
            Some(format!("provider={}", created.provider.as_str())),
        )
        .await;
    Ok(created)
}

/// List BYOD domains visible to the caller (all domains for `Admin`, or scoped to the
/// caller's mailbox for non-admin principals).
pub async fn execute_list_domains(
    state: &AppState,
    requested_mailbox_id: Option<&str>,
    principal: Option<&Principal>,
) -> AppResult<Vec<DomainRecord>> {
    let filter_mb = requested_mailbox_id
        .map(normalize_mailbox_id)
        .filter(|s| !s.is_empty());

    if is_global_admin_principal(principal) {
        return state.store.list_domains(filter_mb.as_deref()).await;
    }

    let target_mb = match filter_mb {
        Some(mb) => {
            authorize_mailbox_access(principal, &mb, "mailbox")?;
            mb
        }
        None => normalize_mailbox_id(state.mailbox_id()),
    };
    state.store.list_domains(Some(&target_mb)).await
}

/// Fetch a single BYOD domain by name with strict ownership enforcement.
pub async fn execute_get_domain(
    state: &AppState,
    raw_domain: &str,
    principal: Option<&Principal>,
) -> AppResult<DomainRecord> {
    let domain = normalize_and_validate_domain(raw_domain)?;
    let record = state
        .store
        .get_domain(&domain)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Domain '{domain}' not found")))?;
    authorize_domain_access(principal, &record)?;
    Ok(record)
}

/// Update mutable domain settings (`catch_all_mailbox`, and admin-only manual verification
/// flags for `provider == manual` domains).
pub async fn execute_patch_domain(
    state: &AppState,
    raw_domain: &str,
    req: PatchDomainRequest,
    principal: Option<&Principal>,
    channel: &str,
) -> AppResult<DomainRecord> {
    let domain = normalize_and_validate_domain(raw_domain)?;
    let existing = state
        .store
        .get_domain(&domain)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Domain '{domain}' not found")))?;
    authorize_domain_access(principal, &existing)?;

    let mut update = DomainUpdate::default();

    if let Some(catch_all_opt) = req.catch_all_mailbox {
        match catch_all_opt
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw) => {
                let validated = validate_catch_all_mailbox(raw)?;
                authorize_mailbox_access(principal, &validated, "catch_all_mailbox")?;
                update.catch_all_mailbox = Some(Some(validated));
            }
            None => {
                update.catch_all_mailbox = Some(None);
            }
        }
    }

    let has_manual_override = req.status.is_some()
        || req.dkim_verified.is_some()
        || req.spf_verified.is_some()
        || req.dmarc_verified.is_some()
        || req.mx_verified.is_some()
        || req.dns_records.is_some();

    if has_manual_override {
        if existing.provider != DomainProviderKind::Manual {
            return Err(AppError::validation(
                format!(
                    "Manual verification overrides are only permitted for 'manual' domains (domain '{}' uses '{}')",
                    existing.domain,
                    existing.provider.as_str()
                ),
                Some(format!(
                    "Use POST /v1/domains/{}/verify to check live verification status.",
                    existing.domain
                )),
            ));
        }
        if !is_global_admin_principal(principal) {
            return Err(AppError::Forbidden(
                "Global admin token is required to manually override domain verification status"
                    .to_string(),
            ));
        }
        let now = Utc::now();
        if let Some(status) = req.status {
            update.status = Some(status);
            update.verified_at = if status == DomainStatus::Verified {
                Some(existing.verified_at.or(Some(now)))
            } else {
                Some(None)
            };
        }
        if let Some(v) = req.dkim_verified {
            update.dkim_verified = Some(v);
        }
        if let Some(v) = req.spf_verified {
            update.spf_verified = Some(v);
        }
        if let Some(v) = req.dmarc_verified {
            update.dmarc_verified = Some(v);
        }
        if let Some(v) = req.mx_verified {
            update.mx_verified = Some(v);
        }
        if let Some(records) = req.dns_records {
            update.dns_records = Some(records);
        }
        update.last_checked_at = Some(Some(now));
    }

    let updated = state.store.update_domain(&domain, &update).await?;
    state
        .record_audit(
            principal,
            channel,
            "domain_update",
            vec![updated.domain.clone()],
            updated.status.as_str(),
            None,
        )
        .await;
    Ok(updated)
}

/// Re-check DNS verification status against the domain's configured provider and update
/// stored status, DNS records, timestamps, and error metadata.
pub async fn execute_verify_domain(
    state: &AppState,
    raw_domain: &str,
    principal: Option<&Principal>,
    channel: &str,
) -> AppResult<DomainRecord> {
    let domain = normalize_and_validate_domain(raw_domain)?;
    let existing = state
        .store
        .get_domain(&domain)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Domain '{domain}' not found")))?;
    authorize_domain_access(principal, &existing)?;

    let now = Utc::now();

    if existing.provider == DomainProviderKind::Manual {
        let update = DomainUpdate {
            last_checked_at: Some(Some(now)),
            ..Default::default()
        };
        let updated = state.store.update_domain(&domain, &update).await?;
        state
            .record_audit(
                principal,
                channel,
                "domain_verify",
                vec![updated.domain.clone()],
                updated.status.as_str(),
                Some("provider=manual".to_string()),
            )
            .await;
        return Ok(updated);
    }

    let provider = state.domain_providers.get(existing.provider)?;
    match provider
        .verify_domain(&existing.domain, existing.provider_domain_id.as_deref())
        .await
    {
        Ok(res) => {
            let verified_at = if res.status == DomainStatus::Verified {
                existing.verified_at.or(Some(now))
            } else {
                None
            };
            let update = DomainUpdate {
                provider_domain_id: res.provider_domain_id.map(Some),
                status: Some(res.status),
                dns_records: Some(res.dns_records),
                dkim_verified: Some(res.dkim_verified),
                spf_verified: Some(res.spf_verified),
                dmarc_verified: Some(res.dmarc_verified),
                mx_verified: Some(res.mx_verified),
                catch_all_mailbox: None,
                verified_at: Some(verified_at),
                last_checked_at: Some(Some(now)),
                last_error: Some(res.last_error),
            };
            let updated = state.store.update_domain(&domain, &update).await?;
            state
                .record_audit(
                    principal,
                    channel,
                    "domain_verify",
                    vec![updated.domain.clone()],
                    updated.status.as_str(),
                    Some(format!("provider={}", updated.provider.as_str())),
                )
                .await;
            Ok(updated)
        }
        Err(err) => {
            let err_msg = err.to_string();
            let _ = state
                .store
                .update_domain(
                    &domain,
                    &DomainUpdate {
                        last_checked_at: Some(Some(now)),
                        last_error: Some(Some(err_msg.clone())),
                        ..Default::default()
                    },
                )
                .await;
            state
                .record_audit(
                    principal,
                    channel,
                    "domain_verify",
                    vec![existing.domain.clone()],
                    "error",
                    Some(err_msg),
                )
                .await;
            Err(err)
        }
    }
}

/// Remove a custom BYOD domain from its upstream provider and delete it from `MailStore`.
pub async fn execute_delete_domain(
    state: &AppState,
    raw_domain: &str,
    principal: Option<&Principal>,
    channel: &str,
) -> AppResult<Value> {
    let domain = normalize_and_validate_domain(raw_domain)?;
    let existing = state
        .store
        .get_domain(&domain)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Domain '{domain}' not found")))?;
    authorize_domain_access(principal, &existing)?;

    let provider = state.domain_providers.get(existing.provider)?;
    provider
        .delete_domain(&existing.domain, existing.provider_domain_id.as_deref())
        .await?;

    state.store.delete_domain(&existing.domain).await?;
    state
        .record_audit(
            principal,
            channel,
            "domain_delete",
            vec![existing.domain.clone()],
            "deleted",
            Some(format!("provider={}", existing.provider.as_str())),
        )
        .await;

    Ok(json!({
        "deleted": true,
        "domain": existing.domain,
    }))
}
