//! Gmail `users.settings.*` handlers (`sendAs`, `vacation`, `autoForwarding`, `imap`, `pop`,
//! `filters`, `forwardingAddresses`, `delegates`, `language`).

use axum::{Json, extract::Path, http::StatusCode};
use uuid::Uuid;

use crate::{
    MailboxState,
    auth::{resolve_user_id, validate_email_header, validate_resource_id},
    error::{AppError, AppResult},
    models::{
        AutoForwarding, Delegate, FilterAction, FilterCriteria, ForwardingAddress, GmailFilter,
        ImapSettings, LanguageSettings, ListDelegatesResponse, ListFiltersResponse,
        ListForwardingAddressesResponse, ListSendAsResponse, PopSettings, SendAs, VacationSettings,
    },
    storage::parse_strict_single_mailbox,
};

fn validate_send_as_fields(send_as: &SendAs) -> AppResult<()> {
    if !send_as.send_as_email.is_empty() {
        validate_email_header("From", &send_as.send_as_email)?;
    }
    if let Some(ref name) = send_as.display_name {
        validate_email_header("Display-Name", name)?;
    }
    if let Some(ref reply_to) = send_as.reply_to_address {
        validate_email_header("Reply-To", reply_to)?;
    }
    Ok(())
}

fn redact_send_as(mut entry: SendAs) -> SendAs {
    if let Some(ref mut msa) = entry.smtp_msa {
        msa.password = None;
    }
    entry
}

fn merge_configured_alias_send_as(
    state: &crate::AppState,
    mut entries: Vec<SendAs>,
) -> Vec<SendAs> {
    for alias in state.config.aliases_for_mailbox(state.mailbox_id()) {
        if !entries
            .iter()
            .any(|s| s.send_as_email.eq_ignore_ascii_case(&alias))
        {
            entries.push(SendAs {
                send_as_email: alias,
                display_name: None,
                reply_to_address: None,
                signature: None,
                is_primary: Some(false),
                is_default: Some(false),
                treat_as_alias: Some(true),
                smtp_msa: None,
                verification_status: Some("accepted".to_string()),
            });
        }
    }
    entries
}

/// `GET /gmail/v1/users/{userId}/settings/sendAs`
pub async fn list_send_as(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListSendAsResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    let merged = merge_configured_alias_send_as(&state, settings.send_as);
    Ok(Json(ListSendAsResponse {
        send_as: merged.into_iter().map(redact_send_as).collect(),
    }))
}

/// `GET /gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}`
pub async fn get_send_as(
    MailboxState(state): MailboxState,
    Path((user_id, send_as_email)): Path<(String, String)>,
) -> AppResult<Json<SendAs>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&send_as_email)?;
    let settings = state.store.get_settings().await?;
    let merged = merge_configured_alias_send_as(&state, settings.send_as);
    let entry = merged
        .into_iter()
        .find(|s| s.send_as_email.eq_ignore_ascii_case(&send_as_email))
        .ok_or_else(|| AppError::NotFound(format!("SendAs alias '{send_as_email}' not found")))?;
    Ok(Json(redact_send_as(entry)))
}

/// `POST /gmail/v1/users/{userId}/settings/sendAs`
pub async fn create_send_as(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(mut payload): Json<SendAs>,
) -> AppResult<Json<SendAs>> {
    resolve_user_id(&user_id, &state.config)?;
    payload.send_as_email = payload.send_as_email.trim().to_string();
    if payload.send_as_email.is_empty() || !payload.send_as_email.contains('@') {
        return Err(AppError::BadRequest(
            "sendAsEmail must be a valid email address".to_string(),
        ));
    }
    validate_resource_id(&payload.send_as_email)?;
    validate_send_as_fields(&payload)?;

    let mut settings = state.store.get_settings().await?;
    if settings
        .send_as
        .iter()
        .any(|s| s.send_as_email.eq_ignore_ascii_case(&payload.send_as_email))
    {
        return Err(AppError::Conflict(format!(
            "SendAs alias '{}' already exists",
            payload.send_as_email
        )));
    }

    payload.is_primary = Some(false);
    if payload.is_default.is_none() {
        payload.is_default = Some(false);
    }
    if payload.treat_as_alias.is_none() {
        payload.treat_as_alias = Some(true);
    }
    payload.verification_status = Some("accepted".to_string());

    if payload.is_default == Some(true) {
        for existing in &mut settings.send_as {
            existing.is_default = Some(false);
        }
    }

    state.encrypt_send_as_password(&mut payload)?;
    settings.send_as.push(payload.clone());
    state.store.save_settings(settings).await?;
    Ok(Json(redact_send_as(payload)))
}

/// `PUT /gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}`
pub async fn update_send_as(
    MailboxState(state): MailboxState,
    Path((user_id, send_as_email)): Path<(String, String)>,
    Json(mut payload): Json<SendAs>,
) -> AppResult<Json<SendAs>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&send_as_email)?;
    validate_send_as_fields(&payload)?;
    state.encrypt_send_as_password(&mut payload)?;

    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .send_as
        .iter()
        .position(|s| s.send_as_email.eq_ignore_ascii_case(&send_as_email))
        .ok_or_else(|| AppError::NotFound(format!("SendAs alias '{send_as_email}' not found")))?;

    let make_default = payload.is_default == Some(true);
    if make_default {
        for existing in &mut settings.send_as {
            existing.is_default = Some(false);
        }
    }

    let entry = &mut settings.send_as[idx];
    entry.display_name = payload.display_name;
    entry.reply_to_address = payload.reply_to_address;
    entry.signature = payload.signature;
    entry.is_default = payload.is_default.or(entry.is_default);
    entry.treat_as_alias = payload.treat_as_alias;
    entry.smtp_msa = payload.smtp_msa;
    let updated = entry.clone();

    state.store.save_settings(settings).await?;
    Ok(Json(redact_send_as(updated)))
}

/// `PATCH /gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}`
pub async fn patch_send_as(
    MailboxState(state): MailboxState,
    Path((user_id, send_as_email)): Path<(String, String)>,
    Json(mut payload): Json<SendAs>,
) -> AppResult<Json<SendAs>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&send_as_email)?;
    validate_send_as_fields(&payload)?;
    state.encrypt_send_as_password(&mut payload)?;

    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .send_as
        .iter()
        .position(|s| s.send_as_email.eq_ignore_ascii_case(&send_as_email))
        .ok_or_else(|| AppError::NotFound(format!("SendAs alias '{send_as_email}' not found")))?;

    if payload.is_default == Some(true) {
        for existing in &mut settings.send_as {
            existing.is_default = Some(false);
        }
    }

    let entry = &mut settings.send_as[idx];
    if payload.display_name.is_some() {
        entry.display_name = payload.display_name;
    }
    if payload.reply_to_address.is_some() {
        entry.reply_to_address = payload.reply_to_address;
    }
    if payload.signature.is_some() {
        entry.signature = payload.signature;
    }
    if payload.is_default.is_some() {
        entry.is_default = payload.is_default;
    }
    if payload.treat_as_alias.is_some() {
        entry.treat_as_alias = payload.treat_as_alias;
    }
    if payload.smtp_msa.is_some() {
        entry.smtp_msa = payload.smtp_msa;
    }
    let updated = entry.clone();

    state.store.save_settings(settings).await?;
    Ok(Json(redact_send_as(updated)))
}

/// `DELETE /gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}`
pub async fn delete_send_as(
    MailboxState(state): MailboxState,
    Path((user_id, send_as_email)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&send_as_email)?;

    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .send_as
        .iter()
        .position(|s| s.send_as_email.eq_ignore_ascii_case(&send_as_email))
        .ok_or_else(|| AppError::NotFound(format!("SendAs alias '{send_as_email}' not found")))?;

    if settings.send_as[idx].is_primary == Some(true) {
        return Err(AppError::BadRequest(
            "Cannot delete primary sendAs address".to_string(),
        ));
    }

    settings.send_as.remove(idx);
    state.store.save_settings(settings).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}/verify`
pub async fn verify_send_as(
    MailboxState(state): MailboxState,
    Path((user_id, send_as_email)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&send_as_email)?;

    let mut settings = state.store.get_settings().await?;
    if let Some(entry) = settings
        .send_as
        .iter_mut()
        .find(|s| s.send_as_email.eq_ignore_ascii_case(&send_as_email))
    {
        entry.verification_status = Some("accepted".to_string());
        state.store.save_settings(settings).await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    if state
        .config
        .aliases_for_mailbox(state.mailbox_id())
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(&send_as_email))
    {
        return Ok(StatusCode::NO_CONTENT);
    }

    Err(AppError::NotFound(format!(
        "SendAs alias '{send_as_email}' not found"
    )))
}

/// `GET /gmail/v1/users/{userId}/settings/vacation`
pub async fn get_vacation(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<VacationSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(settings.vacation))
}

/// `PUT /gmail/v1/users/{userId}/settings/vacation`
pub async fn update_vacation(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<VacationSettings>,
) -> AppResult<Json<VacationSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    if let Some(ref subj) = payload.response_subject {
        validate_email_header("Subject", subj)?;
    }
    let mut settings = state.store.get_settings().await?;
    settings.vacation = payload.clone();
    state.store.save_settings(settings).await?;
    Ok(Json(payload))
}

/// `GET /gmail/v1/users/{userId}/settings/autoForwarding`
pub async fn get_auto_forwarding(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<AutoForwarding>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(settings.auto_forwarding))
}

/// `PUT /gmail/v1/users/{userId}/settings/autoForwarding`
pub async fn update_auto_forwarding(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<AutoForwarding>,
) -> AppResult<Json<AutoForwarding>> {
    resolve_user_id(&user_id, &state.config)?;
    if let Some(ref email) = payload.email_address {
        validate_email_header("Forward-To", email)?;
    }
    let mut settings = state.store.get_settings().await?;
    settings.auto_forwarding = payload.clone();
    state.store.save_settings(settings).await?;
    Ok(Json(payload))
}

/// `GET /gmail/v1/users/{userId}/settings/imap`
pub async fn get_imap(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ImapSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(settings.imap))
}

/// `PUT /gmail/v1/users/{userId}/settings/imap`
pub async fn update_imap(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<ImapSettings>,
) -> AppResult<Json<ImapSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let mut settings = state.store.get_settings().await?;
    settings.imap = payload.clone();
    state.store.save_settings(settings).await?;
    Ok(Json(payload))
}

/// `GET /gmail/v1/users/{userId}/settings/pop`
pub async fn get_pop(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<PopSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(settings.pop))
}

/// `PUT /gmail/v1/users/{userId}/settings/pop`
pub async fn update_pop(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<PopSettings>,
) -> AppResult<Json<PopSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let mut settings = state.store.get_settings().await?;
    settings.pop = payload.clone();
    state.store.save_settings(settings).await?;
    Ok(Json(payload))
}

// ============================================================================
// Filters (`users.settings.filters`)
// ============================================================================

fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b <= 0x1f || b == 0x7f) || s.chars().any(char::is_control)
}

fn validate_bare_email(field: &str, raw: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{field} must be a valid email address"
        )));
    }
    validate_email_header(field, trimmed)?;
    validate_resource_id(trimmed)?;
    let parsed = parse_strict_single_mailbox(trimmed).map_err(|_| {
        AppError::BadRequest(format!(
            "{field} must be a valid email address: '{trimmed}'"
        ))
    })?;
    if parsed.name.is_some() || trimmed.contains('<') || trimmed.contains('>') {
        return Err(AppError::BadRequest(format!(
            "{field} must be a bare email address without display name"
        )));
    }
    Ok(parsed.email)
}

fn validate_and_normalize_criteria(raw: Option<FilterCriteria>) -> AppResult<FilterCriteria> {
    let mut criteria = raw.ok_or_else(|| {
        AppError::BadRequest("Filter requires a non-empty 'criteria' object".to_string())
    })?;

    let clean_opt = |opt: Option<String>| -> Option<String> {
        opt.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    criteria.from = clean_opt(criteria.from);
    criteria.to = clean_opt(criteria.to);
    criteria.subject = clean_opt(criteria.subject);
    criteria.query = clean_opt(criteria.query);
    criteria.negated_query = clean_opt(criteria.negated_query);
    criteria.size_comparison = clean_opt(criteria.size_comparison);

    if let Some(ref from) = criteria.from {
        validate_email_header("From", from)?;
    }
    if let Some(ref to) = criteria.to {
        validate_email_header("To", to)?;
    }
    if let Some(ref subject) = criteria.subject {
        validate_email_header("Subject", subject)?;
    }
    if let Some(ref query) = criteria.query {
        if has_control_chars(query) {
            return Err(AppError::BadRequest(
                "Filter criteria.query contains disallowed control characters".to_string(),
            ));
        }
        crate::search::try_parse_query(query)?;
    }
    if let Some(ref neg) = criteria.negated_query {
        if has_control_chars(neg) {
            return Err(AppError::BadRequest(
                "Filter criteria.negatedQuery contains disallowed control characters".to_string(),
            ));
        }
        crate::search::try_parse_query(neg)?;
    }
    if let Some(size) = criteria.size
        && size < 0
    {
        return Err(AppError::BadRequest(
            "Filter criteria.size must be non-negative".to_string(),
        ));
    }
    if let Some(ref cmp) = criteria.size_comparison {
        let lower = cmp.to_ascii_lowercase();
        if !matches!(lower.as_str(), "unspecified" | "smaller" | "larger") {
            return Err(AppError::BadRequest(format!(
                "Invalid criteria.sizeComparison '{cmp}'; expected 'smaller', 'larger', or 'unspecified'"
            )));
        }
        criteria.size_comparison = Some(lower);
    }

    let has_any = criteria.from.is_some()
        || criteria.to.is_some()
        || criteria.subject.is_some()
        || criteria.query.is_some()
        || criteria.negated_query.is_some()
        || criteria.has_attachment == Some(true)
        || criteria.size.is_some();
    if !has_any {
        return Err(AppError::BadRequest(
            "Filter criteria must specify at least one matching condition".to_string(),
        ));
    }

    Ok(criteria)
}

fn validate_and_normalize_action(raw: Option<FilterAction>) -> AppResult<FilterAction> {
    let mut action = raw.ok_or_else(|| {
        AppError::BadRequest("Filter requires a non-empty 'action' object".to_string())
    })?;

    let clean_labels = |opt: Option<Vec<String>>| -> AppResult<Option<Vec<String>>> {
        let Some(list) = opt else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(list.len());
        for raw_id in list {
            let trimmed = raw_id.trim();
            if trimmed.is_empty() {
                continue;
            }
            validate_resource_id(trimmed)?;
            if !out.iter().any(|existing: &String| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        }
        Ok((!out.is_empty()).then_some(out))
    };

    action.add_label_ids = clean_labels(action.add_label_ids)?;
    action.remove_label_ids = clean_labels(action.remove_label_ids)?;
    action.forward = match action.forward {
        Some(ref addr) if !addr.trim().is_empty() => {
            Some(validate_bare_email("action.forward", addr)?)
        }
        _ => None,
    };

    if action.add_label_ids.is_none()
        && action.remove_label_ids.is_none()
        && action.forward.is_none()
    {
        return Err(AppError::BadRequest(
            "Filter action must specify addLabelIds, removeLabelIds, or forward".to_string(),
        ));
    }

    Ok(action)
}

/// `GET /gmail/v1/users/{userId}/settings/filters`
pub async fn list_filters(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListFiltersResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(ListFiltersResponse {
        filter: settings.filters,
    }))
}

/// `GET /gmail/v1/users/{userId}/settings/filters/{id}`
pub async fn get_filter(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<GmailFilter>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let settings = state.store.get_settings().await?;
    let entry = settings
        .filters
        .into_iter()
        .find(|f| f.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Filter '{id}' not found")))?;
    Ok(Json(entry))
}

/// `POST /gmail/v1/users/{userId}/settings/filters`
pub async fn create_filter(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<GmailFilter>,
) -> AppResult<Json<GmailFilter>> {
    resolve_user_id(&user_id, &state.config)?;
    let criteria = validate_and_normalize_criteria(payload.criteria)?;
    let action = validate_and_normalize_action(payload.action)?;

    let filter = GmailFilter {
        id: format!("flt_{}", &Uuid::new_v4().simple().to_string()[..16]),
        criteria: Some(criteria),
        action: Some(action),
    };

    let mut settings = state.store.get_settings().await?;
    settings.filters.push(filter.clone());
    state.store.save_settings(settings).await?;
    Ok(Json(filter))
}

/// `DELETE /gmail/v1/users/{userId}/settings/filters/{id}`
pub async fn delete_filter(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .filters
        .iter()
        .position(|f| f.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Filter '{id}' not found")))?;
    settings.filters.remove(idx);
    state.store.save_settings(settings).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Forwarding Addresses (`users.settings.forwardingAddresses`)
// ============================================================================

fn validate_forwarding_status(raw: Option<String>) -> AppResult<String> {
    let Some(status) = raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Ok("accepted".to_string());
    };
    match status.as_str() {
        "accepted" | "pending" | "verificationStatusUnspecified" => Ok(status),
        _ => Err(AppError::BadRequest(format!(
            "Invalid verificationStatus '{status}'; expected 'accepted', 'pending', or 'verificationStatusUnspecified'"
        ))),
    }
}

/// `GET /gmail/v1/users/{userId}/settings/forwardingAddresses`
pub async fn list_forwarding_addresses(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListForwardingAddressesResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(ListForwardingAddressesResponse {
        forwarding_addresses: settings.forwarding_addresses,
    }))
}

/// `GET /gmail/v1/users/{userId}/settings/forwardingAddresses/{forwardingEmail}`
pub async fn get_forwarding_address(
    MailboxState(state): MailboxState,
    Path((user_id, forwarding_email)): Path<(String, String)>,
) -> AppResult<Json<ForwardingAddress>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&forwarding_email)?;
    let settings = state.store.get_settings().await?;
    let entry = settings
        .forwarding_addresses
        .into_iter()
        .find(|a| a.forwarding_email.eq_ignore_ascii_case(&forwarding_email))
        .ok_or_else(|| {
            AppError::NotFound(format!("Forwarding address '{forwarding_email}' not found"))
        })?;
    Ok(Json(entry))
}

/// `POST /gmail/v1/users/{userId}/settings/forwardingAddresses`
pub async fn create_forwarding_address(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<ForwardingAddress>,
) -> AppResult<Json<ForwardingAddress>> {
    resolve_user_id(&user_id, &state.config)?;
    let forwarding_email = validate_bare_email("forwardingEmail", &payload.forwarding_email)?;
    let verification_status = validate_forwarding_status(payload.verification_status)?;

    let mut settings = state.store.get_settings().await?;
    if settings
        .forwarding_addresses
        .iter()
        .any(|a| a.forwarding_email.eq_ignore_ascii_case(&forwarding_email))
    {
        return Err(AppError::Conflict(format!(
            "Forwarding address '{forwarding_email}' already exists"
        )));
    }

    let created = ForwardingAddress {
        forwarding_email,
        verification_status: Some(verification_status),
    };
    settings.forwarding_addresses.push(created.clone());
    state.store.save_settings(settings).await?;
    Ok(Json(created))
}

/// `DELETE /gmail/v1/users/{userId}/settings/forwardingAddresses/{forwardingEmail}`
pub async fn delete_forwarding_address(
    MailboxState(state): MailboxState,
    Path((user_id, forwarding_email)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&forwarding_email)?;
    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .forwarding_addresses
        .iter()
        .position(|a| a.forwarding_email.eq_ignore_ascii_case(&forwarding_email))
        .ok_or_else(|| {
            AppError::NotFound(format!("Forwarding address '{forwarding_email}' not found"))
        })?;
    settings.forwarding_addresses.remove(idx);
    state.store.save_settings(settings).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Delegates (`users.settings.delegates`)
// ============================================================================

fn validate_delegate_status(raw: Option<String>) -> AppResult<String> {
    let Some(status) = raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Ok("accepted".to_string());
    };
    match status.as_str() {
        "accepted" | "pending" | "rejected" | "expired" | "verificationStatusUnspecified" => {
            Ok(status)
        }
        _ => Err(AppError::BadRequest(format!(
            "Invalid verificationStatus '{status}'; expected 'accepted', 'pending', 'rejected', 'expired', or 'verificationStatusUnspecified'"
        ))),
    }
}

/// `GET /gmail/v1/users/{userId}/settings/delegates`
pub async fn list_delegates(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListDelegatesResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(ListDelegatesResponse {
        delegates: settings.delegates,
    }))
}

/// `GET /gmail/v1/users/{userId}/settings/delegates/{delegateEmail}`
pub async fn get_delegate(
    MailboxState(state): MailboxState,
    Path((user_id, delegate_email)): Path<(String, String)>,
) -> AppResult<Json<Delegate>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&delegate_email)?;
    let settings = state.store.get_settings().await?;
    let entry = settings
        .delegates
        .into_iter()
        .find(|d| d.delegate_email.eq_ignore_ascii_case(&delegate_email))
        .ok_or_else(|| AppError::NotFound(format!("Delegate '{delegate_email}' not found")))?;
    Ok(Json(entry))
}

/// `POST /gmail/v1/users/{userId}/settings/delegates`
pub async fn create_delegate(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<Delegate>,
) -> AppResult<Json<Delegate>> {
    resolve_user_id(&user_id, &state.config)?;
    let delegate_email = validate_bare_email("delegateEmail", &payload.delegate_email)?;
    let verification_status = validate_delegate_status(payload.verification_status)?;

    let mut settings = state.store.get_settings().await?;
    if settings
        .delegates
        .iter()
        .any(|d| d.delegate_email.eq_ignore_ascii_case(&delegate_email))
    {
        return Err(AppError::Conflict(format!(
            "Delegate '{delegate_email}' already exists"
        )));
    }

    let created = Delegate {
        delegate_email,
        verification_status: Some(verification_status),
    };
    settings.delegates.push(created.clone());
    state.store.save_settings(settings).await?;
    Ok(Json(created))
}

/// `DELETE /gmail/v1/users/{userId}/settings/delegates/{delegateEmail}`
pub async fn delete_delegate(
    MailboxState(state): MailboxState,
    Path((user_id, delegate_email)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&delegate_email)?;
    let mut settings = state.store.get_settings().await?;
    let idx = settings
        .delegates
        .iter()
        .position(|d| d.delegate_email.eq_ignore_ascii_case(&delegate_email))
        .ok_or_else(|| AppError::NotFound(format!("Delegate '{delegate_email}' not found")))?;
    settings.delegates.remove(idx);
    state.store.save_settings(settings).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Language (`users.settings.language`)
// ============================================================================

/// `GET /gmail/v1/users/{userId}/settings/language`
pub async fn get_language(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<LanguageSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(settings.language))
}

/// `PUT /gmail/v1/users/{userId}/settings/language`
pub async fn update_language(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<LanguageSettings>,
) -> AppResult<Json<LanguageSettings>> {
    resolve_user_id(&user_id, &state.config)?;
    let lang = payload.display_language.trim().to_string();
    if lang.is_empty()
        || lang.len() > 35
        || lang.starts_with('-')
        || lang.ends_with('-')
        || lang.starts_with('_')
        || lang.ends_with('_')
        || !lang
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(format!(
            "Invalid displayLanguage '{lang}'; expected a BCP-47 language tag such as 'en' or 'en-US'"
        )));
    }

    let updated = LanguageSettings {
        display_language: lang,
    };
    let mut settings = state.store.get_settings().await?;
    settings.language = updated.clone();
    state.store.save_settings(settings).await?;
    Ok(Json(updated))
}
