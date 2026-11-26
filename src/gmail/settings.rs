//! Gmail `users.settings.*` handlers (`sendAs`, `vacation`, `autoForwarding`, `imap`, `pop`).

use axum::{Json, extract::Path, http::StatusCode};

use crate::{
    MailboxState,
    auth::{resolve_user_id, validate_email_header, validate_resource_id},
    error::{AppError, AppResult},
    models::{
        AutoForwarding, ImapSettings, ListSendAsResponse, PopSettings, SendAs, VacationSettings,
    },
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

/// `GET /gmail/v1/users/{userId}/settings/sendAs`
pub async fn list_send_as(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListSendAsResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let settings = state.store.get_settings().await?;
    Ok(Json(ListSendAsResponse {
        send_as: settings.send_as.into_iter().map(redact_send_as).collect(),
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
    let entry = settings
        .send_as
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
