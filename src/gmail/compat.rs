//! Google OAuth2 `userinfo` and People API compatibility endpoints probed by
//! Superhuman, `google-api-python-client`, and standard OAuth2 clients:
//! - `GET /oauth2/v2/userinfo`
//! - `GET /oauth2/v3/userinfo`
//! - `GET /v1/people/me`

use std::collections::HashSet;

use axum::{Extension, Json, extract::RawQuery};
use serde_json::{Map, Value, json};

use crate::{
    MailboxState, auth::Principal, error::AppResult, gmail::query::QueryParams, models::SendAs,
};

fn resolve_mailbox_email(state: &crate::AppState, principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.mailbox_id.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(state.config.user_email.as_str())
        .to_string()
}

fn resolve_primary_display_name(send_as: &[SendAs], email: &str) -> String {
    let primary = send_as
        .iter()
        .find(|s| s.is_primary == Some(true))
        .or_else(|| {
            send_as
                .iter()
                .find(|s| s.send_as_email.eq_ignore_ascii_case(email))
        })
        .or_else(|| send_as.first());

    if let Some(name) = primary
        .and_then(|s| s.display_name.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }

    email
        .split('@')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(email)
        .to_string()
}

/// `GET /oauth2/v2/userinfo`
///
/// Authenticated via standard Bearer auth (`auth::require_auth`). Returns Google
/// OAuth2 v2 + OIDC userinfo fields (`id`, `sub`, `email`, `verified_email`,
/// `email_verified`, `name`) sourced from `Principal.mailbox_id` and the primary
/// `SendAs` display name.
pub async fn get_userinfo_v2(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
) -> AppResult<Json<Value>> {
    let email = resolve_mailbox_email(&state, principal.as_ref().map(|Extension(p)| p));
    let settings = state.store.get_settings().await?;
    let name = resolve_primary_display_name(&settings.send_as, &email);

    Ok(Json(json!({
        "id": email,
        "sub": email,
        "email": email,
        "verified_email": true,
        "email_verified": true,
        "name": name,
    })))
}

/// `GET /oauth2/v3/userinfo`
///
/// Authenticated via standard Bearer auth (`auth::require_auth`). Returns OIDC
/// userinfo claims (`sub`, `email`, `email_verified`, `name`) sourced from
/// `Principal.mailbox_id` and the primary `SendAs` display name.
pub async fn get_userinfo_v3(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
) -> AppResult<Json<Value>> {
    let email = resolve_mailbox_email(&state, principal.as_ref().map(|Extension(p)| p));
    let settings = state.store.get_settings().await?;
    let name = resolve_primary_display_name(&settings.send_as, &email);

    Ok(Json(json!({
        "sub": email,
        "email": email,
        "email_verified": true,
        "name": name,
    })))
}

/// `GET /v1/people/me` (`?personFields=names,emailAddresses`)
///
/// Minimal Google People API v1 compatibility stub returning `resourceName: "people/me"`,
/// `names`, and `emailAddresses` filtered by `personFields` when specified.
pub async fn get_people_me(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<Value>> {
    let email = resolve_mailbox_email(&state, principal.as_ref().map(|Extension(p)| p));
    let settings = state.store.get_settings().await?;
    let display_name = resolve_primary_display_name(&settings.send_as, &email);

    let query = QueryParams::from_raw(raw_query.as_deref());
    let requested_fields: Option<HashSet<String>> = query
        .get("personFields")
        .or_else(|| query.get("requestMask.includeField"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|raw| {
            raw.split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .filter(|part| !part.is_empty())
                .collect()
        });

    let include_names = requested_fields
        .as_ref()
        .is_none_or(|fields| fields.contains("names") || fields.contains("person.names"));
    let include_emails = requested_fields.as_ref().is_none_or(|fields| {
        fields.contains("emailaddresses")
            || fields.contains("email_addresses")
            || fields.contains("person.email_addresses")
    });

    let mut body = Map::new();
    body.insert(
        "resourceName".to_string(),
        Value::String("people/me".to_string()),
    );

    if include_names {
        body.insert(
            "names".to_string(),
            json!([
                {
                    "metadata": {
                        "primary": true,
                        "source": {
                            "type": "PROFILE",
                            "id": email,
                        }
                    },
                    "displayName": display_name,
                    "unstructuredName": display_name,
                }
            ]),
        );
    }

    if include_emails {
        let mut seen = HashSet::new();
        let mut emails = Vec::new();

        seen.insert(email.to_ascii_lowercase());
        emails.push(json!({
            "metadata": {
                "primary": true,
                "verified": true,
                "source": {
                    "type": "ACCOUNT",
                    "id": email,
                }
            },
            "value": email,
        }));

        for alias in &settings.send_as {
            let addr = alias.send_as_email.trim();
            if addr.is_empty() {
                continue;
            }
            if seen.insert(addr.to_ascii_lowercase()) {
                emails.push(json!({
                    "metadata": {
                        "primary": false,
                        "verified": true,
                        "source": {
                            "type": "ACCOUNT",
                            "id": email,
                        }
                    },
                    "value": addr,
                }));
            }
        }

        for alias in state.config.aliases_for_mailbox(&email) {
            if seen.insert(alias.to_ascii_lowercase()) {
                emails.push(json!({
                    "metadata": {
                        "primary": false,
                        "verified": true,
                        "source": {
                            "type": "ACCOUNT",
                            "id": email,
                        }
                    },
                    "value": alias,
                }));
            }
        }

        body.insert("emailAddresses".to_string(), Value::Array(emails));
    }

    Ok(Json(Value::Object(body)))
}
