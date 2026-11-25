use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

/// Standard Gmail REST API v1 error item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailErrorItem {
    pub message: String,
    pub domain: String,
    pub reason: String,
}

/// Standard Gmail REST API v1 error body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailErrorBody {
    pub code: u16,
    pub message: String,
    pub errors: Vec<GmailErrorItem>,
    pub status: String,
}

/// Standard Gmail REST API v1 error envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailErrorEnvelope {
    pub error: GmailErrorBody,
}

/// Structured AI-first `/v1` error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Structured AI-first `/v1` error envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiErrorEnvelope {
    pub error: AiErrorBody,
}

/// Unified application error type across HTTP, MCP, IMAP, sync, and CLI.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),

    #[error("{message}")]
    Validation {
        message: String,
        hint: Option<String>,
    },

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("Outbound send blocked: server is in draft_only mode")]
    DraftOnlyBlocked { hint: String },

    #[error("One or more recipients are not permitted by allowed_recipients policy")]
    RecipientNotAllowed { disallowed: Vec<String> },

    #[error("{message}")]
    PolicyDenied {
        code: String,
        message: String,
        hint: Option<String>,
        details: Option<Value>,
    },

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    PayloadTooLarge(String),

    #[error("{0}")]
    RateLimited(String),

    #[error("Upstream error (HTTP {status}): {message}")]
    Upstream { status: u16, message: String },

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("MIME error: {0}")]
    Mime(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn validation(message: impl Into<String>, hint: Option<String>) -> Self {
        Self::Validation {
            message: message.into(),
            hint,
        }
    }

    pub fn draft_only_blocked() -> Self {
        Self::DraftOnlyBlocked {
            hint: "Server is in draft_only mode. Call create_draft instead, or pass dry_run: true to preview."
                .to_string(),
        }
    }

    /// HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Validation { .. } | Self::Mime(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_)
            | Self::DraftOnlyBlocked { .. }
            | Self::RecipientNotAllowed { .. }
            | Self::PolicyDenied { .. } => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Upstream { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            Self::Storage(_) | Self::Config(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Gmail API `status` and `reason` strings matching Google REST conventions.
    pub fn gmail_status_and_reason(&self) -> (&'static str, &'static str) {
        match self {
            Self::BadRequest(_)
            | Self::Validation { .. }
            | Self::Mime(_)
            | Self::PayloadTooLarge(_) => ("INVALID_ARGUMENT", "badRequest"),
            Self::Unauthorized(_) => ("UNAUTHENTICATED", "authError"),
            Self::Forbidden(_)
            | Self::DraftOnlyBlocked { .. }
            | Self::RecipientNotAllowed { .. }
            | Self::PolicyDenied { .. } => ("PERMISSION_DENIED", "forbidden"),
            Self::NotFound(_) => ("NOT_FOUND", "notFound"),
            Self::Conflict(_) => ("ALREADY_EXISTS", "conflict"),
            Self::RateLimited(_) => ("RESOURCE_EXHAUSTED", "rateLimitExceeded"),
            Self::Upstream { .. }
            | Self::Storage(_)
            | Self::Config(_)
            | Self::Internal(_) => ("INTERNAL", "backendError"),
        }
    }

    /// Machine-readable AI `/v1` & MCP error code.
    pub fn ai_code(&self) -> &str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Validation { .. } => "validation_error",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::DraftOnlyBlocked { .. } => "draft_only_mode",
            Self::RecipientNotAllowed { .. } => "recipient_not_allowed",
            Self::PolicyDenied { code, .. } => code.as_str(),
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::PayloadTooLarge(_) => "payload_too_large",
            Self::RateLimited(_) => "rate_limited",
            Self::Upstream { .. } => "upstream_error",
            Self::Storage(_) => "storage_error",
            Self::Mime(_) => "mime_error",
            Self::Config(_) => "config_error",
            Self::Internal(_) => "internal_error",
        }
    }

    /// Deterministic CLI exit code:
    /// - `2`: validation / input hardening / config error
    /// - `3`: safety policy block (`draft_only`, `allowed_recipients`, forbidden)
    /// - `4`: auth / upstream / rate-limit error
    /// - `1`: general runtime / not found / storage error
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::BadRequest(_)
            | Self::Validation { .. }
            | Self::Mime(_)
            | Self::PayloadTooLarge(_)
            | Self::Config(_) => 2,
            Self::Forbidden(_)
            | Self::DraftOnlyBlocked { .. }
            | Self::RecipientNotAllowed { .. }
            | Self::PolicyDenied { .. } => 3,
            Self::Unauthorized(_) | Self::RateLimited(_) | Self::Upstream { .. } => 4,
            Self::NotFound(_) | Self::Conflict(_) | Self::Storage(_) | Self::Internal(_) => 1,
        }
    }

    /// Build the exact Gmail REST API v1 error JSON envelope.
    pub fn to_gmail_envelope(&self) -> GmailErrorEnvelope {
        let code = self.status_code().as_u16();
        let (status, reason) = self.gmail_status_and_reason();
        let message = self.to_string();
        GmailErrorEnvelope {
            error: GmailErrorBody {
                code,
                message: message.clone(),
                errors: vec![GmailErrorItem {
                    message,
                    domain: "global".to_string(),
                    reason: reason.to_string(),
                }],
                status: status.to_string(),
            },
        }
    }

    /// Build the AI-first `/v1` error JSON envelope.
    pub fn to_ai_envelope(&self) -> AiErrorEnvelope {
        let (hint, details) = match self {
            Self::Validation { hint, .. } => (hint.clone(), None),
            Self::DraftOnlyBlocked { hint } => (Some(hint.clone()), None),
            Self::RecipientNotAllowed { disallowed } => (
                Some("Adjust recipients to match allowed_recipients policy or run with dry_run: true.".to_string()),
                Some(json!({ "disallowed": disallowed })),
            ),
            Self::PolicyDenied { hint, details, .. } => (hint.clone(), details.clone()),
            Self::Upstream { status, .. } => (None, Some(json!({ "upstream_status": status }))),
            _ => (None, None),
        };
        AiErrorEnvelope {
            error: AiErrorBody {
                code: self.ai_code().to_string(),
                message: self.to_string(),
                hint,
                details,
            },
        }
    }

    /// Convert into an Axum response using the AI `/v1` JSON error format.
    pub fn into_ai_response(self) -> Response {
        let status = self.status_code();
        (status, Json(self.to_ai_envelope())).into_response()
    }
}

/// Default `IntoResponse` produces the exact Gmail REST API v1 JSON error envelope.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        (status, Json(self.to_gmail_envelope())).into_response()
    }
}

/// Wrapper for AI `/v1` route handlers so `?` automatically returns the AI error envelope.
pub struct AiError(pub AppError);

impl From<AppError> for AiError {
    fn from(err: AppError) -> Self {
        Self(err)
    }
}

impl IntoResponse for AiError {
    fn into_response(self) -> Response {
        self.0.into_ai_response()
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::BadRequest(format!("Invalid JSON payload: {err}"))
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        let status = err.status().map(|s| s.as_u16()).unwrap_or(502);
        Self::Upstream {
            status,
            message: err.to_string(),
        }
    }
}
