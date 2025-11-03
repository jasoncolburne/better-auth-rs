//! Error types for better-auth.
//!
//! This module defines the standardized error hierarchy for Better Auth.
//! All error types follow the specification in ERRORS.md in the root repository.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// Context information for errors
pub type ErrorContext = HashMap<String, serde_json::Value>;

// Base error type for all better-auth errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetterAuthError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub context: ErrorContext,
}

impl BetterAuthError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: HashMap::new(),
        }
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.context.insert(key.into(), json_value);
        }
        self
    }
}

impl fmt::Display for BetterAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BetterAuthError {}

// Conversion from String errors (from trait implementations) to BetterAuthError
// This allows the ? operator to work seamlessly with trait methods that return Result<T, String>
impl From<String> for BetterAuthError {
    fn from(err: String) -> BetterAuthError {
        // Generic error for when we receive a string error from a trait implementation
        BetterAuthError::new("BA000", err)
    }
}

// ============================================================================
// Validation Errors
// ============================================================================

// Exception raised when a message is malformed or invalid
pub fn invalid_message_error(field: Option<&str>, details: Option<&str>) -> BetterAuthError {
    let message = if let Some(f) = field {
        format!("Message structure is invalid: {}", f)
    } else {
        "Message structure is invalid or malformed".to_string()
    };

    let message = if let (Some(f), Some(d)) = (field, details) {
        format!("Message structure is invalid: {} ({})", f, d)
    } else {
        message
    };

    let mut err = BetterAuthError::new("BA101", message);
    if let Some(f) = field {
        err = err.with_context("field", f);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when identity verification fails
pub fn invalid_identity_error(provided: Option<&str>, details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA102", "Identity verification failed");
    if let Some(p) = provided {
        err = err.with_context("provided", p);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when device hash validation fails
pub fn invalid_device_error(provided: Option<&str>, calculated: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new(
        "BA103",
        "Device hash does not match hash(publicKey || rotationHash)",
    );
    if let Some(p) = provided {
        err = err.with_context("provided", p);
    }
    if let Some(c) = calculated {
        err = err.with_context("calculated", c);
    }
    err
}

// Exception raised when hash validation fails
pub fn invalid_hash_error(
    expected: Option<&str>,
    actual: Option<&str>,
    hash_type: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA104", "Hash validation failed");
    if let Some(e) = expected {
        err = err.with_context("expected", e);
    }
    if let Some(a) = actual {
        err = err.with_context("actual", a);
    }
    if let Some(h) = hash_type {
        err = err.with_context("hashType", h);
    }
    err
}

// ============================================================================
// Cryptographic Errors
// ============================================================================

// Exception raised when response nonce doesn't match request nonce
pub fn incorrect_nonce_error(expected: Option<&str>, actual: Option<&str>) -> BetterAuthError {
    let truncate = |s: &str| {
        if s.len() > 16 {
            format!("{}...", &s[..16])
        } else {
            s.to_string()
        }
    };

    let mut err = BetterAuthError::new("BA203", "Response nonce does not match request nonce");
    if let Some(e) = expected {
        err = err.with_context("expected", truncate(e));
    }
    if let Some(a) = actual {
        err = err.with_context("actual", truncate(a));
    }
    err
}

// ============================================================================
// Authentication/Authorization Errors
// ============================================================================

// Exception raised when link container identity doesn't match request identity
pub fn mismatched_identities_error(
    link_container_identity: Option<&str>,
    request_identity: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new(
        "BA302",
        "Link container identity does not match request identity",
    );
    if let Some(lci) = link_container_identity {
        err = err.with_context("linkContainerIdentity", lci);
    }
    if let Some(ri) = request_identity {
        err = err.with_context("requestIdentity", ri);
    }
    err
}

// ============================================================================
// Token Errors
// ============================================================================

// Exception raised when a token has expired
pub fn expired_token_error(
    expiry_time: Option<&str>,
    current_time: Option<&str>,
    token_type: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA401", "Token has expired");
    if let Some(et) = expiry_time {
        err = err.with_context("expiryTime", et);
    }
    if let Some(ct) = current_time {
        err = err.with_context("currentTime", ct);
    }
    if let Some(tt) = token_type {
        err = err.with_context("tokenType", tt);
    }
    err
}

// Exception raised when token issued_at is in the future
pub fn future_token_error(
    issued_at: Option<&str>,
    current_time: Option<&str>,
    time_difference: Option<f64>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA403", "Token issued_at timestamp is in the future");
    if let Some(ia) = issued_at {
        err = err.with_context("issuedAt", ia);
    }
    if let Some(ct) = current_time {
        err = err.with_context("currentTime", ct);
    }
    if let Some(td) = time_difference {
        err = err.with_context("timeDifference", td);
    }
    err
}

// ============================================================================
// Temporal Errors
// ============================================================================

// Exception raised when request timestamp is too old
pub fn stale_request_error(
    request_timestamp: Option<&str>,
    current_time: Option<&str>,
    maximum_age: Option<u64>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA501", "Request timestamp is too old");
    if let Some(rt) = request_timestamp {
        err = err.with_context("requestTimestamp", rt);
    }
    if let Some(ct) = current_time {
        err = err.with_context("currentTime", ct);
    }
    if let Some(ma) = maximum_age {
        err = err.with_context("maximumAge", ma);
    }
    err
}

// Exception raised when request timestamp is in the future
pub fn future_request_error(
    request_timestamp: Option<&str>,
    current_time: Option<&str>,
    time_difference: Option<f64>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA502", "Request timestamp is in the future");
    if let Some(rt) = request_timestamp {
        err = err.with_context("requestTimestamp", rt);
    }
    if let Some(ct) = current_time {
        err = err.with_context("currentTime", ct);
    }
    if let Some(td) = time_difference {
        err = err.with_context("timeDifference", td);
    }
    err
}
