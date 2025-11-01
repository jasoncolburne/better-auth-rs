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

// Exception raised when signature verification fails
pub fn signature_verification_error(
    public_key: Option<&str>,
    signed_data: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA201", "Signature verification failed");
    if let Some(pk) = public_key {
        err = err.with_context("publicKey", pk);
    }
    if let Some(sd) = signed_data {
        err = err.with_context("signedData", sd);
    }
    err
}

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

// Exception raised when authentication challenge has expired
pub fn expired_nonce_error(
    nonce_timestamp: Option<&str>,
    current_time: Option<&str>,
    expiration_window: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA204", "Authentication challenge has expired");
    if let Some(nt) = nonce_timestamp {
        err = err.with_context("nonceTimestamp", nt);
    }
    if let Some(ct) = current_time {
        err = err.with_context("currentTime", ct);
    }
    if let Some(ew) = expiration_window {
        err = err.with_context("expirationWindow", ew);
    }
    err
}

// Exception raised when nonce replay attack is detected
pub fn nonce_replay_error(
    nonce: Option<&str>,
    previous_usage_timestamp: Option<&str>,
) -> BetterAuthError {
    let truncate = |s: &str| {
        if s.len() > 16 {
            format!("{}...", &s[..16])
        } else {
            s.to_string()
        }
    };

    let mut err = BetterAuthError::new(
        "BA205",
        "Nonce has already been used (replay attack detected)",
    );
    if let Some(n) = nonce {
        err = err.with_context("nonce", truncate(n));
    }
    if let Some(put) = previous_usage_timestamp {
        err = err.with_context("previousUsageTimestamp", put);
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

// Exception raised for insufficient permissions
pub fn permission_denied_error(
    required_permissions: Option<Vec<String>>,
    actual_permissions: Option<Vec<String>>,
    operation: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA303", "Insufficient permissions for requested operation");
    if let Some(rp) = required_permissions {
        err = err.with_context("requiredPermissions", rp);
    }
    if let Some(ap) = actual_permissions {
        err = err.with_context("actualPermissions", ap);
    }
    if let Some(op) = operation {
        err = err.with_context("operation", op);
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

// Exception raised when token structure or format is invalid
pub fn invalid_token_error(details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA402", "Token structure or format is invalid");
    if let Some(d) = details {
        err = err.with_context("details", d);
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

// Exception raised when client/server clock difference exceeds tolerance
pub fn clock_skew_error(
    client_time: Option<&str>,
    server_time: Option<&str>,
    time_difference: Option<f64>,
    max_tolerance: Option<f64>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new(
        "BA503",
        "Client and server clock difference exceeds tolerance",
    );
    if let Some(ct) = client_time {
        err = err.with_context("clientTime", ct);
    }
    if let Some(st) = server_time {
        err = err.with_context("serverTime", st);
    }
    if let Some(td) = time_difference {
        err = err.with_context("timeDifference", td);
    }
    if let Some(mt) = max_tolerance {
        err = err.with_context("maxTolerance", mt);
    }
    err
}

// ============================================================================
// Storage Errors
// ============================================================================

// Exception raised when a resource is not found
pub fn not_found_error(
    resource_type: Option<&str>,
    resource_identifier: Option<&str>,
) -> BetterAuthError {
    let message = if let Some(rt) = resource_type {
        format!("Resource not found: {}", rt)
    } else {
        "Resource not found".to_string()
    };

    let mut err = BetterAuthError::new("BA601", message);
    if let Some(rt) = resource_type {
        err = err.with_context("resourceType", rt);
    }
    if let Some(ri) = resource_identifier {
        err = err.with_context("resourceIdentifier", ri);
    }
    err
}

// Exception raised when a resource already exists
pub fn already_exists_error(
    resource_type: Option<&str>,
    resource_identifier: Option<&str>,
) -> BetterAuthError {
    let message = if let Some(rt) = resource_type {
        format!("Resource already exists: {}", rt)
    } else {
        "Resource already exists".to_string()
    };

    let mut err = BetterAuthError::new("BA602", message);
    if let Some(rt) = resource_type {
        err = err.with_context("resourceType", rt);
    }
    if let Some(ri) = resource_identifier {
        err = err.with_context("resourceIdentifier", ri);
    }
    err
}

// Exception raised when storage backend is unavailable
pub fn storage_unavailable_error(
    backend_type: Option<&str>,
    connection_details: Option<&str>,
    backend_error: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA603", "Storage backend is unavailable");
    if let Some(bt) = backend_type {
        err = err.with_context("backendType", bt);
    }
    if let Some(cd) = connection_details {
        err = err.with_context("connectionDetails", cd);
    }
    if let Some(be) = backend_error {
        err = err.with_context("backendError", be);
    }
    err
}

// Exception raised when stored data is corrupted
pub fn storage_corruption_error(
    resource_type: Option<&str>,
    resource_identifier: Option<&str>,
    corruption_details: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA604", "Stored data is corrupted or invalid");
    if let Some(rt) = resource_type {
        err = err.with_context("resourceType", rt);
    }
    if let Some(ri) = resource_identifier {
        err = err.with_context("resourceIdentifier", ri);
    }
    if let Some(cd) = corruption_details {
        err = err.with_context("corruptionDetails", cd);
    }
    err
}

// ============================================================================
// Encoding Errors
// ============================================================================

// Exception raised when message serialization fails
pub fn serialization_error(
    message_type: Option<&str>,
    format: Option<&str>,
    details: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA701", "Failed to serialize message");
    if let Some(mt) = message_type {
        err = err.with_context("messageType", mt);
    }
    if let Some(f) = format {
        err = err.with_context("format", f);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when message deserialization fails
pub fn deserialization_error(
    message_type: Option<&str>,
    raw_data: Option<&str>,
    details: Option<&str>,
) -> BetterAuthError {
    let truncate_data = |s: &str| {
        if s.len() > 100 {
            format!("{}...", &s[..100])
        } else {
            s.to_string()
        }
    };

    let mut err = BetterAuthError::new("BA702", "Failed to deserialize message");
    if let Some(mt) = message_type {
        err = err.with_context("messageType", mt);
    }
    if let Some(rd) = raw_data {
        err = err.with_context("rawData", truncate_data(rd));
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when compression/decompression fails
pub fn compression_error(
    operation: Option<&str>,
    data_size: Option<usize>,
    details: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA703", "Failed to compress or decompress data");
    if let Some(op) = operation {
        err = err.with_context("operation", op);
    }
    if let Some(ds) = data_size {
        err = err.with_context("dataSize", ds);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// ============================================================================
// Network Errors (Client-Only)
// ============================================================================

// Exception raised when connection to server fails
pub fn connection_error(server_url: Option<&str>, details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA801", "Failed to connect to server");
    if let Some(su) = server_url {
        err = err.with_context("serverUrl", su);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when request times out
pub fn timeout_error(timeout_duration: Option<u64>, endpoint: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA802", "Request timed out");
    if let Some(td) = timeout_duration {
        err = err.with_context("timeoutDuration", td);
    }
    if let Some(e) = endpoint {
        err = err.with_context("endpoint", e);
    }
    err
}

// Exception raised for HTTP protocol violations
pub fn protocol_error(http_status_code: Option<u16>, details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA803", "Invalid HTTP response or protocol violation");
    if let Some(hsc) = http_status_code {
        err = err.with_context("httpStatusCode", hsc);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// ============================================================================
// Protocol Errors
// ============================================================================

// Exception raised when operation not allowed in current state
pub fn invalid_state_error(
    current_state: Option<&str>,
    attempted_operation: Option<&str>,
    required_state: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA901", "Operation not allowed in current state");
    if let Some(cs) = current_state {
        err = err.with_context("currentState", cs);
    }
    if let Some(ao) = attempted_operation {
        err = err.with_context("attemptedOperation", ao);
    }
    if let Some(rs) = required_state {
        err = err.with_context("requiredState", rs);
    }
    err
}

// Exception raised when key rotation fails
pub fn rotation_error(rotation_type: Option<&str>, details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA902", "Key rotation failed");
    if let Some(rt) = rotation_type {
        err = err.with_context("rotationType", rt);
    }
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when account recovery fails
pub fn recovery_error(details: Option<&str>) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA903", "Account recovery failed");
    if let Some(d) = details {
        err = err.with_context("details", d);
    }
    err
}

// Exception raised when device has been revoked
pub fn device_revoked_error(
    device_identifier: Option<&str>,
    revocation_timestamp: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA904", "Device has been revoked");
    if let Some(di) = device_identifier {
        err = err.with_context("deviceIdentifier", di);
    }
    if let Some(rt) = revocation_timestamp {
        err = err.with_context("revocationTimestamp", rt);
    }
    err
}

// Exception raised when identity has been deleted
pub fn identity_deleted_error(
    identity_identifier: Option<&str>,
    deletion_timestamp: Option<&str>,
) -> BetterAuthError {
    let mut err = BetterAuthError::new("BA905", "Identity has been deleted");
    if let Some(ii) = identity_identifier {
        err = err.with_context("identityIdentifier", ii);
    }
    if let Some(dt) = deletion_timestamp {
        err = err.with_context("deletionTimestamp", dt);
    }
    err
}

// ============================================================================
// Conversion from BetterAuthError to String for Result<T, String>
// ============================================================================

impl From<BetterAuthError> for String {
    fn from(err: BetterAuthError) -> String {
        err.message
    }
}
