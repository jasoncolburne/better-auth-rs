use crate::error::BetterAuthError;
use crate::invalid_message_error;
use crate::messages::{ClientRequest, Serializable, ServerResponse};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Request Session

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionAccess {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionRequestAuthentication {
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionRequestInner {
    pub authentication: RequestSessionRequestAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionPayload {
    pub access: RequestSessionAccess,
    pub request: RequestSessionRequestInner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionRequest {
    pub payload: RequestSessionPayload,
}

impl RequestSessionRequest {
    pub fn new(identity: String, nonce: String) -> Self {
        Self {
            payload: RequestSessionPayload {
                access: RequestSessionAccess { nonce },
                request: RequestSessionRequestInner {
                    authentication: RequestSessionRequestAuthentication { identity },
                },
            },
        }
    }

    pub fn parse(message: &str) -> Result<Self, BetterAuthError> {
        serde_json::from_str(message)
            .map_err(|e| invalid_message_error(Some("message"), Some(&e.to_string())))
    }
}

#[async_trait]
impl Serializable for RequestSessionRequest {
    async fn to_json(&self) -> Result<String, BetterAuthError> {
        serde_json::to_string(self)
            .map_err(|e| invalid_message_error(Some("serialization"), Some(&e.to_string())))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionResponseAuthentication {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSessionResponseData {
    pub authentication: RequestSessionResponseAuthentication,
}

pub type RequestSessionResponse = ServerResponse<RequestSessionResponseData>;

// Create Session

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionAccess {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionAuthentication {
    pub device: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequestData {
    pub access: CreateSessionAccess,
    pub authentication: CreateSessionAuthentication,
}

pub type CreateSessionRequest = ClientRequest<CreateSessionRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponseAccess {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponseData {
    pub access: CreateSessionResponseAccess,
}

pub type CreateSessionResponse = ServerResponse<CreateSessionResponseData>;

// Refresh Session

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSessionAccess {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSessionRequestData {
    pub access: RefreshSessionAccess,
}

pub type RefreshSessionRequest = ClientRequest<RefreshSessionRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSessionResponseAccess {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSessionResponseData {
    pub access: RefreshSessionResponseAccess,
}

pub type RefreshSessionResponse = ServerResponse<RefreshSessionResponseData>;
