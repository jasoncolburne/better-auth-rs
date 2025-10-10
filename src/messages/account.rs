use crate::messages::{ClientRequest, ServerResponse};
use serde::{Deserialize, Serialize};

// Create Account

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "recoveryHash")]
    pub recovery_hash: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequestData {
    pub authentication: CreateAccountAuthentication,
}

pub type CreateAccountRequest = ClientRequest<CreateAccountRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountResponseData {}

pub type CreateAccountResponse = ServerResponse<CreateAccountResponseData>;

// Recover Account

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverAccountAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "recoveryHash")]
    pub recovery_hash: String,
    #[serde(rename = "recoveryKey")]
    pub recovery_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverAccountRequestData {
    pub authentication: RecoverAccountAuthentication,
}

pub type RecoverAccountRequest = ClientRequest<RecoverAccountRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverAccountResponseData {}

pub type RecoverAccountResponse = ServerResponse<RecoverAccountResponseData>;

// Delete Account

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountRequestData {
    pub authentication: DeleteAccountAuthentication,
}

pub type DeleteAccountRequest = ClientRequest<DeleteAccountRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountResponseData {}

pub type DeleteAccountResponse = ServerResponse<DeleteAccountResponseData>;
