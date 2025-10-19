use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPaths {
    pub account: AccountPaths,
    pub session: SessionPaths,
    pub device: DevicePaths,
    pub recovery: RecoveryPaths,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountPaths {
    pub create: String,
    pub delete: String,
    pub recover: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPaths {
    pub request: String,
    pub create: String,
    pub refresh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePaths {
    pub rotate: String,
    pub link: String,
    pub unlink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPaths {
    pub change: String,
}
