use super::crypto::{SigningKey, VerificationKey};
use async_trait::async_trait;

// Client storage

#[async_trait]
pub trait ClientValueStore: Send + Sync {
    async fn store(&self, value: String) -> Result<(), String>;

    /// Returns an error if nothing has been stored
    async fn get(&self) -> Result<String, String>;
}

#[async_trait]
pub trait ClientRotatingKeyStore: Send + Sync {
    /// Returns: (identity, publicKey, rotationHash)
    async fn initialize(
        &self,
        extra_data: Option<String>,
    ) -> Result<(String, String, String), String>;

    /// Returns: (publicKey, rotationHash)
    /// Returns an error if no keys exist
    async fn rotate(&self) -> Result<(String, String), String>;

    /// Returns a handle to a signing key
    async fn signer(&self) -> Result<Box<dyn SigningKey>, String>;
}

#[async_trait]
pub trait VerificationKeyStore: Send + Sync {
    async fn get(&self, identity: &str) -> Result<Box<dyn VerificationKey>, String>;
}

// Server storage

#[async_trait]
pub trait ServerAuthenticationNonceStore: Send + Sync {
    fn lifetime_in_seconds(&self) -> u64;

    /// Generate a nonce for an identity
    /// Consider implementing exponential backoff delay on generation per identity
    async fn generate(&self, identity: String) -> Result<String, String>;

    /// Validate a nonce and return the identity
    /// Returns an error if nonce is not in the store
    async fn validate(&self, nonce: String) -> Result<String, String>;
}

#[async_trait]
pub trait ServerAuthenticationKeyStore: Send + Sync {
    /// Register a new device key
    /// Returns errors for:
    /// - identity_exists is true and identity is not found
    /// - identity_exists is false and identity is found
    /// - identity and device combination already exists
    async fn register(
        &self,
        identity: String,
        device: String,
        public_key: String,
        rotation_hash: String,
        existing_identity: bool,
    ) -> Result<(), String>;

    /// Rotate a device key
    /// Returns errors for:
    /// - identity and device combination does not exist
    /// - previous next hash doesn't match current hash
    async fn rotate(
        &self,
        identity: String,
        device: String,
        public_key: String,
        rotation_hash: String,
    ) -> Result<(), String>;

    /// Get public key for identity and device
    async fn public(&self, identity: String, device: String) -> Result<String, String>;

    /// Revoke access for one device
    async fn revoke_device(&self, identity: String, device: String) -> Result<(), String>;

    /// Revoke access for all devices
    async fn revoke_devices(&self, identity: String) -> Result<(), String>;
}

#[async_trait]
pub trait ServerRecoveryHashStore: Send + Sync {
    async fn register(&self, identity: String, key_hash: String) -> Result<(), String>;

    /// Rotate recovery hash
    /// Returns errors if:
    /// - not found
    /// - hash does not match
    async fn rotate(
        &self,
        identity: String,
        old_hash: String,
        new_hash: String,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait ServerTimeLockStore: Send + Sync {
    fn lifetime_in_seconds(&self) -> u64;

    /// Reserve a value in the store
    /// Returns an error if value is still alive in the store
    async fn reserve(&self, value: String) -> Result<(), String>;
}
