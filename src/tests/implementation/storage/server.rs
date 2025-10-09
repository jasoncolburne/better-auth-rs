use super::super::crypto::{Hasher as HasherImpl, Noncer};
use crate::interfaces::{
    Hasher, Noncer as NoncerTrait,
    ServerAuthenticationKeyStore as ServerAuthenticationKeyStoreTrait,
    ServerAuthenticationNonceStore as ServerAuthenticationNonceStoreTrait,
    ServerRecoveryHashStore as ServerRecoveryHashStoreTrait,
    ServerTimeLockStore as ServerTimeLockStoreTrait,
};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ServerAuthenticationKeyStore {
    data_by_token: Arc<Mutex<HashMap<String, (String, String)>>>,
    hasher: HasherImpl,
    identities: Arc<Mutex<HashSet<String>>>,
}

impl Default for ServerAuthenticationKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerAuthenticationKeyStore {
    pub fn new() -> Self {
        Self {
            data_by_token: Arc::new(Mutex::new(HashMap::new())),
            hasher: HasherImpl::new(),
            identities: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

#[async_trait]
impl ServerAuthenticationKeyStoreTrait for ServerAuthenticationKeyStore {
    async fn revoke_device(&self, identity: String, device: String) -> Result<(), String> {
        let identities = self.identities.lock().await;
        if !identities.contains(&identity) {
            return Err("not found".to_string());
        }

        let mut data = self.data_by_token.lock().await;
        data.remove(&format!("{}{}", identity, device));
        Ok(())
    }

    async fn revoke_devices(&self, identity: String) -> Result<(), String> {
        let identities = self.identities.lock().await;
        if !identities.contains(&identity) {
            return Err("not found".to_string());
        }

        let mut data = self.data_by_token.lock().await;
        data.retain(|key, _| !key.starts_with(&identity));
        Ok(())
    }

    async fn register(
        &self,
        identity: String,
        device: String,
        public_key: String,
        rotation_hash: String,
        existing_identity: bool,
    ) -> Result<(), String> {
        let mut identities = self.identities.lock().await;
        let has_identity = identities.contains(&identity);

        if !existing_identity && has_identity {
            return Err("identity already registered".to_string());
        }

        if existing_identity && !has_identity {
            return Err("identity not found".to_string());
        }

        let mut data = self.data_by_token.lock().await;
        let key = format!("{}{}", identity, device);

        if data.contains_key(&key) {
            return Err("already exists".to_string());
        }

        identities.insert(identity);
        data.insert(key, (public_key, rotation_hash));
        Ok(())
    }

    async fn rotate(
        &self,
        identity: String,
        device: String,
        public_key: String,
        rotation_hash: String,
    ) -> Result<(), String> {
        let mut data = self.data_by_token.lock().await;
        let key = format!("{}{}", identity, device);

        let bundle = data.get(&key).ok_or("not found")?;

        let cesr_hash = self.hasher.sum(&public_key).await?;

        if bundle.1 != cesr_hash {
            return Err("invalid forward secret".to_string());
        }

        data.insert(key, (public_key, rotation_hash));
        Ok(())
    }

    async fn public(&self, identity: String, device: String) -> Result<String, String> {
        let data = self.data_by_token.lock().await;
        let key = format!("{}{}", identity, device);

        data.get(&key)
            .map(|(public_key, _)| public_key.clone())
            .ok_or_else(|| "not found".to_string())
    }
}

#[derive(Clone)]
pub struct ServerRecoveryHashStore {
    data_by_identity: Arc<Mutex<HashMap<String, String>>>,
}

impl Default for ServerRecoveryHashStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerRecoveryHashStore {
    pub fn new() -> Self {
        Self {
            data_by_identity: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ServerRecoveryHashStoreTrait for ServerRecoveryHashStore {
    async fn register(&self, identity: String, hash: String) -> Result<(), String> {
        let mut data = self.data_by_identity.lock().await;

        if data.contains_key(&identity) {
            return Err("already exists".to_string());
        }

        data.insert(identity, hash);
        Ok(())
    }

    async fn rotate(
        &self,
        identity: String,
        old_hash: String,
        new_hash: String,
    ) -> Result<(), String> {
        let mut data = self.data_by_identity.lock().await;

        let stored = data.get(&identity).ok_or("not found")?;

        if stored != &old_hash {
            return Err("incorrect hash".to_string());
        }

        data.insert(identity, new_hash);
        Ok(())
    }
}

#[derive(Clone)]
pub struct ServerAuthenticationNonceStore {
    data_by_nonce: Arc<Mutex<HashMap<String, String>>>,
    nonce_expirations: Arc<Mutex<HashMap<String, SystemTime>>>,
    noncer: Noncer,
    lifetime_in_seconds: u64,
}

impl ServerAuthenticationNonceStore {
    pub fn new(lifetime_in_seconds: u64) -> Self {
        Self {
            data_by_nonce: Arc::new(Mutex::new(HashMap::new())),
            nonce_expirations: Arc::new(Mutex::new(HashMap::new())),
            noncer: Noncer::new(),
            lifetime_in_seconds,
        }
    }
}

#[async_trait]
impl ServerAuthenticationNonceStoreTrait for ServerAuthenticationNonceStore {
    fn lifetime_in_seconds(&self) -> u64 {
        self.lifetime_in_seconds
    }

    async fn generate(&self, identity: String) -> Result<String, String> {
        use std::time::Duration;

        let expiration = SystemTime::now() + Duration::from_secs(self.lifetime_in_seconds);

        let nonce = self.noncer.generate_128().await?;

        let mut data = self.data_by_nonce.lock().await;
        let mut expirations = self.nonce_expirations.lock().await;

        data.insert(nonce.clone(), identity);
        expirations.insert(nonce.clone(), expiration);

        Ok(nonce)
    }

    async fn validate(&self, nonce: String) -> Result<String, String> {
        let data = self.data_by_nonce.lock().await;
        let expirations = self.nonce_expirations.lock().await;

        let identity = data.get(&nonce).ok_or("not found")?;
        let expiration = expirations.get(&nonce).ok_or("not found")?;

        let now = SystemTime::now();

        if now > *expiration {
            return Err("expired nonce".to_string());
        }

        Ok(identity.clone())
    }
}

#[derive(Clone)]
pub struct ServerTimeLockStore {
    nonces: Arc<Mutex<HashMap<String, SystemTime>>>,
    lifetime_in_seconds: u64,
}

impl ServerTimeLockStore {
    pub fn new(lifetime_in_seconds: u64) -> Self {
        Self {
            nonces: Arc::new(Mutex::new(HashMap::new())),
            lifetime_in_seconds,
        }
    }
}

#[async_trait]
impl ServerTimeLockStoreTrait for ServerTimeLockStore {
    fn lifetime_in_seconds(&self) -> u64 {
        self.lifetime_in_seconds
    }

    async fn reserve(&self, value: String) -> Result<(), String> {
        use std::time::Duration;

        let mut nonces = self.nonces.lock().await;

        if let Some(valid_at) = nonces.get(&value) {
            let now = SystemTime::now();
            if now < *valid_at {
                return Err("value reserved too recently".to_string());
            }
        }

        let new_valid_at = SystemTime::now() + Duration::from_secs(self.lifetime_in_seconds);
        nonces.insert(value, new_valid_at);

        Ok(())
    }
}
