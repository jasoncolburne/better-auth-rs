use super::super::crypto::Secp256r1;
use crate::interfaces::{VerificationKey, VerificationKeyStore as VerificationKeyStoreTrait};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct VerificationKeyStore {
    keys_by_identity: Arc<Mutex<HashMap<String, Secp256r1>>>,
}

impl Default for VerificationKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationKeyStore {
    pub fn new() -> Self {
        Self {
            keys_by_identity: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn add(&self, identity: String, key: Secp256r1) -> Result<(), String> {
        let mut keys = self.keys_by_identity.lock().await;
        keys.insert(identity, key);
        Ok(())
    }
}

#[async_trait]
impl VerificationKeyStoreTrait for VerificationKeyStore {
    async fn get(&self, identity: &str) -> Result<Box<dyn VerificationKey>, String> {
        let keys = self.keys_by_identity.lock().await;

        keys.get(identity)
            .map(|k| Box::new(k.clone()) as Box<dyn VerificationKey>)
            .ok_or_else(|| "not found".to_string())
    }
}
