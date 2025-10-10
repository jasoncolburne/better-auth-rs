use super::super::crypto::{Hasher as HasherImpl, Secp256r1};
use crate::interfaces::{
    ClientRotatingKeyStore as ClientRotatingKeyStoreTrait,
    ClientValueStore as ClientValueStoreTrait, Hasher, SigningKey, VerificationKey,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ClientRotatingKeyStore {
    current_key: Arc<Mutex<Option<Secp256r1>>>,
    next_key: Arc<Mutex<Option<Secp256r1>>>,
    future_key: Arc<Mutex<Option<Secp256r1>>>,
    hasher: HasherImpl,
}

impl Default for ClientRotatingKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRotatingKeyStore {
    pub fn new() -> Self {
        Self {
            current_key: Arc::new(Mutex::new(None)),
            next_key: Arc::new(Mutex::new(None)),
            future_key: Arc::new(Mutex::new(None)),
            hasher: HasherImpl::new(),
        }
    }
}

#[async_trait]
impl ClientRotatingKeyStoreTrait for ClientRotatingKeyStore {
    async fn initialize(
        &self,
        extra_data: Option<String>,
    ) -> Result<(String, String, String), String> {
        let mut current = Secp256r1::new();
        let mut next = Secp256r1::new();

        current.generate()?;
        next.generate()?;

        let suffix = extra_data.unwrap_or_default();

        let public_key = current.public().await?;
        let next_public = next.public().await?;
        let rotation_hash = self.hasher.sum(&next_public).await?;
        let identity = self
            .hasher
            .sum(&format!("{}{}{}", public_key, rotation_hash, suffix))
            .await?;

        *self.current_key.lock().await = Some(current);
        *self.next_key.lock().await = Some(next);

        Ok((identity, public_key, rotation_hash))
    }

    async fn next(&self) -> Result<(Box<dyn SigningKey>, String), String> {
        let next_guard = self.next_key.lock().await;
        next_guard.as_ref().ok_or("call initialize() first")?;

        let mut future_guard = self.future_key.lock().await;
        if future_guard.is_none() {
            let mut key = Secp256r1::new();
            key.generate()?;
            *future_guard = Some(key);
        }

        let future_key = future_guard.as_ref().unwrap();
        let rotation_hash = self.hasher.sum(&future_key.public().await?).await?;

        Ok((
            Box::new(next_guard.as_ref().unwrap().clone()),
            rotation_hash,
        ))
    }

    async fn rotate(&self) -> Result<(), String> {
        let mut next_guard = self.next_key.lock().await;
        next_guard.as_ref().ok_or("call initialize() first")?;

        let mut future_guard = self.future_key.lock().await;
        future_guard.as_ref().ok_or("call next() first")?;

        *self.current_key.lock().await = next_guard.take();
        *next_guard = future_guard.take();

        Ok(())
    }

    async fn signer(&self) -> Result<Box<dyn SigningKey>, String> {
        let current_guard = self.current_key.lock().await;
        let current = current_guard.as_ref().ok_or("call initialize() first")?;

        // Clone the key to return as a boxed trait object
        Ok(Box::new(current.clone()))
    }
}

#[derive(Clone)]
pub struct ClientValueStore {
    value: Arc<Mutex<Option<String>>>,
}

impl Default for ClientValueStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientValueStore {
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl ClientValueStoreTrait for ClientValueStore {
    async fn store(&self, value: String) -> Result<(), String> {
        *self.value.lock().await = Some(value);
        Ok(())
    }

    async fn get(&self) -> Result<String, String> {
        self.value
            .lock()
            .await
            .clone()
            .ok_or_else(|| "nothing to get".to_string())
    }
}
