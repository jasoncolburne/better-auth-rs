use super::super::crypto::Hasher as HasherImpl;
use crate::interfaces::{Hasher, IdentityVerifier as IdentityVerifierTrait};
use async_trait::async_trait;

pub struct IdentityVerifier {
    hasher: HasherImpl,
}

impl IdentityVerifier {
    pub fn new() -> Self {
        Self {
            hasher: HasherImpl::new(),
        }
    }
}

#[async_trait]
impl IdentityVerifierTrait for IdentityVerifier {
    async fn verify(
        &self,
        identity: &str,
        public_key: &str,
        rotation_hash: &str,
        extra_data: Option<&str>,
    ) -> Result<(), String> {
        let suffix = extra_data.unwrap_or("");
        let to_hash = format!("{}{}{}", public_key, rotation_hash, suffix);
        let identity_hash = self.hasher.sum(&to_hash).await?;

        if identity_hash != identity {
            return Err("could not verify identity".to_string());
        }

        Ok(())
    }
}
