use async_trait::async_trait;

#[async_trait]
pub trait Hasher: Send + Sync {
    async fn sum(&self, message: &str) -> Result<String, String>;
}

#[async_trait]
pub trait Noncer: Send + Sync {
    /// Generate 128 bits of entropy
    async fn generate_128(&self) -> Result<String, String>;
}

#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify a message signature with a public key
    /// Returns an error when verification fails
    async fn verify(&self, message: &str, signature: &str, public_key: &str) -> Result<(), String>;
}

#[async_trait]
pub trait VerificationKey: Send + Sync {
    /// Fetch the public key
    async fn public(&self) -> Result<String, String>;

    /// Returns the algorithm verifier
    fn verifier(&self) -> &dyn Verifier;

    /// Verify using the verifier and public key (convenience method)
    /// Returns an error when verification fails
    async fn verify(&self, message: &str, signature: &str) -> Result<(), String> {
        let public_key = self.public().await?;
        self.verifier()
            .verify(message, signature, &public_key)
            .await
    }
}

#[async_trait]
pub trait SigningKey: VerificationKey {
    /// Fetch the identifier of the signing entity
    async fn identity(&self) -> Result<String, String>;

    /// Sign a message with the key
    async fn sign(&self, message: &str) -> Result<String, String>;
}
