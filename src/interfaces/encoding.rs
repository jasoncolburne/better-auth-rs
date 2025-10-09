use async_trait::async_trait;
use std::time::SystemTime;

pub trait Timestamper: Send + Sync {
    fn format(&self, when: SystemTime) -> String;
    fn parse(&self, when: &str) -> Result<SystemTime, String>;
    fn now(&self) -> SystemTime;
    fn add_minutes(&self, time: SystemTime, minutes: u32) -> SystemTime;
    fn add_hours(&self, time: SystemTime, hours: u32) -> SystemTime;
    fn add_seconds(&self, time: SystemTime, seconds: u64) -> SystemTime;
    fn compare(&self, a: SystemTime, b: SystemTime) -> std::cmp::Ordering;
}

#[async_trait]
pub trait TokenEncoder: Send + Sync {
    async fn encode(&self, object: &str) -> Result<String, String>;
    async fn decode(&self, raw_token: &str) -> Result<String, String>;
    async fn signature_length(&self, token: &str) -> Result<usize, String>;
}

#[async_trait]
pub trait IdentityVerifier: Send + Sync {
    async fn verify(
        &self,
        identity: &str,
        public_key: &str,
        rotation_hash: &str,
        extra_data: Option<&str>,
    ) -> Result<(), String>;
}
