use async_trait::async_trait;

#[async_trait]
pub trait Network: Send + Sync {
    /// Send a request to a path and return the network response
    async fn send_request(&self, path: &str, message: &str) -> Result<String, String>;
}
