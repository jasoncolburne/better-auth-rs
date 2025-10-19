use async_trait::async_trait;
use better_auth::api::client::*;
use better_auth::interfaces::{
    AccountPaths, AuthenticationPaths as AuthPaths, DevicePaths, Hasher as HasherTrait,
    Network as NetworkTrait, RecoveryPaths, SessionPaths, VerificationKey as VerificationKeyTrait,
    VerificationKeyStore as VerificationKeyStoreTrait, Verifier as VerifierTrait,
};
use better_auth::messages::*;
use better_auth::{Serializable, Signable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

mod implementation;

use implementation::{
    ClientRotatingKeyStore as RotatingKeyStoreImpl, ClientValueStore as ValueStoreImpl,
    Hasher as HasherImpl, Noncer as NoncerImpl, Rfc3339Nano, Secp256r1, Secp256r1Verifier,
};

const DEBUG_LOGGING: bool = false;

struct Secp256r1VerificationKey {
    public_key: String,
    secp_verifier: Secp256r1Verifier,
}

impl Secp256r1VerificationKey {
    fn new(public_key: String) -> Self {
        Self {
            public_key,
            secp_verifier: Secp256r1Verifier::new(),
        }
    }
}

#[async_trait]
impl VerificationKeyTrait for Secp256r1VerificationKey {
    async fn public(&self) -> Result<String, String> {
        Ok(self.public_key.clone())
    }

    fn verifier(&self) -> &dyn VerifierTrait {
        &self.secp_verifier
    }
}

#[derive(Clone)]
struct IntegrationVerificationKeyStore {
    keys_by_identity: Arc<Mutex<HashMap<String, Secp256r1VerificationKey>>>,
}

impl IntegrationVerificationKeyStore {
    fn new() -> Self {
        Self {
            keys_by_identity: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn add(&self, identity: String, key: Secp256r1VerificationKey) -> Result<(), String> {
        let mut keys = self.keys_by_identity.lock().await;
        keys.insert(identity, key);
        Ok(())
    }
}

#[async_trait]
impl VerificationKeyStoreTrait for IntegrationVerificationKeyStore {
    async fn get(&self, identity: &str) -> Result<Box<dyn VerificationKeyTrait>, String> {
        let keys = self.keys_by_identity.lock().await;

        keys.get(identity)
            .map(|k| {
                Box::new(Secp256r1VerificationKey::new(k.public_key.clone()))
                    as Box<dyn VerificationKeyTrait>
            })
            .ok_or_else(|| "not found".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FakeRequestData {
    foo: String,
    bar: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FakeResponseData {
    #[serde(rename = "wasFoo")]
    was_foo: String,
    #[serde(rename = "wasBar")]
    was_bar: String,
}

struct FakeResponse {
    payload: ServerPayload<FakeResponseData>,
    payload_json: Option<serde_json::Value>,
    signature: Option<String>,
}

impl FakeResponse {
    fn parse(message: &str) -> Result<Self, String> {
        let parsed: ServerResponse<FakeResponseData> =
            serde_json::from_str(message).map_err(|e| e.to_string())?;
        let payload_json = serde_json::to_value(&parsed.payload).ok();
        Ok(Self {
            payload: parsed.payload,
            payload_json,
            signature: parsed.signature,
        })
    }
}

#[async_trait]
impl Serializable for FakeResponse {
    async fn to_json(&self) -> Result<String, String> {
        if self.signature.is_none() {
            return Err("null signature".to_string());
        }
        #[derive(Serialize)]
        struct FakeResponseSerialized<'a> {
            payload: &'a ServerPayload<FakeResponseData>,
            signature: Option<&'a String>,
        }
        serde_json::to_string(&FakeResponseSerialized {
            payload: &self.payload,
            signature: self.signature.as_ref(),
        })
        .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl Signable for FakeResponse {
    fn get_payload(&self) -> Option<&serde_json::Value> {
        self.payload_json.as_ref()
    }

    fn get_signature(&self) -> Option<&String> {
        self.signature.as_ref()
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    fn compose_payload(&self) -> Result<String, String> {
        serde_json::to_string(&self.payload).map_err(|e| e.to_string())
    }
}

struct HttpNetwork {
    base_url: String,
}

impl HttpNetwork {
    fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

#[async_trait]
impl NetworkTrait for HttpNetwork {
    async fn send_request(&self, path: &str, message: &str) -> Result<String, String> {
        if DEBUG_LOGGING {
            println!("{}", message);
        }

        let url = format!("{}{}", self.base_url, path);
        let client = reqwest::Client::new();

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(message.to_string())
            .send()
            .await
            .map_err(|e| format!("Network request failed: {}", e))?;

        let reply = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if DEBUG_LOGGING {
            println!("{}", reply);
        }

        Ok(reply)
    }
}

async fn execute_flow(
    better_auth_client: &BetterAuthClient,
    _ecc_verifier: &Secp256r1Verifier,
    response_verification_key_store: &IntegrationVerificationKeyStore,
) -> Result<(), String> {
    better_auth_client.rotate_device().await?;
    better_auth_client.create_session().await?;
    better_auth_client.refresh_session().await?;

    test_access(better_auth_client, response_verification_key_store).await
}

async fn test_access(
    better_auth_client: &BetterAuthClient,
    response_verification_key_store: &IntegrationVerificationKeyStore,
) -> Result<(), String> {
    let message = FakeRequestData {
        foo: "bar".to_string(),
        bar: "foo".to_string(),
    };

    let reply = better_auth_client
        .make_access_request("/foo/bar", message)
        .await?;
    let response = FakeResponse::parse(&reply)?;

    let response_key = VerificationKeyStoreTrait::get(
        response_verification_key_store,
        &response.payload.access.server_identity,
    )
    .await?;
    let public_key_str = VerificationKeyTrait::public(response_key.as_ref()).await?;
    response
        .verify(response_key.verifier(), &public_key_str)
        .await?;

    if response.payload.response.was_foo != "bar" || response.payload.response.was_bar != "foo" {
        return Err("invalid data returned".to_string());
    }

    Ok(())
}

async fn create_client(
    response_verification_key_store: IntegrationVerificationKeyStore,
) -> Result<BetterAuthClient, String> {
    let hasher = HasherImpl::new();
    let noncer = NoncerImpl::new();

    Ok(BetterAuthClient {
        crypto: BetterAuthClientCrypto {
            hasher: Box::new(hasher),
            noncer: Box::new(noncer),
        },
        encoding: BetterAuthClientEncoding {
            timestamper: Box::new(Rfc3339Nano::new()),
        },
        io: BetterAuthClientIo {
            network: Box::new(HttpNetwork::new("http://localhost:8080".to_string())),
        },
        paths: AuthPaths {
            account: AccountPaths {
                create: "/account/create".to_string(),
                delete: "/account/delete".to_string(),
                recover: "/account/recover".to_string(),
            },
            session: SessionPaths {
                request: "/session/request".to_string(),
                create: "/session/create".to_string(),
                refresh: "/session/refresh".to_string(),
            },
            device: DevicePaths {
                rotate: "/device/rotate".to_string(),
                link: "/device/link".to_string(),
                unlink: "/device/unlink".to_string(),
            },
            recovery: RecoveryPaths {
                change: "/recovery/change".to_string(),
            },
        },
        store: BetterAuthClientStore {
            identifier: BetterAuthClientIdentifierStore {
                device: Box::new(ValueStoreImpl::new()),
                identity: Box::new(ValueStoreImpl::new()),
            },
            key: BetterAuthClientKeyStore {
                access: Box::new(RotatingKeyStoreImpl::new()),
                authentication: Box::new(RotatingKeyStoreImpl::new()),
                response: Box::new(response_verification_key_store),
            },
            token: BetterAuthClientTokenStore {
                access: Box::new(ValueStoreImpl::new()),
            },
        },
    })
}

#[tokio::test]
async fn test_completes_auth_flows() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let network = HttpNetwork::new("http://localhost:8080".to_string());
    let response_public_key = network
        .send_request("/key/response", "")
        .await
        .expect("Failed to fetch response key");

    let response_verification_key = Secp256r1VerificationKey::new(response_public_key.clone());

    let response_key_store = IntegrationVerificationKeyStore::new();
    response_key_store
        .add(response_public_key, response_verification_key)
        .await
        .unwrap();

    let response_key_store_clone = response_key_store.clone();
    let better_auth_client = create_client(response_key_store)
        .await
        .expect("Failed to create client");

    let mut recovery_signer = Secp256r1::new();
    recovery_signer
        .generate()
        .expect("Failed to generate recovery key");

    let recovery_hash = HasherTrait::sum(&hasher, &recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    better_auth_client
        .create_account(recovery_hash)
        .await
        .expect("Failed to create account");

    execute_flow(
        &better_auth_client,
        &ecc_verifier,
        &response_key_store_clone,
    )
    .await
    .expect("Flow execution failed");

    better_auth_client
        .delete_account()
        .await
        .expect("Failed to delete account");
}

#[tokio::test]
async fn test_recovers_from_loss() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let network = HttpNetwork::new("http://localhost:8080".to_string());
    let response_public_key = network
        .send_request("/key/response", "")
        .await
        .expect("Failed to fetch response key");

    let response_verification_key = Secp256r1VerificationKey::new(response_public_key.clone());

    let response_key_store = IntegrationVerificationKeyStore::new();
    response_key_store
        .add(response_public_key, response_verification_key)
        .await
        .unwrap();

    let response_key_store_clone = response_key_store.clone();
    let better_auth_client = create_client(response_key_store.clone())
        .await
        .expect("Failed to create client");

    let recovered_better_auth_client = create_client(response_key_store)
        .await
        .expect("Failed to create recovered client");

    let mut recovery_signer = Secp256r1::new();
    recovery_signer
        .generate()
        .expect("Failed to generate recovery key");

    let recovery_hash = hasher
        .sum(&recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    better_auth_client
        .create_account(recovery_hash)
        .await
        .expect("Failed to create account");

    let identity = better_auth_client.identity().await.unwrap();
    let mut new_recovery_signer = Secp256r1::new();
    let mut next_recovery_signer = Secp256r1::new();
    new_recovery_signer
        .generate()
        .expect("Failed to generate new recovery key");
    next_recovery_signer
        .generate()
        .expect("Failed to generate next recovery key");
    let new_recovery_hash = hasher
        .sum(&new_recovery_signer.public().await.unwrap())
        .await
        .unwrap();
    let next_recovery_hash = hasher
        .sum(&next_recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    better_auth_client
        .change_recovery_key(new_recovery_hash)
        .await
        .expect("Failed to change recovery key");

    recovered_better_auth_client
        .recover_account(identity, Box::new(new_recovery_signer), next_recovery_hash)
        .await
        .expect("Failed to recover account");

    execute_flow(
        &recovered_better_auth_client,
        &ecc_verifier,
        &response_key_store_clone,
    )
    .await
    .expect("Flow execution failed");
}

#[tokio::test]
async fn test_links_another_device() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let network = HttpNetwork::new("http://localhost:8080".to_string());
    let response_public_key = network
        .send_request("/key/response", "")
        .await
        .expect("Failed to fetch response key");

    let response_verification_key = Secp256r1VerificationKey::new(response_public_key.clone());

    let response_key_store = IntegrationVerificationKeyStore::new();
    response_key_store
        .add(response_public_key, response_verification_key)
        .await
        .unwrap();

    let response_key_store_clone = response_key_store.clone();
    let better_auth_client = create_client(response_key_store.clone())
        .await
        .expect("Failed to create client");

    let linked_better_auth_client = create_client(response_key_store)
        .await
        .expect("Failed to create linked client");

    let mut recovery_signer = Secp256r1::new();
    recovery_signer
        .generate()
        .expect("Failed to generate recovery key");

    let recovery_hash = hasher
        .sum(&recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    better_auth_client
        .create_account(recovery_hash)
        .await
        .expect("Failed to create account");

    let identity = better_auth_client.identity().await.unwrap();

    // Get link container from the new device
    let link_container = linked_better_auth_client
        .generate_link_container(identity)
        .await
        .expect("Failed to generate link container");

    if DEBUG_LOGGING {
        println!("{}", link_container);
    }

    // Submit an endorsed link container with existing device
    better_auth_client
        .link_device(link_container)
        .await
        .expect("Failed to link device");

    execute_flow(
        &linked_better_auth_client,
        &ecc_verifier,
        &response_key_store_clone,
    )
    .await
    .expect("Flow execution failed");

    // Unlink the original device
    linked_better_auth_client
        .unlink_device(better_auth_client.device().await.unwrap())
        .await
        .expect("Failed to unlink device");
}

#[tokio::test]
async fn test_detects_mismatched_access_nonce() {
    let hasher = HasherImpl::new();

    let network = HttpNetwork::new("http://localhost:8080".to_string());
    let response_public_key = network
        .send_request("/key/response", "")
        .await
        .expect("Failed to fetch response key");

    let response_verification_key = Secp256r1VerificationKey::new(response_public_key.clone());

    let response_key_store = IntegrationVerificationKeyStore::new();
    response_key_store
        .add(response_public_key, response_verification_key)
        .await
        .unwrap();

    let better_auth_client = create_client(response_key_store)
        .await
        .expect("Failed to create client");

    let mut recovery_signer = Secp256r1::new();
    recovery_signer
        .generate()
        .expect("Failed to generate recovery key");

    let recovery_hash = hasher
        .sum(&recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    better_auth_client
        .create_account(recovery_hash)
        .await
        .expect("Failed to create account");

    better_auth_client
        .create_session()
        .await
        .expect("Failed to create session");

    let message = FakeRequestData {
        foo: "bar".to_string(),
        bar: "foo".to_string(),
    };

    let result = better_auth_client
        .make_access_request("/bad/nonce", message)
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "incorrect nonce");
}
