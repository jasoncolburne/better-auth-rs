use async_trait::async_trait;
use better_auth::api::*;
use better_auth::interfaces::{
    AccountPaths, AuthenticationPaths as AuthPaths, ClientValueStore as ClientValueStoreTrait,
    DevicePaths, Hasher as HasherTrait, Network as NetworkTrait, SessionPaths,
    VerificationKey as VerificationKeyTrait, VerificationKeyStore as VerificationKeyStoreTrait,
};
use better_auth::messages::*;
use better_auth::{Serializable, Signable, SigningKey};
use serde::{Deserialize, Serialize};

mod implementation;

// Import implementation types with explicit names to avoid conflicts
use implementation::{
    ClientRotatingKeyStore as RotatingKeyStoreImpl, ClientValueStore as ValueStoreImpl,
    Hasher as HasherImpl, IdentityVerifier as IdentityVerifierImpl, Noncer as NoncerImpl,
    Rfc3339Nano, Secp256r1, Secp256r1Verifier, ServerAuthenticationKeyStore as AuthKeyStoreImpl,
    ServerAuthenticationNonceStore as AuthNonceStoreImpl,
    ServerRecoveryHashStore as RecoveryHashStoreImpl, ServerTimeLockStore as TimeLockStoreImpl,
    TokenEncoder as TokenEncoderImpl, VerificationKeyStore as VerificationKeyStoreImpl,
};

const DEBUG_LOGGING: bool = false;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MockAccessAttributes {
    #[serde(rename = "permissionsByRole")]
    permissions_by_role: serde_json::Value,
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

struct MockNetworkServer {
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    response_signer: Secp256r1,
    attributes: MockAccessAttributes,
    account_create_path: String,
    account_recover_path: String,
    device_link_path: String,
    device_rotate_path: String,
    device_unlink_path: String,
    session_request_path: String,
    session_create_path: String,
    session_refresh_path: String,
}

impl MockNetworkServer {
    async fn respond_to_access_request(
        &self,
        message: &str,
        nonce: Option<String>,
    ) -> Result<String, String> {
        let request = AccessRequest::<FakeRequestData>::parse(message)?;

        let reply_nonce = nonce.unwrap_or_else(|| request.payload.access.nonce.clone());

        let response_data = FakeResponseData {
            was_foo: request.payload.request.foo.clone(),
            was_bar: request.payload.request.bar.clone(),
        };

        let mut response = ServerResponse::new(
            response_data,
            self.response_signer.identity().await?,
            reply_nonce,
        );

        response.sign(&self.response_signer).await?;
        response.to_json().await
    }

    async fn _send_request(&self, path: &str, message: &str) -> Result<String, String> {
        match path {
            p if p == self.account_create_path => {
                self.better_auth_server.create_account(message).await
            }
            p if p == self.account_recover_path => {
                self.better_auth_server.recover_account(message).await
            }
            p if p == self.device_link_path => self.better_auth_server.link_device(message).await,
            p if p == self.device_rotate_path => {
                self.better_auth_server.rotate_device(message).await
            }
            p if p == self.session_request_path => {
                self.better_auth_server.request_session(message).await
            }
            p if p == self.session_create_path => {
                self.better_auth_server
                    .create_session(message, self.attributes.clone())
                    .await
            }
            p if p == self.session_refresh_path => {
                self.better_auth_server
                    .refresh_session::<MockAccessAttributes>(message)
                    .await
            }
            p if p == self.device_unlink_path => {
                self.better_auth_server.unlink_device(message).await
            }
            "/foo/bar" => {
                let (_request, token, _nonce) = self
                    .access_verifier
                    .verify::<FakeRequestData, MockAccessAttributes>(message)
                    .await?;

                // Verify identity format
                if !token.identity.starts_with('E') {
                    return Err("unexpected identity format".to_string());
                }

                if token.identity.len() != 44 {
                    return Err("unexpected identity length".to_string());
                }

                if token.attributes != self.attributes {
                    return Err("attributes do not match".to_string());
                }

                self.respond_to_access_request(message, None).await
            }
            "/bad/nonce" => {
                let (_request, token, _nonce) = self
                    .access_verifier
                    .verify::<FakeRequestData, MockAccessAttributes>(message)
                    .await?;

                // Verify identity format
                if !token.identity.starts_with('E') {
                    return Err("unexpected identity format".to_string());
                }

                if token.identity.len() != 44 {
                    return Err("unexpected identity length".to_string());
                }

                if token.attributes != self.attributes {
                    return Err("attributes do not match".to_string());
                }

                // Return wrong nonce
                self.respond_to_access_request(
                    message,
                    Some("0A0123456789abcdefghijkl".to_string()),
                )
                .await
            }
            _ => Err("unexpected message".to_string()),
        }
    }
}

#[async_trait]
impl NetworkTrait for MockNetworkServer {
    async fn send_request(&self, path: &str, message: &str) -> Result<String, String> {
        if DEBUG_LOGGING {
            println!("{}", message);
        }

        let reply = self._send_request(path, message).await?;

        if DEBUG_LOGGING {
            println!("{}", reply);
        }

        Ok(reply)
    }
}

async fn execute_flow(
    better_auth_client: &BetterAuthClient,
    ecc_verifier: &Secp256r1Verifier,
    response_verification_key_store: &VerificationKeyStoreImpl,
) -> Result<(), String> {
    better_auth_client.rotate_device().await?;
    better_auth_client.create_session().await?;
    better_auth_client.refresh_session().await?;
    better_auth_client.rotate_device().await?;
    better_auth_client.rotate_device().await?;
    better_auth_client.refresh_session().await?;

    test_access(
        better_auth_client,
        ecc_verifier,
        response_verification_key_store,
    )
    .await
}

async fn test_access(
    better_auth_client: &BetterAuthClient,
    _ecc_verifier: &Secp256r1Verifier,
    response_verification_key_store: &VerificationKeyStoreImpl,
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

async fn create_server(
    access_signer: Secp256r1,
    response_signer: Secp256r1,
    access_lifetime_in_minutes: Option<u32>,
    authentication_challenge_lifetime_in_seconds: Option<i64>,
    refresh_lifetime_in_hours: Option<u32>,
    authentication_key_store: Option<AuthKeyStoreImpl>,
    recovery_hash_store: Option<RecoveryHashStoreImpl>,
) -> Result<BetterAuthServer, String> {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();
    let noncer = NoncerImpl::new();

    let refresh_hours = refresh_lifetime_in_hours.unwrap_or(12);
    let access_key_hash_store = TimeLockStoreImpl::new((60 * 60 * refresh_hours) as u64);

    let auth_challenge_lifetime = authentication_challenge_lifetime_in_seconds.unwrap_or(60);
    let authentication_nonce_store = AuthNonceStoreImpl::new(auth_challenge_lifetime as u64);

    let auth_key_store = authentication_key_store.unwrap_or_default();
    let rec_hash_store = recovery_hash_store.unwrap_or_default();

    Ok(BetterAuthServer {
        crypto: BetterAuthServerCrypto {
            hasher: Box::new(hasher),
            key_pair: BetterAuthServerKeyPair {
                access: Box::new(access_signer),
                response: Box::new(response_signer),
            },
            noncer: Box::new(noncer),
            verifier: Box::new(ecc_verifier),
        },
        encoding: BetterAuthServerEncoding {
            identity_verifier: Box::new(IdentityVerifierImpl::new()),
            timestamper: Box::new(Rfc3339Nano::new()),
            token_encoder: Box::new(TokenEncoderImpl::new()),
        },
        expiry: BetterAuthServerExpiry {
            access_in_minutes: access_lifetime_in_minutes.unwrap_or(15),
            refresh_in_hours: refresh_hours,
        },
        store: BetterAuthServerStore {
            access: BetterAuthServerAccessStore {
                key_hash: Box::new(access_key_hash_store),
            },
            authentication: BetterAuthServerAuthenticationStore {
                key: Box::new(auth_key_store),
                nonce: Box::new(authentication_nonce_store),
            },
            recovery: BetterAuthServerRecoveryStore {
                hash: Box::new(rec_hash_store),
            },
        },
    })
}

async fn create_verifier(
    access_signer: Secp256r1,
    access_window_in_seconds: i64,
) -> Result<AccessVerifier, String> {
    let ecc_verifier = Secp256r1Verifier::new();
    let access_nonce_store = TimeLockStoreImpl::new(access_window_in_seconds as u64);
    let access_verification_key_store = VerificationKeyStoreImpl::new();

    access_verification_key_store
        .add(access_signer.identity().await?, access_signer.clone())
        .await?;

    Ok(AccessVerifier {
        crypto: AccessVerifierCrypto {
            verifier: Box::new(ecc_verifier),
        },
        encoding: AccessVerifierEncoding {
            token_encoder: Box::new(TokenEncoderImpl::new()),
            timestamper: Box::new(Rfc3339Nano::new()),
        },
        store: AccessVerifierStore {
            access: AccessVerifierAccessStore {
                nonce: Box::new(access_nonce_store),
                key: Box::new(access_verification_key_store),
            },
        },
    })
}

#[allow(clippy::too_many_arguments)]
async fn create_client(
    access_signer: Secp256r1,
    response_signer: Secp256r1,
    access_window_in_seconds: i64,
    access_lifetime_in_minutes: Option<u32>,
    authentication_challenge_lifetime_in_seconds: Option<i64>,
    refresh_lifetime_in_hours: Option<u32>,
    authentication_key_store: Option<AuthKeyStoreImpl>,
    recovery_hash_store: Option<RecoveryHashStoreImpl>,
    access_token_store: Option<ValueStoreImpl>,
) -> Result<BetterAuthClient, String> {
    let hasher = HasherImpl::new();
    let noncer = NoncerImpl::new();

    let better_auth_server = create_server(
        access_signer.clone(),
        response_signer.clone(),
        access_lifetime_in_minutes,
        authentication_challenge_lifetime_in_seconds,
        refresh_lifetime_in_hours,
        authentication_key_store,
        recovery_hash_store,
    )
    .await?;

    let access_verifier = create_verifier(access_signer.clone(), access_window_in_seconds).await?;

    let permissions = serde_json::json!({
        "admin": ["read", "write"]
    });
    let attributes = MockAccessAttributes {
        permissions_by_role: permissions,
    };

    let mock_network_server = MockNetworkServer {
        better_auth_server,
        access_verifier,
        response_signer: response_signer.clone(),
        attributes,
        account_create_path: "/account/create".to_string(),
        account_recover_path: "/account/recover".to_string(),
        device_link_path: "/device/link".to_string(),
        device_rotate_path: "/device/rotate".to_string(),
        device_unlink_path: "/device/unlink".to_string(),
        session_request_path: "/session/request".to_string(),
        session_create_path: "/session/create".to_string(),
        session_refresh_path: "/session/refresh".to_string(),
    };

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(response_signer.identity().await?, response_signer.clone())
        .await?;

    Ok(BetterAuthClient {
        crypto: BetterAuthClientCrypto {
            hasher: Box::new(hasher),
            noncer: Box::new(noncer),
        },
        encoding: BetterAuthClientEncoding {
            timestamper: Box::new(Rfc3339Nano::new()),
        },
        io: BetterAuthClientIo {
            network: Box::new(mock_network_server),
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
        },
        store: BetterAuthClientStore {
            identifier: BetterAuthClientIdentifierStore {
                device: Box::new(ValueStoreImpl::new()),
                identity: Box::new(ValueStoreImpl::new()),
            },
            key: BetterAuthClientKeyStore {
                access: Box::new(RotatingKeyStoreImpl::new()),
                authentication: Box::new(RotatingKeyStoreImpl::new()),
                response: Box::new(response_key_store),
            },
            token: BetterAuthClientTokenStore {
                access: Box::new(access_token_store.unwrap_or_default()),
            },
        },
    })
}

#[tokio::test]
async fn test_completes_auth_flows() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        None,
        None,
        None,
    )
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

    execute_flow(&better_auth_client, &ecc_verifier, &response_key_store)
        .await
        .expect("Flow execution failed");
}

#[tokio::test]
async fn test_recovers_from_loss() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    let authentication_key_store = AuthKeyStoreImpl::new();
    let recovery_hash_store = RecoveryHashStoreImpl::new();

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        Some(authentication_key_store.clone()),
        Some(recovery_hash_store.clone()),
        None,
    )
    .await
    .expect("Failed to create client");

    let recovered_better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        Some(authentication_key_store),
        Some(recovery_hash_store),
        None,
    )
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
    let mut next_recovery_signer = Secp256r1::new();
    next_recovery_signer
        .generate()
        .expect("Failed to generate next recovery key");
    let next_recovery_hash = hasher
        .sum(&next_recovery_signer.public().await.unwrap())
        .await
        .unwrap();

    recovered_better_auth_client
        .recover_account(identity, Box::new(recovery_signer), next_recovery_hash)
        .await
        .expect("Failed to recover account");

    execute_flow(
        &recovered_better_auth_client,
        &ecc_verifier,
        &response_key_store,
    )
    .await
    .expect("Flow execution failed");
}

#[tokio::test]
async fn test_links_another_device() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    let authentication_key_store = AuthKeyStoreImpl::new();

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        Some(authentication_key_store.clone()),
        None,
        None,
    )
    .await
    .expect("Failed to create client");

    let linked_better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        Some(authentication_key_store),
        None,
        None,
    )
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
        &response_key_store,
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
async fn test_rejects_expired_authentication_challenges() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        Some(0), // Expired authentication challenge
        None,
        None,
        None,
        None,
    )
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

    let result = execute_flow(&better_auth_client, &ecc_verifier, &response_key_store).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "expired nonce");
}

#[tokio::test]
async fn test_rejects_expired_refresh_tokens() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    // Use a negative refresh lifetime to simulate expiry
    // Note: We need to use Some(0) as negative u32 won't work
    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        Some(0), // Immediately expired refresh
        None,
        None,
        None,
    )
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

    // Sleep for 1 second to ensure refresh expires
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let result = execute_flow(&better_auth_client, &ecc_verifier, &response_key_store).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "refresh has expired");
}

#[tokio::test]
async fn test_rejects_expired_access_tokens() {
    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    // Use 0 minutes for access token lifetime to simulate expiry
    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        Some(0), // Immediately expired access token
        None,
        None,
        None,
        None,
        None,
    )
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

    // Sleep for 1 second to ensure access token expires
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let result = execute_flow(&better_auth_client, &ecc_verifier, &response_key_store).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "token expired");
}

#[tokio::test]
async fn test_detects_tampered_access_tokens() {
    use implementation::Base64;

    let ecc_verifier = Secp256r1Verifier::new();
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let response_key_store = VerificationKeyStoreImpl::new();
    response_key_store
        .add(
            response_signer.identity().await.unwrap(),
            response_signer.clone(),
        )
        .await
        .unwrap();

    let access_token_store = ValueStoreImpl::new();

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        None,
        None,
        Some(access_token_store.clone()),
    )
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

    let token = access_token_store.get().await.unwrap();
    let signature = &token[..88];
    let mut bytes = Base64::decode(signature).unwrap();
    let index = rand::random::<usize>() % 64;
    bytes[2 + index] ^= 0xff;
    let tampered_token = format!("{}{}", Base64::encode(&bytes), &token[88..]);
    access_token_store.store(tampered_token).await.unwrap();

    let result = test_access(&better_auth_client, &ecc_verifier, &response_key_store).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "invalid signature");
}

#[tokio::test]
async fn test_detects_mismatched_access_nonce() {
    let hasher = HasherImpl::new();

    let mut access_signer = Secp256r1::new();
    access_signer
        .generate()
        .expect("Failed to generate access key");

    let mut response_signer = Secp256r1::new();
    response_signer
        .generate()
        .expect("Failed to generate response key");

    let better_auth_client = create_client(
        access_signer.clone(),
        response_signer.clone(),
        30,
        None,
        None,
        None,
        None,
        None,
        Some(ValueStoreImpl::new()),
    )
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
