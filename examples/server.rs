use axum::{Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use better_auth::api::server::{
    AccessVerifier, AccessVerifierAccessStore, AccessVerifierCrypto, AccessVerifierEncoding,
    AccessVerifierStore, BetterAuthServer, BetterAuthServerAccessStore,
    BetterAuthServerAuthenticationStore, BetterAuthServerCrypto, BetterAuthServerEncoding,
    BetterAuthServerExpiry, BetterAuthServerKeyPair, BetterAuthServerRecoveryStore,
    BetterAuthServerStore,
};
use better_auth::interfaces::{SigningKey, VerificationKey};
use better_auth::messages::{AccessToken, ServerResponse};
use better_auth::messages::{Serializable, Signable};

#[path = "../tests/implementation/mod.rs"]
mod implementation;

use implementation::{
    Hasher, IdentityVerifier, Noncer, Rfc3339, Secp256r1, Secp256r1Verifier,
    ServerAuthenticationKeyStore, ServerAuthenticationNonceStore, ServerRecoveryHashStore,
    ServerTimeLockStore, TokenEncoder, VerificationKeyStore,
};

#[derive(Clone, Serialize, Deserialize)]
struct MockTokenAttributes {
    #[serde(rename = "permissionsByRole")]
    permissions_by_role: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MockRequestPayload {
    foo: String,
    bar: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct MockResponsePayload {
    #[serde(rename = "wasFoo")]
    was_foo: String,
    #[serde(rename = "wasBar")]
    was_bar: String,
}

#[derive(Clone)]
struct AppState {
    ba: Arc<BetterAuthServer>,
    av: Arc<AccessVerifier>,
    server_response_key: Arc<Secp256r1>,
}

async fn wrap_response<F, Fut>(body: String, logic: F) -> (StatusCode, String)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    match logic(body).await {
        Ok(reply) => (StatusCode::OK, reply),
        Err(e) => {
            eprintln!("error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"an error occurred"}"#.to_string(),
            )
        }
    }
}

async fn create(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.create_account(&msg).await },
    )
    .await
}

async fn recover(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.recover_account(&msg).await },
    )
    .await
}

async fn delete(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.delete_account(&msg).await },
    )
    .await
}

async fn link(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(body, |msg| async move { state.ba.link_device(&msg).await }).await
}

async fn unlink(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.unlink_device(&msg).await },
    )
    .await
}

async fn start_authentication(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.request_session(&msg).await },
    )
    .await
}

async fn finish_authentication(
    State(state): State<AppState>,
    body: String,
) -> (StatusCode, String) {
    wrap_response(body, |msg| async move {
        let mut permissions = std::collections::HashMap::new();
        permissions.insert(
            "admin".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        state
            .ba
            .create_session(
                &msg,
                MockTokenAttributes {
                    permissions_by_role: permissions,
                },
            )
            .await
    })
    .await
}

async fn rotate_authentication(
    State(state): State<AppState>,
    body: String,
) -> (StatusCode, String) {
    wrap_response(
        body,
        |msg| async move { state.ba.rotate_device(&msg).await },
    )
    .await
}

async fn change_recovery_key(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(body, |msg| async move {
        state.ba.change_recovery_key(&msg).await
    })
    .await
}

async fn rotate_access(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(body, |msg| async move {
        state.ba.refresh_session::<MockTokenAttributes>(&msg).await
    })
    .await
}

async fn response_key(State(state): State<AppState>, _body: String) -> (StatusCode, String) {
    wrap_response(String::new(), |_| async move {
        state.server_response_key.public().await
    })
    .await
}

async fn respond_to_access_request(
    state: &AppState,
    message: String,
    bad_nonce: bool,
) -> Result<String, String> {
    // Verify the access token
    let (request, _token, request_nonce): (
        MockRequestPayload,
        AccessToken<MockTokenAttributes>,
        String,
    ) = state
        .av
        .verify::<MockRequestPayload, MockTokenAttributes>(&message)
        .await?;

    // Get the server identity
    let server_identity = state.server_response_key.identity().await?;

    // Use the request nonce or a bad one for testing
    let nonce = if bad_nonce {
        "0A0123456789".to_string()
    } else {
        request_nonce.clone()
    };

    // Create the response
    let mut response: ServerResponse<MockResponsePayload> = ServerResponse::new(
        MockResponsePayload {
            was_foo: request.foo.clone(),
            was_bar: request.bar.clone(),
        },
        server_identity,
        nonce,
    );

    // Sign the response
    response.sign(state.server_response_key.as_ref()).await?;

    response.to_json().await
}

async fn foo_bar(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(body, |msg| async move {
        respond_to_access_request(&state, msg, false).await
    })
    .await
}

async fn bad_nonce(State(state): State<AppState>, body: String) -> (StatusCode, String) {
    wrap_response(body, |msg| async move {
        respond_to_access_request(&state, msg, true).await
    })
    .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Lifetimes
    let access_lifetime: u32 = 15; // 15 minutes
    let access_window = 30; // 30 seconds
    let refresh_lifetime: u32 = 12; // 12 hours
    let authentication_challenge_lifetime = 60; // 1 minute

    // Crypto components
    let hasher = Hasher::new();
    let verifier = Secp256r1Verifier::new();
    let noncer = Noncer::new();

    // Storage components
    let access_key_hash_store = ServerTimeLockStore::new((refresh_lifetime as u64) * 60 * 60);
    let access_nonce_store = ServerTimeLockStore::new(access_window as u64);
    let authentication_key_store = ServerAuthenticationKeyStore::new();
    let authentication_nonce_store =
        ServerAuthenticationNonceStore::new(authentication_challenge_lifetime);
    let recovery_hash_store = ServerRecoveryHashStore::new();

    // Encoding components
    let identity_verifier = IdentityVerifier::new();
    let timestamper = Rfc3339::new();
    let token_encoder = TokenEncoder::new();

    // Generate server keys
    let mut server_response_key = Secp256r1::new();
    let mut server_access_key = Secp256r1::new();

    server_response_key.generate()?;
    server_access_key.generate()?;

    // Create access key store and add server access key
    let access_key_store = VerificationKeyStore::new();
    let server_access_identity = server_access_key.identity().await?;
    access_key_store
        .add(server_access_identity, server_access_key.clone())
        .await?;

    // Create BetterAuthServer
    let verifier2 = Secp256r1Verifier::new();
    let timestamper2 = Rfc3339::new();
    let token_encoder2 = TokenEncoder::new();

    let ba = BetterAuthServer {
        crypto: BetterAuthServerCrypto {
            hasher: Box::new(hasher),
            key_pair: BetterAuthServerKeyPair {
                access: Box::new(server_access_key.clone()),
                response: Box::new(server_response_key.clone()),
            },
            noncer: Box::new(noncer),
            verifier: Box::new(verifier),
        },
        encoding: BetterAuthServerEncoding {
            identity_verifier: Box::new(identity_verifier),
            timestamper: Box::new(timestamper),
            token_encoder: Box::new(token_encoder),
        },
        expiry: BetterAuthServerExpiry {
            access_in_minutes: access_lifetime,
            refresh_in_hours: refresh_lifetime,
        },
        store: BetterAuthServerStore {
            access: BetterAuthServerAccessStore {
                verification_key: Box::new(access_key_store.clone()),
                key_hash: Box::new(access_key_hash_store),
            },
            authentication: BetterAuthServerAuthenticationStore {
                key: Box::new(authentication_key_store),
                nonce: Box::new(authentication_nonce_store),
            },
            recovery: BetterAuthServerRecoveryStore {
                hash: Box::new(recovery_hash_store),
            },
        },
    };

    // Create AccessVerifier
    let av = AccessVerifier {
        crypto: AccessVerifierCrypto {
            verifier: Box::new(verifier2),
        },
        encoding: AccessVerifierEncoding {
            token_encoder: Box::new(token_encoder2),
            timestamper: Box::new(timestamper2),
        },
        store: AccessVerifierStore {
            access: AccessVerifierAccessStore {
                nonce: Box::new(access_nonce_store),
                key: Box::new(access_key_store),
            },
        },
    };

    let state = AppState {
        ba: Arc::new(ba),
        av: Arc::new(av),
        server_response_key: Arc::new(server_response_key),
    };

    // Build the router
    let app = Router::new()
        .route("/account/create", post(create))
        .route("/account/recover", post(recover))
        .route("/account/delete", post(delete))
        .route("/session/request", post(start_authentication))
        .route("/session/create", post(finish_authentication))
        .route("/session/refresh", post(rotate_access))
        .route("/device/rotate", post(rotate_authentication))
        .route("/device/link", post(link))
        .route("/device/unlink", post(unlink))
        .route("/recovery/change", post(change_recovery_key))
        .route("/key/response", post(response_key))
        .route("/foo/bar", post(foo_bar))
        .route("/bad/nonce", post(bad_nonce))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server running on http://localhost:8080");

    axum::serve(listener, app).await?;

    Ok(())
}
