use crate::interfaces::*;
use crate::messages::*;
use serde::{Deserialize, Serialize};

pub struct BetterAuthServerCrypto {
    pub hasher: Box<dyn Hasher>,
    pub key_pair: BetterAuthServerKeyPair,
    pub noncer: Box<dyn Noncer>,
    pub verifier: Box<dyn Verifier>,
}

pub struct BetterAuthServerKeyPair {
    pub response: Box<dyn SigningKey>,
    pub access: Box<dyn SigningKey>,
}

pub struct BetterAuthServerEncoding {
    pub identity_verifier: Box<dyn IdentityVerifier>,
    pub timestamper: Box<dyn Timestamper>,
    pub token_encoder: Box<dyn TokenEncoder>,
}

pub struct BetterAuthServerExpiry {
    pub access_in_minutes: u32,
    pub refresh_in_hours: u32,
}

pub struct BetterAuthServerAccessStore {
    pub key_hash: Box<dyn ServerTimeLockStore>,
}

pub struct BetterAuthServerAuthenticationStore {
    pub key: Box<dyn ServerAuthenticationKeyStore>,
    pub nonce: Box<dyn ServerAuthenticationNonceStore>,
}

pub struct BetterAuthServerRecoveryStore {
    pub hash: Box<dyn ServerRecoveryHashStore>,
}

pub struct BetterAuthServerStore {
    pub access: BetterAuthServerAccessStore,
    pub authentication: BetterAuthServerAuthenticationStore,
    pub recovery: BetterAuthServerRecoveryStore,
}

pub struct BetterAuthServer {
    pub crypto: BetterAuthServerCrypto,
    pub encoding: BetterAuthServerEncoding,
    pub expiry: BetterAuthServerExpiry,
    pub store: BetterAuthServerStore,
}

impl BetterAuthServer {
    pub async fn create_account(&self, message: &str) -> Result<String, String> {
        let request = CreateAccountRequest::parse(message)?;
        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.public_key,
            )
            .await?;

        let identity = &request.payload.request.authentication.identity;

        self.encoding
            .identity_verifier
            .verify(
                identity,
                &request.payload.request.authentication.public_key,
                &request.payload.request.authentication.rotation_hash,
                Some(&request.payload.request.authentication.recovery_hash),
            )
            .await?;

        let device = self
            .crypto
            .hasher
            .sum(&format!(
                "{}{}",
                request.payload.request.authentication.public_key,
                request.payload.request.authentication.rotation_hash
            ))
            .await?;

        if device != request.payload.request.authentication.device {
            return Err("bad device derivation".to_string());
        }

        self.store
            .recovery
            .hash
            .register(
                identity.clone(),
                request.payload.request.authentication.recovery_hash.clone(),
            )
            .await?;

        self.store
            .authentication
            .key
            .register(
                identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
                false,
            )
            .await?;

        let mut response = CreateAccountResponse::new(
            CreateAccountResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn delete_account(&self, message: &str) -> Result<String, String> {
        let request = DeleteAccountRequest::parse(message)?;
        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.public_key,
            )
            .await?;

        self.store
            .authentication
            .key
            .rotate(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
            )
            .await?;

        self.store
            .authentication
            .key
            .delete_identity(request.payload.request.authentication.identity.clone())
            .await?;

        let mut response = DeleteAccountResponse::new(
            DeleteAccountResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn recover_account(&self, message: &str) -> Result<String, String> {
        let request = RecoverAccountRequest::parse(message)?;
        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.recovery_key,
            )
            .await?;

        let device = self
            .crypto
            .hasher
            .sum(&format!(
                "{}{}",
                request.payload.request.authentication.public_key,
                request.payload.request.authentication.rotation_hash
            ))
            .await?;

        if device != request.payload.request.authentication.device {
            return Err("bad device derivation".to_string());
        }

        let hash = self
            .crypto
            .hasher
            .sum(&request.payload.request.authentication.recovery_key)
            .await?;

        self.store
            .recovery
            .hash
            .rotate(
                request.payload.request.authentication.identity.clone(),
                hash,
                request.payload.request.authentication.recovery_hash.clone(),
            )
            .await?;

        self.store
            .authentication
            .key
            .revoke_devices(request.payload.request.authentication.identity.clone())
            .await?;

        self.store
            .authentication
            .key
            .register(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
                true,
            )
            .await?;

        let mut response = RecoverAccountResponse::new(
            RecoverAccountResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn link_device(&self, message: &str) -> Result<String, String> {
        let request = LinkDeviceRequest::parse(message)?;

        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.public_key,
            )
            .await?;

        let link_container = request.payload.request.link.clone();

        link_container
            .verify(
                self.crypto.verifier.as_ref(),
                &link_container.payload.authentication.public_key,
            )
            .await?;

        if link_container.payload.authentication.identity
            != request.payload.request.authentication.identity
        {
            return Err("mismatched identities".to_string());
        }

        let device = self
            .crypto
            .hasher
            .sum(&format!(
                "{}{}",
                link_container.payload.authentication.public_key,
                link_container.payload.authentication.rotation_hash
            ))
            .await?;

        if device != link_container.payload.authentication.device {
            return Err("bad device derivation".to_string());
        }

        self.store
            .authentication
            .key
            .rotate(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
            )
            .await?;

        self.store
            .authentication
            .key
            .register(
                link_container.payload.authentication.identity.clone(),
                link_container.payload.authentication.device.clone(),
                link_container.payload.authentication.public_key.clone(),
                link_container.payload.authentication.rotation_hash.clone(),
                true,
            )
            .await?;

        let mut response = LinkDeviceResponse::new(
            LinkDeviceResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn unlink_device(&self, message: &str) -> Result<String, String> {
        let request = UnlinkDeviceRequest::parse(message)?;

        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.public_key,
            )
            .await?;

        self.store
            .authentication
            .key
            .rotate(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
            )
            .await?;

        self.store
            .authentication
            .key
            .revoke_device(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.link.device.clone(),
            )
            .await?;

        let mut response = UnlinkDeviceResponse::new(
            UnlinkDeviceResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn rotate_device(&self, message: &str) -> Result<String, String> {
        let request = RotateDeviceRequest::parse(message)?;

        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.authentication.public_key,
            )
            .await?;

        self.store
            .authentication
            .key
            .rotate(
                request.payload.request.authentication.identity.clone(),
                request.payload.request.authentication.device.clone(),
                request.payload.request.authentication.public_key.clone(),
                request.payload.request.authentication.rotation_hash.clone(),
            )
            .await?;

        let mut response = RotateDeviceResponse::new(
            RotateDeviceResponseData {},
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn request_session(&self, message: &str) -> Result<String, String> {
        let request = RequestSessionRequest::parse(message)?;

        let nonce = self
            .store
            .authentication
            .nonce
            .generate(request.payload.request.authentication.identity.clone())
            .await?;

        let mut response = RequestSessionResponse::new(
            RequestSessionResponseData {
                authentication: RequestSessionResponseAuthentication { nonce },
            },
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn create_session<T: Serialize + Send + Sync>(
        &self,
        message: &str,
        attributes: T,
    ) -> Result<String, String> {
        let request = CreateSessionRequest::parse(message)?;

        let identity = self
            .store
            .authentication
            .nonce
            .validate(request.payload.request.authentication.nonce.clone())
            .await?;

        let authentication_public_key = self
            .store
            .authentication
            .key
            .public(
                identity.clone(),
                request.payload.request.authentication.device.clone(),
            )
            .await?;

        request
            .verify(self.crypto.verifier.as_ref(), &authentication_public_key)
            .await?;

        let now = self.encoding.timestamper.now();
        let later = self
            .encoding
            .timestamper
            .add_minutes(now, self.expiry.access_in_minutes);
        let even_later = self
            .encoding
            .timestamper
            .add_hours(now, self.expiry.refresh_in_hours);

        let issued_at = self.encoding.timestamper.format(now);
        let expiry = self.encoding.timestamper.format(later);
        let refresh_expiry = self.encoding.timestamper.format(even_later);

        let mut access_token = AccessToken::new(
            self.crypto.key_pair.access.identity().await?,
            request.payload.request.authentication.device.clone(),
            identity,
            request.payload.request.access.public_key.clone(),
            request.payload.request.access.rotation_hash.clone(),
            issued_at,
            expiry,
            refresh_expiry,
            attributes,
        );

        access_token
            .sign(self.crypto.key_pair.access.as_ref())
            .await?;
        let token = access_token
            .serialize_token(self.encoding.token_encoder.as_ref())
            .await?;

        let mut response = CreateSessionResponse::new(
            CreateSessionResponseData {
                access: CreateSessionResponseAccess { token },
            },
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }

    pub async fn refresh_session<T>(&self, message: &str) -> Result<String, String>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        let request = RefreshSessionRequest::parse(message)?;

        request
            .verify(
                self.crypto.verifier.as_ref(),
                &request.payload.request.access.public_key,
            )
            .await?;

        let token_string = &request.payload.request.access.token;
        let token =
            AccessToken::<T>::parse(token_string, self.encoding.token_encoder.as_ref()).await?;

        let access_public_key = self.crypto.key_pair.access.public().await?;
        token
            .verify_token(
                self.crypto.verifier.as_ref(),
                &access_public_key,
                self.encoding.timestamper.as_ref(),
            )
            .await?;

        let hash = self
            .crypto
            .hasher
            .sum(&request.payload.request.access.public_key)
            .await?;
        if hash != token.rotation_hash {
            return Err("hash mismatch".to_string());
        }

        let now = self.encoding.timestamper.now();
        let refresh_expiry = self.encoding.timestamper.parse(&token.refresh_expiry)?;

        if self.encoding.timestamper.compare(now, refresh_expiry) == std::cmp::Ordering::Greater {
            return Err("refresh has expired".to_string());
        }

        self.store.access.key_hash.reserve(hash).await?;

        let later = self
            .encoding
            .timestamper
            .add_minutes(now, self.expiry.access_in_minutes);
        let issued_at = self.encoding.timestamper.format(now);
        let expiry = self.encoding.timestamper.format(later);

        let mut access_token = AccessToken::new(
            self.crypto.key_pair.access.identity().await?,
            token.device,
            token.identity,
            request.payload.request.access.public_key.clone(),
            request.payload.request.access.rotation_hash.clone(),
            issued_at,
            expiry,
            token.refresh_expiry,
            token.attributes,
        );

        access_token
            .sign(self.crypto.key_pair.access.as_ref())
            .await?;
        let serialized_token = access_token
            .serialize_token(self.encoding.token_encoder.as_ref())
            .await?;

        let mut response = RefreshSessionResponse::new(
            RefreshSessionResponseData {
                access: RefreshSessionResponseAccess {
                    token: serialized_token,
                },
            },
            self.crypto.key_pair.response.identity().await?,
            request.payload.access.nonce.clone(),
        );

        response
            .sign(self.crypto.key_pair.response.as_ref())
            .await?;

        response.to_json().await
    }
}

pub struct AccessVerifierCrypto {
    pub verifier: Box<dyn Verifier>,
}

pub struct AccessVerifierEncoding {
    pub token_encoder: Box<dyn TokenEncoder>,
    pub timestamper: Box<dyn Timestamper>,
}

pub struct AccessVerifierAccessStore {
    pub nonce: Box<dyn ServerTimeLockStore>,
    pub key: Box<dyn VerificationKeyStore>,
}

pub struct AccessVerifierStore {
    pub access: AccessVerifierAccessStore,
}

pub struct AccessVerifier {
    pub crypto: AccessVerifierCrypto,
    pub encoding: AccessVerifierEncoding,
    pub store: AccessVerifierStore,
}

impl AccessVerifier {
    pub async fn verify<T, U>(&self, message: &str) -> Result<(T, AccessToken<U>, String), String>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
        U: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        let request: AccessRequest<T> = AccessRequest::parse(message)?;

        let access_token = request
            .verify_access::<U>(
                self.store.access.nonce.as_ref(),
                self.crypto.verifier.as_ref(),
                self.store.access.key.as_ref(),
                self.encoding.token_encoder.as_ref(),
                self.encoding.timestamper.as_ref(),
            )
            .await?;

        Ok((
            request.payload.request,
            access_token,
            request.payload.access.nonce.clone(),
        ))
    }
}
