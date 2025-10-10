use crate::interfaces::*;
use crate::messages::*;

pub struct BetterAuthClientCrypto {
    pub hasher: Box<dyn Hasher>,
    pub noncer: Box<dyn Noncer>,
}

pub struct BetterAuthClientEncoding {
    pub timestamper: Box<dyn Timestamper>,
}

pub struct BetterAuthClientIo {
    pub network: Box<dyn Network>,
}

pub struct BetterAuthClientIdentifierStore {
    pub device: Box<dyn ClientValueStore>,
    pub identity: Box<dyn ClientValueStore>,
}

pub struct BetterAuthClientKeyStore {
    pub access: Box<dyn ClientRotatingKeyStore>,
    pub authentication: Box<dyn ClientRotatingKeyStore>,
    pub response: Box<dyn VerificationKeyStore>,
}

pub struct BetterAuthClientTokenStore {
    pub access: Box<dyn ClientValueStore>,
}

pub struct BetterAuthClientStore {
    pub identifier: BetterAuthClientIdentifierStore,
    pub key: BetterAuthClientKeyStore,
    pub token: BetterAuthClientTokenStore,
}

pub struct BetterAuthClient {
    pub crypto: BetterAuthClientCrypto,
    pub encoding: BetterAuthClientEncoding,
    pub io: BetterAuthClientIo,
    pub paths: AuthenticationPaths,
    pub store: BetterAuthClientStore,
}

impl BetterAuthClient {
    pub async fn identity(&self) -> Result<String, String> {
        self.store.identifier.identity.get().await
    }

    pub async fn device(&self) -> Result<String, String> {
        self.store.identifier.device.get().await
    }

    async fn verify_response<T: Signable>(
        &self,
        response: &T,
        server_identity: &str,
    ) -> Result<(), String> {
        let public_key = self.store.key.response.get(server_identity).await?;
        let verifier = public_key.verifier();
        let pk = public_key.public().await?;

        response.verify(verifier, &pk).await
    }

    pub async fn create_account(&self, recovery_hash: String) -> Result<(), String> {
        let (identity, public_key, rotation_hash) = self
            .store
            .key
            .authentication
            .initialize(Some(recovery_hash.clone()))
            .await?;

        let device = self
            .crypto
            .hasher
            .sum(&format!("{}{}", public_key, rotation_hash))
            .await?;
        let nonce = self.crypto.noncer.generate_128().await?;

        let mut request = CreateAccountRequest::new(
            CreateAccountRequestData {
                authentication: CreateAccountAuthentication {
                    device: device.clone(),
                    identity: identity.clone(),
                    public_key,
                    recovery_hash,
                    rotation_hash,
                },
            },
            nonce.clone(),
        );

        let signer = self.store.key.authentication.signer().await?;
        request.sign(signer.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.account.create, &message)
            .await?;

        let response = CreateAccountResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.identifier.identity.store(identity).await?;
        self.store.identifier.device.store(device).await?;

        Ok(())
    }

    pub async fn delete_account(&self) -> Result<(), String> {
        let nonce = self.crypto.noncer.generate_128().await?;
        let (signing_key, rotation_hash) = self.store.key.authentication.next().await?;

        let mut request = DeleteAccountRequest::new(
            DeleteAccountRequestData {
                authentication: DeleteAccountAuthentication {
                    device: self.store.identifier.device.get().await?,
                    identity: self.store.identifier.identity.get().await?,
                    public_key: signing_key.public().await?,
                    rotation_hash,
                },
            },
            nonce.clone(),
        );

        request.sign(signing_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.account.delete, &message)
            .await?;

        let response = DeleteAccountResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.key.authentication.rotate().await?;

        Ok(())
    }

    pub async fn recover_account(
        &self,
        identity: String,
        recovery_key: Box<dyn SigningKey>,
        recovery_hash: String,
    ) -> Result<(), String> {
        let (_, public_key, rotation_hash) = self.store.key.authentication.initialize(None).await?;

        let device = self
            .crypto
            .hasher
            .sum(&format!("{}{}", public_key, rotation_hash))
            .await?;
        let nonce = self.crypto.noncer.generate_128().await?;

        let mut request = RecoverAccountRequest::new(
            RecoverAccountRequestData {
                authentication: RecoverAccountAuthentication {
                    device: device.clone(),
                    identity: identity.clone(),
                    public_key,
                    recovery_hash,
                    recovery_key: recovery_key.public().await?,
                    rotation_hash,
                },
            },
            nonce.clone(),
        );

        request.sign(recovery_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.account.recover, &message)
            .await?;

        let response = RecoverAccountResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.identifier.identity.store(identity).await?;
        self.store.identifier.device.store(device).await?;

        Ok(())
    }

    pub async fn generate_link_container(&self, identity: String) -> Result<String, String> {
        let (_, public_key, rotation_hash) = self.store.key.authentication.initialize(None).await?;

        let device = self
            .crypto
            .hasher
            .sum(&format!("{}{}", public_key, rotation_hash))
            .await?;

        self.store
            .identifier
            .identity
            .store(identity.clone())
            .await?;
        self.store.identifier.device.store(device.clone()).await?;

        let mut link_container = LinkContainer::new(LinkContainerPayload {
            authentication: LinkContainerAuthentication {
                device,
                identity,
                public_key,
                rotation_hash,
            },
        });

        let signer = self.store.key.authentication.signer().await?;
        link_container.sign(signer.as_ref()).await?;

        link_container.to_json().await
    }

    pub async fn link_device(&self, link_container: String) -> Result<(), String> {
        let container = LinkContainer::parse(&link_container)?;
        let nonce = self.crypto.noncer.generate_128().await?;
        let (signing_key, rotation_hash) = self.store.key.authentication.next().await?;

        let mut request = LinkDeviceRequest::new(
            LinkDeviceRequestData {
                authentication: LinkDeviceAuthentication {
                    device: self.store.identifier.device.get().await?,
                    identity: self.store.identifier.identity.get().await?,
                    public_key: signing_key.public().await?,
                    rotation_hash,
                },
                link: container,
            },
            nonce.clone(),
        );

        request.sign(signing_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.device.link, &message)
            .await?;

        let response = LinkDeviceResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.key.authentication.rotate().await?;

        Ok(())
    }

    pub async fn unlink_device(&self, device: String) -> Result<(), String> {
        let nonce = self.crypto.noncer.generate_128().await?;
        let (signing_key, rotation_hash) = self.store.key.authentication.next().await?;

        let mut hash = rotation_hash;
        let current_device = self.store.identifier.device.get().await?;

        if device == current_device {
            // If we're disabling the current device, hash again to prevent rotation
            hash = self.crypto.hasher.sum(&hash).await?;
        }

        let mut request = UnlinkDeviceRequest::new(
            UnlinkDeviceRequestData {
                authentication: UnlinkDeviceAuthentication {
                    device: current_device,
                    identity: self.store.identifier.identity.get().await?,
                    public_key: signing_key.public().await?,
                    rotation_hash: hash,
                },
                link: UnlinkDeviceLink { device },
            },
            nonce.clone(),
        );

        request.sign(signing_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.device.unlink, &message)
            .await?;

        let response = UnlinkDeviceResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.key.authentication.rotate().await?;

        Ok(())
    }

    pub async fn rotate_device(&self) -> Result<(), String> {
        let (signing_key, rotation_hash) = self.store.key.authentication.next().await?;
        let nonce = self.crypto.noncer.generate_128().await?;

        let mut request = RotateDeviceRequest::new(
            RotateDeviceRequestData {
                authentication: RotateDeviceAuthentication {
                    device: self.store.identifier.device.get().await?,
                    identity: self.store.identifier.identity.get().await?,
                    public_key: signing_key.public().await?,
                    rotation_hash,
                },
            },
            nonce.clone(),
        );

        request.sign(signing_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.device.rotate, &message)
            .await?;

        let response = RotateDeviceResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store.key.authentication.rotate().await?;

        Ok(())
    }

    pub async fn create_session(&self) -> Result<(), String> {
        let start_nonce = self.crypto.noncer.generate_128().await?;

        let start_request = RequestSessionRequest::new(
            self.store.identifier.identity.get().await?,
            start_nonce.clone(),
        );

        let start_message = start_request.to_json().await?;
        let start_reply = self
            .io
            .network
            .send_request(&self.paths.session.request, &start_message)
            .await?;

        let start_response = RequestSessionResponse::parse(&start_reply)?;
        self.verify_response(
            &start_response,
            &start_response.payload.access.server_identity,
        )
        .await?;

        if start_response.payload.access.nonce != start_nonce {
            return Err("incorrect nonce".to_string());
        }

        let (_, current_key, next_key_hash) = self.store.key.access.initialize(None).await?;
        let finish_nonce = self.crypto.noncer.generate_128().await?;

        let mut finish_request = CreateSessionRequest::new(
            CreateSessionRequestData {
                access: CreateSessionAccess {
                    public_key: current_key,
                    rotation_hash: next_key_hash,
                },
                authentication: CreateSessionAuthentication {
                    device: self.store.identifier.device.get().await?,
                    nonce: start_response.payload.response.authentication.nonce,
                },
            },
            finish_nonce.clone(),
        );

        let signer = self.store.key.authentication.signer().await?;
        finish_request.sign(signer.as_ref()).await?;

        let finish_message = finish_request.to_json().await?;
        let finish_reply = self
            .io
            .network
            .send_request(&self.paths.session.create, &finish_message)
            .await?;

        let finish_response = CreateSessionResponse::parse(&finish_reply)?;
        self.verify_response(
            &finish_response,
            &finish_response.payload.access.server_identity,
        )
        .await?;

        if finish_response.payload.access.nonce != finish_nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store
            .token
            .access
            .store(finish_response.payload.response.access.token)
            .await?;

        Ok(())
    }

    pub async fn refresh_session(&self) -> Result<(), String> {
        let (signing_key, rotation_hash) = self.store.key.access.next().await?;
        let nonce = self.crypto.noncer.generate_128().await?;

        let mut request = RefreshSessionRequest::new(
            RefreshSessionRequestData {
                access: RefreshSessionAccess {
                    public_key: signing_key.public().await?,
                    rotation_hash,
                    token: self.store.token.access.get().await?,
                },
            },
            nonce.clone(),
        );

        request.sign(signing_key.as_ref()).await?;

        let message = request.to_json().await?;
        let reply = self
            .io
            .network
            .send_request(&self.paths.session.refresh, &message)
            .await?;

        let response = RefreshSessionResponse::parse(&reply)?;
        self.verify_response(&response, &response.payload.access.server_identity)
            .await?;

        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        self.store
            .token
            .access
            .store(response.payload.response.access.token)
            .await?;

        self.store.key.access.rotate().await?;

        Ok(())
    }

    pub async fn make_access_request<T: serde::Serialize + Send + Sync>(
        &self,
        path: &str,
        request: T,
    ) -> Result<String, String> {
        let nonce = self.crypto.noncer.generate_128().await?;
        let timestamp = self
            .encoding
            .timestamper
            .format(self.encoding.timestamper.now());
        let token = self.store.token.access.get().await?;

        let mut access_request = AccessRequest::new(AccessRequestPayload {
            access: AccessRequestAccess {
                nonce: nonce.clone(),
                timestamp,
                token,
            },
            request,
        });

        let signer = self.store.key.access.signer().await?;
        access_request.sign(signer.as_ref()).await?;

        let message = access_request.to_json().await?;
        let reply = self.io.network.send_request(path, &message).await?;

        let response = ScannableResponse::parse(&reply)?;
        if response.payload.access.nonce != nonce {
            return Err("incorrect nonce".to_string());
        }

        Ok(reply)
    }
}
