use anyhow::Context;
use josekit::jwk;

use crate::{
    issuance::models::CredentialResponseEncryptionSpecification, jwx::EncryptionParameters,
};

pub trait ContentEncryptor: Send + Sync {
    fn encrypt(&self, claims: serde_json::Map<String, serde_json::Value>)
        -> anyhow::Result<String>;
}

pub trait CloneableEncryptor<T>: Send + Sync
where
    T: Clone + ContentEncryptor,
{
    fn clone_inner(&self) -> Box<dyn ContentEncryptor>;
}

impl CloneableEncryptor<EncryptionParameters> for EncryptionParameters {
    fn clone_inner(&self) -> Box<dyn ContentEncryptor> {
        Box::new(EncryptionParameters::clone(self))
    }
}

impl ContentEncryptor for EncryptionParameters {
    fn encrypt(
        &self,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> anyhow::Result<String> {
        self.encrypt(claims, None, None)
            .context("failed to encrypt")
    }
}

pub trait ContentDecryptor: Send + Sync {
    fn public_key(&self) -> jwk::Jwk;
    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification;
    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<String>;
}

pub trait CloneableDecryptor<T>: Send + Sync
where
    T: Clone + ContentDecryptor,
{
    fn clone_inner(&self) -> Box<dyn ContentDecryptor>;
}

impl CloneableDecryptor<EncryptionParameters> for EncryptionParameters {
    fn clone_inner(&self) -> Box<dyn ContentDecryptor> {
        Box::new(EncryptionParameters::clone(self))
    }
}

impl ContentDecryptor for EncryptionParameters {
    fn public_key(&self) -> jwk::Jwk {
        self.jwk
            .to_public_key()
            .expect("somethings terribly wrong with the jwk")
            .clone()
    }

    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification {
        CredentialResponseEncryptionSpecification {
            jwk: self
                .jwk
                .to_public_key()
                .expect("somethings terribly wrong with the jwk"),
            enc: self.authorization_encrypted_response_enc.clone(),
        }
    }

    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<String> {
        let (jwt_payload, _) = self.decrypt(encrypted_token_response)?;
        serde_json::to_string(jwt_payload.as_ref()).map_err(|e| anyhow::anyhow!(e))
    }
}
