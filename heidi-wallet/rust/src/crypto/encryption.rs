use josekit::jwk;

use crate::{
    issuance::models::CredentialResponseEncryptionSpecification, jwx::EncryptionParameters,
};

pub trait ContentDecryptor: Send + Sync {
    fn public_key(&self) -> jwk::Jwk;
    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification;
    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<String>;
}

impl ContentDecryptor for EncryptionParameters {
    fn public_key(&self) -> jwk::Jwk {
        self.jwk.clone()
    }

    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification {
        CredentialResponseEncryptionSpecification {
            jwk: self.jwk.clone(),
            enc: self.authorization_encrypted_response_enc.clone(),
            alg: self.authorization_encrytped_response_alg.clone(),
        }
    }

    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<String> {
        let (jwt_payload, _) = self.decrypt(encrypted_token_response)?;
        serde_json::to_string(jwt_payload.as_ref()).map_err(|e| anyhow::anyhow!(e))
    }
}
