use ed25519_dalek::{Signature, VerifyingKey};
use unsigned_varint::decode as varint;

#[derive(Debug, Clone, uniffi::Object)]
pub struct EdDsaPublicKey {
    inner: VerifyingKey,
}

#[derive(Debug, Clone, uniffi::Error)]
pub enum EdDsaError {
    DecodeError(String),
    VerificationError(String),
}

impl std::fmt::Display for EdDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdDsaError::DecodeError(e) => f.write_str(&format!("EdDsaError::DecodeError: {e}")),
            EdDsaError::VerificationError(e) => {
                f.write_str(&format!("EdDsaError::VerificationError: {e}"))
            }
        }
    }
}

#[uniffi::export]
impl EdDsaPublicKey {
    #[uniffi::constructor]
    pub fn from_multibase(str: &str) -> Result<Self, EdDsaError> {
        let (_base, decoded) =
            multibase::decode(str).map_err(|e| EdDsaError::DecodeError(e.to_string()))?;
        let (prefix, key_bytes) = varint::u64(&decoded).unwrap();
        if prefix != 0xed {
            return Err(EdDsaError::DecodeError(
                "Invalid key prefix, expected 0xed".to_string(),
            ));
        }
        let key_bytes: &[u8; 32] = &key_bytes
            .try_into()
            .map_err(|_| EdDsaError::DecodeError("Invalid key length".to_string()))?;
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| EdDsaError::DecodeError(e.to_string()))?;
        Ok(EdDsaPublicKey { inner: key })
    }

    pub fn verify(&self, message: Vec<u8>, signature: &str) -> Result<bool, EdDsaError> {
        let (_base, decoded) =
            multibase::decode(signature).map_err(|e| EdDsaError::DecodeError(e.to_string()))?;
        let bytes: &[u8; 64] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| EdDsaError::DecodeError("Invalid signature length".to_string()))?;
        let signature = Signature::from_bytes(bytes);

        self.inner
            .verify_strict(&message, &signature)
            .map(|_| true)
            .map_err(|e| EdDsaError::VerificationError(e.to_string()))
    }
}
