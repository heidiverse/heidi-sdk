use std::{fmt, unimplemented};

use kapun_util_rust::value::Value;

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum VerificationProblem {
    EncodingIssuer,
    SignatureInvalid,
}
impl fmt::Display for VerificationProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationProblem::EncodingIssuer => f.write_str("Issue with encoding"),
            VerificationProblem::SignatureInvalid => f.write_str("signature invalid"),
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Signing: Send + Sync {
    fn sign(&self, data: Vec<u8>) -> Vec<u8>;
    fn sign_hash(&self, hash: Vec<u8>) -> Vec<u8>;
    fn sign_hash_context(&self, _hash: Vec<u8>, _context: Vec<u8>) -> Vec<u8> {
        unimplemented!("Not available");
    }
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Verifying: Send + Sync {
    fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<(), VerificationProblem>;
    fn verify_hash(&self, hash: Vec<u8>, signature: Vec<u8>) -> Result<(), VerificationProblem>;
    fn verify_hash_context(
        &self,
        hash: Vec<u8>,
        context: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), VerificationProblem>;
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Metadata: Send + Sync {
    fn jose_alg(&self) -> Option<String> {
        None
    }
    fn oid(&self) -> Option<Vec<u8>> {
        None
    }
    fn additional(&self) -> Option<Value> {
        None
    }
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait KeyEncoding: Send + Sync {
    fn private_jwk(&self) -> Option<String> {
        None
    }
    fn public_jwk(&self) -> Option<String> {
        None
    }
    fn private_pkcs8_der(&self) -> Option<Vec<u8>> {
        None
    }
    fn private_pkcs8_pem(&self) -> Option<String> {
        None
    }
    fn public_spki_der(&self) -> Option<Vec<u8>> {
        None
    }
    fn public_spki_pem(&self) -> Option<String> {
        None
    }
}
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
