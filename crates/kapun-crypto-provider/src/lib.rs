use std::{fmt, unimplemented};

pub use kapun_util_rust::value::Value as KapunValue;
pub use oid_registry;
use oid_registry::Oid;

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

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum SigningProblem {
    SigningFailed,
}
impl fmt::Display for SigningProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningProblem::SigningFailed => f.write_str("Signing failed"),
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Signing: Send + Sync {
    fn kapun_sign(&self, data: Vec<u8>) -> Result<Vec<u8>, SigningProblem>;
    fn kapun_sign_hash(&self, hash: Vec<u8>) -> Result<Vec<u8>, SigningProblem>;
    fn kapun_sign_hash_context(
        &self,
        _hash: Vec<u8>,
        _context: Vec<u8>,
    ) -> Result<Vec<u8>, SigningProblem> {
        unimplemented!("Not available");
    }
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Verifying: Send + Sync {
    fn kapun_verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<(), VerificationProblem>;
    fn kapun_verify_hash(
        &self,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), VerificationProblem>;
    fn kapun_verify_hash_context(
        &self,
        _hash: Vec<u8>,
        _context: Vec<u8>,
        _signature: Vec<u8>,
    ) -> Result<(), VerificationProblem> {
        unimplemented!("Not available");
    }
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait Metadata: Send + Sync {
    fn kapun_jose_alg(&self) -> Option<String> {
        None
    }
    fn kapun_oid(&self) -> Option<Vec<u8>> {
        None
    }
    fn kapun_additional(&self) -> Option<KapunValue> {
        None
    }
}
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait KeyEncoding: Send + Sync {
    fn kapun_private_jwk(&self) -> Option<String> {
        None
    }
    fn kapun_public_jwk(&self) -> Option<String> {
        None
    }
    fn kapun_private_pkcs8_der(&self) -> Option<Vec<u8>> {
        None
    }
    fn kapun_private_pkcs8_pem(&self) -> Option<String> {
        None
    }
    fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
        None
    }
    fn kapun_public_spki_pem(&self) -> Option<String> {
        None
    }
}

pub trait KapunCryptoProvider {
    fn verifier(key_data: Vec<u8>) -> Box<dyn Verifier>;
    fn verifier_for_oid(key_data: Vec<u8>, _oid: Oid<'static>) -> Box<dyn Verifier> {
        Self::verifier(key_data)
    }
    fn signer(key_data: Vec<u8>) -> Box<dyn Signer>;
    fn signer_for_oid(key_data: Vec<u8>, _oid: Oid<'static>) -> Box<dyn Signer> {
        Self::signer(key_data)
    }
}

pub trait Verifier: Verifying + KeyEncoding + Metadata {}
pub trait Signer: Signing + KeyEncoding + Metadata {}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
