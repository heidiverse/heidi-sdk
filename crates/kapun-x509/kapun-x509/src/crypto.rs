use kapun_crypto_provider::KapunCryptoProvider;

use kapun_crypto_provider::oid_registry::Oid;
use x509_parser::{der_parser::oid, prelude::X509Certificate};

pub const OID_SIG_MLDSA44: Oid<'static> = oid!(2.16.840.1.101.3.4.3.17);
pub const OID_SIG_MLDSA65: Oid<'static> = oid!(2.16.840.1.101.3.4.3.18);
pub const OID_SIG_MLDSA87: Oid<'static> = oid!(2.16.840.1.101.3.4.3.19);

#[derive(Debug, Clone, Copy)]
pub enum SignatureError {
    UnknownAlgorithm,
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedSignatureAlgorithm,
    Other,
}

pub fn verify_signature<Provider: KapunCryptoProvider>(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<(), SignatureError> {
    let signature = subject.signature_value.data.to_vec();
    let subject_alg = subject.signature_algorithm.algorithm.clone();

    let verifier = Provider::verifier_for_oid(issuer.public_key().raw.to_vec(), subject_alg)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    verifier
        .kapun_verify(subject.tbs_certificate.as_ref().to_vec(), signature)
        .map_err(|_| SignatureError::InvalidSignature)?;

    Ok(())
}
