use josekit::{JoseError, jwe::alg::pbes2_hmac_aeskw::MessageDigest};
use oid_registry::{
    OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA,
    OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
    OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED448, OID_SIG_ED25519, Oid,
};
use rsa::pkcs8::DecodePublicKey;
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

impl From<JoseError> for SignatureError {
    fn from(value: JoseError) -> Self {
        match value {
            JoseError::UnsupportedSignatureAlgorithm(error) => {
                tracing::error!("{error}");
                Self::UnsupportedSignatureAlgorithm
            }
            JoseError::InvalidKeyFormat(error) => {
                tracing::error!("{error}");
                Self::InvalidPublicKey
            }
            JoseError::InvalidSignature(error) => {
                tracing::error!("{error}");
                Self::InvalidSignature
            }
            _ => Self::Other,
        }
    }
}

pub fn verify_signature(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<(), SignatureError> {
    let signature = subject.signature_value.data.to_vec();
    let subject_alg = subject.signature_algorithm.algorithm.clone();
    if subject_alg == OID_PKCS1_SHA256WITHRSA {
        tracing::info!("verifying rsa pkcs");
        let verifier = josekit::jws::RS256.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_PKCS1_SHA384WITHRSA {
        tracing::info!("verifying rsa pkcs");
        let verifier = josekit::jws::RS384.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_PKCS1_SHA512WITHRSA {
        tracing::info!("verifying rsa pkcs");
        let verifier = josekit::jws::RS512.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_PKCS1_RSASSAPSS {
        tracing::info!("verifying rsassa pss");
        let verifier = josekit::jws::PS256.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_SIG_ECDSA_WITH_SHA256 {
        tracing::info!("verifying ecdsa");
        let verifier = josekit::jws::ES256.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_SIG_ECDSA_WITH_SHA384 {
        tracing::info!("verifying ecdsa");
        let verifier = josekit::jws::ES384.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_SIG_ECDSA_WITH_SHA512 {
        tracing::info!("verifying ecdsa");
        let verifier = josekit::jws::ES512.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_SIG_ED25519 || subject_alg == OID_SIG_ED448 {
        tracing::info!("verifying eddsa");
        let verifier = josekit::jws::EdDSA.verifier_from_der(issuer.public_key().raw)?;
        verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
    } else if subject_alg == OID_PKCS1_SHA1WITHRSA {
        tracing::warn!("verifying RSA with sha1");
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(&issuer.public_key().raw).map_err(|e| {
                tracing::error!("{e}");
                SignatureError::InvalidPublicKey
            })?;
        use rsa::{Pkcs1v15Sign, traits::SignatureScheme};
        use sha1::Sha1;

        let verifier = Pkcs1v15Sign::new::<Sha1>();
        let md = MessageDigest::sha1();
        verifier
            .verify(
                &public_key,
                &md.hash(subject.tbs_certificate.as_ref()),
                &signature,
            )
            .map_err(|e| {
                tracing::error!("{e}");
                SignatureError::InvalidSignature
            })?;
    } else if subject_alg == OID_SIG_MLDSA44 {
        #[cfg(feature = "pqc")]
        {
            tracing::info!("verifying ml-dsa");
            let verifier = josekit::jws::MlDSA44.verifier_from_der(issuer.public_key().raw)?;
            verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
        }
        #[cfg(not(feature = "pqc"))]
        {
            tracing::error!(
                "found certificate with ML-DSA signature and the feature is disabled. Rebuild the library with the `pqc` feature enabled"
            );
            return Err(SignatureError::UnknownAlgorithm);
        }
    } else if subject_alg == OID_SIG_MLDSA65 {
        #[cfg(feature = "pqc")]
        {
            tracing::info!("verifying ml-dsa");
            let verifier = josekit::jws::MlDSA65.verifier_from_der(issuer.public_key().raw)?;
            verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
        }
        #[cfg(not(feature = "pqc"))]
        {
            tracing::error!(
                "found certificate with ML-DSA signature and the feature is disabled. Rebuild the library with the `pqc` feature enabled"
            );
            return Err(SignatureError::UnknownAlgorithm);
        }
    } else if subject_alg == OID_SIG_MLDSA87 {
        #[cfg(feature = "pqc")]
        {
            tracing::info!("verifying ml-dsa");
            let verifier = josekit::jws::MlDSA87.verifier_from_der(issuer.public_key().raw)?;
            verifier.verify(subject.tbs_certificate.as_ref(), signature.as_ref())?;
        }
        #[cfg(not(feature = "pqc"))]
        {
            tracing::error!(
                "found certificate with ML-DSA signature and the feature is disabled. Rebuild the library with the `pqc` feature enabled"
            );
            return Err(SignatureError::UnknownAlgorithm);
        }
    } else {
        tracing::error!("unsupported algorithm {}", subject_alg);
        return Err(SignatureError::UnknownAlgorithm);
    }

    Ok(())
}
