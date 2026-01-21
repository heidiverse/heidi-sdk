use std::{collections::HashMap, fmt::Display};

use heidi_util_rust::value::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofPurpose {
    /// Indicates that a given proof is only to be used for the purposes of an authentication
    /// protocol.
    #[serde(rename = "authentication")]
    Authentication,

    /// Indicates that a proof can only be used for making assertions, for example signing a
    /// verifiable credential.
    #[serde(rename = "assertionMethod")]
    AssertionMethod,

    /// Indicates that a proof is used for for key agreement protocols, such as Elliptic Curve
    /// Diffie Hellman key agreement used by popular encryption libraries.
    #[serde(rename = "keyAgreement")]
    KeyAgreement,

    /// Indicates that the proof can only be used for delegating capabilities. See the Authorization
    /// Capabilities [ZCAP] specification for more detail.
    #[serde(rename = "capabilityDelegation")]
    CapabilityDelegation,

    /// Indicates that the proof can only be used for invoking capabilities. See the Authorization
    /// Capabilities [ZCAP] specification for more detail.
    #[serde(rename = "capabilityInvocation")]
    CapabilityInvocation,
}

/// A data integrity as per https://www.w3.org/TR/vc-data-integrity/#proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    /// An optional identifier for the proof, which MUST be a URL [URL], such as a UUID as a URN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The specific type of proof MUST be specified as a string that maps to a URL [URL]. Examples
    /// of proof types include DataIntegrityProof and Ed25519Signature2020. Proof types determine
    /// what other fields are required to secure and verify the proof.
    #[serde(rename = "type")]
    pub r#type: String,

    /// The reason the proof was created MUST be specified as a string that maps to a URL [URL]. The
    /// proof purpose acts as a safeguard to prevent the proof from being misused by being applied
    /// to a purpose other than the one that was intended. For example, without this value the
    /// creator of a proof could be tricked into using cryptographic material typically used to
    /// create a Verifiable Credential (assertionMethod) during a login process (authentication)
    /// which would then result in the creation of a verifiable credential they never meant to
    /// create instead of the intended action, which was to merely log in to a website.
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    /// A verification method is the means and information needed to verify the proof. If included,
    /// the value MUST be a string that maps to a [URL]. Inclusion of verificationMethod is OPTIONAL,
    /// but if it is not included, other properties such as cryptosuite might provide a mechanism
    /// by which to obtain the information necessary to verify the proof. Note that when
    /// verificationMethod is expressed in a data integrity proof, the value points to the actual
    /// location of the data; that is, the verificationMethod references, via a URL, the location of
    /// the public key that can be used to verify the proof. This public key data is stored in a
    /// controlled identifier document, which contains a full description of the verification method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,

    /// An identifier for the cryptographic suite that can be used to verify the proof. See
    /// 3. Cryptographic Suites for more information. If the proof type is DataIntegrityProof,
    /// cryptosuite MUST be specified; otherwise, cryptosuite MAY be specified. If specified,
    /// its value MUST be a string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// The date and time the proof was created is OPTIONAL and, if included, MUST be specified as
    /// an [XMLSCHEMA11-2] dateTimeStamp string, either in Universal Coordinated Time (UTC), denoted
    /// by a Z at the end of the value, or with a time zone offset relative to UTC. A conforming
    /// processor MAY chose to consume time values that were incorrectly serialized without an
    /// offset. Incorrectly serialized time values without an offset are to be interpreted as UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// The expires property is OPTIONAL and, if present, specifies when the proof expires. If
    /// present, it MUST be an [XMLSCHEMA11-2] dateTimeStamp string, either in Universal Coordinated
    /// Time (UTC), denoted by a Z at the end of the value, or with a time zone offset relative to
    /// UTC. A conforming processor MAY chose to consume time values that were incorrectly
    /// serialized without an offset. Incorrectly serialized time values without an offset are to be
    /// interpreted as UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// The domain property is OPTIONAL. It conveys one or more security domains in which the proof
    /// is meant to be used. If specified, the associated value MUST be either a string, or an
    /// unordered set of strings. A verifier SHOULD use the value to ensure that the proof was
    /// intended to be used in the security domain in which the verifier is operating. The
    /// specification of the domain parameter is useful in challenge-response protocols where the
    /// verifier is operating from within a security domain known to the creator of the proof.
    /// Example domain values include:
    /// * domain.example (DNS domain)
    /// * https://domain.example:8443 (Web origin)
    /// * mycorp-intranet (bespoke text string)
    /// * b31d37d4-dd59-47d3-9dd8-c973da43b63a (UUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<OneOrMany<String>>,

    /// A string value that SHOULD be included in a proof if a domain is specified. The value is
    /// used once for a particular domain and window of time. This value is used to mitigate replay
    /// attacks. Examples of a challenge value include:
    /// * 1235abcd6789
    /// * 79d34551-ae81-44ae-823b-6dadbab9ebd4
    /// * ruby
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// A string value that expresses base-encoded binary data necessary to verify the digital proof
    /// using the verificationMethod specified. The value MUST use a header and encoding as
    /// described in Section 2.4 Multibase of the Controlled Identifiers v1.0 specification to
    /// express the binary data. The contents of this value are determined by a specific cryptosuite
    /// and set to the proof value generated by the Add Proof Algorithm for that cryptosuite.
    /// Alternative properties with different encodings specified by the cryptosuite MAY be used,
    /// instead of this property, to encode the data necessary to verify the digital proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "proofValue")]
    pub proof_value: Option<String>,

    /// The previousProof property is OPTIONAL. If present, it MUST be a string value or an
    /// unordered list of string values. Each value identifies another data integrity proof, all of
    /// which MUST also verify for the current proof to be considered verified. This property is
    /// used in Section 2.1.2 Proof Chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<OneOrMany<String>>,

    /// An OPTIONAL string value supplied by the proof creator. One use of this field is to increase
    /// privacy by decreasing linkability that is the result of deterministically generated
    /// signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// A controlled identifier document as per https://www.w3.org/TR/cid-1.0/#controlled-identifier-documents
///
/// Note: This is a partial representation focusing on fields relevant to proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlledIdentifierDocument {
    /// A string that conforms to the URL syntax.
    pub id: String,

    /// A set of verification method maps.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "verificationMethod")]
    pub verification_method: Option<OneOrMany<VerificationMethod>>,
}

// A verification method as per https://www.w3.org/TR/cid-1.0/#verification-methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// he value of the id property for a verification method MUST be a string that conforms to the
    /// [URL] syntax. This value is called the verification method identifier and can also be used
    /// in a proof to refer to a specific instance of a verification method, which is called the
    /// verification method definition.
    pub id: String,

    /// The value of the type property MUST be a string that references exactly one verification
    /// method type. This specification defines the types JsonWebKey (see Section 2.2.3 JsonWebKey)
    /// and Multikey (see Section 2.2.2 Multikey).
    #[serde(rename = "type")]
    pub r#type: String,

    /// The value of the controller property MUST be a string that conforms to the [URL] syntax.
    pub controller: String,

    /// The expires property is OPTIONAL. If provided, it MUST be an [XMLSCHEMA11-2] dateTimeStamp
    /// string specifying when the verification method SHOULD cease to be used. Once the value is
    /// set, it is not expected to be updated, and systems depending on the value are expected to
    /// not verify any proofs associated with the verification method at or after the time of
    /// expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// The revoked property is OPTIONAL. If present, it MUST be an [XMLSCHEMA11-2] dateTimeStamp
    /// string specifying when the verification method MUST NOT be used. Once the value is set, it
    /// is not expected to be updated, and systems depending on the value are expected to not verify
    /// any proofs associated with the verification method at or after the time of revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,

    #[serde(flatten)]
    pub data: HashMap<String, JsonValue>,
}

trait ElementGetter {
    fn get_first(&self, key: &str) -> Option<&JsonValue>;
}

impl ElementGetter for JsonValue {
    fn get_first(&self, key: &str) -> Option<&JsonValue> {
        let map = self.as_object()?;
        let value = map.get(key)?;

        match value {
            JsonValue::Array(arr) => arr.first(),
            _ => Some(value),
        }
    }
}

#[derive(Debug, uniffi::Error)]
pub enum ProofVerificationError {
    NoProof,
    DocumentNotAnObject,
    ProofNotAnObject,
    UnsupportedCryptosuite,
    InvalidCryptosuite,
    NoProofValue,
    ProofValueNotAString,
    NotDataIntegrityProof,
    NoVerificationMethod,
    InvalidVerificationMethod(String),
    InvalidProof(String),
    InvalidPublicKey(String),
    JsonError(String),
    MultibaseDecodeError(String),
    JoinError(String),
    NetworkError(String),
}

impl Display for ProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub async fn verify_secured_document_proof(
    secured_document: JsonValue,
) -> Result<(), ProofVerificationError> {
    // Let unsecuredDocument be a copy of securedDocument with the proof value removed.
    let unsecured_document = {
        let mut doc = secured_document
            .as_object()
            .ok_or_else(|| ProofVerificationError::DocumentNotAnObject)?
            .clone();
        doc.remove("proof");
        JsonValue::Object(doc)
    };

    // Let proofOptions be the result of a copy of securedDocument.proof with proofValue removed.
    let (proof_options, proof_value) = {
        let mut proof = secured_document
            .get_first("proof")
            .ok_or(ProofVerificationError::NoProof)?
            .as_object()
            .ok_or(ProofVerificationError::ProofNotAnObject)?
            .clone();
        let proof_value = proof
            .remove("proofValue")
            .map(|v| match v {
                JsonValue::String(string) => Ok(string),
                _ => Err(ProofVerificationError::ProofValueNotAString),
            })
            .transpose()?;
        (JsonValue::Object(proof), proof_value)
    };

    match proof_options["cryptosuite"].as_str() {
        Some("eddsa-rdfc-2022") => {
            eddsa_rdfc_2022::verify(unsecured_document, proof_options, proof_value).await?;
        }
        _ => return Err(ProofVerificationError::UnsupportedCryptosuite),
    }

    Ok(())
}

async fn retrieve_public_key(
    verification_method: String,
) -> Result<String, ProofVerificationError> {
    let (document_url, _fragment) = verification_method.split_once('#').ok_or(
        ProofVerificationError::InvalidVerificationMethod(
            "Missing fragment in verificationMethod".to_string(),
        ),
    )?;

    let doc = reqwest::get(document_url)
        .await
        .map_err(|e| ProofVerificationError::NetworkError(e.to_string()))?
        .json::<ControlledIdentifierDocument>()
        .await
        .map_err(|e| ProofVerificationError::JsonError(e.to_string()))?;

    let methods = doc
        .verification_method
        .ok_or(ProofVerificationError::InvalidVerificationMethod(
            "No verification methods found".to_string(),
        ))?
        .into_vec();

    // TODO: Validate stuff

    let method = methods
        .into_iter()
        .find(|m| m.id == verification_method)
        .ok_or(ProofVerificationError::InvalidVerificationMethod(
            "Verification method not found".to_string(),
        ))?;

    let public_key_multibase = method
        .data
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        .ok_or(ProofVerificationError::InvalidVerificationMethod(
            "publicKeyMultibase not found".to_string(),
        ))?;

    Ok(public_key_multibase.to_string())
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn verify_secured_document_string(document: String) -> bool {
    let Ok(json) = serde_json::from_str::<JsonValue>(&document) else {
        return false;
    };
    verify_secured_document_proof(json).await.is_ok()
}

mod eddsa_rdfc_2022 {
    use heidi_crypto_rust::crypto::{eddsa::EdDsaPublicKey, sha256};
    use json_ld::{ChainLoader, ReqwestLoader};
    use serde_json::Value as JsonValue;
    use tokio::{
        runtime::Handle,
        task::{JoinError, LocalSet},
    };

    use crate::{
        json_ld::{JsonLdDocument, loader::StaticLoader},
        ldp::{ProofVerificationError, retrieve_public_key},
        w3c::CONTEXT_W3C_VCDM2,
    };

    pub async fn verify(
        unsecured_document: JsonValue,
        proof_options: JsonValue,
        proof_value: Option<String>,
    ) -> Result<(), ProofVerificationError> {
        let proof_value = proof_value.ok_or(ProofVerificationError::NoProofValue)?;

        // Let transformedData be the result of running the algorithm in Section 3.2.3 Transformation
        // (eddsa-rdfc-2022) with unsecuredDocument and proofOptions passed as parameters.
        let transformed_data = transform(&unsecured_document, &proof_options).await?;

        // Let proofConfig be the result of running the algorithm in Section 3.2.5 Proof
        // Configuration (eddsa-rdfc-2022) with unsecuredDocument and proofOptions passed as
        // parameters.
        let proof_config = proof_config(&unsecured_document, &proof_options).await?;

        // Let hashData be the result of running the algorithm in Section 3.2.4 Hashing
        // (eddsa-rdfc-2022) with transformedData and proofConfig passed as a parameters.
        let hash_data = hash(transformed_data, proof_config);

        // Let verified be the result of running the algorithm in Section 3.2.7 Proof Verification
        // (eddsa-rdfc-2022) algorithm on hashData, proofBytes, and proofConfig.
        verify_proof(hash_data, proof_value, proof_options).await?;

        Ok(())
    }

    async fn transform(
        unsecured_document: &JsonValue,
        options: &JsonValue,
    ) -> Result<String, ProofVerificationError> {
        // If options.type is not set to the string DataIntegrityProof and options.cryptosuite is
        // not set to the string eddsa-rdfc-2022, an error MUST be raised
        if options["type"].as_str().as_deref() != Some("DataIntegrityProof") {
            return Err(ProofVerificationError::NotDataIntegrityProof);
        }

        if options["cryptosuite"].as_str().as_deref() != Some("eddsa-rdfc-2022") {
            return Err(ProofVerificationError::UnsupportedCryptosuite);
        }

        // Let canonicalDocument be the result of converting unsecuredDocument to RDF statements,
        // applying the RDF Dataset Canonicalization Algorithm [RDF-CANON] to the result, and then
        // serializing the result to a serialized canonical form [RDF-CANON].
        let canonical_document = canonicalize(
            serde_json::to_string(&unsecured_document)
                .map_err(|e| ProofVerificationError::JsonError(e.to_string()))?,
        )
        .await
        .map_err(|e| ProofVerificationError::JoinError(e.to_string()))?;

        // Return canonicalDocument as the transformed data document.
        Ok(canonical_document)
    }

    async fn proof_config(
        unsecured_document: &JsonValue,
        options: &JsonValue,
    ) -> Result<String, ProofVerificationError> {
        // Let proofConfig be a clone of the options object.
        let mut proof_config = options.clone();

        // If proofConfig.type is not set to DataIntegrityProof and/or proofConfig.cryptosuite is
        // not set to eddsa-rdfc-2022, an error MUST be raised.
        if options["type"].as_str().as_deref() != Some("DataIntegrityProof") {
            return Err(ProofVerificationError::NotDataIntegrityProof);
        }

        if options["cryptosuite"].as_str().as_deref() != Some("eddsa-rdfc-2022") {
            return Err(ProofVerificationError::UnsupportedCryptosuite);
        }

        // TODO: Check for created and exires fields and validity

        // Set proofConfig.@context to unsecuredDocument.@context.
        proof_config["@context"] = unsecured_document["@context"].clone();

        // Let canonicalProofConfig be the result of applying the RDF Dataset Canonicalization
        // Algorithm [RDF-CANON] to the proofConfig.
        let canonical_proof_config = canonicalize(
            serde_json::to_string(&proof_config)
                .map_err(|e| ProofVerificationError::JsonError(e.to_string()))?,
        )
        .await
        .map_err(|e| ProofVerificationError::JoinError(e.to_string()))?;

        // Return canonicalProofConfig.
        Ok(canonical_proof_config)
    }

    async fn canonicalize(document: String) -> Result<String, JoinError> {
        tokio::task::spawn_blocking(move || {
            let handle = Handle::current();
            let local = LocalSet::new();

            // Use the handle to block, and let the local set run the future
            handle.block_on(local.run_until(async move {
                let loader = ChainLoader::new(
                    StaticLoader::new()
                        .with_document("https://www.w3.org/ns/credentials/v2", CONTEXT_W3C_VCDM2),
                    ReqwestLoader::new(),
                );
                JsonLdDocument::new(&document, &loader)
                    .to_canonical_rdf()
                    .await
            }))
        })
        .await
    }

    fn hash(transformed_data: String, proof_config: String) -> Vec<u8> {
        // Let proofConfigHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        // cryptographic hashing algorithm [RFC6234] to the canonicalProofConfig. proofConfigHash
        // will be exactly 32 bytes in size.
        let proof_config_hash = sha256(&proof_config.as_bytes());

        // Let transformedDocumentHash be the result of applying the SHA-256 (SHA-2 with 256-bit
        // output) cryptographic hashing algorithm [RFC6234] to the transformedDocument.
        // transformedDocumentHash will be exactly 32 bytes in size.
        let transformed_document_hash = sha256(&transformed_data.as_bytes());

        // Let hashData be the result of concatenating proofConfigHash (the first hash produced
        // above) followed by transformedDocumentHash (the second hash produced above).
        let mut hash_data = Vec::<u8>::with_capacity(64);
        hash_data.extend_from_slice(&proof_config_hash);
        hash_data.extend_from_slice(&transformed_document_hash);

        // Return hashData as the hash data.
        hash_data
    }

    async fn verify_proof(
        hash_data: Vec<u8>,
        proof_multibase: String,
        proof_options: JsonValue,
    ) -> Result<(), ProofVerificationError> {
        // Let publicKeyBytes be the result of retrieving the public key bytes associated with the
        // options.verificationMethod value as described in the Retrieve Verification Method section
        // of the Controlled Identifiers v1.0 specification.
        let verification_method = proof_options["verificationMethod"]
            .as_str()
            .ok_or(ProofVerificationError::NoVerificationMethod)?;
        let public_key_multibase = retrieve_public_key(verification_method.to_string()).await?;
        let public_key = EdDsaPublicKey::from_multibase(&public_key_multibase)
            .map_err(|e| ProofVerificationError::InvalidPublicKey(e.to_string()))?;

        // Let verificationResult be the result of applying the verification algorithm for the
        // Edwards-Curve Digital Signature Algorithm (EdDSA) [RFC8032], using the Ed25519 variant
        // (Pure EdDSA), with hashData as the data to be verified against the proofBytes using the
        // public key specified by publicKeyBytes.
        let valid = public_key
            .verify(hash_data, &proof_multibase)
            .map_err(|e| ProofVerificationError::InvalidProof(e.to_string()))?;

        if !valid {
            return Err(ProofVerificationError::InvalidProof(
                "Proof verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::ldp::DataIntegrityProof;

    #[test]
    fn test_parse_proof_example_2() {
        let example = r#"
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2023-03-05T19:23:24Z",
            "verificationMethod": "https://di.example/issuer#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG",
            "proofPurpose": "assertionMethod",
            "proofValue": "zQeVbY4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYV8nQApmEcqaqA3Q1gVHMrXFkXJeV6doDwLWx"
        }"#;

        assert!(serde_json::from_str::<DataIntegrityProof>(example).is_ok());
    }

    #[test]
    fn test_parse_proof_example_4() {
        let example = r#"
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-rdfc-2019",
            "created": "2020-06-11T19:14:04Z",
            "verificationMethod": "https://ldi.example/issuer#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            "proofPurpose": "assertionMethod",
            "proofValue": "zXb23ZkdakfJNUhiTEdwyE598X7RLrkjnXEADLQZ7vZyUGXX8cyJZRBkNw813SGsJHWrcpo4Y8hRJ7adYn35Eetq"
        }"#;

        assert!(serde_json::from_str::<DataIntegrityProof>(example).is_ok());
    }

    #[test]
    fn test_parse_proof_example_5() {
        let example = r#"
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-rdfc-2019",
            "created": "2020-06-11T19:14:04Z",
            "expires": "2020-07-11T19:14:04Z",
            "verificationMethod": "https://ldi.example/issuer#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            "proofPurpose": "assertionMethod",
            "proofValue": "z98X7RLrkjnXEADJNUhiTEdwyE5GXX8cyJZRLQZ7vZyUXb23ZkdakfRJ7adYY8hn35EetqBkNw813SGsJHWrcpo4"
        }"#;

        assert!(serde_json::from_str::<DataIntegrityProof>(example).is_ok());
    }

    #[test]
    fn test_parse_proof_example_7() {
        let example = r#"
        {
            "id": "urn:uuid:60102d04-b51e-11ed-acfe-2fcd717666a7",
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2020-11-05T19:23:42Z",
            "verificationMethod": "https://ldi.example/issuer/1#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG",
            "proofPurpose": "assertionMethod",
            "proofValue": "zVbY8nQAVHMrXFkXJpmEcqdoDwLWxaqA3Q1geV64oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYVQe"
        }"#;

        assert!(serde_json::from_str::<DataIntegrityProof>(example).is_ok());

        let example = r#"
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2020-11-05T21:28:14Z",
            "verificationMethod": "https://pfps.example/issuer/2#z6MkGskxnGjLrk3gKS2mesDpuwRBokeWcmrgHxUXfnncxiZP",
            "proofPurpose": "assertionMethod",
            "proofValue": "z6Qnzr5CG9876zNht8BpStWi8H2Mi7XCY3inbLrZrm955QLBrp19KiWXerb8ByPnAZ9wujVFN8PDsxxXeMoyvDqhZ",
            "previousProof": "urn:uuid:60102d04-b51e-11ed-acfe-2fcd717666a7"
        }"#;
        assert!(serde_json::from_str::<DataIntegrityProof>(example).is_ok());
    }

    const OPEN_BADGE_VC_1: &str = r#"
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
  ],
  "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ?v=3_0",
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  "name": "AI Act",
  "evidence": [],
  "issuer": {
    "id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0",
    "type": [
      "Profile"
    ],
    "name": "Open Educational Badges",
    "url": "https://openbadges.education",
    "email": "annika@mycelia.education"
  },
  "validFrom": "2025-12-04T08:37:40.379213+00:00",
  "credentialSubject": {
    "type": [
      "AchievementSubject"
    ],
    "identifier": [
      {
        "type": "IdentityObject",
        "identityHash": "sha256$79a12f688e1bd35f85ad4ee1c71b5d7c942ea289aecf616159a20dc0d5af2419",
        "identityType": "emailAddress",
        "hashed": true,
        "salt": "6800b252df744e47b9d9837371a1618a"
      }
    ],
    "achievement": {
      "id": "https://api.openbadges.education/public/badges/1l5y_22PSauVhLYihoqmVw?v=3_0",
      "type": [
        "Achievement"
      ],
      "name": "AI Act",
      "description": "Dieser Workshop bietet eine solide Einf\u00fchrung in KI mit besonderem Schwerpunkt auf dem Grundlagenwissen, das f\u00fcr einen verantwortungsvollen Umgang mit KI erforderlich ist - im Einklang mit den Anforderungen des EU-AI-Act. Die Teilnehmenden erhalten Einblicke in die Funktionsweise von KI-Systemen, wo ihre Grenzen und Risiken liegen und was eine verantwortungsvolle Nutzung in der Praxis bedeutet. Mit einer Mischung aus interaktivem Input und praktischer Reflexion st\u00e4rkt das Training das Vertrauen und das Bewusstsein f\u00fcr den Umgang mit der sich entwickelnden KI-Landschaft und gibt rechtliche Grundlagen.",
      "achievementType": "Badge",
      "criteria": {
        "narrative": ""
      },
      "image": {
        "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/image",
        "type": "Image"
      }
    },
    "activityStartDate": "2025-12-04T00:00:00+00:00",
    "activityLocation": {
      "type": [
        "Address"
      ],
      "addressLocality": "Z\u00fcrich",
      "postalCode": "8001"
    }
  },
  "credentialStatus": {
    "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/revocations",
    "type": "1EdTechRevocationList"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2025-12-04T08:37:40.379213+00:00",
      "verificationMethod": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0#key-0",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5hTkyXpMzQx671RKemdnj2GpmHCUthKY1KxYRVT8renbL81MTrnVbBGfR3QfwJVu8j32ZZdpvuwPvBVYxLEbuA5z"
    }
  ]
}
    "#;

    const OPEN_BADGE_VC_2: &str = r#"
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
  ],
  "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ?v=3_0",
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  "name": "Competent Developer",
  "evidence": [],
  "issuer": {
    "id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0",
    "type": [
      "Profile"
    ],
    "name": "Open Educational Badges",
    "url": "https://openbadges.education",
    "email": "annika@mycelia.education"
  },
  "validFrom": "2026-01-15T12:10:16.064699+00:00",
  "credentialSubject": {
    "type": [
      "AchievementSubject"
    ],
    "identifier": [
      {
        "type": "IdentityObject",
        "identityHash": "sha256$43542fe801368f236d83612930b5031532593f4691595c951f3b3c0f5ebf8590",
        "identityType": "emailAddress",
        "hashed": true,
        "salt": "cd56023d11e144a995542bcd90a2107f"
      }
    ],
    "achievement": {
      "id": "https://api.openbadges.education/public/badges/i_5bFW5cS1umulncJIoaKQ?v=3_0",
      "type": [
        "Achievement"
      ],
      "name": "Competent Developer",
      "description": "Implemented Open Badges in Heidi Wallet",
      "achievementType": "Badge",
      "criteria": {
        "narrative": ""
      },
      "image": {
        "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ/image",
        "type": "Image"
      }
    }
  },
  "validUntil": "2028-10-11T12:10:16.064530+00:00",
  "credentialStatus": {
    "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ/revocations",
    "type": "1EdTechRevocationList"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2026-01-15T12:10:16.064699+00:00",
      "verificationMethod": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0#key-0",
      "proofPurpose": "assertionMethod",
      "proofValue": "z3o81trEVFipGK3UxHfmYhJgiFz8pqHZyJqkCWo6oxvoZzqEJCb5xsPmDn6eNt92aNUgXQHqeY8gpsjkhPtp3PELq"
    }
  ]
}
"#;

    #[tokio::test]
    async fn test_verify_open_badge_vc() {
        let doc1 = serde_json::from_str::<serde_json::Value>(OPEN_BADGE_VC_1).unwrap();

        super::verify_secured_document_proof(doc1).await.unwrap();

        let doc2 = serde_json::from_str::<serde_json::Value>(OPEN_BADGE_VC_2).unwrap();

        super::verify_secured_document_proof(doc2).await.unwrap();
    }
}
