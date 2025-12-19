#![allow(async_fn_in_trait)]
use std::{collections::HashMap, sync::Arc};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use heidi_jwt::jwt::creator::JwtCreator;
use heidi_util_rust::value::Value;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with_macros::skip_serializing_none;

use crate::{
    builder_fn, crypto::b64url_encode_bytes, presentation::presentation_exchange::RFC7519Claims,
    signing::SecureSubject,
};

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PushedAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    // Additional authorization request parameters for OID4VCI https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-additional-request-paramete
    pub issuer_state: Option<String>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthorizationRequestReference {
    pub request_uri: String,
    pub expires_in: u32,
}

// Authorization Server Metadata as described here: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub response_modes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub service_documentation: Option<String>,
    pub ui_locales_supported: Option<Vec<String>>,
    pub op_policy_uri: Option<String>,
    pub op_tos_uri: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint: Option<String>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: Option<bool>,
    // Additional authorization server metadata parameters MAY also be used.
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    // Firstparty metadata
    #[serde(default)]
    pub first_party_usage: bool,
    pub authorization_challenge_endpoint: Option<String>,
}

/// Credential Issuer Metadata as described here:
/// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-issuer-metadata-p
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub batch_credential_endpoint: Option<String>,
    pub deferred_credential_endpoint: Option<String>,
    pub notification_endpoint: Option<String>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    pub credential_identifiers_supported: Option<bool>,
    pub signed_metadata: Option<String>,
    pub display: Option<Vec<Value>>,
    pub credential_configurations_supported:
        HashMap<String, CredentialConfigurationsSupportedObject>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

/// Credentials Supported object as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-11.2.3-2.11.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialConfigurationsSupportedObject {
    /// This field is flattened into a `format` field and optionally extra format-specific fields.
    #[serde(flatten)]
    pub credential_format: Value,
    // Use `Scope` from oid4vc-core/src/scope.rs.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub proof_types_supported: HashMap<ProofType, KeyProofMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ProofType {
    Jwt,
    Cwt,
    Attestation,
    #[serde(alias = "ldp_vp")]
    LdpVp,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct KeyProofMetadata {
    pub proof_signing_alg_values_supported: Vec<String>,
    pub key_attestations_required: Option<KeyAttestationMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct KeyAttestationMetadata {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub key_storage: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub user_authentication: Vec<String>,
}

/// Token Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-request
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "grant_type")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        code: String,
        code_verifier: Option<String>,
        redirect_uri: Option<String>,
        client_id: Option<String>,
    },
    #[serde(rename = "refresh_token")]
    TokenRefresh {
        client_id: Option<String>,
        refresh_token: String,
    },
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        tx_code: Option<String>,
    },
}

/// Token Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-successful-token-response
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<StringOrInt>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<StringOrInt>,
    // TODO: add `authorization_details` field when support for Authorization Code Flow is added.
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum StringOrInt {
    String(String),
    Int(u64),
}

impl From<StringOrInt> for u64 {
    fn from(value: StringOrInt) -> Self {
        match value {
            StringOrInt::String(s) => u64::from_str_radix(s.as_str(), 10).unwrap_or(0),
            StringOrInt::Int(i) => i,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "type")]
pub enum AuthorizationDetail {
    #[serde(rename = "openid_credential")]
    OpenIdCredential(OpenIdCredential),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct OpenIdCredential {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    #[serde(flatten)]
    pub format_specific_arguments: Value,
}

/// Grant Type `authorization_code` as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-4.1.1-4.1.1
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

/// Grant Type `pre-authorized_code` as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-4.1.1-4.2.1
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub tx_code: Option<TransactionCode>,
    pub interval: Option<i64>,
    pub authorization_server: Option<String>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TransactionCode {
    pub input_mode: Option<InputMode>,
    pub length: Option<u64>,
    pub description: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum InputMode {
    #[default]
    Numeric,
    Text,
}

/// Credential Offer Parameters as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-offer-parameters
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CredentialOfferParameters {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<Grants>,
}

/// Credential Offer as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-offer
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOffer {
    CredentialOfferUri(String),
    CredentialOffer(CredentialOfferParameters),
}

pub type JsonObject = serde_json::Map<String, serde_json::Value>;

impl std::str::FromStr for CredentialOffer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let map: JsonObject = s
            .parse::<Url>()?
            .query_pairs()
            .map(|(key, value)| {
                let value = serde_json::from_str::<serde_json::Value>(&value)
                    .unwrap_or(serde_json::Value::String(value.into_owned()));
                Ok((key.into_owned(), value))
            })
            .collect::<anyhow::Result<_>>()?;
        serde_json::from_value(serde_json::Value::Object(map)).map_err(Into::into)
    }
}

/// Grants as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-4.1.1-2.3
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCode>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CredentialProofs {
    #[serde(rename = "proof")]
    Proof(Option<KeyProofType>),
    #[serde(rename = "proofs")]
    Proofs(KeyProofsType),
    #[serde(skip)]
    NoProof,
}

impl CredentialProofs {
    pub fn is_none(&self) -> bool {
        matches!(self, CredentialProofs::NoProof)
    }
}

/// Key Proof Type (JWT or CWT) and the proof itself, as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#proof-types
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(tag = "proof_type")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyProofType {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    #[serde(rename = "cwt")]
    Cwt { cwt: String },
    #[serde(rename = "attestation")]
    Attestation { attestation: String },
}
impl KeyProofType {
    pub fn builder() -> ProofBuilder {
        ProofBuilder::default()
    }
}

// Key Proof_s_ type for multiple proof-of-posessions in the same credential request
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyProofsType {
    Jwt(Vec<String>),
    Cwt(Vec<String>),
    Attestation(Vec<String>),
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
#[serde(untagged)]
pub enum CredentialResponseType {
    Deferred {
        transaction_id: String,
    },
    Immediate {
        #[serde(alias = "credentials")]
        // XXX Accepts "credential" with multiple. Meh, good enough...
        credential: Value,
        notification_id: Option<String>,
    },
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<StringOrInt>,
}

// Credential Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-response
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialResponse {
    #[serde(flatten)]
    pub credential: CredentialResponseType,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<StringOrInt>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorDetails {
    #[serde(skip_serializing, skip_deserializing)]
    pub status: reqwest::StatusCode,
    pub error: String,
    #[serde(alias = "description")]
    pub error_description: String,
}

impl std::fmt::Display for ErrorDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status: {}, error: \"{}\", error description: \"{}\"",
            self.status, self.error, self.error_description
        )
    }
}

impl std::error::Error for ErrorDetails {}

/// Credential Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-request
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,

    #[serde(flatten, skip_serializing_if = "CredentialProofs::is_none")]
    pub proof: CredentialProofs,
    pub credential_identifier: Option<String>,
    pub credential_response_encryption: Option<CredentialResponseEncryptionSpecification>,
    // Format and the format-specific parameters are only kept for backwards compatibility with
    // pre-draft15 issuers. Remove.
    #[serde(flatten)]
    pub credential_format: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CredentialResponseEncryptionSpecification {
    pub jwk: josekit::jwk::Jwk,
    pub enc: String,
    pub alg: String,
}

pub mod credential_formats {
    use heidi_util_rust::value::Value;

    pub const JWT_VC_JSON: &str = "jwt_vc_json";
    pub const VC_IETF_SD_JWT_LEGACY: &str = "vc+sd-jwt";
    pub const VC_IETF_SD_JWT: &str = "dc+sd-jwt";
    pub const W3C_SD_JWT: &str = "vc+sd-jwt";
    pub const MSO_MDOC: &str = "mso_mdoc";
    pub const ZKP_VC: &str = "zkp_vc";
    pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
    pub const LDP_VC: &str = "ldp_vc";

    pub enum CredentialFormat {
        JwtVcJson,
        VcIetfSdJwt,
        VcIetfSdJwtLegacy,
        W3cSdJwt,
        MsoMdoc,
        ZkpVc,
        JwtVcJsonLd,
        LdpVc,
        Unknown,
    }
    impl From<&Value> for CredentialFormat {
        fn from(value: &Value) -> Self {
            match value.get("format").and_then(|a| a.as_str()) {
                Some(JWT_VC_JSON) => CredentialFormat::JwtVcJson,
                Some(VC_IETF_SD_JWT_LEGACY) if value.get("vct").is_some() => {
                    CredentialFormat::VcIetfSdJwtLegacy
                }
                Some(W3C_SD_JWT) => CredentialFormat::W3cSdJwt,
                Some(VC_IETF_SD_JWT) => CredentialFormat::VcIetfSdJwt,
                Some(MSO_MDOC) => CredentialFormat::MsoMdoc,
                Some(ZKP_VC) => CredentialFormat::ZkpVc,
                Some(JWT_VC_JSON_LD) => CredentialFormat::JwtVcJsonLd,
                Some(LDP_VC) => CredentialFormat::LdpVc,
                _ => CredentialFormat::Unknown,
            }
        }
    }
}

#[derive(Default)]
pub struct ProofBuilder {
    proof_type: Option<ProofType>,
    rfc7519_claims: RFC7519Claims,
    nonce: Option<String>,
    signer: Option<Arc<SecureSubject>>,
    subject_syntax_type: Option<String>,
    use_did_jwk: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOfPossession {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub nonce: String,
}

impl ProofBuilder {
    fn get_jws_header(&self) -> anyhow::Result<josekit::jws::JwsHeader> {
        if self.use_did_jwk {
            use serde_json::Value as JsonValue;
            let signer = self
                .signer
                .as_ref()
                .ok_or(anyhow::anyhow!("No subject found"))?;

            let encoded_jwk =
                BASE64_URL_SAFE_NO_PAD.encode(signer.signer.public_key_jwk().as_bytes());

            let mut map = serde_json::Map::new();
            map.insert("alg".to_string(), JsonValue::String(signer.signer.alg()));
            map.insert(
                "typ".to_string(),
                JsonValue::String("openid4vc-proof+jwt".to_string()),
            );
            map.insert(
                "kid".to_string(),
                JsonValue::String(format!("did:jwk:{encoded_jwk}#0")),
            );
            josekit::jws::JwsHeader::from_map(map)
                .or_else(|e| Err(anyhow::anyhow!("Invalid Header: {e}")))
        } else {
            josekit::jws::JwsHeader::from_bytes(
                self.signer.as_ref().unwrap().signer.jwt_header().as_bytes(),
            )
            .or_else(|e| Err(anyhow::anyhow!("Invalid Header: {e}")))
        }
    }

    pub fn build_signing_payload(&self) -> anyhow::Result<String> {
        let jws_header = self.get_jws_header()?;
        let pop = ProofOfPossession {
            rfc7519_claims: self.rfc7519_claims.clone(),
            nonce: self
                .nonce
                .clone()
                .ok_or(anyhow::anyhow!("No nonce found"))?,
        };
        Ok(format!(
            "{}.{}",
            b64url_encode_bytes(
                serde_json::to_string(jws_header.as_ref())
                    .or_else(|e| Err(anyhow::anyhow!("Invalid Header: {e}")))?
            ),
            b64url_encode_bytes(
                serde_json::to_string(&pop)
                    .or_else(|e| Err(anyhow::anyhow!("Invalid Proof of Possession: {e}")))?
            ),
        ))
    }
    pub async fn build_no_sign(self) -> anyhow::Result<KeyProofType> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(self.nonce.is_some(), "nonce claim is required");

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(KeyProofType::Jwt {
                jwt: self.build_signing_payload()?,
            }),
            Some(_) => todo!(),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }
    pub async fn build(self) -> anyhow::Result<KeyProofType> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        let jws_header = self.get_jws_header()?;
        let pop = ProofOfPossession {
            rfc7519_claims: self.rfc7519_claims,
            nonce: self.nonce.ok_or(anyhow::anyhow!("No nonce found"))?,
        };
        let signer = self
            .signer
            .as_ref()
            .ok_or(anyhow::anyhow!("No subject found"))?;

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(KeyProofType::Jwt {
                jwt: pop
                    .create_jwt(
                        &jws_header,
                        None,
                        chrono::Duration::minutes(2),
                        signer.as_ref(),
                    )
                    .or_else(|e| Err(anyhow::anyhow!("failed to build jwt: {e}")))?,
            }),
            Some(_) => Err(anyhow::anyhow!("proof type not supported")),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }

    pub fn signer(mut self, signer: Arc<SecureSubject>) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn use_did_jwk(mut self, use_did_jwk: bool) -> Self {
        self.use_did_jwk = use_did_jwk;
        self
    }

    builder_fn!(proof_type, ProofType);
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, aud, String);
    // TODO: fix this, required by jsonwebtoken crate.
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(nonce, String);
    builder_fn!(subject_syntax_type, String);
}

// Like reqwest.Response.error_for_status, but includes the details of the error returned by the
// server, if they can be parsed.
pub trait ErrorForStatusDetailed
where
    Self: std::marker::Sized,
{
    async fn error_for_status_detailed(self) -> anyhow::Result<Self>;
}

impl ErrorForStatusDetailed for reqwest::Response {
    async fn error_for_status_detailed(self) -> anyhow::Result<Self> {
        if let Err(err_status) = self.error_for_status_ref() {
            let status = self.status();
            if status.is_client_error() {
                match self.json::<ErrorDetails>().await {
                    Ok(details) => Err(ErrorDetails {
                        status,
                        error: details.error,
                        error_description: details.error_description,
                    }
                    .into()),
                    Err(_) => Err(err_status.into()),
                }
            } else {
                Err(err_status.into())
            }
        } else {
            Ok(self)
        }
    }
}

pub trait ErrorAsCredentialErrorResponse
where
    Self: std::marker::Sized,
{
    async fn as_credential_error_response(self) -> Result<Self, CredentialErrorResponse>;
}

impl ErrorAsCredentialErrorResponse for reqwest::Response {
    async fn as_credential_error_response(self) -> Result<Self, CredentialErrorResponse> {
        if let Err(err_status) = self.error_for_status_ref() {
            let status = self.status();
            if status.is_client_error() {
                match self.json::<CredentialErrorResponse>().await {
                    Ok(details) => Err(details),
                    Err(e) => Err(CredentialErrorResponse {
                        error: "no_credential_error_response".to_string(),
                        error_description: Some(format!("{e}")),
                        c_nonce: None,
                        c_nonce_expires_in: None,
                    }),
                }
            } else {
                Err(CredentialErrorResponse {
                    error: "unknown_error".to_string(),
                    error_description: Some(format!("{err_status}")),
                    c_nonce: None,
                    c_nonce_expires_in: None,
                })
            }
        } else {
            Ok(self)
        }
    }
}
