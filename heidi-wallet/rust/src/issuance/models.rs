use std::collections::HashMap;

use heidi_util_rust::value::Value;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with_macros::skip_serializing_none;

use crate::issuance::helper::to_query_value;

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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "type")]
pub enum AuthorizationDetail {
    #[serde(rename = "openid_credential")]
    OpenIdCredential(OpenIdCredential),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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

impl std::fmt::Display for CredentialOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOffer::CredentialOfferUri(uri) => {
                let mut url =
                    Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut().append_pair(
                    "credential_offer_uri",
                    &to_query_value(uri).map_err(|_| std::fmt::Error)?,
                );
                write!(f, "{}", url)
            }
            CredentialOffer::CredentialOffer(offer) => {
                let mut url =
                    Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut().append_pair(
                    "credential_offer",
                    &to_query_value(offer).map_err(|_| std::fmt::Error)?,
                );
                write!(f, "{}", url)
            }
        }
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
