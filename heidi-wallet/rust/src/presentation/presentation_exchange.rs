use crate::builder_fn;
use heidi_util_rust::value::Value;
use is_empty::IsEmpty;
use jsonpath_lib as jsonpath;
use jsonschema::JSONSchema;
use monostate::MustBe;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with_macros::skip_serializing_none;
use std::collections::HashMap;

use crate::issuance::models::JsonObject;

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub struct PresentationDefinition {
    pub(crate) id: String,
    // All inputs listed in the `input_descriptors` array are required for submission, unless otherwise specified by a
    // Feature.
    pub(crate) input_descriptors: Vec<InputDescriptor>,
    pub(crate) submission_requirements: Option<Vec<SubmissionRequirement>>,
    pub(crate) name: Option<String>,
    pub(crate) purpose: Option<String>,
    #[serde(default, deserialize_with = "deserialize_format")]
    pub(crate) format: Option<HashMap<ClaimFormatDesignation, Option<ClaimFormatProperty>>>,
}

/// As specified in https://identity.foundation/presentation-exchange/#submission-requirement-feature.
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub struct SubmissionRequirement {
    name: String,
    rule: SubmissionRule,
    count: u32,
    from: String,
}
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub enum SubmissionRule {
    #[serde(alias = "pick", alias = "PICK", alias = "Pick")]
    Pick,
}

/// As specified in https://identity.foundation/presentation-exchange/#input-descriptor-object.
/// All input descriptors MUST be satisfied, unless otherwise specified by a Feature.
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub struct InputDescriptor {
    // Must not conflict with other input descriptors.
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) group: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_format")]
    pub(crate) format: Option<HashMap<ClaimFormatDesignation, Option<ClaimFormatProperty>>>,
    pub(crate) constraints: Constraints,
    pub(crate) schema: Option<String>,
}

fn deserialize_format<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<ClaimFormatDesignation, Option<ClaimFormatProperty>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_value: Option<HashMap<ClaimFormatDesignation, serde_json::Value>> =
        Option::deserialize(deserializer)?;
    let Some(value) = opt_value else {
        return Ok(None);
    };

    let mut map = HashMap::new();
    for (key, val) in value {
        let parsed_val = if val.as_object().map(|o| o.is_empty()).unwrap_or(false) {
            None
        } else {
            Some(serde_json::from_value(val).map_err(serde::de::Error::custom)?)
        };
        map.insert(key, parsed_val);
    }
    Ok(Some(map))
}

// Its value MUST be an array of one or more format-specific algorithmic identifier references
// TODO: fix this related to jwt_vc_json and jwt_vp_json: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-e.1
#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormatDesignation {
    Jwt,
    JwtVc,
    JwtVcJson,
    JwtVp,
    JwtVpJson,
    Ldp,
    LdpVc,
    LdpVp,
    AcVc,
    AcVp,
    MsoMdoc,
    #[serde(rename = "vc+sd-jwt", alias = "dc+sd-jwt")]
    VcSdJwt,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormatProperty {
    Alg(Vec<String>),
    ProofType(Vec<String>),
    #[serde(untagged)]
    Sdjwt {
        #[serde(rename = "kb-jwt_alg_values")]
        kb_jwt_alg_values: Vec<String>,
        #[serde(rename = "sd-jwt_alg_values")]
        sd_jwt_alg_values: Vec<String>,
    },
}

#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct Constraints {
    pub(crate) fields: Option<Vec<Field>>,
    // Omission of the `limit_disclosure` property indicates the Conforment Consumer MAY submit a response that contains
    // more than the data described in the `fields` array.
    pub(crate) limit_disclosure: Option<LimitDisclosure>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitDisclosure {
    Required,
    Preferred,
}

#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct Field {
    // The value of this property MUST be an array of ONE OR MORE JSONPath string expressions.
    // The ability to declare multiple expressions in this way allows the Verifier to account for format differences.
    pub(crate) path: Vec<String>,
    pub(crate) id: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) filter: Option<serde_json::Value>,
    // TODO: check default behaviour
    pub(crate) optional: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldQueryResult {
    Some {
        value: serde_json::Value,
        path: String,
    },
    None,
    Invalid,
}

impl FieldQueryResult {
    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn is_invalid(&self) -> bool {
        *self == FieldQueryResult::Invalid
    }
}

// Input Evaluation as described in section [8. Input
/// Evaluation](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation) of the DIF
/// Presentation Exchange specification.
pub fn evaluate_input_raw(
    input_descriptor: &InputDescriptor,
    value: &serde_json::Value,
) -> Option<Vec<FieldQueryResult>> {
    let selector = &mut jsonpath::selector(value);

    input_descriptor
        .constraints
        .fields
        .as_ref()
        .map(|fields| {
            let results: Vec<FieldQueryResult> = fields
                .iter()
                .map(|field| {
                    let filter = field
                        .filter
                        .as_ref()
                        .map(JSONSchema::compile)
                        .transpose()
                        .ok()
                        .flatten();

                    // For each JSONPath expression in the `path` array (incrementing from the 0-index),
                    // evaluate the JSONPath expression against the candidate input and repeat the following
                    // subsequence on the result.
                    field
                        .path
                        .iter()
                        // Repeat until a Field Query Result is found, or the path array elements are exhausted:
                        .find_map(|path| {
                            // If the result returned no JSONPath match, skip to the next path array element.
                            // Else, evaluate the first JSONPath match (candidate) as follows:
                            selector(path).ok().and_then(|values| {
                                values.into_iter().find_map(|result| {
                                    // If the fields object has no `filter`, or if candidate validates against
                                    // the JSON Schema descriptor specified in `filter`, then:
                                    filter
                                        .as_ref()
                                        .map(|filter| filter.is_valid(result))
                                        .unwrap_or(true)
                                        // set Field Query Result to be candidate
                                        .then(|| FieldQueryResult::Some {
                                            value: result.to_owned(),
                                            path: path.to_owned(),
                                        })
                                    // Else, skip to the next `path` array element.
                                })
                            })
                        })
                        // If no value is located for any of the specified `path` queries, and the fields
                        // object DOES NOT contain the `optional` property or it is set to `false`, reject the
                        // field as invalid. If no value is located for any of the specified `path` queries and
                        // the fields object DOES contain the `optional` property set to the value `true`,
                        // treat the field as valid and proceed to the next fields object.
                        .or_else(|| {
                            field
                                .optional
                                .and_then(|opt| opt.then(|| FieldQueryResult::None))
                        })
                        .unwrap_or(FieldQueryResult::Invalid)
                })
                .collect();
            results
                .iter()
                .all(FieldQueryResult::is_valid)
                .then_some(results)
        })
        .flatten()
}

/// Input Evaluation as described in section [8. Input
/// Evaluation](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation) of the DIF
/// Presentation Exchange specification.
pub fn evaluate_input(input_descriptor: &InputDescriptor, value: &serde_json::Value) -> bool {
    let selector = &mut jsonpath::selector(value);

    input_descriptor
        .constraints
        .fields
        .as_ref()
        .map(|fields| {
            let results: Vec<FieldQueryResult> = fields
                .iter()
                .map(|field| {
                    let filter = field
                        .filter
                        .as_ref()
                        .map(JSONSchema::compile)
                        .transpose()
                        .ok()
                        .flatten();

                    // For each JSONPath expression in the `path` array (incrementing from the 0-index),
                    // evaluate the JSONPath expression against the candidate input and repeat the following
                    // subsequence on the result.
                    field
                        .path
                        .iter()
                        // Repeat until a Field Query Result is found, or the path array elements are exhausted:
                        .find_map(|path| {
                            // If the result returned no JSONPath match, skip to the next path array element.
                            // Else, evaluate the first JSONPath match (candidate) as follows:
                            selector(path).ok().and_then(|values| {
                                values.into_iter().find_map(|result| {
                                    // If the fields object has no `filter`, or if candidate validates against
                                    // the JSON Schema descriptor specified in `filter`, then:
                                    filter
                                        .as_ref()
                                        .map(|filter| filter.is_valid(result))
                                        .unwrap_or(true)
                                        // set Field Query Result to be candidate
                                        .then(|| FieldQueryResult::Some {
                                            value: result.to_owned(),
                                            path: path.to_owned(),
                                        })
                                    // Else, skip to the next `path` array element.
                                })
                            })
                        })
                        // If no value is located for any of the specified `path` queries, and the fields
                        // object DOES NOT contain the `optional` property or it is set to `false`, reject the
                        // field as invalid. If no value is located for any of the specified `path` queries and
                        // the fields object DOES contain the `optional` property set to the value `true`,
                        // treat the field as valid and proceed to the next fields object.
                        .or_else(|| {
                            field
                                .optional
                                .and_then(|opt| opt.then(|| FieldQueryResult::None))
                        })
                        .unwrap_or(FieldQueryResult::Invalid)
                })
                .collect();
            results.iter().all(FieldQueryResult::is_valid)
        })
        .unwrap_or(false)
}

#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Serialize, PartialEq, Clone)]
pub struct InputDescriptorMappingObject {
    // Matches the `id` property of the Input Descriptor in the Presentation Definition that this Presentation
    // Submission is related to.
    pub id: String,
    // Matches one of the Claim Format Designation. This denotes the data format of the Claim.
    pub format: ClaimFormatDesignation,
    // TODO Must be a JSONPath string expression
    // Indicates the Claim submitted in relation to the identified Input Descriptor, When executed against the
    // top-level of the object the Presentation Submission is embedded within.
    pub path: String,
    pub path_nested: Option<PathNested>,
}
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Serialize, PartialEq, Clone)]
pub struct PathNested {
    pub id: Option<String>,
    pub format: ClaimFormatDesignation,
    pub path: String,
    pub path_nested: Option<Box<Self>>,
}

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize, PartialEq, Clone)]
pub struct PresentationSubmission {
    // TODO: Must be unique.
    pub id: String,
    // TODO: Value must be the id value of a valid presentation definition.
    pub definition_id: String,
    pub descriptor_map: Vec<InputDescriptorMappingObject>,
}

/// Represents the parameters of an OpenID4VP response. It can hold a Verifiable Presentation Token and a Presentation
/// Submission, or a JWT containing them.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Oid4vpParams {
    Jwt {
        response: String,
    },
    Params {
        vp_token: String,
        presentation_submission: PresentationSubmission,
    },
}

/// [`ClientMetadata`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a
/// [`crate::Provider`].
#[skip_serializing_none]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMetadataResource {
    // TODO: Add all fields described in https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    ClientMetadata {
        client_name: Option<String>,
        logo_uri: Option<String>,
        /// As described in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591.html#section-2), the client metadata can be
        /// expanded with Extensions and profiles.
        #[serde(flatten)]
        extension: Value,
    },
    ClientMetadataUri(String),
}

/// The Client ID Scheme enables the use of different mechanisms to obtain and validate the Verifier's metadata. As
/// described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-managemen
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdScheme {
    #[serde(rename = "pre-registered")]
    PreRegistered,
    RedirectUri,
    EntityId,
    Did,
    VerifierAttestation,
    X509SanDns,
    X509SanUri,
}

/// A [`AuthorizationRequest`] is a request that is sent by a client to a provider. It contains a set of claims in the
/// form of a [`Body`] which can be [`ByValue`], [`ByReference`], or an [`Object`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequest {
    #[serde(skip)]
    pub custom_url_scheme: String,
    #[serde(flatten)]
    pub body: AuthorizationRequestParameters,
}
impl AuthorizationRequest {
    pub fn builder() -> AuthorizationRequestBuilder {
        AuthorizationRequestBuilder::default()
    }
}

/// Set of IANA registered claims by the Internet Engineering Task Force (IETF) in
/// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, IsEmpty, PartialEq, Clone)]
pub struct RFC7519Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
}

/// [`AuthorizationRequest`] claims specific to [`OID4VP`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequestParameters {
    pub response_type: MustBe!("vp_token"),
    pub presentation_definition: Option<PresentationDefinition>,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub scope: Option<String>,
    pub nonce: String,
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    #[serde(flatten)]
    pub client_metadata: Option<ClientMetadataResource>,
    pub zkp: Option<ZkpInfo>,
}
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub struct ZkpInfo {
    pub definition: String,
    #[serde(alias = "provingKey")]
    pub proving_key: String,
    #[serde(alias = "issuerPk")]
    pub issuer_pk: String,
    #[serde(alias = "issuerId")]
    pub issuer_id: String,
    #[serde(alias = "issuerKeyId")]
    pub issuer_key_id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ClientMetadataParameters {
    /// Represents the URI scheme identifiers of supported Subject Syntax Types.
    /// As described here: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-7.5-2.1.1
    pub subject_syntax_types_supported: Vec<SubjectSyntaxType>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubjectSyntaxType {
    #[serde(with = "serde_unit_variant")]
    JwkThumbprint,
    Did(DidMethod),
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidMethod {
    method_name: String,
    namespace: Option<String>,
}

pub mod serde_unit_variant {
    use super::*;

    static JWK_THUMBPRINT: &str = "urn:ietf:params:oauth:jwk-thumbprint";

    pub fn serialize<S>(serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(JWK_THUMBPRINT)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        (s == JWK_THUMBPRINT)
            .then_some(())
            .ok_or(serde::de::Error::custom("Invalid subject syntax type"))
    }
}

/// In order to convert a string to a [`AuthorizationRequest`], we need to try to parse each value as a JSON object. This way we
/// can catch any non-primitive types. If the value is not a JSON object or an Array, we just leave it as a string.
impl std::str::FromStr for AuthorizationRequest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = reqwest::Url::parse(s)?;
        let query = url
            .query()
            .ok_or_else(|| anyhow::anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<JsonObject>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) => Some(Ok((
                    k,
                    serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
                ))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let mut authorization_request: AuthorizationRequest =
            serde_json::from_value(serde_json::Value::Object(map))?;
        authorization_request.custom_url_scheme = url.scheme().to_string();
        Ok(authorization_request)
    }
}

#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    presentation_definition: Option<PresentationDefinition>,
    client_id_scheme: Option<ClientIdScheme>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    response_mode: Option<String>,
    response_uri: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadataResource>,
    custom_url_scheme: Option<String>,
    zkp: Option<ZkpInfo>,
}

impl AuthorizationRequestBuilder {
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(response_mode, String);
    builder_fn!(response_uri, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, String);
    builder_fn!(redirect_uri, String);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadataResource);
    builder_fn!(state, String);
    builder_fn!(presentation_definition, PresentationDefinition);
    builder_fn!(client_id_scheme, ClientIdScheme);
    builder_fn!(custom_url_scheme, String);
    builder_fn!(zkp, ZkpInfo);

    pub fn build(mut self) -> anyhow::Result<AuthorizationRequest> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow::anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    response_type: MustBe!("vp_token"),
                    presentation_definition: self.presentation_definition.take(),
                    client_id_scheme: self.client_id_scheme.take(),
                    scope: self.scope.take(),
                    response_mode: self.response_mode.take(),
                    response_uri: self.response_uri.take(),
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("nonce parameter is required."))?,
                    client_metadata: self.client_metadata.take(),
                    zkp: self.zkp.take(),
                    rfc7519_claims: self.rfc7519_claims,
                    client_id,
                    redirect_uri: self.redirect_uri.take(),
                    state: self.state.take(),
                };

                Ok(AuthorizationRequest {
                    custom_url_scheme: self
                        .custom_url_scheme
                        .take()
                        .unwrap_or("openid".to_string()),
                    body: extension,
                })
            }
            _ => Err(anyhow::anyhow!(
                "one of either request_uri, request or other parameters should be set"
            )),
        }
    }
}

// Macro that generates a builder function for a field.
#[macro_export]
macro_rules! builder_fn {
    ($name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$name.replace(value.into());
            self
        }
    };
    ($field:ident, $name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$field.$name.replace(value.into());
            self
        }
    };
}
