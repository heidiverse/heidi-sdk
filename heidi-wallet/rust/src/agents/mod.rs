/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

//! Module for parsing information about verifier/issuers. It tries different formats
//! gathering information from the metadata endpoints or the authorization request.
//! It also performs various validation based on the RFCs, whereas we try to be somewhat
//! lenient

use crate::log_error;

use heidi_jwt::jwt::{
    verifier::{ClaimValidator, DefaultVerifier},
    Jwt,
};

use std::{collections::VecDeque, fmt::Debug, str::FromStr};

use reqwest::Url;
use reqwest_middleware::ClientBuilder;

use x509_parser::{
    prelude::{FromDer, GeneralName},
    x509::SubjectPublicKeyInfo,
};

use crate::issuance::{self, metadata::MetadataFetcher};
#[allow(unused)]
use crate::{
    error::{AgentParseError, IssuerError, VerifierError, VerifierParseError},
    ApiError,
};
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
use crate::{TRUSTED_CAS, TRUSTED_ISSUERS};
use heidi_util_rust::value::Value;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// Struct containing informatino about a verifier/issuer.
pub struct AgentInfo {
    /// For the verifier it contains the certificate chain
    /// for the issuer the url (which should provide the metadata)
    pub r#type: AgentType,
    /// A user-friendly common name parsed from the x509
    pub name: String,
    pub domain: String,
    /// Trust anchor contains the name of the trust certificate
    pub trust_anchor: String,
    /// Valid indicates, if all validations passed. A invalid agent might
    /// still be used.
    pub valid: bool,
    /// Indicates if the certificate was found in either webpki_roots or our custom root store.
    pub trusted: bool,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
/// The type of the agent
pub enum AgentType {
    Issuer { issuer_url: String },
    Verifier { trust_chain: Vec<Vec<u8>> },
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(feature = "reqwest")]
/// Allows the wallet to get some information from a credential offer. It connects to the agent
/// and parsed some of the metadata to get information about the issuer.
///
/// SAFETY:
/// Clientbuilder does not panic
#[cfg(feature = "uniffi")]
pub async fn get_agent_info_from_scheme(offer: String) -> Result<AgentInfo, ApiError> {
    use crate::get_reqwest_client;
    let client = ClientBuilder::new(get_reqwest_client().build().unwrap()).build();

    let cred_offer = issuance::resolve_credential_offer(&offer, &client).await?;
    let issuer = cred_offer.credential_issuer.to_string();
    get_agent_info_from_issuer(issuer).await
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(feature = "reqwest")]
/// As `get_agent_info_from_scheme` but uses the issuer url directly to connect to the metadata endpoint
///
/// We do not yet know what or how to validate an issuer. As such an issuer is always valid, and it all depends
/// on the wallet trusting it.
///
/// SAFETY:
/// Clientbuilder does not panic
pub async fn get_agent_info_from_issuer(issuer: String) -> Result<AgentInfo, ApiError> {
    use crate::get_reqwest_client;

    let client = get_reqwest_client().build().unwrap();

    let metadata_client = ClientBuilder::new(client).build();

    let metadata_fetcher: MetadataFetcher = MetadataFetcher::new(metadata_client);
    let issuer_url = issuer.parse().generic_issuer_error("Invalid url")?;
    let name = if let Ok(credential_issuer_metadata) = metadata_fetcher
        .get_credential_issuer_metadata(issuer_url)
        .await
    {
        credential_issuer_metadata
            .display
            .and_then(|a| a.first().cloned())
            .and_then(|a| a.get("name").cloned())
            .and_then(|a| a.as_str().map(|a| a.to_string()))
            .unwrap_or(issuer.clone())
    } else {
        issuer.clone()
    };
    #[cfg(all(feature = "uniffi", feature = "reqwest"))]
    let trusted = {
        TRUSTED_ISSUERS
            .lock()
            .map(|a| a.iter().any(|a| a == &issuer || issuer.starts_with(a)))
            .unwrap_or(false)
    };
    #[cfg(not(all(feature = "uniffi", feature = "reqwest")))]
    let trusted = false;
    Ok(AgentInfo {
        r#type: AgentType::Issuer {
            issuer_url: issuer.clone(),
        },
        name,
        domain: issuer.clone(),
        trust_anchor: issuer,
        valid: true,
        trusted,
    })
}

/// Decode a JWT to access claims, ignoring the validity of the token itself.
///
/// *NOTE: Neither signature NOR expiration are checked.*
async fn decode_jwt_insecure(jwt_str: &str) -> Result<(Value, AgentInfo, String), ApiError> {
    let jwt = Jwt::<serde_json::Value>::from_str(jwt_str).map_err(|_| {
        ApiError::AgentParse(AgentParseError::Verifier(VerifierParseError::TokenInvalid(
            "could not parse jwt".to_string(),
        )))
    })?;
    let request = auth_request_from_json(jwt.payload_unverified().insecure().clone()).await?;
    let verifier_info = AgentInfo {
        r#type: AgentType::Verifier {
            trust_chain: vec![],
        },
        name: "INVALID".to_string(),
        domain: "INVALID".to_string(),
        trust_anchor: "INVALID".to_string(),
        valid: false,
        trusted: false,
    };
    let request: heidi_util_rust::value::Value = serde_json::to_value(&request)?.into();
    Ok((request, verifier_info, jwt_str.to_string()))
}
impl AgentInfo {
    /// Extension function to obtain `AgentInfo` from an authorization request jwt. It parses and validates
    /// the jwt and the corresponding x5c chain.
    ///
    /// It also performs validations based on the [OpenID for Verifiable Presentations - draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
    pub async fn from_auth_request(jwt: String) -> Result<(Value, Self, String), ApiError> {
        // we for now disable strict validation according to the [OpenID for Verifiable Presentations - draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
        let strict = false;
        let mut _is_dcapi = false;
        let jwt_parsed = Jwt::<serde_json::Value>::from_str(&jwt).map_err(|_| {
            ApiError::AgentParse(AgentParseError::Verifier(VerifierParseError::TokenInvalid(
                "Invalid JWT".to_string(),
            )))
        })?;

        let header = jwt_parsed.header().map_err(|_| {
            ApiError::AgentParse(AgentParseError::Verifier(VerifierParseError::TokenInvalid(
                "Invalid JWT".to_string(),
            )))
        })?;
        // we only support the x509_san_dns for now
        let Some(chain) = header.x509_certificate_chain() else {
            log_error!("AgentInfo::Parsing", "Could not parse x5c certificates");
            return decode_jwt_insecure(&jwt).await;
        };

        // check the integrity of the certificate chain
        let Ok(_) = heidi_jwt::jwt::check_x5c_chain(&chain) else {
            log_error!("AgentInfo::Parsing", "X5C integrity check failed");
            return decode_jwt_insecure(&jwt).await;
        };

        let Some(root_cert) = chain.last().cloned() else {
            log_error!("AgentInfo::Parsing", "Could not parse x5c certificates");
            return decode_jwt_insecure(&jwt).await;
        };

        let (_, root_parsed) = x509_parser::parse_x509_certificate(&root_cert)
            .generic_verifier_error("Could not parse root")?;
        let mut chain = VecDeque::from(chain);

        let Some(leaf_certificate) = chain.pop_front() else {
            return Err(
                AgentParseError::Verifier(VerifierParseError::CertificateParseError(
                    "no certificates".to_string(),
                ))
                .into(),
            );
        };

        #[cfg(all(feature = "uniffi", feature = "reqwest"))]
        let in_webpki_truststore = if root_parsed.is_ca() {
            {
                let trusted_cas = TRUSTED_CAS
                    .lock()
                    .map(|a| {
                        a.iter().any(|cert| {
                            let Ok((_, parsed_cert)) = x509_parser::parse_x509_certificate(cert)
                            else {
                                return false;
                            };
                            parsed_cert.subject() == root_parsed.subject()
                                && parsed_cert.subject_pki == root_parsed.subject_pki
                        })
                    })
                    .unwrap_or(false);

                webpki_roots::TLS_SERVER_ROOTS.iter().any(|a| {
                    a.subject.as_ref() == root_parsed.subject().as_raw()
                        && a.subject_public_key_info.as_ref() == root_parsed.subject_pki.raw
                }) || trusted_cas
            }
        } else {
            let trusted_cas = TRUSTED_CAS
                .lock()
                .map(|a| {
                    a.iter().any(|cert| {
                        let Ok((_, parsed_cert)) = x509_parser::parse_x509_certificate(cert) else {
                            return false;
                        };
                        root_parsed
                            .verify_signature(Some(parsed_cert.public_key()))
                            .is_ok()
                    })
                })
                .unwrap_or(false);
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .find(|a| a.subject.as_ref() == root_parsed.issuer().as_raw())
                .map(|ca| {
                    let Ok((_, spki)) =
                        SubjectPublicKeyInfo::from_der(ca.subject_public_key_info.as_ref())
                    else {
                        return false;
                    };
                    root_parsed.verify_signature(Some(&spki)).is_ok()
                })
                .unwrap_or(false)
                || trusted_cas
        };
        #[cfg(not(all(feature = "uniffi", feature = "reqwest")))]
        let in_webpki_truststore = false;

        let Ok(payload) = jwt_parsed.payload_with_verifier_from_header(&DefaultVerifier::new(
            "oauth-authz-req+jwt".to_string(),
            vec![
                ClaimValidator::Presence("nonce".to_string()),
                ClaimValidator::Presence("response_mode".to_string()),
                ClaimValidator::Presence("client_id".to_string()),
                ClaimValidator::Presence("state".to_string()),
            ],
        )) else {
            log_error!("AgentInfo::Parsing", "Invalid JWT signature");
            return decode_jwt_insecure(&jwt).await;
        };
        let request = auth_request_from_json(payload.clone()).await?;

        let Some(request_client_id) = request.get("client_id").and_then(|a| a.as_str()) else {
            return Err(ApiError::AgentParse(AgentParseError::Verifier(
                VerifierParseError::Generic(
                    "response_uri is missing when direct_post!".to_string(),
                ),
            )));
        };

        // If the URL is not in the trust store, the redirect_uri/response_uri must match with the client_id

        // According to https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2 `redirect_uri` is
        // not permitted, when `response_mode=direct_post` is used. Otherwise `response_uri` must be validated the same as `redirect_uri`
        // would.

        let valid = if !in_webpki_truststore {
            let return_adress = match request.get("response_mode").and_then(|a| a.as_str()) {
                Some(mode) if mode == "direct_post" || mode == "direct_post.jwt" => {
                    if strict {
                        let Some(url) = request.get("response_uri").and_then(|a| a.as_str()) else {
                            return Err(ApiError::AgentParse(AgentParseError::Verifier(
                                VerifierParseError::Generic(
                                    "response_uri is missing when direct_post!".to_string(),
                                ),
                            )));
                        };
                        Some(url.to_string())
                    } else {
                        request
                            .get("response_uri")
                            .and_then(|a| a.as_str())
                            .map(|a| a.to_string())
                    }
                }
                Some(mode) if mode == "dc_api" || mode == "dc_api.jwt" => {
                    _is_dcapi = true;
                    Some("<dc_api>".to_string())
                }
                _ => {
                    if strict {
                        let Some(url) = request.get("redirect_uri").and_then(|a| a.as_str()) else {
                            return Err(ApiError::AgentParse(AgentParseError::Verifier(
                                VerifierParseError::Generic(
                                    "redirect_uri is missing when no direct_post!".to_string(),
                                ),
                            )));
                        };
                        Some(url.to_string())
                    } else {
                        request
                            .get("redirect_uri")
                            .and_then(|a| a.as_str())
                            .map(|a| a.to_string())
                    }
                }
            };
            if return_adress == Some("<dc_api>".to_string()) {
                true
            } else {
                return_adress
                    .and_then(|a| a.parse::<Url>().ok())
                    .map(|a| {
                        a.host_str()
                            .map(|a| a == request_client_id)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            }
        } else {
            true
        };

        let (_, leaf_certificate) = x509_parser::parse_x509_certificate(&leaf_certificate)
            .generic_verifier_error("Could not parse x509 chain certificate")?;

        let Ok(Some(subject_alternative_name)) = leaf_certificate.subject_alternative_name() else {
            log_error!("AgentInfo::parse", "certificate has no SAN");
            return decode_jwt_insecure(&jwt).await;
        };

        let client_id_is_contained =
            subject_alternative_name
                .value
                .general_names
                .iter()
                .any(|gn| {
                    if let GeneralName::DNSName(dns_name) = gn {
                        dns_name == &request_client_id
                            || format!("https://{dns_name}") == request_client_id
                    }
                    // until there is more clearance also accept if the client_id == uri in SAN
                    else if let GeneralName::URI(uri) = gn {
                        uri == &request_client_id
                    } else {
                        false
                    }
                });

        if !client_id_is_contained {
            log_error!("AgentInfo::parse", "certificate has no SAN");
            return decode_jwt_insecure(&jwt).await;
        }

        if strict
            && request
                .get("response_mode")
                .and_then(|a| a.as_str())
                .map(|a| a == "direct_post")
                .unwrap_or(false)
            && request.get("response_uri").is_none()
        {
            return AgentParseError::generic_verifier_error(
            "'response_uri' is required in authorization request if response mode is direct_post!",
        )
        .map_err(|e| e.into());
        }

        let Some(certificate_chain) = header.x509_certificate_chain() else {
            unreachable!("We checked before")
        };
        let san = subject_alternative_name
            .value
            .general_names
            .iter()
            .filter_map(|gn| {
                if let GeneralName::DNSName(dns_name) = gn {
                    Some(dns_name.to_string())
                }
                // until there is more clearance also accept if the client_id == uri in SAN
                else if let GeneralName::URI(uri) = gn {
                    Some(uri.to_string())
                } else {
                    None
                }
            })
            .next();
        let name = leaf_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or(&san.unwrap_or(leaf_certificate.subject.to_string()))
            .to_string();

        let ca_name = root_parsed.subject.to_string();
        let verifier_info = AgentInfo {
            r#type: AgentType::Verifier {
                trust_chain: certificate_chain,
            },
            name: name.clone(),
            domain: name,
            trust_anchor: ca_name,
            valid,
            trusted: in_webpki_truststore,
        };
        let request: heidi_util_rust::value::Value = serde_json::to_value(&request)?.into();
        Ok((request, verifier_info, jwt))
    }
}

/// Parses a AuthroizationRequest from json. Internally it uses an underlaying builder. We need this workaround
/// to resolve all the *_uri variants of the AuthroizationRequest.
#[cfg(feature = "reqwest")]
pub(crate) async fn auth_request_from_json(
    value: serde_json::Value,
) -> Result<heidi_util_rust::value::Value, ApiError> {
    use crate::get_default_client;
    let mut auth_request: heidi_util_rust::value::Value = value.clone().into();

    let client = get_default_client();
    let pd = if let Some(pdu) = value
        .get("presentation_definition_uri")
        .and_then(|a| a.as_str())
    {
        Some(
            client
                .get(pdu)
                .send()
                .await?
                .error_for_status()?
                .json::<heidi_util_rust::value::Value>()
                .await?,
        )
    } else {
        value.get("presentation_defintion").map(|pd| pd.into())
    };

    let mut metadata = if let Some(client_metadata_uri) =
        value.get("client_metadata_uri").and_then(|a| a.as_str())
    {
        let r: serde_json::Value = client
            .get(client_metadata_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Some(r)
    } else {
        value.get("client_metadata").cloned()
    };

    if let Some(metadata) = metadata.as_mut() {
        {
            let Some(metadata_stuff) = metadata.as_object_mut() else {
                use anyhow::anyhow;

                use crate::error::{GenericError, InnerError};

                return Err(ApiError::Generic(GenericError::Inner(InnerError::Anyhow(
                    anyhow!("metadata is not an object"),
                ))));
            };
            if let Some(jwks_uri) = metadata_stuff.get("jwks_uri").and_then(|a| a.as_str()) {
                let jwks = get_default_client()
                    .get(jwks_uri)
                    .send()
                    .await?
                    .json::<serde_json::Value>()
                    .await?;
                metadata_stuff.insert("jwks".to_string(), jwks);
            }
        }
        auth_request.as_object_mut().and_then(|a| {
            a.insert(
                "client_metadata".to_string(),
                heidi_util_rust::value::Value::from(metadata.clone()),
            )
        });
    }
    if let Some(pd) = pd {
        auth_request.as_object_mut().and_then(|a| {
            a.insert(
                "presentation_definition".to_string(),
                heidi_util_rust::value::Value::from_serialize(&pd)?,
            )
        });
    }

    Ok(auth_request)
}
