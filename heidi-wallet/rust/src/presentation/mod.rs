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
//! This module defines functions to allow the format agnostic presentation process. The
//! format specific implementations are in the respective modules.

use std::sync::Arc;
use std::time::SystemTime;

#[cfg(feature = "reqwest")]
use crate::agents::AgentInfo;
#[cfg(feature = "reqwest")]
use crate::get_reqwest_client;
#[cfg(feature = "reqwest")]
use crate::presentation::helper::encrypt_submission;
use crate::presentation::presentation_exchange::{
    AuthorizationRequest, PresentationDefinition, PresentationSubmission,
};
use crate::vc::VerifiableCredential;
use crate::{
    formats, log_warn, signing::SecureSubject, util::generate_code_verifier,
    vc::PresentableCredential, ApiError,
};

use ciborium::cbor;
use heidi_util_rust::value::Value;
#[cfg(feature = "reqwest")]
use helper::{ARWrapper, PresentationData};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};

pub mod helper;
pub mod presentation_exchange;

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// Object holding the relevant state for the presentation process.
pub struct PresentationProcess {
    _authorization_request: AuthorizationRequest,

    _agent_info: AgentInfo,
}
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg(feature = "reqwest")]
pub struct PresentationMetadata {
    authorization_request: Value,
    agent_info: AgentInfo,
    original_jwt: String,
}
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#[cfg(all(feature = "reqwest"))]
pub async fn parse_presentation_offer(
    blob: String,
) -> Result<PresentationMetadata, crate::ApiError> {
    let Ok(client) = get_reqwest_client().build() else {
        return Err(anyhow::anyhow!("client failed to build").into());
    };

    let (authorization_request, agent_info, original_jwt) =
        if let Ok(presentation_data) = blob.parse::<PresentationData>() {
            presentation_data
                .fetch_authorization_request(&client)
                .await?
        } else if let Ok(url) = blob.parse::<Url>() {
            let ARWrapper(authorization_request, agent_info, original) =
                ARWrapper::from_url_async(url).await?;
            (authorization_request, agent_info, original)
        } else if let Ok(value) = serde_json::from_str(&blob) {
            (
                value,
                AgentInfo {
                    r#type: crate::agents::AgentType::Verifier {
                        trust_chain: vec![],
                    },
                    name: String::default(),
                    domain: String::default(),
                    trust_anchor: String::default(),
                    valid: true,
                    trusted: false,
                },
                blob,
            )
        } else {
            AgentInfo::from_auth_request(blob)
                .await
                .map_err(|e| anyhow::anyhow!(e))?
        };

    Ok(PresentationMetadata {
        authorization_request,
        agent_info,
        original_jwt,
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
pub async fn initialize_proximity(jwt: String) -> Result<PresentationMetadata, crate::ApiError> {
    let (authorization_request, agent_info, original_jwt) = AgentInfo::from_auth_request(jwt)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(PresentationMetadata {
        authorization_request,
        agent_info,
        original_jwt,
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_matching_credentials_with_dif_pex(
    presentation_definition: Value,
    credentials: Vec<VerifiableCredential>,
    valid_at: Option<SystemTime>,
) -> Result<Vec<Vec<PresentableCredential>>, crate::ApiError> {
    let matching_mdoc =
        formats::mdoc::get_matching_credentials(&credentials, &presentation_definition, valid_at)?;
    let matching_sdjwt =
        formats::sdjwt::get_matching_credentials(&credentials, &presentation_definition, valid_at)?;
    let matching = [matching_mdoc, matching_sdjwt].concat();
    Ok(matching)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
pub fn present_credential_with_proximity(
    authorization_request: Value,
    credential: PresentableCredential,
    secure_subject: Arc<SecureSubject>,
) -> Result<Vec<u8>, crate::ApiError> {
    // let auth_request : AuthorizationRequest = authorization_request.transform().unwrap();
    let state = authorization_request
        .get("state")
        .and_then(|a| a.as_str())
        .map(|a| a.to_string());
    let mdoc_generated_nonce = generate_code_verifier();
    let vp_token = create_submission(
        authorization_request.clone(),
        credential.clone(),
        secure_subject,
        mdoc_generated_nonce.clone(),
    )?;
    log_warn!("PEX", "try deserializing presentaiton defintion");
    let presentation_definition: PresentationDefinition = authorization_request
        .get("presentation_definition")
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("No presentation definition found")))?
        .transform()
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("Transform failed")))?;
    let presentation_submission = PresentationSubmission {
        id: presentation_definition.id.to_string(),
        definition_id: presentation_definition.id.clone(),
        descriptor_map: serde_json::from_str(&credential.descriptor_map).unwrap_or(vec![]),
    };

    let data = match authorization_request
        .get("response_mode")
        .and_then(|a| a.as_str())
    {
        Some("direct_post.jwt") => {
            let Some(metadata) = authorization_request.get("client_metadata") else {
                return Err(anyhow::anyhow!("We don't have any client_metadata").into());
            };
            log_warn!("PEX", "get nonce");
            let nonce = authorization_request
                .get("nonce")
                .and_then(|a| a.as_str())
                .ok_or_else(|| ApiError::from(anyhow::anyhow!("No nonce found")))?
                .to_string();
            let response = encrypt_submission(
                heidi_util_rust::value::Value::String(vp_token),
                Value::from_serialize(&presentation_submission).ok_or_else(|| {
                    ApiError::from(anyhow::anyhow!("Coult not serialize presentation"))
                })?,
                mdoc_generated_nonce,
                nonce.as_bytes().to_vec(),
                state,
                metadata.to_owned(),
            )?;
            Ok::<_, ApiError>(json!({
                    "response": response
            }))
        }
        Some("direct_post") => {
            Ok(json!({
                "vp_token": vp_token,
                "presentation_submission": presentation_submission,
                "state": state,
                // "mdoc_generated_nonce": mdoc_generated_nonce
            }))
        }
        _ => Err(anyhow::anyhow!("Invalid response_mode").into()),
    }?;

    let data_bytes = serde_urlencoded::to_string(data).map_err(|e| anyhow::anyhow!(e))?;

    Ok(data_bytes.as_bytes().to_vec())
}

/// Use the provided presentation and the earlier fetched authorization_request to generate and
/// submit the presentation
#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg(feature = "reqwest")]
pub async fn get_dif_pex_vp_token(
    authorization_request: heidi_util_rust::value::Value,
    credential: PresentableCredential,
    secure_subject: Arc<SecureSubject>,
    mdoc_generated_nonce: String,
) -> Result<String, crate::ApiError> {
    let submission = create_submission(
        authorization_request,
        credential,
        secure_subject,
        mdoc_generated_nonce.clone(),
    )?;
    Ok(submission)
}

pub fn create_submission(
    authorization_request: Value,
    credential: PresentableCredential,
    secure_subject: Arc<SecureSubject>,
    mdoc_generated_nonce: String,
) -> Result<String, ApiError> {
    log_warn!("PEX", "before nonce");
    let nonce = authorization_request
        .get("nonce")
        .and_then(|a| a.as_str())
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("request invalid")))?
        .to_string();
    log_warn!("PEX", "before audience");
    let audience = authorization_request
        .get("client_id")
        .and_then(|a| a.as_str())
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("request invalid")))?
        .to_string();
    log_warn!("PEX", "transform presi");
    let presentation_definition = authorization_request
        .get("presentation_definition")
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("request invalid")))?
        .to_owned();
    // fix_pd_value(&mut val_pd);
    // let presentation_definition : PresentationDefinition = val_pd.transform().unwrap();

    let credential_type = credential.credential.get_type()?;

    // Check if cryptographic holder binding is required
    let requires_cryptographic_binding =
        is_cryptographic_holder_binding_required(&authorization_request);
    log_warn!(
        "PRESENTATION",
        &format!(
            "Cryptographic binding required: {}",
            requires_cryptographic_binding
        )
    );

    match credential_type.as_str() {
        "SdJwt" => Ok(helper::create_submission(
            nonce.clone(),
            audience.clone(),
            &presentation_definition,
            &credential,
            secure_subject,
            requires_cryptographic_binding,
        )?),
        "Mdoc" => {
            let response_uri = authorization_request
                .get("response_uri")
                .and_then(|a| a.as_str())
                .unwrap_or("");
            // let mdoc_generated_nonce = generate_code_verifier();
            let client_id_to_hash =
                cbor!([audience, mdoc_generated_nonce]).map_err(|e| anyhow::anyhow!(e))?;
            let response_uri_to_hash =
                cbor!([response_uri, mdoc_generated_nonce]).map_err(|e| anyhow::anyhow!(e))?;
            let client_id_hash =
                Sha256::digest(formats::mdoc::helper::serialize(&client_id_to_hash)?).to_vec();
            let response_uri_hash =
                Sha256::digest(formats::mdoc::helper::serialize(&response_uri_to_hash)?).to_vec();

            let (vp_token, _presentation_submission) = formats::mdoc::prepare_mdoc_submission(
                secure_subject.signer.clone(),
                credential,
                client_id_hash.clone(),
                response_uri_hash.clone(),
                nonce.clone(),
                &presentation_definition,
            )?;
            Ok(vp_token)
        }
        _ => Err(anyhow::anyhow!("Unsupported format: {credential_type}").into()),
    }
}

/// Fixes the problem of None vs empty object and so for the format designators in vc+sd-jwt
// fn fix_pd_value(val: &mut crate::value::Value) {
//     let ids = val.get_mut("input_descriptors").unwrap().as_array_mut().unwrap();
//     for id in ids {
//         let fmt = id.get_mut("format").unwrap().as_object_mut().unwrap();
//         if let Some(entry) = fmt.get_mut("vc+sd-jwt") {
//             *entry = crate::value::Value::Object(HashMap::new())
//         } else if let Some(entry) = fmt.get_mut("vc+sd-jwt") {
//             *entry = crate::value::Value::Object(HashMap::new())
//         }
//     }
// }

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {
    // use std::{sync::Arc, vec};

    // use crate::{
    //     presentation::PresentationProcess,
    //     vc::{VerifiableCredential, VerifiableCredentialStore},
    //     UNSAFE_TLS,
    // };
    // Test is interactive...
    // #[tokio::test]
    // pub async fn test_animo() {
    //     let link = "openid4vp://?request_uri=https%3A%2F%2Ffunke.animo.id%2Fsiop%2Fc01ea0f3-34df-41d5-89d1-50ef3d181855%2Fauthorization-requests%2F59d127bc-de50-4caf-9f49-341d3065765d";
    //     //let link = "openid4vp://?request_uri=https://10.122.150.225/wallet/request.jwt/s66vCeCkUv5ieSi1nMMM8GIxLf3h4OxF2T3sFelzNT_4mvhb_OS--G0z45MD-rODI_ry6vqeg9w-hvBBfYcIQg";
    //     let link = "openid4vp://?request_uri=https%3A%2F%2Ffunke.animo.id%2Fsiop%2Fc01ea0f3-34df-41d5-89d1-50ef3d181855%2Fauthorization-requests%2F1dc588a4-3da4-4fa2-8217-f6adcc26e961";
    //     let link = "openid4vp://?request_uri=https://demo.certification.openid.net/test/a/heidi-wallet/requesturi/F7uiPGqczMCJnl0M2yh8pvcQhIWcmYJdMseFYR78uII3NAlgWeBSUkBZBtzIkjld%23ba1xxXsD5HKgqmkDxZfgNUZHJnTnxFwT_Okf7NRECqo&client_id=demo.certification.openid.net";
    //     UNSAFE_TLS.store(true, std::sync::atomic::Ordering::Relaxed);
    //     #[derive(Debug)]
    //     struct Store;
    //     impl VerifiableCredentialStore for Store {
    //         fn get_all(&self) -> Vec<VerifiableCredential> {
    //             vec![]
    //         }
    //         fn get_all_where(&self, _used: bool) -> Vec<VerifiableCredential> {
    //             vec![]
    //         }
    //     }

    //     // let (ARWrapper)= ARWrapper::from_url_async(link).await.unwrap();

    //     let process = PresentationProcess::initialize(link.to_string(), Arc::new(Store))
    //         .await
    //         .unwrap();
    //     println!("{:?}", process.agent_info);
    //     println!("{:?}", process.authorization_request);
    // }
}

#[test]
fn test_presentation_parse() {
    let auth_request = r#"{
  "response_uri": "https://oid4vp-verifier-ws-dev.ubique.ch/v1/wallet/authorization",
  "aud": "https://self-issued.me/v2",
  "client_id_scheme": "x509_san_dns",
  "iss": "funke.ubique.ch",
  "response_type": "vp_token",
  "presentation_definition": {
    "id": "42e01950-e575-436e-836b-968338fff8f7",
    "input_descriptors": [
      {
        "id": "abcd-mitgliedskarte-ozomz_sdjwt",
        "name": "All credentials descriptor for SD-JWT format",
        "purpose": "To verify the disclosure of all attributes for the SD-JWT format",
        "format": {
          "vc+sd-jwt": {}
        },
        "group": [
          "A"
        ],
        "constraints": {
          "fields": [
            {
              "path": [
                "$['lastName']"
              ],
              "purpose": "purpose for lastName",
              "name": "lastName",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['firstName']"
              ],
              "purpose": "purpose for firstName",
              "name": "firstName",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['memberNr']"
              ],
              "purpose": "purpose for memberNr",
              "name": "memberNr",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['memberSince']"
              ],
              "purpose": "purpose for memberSince",
              "name": "memberSince",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['validUntil']"
              ],
              "purpose": "purpose for validUntil",
              "name": "validUntil",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['dateOfBirth']"
              ],
              "purpose": "purpose for dateOfBirth",
              "name": "dateOfBirth",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['vct']"
              ],
              "purpose": "purpose for vct",
              "name": "VCT sd-jwt",
              "filter": {
                "const": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/abcd-mitgliedskarte-ozomz/0.0.5"
              },
              "intent_to_retain": false,
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        }
      },
      {
        "id": "abcd-mitgliedskarte-ozomz_mdoc",
        "name": "All credentials descriptor for MSO MDOC format",
        "purpose": "To verify the disclosure of all attributes for the MSO MDOC format",
        "format": {
          "mso_mdoc": {
            "alg": [
              "ES256",
              "ES384",
              "ES512",
              "EdDSA"
            ]
          }
        },
        "group": [
          "A"
        ],
        "constraints": {
          "fields": [
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['lastName']"
              ],
              "purpose": "purpose for lastName",
              "name": "lastName",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['firstName']"
              ],
              "purpose": "purpose for firstName",
              "name": "firstName",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['memberNr']"
              ],
              "purpose": "purpose for memberNr",
              "name": "memberNr",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['memberSince']"
              ],
              "purpose": "purpose for memberSince",
              "name": "memberSince",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['validUntil']"
              ],
              "purpose": "purpose for validUntil",
              "name": "validUntil",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['ch.ubique.dev-ssi-schema-creator-ws.1']['dateOfBirth']"
              ],
              "purpose": "purpose for dateOfBirth",
              "name": "dateOfBirth",
              "intent_to_retain": false,
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        }
      }
    ],
    "name": "ABCD Mitgliedsausweis",
    "purpose": "ABCD Mitgliedschaft prüfen",
    "submission_requirements": [
      {
        "name": "sample submission requirement A",
        "purpose": "We only need a submission for one of two formats A",
        "rule": "pick",
        "count": 1,
        "from": "A"
      }
    ]
  },
  "state": "9c6385bf-d3b7-4f61-acad-6bca9b9c52bb",
  "nonce": "63rN9ze4aoybBI80qTDaXA",
  "client_id": "funke.ubique.ch",
  "client_metadata": {
    "vp_formats": {
      "mso_mdoc": {
        "alg": [
          "ES256",
          "ES384",
          "ES512",
          "EdDSA"
        ]
      },
      "vc+sd-jwt": {
        "kb-jwt_alg_values": [
          "ES256",
          "ES384",
          "ES512",
          "EdDSA"
        ],
        "sd-jwt_alg_values": [
          "ES256",
          "ES384",
          "ES512",
          "EdDSA"
        ]
      }
    },
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "use": "enc",
          "crv": "P-256",
          "x": "q483qsEP_LacxLokQJwjFeP478z79FLQKz4Ina7UXnA",
          "y": "brI5t4BdlFDueRdMDytcUcTgXZJnxX8gmzcQ-xoMbXA",
          "alg": "ECDH-ES"
        }
      ]
    }
  },
  "response_mode": "direct_post.jwt"
}"#;
    let auth_request_value: Value = serde_json::from_str(&auth_request).unwrap();
    let _auth_request: AuthorizationRequest = auth_request_value.transform().unwrap();
    println!("{:#?}", auth_request_value.get("presentation_definition"));
    let pd: PresentationDefinition = auth_request_value
        .get("presentation_definition")
        .unwrap()
        .transform()
        .unwrap();

    let back_pd: Value = Value::from_serialize(&pd).unwrap();
    println!("{back_pd:#?}");
    // fix_pd_value(&mut back_pd);
    // let pd: PresentationDefinition = back_pd.transform().unwrap();
    // println!("{auth_request:?}");
    // println!("{pd:?}");
}

/// Check if cryptographic holder binding is required based on the authorization request.
/// According to OpenID4VP spec, when require_cryptographic_holder_binding is set to false,
/// no proof needs to be sent.
fn is_cryptographic_holder_binding_required(authorization_request: &Value) -> bool {
    // Check if there's a DCQL query with require_cryptographic_holder_binding set to false
    if let Some(dcql_query) = authorization_request.get("dcql_query") {
        if let Some(credentials) = dcql_query.get("credentials").and_then(|c| c.as_array()) {
            // Check if any credential query has require_cryptographic_holder_binding set to false
            for credential_query in credentials {
                if let Some(Value::Boolean(false)) =
                    credential_query.get("require_cryptographic_holder_binding")
                {
                    // Check if the value is a boolean false
                    return false;
                }
            }
        }
    }

    // Default to requiring cryptographic holder binding if not specified
    true
}
