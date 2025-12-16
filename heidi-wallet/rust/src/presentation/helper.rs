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
//! Provide some helper functions in the presentation/proof process.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use heidi_jwt::jwt::creator::JwtCreator;
use regex::Regex;
use reqwest::Url;
use sdjwt::{ExternalSigner, Holder, SpecVersion};
use serde::Deserialize;
use serde_json::{json, Value};

#[cfg(feature = "reqwest")]
use crate::agents::{AgentInfo, AgentType};
#[cfg(all(feature = "reqwest", feature = "oid4vp"))]
use crate::get_reqwest_client;
use crate::jwx::EncryptionParameters;
use crate::presentation::presentation_exchange::{
    AuthorizationRequest, ClientIdScheme, ClientMetadataResource, PresentationDefinition,
};
use crate::vc::PresentableCredential;
use crate::{log_debug, log_warn, ApiError};

/// Wrap AuthorizationRequest and AgentInfo into one struct
pub(crate) struct ARWrapper(pub heidi_util_rust::value::Value, pub AgentInfo, pub String);

impl From<(heidi_util_rust::value::Value, AgentInfo, String)> for ARWrapper {
    fn from(value: (heidi_util_rust::value::Value, AgentInfo, String)) -> Self {
        ARWrapper(value.0, value.1, value.2)
    }
}

impl ARWrapper {
    /// Try fetching AuthorizationRequest and AgentInfo from a data blob.
    /// Usually the data blob is encoded in a QR-Code and contains an url-scheme known
    /// to the Wallet.
    /// We also provide some fallback mechanisms to account for earlier (slightly) wrong versions.
    pub async fn from_url_async(url: Url) -> Result<Self, ApiError> {
        log_warn!("RDDEBUG", "from_url_async");
        let Ok(client) = get_reqwest_client().build() else {
            return Err(anyhow::anyhow!("client failed to build").into());
        };
        let scheme = url.scheme();
        if ![
            "https",
            "http",
            "openid4vp",
            "haip",
            "mdoc-openid4vp",
            "eudi-openid4vp",
            "swiyu",
        ]
        .contains(&scheme)
        {
            return Err(anyhow!("invalid scheme").into());
        }
        let params: serde_json::Value =
            serde_urlencoded::from_str(url.query().unwrap_or("")).unwrap_or_default();
        if let Some(redirect_uri) = params.get("redirect_uri").and_then(|a| a.as_str()) {
            let data = PresentationData {
                redirect_uri: redirect_uri.to_string(),
            };
            log_warn!("RDDEBUG", "from_url_async try fetch");
            return Ok(data.fetch_authorization_request(&client).await?.into());
        }
        if let Some(redirect_uri) = params.get("request_uri").and_then(|a| a.as_str()) {
            let data = PresentationData {
                redirect_uri: redirect_uri.to_string(),
            };
            return Ok(data.fetch_authorization_request(&client).await?.into());
        }
        log_warn!("RDDEBUG", "from_url_async try fetch");
        if let Ok(auth_request) = url.to_string().parse::<AuthorizationRequest>() {
            let v: heidi_util_rust::value::Value = serde_json::to_value(&auth_request)?.into();
            return Ok(ARWrapper(
                v,
                AgentInfo {
                    r#type: AgentType::Verifier {
                        trust_chain: vec![],
                    },
                    name: auth_request.body.client_id.clone(),
                    domain: auth_request.body.client_id.clone(),
                    trust_anchor: "".to_string(),
                    valid: auth_request.body.client_id
                        == auth_request.body.response_uri.unwrap_or_default(),
                    trusted: false,
                },
                url.to_string(),
            ));
        }

        let presentation_definition = if let Some(presentation_definition_uri) = params
            .get("presentation_definition_uri")
            .and_then(|a| a.as_str())
        {
            let r: PresentationDefinition = client
                .get(presentation_definition_uri)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Some(r)
        } else if let Some(pd) = params.get("presentation_definition") {
            Some(serde_json::from_value(pd.clone()).map_err(|e| anyhow!(e))?)
        } else {
            None
        };
        let metadata = if let Some(client_metadata_uri) =
            params.get("client_metadata_uri").and_then(|a| a.as_str())
        {
            let r: Value = client
                .get(client_metadata_uri)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Some(r)
        } else {
            params.get("client_metadata").cloned()
        };
        let mut auth_request = AuthorizationRequest::builder();
        if let Some(metadata) = metadata.as_ref() {
            if let Ok(metadata) = serde_json::from_value::<ClientMetadataResource>(metadata.clone())
            {
                auth_request = auth_request.client_metadata(metadata);
            }
        }
        if let Some(pd) = presentation_definition {
            auth_request = auth_request.presentation_definition(pd);
        }
        let auth_request = auth_request
            .client_id(
                params
                    .get("client_id")
                    .and_then(|a| a.as_str())
                    .ok_or(anyhow!("client_id missing"))?,
            )
            .client_id_scheme(
                params
                    .get("client_id_scheme")
                    .and_then(|a| serde_json::from_value::<ClientIdScheme>(a.clone()).ok())
                    .ok_or(anyhow!("client_id_scheme missing"))?,
            )
            .state(
                params
                    .get("state")
                    .and_then(|a| a.as_str())
                    .ok_or(anyhow!("state missing"))?,
            )
            .response_mode(
                params
                    .get("response_mode")
                    .and_then(|a| a.as_str())
                    .ok_or(anyhow!("response_mode missing"))?,
            )
            .response_uri(
                params
                    .get("response_uri")
                    .and_then(|a| a.as_str())
                    .ok_or(anyhow!("response_uri missing"))?,
            )
            .nonce(
                params
                    .get("nonce")
                    .and_then(|a| a.as_str())
                    .ok_or(anyhow!("nonce missing"))?,
            )
            .build()
            .map_err(|e| anyhow!(e))?;
        let name = metadata
            .as_ref()
            .and_then(|a| a.get("client_name"))
            .and_then(|a| a.as_str())
            .map(|a| a.to_string())
            .unwrap_or(String::from(
                params
                    .get("client_id")
                    .and_then(|a| a.as_str())
                    .unwrap_or(""),
            ));
        let v: heidi_util_rust::value::Value = serde_json::to_value(&auth_request)?.into();
        Ok(ARWrapper(
            v.clone(),
            AgentInfo {
                r#type: AgentType::Verifier {
                    trust_chain: vec![],
                },
                name,
                domain: auth_request.body.client_id.clone(),
                trust_anchor: "".to_string(),
                valid: auth_request.body.client_id
                    == auth_request.body.response_uri.unwrap_or_default(),
                trusted: false,
            },
            url.to_string(),
        ))
    }
}

/// Data struct defining what information is needed for the wallet
/// to start a presentation.
#[derive(Debug, Deserialize)]
pub(super) struct PresentationData {
    pub(super) redirect_uri: String,
}

impl FromStr for PresentationData {
    type Err = anyhow::Error;

    fn from_str(blob: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(blob).map_err(|e| e.into())
    }
}

impl PresentationData {
    /// Using the URI fetch the authorization_request, parse and validate it!
    pub(super) async fn fetch_authorization_request(
        &self,
        client: &reqwest::Client,
    ) -> Result<(heidi_util_rust::value::Value, AgentInfo, String), ApiError> {
        let jwt_response = client.get(&self.redirect_uri).send().await?;

        if !jwt_response.status().is_success() {
            let headers = jwt_response.headers().clone();
            let status = jwt_response.status().as_u16();

            let jwt: Option<String> = jwt_response.text().await.ok();
            return Err((status, jwt, headers).into());
        }
        let Ok(jwt) = jwt_response.text().await else {
            return Err(anyhow!("Could not read response body").into());
        };
        println!("{jwt}");

        AgentInfo::from_auth_request(jwt)
            .await
            .map_err(|e| anyhow!(e).into())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encrypt_submission(
    vp_token: heidi_util_rust::value::Value,
    submission: heidi_util_rust::value::Value,
    mdoc_generated_nonce: String,
    nonce: Vec<u8>,
    state: Option<String>,
    metadata: heidi_util_rust::value::Value,
) -> Result<String, ApiError> {
    log_warn!("PEX", "start encryption");
    let encrypter = EncryptionParameters::try_from(&metadata)?;
    let object = if let Some(state) = state {
        if submission.is_null() {
            json!({
                "vp_token": vp_token,
                "state" : state
            })
        } else {
            json!({
                "vp_token": vp_token,
                "presentation_submission": submission,
                "state" : state
            })
        }
    } else if submission.is_null() {
        json!({
            "vp_token": vp_token
        })
    } else {
        json!({
            "vp_token": vp_token,
            "presentation_submission": submission
        })
    }
    .as_object()
    .ok_or_else(|| anyhow!("Should not happen"))?
    .to_owned();
    let response = encrypter.encrypt(
        object,
        Some(mdoc_generated_nonce.as_bytes().to_vec()),
        Some(nonce),
    )?;
    Ok(response)
}

/// Create a submission using the format agnostic version.
pub(super) fn create_submission(
    nonce: String,
    audience: String,
    presentation_definition: &heidi_util_rust::value::Value,
    credential: &PresentableCredential,
    external_signer: Arc<dyn ExternalSigner>,
    requires_cryptographic_binding: bool,
) -> Result<String, ApiError> {
    let sd_jwt = &credential.credential.payload;

    let mut jwt_presentation = Holder::presentation_with_nonce(sd_jwt, Some(nonce.clone()))
        .context("Could not generate presentation")?;

    // Only perform device binding if cryptographic holder binding is required
    if requires_cryptographic_binding {
        jwt_presentation
            .device_binding(&audience, external_signer.clone(), &external_signer.alg())
            .context("device binding failed")?;
        log_warn!("PRESENTATION", "Applied cryptographic device binding");
    } else {
        log_warn!(
            "PRESENTATION",
            "Skipped cryptographic device binding - claim-based binding"
        );
    }
    jwt_presentation.redact_all().context("redact all failed")?;

    let input_descriptors = presentation_definition
        .get("input_descriptors")
        .and_then(|a| a.as_array())
        .ok_or(anyhow!("No input descriptors"))?;
    let input_descriptor = input_descriptors
        .iter()
        .find(|input_descriptor| {
            input_descriptor
                .get("id")
                .and_then(|a| a.as_str())
                .map(|a| a == &credential.response_id)
                .unwrap_or(false)
        })
        .ok_or(anyhow!("No input descriptors"))?;

    let transaction_data = input_descriptor
        .get("transaction_data")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .flat_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect::<Vec<_>>()
        });

    for field in input_descriptor
        .get("constraints")
        .and_then(|a| a.get("fields"))
        .and_then(|a| a.as_array())
        .ok_or(anyhow!("No fields"))?
    {
        let Some(path) = field.get("path").and_then(|a| a.as_array()) else {
            continue;
        };
        for p in path {
            let Some(p) = p.as_str() else { continue };
            let p = transform_disclosure_path(p);
            log_debug!("PEX", &format!("Disclosing: {p}"));
            jwt_presentation.disclose(&p).context("Disclosing failed")?;
        }
    }
    if let Some(transaction_data) = transaction_data.clone() {
        jwt_presentation
            .with_transaction_data(transaction_data, SpecVersion::PotentialUc5)
            .context("Transaction data failed")?;
    }
    let vp_token = match jwt_presentation.build() {
        Ok(token) => token,
        Err(sdjwt::Error::SigningFailed(msg)) if msg == "InvalidSecret" => {
            return Err(ApiError::Signing(crate::error::SigningError::InvalidSecret))
        }
        Err(e) => return Err(anyhow!(e).into()),
    };
    Ok(vp_token)
}

// /// Submit the presentation to the verifier backend.
// pub(super) async fn submit_submission(
//     client: &reqwest::Client,
//     submission: Oid4vpParams,
//     response_uri: &str,
//     state: Option<String>,
//     use_https: bool,
//     _mdoc_generated_nonce: String,
// ) -> Result<Option<String>, ApiError> {
//     let data = match submission {
//         Oid4vpParams::Params {
//             vp_token,
//             presentation_submission,
//         } => {
//             if let Some(state) = state {
//                 json!({
//                     "vp_token": vp_token,
//                     "presentation_submission": serde_json::to_string(&presentation_submission).map_err(|e| anyhow!(e))?,
//                     "state": state,
//                     // "mdoc_generated_nonce": mdoc_generated_nonce
//                 })
//             } else {
//                 json!({
//                     "vp_token": vp_token,
//                     "presentation_submission": serde_json::to_string(&presentation_submission).map_err(|e| anyhow!(e))?,
//                     // "mdoc_generated_nonce": mdoc_generated_nonce
//                 })
//             }
//         }
//         Oid4vpParams::Jwt { response } => {
//             json!({
//                 "response": response
//             })
//         }
//     };
//
//     let url = if use_https {
//         if response_uri.starts_with("https") {
//             response_uri.to_string()
//         } else {
//             format!("https://{response_uri}")
//         }
//     } else {
//         format!("http://{response_uri}")
//     };
//
//     let resp = client.post(url).form(&data).send().await?;
//
//     if !resp.status().is_success() {
//         let reason = resp.text().await?;
//         return Err(anyhow::anyhow!("Submission failed due to: {reason}").into());
//     }
//
//     if let Ok(json) = resp.json::<serde_json::Value>().await {
//         Ok(json
//             .get("redirect_uri")
//             .and_then(|a| a.as_str())
//             .map(|a| a.to_string()))
//     } else {
//         Ok(None)
//     }
// }

#[cfg_attr(feature = "uniffi", uniffi::export)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
/// Create test credentials
pub fn sign_with_test_issuer_key(kb_public_key: Vec<u8>, json: String) -> String {
    let pem = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCpSMiJj/aWKGNlg3
QDVxPuyj2MJjrfJpObqhmKuzjXWhRANCAARoOdx9P/3Pr9TOyWtvRNnv9gyVEJd9
eQitkfKWSHR/Sco6Jm/PJkO2ozsMJz5R5k7/+bXVJWll7Lo4xfKij8XI
-----END PRIVATE KEY-----"#;

    let signer = josekit::jws::ES256.signer_from_der(&pem).unwrap();

    // let issuer = EncodingKey::from_ec_pem(pem).unwrap();
    let payload = {
        let mut payload: serde_json::Value =
            serde_json::from_str(&json).expect("json decoding failed");
        let public_key =
            p256::PublicKey::from_sec1_bytes(&kb_public_key).expect("public_key decoding failed");
        let jwk = public_key.to_jwk();

        payload["cnf"] = json!({
            "jwk": serde_json::to_value(&jwk).unwrap()
        });
        payload["cnf"]["jwk"]["alg"] = serde_json::Value::String("ES256".into());
        payload
    };
    let mut header = josekit::jws::JwsHeader::new();
    header.set_algorithm(josekit::jws::ES256.name());
    header.set_token_type("vc+sd-jwt");

    payload
        .create_jwt(
            &header,
            Some("example-test"),
            heidi_jwt::chrono::Duration::weeks(52),
            &signer,
        )
        .expect("JWT creation failed")
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub async fn start_test_presentation() -> String {
    let data = json!({
        "client_id" : "schnapsladen.ubique.de",
        "nonce": "tests-nonce",
        "name": "Sample credential request",
        "purpose": "API tests",
        "input_descriptors": [
            {
                "id": "some credential",
                "name": "sample input descriptor",
                "purpose": "API tests",
                "group": ["A"],
                "format" : ["dc+sd-jwt"],
                "fields": [{
                    "path": [ "$.given_name" ],
                    "name": "sample input descriptor field",
                    "purpose": "API tests",
                    "optional": false
                }]
            }
        ],
        "submission_requirements": [
            {
                "name": "sample submission requirement",
                "purpose": "API tests",
                "rule": "pick",
                "count": 1,
                "from": "A"
            }
        ]
    })
    .to_string();
    let data = json!({
        "credentialRequest": data
    });

    let client = get_reqwest_client().build().unwrap();
    const BASE_URL: &str = "https://oid4vp-verifier-ws-dev.ubique.ch";
    let resp = client
        .post(format!("{BASE_URL}/v1/verifier/par"))
        .form(&data)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    println!("{resp}");

    resp["requestUri"].as_str().unwrap().to_string()
}

/// Use a originally jsonpath disclosure_path and transform it to a normalized version.
pub fn transform_disclosure_path(path: &str) -> String {
    thread_local! {
        // We know the regex works!
        static ARRAY_INDICES : Regex =  #[allow(clippy::unwrap_used, clippy::expect_used)] { Regex::new(r"\[(\d+)\]").unwrap() };
        static PROPERTY_ACCESSOR : Regex = #[allow(clippy::unwrap_used, clippy::expect_used)] { Regex::new(r"\[('.+?')\]").unwrap() };
    };

    ARRAY_INDICES.with(move |a| {
        PROPERTY_ACCESSOR.with(move |b| {
            let p = a.replace_all(path, "/$1");
            let p = b.replace_all(&p, "/$1");

            let p = p
                .replace('$', "")
                .replace('.', "/")
                .replace("[", "")
                .replace("]", "")
                .replace("'", "");
            p.to_string()
        })
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// get disclosure path to allow for better localization handling
pub fn get_disclosure_path(path: String) -> String {
    let path = path.replace("$['eu.europa.ec.eudi.pid.1']", "");
    transform_disclosure_path(&path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::VecDeque;

    use base64::Engine;

    use super::transform_disclosure_path;

    #[test]
    fn test_transform() {
        let path = "$['age_equal_or_over']['16']";
        let p = transform_disclosure_path(path);
        assert_eq!("/age_equal_or_over/16", p.as_str());

        let path = "$['place_of_birth']['locality']";
        let p = transform_disclosure_path(path);
        assert_eq!("/place_of_birth/locality", p.as_str());

        let path = "$['age_in_years']";
        let p = transform_disclosure_path(path);
        assert_eq!("/age_in_years", p.as_str());
    }

    #[test]
    fn test_chain_validation() {
        let mut data = ["MIIBZzCCAQ2gAwIBAgIGAZEso3O5MAoGCCqGSM49BAMCMB8xHTAbBgNVBAMMFGh0dHBzOi8vYXV0aG9yaXR5LmNoMB4XDTI0MDgwNzExMzk1NVoXDTI1MDgwNzExMzk1NVowITEfMB0GA1UEAwwWc2NobmFwc2xhZGVuLnViaXF1ZS5kZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKuPN6rBD/y2nMS6JECcIxXj+O/M+/RS0Cs+CJ2u1F5wbrI5t4BdlFDueRdMDytcUcTgXZJnxX8gmzcQ+xoMbXCjMzAxMCEGA1UdEQQaMBiCFnNjaG5hcHNsYWRlbi51YmlxdWUuZGUwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiAlGalROicGPBCjeHQE7z+iNLCdzJu55qznLMV3t//21QIhAPkoattZLCoUy28gf9IvbIVNZiB49a88y7XrrMRwR3c0","MIIBZTCCAQygAwIBAgIGAZEso3OBMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMMFGh0dHBzOi8vYXV0aG9yaXR5LmNoMB4XDTI0MDgwNzExMzk1NVoXDTI1MDgwNzExMzk1NVowHzEdMBsGA1UEAwwUaHR0cHM6Ly9hdXRob3JpdHkuY2gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAScIjAmHrkp3TC6bisgaqmszbKkpY0iGTdHF2rcRemJCV+ikotDt7G+ApwG0m6fxt8aBJHeJ2mssLvZBmZj5LtWozQwMjAfBgNVHREEGDAWghRodHRwczovL2F1dGhvcml0eS5jaDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBwVkphb/oKV1raVo+gHmnxnAasvbX4IlDpp2dO9ROxOAiBwmoYDC4L/zjO/+Tt2YqrE2fK3bUyMvnTyI+Reia9IgA=="].iter().map(|a| base64::prelude::BASE64_STANDARD.decode(a).unwrap()).collect::<VecDeque<_>>();

        let leaf_certificate = data.pop_front().unwrap();
        let (_, parsed_cert) =
            x509_parser::parse_x509_certificate(&leaf_certificate).expect("Could not parse x509");
        println!("{:?}", parsed_cert.subject_alternative_name());

        let jwt = "eyJ4NWMiOlsiTUlJQlp6Q0NBUTJnQXdJQkFnSUdBWkVzdmt6Wk1Bb0dDQ3FHU000OUJBTUNNQjh4SFRBYkJnTlZCQU1NRkdoMGRIQnpPaTh2WVhWMGFHOXlhWFI1TG1Ob01CNFhEVEkwTURnd056RXlNRGt4TkZvWERUSTFNRGd3TnpFeU1Ea3hORm93SVRFZk1CMEdBMVVFQXd3V2MyTm9ibUZ3YzJ4aFpHVnVMblZpYVhGMVpTNWtaVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCS3VQTjZyQkQveTJuTVM2SkVDY0l4WGorTy9NKy9SUzBDcytDSjJ1MUY1d2JySTV0NEJkbEZEdWVSZE1EeXRjVWNUZ1haSm54WDhnbXpjUSt4b01iWENqTXpBeE1DRUdBMVVkRVFRYU1CaUNGbk5qYUc1aGNITnNZV1JsYmk1MVltbHhkV1V1WkdVd0RBWURWUjBUQVFIL0JBSXdBREFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUJIK3lDYTlTaGVtc0xQU1ladFEzWVpoUWVPZWNyWTBHRGFtNzhPclJoMVdBSWhBS1JER3A1Yjc1enF2b0p1VWRWVFBWVEI2VGI2QWZ4SkVYY2FZcTk3UHFnbSIsIk1JSUJaakNDQVF5Z0F3SUJBZ0lHQVpFc3Zrek9NQW9HQ0NxR1NNNDlCQU1DTUI4eEhUQWJCZ05WQkFNTUZHaDBkSEJ6T2k4dllYVjBhRzl5YVhSNUxtTm9NQjRYRFRJME1EZ3dOekV5TURreE5Gb1hEVEkxTURnd056RXlNRGt4TkZvd0h6RWRNQnNHQTFVRUF3d1VhSFIwY0hNNkx5OWhkWFJvYjNKcGRIa3VZMmd3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNjSWpBbUhya3AzVEM2YmlzZ2FxbXN6YktrcFkwaUdUZEhGMnJjUmVtSkNWK2lrb3REdDdHK0Fwd0cwbTZmeHQ4YUJKSGVKMm1zc0x2WkJtWmo1THRXb3pRd01qQWZCZ05WSFJFRUdEQVdnaFJvZEhSd2N6b3ZMMkYxZEdodmNtbDBlUzVqYURBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFDS3lDckVkT1dYeXFKT1lXQWtIcFdNZWRWRXRTTVVPSUhveEhoZmNBeWxxQUlnVFJtcGJmaEJXOGJ6UGFyR2E2NGhQUG4zMGNvK3plaFdqQUFNWGlIRjNDND0iXSwiYWxnIjoiRVMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJvaWQ0dnAtdmVyaWZpZXItd3MtZGV2LnViaXF1ZS5jaC92MS93YWxsZXQvYXV0aG9yaXphdGlvbiIsImF1ZCI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIiLCJjbGllbnRfaWRfc2NoZW1lIjoieDUwOV9zYW5fZG5zIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJhMjJhN2ZjYy1mZTM3LTQ5ZTItOTU4My1lMmM2MGYxNjI3NzQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJzb21lIGNyZWRlbnRpYWwiLCJuYW1lIjoic2FtcGxlIGlucHV0IGRlc2NyaXB0b3IiLCJwdXJwb3NlIjoiQVBJIHRlc3RzIiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6e319LCJncm91cCI6WyJBIl0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmdpdmVuX25hbWUiXSwicHVycG9zZSI6IkFQSSB0ZXN0cyIsIm5hbWUiOiJzYW1wbGUgaW5wdXQgZGVzY3JpcHRvciBmaWVsZCIsImludGVudF90b19yZXRhaW4iOmZhbHNlLCJvcHRpb25hbCI6ZmFsc2V9XSwibGltaXRfZGlzY2xvc3VyZSI6InJlcXVpcmVkIn19XSwibmFtZSI6IlNhbXBsZSBjcmVkZW50aWFsIHJlcXVlc3QiLCJwdXJwb3NlIjoiQVBJIHRlc3RzIiwic3VibWlzc2lvbl9yZXF1aXJlbWVudHMiOlt7Im5hbWUiOiJzYW1wbGUgc3VibWlzc2lvbiByZXF1aXJlbWVudCIsInB1cnBvc2UiOiJBUEkgdGVzdHMiLCJydWxlIjoiUElDSyIsImNvdW50IjoxLCJmcm9tIjoiQSJ9XX0sInN0YXRlIjoiNjFkMjBiZGMtYjc5Yi00ZDVjLWIzOWMtNjAzY2RiMWVmYjI4Iiwibm9uY2UiOiJ0ZXN0cy1ub25jZSIsImNsaWVudF9pZCI6InNjaG5hcHNsYWRlbi51YmlxdWUuZGUiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJtc29fbWRvYyI6eyJhbGciOlsiRVMyNTYiLCJFUzM4NCIsIkVTNTEyIiwiRWREU0EiXX0sInZjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiLCJFZERTQSJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiLCJFZERTQSJdfX19LCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QifQ.PKXofatUruhhaGoeGbpLUZce-7WpQYusEaoNYDoe9964GgVLaOEQ9s09zsR3HJLUiKQ-32HOSoVFELCovs_SqA";

        // let header = jsonwebtoken::decode_header(jwt).unwrap();
        // let key = parsed_cert.public_key().subject_public_key.as_ref();
        // let key = match header.alg {
        //     jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384 => {
        //         jsonwebtoken::DecodingKey::from_ec_der(key)
        //     }
        //     Algorithm::PS256
        //     | Algorithm::PS384
        //     | Algorithm::RS256
        //     | Algorithm::RS384
        //     | Algorithm::RS512 => jsonwebtoken::DecodingKey::from_rsa_der(key),
        //     Algorithm::EdDSA => jsonwebtoken::DecodingKey::from_ed_der(key),
        //     _ => panic!("{:?} not supported", header.alg),
        // };
        // let mut validation = Validation::default();
        // validation.required_spec_claims = Default::default();
        // validation.validate_exp = false;
        // validation.algorithms = vec![Algorithm::ES256, Algorithm::ES384];
        // let token = jsonwebtoken::decode::<AuthorizationRequest>(jwt, &key, &validation).unwrap();
        // println!("{token:?}");
    }
}
