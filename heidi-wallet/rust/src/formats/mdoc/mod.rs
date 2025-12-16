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

//! Some presentation process specific functions handling the mdoc format. It includes finding matching credentials
//! based on a credential request and such.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use anyhow::{anyhow, ensure, Context};
use ciborium::{cbor, Value};
use helper::CBorHelper;
use jsonpath_lib as jsonpath;

use serde_json::{json, Value as JsonValue};

use crate::{
    crypto::{b64url_decode_bytes, b64url_encode_bytes},
    presentation::presentation_exchange::{
        ClaimFormatDesignation, FieldQueryResult, InputDescriptor, InputDescriptorMappingObject,
        Oid4vpParams, PresentationSubmission,
    },
    signing::NativeSigner,
    vc::{PresentableCredential, VerifiableCredential},
    ApiError,
};

#[cfg(feature = "uniffi")]
use crate::jwx::EncryptionParameters;

pub mod helper;

const SIGN_ALG_KEY: i64 = 1;
const SIGN_ALG_ES256: i64 = -7;
/// Get issuer auth from the issuer_signed struct
pub(crate) fn get_issuer_auth_payload(issuer_signed: &Value) -> Result<Value, ApiError> {
    let payload_bytes = issuer_signed
        .get("issuerAuth")?
        .as_array()
        .context("issuerAuth is not an array!")?
        .get(2)
        .context("issuerAuth has no payload!")?
        .as_bytes()
        .context("payload is not a byte array")?;

    let payload = helper::deserialize(payload_bytes)?;
    let bytes = payload
        .as_expect_tag(24)?
        .as_bytes()
        .context("payload is not a byte array!")?;

    helper::deserialize(bytes)
}

/// Get mdoc version
pub(crate) fn get_version(issuer_signed: &Value) -> Result<String, ApiError> {
    get_issuer_auth_payload(issuer_signed)?
        .get("version")?
        .clone()
        .into_text()
        .map_err(|_| anyhow::anyhow!("version is not a string!").into())
}

/// Get mdoc document type
pub(crate) fn get_doc_type(issuer_signed: &Value) -> Result<String, ApiError> {
    get_issuer_auth_payload(issuer_signed)?
        .get("docType")?
        .clone()
        .into_text()
        .map_err(|_| anyhow::anyhow!("docType is not a string!").into())
}

/// Use the various cbor parsings to determine the validity of the mdoc.
/// Although the ISO defines exactly what CBOR encoding to use (CBOR_TAG_DATETIME_STRING), out of experience
/// we should support all possible CBOR encodings.
#[allow(clippy::expect_used)]
pub(crate) fn get_valid_until(issuer_signed: &Value) -> Result<SystemTime, ApiError> {
    let valid_until = get_issuer_auth_payload(issuer_signed)?
        .get("validityInfo")?
        .get("validUntil")?
        .clone();

    // Parse date time:
    const CBOR_TAG_DATETIME_STRING: u64 = 0; // see https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
    const CBOR_TAG_DATETIME_EPOCH: u64 = 1;
    if let Some(valid_until) = valid_until.as_text() {
        Ok(chrono::DateTime::parse_from_rfc3339(valid_until)?.into())
    } else if let Ok(valid_until) = valid_until.as_expect_tag(CBOR_TAG_DATETIME_STRING) {
        Ok(chrono::DateTime::parse_from_rfc3339(
            valid_until
                .as_text()
                .expect("CBOR standard date/time string must be string"),
        )?
        .into())
    } else {
        let valid_until = valid_until.as_expect_tag(CBOR_TAG_DATETIME_EPOCH)?;
        if let Some(seconds) = valid_until.as_integer() {
            Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds.try_into()?))
        } else {
            let seconds = valid_until
                .as_float()
                .expect("CBOR epoch-based date/time must be integer or float");
            Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(seconds))
        }
    }
}

/// Convenience conversion to be able to use the same functions (e.g. jsonpath) as for SD-Jwts.
pub(crate) fn namespaces_to_json_map(namespaces: &Value, raw: bool) -> Result<JsonValue, ApiError> {
    fn process_ns(ns: &Value, raw: bool) -> Result<JsonValue, ApiError> {
        let values = ns
            .as_array()
            .context("nameSpace is not an array")?
            .iter()
            .map(|v| {
                let obj = v
                    .as_tag()
                    .and_then(|(_, v)| v.as_bytes())
                    .map(|bytes| helper::deserialize(bytes))
                    .context("nameSpace entry is not a tagged byte array")??
                    .into_map()
                    .map_err(|_| anyhow::anyhow!("nameSpace entry is not a map"))?;

                let key = obj
                    .iter()
                    .find_map(|(k, v)| {
                        (k == &Value::Text("elementIdentifier".into())).then_some(v.clone())
                    })
                    .context("nameSpace entry has no 'elementIdentifier'")?
                    .as_text()
                    .context("elementIdentifier is not text!")?
                    .to_owned();

                let value = if raw {
                    let bytes = helper::serialize(&Value::Map(obj))?;
                    let base64url = b64url_encode_bytes(&bytes);

                    JsonValue::String(base64url)
                } else {
                    obj.iter()
                        .find_map(|(k, v)| {
                            (k == &Value::Text("elementValue".into())).then_some(v.clone())
                        })
                        .context("nameSpace entry has no 'elementValue'")?
                        .to_json_value()
                        .context("elementValue couldn't be converted to json!")?
                        .to_owned()
                };

                Ok::<_, ApiError>((key, value))
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()?;

        Ok(JsonValue::Object(values))
    }

    let ns_map = namespaces
        .as_map()
        .context("nameSpaces is not a map!")?
        .iter()
        .map(|(k, v)| {
            Ok::<_, ApiError>((
                k.as_text().context("nameSpace key is not text")?.to_owned(),
                process_ns(v, raw)?,
            ))
        })
        .collect::<Result<serde_json::Map<_, _>, _>>()?;

    Ok(JsonValue::Object(ns_map))
}

pub enum Either<A, B> {
    A(A),
    B(B),
}

/// Check if an input_descriptor matches a credential
pub fn evaluate_input_raw(
    input_descriptor: &heidi_util_rust::value::Value,
    value: &Value,
) -> Option<Either<bool, Vec<FieldQueryResult>>> {
    let input_descriptor: InputDescriptor = input_descriptor.transform().unwrap();
    if input_descriptor.constraints.fields.is_none() {
        return Some(Either::A(true));
    }
    crate::presentation::presentation_exchange::evaluate_input_raw(
        &input_descriptor,
        &namespaces_to_json_map(value, false).ok()?,
    )
    .map(|b| Either::B(b))
}

/// Find all matching credentials given a [PresentationDefinition]. If [valid_at] is provided
/// filter out credentials that are not valid anymore.
pub(crate) fn get_matching_credentials(
    credentials: &[VerifiableCredential],
    presentation_definition: &heidi_util_rust::value::Value,
    valid_at: Option<SystemTime>,
) -> Result<Vec<Vec<PresentableCredential>>, ApiError> {
    let credentials = credentials
        .iter()
        .filter_map(|cred| {
            let r#type = cred.get_type().ok()?;

            (&r#type == "Mdoc").then_some({
                let bytes = b64url_decode_bytes(&cred.payload).ok()?;
                (helper::deserialize(&bytes).ok()?, cred)
            })
        })
        .filter(|(credential, _)| {
            let Some(valid_at) = valid_at else {
                return true;
            };
            let Ok(valid_until) = get_valid_until(credential) else {
                return true; // invalid document, or maybe just valid indefinitly? Cautiously keep it.
            };
            valid_at < valid_until
        })
        .collect::<Vec<(_, _)>>();

    let input_descriptors = presentation_definition
        .get("input_descriptors")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|id| {
            if id.get("format").is_none() {
                true
            } else {
                id.get("format")
                    .unwrap()
                    .as_object()
                    .map(|format| format.contains_key("mso_mdoc"))
                    .unwrap_or(false)
            }
        })
        .collect::<Vec<_>>();

    if input_descriptors.is_empty() {
        return Ok(vec![]);
    }

    let presentables = credentials
        .iter()
        .filter_map(|(credential, raw)| {
            let results = input_descriptors
                .iter()
                .filter_map(|input_descriptor| {
                    evaluate_input_raw(input_descriptor, credential.get("nameSpaces").ok()?).map(
                        |results| {
                            let obj = InputDescriptorMappingObject {
                                id: input_descriptor
                                    .get("id")
                                    .unwrap()
                                    .as_str()
                                    .unwrap()
                                    .to_string(),
                                format: ClaimFormatDesignation::MsoMdoc,
                                path: "$".to_string(),
                                path_nested: None,
                            };
                            (
                                results,
                                obj,
                                input_descriptor
                                    .get("group")
                                    .cloned()
                                    .unwrap_or(heidi_util_rust::value::Value::Null),
                            )
                        },
                    )
                })
                .filter(|(fields_evaluation, obj, _)| {
                    // if fields_evaluation yields no results (e.g. no fields), compare doctype to inputdescriptor map id
                    match fields_evaluation {
                        Either::B(_) => true,
                        Either::A(_) => {
                            let Ok(doc_type) = get_doc_type(&credential) else {
                                return false;
                            };
                            doc_type == obj.id
                        }
                    }
                })
                .collect::<Vec<_>>();

            if results.is_empty() {
                return None;
            }

            for requirement in presentation_definition
                .get("submission_requirements")
                .and_then(|a| a.as_array())
                .unwrap_or(&vec![])
            {
                // let requirement = requirement.transform::<dif_presentation_exchange::presentation_definition::SubmissionRequirement>().unwrap();
                let req_count = requirement.get("count").unwrap().as_i64().unwrap();
                let req_from = requirement.get("from").unwrap().as_str().unwrap();
                let rule = requirement
                    .get("rule")
                    .and_then(|a| a.as_str())
                    .map(|a| a.to_lowercase())
                    .unwrap();
                match rule.as_str() {
                    "pick" => {
                        let howmanytopick = *req_count as usize;
                        let group_to_pick = req_from.to_string();
                        let matching_descriptors = results
                            .iter()
                            .filter(|(_, _, group)| {
                                group
                                    .transform::<Vec<String>>()
                                    .unwrap()
                                    .contains(&group_to_pick)
                            })
                            .count();
                        if howmanytopick > matching_descriptors {
                            return None;
                        }
                    }
                    _ => continue,
                }
            }

            let data = results;
            let map = data.iter().map(|(_, obj, _)| obj).collect::<Vec<_>>();

            let values = data
                .iter()
                .map(|(results, obj, _)| {
                    (
                        obj,
                        match results {
                            Either::A(_) => HashMap::new(),
                            Either::B(results) => results
                                .iter()
                                .filter_map(|result| match result {
                                    FieldQueryResult::Some { value, path } => {
                                        let key = path.clone();
                                        let value = serde_json::to_string(value);
                                        match value {
                                            Err(_) => None,
                                            Ok(value) => Some((key, value)),
                                        }
                                    }
                                    _ => None,
                                })
                                .collect::<HashMap<String, String>>(),
                        },
                    )
                })
                .collect::<Vec<_>>();
            Some(Ok::<_, serde_json::Error>(
                values
                    .into_iter()
                    .filter_map(|(obj, val)| {
                        Some(PresentableCredential {
                            credential: (*raw).clone(),
                            descriptor_map: serde_json::to_string(&map).ok()?,
                            values: val,
                            response_id: obj.id.clone(),
                        })
                    })
                    .collect::<Vec<_>>(),
            ))
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?;

    Ok(presentables)
}

fn filter_issuer_signed(
    issuer_signed: Value,
    kv: &HashMap<String, String>,
) -> Result<Value, ApiError> {
    let namespaces = issuer_signed
        .get("nameSpaces")
        .context("issuerSigned has no nameSpaces!")?;

    let json = namespaces_to_json_map(namespaces, true)?;
    let selector = &mut jsonpath::selector(&json);

    let namespaces_keys = namespaces
        .as_map()
        .context("nameSpaces is not a map!")?
        .iter()
        .map(|(k, _)| {
            k.as_text()
                .map(|t| t.to_owned())
                .context("nameSpaces key is not text!")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let values = kv
        .iter()
        .map(|(k, _)| {
            let value = Value::Tag(
                24,
                Box::new(Value::Bytes(
                    selector(k).map_err(|err| err.into()).and_then(|values| {
                        ensure!(values.len() == 1, "Found more than one value!");
                        let JsonValue::String(base64url) = values[0] else {
                            anyhow::bail!("Found a non-string value");
                        };
                        Ok(b64url_decode_bytes(base64url)?)
                    })?,
                )),
            );

            let key = namespaces_keys
                .iter()
                .find(|key| k.contains(*key))
                .context("nameSpace has no key!")?;

            Ok::<_, ApiError>((key, value))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut kv = HashMap::<String, Vec<Value>>::new();
    for (key, value) in values {
        let vec = kv.entry(key.to_owned()).or_default();
        vec.push(value)
    }

    let namespaces = Value::Map(
        kv.into_iter()
            .map(|(k, v)| (Value::Text(k), Value::Array(v)))
            .collect::<Vec<(Value, Value)>>(),
    );

    let issuer_signed = Value::Map(
        issuer_signed
            .into_map()
            .map_err(|_| anyhow::anyhow!("issuerSigned is not a map!"))?
            .into_iter()
            .map(|(k, v)| {
                if k == Value::Text("nameSpaces".into()) {
                    (k, namespaces.clone())
                } else {
                    (k, v)
                }
            })
            .collect::<Vec<(_, _)>>(),
    );

    Ok(issuer_signed)
}

/// Create a presentation based on the credential that was selected by the wallet.
pub fn create_presentation(
    signer: Arc<dyn NativeSigner>,
    credential: PresentableCredential,
    client_id_hash: Vec<u8>,
    response_uri_hash: Vec<u8>,
    nonce: String,
) -> Result<Value, ApiError> {
    let issuer_signed = helper::deserialize(&b64url_decode_bytes(&credential.credential.payload)?)?;

    let doc_type = get_doc_type(&issuer_signed)?;
    let version = get_version(&issuer_signed)?;

    let session_transcript = get_session_transcript(&client_id_hash, &response_uri_hash, &nonce)?;
    let cose_sign1 = device_signature(signer, doc_type.clone(), session_transcript)?;

    let device_name_spaces_bytes = Value::Bytes(helper::serialize(&Value::Map(vec![]))?);

    let issuer_signed = filter_issuer_signed(issuer_signed, &credential.values)?;

    cbor!({
        "version" => version,
        "documents" => [
            {
                "docType" => doc_type,
                "issuerSigned" => issuer_signed,
                "deviceSigned" => {
                    "nameSpaces" => Value::Tag(24, Box::new(device_name_spaces_bytes)),
                    "deviceAuth" => {
                        "deviceSignature" => cose_sign1
                    }
                }
            }
        ],
        "status" => 0
    })
    .map_err(|e| anyhow::anyhow!("{e}").into())
}
pub fn get_session_transcript(
    client_id_hash: &[u8],
    response_uri_hash: &[u8],
    nonce: &str,
) -> Result<Value, ApiError> {
    let handover = cbor!([
        Value::Bytes(client_id_hash.to_vec()),
        Value::Bytes(response_uri_hash.to_vec()),
        nonce
    ])
    .map_err(|e| anyhow!(e))?;
    Ok(cbor!([null, null, handover]).map_err(|e| anyhow!(e))?)
}
/// Calculate the device_signature struct for MDL credential presentation.
pub fn device_signature(
    signer: Arc<dyn NativeSigner>,
    doc_type: String,
    session_transcript: Value,
) -> Result<Value, ApiError> {
    let tagged_device_name_spaces = Value::Tag(
        24,
        Box::new(Value::Bytes(helper::serialize(&Value::Map(vec![]))?)),
    );

    let device_authentication = cbor!([
        "DeviceAuthentication",
        session_transcript,
        doc_type,
        tagged_device_name_spaces
    ])
    .map_err(|e| anyhow!(e))?;
    let device_authentication_bytes = Value::Bytes(helper::serialize(&Value::Tag(
        24,
        Box::new(Value::Bytes(helper::serialize(&device_authentication)?)),
    ))?);

    let protected_header_bytes = Value::Bytes(helper::serialize(
        &cbor!({ SIGN_ALG_KEY => SIGN_ALG_ES256 })?,
    )?);

    let sig_structure = cbor!([
        "Signature1",
        protected_header_bytes,
        Value::Bytes(vec![]),
        device_authentication_bytes
    ])?;
    let sig_structure_bytes = helper::serialize(&sig_structure)?;
    let signature = Value::Bytes(signer.sign_bytes(sig_structure_bytes)?);

    cbor!([
        protected_header_bytes,
        // unprotected_header
        {},
        // payload
        null,
        signature
    ])
    .map_err(|e| e.into())
}

/// Create vp_token and presentation submission
pub fn prepare_mdoc_submission(
    signer: Arc<dyn NativeSigner>,
    credential: PresentableCredential,
    client_id_hash: Vec<u8>,
    response_uri_hash: Vec<u8>,
    nonce: String,
    presentation_definition: &heidi_util_rust::value::Value,
) -> Result<(String, PresentationSubmission), ApiError> {
    let descriptor_map =
        serde_json::from_str::<Vec<InputDescriptorMappingObject>>(&credential.descriptor_map)
            .map_err(|e| anyhow::anyhow!(e))?;
    let presi_id = presentation_definition
        .get("id")
        .and_then(|a| a.as_str())
        .unwrap_or_default();
    let presentation_submission = PresentationSubmission {
        id: presi_id.to_string(),
        definition_id: presi_id.to_string(),
        descriptor_map,
    };

    let vp_token = {
        let value = create_presentation(
            signer,
            credential,
            client_id_hash,
            response_uri_hash,
            nonce.clone(),
        )?;
        let bytes = helper::serialize(&value)?;
        b64url_encode_bytes(&bytes)
    };
    Ok((vp_token, presentation_submission))
}

/// Create a presentation direct_post and submit it to the verifier.
pub fn create_submission(
    vp_token: String,
    presentation_submission: PresentationSubmission,
) -> Result<Oid4vpParams, ApiError> {
    Ok(Oid4vpParams::Params {
        vp_token,
        presentation_submission,
    })
}

/// Create a presentation (encrypted, direct_post.jwt) and submit it to the verifier.
#[allow(unreachable_code)]
pub fn create_submission_encrypted(
    vp_token: String,
    presentation_submission: PresentationSubmission,
    mdoc_generated_nonce: Vec<u8>,
    nonce: String,
    client_metadata: &heidi_util_rust::value::Value,
    state: Option<String>,
) -> Result<Oid4vpParams, ApiError> {
    let encrypter = EncryptionParameters::try_from(client_metadata)?;
    let object = if let Some(state) = state {
        json!({
            "vp_token": vp_token,
            "presentation_submission": presentation_submission,
            "state" : state
        })
    } else {
        json!({
            "vp_token": vp_token,
            "presentation_submission": presentation_submission
        })
    }
    .as_object()
    .ok_or_else(|| anyhow!("Should not happen"))?
    .to_owned();
    let response = encrypter.encrypt(
        object,
        Some(mdoc_generated_nonce),
        Some(nonce.as_bytes().to_vec()),
    )?;
    return Ok(Oid4vpParams::Jwt { response });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    use crate::presentation::presentation_exchange::PresentationDefinition;

    use super::*;

    const PRESENTATION_REQUEST: &str = r#"
    {
      "id" : "presentation_id",
      "input_descriptors" : [ {
        "id" : "urn:eu.europa.ec.eudi:pid:1",
        "name" : "sample input descriptor",
        "purpose" : "test",
        "format" : {
          "dc+sd-jwt" : { }
        },
        "group" : [ "A" ],
        "constraints" : {
          "fields" : [ {
            "path" : [ "$.given_name" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$.family_name" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$.age_in_years" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$.issuing_country" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          } ],
          "limit_disclosure" : "required"
        }
      }, {
        "id" : "eu.europa.ec.eudi.pid.1",
        "name" : "sample input descriptor",
        "purpose" : "test",
        "format" : {
          "mso_mdoc" : {
            "alg" : [ "ES256", "ES384", "ES512", "EdDSA" ]
          }
        },
        "group" : [ "A" ],
        "constraints" : {
          "fields" : [ {
            "path" : [ "$['eu.europa.ec.eudi.pid.1']['given_name']" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$['eu.europa.ec.eudi.pid.1']['family_name']" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$['eu.europa.ec.eudi.pid.1']['age_in_years']" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          }, {
            "path" : [ "$['eu.europa.ec.eudi.pid.1']['issuing_country']" ],
            "purpose" : "test",
            "name" : "sample field",
            "intent_to_retain" : false,
            "optional" : false
          } ],
          "limit_disclosure" : "required"
        }
      } ],
      "name" : "sample presentation definition",
      "purpose" : "test",
      "submission_requirements" : [ {
        "name" : "sample submission requirement",
        "purpose" : "test",
        "rule" : "PICK",
        "count" : 1,
        "from" : "A"
      } ]
    }"#;

    #[test]
    fn session_transcript() {
        let client_id = "test-audience";
        let response_uri = "test-uri";
        let mdoc_generated_nonce = "mdoc-1234";
        let client_id_to_hash = cbor!([client_id, mdoc_generated_nonce]).unwrap();
        let response_uri_to_hash = cbor!([response_uri, mdoc_generated_nonce]).unwrap();
        let client_id_hash =
            Sha256::digest(helper::serialize(&client_id_to_hash).unwrap()).to_vec();
        let response_uri_hash =
            Sha256::digest(helper::serialize(&response_uri_to_hash).unwrap()).to_vec();
        let session_transcript =
            get_session_transcript(&client_id_hash, &response_uri_hash, "1234").unwrap();
        println!(
            "{}",
            b64url_encode_bytes(&helper::serialize(&session_transcript).unwrap())
        )
    }

    #[test]
    fn should_not_panic() {
        use crate::testing::signing::new_native_signer;

        use base64::prelude::*;
        use did_key::{from_existing_key, KeyMaterial, P256KeyPair};
        use p256::PublicKey;

        let credential = VerifiableCredential {
            id: 1337,
            identity_id: 42,
            name: "test".to_string(),
            metadata: json!({
                "credentialType": "Mdoc"
            }).to_string(),
            payload: "omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQRA2BhZBDumZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWR0MjAyNC0wNi0yNFQwNjo1MDo0MFppdmFsaWRGcm9tdDIwMjQtMDYtMjRUMDY6NTA6NDBaanZhbGlkVW50aWx0MjAyNC0wNy0wOFQwNjo1MDo0MFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCDJVfFwuYp2QoZROAvEN2pyUZ1KM8pEWRZXfdWrF1HkigFYIHhpl7kR5NAjeLSFJd0LsjMB9_ZeOBi-pYiOSwG78rrEAlggEih2FMRoq01sCrA8gZ-r_pUqi7add99aSg_l9iuV7w8DWCD9umaT-ULFoZSewraVNXFFWf3iNm5rgj75OQAy7n-1HQRYIL8xH7_OLXmsTruVMI1AInTjtDyPiDkk3ZaljsXFMaeYBVgg2-7WIwtpcZgVI3ZpKiFOqf8cV_R8G20adAqk3xLmaR8GWCCMFjcNb1Yp0rw86h1OOYCPzIhE-Dt5yWCQ7BTpNbZBuwdYIEzmGyjypgomuuwlwyp44zLi6sXT11ZNoyDAMKEsNP0pCFggI2ENhbCnOrZsVvqNE1GJe13ygY7MMU_Hv7l7j60Y5BgJWCBDZb6ztiG-09jmZNNc3Qi4e1OhyqtNmrOxzuzCtMYKcgpYIDGYllJw4PxQlyaeiI-a0qaeD9C3qh2hKXtvYYol928zC1gg4etokah75K55-qzJ6_FtE2KtAF9gy3gzcTeirdZ3LHwMWCDnCnqeX1M1iJe3LH2qc0kJOXQHYUEubpqVi2c4wtt3xQ1YIL7dVtgkdG9n2pDvrBtgY21i7X7YyiVCe-p61mtghwjnDlggQk4FkmKScm6oCwHtt5Og5E_1SQfuWpFIMdj0x8ZCS0wPWCBGMDXYqqBPDqeqBoFn3IKJSZWcdMj7KyU1ZtNOZ3OE6hBYIJyzjluOe_VlYSQw1aIBcrsnnF2czy5ypChycRfi0nrOEVggKOd_n9xKuZDdnak-vQ1zrIzSWLxJIlPgJMpLEn2FuLYSWCBHx1eoCb1ydVj_EGIKUOYPCyEjAgP5HxN-J_zSZUwkKBNYIN0hCZPdhjF4pU-LVEoQi7FdOSF3lrQ8EimA7C31NcVhFFggxtk6j0328cyjnwNoWKCUgvg1Uk37Bktpzb4atlRT5VIVWCAMujq43dRJg7XilJJL0z-hxQoLUpkzO2tq6H6LazG0uW1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIMrI7GWNvKwCXqwcJmkBMyIRAXejiET9PRAFCMhJEfo9IlggEvXLy65sT8QyzLnWsC7aIM1eem2029awDcWI7WO0ES9vZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQLVKBk4WMWUjTFWSwUuz7vCPNCAqw5x7HIBHVr1H_gC5WOEXxBaFlnxHYBjBguFSfLe5e-7t82ySdef7uvo6d2NqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGW2BhYVqRmcmFuZG9tUPYpQ7wOENpcyi6n1L56UdhoZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMRgxk_vnHlF0GwDT1_ULxJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhbpGZyYW5kb21QKjeWt5G4r5-qtZytkvPCY2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZkdBQkxFUnFlbGVtZW50SWRlbnRpZmllcnFmYW1pbHlfbmFtZV9iaXJ0aNgYWFOkZnJhbmRvbVBDbqFvUf9mgbrDQOa3wxwcaGRpZ2VzdElEA2xlbGVtZW50VmFsdWVlRVJJS0FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWFSkZnJhbmRvbVC0poiPe3Qx58JWmtP7Q_WGaGRpZ2VzdElEBGxlbGVtZW50VmFsdWUZB6xxZWxlbWVudElkZW50aWZpZXJuYWdlX2JpcnRoX3llYXLYGFhPpGZyYW5kb21Qu7cn53_6IG1TiAz9anV2VGhkaWdlc3RJRAVsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xONgYWE-kZnJhbmRvbVCRPYwpMh16--3IgrBqvPiHaGRpZ2VzdElEBmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzIx2BhYVqRmcmFuZG9tUGu5N18O3ztKBJRIqXuXprFoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZWVLw5ZMTnFlbGVtZW50SWRlbnRpZmllcm1yZXNpZGVudF9jaXR52BhYbKRmcmFuZG9tUDKXb5L9OGRMoOqY4ixLrj5oZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZaJldmFsdWViREVrY291bnRyeU5hbWVnR2VybWFueXFlbGVtZW50SWRlbnRpZmllcmtuYXRpb25hbGl0edgYWFmkZnJhbmRvbVD4nB3KeJEBfi7oTQaUgKmcaGRpZ2VzdElECWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWFWkZnJhbmRvbVDzJdpDC6MZvIaVDJ_psS7JaGRpZ2VzdElECmxlbGVtZW50VmFsdWVmQkVSTElOcWVsZW1lbnRJZGVudGlmaWVya2JpcnRoX3BsYWNl2BhYVaRmcmFuZG9tUKEIada4bfyv5GeAbFb3reZoZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnnYGFhPpGZyYW5kb21Qqbo3TPNv6ilm7tvlR4l_GGhkaWdlc3RJRAxsZWxlbWVudFZhbHVl9HFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl82NdgYWGykZnJhbmRvbVC_nvMTClyTddZfwm_WviXAaGRpZ2VzdElEDWxlbGVtZW50VmFsdWWiZG5hbm8aNQgmzGtlcG9jaFNlY29uZBpmeRdAcWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhqpGZyYW5kb21QPqCKymVJhGPADlN7tILk2mhkaWdlc3RJRA5sZWxlbWVudFZhbHVlomRuYW5vGjUIJsxrZXBvY2hTZWNvbmQaZouMQHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWGOkZnJhbmRvbVC0Cd-E5IjcJYTHKNzujqXlaGRpZ2VzdElED2xlbGVtZW50VmFsdWVwSEVJREVTVFJB4bqeRSAxN3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXTYGFhPpGZyYW5kb21QBSfulxP_wSm8WUJ31jD9U2hkaWdlc3RJRBBsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWF2kZnJhbmRvbVDAyvF8NuW7ZU4yWPFlZEQ9aGRpZ2VzdElEEWxlbGVtZW50VmFsdWVlNTExNDdxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGXYGFhYpGZyYW5kb21QH_0ki1hqwWblAMFbrwMO2GhkaWdlc3RJRBJsZWxlbWVudFZhbHVlajE5NjQtMDgtMTJxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWFekZnJhbmRvbVBaUAbNICOqTrrbEaDKqbtSaGRpZ2VzdElEE2xlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhPpGZyYW5kb21QtyDyyKiExuZFhmsIS1M122hkaWdlc3RJRBRsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFGkZnJhbmRvbVAIbRM0JOd2WfpsMlmrMWMaaGRpZ2VzdElEFWxlbGVtZW50VmFsdWUYO3FlbGVtZW50SWRlbnRpZmllcmxhZ2VfaW5feWVhcnM".to_string()
        };

        let presentable =
            get_matching_credentials(&[credential], &sample_presentation_definition(), None)
                .unwrap()
                .swap_remove(0);

        let secret_key = "dc77599b6aabd6693454409b7fe4f6334c794fd5873eeaf49f59c65ad3571e00";
        let kp = from_existing_key::<P256KeyPair>(&[], Some(&hex::decode(secret_key).unwrap()));

        println!(
            "{}",
            PublicKey::from_sec1_bytes(&kp.public_key_bytes())
                .unwrap()
                .to_jwk_string()
        );

        let signer = new_native_signer();

        let presentation = create_presentation(
            signer,
            presentable[0].clone(),
            b"client-id".to_vec(),
            b"test".to_vec(),
            "1234".to_string(),
        )
        .unwrap();

        let mut bytes = Vec::<u8>::new();
        ciborium::into_writer(&presentation, &mut bytes).unwrap();

        println!("{}", BASE64_URL_SAFE_NO_PAD.encode(&bytes));
    }

    fn sample_presentation_definition() -> heidi_util_rust::value::Value {
        serde_json::from_str(PRESENTATION_REQUEST).unwrap()
    }

    #[test]
    fn test_evaluate_input_raw() {
        let request = sample_presentation_definition();
        let request: PresentationDefinition = request.transform().unwrap();
        let input_descriptor = request
            .input_descriptors
            .iter()
            .find(|i| {
                i.format
                    .as_ref()
                    .map(|f| f.contains_key(&ClaimFormatDesignation::MsoMdoc))
                    .unwrap_or(false)
            })
            .unwrap();

        let value: Value = {
            let issuer_signed = "omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQRA2BhZBDumZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWR0MjAyNC0wNi0yNFQwNjo1MDo0MFppdmFsaWRGcm9tdDIwMjQtMDYtMjRUMDY6NTA6NDBaanZhbGlkVW50aWx0MjAyNC0wNy0wOFQwNjo1MDo0MFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCDJVfFwuYp2QoZROAvEN2pyUZ1KM8pEWRZXfdWrF1HkigFYIHhpl7kR5NAjeLSFJd0LsjMB9_ZeOBi-pYiOSwG78rrEAlggEih2FMRoq01sCrA8gZ-r_pUqi7add99aSg_l9iuV7w8DWCD9umaT-ULFoZSewraVNXFFWf3iNm5rgj75OQAy7n-1HQRYIL8xH7_OLXmsTruVMI1AInTjtDyPiDkk3ZaljsXFMaeYBVgg2-7WIwtpcZgVI3ZpKiFOqf8cV_R8G20adAqk3xLmaR8GWCCMFjcNb1Yp0rw86h1OOYCPzIhE-Dt5yWCQ7BTpNbZBuwdYIEzmGyjypgomuuwlwyp44zLi6sXT11ZNoyDAMKEsNP0pCFggI2ENhbCnOrZsVvqNE1GJe13ygY7MMU_Hv7l7j60Y5BgJWCBDZb6ztiG-09jmZNNc3Qi4e1OhyqtNmrOxzuzCtMYKcgpYIDGYllJw4PxQlyaeiI-a0qaeD9C3qh2hKXtvYYol928zC1gg4etokah75K55-qzJ6_FtE2KtAF9gy3gzcTeirdZ3LHwMWCDnCnqeX1M1iJe3LH2qc0kJOXQHYUEubpqVi2c4wtt3xQ1YIL7dVtgkdG9n2pDvrBtgY21i7X7YyiVCe-p61mtghwjnDlggQk4FkmKScm6oCwHtt5Og5E_1SQfuWpFIMdj0x8ZCS0wPWCBGMDXYqqBPDqeqBoFn3IKJSZWcdMj7KyU1ZtNOZ3OE6hBYIJyzjluOe_VlYSQw1aIBcrsnnF2czy5ypChycRfi0nrOEVggKOd_n9xKuZDdnak-vQ1zrIzSWLxJIlPgJMpLEn2FuLYSWCBHx1eoCb1ydVj_EGIKUOYPCyEjAgP5HxN-J_zSZUwkKBNYIN0hCZPdhjF4pU-LVEoQi7FdOSF3lrQ8EimA7C31NcVhFFggxtk6j0328cyjnwNoWKCUgvg1Uk37Bktpzb4atlRT5VIVWCAMujq43dRJg7XilJJL0z-hxQoLUpkzO2tq6H6LazG0uW1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIMrI7GWNvKwCXqwcJmkBMyIRAXejiET9PRAFCMhJEfo9IlggEvXLy65sT8QyzLnWsC7aIM1eem2029awDcWI7WO0ES9vZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQLVKBk4WMWUjTFWSwUuz7vCPNCAqw5x7HIBHVr1H_gC5WOEXxBaFlnxHYBjBguFSfLe5e-7t82ySdef7uvo6d2NqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGW2BhYVqRmcmFuZG9tUPYpQ7wOENpcyi6n1L56UdhoZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMRgxk_vnHlF0GwDT1_ULxJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhbpGZyYW5kb21QKjeWt5G4r5-qtZytkvPCY2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZkdBQkxFUnFlbGVtZW50SWRlbnRpZmllcnFmYW1pbHlfbmFtZV9iaXJ0aNgYWFOkZnJhbmRvbVBDbqFvUf9mgbrDQOa3wxwcaGRpZ2VzdElEA2xlbGVtZW50VmFsdWVlRVJJS0FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWFSkZnJhbmRvbVC0poiPe3Qx58JWmtP7Q_WGaGRpZ2VzdElEBGxlbGVtZW50VmFsdWUZB6xxZWxlbWVudElkZW50aWZpZXJuYWdlX2JpcnRoX3llYXLYGFhPpGZyYW5kb21Qu7cn53_6IG1TiAz9anV2VGhkaWdlc3RJRAVsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xONgYWE-kZnJhbmRvbVCRPYwpMh16--3IgrBqvPiHaGRpZ2VzdElEBmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzIx2BhYVqRmcmFuZG9tUGu5N18O3ztKBJRIqXuXprFoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZWVLw5ZMTnFlbGVtZW50SWRlbnRpZmllcm1yZXNpZGVudF9jaXR52BhYbKRmcmFuZG9tUDKXb5L9OGRMoOqY4ixLrj5oZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZaJldmFsdWViREVrY291bnRyeU5hbWVnR2VybWFueXFlbGVtZW50SWRlbnRpZmllcmtuYXRpb25hbGl0edgYWFmkZnJhbmRvbVD4nB3KeJEBfi7oTQaUgKmcaGRpZ2VzdElECWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWFWkZnJhbmRvbVDzJdpDC6MZvIaVDJ_psS7JaGRpZ2VzdElECmxlbGVtZW50VmFsdWVmQkVSTElOcWVsZW1lbnRJZGVudGlmaWVya2JpcnRoX3BsYWNl2BhYVaRmcmFuZG9tUKEIada4bfyv5GeAbFb3reZoZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnnYGFhPpGZyYW5kb21Qqbo3TPNv6ilm7tvlR4l_GGhkaWdlc3RJRAxsZWxlbWVudFZhbHVl9HFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl82NdgYWGykZnJhbmRvbVC_nvMTClyTddZfwm_WviXAaGRpZ2VzdElEDWxlbGVtZW50VmFsdWWiZG5hbm8aNQgmzGtlcG9jaFNlY29uZBpmeRdAcWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhqpGZyYW5kb21QPqCKymVJhGPADlN7tILk2mhkaWdlc3RJRA5sZWxlbWVudFZhbHVlomRuYW5vGjUIJsxrZXBvY2hTZWNvbmQaZouMQHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWGOkZnJhbmRvbVC0Cd-E5IjcJYTHKNzujqXlaGRpZ2VzdElED2xlbGVtZW50VmFsdWVwSEVJREVTVFJB4bqeRSAxN3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXTYGFhPpGZyYW5kb21QBSfulxP_wSm8WUJ31jD9U2hkaWdlc3RJRBBsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWF2kZnJhbmRvbVDAyvF8NuW7ZU4yWPFlZEQ9aGRpZ2VzdElEEWxlbGVtZW50VmFsdWVlNTExNDdxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGXYGFhYpGZyYW5kb21QH_0ki1hqwWblAMFbrwMO2GhkaWdlc3RJRBJsZWxlbWVudFZhbHVlajE5NjQtMDgtMTJxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWFekZnJhbmRvbVBaUAbNICOqTrrbEaDKqbtSaGRpZ2VzdElEE2xlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhPpGZyYW5kb21QtyDyyKiExuZFhmsIS1M122hkaWdlc3RJRBRsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFGkZnJhbmRvbVAIbRM0JOd2WfpsMlmrMWMaaGRpZ2VzdElEFWxlbGVtZW50VmFsdWUYO3FlbGVtZW50SWRlbnRpZmllcmxhZ2VfaW5feWVhcnM".to_string();
            let bytes = b64url_decode_bytes(&issuer_signed).unwrap();
            ciborium::from_reader(&bytes[..]).unwrap()
        };

        let matches = evaluate_input_raw(
            &heidi_util_rust::value::Value::from_serialize(input_descriptor).unwrap(),
            value.get("nameSpaces").unwrap(),
        );
        // println!("{matches:#?}");
        assert!(matches.is_some())
    }

    #[test]
    fn test_get_matching_credentials() {
        let credentials = vec![
            VerifiableCredential {
                id: 1337,
                identity_id: 42,
                name: "test".to_string(),
                metadata: json!({
                    "credentialType": "Mdoc"
                }).to_string(),
                payload: "omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQRA2BhZBDumZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWR0MjAyNC0wNi0yNFQwNjo1MDo0MFppdmFsaWRGcm9tdDIwMjQtMDYtMjRUMDY6NTA6NDBaanZhbGlkVW50aWx0MjAyNC0wNy0wOFQwNjo1MDo0MFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCDJVfFwuYp2QoZROAvEN2pyUZ1KM8pEWRZXfdWrF1HkigFYIHhpl7kR5NAjeLSFJd0LsjMB9_ZeOBi-pYiOSwG78rrEAlggEih2FMRoq01sCrA8gZ-r_pUqi7add99aSg_l9iuV7w8DWCD9umaT-ULFoZSewraVNXFFWf3iNm5rgj75OQAy7n-1HQRYIL8xH7_OLXmsTruVMI1AInTjtDyPiDkk3ZaljsXFMaeYBVgg2-7WIwtpcZgVI3ZpKiFOqf8cV_R8G20adAqk3xLmaR8GWCCMFjcNb1Yp0rw86h1OOYCPzIhE-Dt5yWCQ7BTpNbZBuwdYIEzmGyjypgomuuwlwyp44zLi6sXT11ZNoyDAMKEsNP0pCFggI2ENhbCnOrZsVvqNE1GJe13ygY7MMU_Hv7l7j60Y5BgJWCBDZb6ztiG-09jmZNNc3Qi4e1OhyqtNmrOxzuzCtMYKcgpYIDGYllJw4PxQlyaeiI-a0qaeD9C3qh2hKXtvYYol928zC1gg4etokah75K55-qzJ6_FtE2KtAF9gy3gzcTeirdZ3LHwMWCDnCnqeX1M1iJe3LH2qc0kJOXQHYUEubpqVi2c4wtt3xQ1YIL7dVtgkdG9n2pDvrBtgY21i7X7YyiVCe-p61mtghwjnDlggQk4FkmKScm6oCwHtt5Og5E_1SQfuWpFIMdj0x8ZCS0wPWCBGMDXYqqBPDqeqBoFn3IKJSZWcdMj7KyU1ZtNOZ3OE6hBYIJyzjluOe_VlYSQw1aIBcrsnnF2czy5ypChycRfi0nrOEVggKOd_n9xKuZDdnak-vQ1zrIzSWLxJIlPgJMpLEn2FuLYSWCBHx1eoCb1ydVj_EGIKUOYPCyEjAgP5HxN-J_zSZUwkKBNYIN0hCZPdhjF4pU-LVEoQi7FdOSF3lrQ8EimA7C31NcVhFFggxtk6j0328cyjnwNoWKCUgvg1Uk37Bktpzb4atlRT5VIVWCAMujq43dRJg7XilJJL0z-hxQoLUpkzO2tq6H6LazG0uW1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIMrI7GWNvKwCXqwcJmkBMyIRAXejiET9PRAFCMhJEfo9IlggEvXLy65sT8QyzLnWsC7aIM1eem2029awDcWI7WO0ES9vZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQLVKBk4WMWUjTFWSwUuz7vCPNCAqw5x7HIBHVr1H_gC5WOEXxBaFlnxHYBjBguFSfLe5e-7t82ySdef7uvo6d2NqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGW2BhYVqRmcmFuZG9tUPYpQ7wOENpcyi6n1L56UdhoZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMRgxk_vnHlF0GwDT1_ULxJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhbpGZyYW5kb21QKjeWt5G4r5-qtZytkvPCY2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZkdBQkxFUnFlbGVtZW50SWRlbnRpZmllcnFmYW1pbHlfbmFtZV9iaXJ0aNgYWFOkZnJhbmRvbVBDbqFvUf9mgbrDQOa3wxwcaGRpZ2VzdElEA2xlbGVtZW50VmFsdWVlRVJJS0FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWFSkZnJhbmRvbVC0poiPe3Qx58JWmtP7Q_WGaGRpZ2VzdElEBGxlbGVtZW50VmFsdWUZB6xxZWxlbWVudElkZW50aWZpZXJuYWdlX2JpcnRoX3llYXLYGFhPpGZyYW5kb21Qu7cn53_6IG1TiAz9anV2VGhkaWdlc3RJRAVsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xONgYWE-kZnJhbmRvbVCRPYwpMh16--3IgrBqvPiHaGRpZ2VzdElEBmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzIx2BhYVqRmcmFuZG9tUGu5N18O3ztKBJRIqXuXprFoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZWVLw5ZMTnFlbGVtZW50SWRlbnRpZmllcm1yZXNpZGVudF9jaXR52BhYbKRmcmFuZG9tUDKXb5L9OGRMoOqY4ixLrj5oZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZaJldmFsdWViREVrY291bnRyeU5hbWVnR2VybWFueXFlbGVtZW50SWRlbnRpZmllcmtuYXRpb25hbGl0edgYWFmkZnJhbmRvbVD4nB3KeJEBfi7oTQaUgKmcaGRpZ2VzdElECWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWFWkZnJhbmRvbVDzJdpDC6MZvIaVDJ_psS7JaGRpZ2VzdElECmxlbGVtZW50VmFsdWVmQkVSTElOcWVsZW1lbnRJZGVudGlmaWVya2JpcnRoX3BsYWNl2BhYVaRmcmFuZG9tUKEIada4bfyv5GeAbFb3reZoZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnnYGFhPpGZyYW5kb21Qqbo3TPNv6ilm7tvlR4l_GGhkaWdlc3RJRAxsZWxlbWVudFZhbHVl9HFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl82NdgYWGykZnJhbmRvbVC_nvMTClyTddZfwm_WviXAaGRpZ2VzdElEDWxlbGVtZW50VmFsdWWiZG5hbm8aNQgmzGtlcG9jaFNlY29uZBpmeRdAcWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhqpGZyYW5kb21QPqCKymVJhGPADlN7tILk2mhkaWdlc3RJRA5sZWxlbWVudFZhbHVlomRuYW5vGjUIJsxrZXBvY2hTZWNvbmQaZouMQHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWGOkZnJhbmRvbVC0Cd-E5IjcJYTHKNzujqXlaGRpZ2VzdElED2xlbGVtZW50VmFsdWVwSEVJREVTVFJB4bqeRSAxN3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXTYGFhPpGZyYW5kb21QBSfulxP_wSm8WUJ31jD9U2hkaWdlc3RJRBBsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWF2kZnJhbmRvbVDAyvF8NuW7ZU4yWPFlZEQ9aGRpZ2VzdElEEWxlbGVtZW50VmFsdWVlNTExNDdxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGXYGFhYpGZyYW5kb21QH_0ki1hqwWblAMFbrwMO2GhkaWdlc3RJRBJsZWxlbWVudFZhbHVlajE5NjQtMDgtMTJxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWFekZnJhbmRvbVBaUAbNICOqTrrbEaDKqbtSaGRpZ2VzdElEE2xlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhPpGZyYW5kb21QtyDyyKiExuZFhmsIS1M122hkaWdlc3RJRBRsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFGkZnJhbmRvbVAIbRM0JOd2WfpsMlmrMWMaaGRpZ2VzdElEFWxlbGVtZW50VmFsdWUYO3FlbGVtZW50SWRlbnRpZmllcmxhZ2VfaW5feWVhcnM".to_string()
            },
            // Note: this mdoc is a bit more recent and encodes the validUntil differently in CBOR (tag 0).
            VerifiableCredential {
                id: 0xf00d,
                identity_id: 42,
                name: "test2".to_string(),
                metadata: json!({
                    "credentialType": "Mdoc"
                }).to_string(),
                payload: "omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQRD2BhZBD6mZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMDgtMjNUMTE6NTI6MzFaaXZhbGlkRnJvbcB0MjAyNC0wOC0yM1QxMTo1MjozMVpqdmFsaWRVbnRpbMB0MjAyNC0wOS0wNlQxMTo1MjozMVpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCBM4N75NfzYxmdoY8Z3Q1VVrpvxFpdiManzvspHHopkQwFYIEDDD9veRtW8rBe8FTJUTs-3FR8VIL0tPG0PsMydMYfBAlgge2S2sG7VXbZ9n0yla9pDZgU37R0CHVhdujmsDX7fVZkDWCB25O3D6_GM4iZUvLOJlj5FyVOFt1k8QJjXBc4kyGwhtgRYIMFI232agyu4U9y_fjt0KwxBKRphfTKus4QLAIR7TNP2BVggG_TC_Nr5b08GeU2lco11kVWfS0forNlVbJ_u3KzL1yMGWCABB74ELtQdePnZ353FsBttzEi7q-rRkercUwF1CJfrawdYIBg9S6tzvmJLPsg2qFKBU95-YYTBhX5dr3ALF7yyrmEZCFggolTy3XlF-A1YQGae1iH0akwROT8uMHi4vj9Dl9azEN8JWCAZE6pvPyI3a3gBK-KgknDA7ffMyzcZoviH_VWVWhXkOApYIHHykmUt2z1DwZrJnZcdfKfrGT9WkUlm0J4Rty8yd7xgC1ggP3jHH6SYLjy_zmO0GBTHOFETl2mPz61iNAm-7LHU_ngMWCBKWTukNvsUcVUcW6THBdjx95_exzNtc-GtksZrtUjOIQ1YIMXTBJENedwVfM6bEBhejaqqw7obBcWHdx0B-I9hUOJ_Dlgg3UaS8cySNuPTRPvCFYkut16y1zFFM-X1szIc35qfpakPWCAtM3hJ2HI_iiUp12gA2_poflhYfrXY_Yu98aBHJmAPaRBYIPo2kzVlBjeYJulNTmcUNzpbG_VpXZQ2myYr0wiVs2UQEVggcUzOHrgudu2zAPAPbgQ8ZDYAKXphokGKC9Z_skxcy8gSWCAE4lwxPOJdRESkaWql_ZyobNnI3YM8AViE-7fTvkQ4AhNYINOXWE4Ikl_dB8IJmdkiFxY7LD0Q8w1ZkNmuAal_dS2IFFggREcHV2iOqKwX2d6UDcqjgUHFZLiwQyT_d7i-FqdJ-hMVWCATtQey2GML16MWL-sWYl1n25dgQaxiZbOU1Pl_B2sfOm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIA4ktbj4xtGHjzlZLKX57RsKOUX2MwAeqHnOgxzWXkteIlggbL3FZb1Q3zG4LTn3AMSOy1OBef6qLmWl9lZ0of8RLlJvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQD514tb0kyXfVxIUjBI8KTU0fw6JSXoQIqND5wU2QAO3qslYm_8NF2rDUcOrxrcnMevrg0m8zNRGgTBCCWn7gM1qbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGW2BhYT6RmcmFuZG9tUAR6y94lPqcHQEdWwRH5Ri1oZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMjHYGFhVpGZyYW5kb21Q4dFlcpU3uZ2vAVgGm6FYG2hkaWdlc3RJRAFsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWFukZnJhbmRvbVC3J8s3uF7aMVqMIp0BVG5ZaGRpZ2VzdElEAmxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYT6RmcmFuZG9tUHlOETZY_6_HvCGLgMfYUiBoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTTYGFhZpGZyYW5kb21QbyifHyPY5zNmZCRGPpBiVmhkaWdlc3RJRARsZWxlbWVudFZhbHVlak1VU1RFUk1BTk5xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhXpGZyYW5kb21Q6SO5XFd1a1dV2Zj-9YiPxWhkaWdlc3RJRAVsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYU6RmcmFuZG9tUPOs9AfY0vBy4PaL-AslXf9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZWVFUklLQXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYa6RmcmFuZG9tUGi2YDZNrV9x1yBbBTOVV6ZoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZcB4GDIwMjQtMDgtMjNUMTE6NTI6MzEuODM5WnFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYT6RmcmFuZG9tUC88wuRF0SyDt2txPs-5t3doZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZfRxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfNjXYGFhspGZyYW5kb21QgtL8kjf4sMVpPycbcuZ3XWhkaWdlc3RJRAlsZWxlbWVudFZhbHVlomV2YWx1ZWJERWtjb3VudHJ5TmFtZWdHZXJtYW55cWVsZW1lbnRJZGVudGlmaWVya25hdGlvbmFsaXR52BhYYqRmcmFuZG9tUHnNVaLjktqBLlDG8DF8rT5oZGlnZXN0SUQKbGVsZW1lbnRWYWx1ZW9IRUlERVNUUkFTU0UgMTdxZWxlbWVudElkZW50aWZpZXJvcmVzaWRlbnRfc3RyZWV02BhYUaRmcmFuZG9tUG70_C8C44mrYtgCktFy6U9oZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZRgocWVsZW1lbnRJZGVudGlmaWVybGFnZV9pbl95ZWFyc9gYWFikZnJhbmRvbVC4ut5rtfgu038qbqWtVCGkaGRpZ2VzdElEDGxlbGVtZW50VmFsdWVqMTk4NC0wMS0yNnFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRl2BhYVqRmcmFuZG9tUFYIfkyFmwOqvgE97GLazXdoZGlnZXN0SUQNbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUFYkOJPPfNDxtH32glKS7Y5oZGlnZXN0SUQObGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhVpGZyYW5kb21Q8njjyCT3sbXZ04Nv2H3zhmhkaWdlc3RJRA9sZWxlbWVudFZhbHVlZkJFUkxJTnFlbGVtZW50SWRlbnRpZmllcmtiaXJ0aF9wbGFjZdgYWFakZnJhbmRvbVB_HBpnPznmnZHtxJ9xxxk6aGRpZ2VzdElEEGxlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWGmkZnJhbmRvbVAxV1sEqVKMhPRZ998TmmKiaGRpZ2VzdElEEWxlbGVtZW50VmFsdWXAeBgyMDI0LTA5LTA2VDExOjUyOjMxLjgzOVpxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGXYGFhPpGZyYW5kb21QQHOTs5ufsOV7j5b6W3eJyGhkaWdlc3RJRBJsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xONgYWFSkZnJhbmRvbVD35QgQUbIqFN7VN6Q5NhpJaGRpZ2VzdElEE2xlbGVtZW50VmFsdWUZB8BxZWxlbWVudElkZW50aWZpZXJuYWdlX2JpcnRoX3llYXLYGFhPpGZyYW5kb21QQBwcBxzcrLOHs9M5ymgWwGhkaWdlc3RJRBRsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWF2kZnJhbmRvbVCTB_hE9KLSeZoaNvCcMqLQaGRpZ2VzdElEFWxlbGVtZW50VmFsdWVlNTExNDdxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGU".to_string()
            },
            VerifiableCredential {
                id: 101,
                identity_id: 42,
                name: "test".to_string(),
                metadata: json!({
                    "credentialType": "SdJwt"
                }).to_string(),
                payload: "".to_string(),
            }
        ];

        // creds have _not_ expired then
        let far_in_the_past = std::time::UNIX_EPOCH;
        // creds will have certainly expired by then
        let far_in_the_future = std::time::UNIX_EPOCH + Duration::from_secs(1000 * 365 * 24 * 3600);

        let matching = get_matching_credentials(
            &credentials,
            &sample_presentation_definition(),
            Some(far_in_the_past),
        )
        .unwrap();

        assert_eq!(matching.len(), 2);
        dbg!(&matching[0]);

        let matching = get_matching_credentials(
            &credentials,
            &sample_presentation_definition(),
            Some(far_in_the_future),
        )
        .unwrap();
        assert!(matching.is_empty());

        // without valid_at, returns all
        let matching =
            get_matching_credentials(&credentials, &sample_presentation_definition(), None)
                .unwrap();
        assert_eq!(matching.len(), 2);
    }
}
