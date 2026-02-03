/* Copyright 2025 Ubique Innovation AG

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

use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    sync::Arc,
};

use heidi_util_rust::value::Value;
use iref::IriBuf;
use json_ld::{ChainLoader, ReqwestLoader};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use static_iref::iri;
use tokio::{runtime::Handle, task::LocalSet};

use crate::{
    claims_pointer::Selector,
    json_ld::{JsonLdDocument, loader::StaticLoader},
    sdjwt_util::{self, Disclosure, DisclosureTree, SdJwtDecodeError},
};

#[derive(Debug, Clone, uniffi::Error)]
pub enum W3CParseError {
    SdJwtError(SdJwtDecodeError),
    NoType,
}

impl Display for W3CParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Clone, uniffi::Record, Serialize)]
pub struct W3CSdJwt {
    /// The credential document type
    pub doctype: String,

    /// The credential as a JSON object
    pub json: Value,

    /// The original JWT (SD-JWT without the disclosures and kb-jwt)
    pub original_jwt: String,

    /// The original SD-JWT
    pub original_sdjwt: String,

    /// The disclosure map, mapping sd-hashes to decoded disclosures
    pub disclosure_map: HashMap<String, Disclosure>,

    /// The disclosure tree, mapping paths to disclosures
    pub disclosure_tree: DisclosureTree,

    /// The number of disclosures in the disclosure map
    pub num_disclosures: u32,
}

impl W3CSdJwt {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.json.clone()).ok()
    }
}

#[uniffi::export]
pub fn parse_w3c_sd_jwt(credential: &str) -> Result<W3CSdJwt, W3CParseError> {
    let decoded = sdjwt_util::decode_sdjwt(credential).map_err(W3CParseError::SdJwtError)?;

    let types = match decoded.claims.get("type") {
        Some(JsonValue::Array(types)) => types
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        Some(JsonValue::String(r#type)) => vec![r#type.clone()],
        _ => return Err(W3CParseError::NoType),
    };

    let Some(doctype) = types
        .iter()
        .find(|t| t.as_str() != "VerifiableCredential")
        .or(types.first())
    else {
        return Err(W3CParseError::NoType);
    };

    Ok(W3CSdJwt {
        doctype: doctype.clone(),
        json: decoded.claims.into(),
        original_sdjwt: decoded.original_sdjwt,
        original_jwt: decoded.original_jwt,
        disclosure_map: decoded.disclosure_map,
        disclosure_tree: decoded.disclosure_tree,
        num_disclosures: decoded.num_disclosures as u32,
    })
}

#[derive(Debug, Clone, uniffi::Record, Serialize, Deserialize)]
pub struct LanguageValueObject {
    /// The object MUST contain a @value property whose value is a string.
    #[serde(rename = "@value")]
    value: String,

    /// The object SHOULD contain a @language property whose value is a string containing a
    /// well-formed Language-Tag as defined by [BCP47].
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@language")]
    language: Option<String>,

    /// The object MAY contain a @direction property whose value is a base direction string
    /// defined by the @direction property in [JSON-LD11].
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@direction")]
    direction: Option<String>,
}

/// A LocalizableString is either a string or a language value object as described in
/// https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction
#[derive(Debug, Clone, uniffi::Enum, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LocalizableString {
    /// A simple string
    String(String),

    /// A language value object
    OneLvo(LanguageValueObject),

    /// An array of language value objects
    ManyLvo(Vec<LanguageValueObject>),
}

/// A W3C Verifiable Credential as per https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
#[derive(Debug, Clone, uniffi::Record, Serialize, Deserialize)]
pub struct W3CVerifiableCredential {
    /// The value of the @context property MUST be an ordered set where the first item is a URL with
    /// the value https://www.w3.org/ns/credentials/v2. Subsequent items in the ordered set MUST be
    /// composed of any combination of URLs and objects, where each is processable as a JSON-LD
    /// Context.
    #[serde(rename = "@context")]
    pub context: Vec<Value>,

    /// The id property is OPTIONAL. If present, id property's value MUST be a single URL, which MAY
    /// be dereferenceable. It is RECOMMENDED that the URL in the id be one which, if dereferenceable,
    /// results in a document containing machine-readable information about the id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The value of the type property MUST be one or more terms and absolute URL strings. If more
    /// than one value is provided, the order does not matter.
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// An OPTIONAL property that expresses the name of the credential. If present, the value of the
    /// name property MUST be a string or a language value object as described in 11.1 Language and
    /// Base Direction. Ideally, the name of a credential is concise, human-readable, and could
    /// enable an individual to quickly differentiate one credential from any other credentials they
    /// might hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<LocalizableString>,

    /// An OPTIONAL property that conveys specific details about a credential. If present, the value
    /// of the description property MUST be a string or a language value object as described in 11.1
    /// Language and Base Direction. Ideally, the description of a credential is no more than a few
    /// sentences in length and conveys enough information about the credential to remind an
    /// individual of its contents without having to look through the entirety of the claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LocalizableString>,

    /// The value of the issuer property MUST be either a URL or an object containing an id property
    /// whose value is a URL; in either case, the issuer selects this URL to identify itself in a
    /// globally unambiguous way. It is RECOMMENDED that the URL be one which, if dereferenced,
    /// results in a controlled identifier document, as defined in the Controlled Identifiers v1.0
    /// specification, about the issuer that can be used to verify the information expressed in the
    /// credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Value>,

    /// The value of the credentialSubject property is a set of objects where each object MUST be
    /// the subject of one or more claims, which MUST be serialized inside the credentialSubject
    /// property. Each object MAY also contain an id property to identify the subject, as described
    /// in Section 4.4 Identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<Value>,

    /// If present, the value of the validFrom property MUST be a [XMLSCHEMA11-2] dateTimeStamp
    /// string value representing the date and time the credential becomes valid, which could be a
    /// date and time in the future or the past. Note that this value represents the earliest point
    /// in time at which the information associated with the credentialSubject property becomes
    /// valid. If a validUntil value also exists, the validFrom value MUST express a point in time
    /// that is temporally the same or earlier than the point in time expressed by the validUntil
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "validFrom")]
    pub valid_from: Option<String>,

    /// If present, the value of the validUntil property MUST be a [XMLSCHEMA11-2] dateTimeStamp
    /// string value representing the date and time the credential ceases to be valid, which could
    /// be a date and time in the past or the future. Note that this value represents the latest
    /// point in time at which the information associated with the credentialSubject property is
    /// valid. If a validFrom value also exists, the validUntil value MUST express a point in time
    /// that is temporally the same or later than the point in time expressed by the validFrom
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "validUntil")]
    pub valid_until: Option<String>,

    ///  If present, the value associated with the credentialStatus property is a single object or a
    /// set of one or more objects. The following properties are defined for every object:
    ///
    /// **id:**
    /// The id property is OPTIONAL. It MAY be used to provide a unique identifier for the
    /// credential status object. If present, the normative guidance in Section 4.4 Identifiers MUST
    /// be followed.
    ///
    /// **type:**
    /// The type property is REQUIRED. It is used to express the type of status information
    /// expressed by the object. The related normative guidance in Section 4.5 Types MUST be
    /// followed.
    ///
    /// The precise content of the credential status information is determined by the specific
    /// credentialStatus type definition and varies depending on factors such as whether it is
    /// simple to implement or if it is privacy-enhancing. The value will provide enough information
    /// to determine the current status of the credential and whether machine-readable information
    /// will be retrievable from the URL. For example, the object could contain a link to an
    /// external document that notes whether the credential is suspended or revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialStatus")]
    pub status: Option<Value>,

    /// The value of the credentialSchema property MUST be one or more data schemas that provide
    /// verifiers with enough information to determine whether the provided data conforms to the
    /// provided schema(s). Each credentialSchema MUST specify its type (for example, JsonSchema)
    /// and an id property that MUST be a URL identifying the schema file. The specific type
    /// definition determines the precise contents of each data schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSchema")]
    pub credential_schema: Option<Value>,

    /// The value of the refreshService property MUST be one or more refresh services that provides
    /// enough information to the recipient's software such that the recipient can refresh the
    /// verifiable credential. Each refreshService value MUST specify its type. The precise content
    /// of each refresh service is determined by the specific refreshService type definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "refreshService")]
    pub refresh_service: Option<Value>,

    /// The value of the termsOfUse property MUST specify one or more terms of use policies under
    /// which the creator issued the credential or presentation. If the recipient (a holder or
    /// verifier) is not willing to adhere to the specified terms of use, then they do so on their
    /// own responsibility and might incur legal liability if they violate the stated terms of use.
    /// Each termsOfUse value MUST specify its type, for example, TrustFrameworkPolicy, and MAY
    /// specify its instance id. The precise contents of each term of use is determined by the
    /// specific termsOfUse type definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "termsOfUse")]
    pub terms_of_use: Option<Value>,

    /// If present, the value of the evidence property MUST be either a single object or a set of
    /// one or more objects. The following properties are defined for every evidence object:
    ///
    /// **id:**
    /// The id property is OPTIONAL. It MAY be used to provide a unique identifier for the evidence
    /// object. If present, the normative guidance in Section 4.4 Identifiers MUST be followed.
    ///
    /// **type:**
    /// The type property is REQUIRED. It is used to express the type of evidence information
    /// expressed by the object. The related normative guidance in Section 4.5 Types MUST be
    /// followed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,

    /// An embedded proof is a mechanism where the proof is included in the serialization of the
    /// data model. One such RECOMMENDED embedded proof mechanism is defined in Verifiable
    /// Credential Data Integrity 1.0 [VC-DATA-INTEGRITY].
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "proof")]
    pub embedded_proof: Option<Value>,
}

impl W3CVerifiableCredential {
    pub fn into_value(self) -> Value {
        serde_json::to_value(self).unwrap().into()
    }

    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.clone().into_value()).ok()
    }
}

#[derive(Debug, Clone, uniffi::Error)]
pub enum JsonLDParseError {
    Join(String),
    Json(String),
    Iri(String),
}

impl Display for JsonLDParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

pub const CONTEXT_W3C_VCDM2: &'static str = include_str!("../jsonld/www.w3.org/ns/credentials/v2");

pub async fn parse_and_canonicalize_w3c_json_ld(
    credential: String,
    additional_context: Vec<String>,
) -> Result<W3CVerifiableCredential, JsonLDParseError> {
    let vc = tokio::task::spawn_blocking(move || {
        let handle = Handle::current();
        let local = LocalSet::new();

        // Use the handle to block, and let the local set run the future
        handle.block_on(local.run_until(async move {
            let loader = ChainLoader::new(
                StaticLoader::new()
                    .with_document("https://www.w3.org/ns/credentials/v2", CONTEXT_W3C_VCDM2),
                ReqwestLoader::new(),
            );
            let mut context = vec![iri!("https://www.w3.org/ns/credentials/v2").to_owned()];
            context.extend(
                additional_context
                    .into_iter()
                    .map(|c| IriBuf::new(c))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| JsonLDParseError::Iri(e.to_string()))?,
            );

            let flattened = JsonLdDocument::new(credential.as_str(), &loader)
                .flattened()
                .await;
            let flattened = JsonLdDocument::new(&flattened.to_string(), &loader);

            let frame = json!({
                "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
                "https://w3id.org/security#proof": {
                    "@graph": {
                        "@type": "https://w3id.org/security#DataIntegrityProof"
                    }
                }
            });
            let framed = flattened.framed(&frame).await;

            let document = JsonLdDocument::new(&framed.to_string(), &loader)
                .compacted(context)
                .await;

            Ok(document)
        }))
    })
    .await
    .map_err(|e| JsonLDParseError::Join(e.to_string()))??;

    let vc = serde_json::from_value::<W3CVerifiableCredential>(vc)
        .map_err(|e| JsonLDParseError::Json(e.to_string()))?;

    Ok(vc)
}

pub fn parse_canonicalized_w3c_json_ld(
    credential: &str,
) -> Result<W3CVerifiableCredential, JsonLDParseError> {
    let vc = serde_json::from_str::<W3CVerifiableCredential>(credential)
        .map_err(|e| JsonLDParseError::Json(e.to_string()))?;

    Ok(vc)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn w3c_credential_as_json(data: W3CVerifiableCredential) -> Value {
    data.into_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_w3c_sd_jwt() {
        let credential = "eyJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3NDU3NzY3MTMsImV4cCI6MTc0Njk4NjMxMywiX3NkX2FsZyI6InNoYS0yNTYiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaXNzdWVyIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy81NjUwNDkiLCJ2YWxpZEZyb20iOiIyMDEwLTAxLTAxVDAwOjAwOjAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJuYW1lIjoiQmFjaGVsb3Igb2YgU2NpZW5jZSBhbmQgQXJ0cyIsIl9zZCI6WyJEUkg1aWVsZHdHNXJPMlVQNXlYYlBXWHNTaFFNSmxESlJfZlFVbmhZVDNFIl19LCJfc2QiOlsiUzRvTGpDb0dNckpuMnFFR2lXY1JNNmdFNGZ6cVVFcVIzNC1FOWdjZzIyWSJdfSwiX3NkIjpbIlZtWnFMMkpKUFB0RDk2TmxwNE43TzFRMXhFRmNMZ1hCVzVfQWFGQXp4Sm8iLCJaYTdxRkpZSnRSTExSOFNRT1VUYUxwaDZBY21QSGlYVkc5Ni03Wnp3MEtJIl19.ypl46Q1EqUERV-IUUS_-qGoAESfv_WdXwtHOk2vX7QTZNFf0NNfg-w2OR8JPRe97kZBDQLuBZKPJhBXdFjbSwg~WyIxeDVielRkZXhsLW4zWVVIQXF5ZUxBIiwgImlkIiwgImh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMzczMiJd~WyJablVReVZXRmo0UlFfTHFmOVBkbmN3IiwgInR5cGUiLCBbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgIkV4YW1wbGVEZWdyZWVDcmVkZW50aWFsIl1d~WyI5TG1nOHhaUVJxWEZZaVRlV0hRZjV3IiwgImlkIiwgImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJd~WyJZMVBDaVA3YnJ3TjFHMEVMWmJXRlZRIiwgInR5cGUiLCAiRXhhbXBsZUJhY2hlbG9yRGVncmVlIl0~";
        let parsed = parse_w3c_sd_jwt(credential).unwrap();

        assert_eq!(parsed.doctype, "ExampleDegreeCredential");
    }

    #[test]
    fn test_parse_w3c_json_ld_example_2() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/58473",
            "type": ["VerifiableCredential", "ExampleAlumniCredential"],
            "issuer": "did:example:2g55q912ec3476eba2l9812ecbfe",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "alumniOf": {
                "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
                "name": "Example University"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_3() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_4() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": [
                "VerifiableCredential",
                "ExampleDegreeCredential"
            ],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            },
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2025-04-27T17:58:33Z",
                "verificationMethod": "did:key:zDnaebSRtPnW6YCpxAhR5JPxJqt9UunCsBPhLEtUokUvp87nQ",
                "cryptosuite": "ecdsa-rdfc-2019",
                "proofPurpose": "assertionMethod",
                "proofValue": "z2F16goBUjRsg2ieNiojpaz313CN98DU4APFiokAUkUvEYESSDmokg1omwvcK7EFqLgYpdyekEoxnVHwuxt8Webwa"
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_5() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "https://university.example/issuers/565049",
                "name": "Example University",
                "description": "A public university focusing on teaching examples."
            },
            "validFrom": "2015-05-10T12:30:00Z",
            "name": "Example University Degree",
            "description": "2015 Bachelor of Science and Arts Degree",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_6() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "https://university.example/issuers/565049",
                "name": [{
                "@value": "Example University",
                "@language": "en"
                }, {
                "@value": "Université Exemple",
                "@language": "fr"
                }, {
                "@value": "جامعة المثال",
                "@language": "ar",
                "@direction": "rtl"
                }],
                "description": [{
                "@value": "A public university focusing on teaching examples.",
                "@language": "en"
                }, {
                "@value": "Une université publique axée sur l'enseignement d'exemples.",
                "@language": "fr"
                }, {
                "@value": ".جامعة عامة تركز على أمثلة التدريس",
                "@language": "ar",
                "@direction": "rtl"
                }]
            },
            "validFrom": "2015-05-10T12:30:00Z",
            "name": [{
                "@value": "Example University Degree",
                "@language": "en"
            }, {
                "@value": "Exemple de Diplôme Universitaire",
                "@language": "fr"
            }, {
                "@value": "مثال الشهادة الجامعية",
                "@language": "ar",
                "@direction": "rtl"
            }],
            "description": [{
                "@value": "2015 Bachelor of Science and Arts Degree",
                "@language": "en"
            }, {
                "@value": "2015 Licence de Sciences et d'Arts",
                "@language": "fr"
            }, {
                "@value": "2015 بكالوريوس العلوم والآداب",
                "@language": "ar",
                "@direction": "rtl"
            }],
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": [{
                    "@value": "Bachelor of Science and Arts Degree",
                    "@language": "en"
                }, {
                    "@value": "Licence de Sciences et d'Arts",
                    "@language": "fr"
                }, {
                    "@value": "بكالوريوس العلوم والآداب",
                    "@language": "ar",
                    "@direction": "rtl"
                }]
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_7() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_8() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_9() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_10() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "RelationshipCredential"],
            "issuer": "https://issuer.example/issuer/123",
            "validFrom": "2010-01-01T00:00:00Z",
            "credentialSubject": [{
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            }, {
                "id": "https://subject.example/subject/8675",
                "name": "Morgan Doe",
                "spouse": "https://subject.example/subject/7421"
            }]
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_11() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "validUntil": "2020-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_12() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            },
            "credentialStatus": {
                "id": "https://university.example/credentials/status/3#94567",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "94567",
                "statusListCredential": "https://university.example/credentials/status/3"
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_13() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://license.example/credentials/9837",
            "type": ["VerifiableCredential", "ExampleDrivingLicenseCredential"],
            "issuer": "https://license.example/issuers/48",
            "validFrom": "2020-03-14T12:10:42Z",
            "credentialSubject": {
                "id": "did:example:f1c276e12ec21ebfeb1f712ebc6",
                "license": {
                "type": "ExampleDrivingLicense",
                "name": "License to Drive a Car"
                }
            },
            "credentialStatus": [{
                "id": "https://license.example/credentials/status/84#14278",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "14278",
                "statusListCredential": "https://license.example/credentials/status/84"
            }, {
                "id": "https://license.example/credentials/status/84#82938",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "suspension",
                "statusListIndex": "82938",
                "statusListCredential": "https://license.example/credentials/status/84"
            }]
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }
    #[test]
    fn test_parse_w3c_json_ld_example_14() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential", "ExamplePersonCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                },
                "alumniOf": {
                "name": "Example University"
                }
            },
            "credentialSchema": [{
                "id": "https://example.org/examples/degree.json",
                "type": "JsonSchema"
            },
            {
                "id": "https://example.org/examples/alumni.json",
                "type": "JsonSchema"
            }]
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[test]
    fn test_parse_w3c_json_ld_example_15() {
        let example = r#"
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://example.gov/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "did:example:6fb1f712ebe12c27cc26eebfe11",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "https://subject.example/subject/3921",
                "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-rdfc-2022",
                "created": "2021-11-13T18:19:39Z",
                "verificationMethod": "https://university.example/issuers/14#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz"
            }
        }"#;

        assert!(serde_json::from_str::<W3CVerifiableCredential>(example).is_ok());
    }

    #[tokio::test]
    async fn test_open_badge_vc() {
        let vc = r#"
        {
            "@id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ?v=3_0",
            "@type": [
                "https://www.w3.org/2018/credentials#VerifiableCredential",
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"
            ],
            "https://schema.org/name": {
                "@value": "AI Act"
            },
            "https://w3id.org/security#proof": {
                "@graph": [
                {
                    "@type": [
                    "https://w3id.org/security#DataIntegrityProof"
                    ],
                    "http://purl.org/dc/terms/created": [
                    {
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
                        "@value": "2025-12-04T08:37:40.379213+00:00"
                    }
                    ],
                    "https://w3id.org/security#cryptosuite": [
                    {
                        "@type": "https://w3id.org/security#cryptosuiteString",
                        "@value": "eddsa-rdfc-2022"
                    }
                    ],
                    "https://w3id.org/security#proofPurpose": [
                    {
                        "@id": "https://w3id.org/security#assertionMethod"
                    }
                    ],
                    "https://w3id.org/security#proofValue": [
                    {
                        "@type": "https://w3id.org/security#multibase",
                        "@value": "z5hTkyXpMzQx671RKemdnj2GpmHCUthKY1KxYRVT8renbL81MTrnVbBGfR3QfwJVu8j32ZZdpvuwPvBVYxLEbuA5z"
                    }
                    ],
                    "https://w3id.org/security#verificationMethod": [
                    {
                        "@id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0#key-0"
                    }
                    ]
                }
                ]
            },
            "https://www.w3.org/2018/credentials#credentialStatus": {
                "@id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/revocations",
                "@type": [
                "https://purl.imsglobal.org/spec/vcrl/v1p0/context.json#1EdTechRevocationList"
                ]
            },
            "https://www.w3.org/2018/credentials#credentialSubject": {
                "@id": "_:2",
                "@type": [
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#AchievementSubject"
                ],
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievement": {
                "@id": "https://api.openbadges.education/public/badges/1l5y_22PSauVhLYihoqmVw?v=3_0",
                "@type": [
                    "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Achievement"
                ],
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Criteria": {
                    "@id": "_:4",
                    "https://purl.imsglobal.org/spec/vc/ob/vocab.html#narrative": {
                    "@value": ""
                    }
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievementType": {
                    "@value": "Badge"
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image": {
                    "@id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/image",
                    "@type": [
                    "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Image"
                    ]
                },
                "https://schema.org/description": {
                    "@value": "Dieser Workshop bietet eine solide Einführung in KI mit besonderem Schwerpunkt auf dem Grundlagenwissen, das für einen verantwortungsvollen Umgang mit KI erforderlich ist - im Einklang mit den Anforderungen des EU-AI-Act. Die Teilnehmenden erhalten Einblicke in die Funktionsweise von KI-Systemen, wo ihre Grenzen und Risiken liegen und was eine verantwortungsvolle Nutzung in der Praxis bedeutet. Mit einer Mischung aus interaktivem Input und praktischer Reflexion stärkt das Training das Vertrauen und das Bewusstsein für den Umgang mit der sich entwickelnden KI-Landschaft und gibt rechtliche Grundlagen."
                },
                "https://schema.org/name": {
                    "@value": "AI Act"
                }
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#activityStartDate": {
                "@type": "https://www.w3.org/2001/XMLSchema#date",
                "@value": "2025-12-04T00:00:00+00:00"
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifier": {
                "@id": "_:3",
                "@type": [
                    "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentityObject"
                ],
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#hashed": {
                    "@type": "https://www.w3.org/2001/XMLSchema#boolean",
                    "@value": true
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityHash": {
                    "@value": "sha256$79a12f688e1bd35f85ad4ee1c71b5d7c942ea289aecf616159a20dc0d5af2419"
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityType": {
                    "@value": "emailAddress"
                },
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#salt": {
                    "@value": "6800b252df744e47b9d9837371a1618a"
                }
                }
            },
            "https://www.w3.org/2018/credentials#issuer": {
                "@id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0",
                "@type": [
                "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile"
                ],
                "https://schema.org/email": {
                "@value": "annika@mycelia.education"
                },
                "https://schema.org/name": {
                "@value": "Open Educational Badges"
                },
                "https://schema.org/url": {
                "@type": "https://www.w3.org/2001/XMLSchema#anyURI",
                "@value": "https://openbadges.education"
                }
            },
            "https://www.w3.org/2018/credentials#validFrom": {
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
                "@value": "2025-12-04T08:37:40.379213+00:00"
            }
        }"#;

        let vc = parse_and_canonicalize_w3c_json_ld(
            vc.to_string(),
            vec![
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json".to_string(),
                "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json".to_string(),
            ],
        )
        .await
        .unwrap();

        let vc = w3c_credential_as_json(vc);

        println!("VC: {:#}", vc);
    }
}
