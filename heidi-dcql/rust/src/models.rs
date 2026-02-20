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

#[cfg(feature = "bbs")]
use heidi_credentials_rust::bbs::{decode_bbs, BbsRust};
use heidi_credentials_rust::sdjwt::{decode_sdjwt, SdJwtRust};
use heidi_credentials_rust::{
    mdoc::{decode_mdoc, MdocRust},
    w3c::{W3CSdJwt, W3CVerifiableCredential},
};
use heidi_credentials_rust::{models::Pointer, w3c::parse_w3c_sd_jwt};
use heidi_util_rust::value::Value;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
pub struct DcqlQuery {
    pub credentials: Option<Vec<CredentialQuery>>,
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    pub multiple: Option<bool>,
    pub meta: Option<Meta>,
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    pub require_cryptographic_holder_binding: Option<bool>,
    pub claims: Option<Vec<ClaimsQuery>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Enum)]
#[serde(untagged)]
pub enum Meta {
    IsoMdoc { doctype_value: String },
    SdjwtVc { vct_values: Vec<String> },
    W3C { credential_types: Vec<String> },
    LdpVc { type_values: Vec<Vec<String>> },
    // NOTE: BBS uses the W3C VCDM, so it makes sense to
    // reuse the same object for the metadata.
    // Bbs { credential_types: Vec<String> },
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
pub struct TrustedAuthority {
    pub r#type: TrustedAuthorityQueryType,
    pub values: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Enum, PartialEq, Eq)]
pub enum TrustedAuthorityQueryType {
    #[serde(rename = "aki")]
    AuthorityKeyIdentifier,
    #[serde(rename = "esti_tl")]
    EtsiTrustedList,
    #[serde(rename = "openid_federation")]
    OpenIDFederation,
    #[serde(rename = "did")]
    DecentralizedIdentifier,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum Credential {
    SdJwtCredential(SdJwtRust),
    MdocCredential(MdocRust),
    #[cfg(feature = "bbs")]
    BbsCredential(BbsRust),
    W3CCredential(W3CSdJwt),
    OpenBadge303Credential(W3CVerifiableCredential),
}

#[derive(Clone, Debug, uniffi::Record, Serialize)]
pub struct CredentialOptions {
    pub options: Vec<Disclosure>,
}

#[derive(Clone, Debug, uniffi::Record, Serialize)]
pub struct Disclosure {
    pub credential: Credential,
    pub claims_queries: Vec<ClaimsQuery>,
}

#[derive(Clone, Debug, uniffi::Record, Serialize)]
pub struct CredentialSetOption {
    pub purpose: Option<String>,
    pub set_options: Vec<Vec<SetOption>>,
}
#[derive(Clone, Debug, uniffi::Record, Serialize)]
pub struct SetOption {
    pub id: String,
    pub options: Vec<Disclosure>,
}

#[derive(Debug, uniffi::Error)]
pub enum ParseError {
    Invalid,
}

impl FromStr for Credential {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sdjwt = decode_sdjwt(s);
        let w3c = parse_w3c_sd_jwt(s);

        match (sdjwt, w3c) {
            (Ok(sdjwt), Ok(w3c)) => {
                // NOTE: This is a hack, there should be a type hint somewhere

                // To distinguish between W3C and SD-JWT credentials,
                // we check if the W3C credential has a context.
                return if w3c.json.get("@context").is_some() {
                    Ok(Credential::W3CCredential(w3c))
                } else {
                    Ok(Credential::SdJwtCredential(sdjwt))
                };
            }
            (Ok(sdjwt), _) => return Ok(Credential::SdJwtCredential(sdjwt)),
            (_, Ok(w3c)) => return Ok(Credential::W3CCredential(w3c)),

            // Fallthrough to other formats
            _ => (),
        };

        if let Ok(vc) = serde_json::from_str::<W3CVerifiableCredential>(s) {
            if vc.types.contains(&"OpenBadgeCredential".to_string()) {
                return Ok(Credential::OpenBadge303Credential(vc));
            }
        }

        if let Ok(mdoc) = decode_mdoc(s) {
            return Ok(Credential::MdocCredential(mdoc));
        }
        #[cfg(feature = "bbs")]
        if let Ok(bbs) = decode_bbs(s) {
            return Ok(Credential::BbsCredential(bbs));
        }
        Err(ParseError::Invalid)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
pub struct ClaimsQuery {
    pub id: Option<String>,
    pub path: Pointer,
    pub values: Option<Vec<Value>>,
}

impl ClaimsQuery {
    pub fn id(&self) -> Option<String> {
        self.id.clone()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
pub struct CredentialSetQuery {
    pub options: Vec<Vec<String>>,
    #[serde(default = "default_required")]
    #[uniffi(default = true)]
    pub required: bool,
    pub purpose: Option<Value>,
}

pub const fn default_required() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use crate::models::TrustedAuthorityQueryType;

    #[test]
    fn test_parsing_trusted_authority_query_type() {
        let json = r#""aki""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(
            query_type,
            TrustedAuthorityQueryType::AuthorityKeyIdentifier
        );

        let json = r#""esti_tl""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(query_type, TrustedAuthorityQueryType::EtsiTrustedList);

        let json = r#""openid_federation""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(query_type, TrustedAuthorityQueryType::OpenIDFederation);

        let json = r#""did""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(
            query_type,
            TrustedAuthorityQueryType::DecentralizedIdentifier
        );

        let json = r#""other""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(
            query_type,
            TrustedAuthorityQueryType::Other("other".to_string())
        );
    }
}
