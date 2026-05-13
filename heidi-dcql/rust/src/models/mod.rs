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
pub mod parser;
pub mod trusted_authority;

use heidi_credentials_rust::claims_pointer::Selector;

use heidi_credentials_rust::models::Pointer;
use heidi_util_rust::value::Value;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

use crate::models::parser::REGISTERED_PARSERS;
use crate::MetaMismatch;

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
/// A DCQL Query (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)
pub struct DcqlQuery {
    /// List of credential queries
    pub credentials: Option<Vec<CredentialQuery>>,
    /// List of credential sets
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record)]
/// Credential Query (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-credential-query)
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
    pub r#type: String,
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
    #[serde(other)]
    Other,
}

impl<T: AsRef<str>> From<T> for TrustedAuthorityQueryType {
    fn from(s: T) -> Self {
        match s.as_ref() {
            "aki" => TrustedAuthorityQueryType::AuthorityKeyIdentifier,
            "esti_tl" => TrustedAuthorityQueryType::EtsiTrustedList,
            "openid_federation" => TrustedAuthorityQueryType::OpenIDFederation,
            "did" => TrustedAuthorityQueryType::DecentralizedIdentifier,
            _ => TrustedAuthorityQueryType::Other,
        }
    }
}

#[uniffi::export(with_foreign)]
pub trait CredentialLike: Send + Sync + std::fmt::Debug {
    fn get_body(&self) -> Value;
    fn serialize(&self) -> String;
    fn format_specifiers(&self) -> Vec<String>;
    fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch>;
    fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>>;
}

pub trait SdJwtLike: Send + Sync + Debug {
    fn get_vct(&self) -> Option<String>;
}
impl<T> SdJwtLike for Arc<T>
where
    T: CredentialLike,
{
    fn get_vct(&self) -> Option<String> {
        let b = self.get_body();
        let Some(vct) = b.get("vct").and_then(|a| a.as_str()) else {
            return None;
        };
        Some(vct.to_string())
    }
}
#[uniffi::export(with_foreign)]
pub trait MdocLike: Send + Sync + Debug {}
#[uniffi::export(with_foreign)]
pub trait BbsLike: Send + Sync + Debug {}
#[uniffi::export(with_foreign)]
pub trait W3CLike: Send + Sync + Debug {}
#[uniffi::export(with_foreign)]
pub trait OpenBadgeLike: Send + Sync + Debug {}

impl Serialize for Credential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Credential::SdJwtCredential(sd_jwt_rust) => {
                let body = sd_jwt_rust.get_body();
                serializer.serialize_newtype_struct("SdJwt", &body)
            }
            Credential::MdocCredential(mdoc_rust) => {
                let body = mdoc_rust.get_body();
                serializer.serialize_newtype_struct("Mdoc", &body)
            }
            Credential::BbsCredential(bbs_rust) => {
                let body = bbs_rust.get_body();
                serializer.serialize_newtype_struct("Bbs", &body)
            }
            Credential::W3CCredential(w3_csd_jwt) => {
                let body = w3_csd_jwt.get_body();
                serializer.serialize_newtype_struct("W3C", &body)
            }
            Credential::OpenBadge303Credential(w3_cverifiable_credential) => {
                let body = w3_cverifiable_credential.get_body();
                serializer.serialize_newtype_struct("OpenBadge", &body)
            }
            Credential::Other(credential_like) => {
                let body = credential_like.get_body();
                serializer.serialize_newtype_struct("Other", &body)
            }
        }
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Credential {
    SdJwtCredential(Arc<dyn CredentialLike>),
    MdocCredential(Arc<dyn CredentialLike>),
    BbsCredential(Arc<dyn CredentialLike>),
    W3CCredential(Arc<dyn CredentialLike>),
    OpenBadge303Credential(Arc<dyn CredentialLike>),
    Other(Arc<dyn CredentialLike>),
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
        let Ok(parsers) = REGISTERED_PARSERS.lock() else {
            return Err(ParseError::Invalid);
        };
        for p in parsers.iter() {
            if let Some(c) = p.from_str(s.to_string()) {
                return Ok(c);
            }
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
/// Credential Set Query (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-credential-set-query)
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

        let json = r#""something_else""#;
        let query_type = serde_json::from_str::<TrustedAuthorityQueryType>(json).unwrap();
        assert_eq!(query_type, TrustedAuthorityQueryType::Other);
    }
}
