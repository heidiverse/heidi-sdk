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
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use heidi_util_rust::{log::log, value::Value};
use sha2::{digest::DynDigest, Digest, Sha256};

use crate::{
    claims_pointer::Selector,
    generate_nonce,
    models::{Pointer, PointerPart, SignatureCreator, SpecVersion},
    sdjwt::SdJwtRust,
    sdjwt_util::{
        base64_hash, Disclosure, DisclosureIndex, DisclosureNode, DisclosureTree, Header,
    },
    w3c::W3CSdJwt,
};

const UNDISCLOSABLE_CLAIMS: [&str; 5] = ["iss", "iat", "exp", "nbf", "vct"];

#[derive(Debug, uniffi::Error, Clone)]
pub enum BuilderError {
    InvalidPath(String),
    InvalidHashAlg,
    Lock,
    Unknown,
    AlreadyBuilt,
    InvalidDisclosure,
}

impl Display for BuilderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

#[derive(Debug, Clone)]
pub struct BuilderImpl {
    claims: Value,
    original_jwt: String,
    disclosure_map: HashMap<String, Disclosure>,
    disclosure_tree: DisclosureTree,

    disclosures: Vec<String>,
    nonce: Option<String>,
    aud: Option<String>,
    transaction_data: Option<(Vec<String>, SpecVersion)>,

    is_w3c: bool,
}

impl BuilderImpl {
    fn resolve_pointer(&self, ptr: Pointer) -> Result<Vec<String>, BuilderError> {
        let mut current = &self.disclosure_tree;
        let ptr_str = format!("{ptr:?}");
        log(
            heidi_util_rust::log::LogPriority::ERROR,
            "SDJWT_BUILDER",
            &format!("Disclosures: {:?}", current),
        );

        let mut it = ptr.into_iter().peekable();
        while let Some(p) = it.next() {
            let index = match p {
                PointerPart::String(s) => DisclosureIndex::String(s),
                PointerPart::Index(i) => DisclosureIndex::Index(i),
                PointerPart::Null(_) => {
                    return Err(BuilderError::InvalidPath("Null pointer part".to_string()))
                }
            };
            let Some(node) = current.get(&index) else {
                return Err(BuilderError::InvalidPath(format!(
                    "No disclosure found for index: {index:?} in path: {ptr_str}"
                )));
            };
            match node {
                DisclosureNode::Node(subtree) => {
                    log(
                        heidi_util_rust::log::LogPriority::ERROR,
                        "SDJWT_BUILDER",
                        &format!("---> {subtree:?} {:?}", it.peek()),
                    );
                    current = subtree;
                }
                DisclosureNode::Leaf(disc) if it.peek().is_none() => {
                    log(
                        heidi_util_rust::log::LogPriority::ERROR,
                        "SDJWT_BUILDER",
                        &format!("---> {disc:?}"),
                    );
                    return Ok(disc.iter().map(|e| e.enc.to_string()).collect());
                }
                _ => {
                    return Err(BuilderError::InvalidPath(format!(
                        "Expected leaf node at end of path: {ptr_str}, found: {node:?}"
                    )))
                }
            }
        }

        Err(BuilderError::InvalidPath(format!(
            "Pointer did not resolve to a disclosure: {ptr_str}"
        )))
    }

    pub fn add_disclosure(&mut self, p: Pointer) -> Result<&mut Self, BuilderError> {
        let disclosure = self.resolve_pointer(p)?;
        for d in disclosure {
            self.disclosures.push(d);
        }
        self.disclosures.sort();
        self.disclosures.dedup();
        Ok(self)
    }

    pub fn add_all(&mut self) -> Result<&mut Self, BuilderError> {
        let all_disclosures = self.disclosure_map.values().map(|d| d.enc.clone());
        self.disclosures.extend(all_disclosures);
        self.disclosures.sort();
        self.disclosures.dedup();
        Ok(self)
    }

    pub fn remove_disclosure(&mut self, p: Pointer) -> Result<&mut Self, BuilderError> {
        let disclosure = self.resolve_pointer(p)?;
        for disc in disclosure {
            self.disclosures.retain(|d| d != &disc);
        }
        Ok(self)
    }

    pub fn remove_all(&mut self) -> Result<&mut Self, BuilderError> {
        self.disclosures.clear();
        Ok(self)
    }

    pub fn with_nonce(&mut self, nonce: &str) -> Result<&mut Self, BuilderError> {
        self.nonce = Some(nonce.to_string());
        Ok(self)
    }

    pub fn with_audience(&mut self, aud: &str) -> Result<&mut Self, BuilderError> {
        self.aud = Some(aud.to_string());
        Ok(self)
    }

    pub fn with_transaction_data(
        &mut self,
        transaction_data: Vec<String>,
        spec_version: SpecVersion,
    ) -> Result<&mut Self, BuilderError> {
        self.transaction_data = Some((transaction_data, spec_version));
        Ok(self)
    }

    pub fn build(
        &mut self,
        signer: Option<Arc<dyn SignatureCreator>>,
    ) -> Result<String, BuilderError> {
        let mut presentation = self.original_jwt.clone();

        if !self.disclosures.is_empty() {
            presentation.push_str(&format!("~{}", self.disclosures.join("~")));
        }

        presentation.push('~');

        if self.claims.get("cnf").is_some() {
            if let Some(signer) = signer {
                let jwt = {
                    let hash_alg = self
                        .claims
                        .get("_sd_alg")
                        .and_then(|s| s.as_str())
                        .unwrap_or("sha-256");

                    let mut digest: Box<dyn DynDigest> = match hash_alg {
                        "sha-256" | "SHA-256" => Box::new(Sha256::new()),
                        _ => return Err(BuilderError::InvalidHashAlg),
                    };

                    let header = {
                        let mut header = Header::new(signer.alg().as_str());
                        header.typ = "kb+jwt".to_string();

                        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
                    };

                    let body = {
                        let nonce = self.nonce.clone().unwrap_or(generate_nonce(32));

                        let iat = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        let sd_hash = base64_hash(digest.as_mut(), &presentation);

                        let mut claims = serde_json::json!({
                            "nonce": nonce,
                            "iat": iat,
                            "sd_hash": sd_hash,
                        });

                        if let Some(aud) = &self.aud {
                            claims["aud"] = serde_json::json!(aud);
                        }

                        if let Some((transaction_data, spec_version)) = &self.transaction_data {
                            match spec_version {
                                SpecVersion::PotentialUc5 => {
                                    claims["transaction_data"] =
                                        serde_json::json!(transaction_data);
                                }
                                SpecVersion::Oid4VpDraft23 => {
                                    // Note: the Authorization Request can contain a list of hash algorithms.
                                    // SHA256 must always be supported, so we can be lazy and implement nothing else.
                                    let mut hasher = Sha256::new();

                                    let hashes = transaction_data
                                        .iter()
                                        .map(|td| base64_hash(&mut hasher, td))
                                        .collect::<Vec<_>>();

                                    claims["transaction_data_hashes"] = serde_json::json!(hashes);

                                    // Spec: REQUIRED when this parameter was present in the transaction_data request
                                    // parameter --> lazy: include it always.
                                    claims["transaction_data_hashes_alg"] =
                                        serde_json::json!("sha-256");
                                }
                            }
                        }

                        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
                    };

                    let signature = {
                        let signature = signer
                            .sign(format!("{header}.{body}").as_bytes().to_vec())
                            .unwrap();
                        BASE64_URL_SAFE_NO_PAD.encode(signature)
                    };

                    format!("{header}.{body}.{signature}")
                };
                presentation.push_str(&jwt);
            }
        }
        Ok(presentation)
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct SdJwtBuilder {
    inner: Arc<Mutex<BuilderImpl>>,
}

#[uniffi::export]
impl SdJwtBuilder {
    #[uniffi::constructor]
    pub fn from_sdjwt(sdjwt: &SdJwtRust) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BuilderImpl {
                claims: sdjwt.claims.clone(),
                original_jwt: sdjwt.original_jwt.clone(),
                disclosure_map: sdjwt.disclosures_map.clone(),
                disclosure_tree: sdjwt.disclosure_tree.clone(),
                disclosures: vec![],
                nonce: None,
                aud: None,
                transaction_data: None,
                is_w3c: false,
            })),
        }
    }

    #[uniffi::constructor]
    pub fn from_w3c(w3c: &W3CSdJwt) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BuilderImpl {
                claims: w3c.json.clone(),
                original_jwt: w3c.original_jwt.clone(),
                disclosure_map: w3c.disclosure_map.clone(),
                disclosure_tree: w3c.disclosure_tree.clone(),
                disclosures: vec![],
                nonce: None,
                aud: None,
                transaction_data: None,
                is_w3c: true,
            })),
        }
    }

    pub fn add_disclosure(&self, p: Pointer) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        let Some(first) = p.first() else {
            return Err(BuilderError::InvalidPath("Empty pointer path".to_string()));
        };

        if UNDISCLOSABLE_CLAIMS
            .iter()
            .any(|uc| matches!(first, PointerPart::String(c) if &c == uc))
        {
            return Err(BuilderError::InvalidDisclosure);
        }

        let Ok(resolver) = p.resolve_ptr(this.claims.clone()) else {
            return Err(BuilderError::InvalidPath(
                "Failed to resolve pointer".to_string(),
            ));
        };

        for p in resolver {
            this.add_disclosure(p)?;
        }

        Ok(())
    }

    pub fn add_all(&self) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.add_all()?;

        Ok(())
    }

    pub fn remove_disclosure(&self, p: Pointer) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.remove_disclosure(p)?;

        Ok(())
    }

    pub fn remove_all(&self) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.remove_all()?;

        Ok(())
    }

    pub fn with_nonce(&self, nonce: &str) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_nonce(nonce)?;

        Ok(())
    }

    pub fn with_audience(&self, aud: &str) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_audience(aud)?;

        Ok(())
    }

    pub fn with_transaction_data(
        &self,
        transaction_data: Vec<String>,
        spec_version: SpecVersion,
    ) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_transaction_data(transaction_data, spec_version)?;

        Ok(())
    }

    pub fn build(&self, signer: Option<Arc<dyn SignatureCreator>>) -> Result<String, BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        let result = this.build(signer)?;
        Ok(result)
    }

    pub fn get_disclosure_tree(&self) -> DisclosureTree {
        let this = self.inner.lock().unwrap();
        this.disclosure_tree.clone()
    }

    pub fn is_w3c(&self) -> bool {
        let this = self.inner.lock().unwrap();
        this.is_w3c
    }
}
