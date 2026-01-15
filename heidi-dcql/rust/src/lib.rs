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

pub mod models;
pub mod verify;

use crate::models::SetOption;
#[cfg(feature = "bbs")]
use heidi_credentials_rust::bbs::BbsRust;
use heidi_credentials_rust::models::{Pointer, PointerPart};
use heidi_credentials_rust::sdjwt::SdJwtRust;
use heidi_credentials_rust::{claims_pointer::Selector, w3c::W3CSdJwt};
use heidi_credentials_rust::{ldp::LdpVC, mdoc::MdocRust};
use heidi_util_rust::value::Value;
use models::{
    ClaimsQuery, Credential, CredentialOptions, CredentialQuery, CredentialSetOption, DcqlQuery,
    Disclosure, Meta,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const SDJWT_FORMATS: [&str; 2] = ["dc+sd-jwt", "vc+sd-jwt"];
const MDOC_FORMATS: [&str; 1] = ["mso_mdoc"];
const W3C_FORMATS: [&str; 1] = ["vc+sd-jwt"];
const OPEN_BADGE_FORMATS: [&str; 1] = ["ldp_vc"];

#[cfg(feature = "bbs")]
const BBS_FORMATS: [&str; 1] = ["bbs-termwise"];

#[derive(uniffi::Object)]
pub struct KmpPointer {
    pointer: Vec<PointerPart>,
}

#[uniffi::export]
impl KmpPointer {
    #[uniffi::constructor]
    pub fn new(pointer: Vec<PointerPart>) -> Self {
        Self { pointer }
    }
    pub fn as_selector(self: &Arc<Self>) -> Arc<dyn Selector> {
        Arc::new(self.pointer.clone())
    }
}

pub trait InformationScore {
    fn score(&self) -> usize;
}

const DANGEROUS_PROPERTIES: [&str; 4] = ["birth", "date", "address", "street"];
const HIDING_PROPERTIES: [&str; 1] = ["age_over"];

impl InformationScore for &str {
    fn score(&self) -> usize {
        if DANGEROUS_PROPERTIES.iter().any(|a| self.contains(a)) {
            return 4;
        }
        if HIDING_PROPERTIES.iter().any(|a| self.contains(a)) {
            return 1;
        }
        2
    }
}
impl InformationScore for String {
    fn score(&self) -> usize {
        self.as_str().score()
    }
}
impl InformationScore for Vec<String> {
    fn score(&self) -> usize {
        let mut score = 0;
        for attribute in self {
            for dp in &DANGEROUS_PROPERTIES {
                if attribute.contains(dp) {
                    score += 4;
                    continue;
                }
            }
            for hiding_property in &HIDING_PROPERTIES {
                if attribute.contains(hiding_property) {
                    score += 1;
                    continue;
                }
            }
            score += 2;
        }
        score
    }
}
impl InformationScore for Pointer {
    fn score(&self) -> usize {
        let mut score = 0;
        for p in self {
            match p {
                PointerPart::String(attribute) => {
                    for dp in &DANGEROUS_PROPERTIES {
                        if attribute.contains(dp) {
                            score += 4;
                            continue;
                        }
                    }
                    for hiding_property in &HIDING_PROPERTIES {
                        if attribute.contains(hiding_property) {
                            score += 1;
                            continue;
                        }
                    }
                    score += 2;
                }
                _ => continue,
            }
        }
        score
    }
}

pub trait CredentialStore {
    fn get(&self) -> Vec<Credential>;
}

impl<'a, T: AsRef<[&'a str]>> CredentialStore for T {
    fn get(&self) -> Vec<Credential> {
        self.as_ref()
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    }
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum DcqlQueryMismatch {
    CredentialQueryNotFound {
        id: String,
    },

    UnsatisfiedCredentialQuery {
        query_id: String,
        credential: Credential,
        reason: DcqlCredentialQueryMismatch,
    },
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum DcqlCredentialQueryMismatch {
    SdJwtMeta(SdJwtMetaMismatch),
    MdocMeta(MdocMetaMismatch),
    #[cfg(feature = "bbs")]
    BbsMeta(BbsMetaMismatch),
    W3CMeta(W3CMetaMismatch),

    ExpectedFormat(String),

    SomeCredentialQueriesDoNotHaveAnId,

    UnsatisfiedClaimQueries(Vec<DcqlClaimQueryMismatch>),
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum SdJwtMetaMismatch {
    WrongVctValue,
    InvalidMeta,
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum MdocMetaMismatch {
    WrongDocType,
    InvalidMeta,
}

#[cfg(feature = "bbs")]
#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum BbsMetaMismatch {
    InvalidMeta,
    WrongCredentialType,
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum W3CMetaMismatch {
    InvalidMeta,
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
pub enum DcqlClaimQueryMismatch {
    ClaimQueryPath {
        id: Option<String>,
        path: Vec<PointerPart>,
    },
    ClaimQueryValues {
        id: Option<String>,
        path: Vec<PointerPart>,
        actual: Value,
        values: Vec<Value>,
    },
}

#[derive(Debug, Clone, Default, uniffi::Record, Serialize)]
pub struct DcqlMatchResponse {
    /// Set options that satisfy the DcqlQuery.
    pub set_options: Vec<CredentialSetOption>,

    /// Map from CredentialQuery ID to all credentials that failed to match and why.
    pub mismatches: Vec<DcqlQueryMismatch>,
}

impl DcqlMatchResponse {
    pub fn new(set_options: Vec<CredentialSetOption>, mismatches: Vec<DcqlQueryMismatch>) -> Self {
        Self {
            set_options,
            mismatches,
        }
    }
}

impl DcqlQuery {
    pub fn select_credentials_with_info(
        &self,
        credential_store: impl CredentialStore,
    ) -> DcqlMatchResponse {
        let credentials = credential_store.get();

        match (&self.credential_sets, &self.credentials) {
            (Some(sets), Some(queries)) => {
                let credential_query_map = queries
                    .iter()
                    .map(|a| (a.id.clone(), a))
                    .collect::<HashMap<_, _>>();

                let mut mismatches = Vec::<DcqlQueryMismatch>::new();
                let mut matching_sets = Vec::<CredentialSetOption>::new();

                for set in sets {
                    let mut variations = Vec::<BTreeMap<String, CredentialOptions>>::new();

                    'outer_loop: for option in &set.options {
                        let mut possible_candidates: BTreeMap<String, CredentialOptions> =
                            BTreeMap::new();

                        for id in option {
                            let Some(query) = credential_query_map.get(id) else {
                                mismatches.push(DcqlQueryMismatch::CredentialQueryNotFound {
                                    id: id.clone(),
                                });
                                continue 'outer_loop;
                            };

                            let mut matching_creds = Vec::<Disclosure>::new();

                            for cred in &credentials {
                                match cred.is_satisfied(query) {
                                    Ok(claims) => matching_creds.push(Disclosure {
                                        credential: cred.clone(),
                                        claims_queries: claims,
                                    }),
                                    Err(err) => mismatches.push(
                                        DcqlQueryMismatch::UnsatisfiedCredentialQuery {
                                            query_id: id.clone(),
                                            credential: cred.clone(),
                                            reason: err,
                                        },
                                    ),
                                }
                            }

                            if matching_creds.is_empty() {
                                continue 'outer_loop;
                            }

                            possible_candidates.insert(
                                id.clone(),
                                CredentialOptions {
                                    options: matching_creds,
                                },
                            );
                        }

                        variations.push(possible_candidates);
                    }

                    if variations.is_empty() {
                        continue;
                    }

                    matching_sets.push(CredentialSetOption {
                        purpose: set
                            .purpose
                            .as_ref()
                            .and_then(|a| a.as_str().map(|a| a.to_string())),
                        set_options: variations
                            .into_iter()
                            .map(|bt| {
                                bt.into_iter()
                                    .map(|kv| SetOption {
                                        id: kv.0,
                                        options: kv.1.options,
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .collect(),
                    })
                }

                DcqlMatchResponse::new(matching_sets, mismatches)
            }

            (None, Some(queries)) => {
                let mut mismatches = Vec::<DcqlQueryMismatch>::new();
                let mut option = Vec::<SetOption>::new();

                for query in queries {
                    let mut matches = Vec::<Disclosure>::new();

                    for credential in &credentials {
                        match credential.is_satisfied(query) {
                            Ok(claims) => matches.push(Disclosure {
                                credential: credential.clone(),
                                claims_queries: claims,
                            }),
                            Err(err) => {
                                mismatches.push(DcqlQueryMismatch::UnsatisfiedCredentialQuery {
                                    query_id: query.id.clone(),
                                    credential: credential.clone(),
                                    reason: err,
                                })
                            }
                        }
                    }

                    if !matches.is_empty() {
                        option.push(SetOption {
                            id: query.id.clone(),
                            options: matches,
                        });
                    }
                }

                // All credential queries can be satisfied.
                let options = if option.is_empty() {
                    Vec::<CredentialSetOption>::new()
                } else {
                    vec![CredentialSetOption {
                        purpose: None,
                        set_options: vec![option],
                    }]
                };

                DcqlMatchResponse::new(options, mismatches)
            }

            // No queries are defined.
            _ => DcqlMatchResponse::default(),
        }
    }

    pub fn select_credentials(
        &self,
        credential_store: impl CredentialStore,
    ) -> Vec<CredentialSetOption> {
        self.select_credentials_with_info(credential_store)
            .set_options
    }
}

#[uniffi::export]
pub fn get_requested_attributes(
    credential_query: &CredentialQuery,
    credential: Credential,
) -> Value {
    let Ok(claims_queries) = credential.is_satisfied(credential_query) else {
        return Value::Null;
    };
    // all queries match
    if claims_queries.is_empty() {
        let mut key_value_match = HashMap::new();
        let Some(claims) = credential_query.claims.as_ref() else {
            return Value::Null;
        };
        for claim in claims {
            let body = match &credential {
                Credential::SdJwtCredential(sdjwt) => sdjwt.claims.clone(),
                Credential::MdocCredential(mdoc) => mdoc.namespace_map.clone(),
                #[cfg(feature = "bbs")]
                Credential::BbsCredential(bbs) => bbs.body().clone(),
                Credential::W3CCredential(w3c) => w3c.json.clone(),
                Credential::OpenBadgeCredential(ldp_vc) => ldp_vc.data.clone(),
            };

            let all_ptrs = claim.path.resolve_ptr(body.clone()).unwrap_or(vec![]);
            for p in all_ptrs {
                let key = p
                    .iter()
                    .map(|p| match p {
                        PointerPart::String(s) => s.to_string(),
                        PointerPart::Index(i) => i.to_string(),
                        PointerPart::Null(_) => "null".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                key_value_match.insert(key, p.select(body.clone()).unwrap()[0].clone());
            }
        }
        Value::Object(key_value_match)
    } else {
        let mut key_value_match = HashMap::new();
        let Some(claims) = credential_query.claims.as_ref() else {
            return Value::Null;
        };
        for cq in claims_queries {
            let Some(claim) = claims
                .iter()
                .find(|a| a.id().unwrap_or_default() == cq.id().unwrap_or_default())
            else {
                continue;
            };

            let body = match &credential {
                Credential::SdJwtCredential(sdjwt) => sdjwt.claims.clone(),
                Credential::MdocCredential(mdoc) => mdoc.namespace_map.clone(),
                #[cfg(feature = "bbs")]
                Credential::BbsCredential(bbs) => bbs.body().clone(),
                Credential::W3CCredential(w3c) => w3c.json.clone(),
                Credential::OpenBadgeCredential(ldp_vc) => ldp_vc.data.clone(),
            };

            let all_ptrs = claim.path.resolve_ptr(body.clone()).unwrap_or(vec![]);
            for p in all_ptrs {
                let key = p
                    .iter()
                    .map(|p| match p {
                        PointerPart::String(s) => s.to_string(),
                        PointerPart::Index(i) => i.to_string(),
                        PointerPart::Null(_) => "null".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                key_value_match.insert(key, p.select(body.clone()).unwrap()[0].clone());
            }
        }
        Value::Object(key_value_match)
    }
}

impl Credential {
    pub fn matches_meta_mdoc(mdoc: &MdocRust, meta: Option<&Meta>) -> Result<(), MdocMetaMismatch> {
        // Assume that if meta is set, we also have vct_values set
        if let Some(Meta::IsoMdoc { doctype_value }) = meta {
            let doc_type = mdoc.get_doc_type();
            if &doc_type != doctype_value {
                return Err(MdocMetaMismatch::WrongDocType);
            }
        } else if meta.is_some() {
            return Err(MdocMetaMismatch::InvalidMeta);
        }
        Ok(())
    }

    pub fn matches_meta_sdjwt(
        sd_jwt: &SdJwtRust,
        meta: Option<&Meta>,
    ) -> Result<(), SdJwtMetaMismatch> {
        // Assume that if meta is set, we also have vct_values set
        if let Some(Meta::SdjwtVc { vct_values: values }) = meta {
            let vct = Self::get_vct(sd_jwt);
            if !values.iter().any(|a| a == vct) {
                return Err(SdJwtMetaMismatch::WrongVctValue);
            }
        } else if meta.is_some() {
            return Err(SdJwtMetaMismatch::InvalidMeta);
        }
        Ok(())
    }

    #[cfg(feature = "bbs")]
    pub fn matches_meta_bbs(bbs: &BbsRust, meta: Option<&Meta>) -> Result<(), BbsMetaMismatch> {
        // Assume that if meta is set, we also have vct_values set
        match meta {
            Some(Meta::W3C { credential_types }) => {
                let types = bbs.types();

                if !credential_types.iter().any(|a| types.contains(a)) {
                    Err(BbsMetaMismatch::WrongCredentialType)
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
            _ => Err(BbsMetaMismatch::InvalidMeta),
        }
    }

    pub fn matches_meta_w3c(_w3c: &W3CSdJwt, _meta: Option<&Meta>) -> Result<(), W3CMetaMismatch> {
        Ok(())
    }

    pub fn matches_meta_open_badges(_ldp_vc: &LdpVC, _meta: Option<&Meta>) -> Result<(), ()> {
        Ok(())
    }

    pub fn get_vct(sd_jwt: &SdJwtRust) -> &str {
        sd_jwt
            .claims
            .get("vct")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or("")
    }

    pub fn is_satisfied(
        &self,
        credential_query: &CredentialQuery,
    ) -> Result<Vec<ClaimsQuery>, DcqlCredentialQueryMismatch> {
        let expected_format_error =
            DcqlCredentialQueryMismatch::ExpectedFormat(credential_query.format.clone());

        // check for the credential query format
        match self {
            Credential::SdJwtCredential(_)
                if !SDJWT_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error);
            }
            Credential::MdocCredential(_)
                if !MDOC_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error)
            }
            #[cfg(feature = "bbs")]
            Credential::BbsCredential(_)
                if !BBS_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error)
            }
            Credential::W3CCredential(_)
                if !W3C_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error)
            }
            Credential::OpenBadgeCredential(_)
                if !OPEN_BADGE_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error)
            }
            _ => (),
        }

        match self {
            Credential::SdJwtCredential(sd_jwt) => {
                if let Err(e) = Self::matches_meta_sdjwt(sd_jwt, credential_query.meta.as_ref()) {
                    return Err(DcqlCredentialQueryMismatch::SdJwtMeta(e));
                }
            }
            Credential::MdocCredential(mdoc) => {
                if let Err(e) = Self::matches_meta_mdoc(mdoc, credential_query.meta.as_ref()) {
                    return Err(DcqlCredentialQueryMismatch::MdocMeta(e));
                }
            }
            #[cfg(feature = "bbs")]
            Credential::BbsCredential(bbs) => {
                if let Err(e) = Self::matches_meta_bbs(bbs, credential_query.meta.as_ref()) {
                    return Err(DcqlCredentialQueryMismatch::BbsMeta(e));
                }
            }
            Credential::W3CCredential(w3c) => {
                if let Err(e) = Self::matches_meta_w3c(w3c, credential_query.meta.as_ref()) {
                    return Err(DcqlCredentialQueryMismatch::W3CMeta(e));
                }
            }
            Credential::OpenBadgeCredential(ldp_vc) => {
                if let Err(_) =
                    Self::matches_meta_open_badges(ldp_vc, credential_query.meta.as_ref())
                {
                    unreachable!(); // currently no meta checks for open badges
                }
            }
        }

        match (&credential_query.claim_sets, &credential_query.claims) {
            // if we have claims_sets we need to check possible combinations
            (Some(claims_sets), Some(claims)) => {
                let mut order_least = claims_sets.clone();
                // if claims_set is set all claims need an id
                // https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html#section-6.1
                if !claims.iter().all(|a| a.id().is_some()) {
                    return Err(DcqlCredentialQueryMismatch::SomeCredentialQueriesDoNotHaveAnId);
                }

                let claims_map = claims
                    .iter()
                    .map(|a| (a.id().unwrap(), a.to_owned()))
                    .collect::<HashMap<_, _>>();

                // we SHOULD use the "principle of least information".
                order_least.sort_by(|a, b| {
                    let left: usize = a
                        .iter()
                        .filter_map(|e| claims_map.get(e))
                        .map(|a| a.path.score())
                        .sum();
                    let right = b
                        .iter()
                        .filter_map(|e| claims_map.get(e))
                        .map(|a| a.path.score())
                        .sum();
                    left.cmp(&right)
                });

                let mut errors = HashMap::<String, DcqlClaimQueryMismatch>::new();

                //find first matching claims set
                'claim_set: for claim_set in order_least {
                    let mut queries = vec![];
                    for claim_query_id in &claim_set {
                        let Some(claim_query) = claims_map.get(claim_query_id) else {
                            continue 'claim_set;
                        };
                        if let Err(err) = claim_query.matches(self) {
                            errors.insert(claim_query_id.clone(), err);
                            continue 'claim_set;
                        }
                        queries.push(claim_query.clone());
                    }
                    return Ok(queries);
                }

                Err(DcqlCredentialQueryMismatch::UnsatisfiedClaimQueries(
                    errors.into_values().collect::<Vec<_>>(),
                ))
            }

            // when we have no claims_sets we need to check all claim_querries
            (None, Some(claims)) => {
                let mut errors = Vec::<DcqlClaimQueryMismatch>::new();

                for claim_query in claims {
                    if let Err(e) = claim_query.matches(self) {
                        errors.push(e);
                    }
                }

                if errors.is_empty() {
                    Ok(claims.clone())
                } else {
                    Err(DcqlCredentialQueryMismatch::UnsatisfiedClaimQueries(errors))
                }
            }
            _ => Ok(Vec::new()),
        }
    }
}

impl ClaimsQuery {
    pub fn matches(&self, credential: &Credential) -> Result<(), DcqlClaimQueryMismatch> {
        let data = match credential {
            Credential::SdJwtCredential(sd_jwt) => sd_jwt.get(Arc::new(self.path.clone())),
            Credential::MdocCredential(mdoc) => mdoc.get(Arc::new(self.path.clone())),
            #[cfg(feature = "bbs")]
            Credential::BbsCredential(bbs) => bbs.get(Arc::new(self.path.clone())),
            Credential::W3CCredential(w3c) => {
                let path = if matches!(self.path.first(),
                    Some(PointerPart::String(s)) if s == "credentialSubject"
                ) {
                    self.path.clone()
                } else {
                    let mut path = self.path.clone();
                    path.insert(0, PointerPart::String("credentialSubject".to_string()));
                    path
                };
                w3c.get(Arc::new(path))
            }
            Credential::OpenBadgeCredential(ldp_vc) => {
                let path = if matches!(self.path.first(),
                    Some(PointerPart::String(s)) if s == "credentialSubject"
                ) {
                    self.path.clone()
                } else {
                    let mut path = self.path.clone();
                    path.insert(0, PointerPart::String("credentialSubject".to_string()));
                    path
                };
                ldp_vc.get(Arc::new(path))
            }
        };

        let Some(data) = data else {
            return Err(DcqlClaimQueryMismatch::ClaimQueryPath {
                path: self.path.clone(),
                id: self.id.clone(),
            });
        };

        if let Some(vals) = self.values.as_ref() {
            for d in &data {
                if !vals.iter().any(|v| v == d) {
                    return Err(DcqlClaimQueryMismatch::ClaimQueryValues {
                        id: self.id.clone(),
                        path: self.path.clone(),
                        actual: d.clone(),
                        values: vals.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[uniffi::export]
pub fn select_credentials(query: DcqlQuery, credentials: Vec<String>) -> Vec<CredentialSetOption> {
    query
        .select_credentials(credentials.iter().map(String::as_str).collect::<Vec<_>>())
        .into_iter()
        .collect()
}

#[uniffi::export]
pub fn select_credentials_with_info(
    query: DcqlQuery,
    credentials: Vec<String>,
) -> DcqlMatchResponse {
    query.select_credentials_with_info(credentials.iter().map(String::as_str).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {

    use heidi_credentials_rust::models::PointerPart;

    use crate::models::{Credential, DcqlQuery};

    pub const CREDENTIAL_STORE :[&str;6] = ["eyJ4NWMiOlsiTUlJQ3NqQ0NBbGVnQXdJQkFnSVVFdCtiNjdmRVJpWnV3MDFNbnl5N1lqU01rbk13Q2dZSUtvWkl6ajBFQXdJd2djWXhDekFKQmdOVkJBWVRBa1JGTVIwd0d3WURWUVFJREJSSFpXMWxhVzVrWlNCTmRYTjBaWEp6ZEdGa2RERVVNQklHQTFVRUJ3d0xUWFZ6ZEdWeWMzUmhaSFF4SFRBYkJnTlZCQW9NRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1Rc3dDUVlEVlFRTERBSkpWREVwTUNjR0ExVUVBd3dnYVhOemRXRnVZMlV1WjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXhLekFwQmdrcWhraUc5dzBCQ1FFV0hIUmxjM1JBWjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXdIaGNOTWpReE1USTJNVE15TlRVNFdoY05NalV4TVRJMk1UTXlOVFU0V2pDQnhqRUxNQWtHQTFVRUJoTUNSRVV4SFRBYkJnTlZCQWdNRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1SUXdFZ1lEVlFRSERBdE5kWE4wWlhKemRHRmtkREVkTUJzR0ExVUVDZ3dVUjJWdFpXbHVaR1VnVFhWemRHVnljM1JoWkhReEN6QUpCZ05WQkFzTUFrbFVNU2t3SndZRFZRUUREQ0JwYzNOMVlXNWpaUzVuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pURXJNQ2tHQ1NxR1NJYjNEUUVKQVJZY2RHVnpkRUJuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJEWVh0OE0rNUUxQURqNU4yUnYvekl3Qmx2a1RsdDNnc3NjcktQNG93ZzZrbTlFanY1YkhxRFdZK25RaTI5ZXpOSDJ0a2hHcktlMFpzbWVIOVpxVXNJK2pJVEFmTUIwR0ExVWREZ1FXQkJSU1cyQUdZajFkSjVOejg0L1hvakREakgwMFh6QUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF6YTE0WGF0eHJoOFBlYmhvS3dFd0hIYkhFZVA4NlNFNHBaaUh2VklhZlpRQ0lRRDJqcXN1U1FiZUtDdWk5NVJ3Q2txQWdXcnlad29LWE80VG1iK0x1NnlwWHc9PSJdLCJraWQiOiJNSUhsTUlITXBJSEpNSUhHTVFzd0NRWURWUVFHRXdKRVJURWRNQnNHQTFVRUNBd1VSMlZ0WldsdVpHVWdUWFZ6ZEdWeWMzUmhaSFF4RkRBU0JnTlZCQWNNQzAxMWMzUmxjbk4wWVdSME1SMHdHd1lEVlFRS0RCUkhaVzFsYVc1a1pTQk5kWE4wWlhKemRHRmtkREVMTUFrR0ExVUVDd3dDU1ZReEtUQW5CZ05WQkFNTUlHbHpjM1ZoYm1ObExtZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsTVNzd0tRWUpLb1pJaHZjTkFRa0JGaHgwWlhOMFFHZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsQWhRUzM1dnJ0OFJHSm03RFRVeWZMTHRpTkl5U2N3PT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiM1VDUmFnbFFnZ29BZEMtLU1iN1RnMTFBRUhMb3B0VjJmaDZ0b19MYXBZYyIsIjY3TWw4REh5OFJlYVZQVzRZbU9ielFhSXNpSEJoU181ODdjY0c0VVQzQ1EiLCJBVm5GZEptZTA5dFpoZkFPN2pPSzhpNzE3Uzl1UHBHd0xtVTRXSEk2MGwwIiwiWVNkamd4akdGTjdKTWg5UHl6Z2VFaGtTc0VQXzJrb1hEU2cxaUhPdFc1TSIsImJnTUg1Rkk3OHNCRmo2bTdFZm52Nm1OZDZVVjhCZXJ4bjlNVzR5X0lWUDQiLCJidHozcVNfTXE5eEI4bmVVaDRWeTRzRndGTmM1Y0RsUnQzUlBYaFc5elc0IiwiZW1KcllFN1I4bThTTkpRY3NldFpEVHViNVJlT05HYW1Ma2N5djBNMEZWMCIsInVEei1ZZG1KS2sxWExhYVR1MW91Nk5XNWlMcWJ0R1k0VWw2RTlNVXVNWVUiXSwidmN0IjoiaHR0cHM6Ly9kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLnViaXF1ZS5jaC92MS9zY2hlbWEvc3R1ZGllcmVuZGVuYXVzd2Vpcy0zMWlxMi8wLjAuNCIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9zcHJpbmQtZXVkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9kd2ppb28vYy9pVGRqbFlLRVowVWRnNHB0RWd0Ym5yIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InNHVVBwWFNuZUI2SWVtTTdZUklqbmxVQjZmZUtfbm1tQkN5LXh3ODBiSkEiLCJ5IjoiS1haNkp4Y3cxdUxKNTVDZnJBM0lPRWtGcTA1LXRlYVdjOGlCbHF3RWNSdyJ9fSwiZXhwIjoxNzM1NzI5ODM0LCJzY2hlbWFfaWRlbnRpZmllciI6eyJjcmVkZW50aWFsSWRlbnRpZmllciI6InN0dWRpZXJlbmRlbmF1c3dlaXMtMzFpcTIiLCJ2ZXJzaW9uIjoiMC4wLjQifSwiaWF0IjoxNzM0NTIwMjM0LCJyZW5kZXIiOnsidHlwZSI6Ik92ZXJsYXlzQ2FwdHVyZUJ1bmRsZVYxIiwib2NhIjoiaHR0cHM6Ly9zcHJpbmQtZXVkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9vY2EvSUFKU3l2M3V4R3NSOThxR0dMbnJFSFROMjBaNG9rU2dWMWw1cVFvQnczeUs3Lmpzb24ifX0.eWMps2qbyfpoKwmcF0rVQO4sRzFngKDavhnnUKaIOH0U4VqY2Eb6ELwM-eRmWPNs20B6gAPlSMMTCH05kZIR1A~WyJrZlBSVGF0TGMyVGE0VGdCb1JJQTZ3IiwiZmlyc3ROYW1lIiwiTWFydGluYSJd~WyJDNFRLTWR3U2Y5b2V5UlhtSmU0cld3IiwibGFzdE5hbWUiLCJNdXN0ZXJtYW5uIl0~WyJjVzd3MmlsdEtoOGlMS1l6UFhwX1FnIiwibWF0cmljdWxhdGlvbk5yIiwiMDEvNzY1NDMyMSJd~WyJ6RzR6cWsxa25oN1MtNkhZLVp6ME93IiwiaXNzdWVkQnkiLCJVbml2ZXJzaXTDpHQgTXVzdGVyc3RhZHQiXQ~WyJ2SDVCRFYzTll0R1VnRkVDZFRiMmhRIiwidmFsaWRVbnRpbCIsIjIwMjUxMjE4Il0~WyJfNU4tS2hJUzItOExQVXR0UkJZcjB3IiwiZGF0ZU9mQmlydGgiLCIyMDAxMDgxMiJd~WyJUV05ZZzY1MUZCc2RhY2V2UngyY2NBIiwiYmFkZ2VOciIsIjEyMzQ1Njc4OSJd~WyJ2NnRiWFRacXBKckc5QjBkQy0tMVpnIiwiaXNzdWVkT24iLCIyMDI0MTIxOCJd~",
        "eyJ4NWMiOlsiTUlJQ3NqQ0NBbGVnQXdJQkFnSVVFdCtiNjdmRVJpWnV3MDFNbnl5N1lqU01rbk13Q2dZSUtvWkl6ajBFQXdJd2djWXhDekFKQmdOVkJBWVRBa1JGTVIwd0d3WURWUVFJREJSSFpXMWxhVzVrWlNCTmRYTjBaWEp6ZEdGa2RERVVNQklHQTFVRUJ3d0xUWFZ6ZEdWeWMzUmhaSFF4SFRBYkJnTlZCQW9NRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1Rc3dDUVlEVlFRTERBSkpWREVwTUNjR0ExVUVBd3dnYVhOemRXRnVZMlV1WjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXhLekFwQmdrcWhraUc5dzBCQ1FFV0hIUmxjM1JBWjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXdIaGNOTWpReE1USTJNVE15TlRVNFdoY05NalV4TVRJMk1UTXlOVFU0V2pDQnhqRUxNQWtHQTFVRUJoTUNSRVV4SFRBYkJnTlZCQWdNRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1SUXdFZ1lEVlFRSERBdE5kWE4wWlhKemRHRmtkREVkTUJzR0ExVUVDZ3dVUjJWdFpXbHVaR1VnVFhWemRHVnljM1JoWkhReEN6QUpCZ05WQkFzTUFrbFVNU2t3SndZRFZRUUREQ0JwYzNOMVlXNWpaUzVuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pURXJNQ2tHQ1NxR1NJYjNEUUVKQVJZY2RHVnpkRUJuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJEWVh0OE0rNUUxQURqNU4yUnYvekl3Qmx2a1RsdDNnc3NjcktQNG93ZzZrbTlFanY1YkhxRFdZK25RaTI5ZXpOSDJ0a2hHcktlMFpzbWVIOVpxVXNJK2pJVEFmTUIwR0ExVWREZ1FXQkJSU1cyQUdZajFkSjVOejg0L1hvakREakgwMFh6QUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF6YTE0WGF0eHJoOFBlYmhvS3dFd0hIYkhFZVA4NlNFNHBaaUh2VklhZlpRQ0lRRDJqcXN1U1FiZUtDdWk5NVJ3Q2txQWdXcnlad29LWE80VG1iK0x1NnlwWHc9PSJdLCJraWQiOiJNSUhsTUlITXBJSEpNSUhHTVFzd0NRWURWUVFHRXdKRVJURWRNQnNHQTFVRUNBd1VSMlZ0WldsdVpHVWdUWFZ6ZEdWeWMzUmhaSFF4RkRBU0JnTlZCQWNNQzAxMWMzUmxjbk4wWVdSME1SMHdHd1lEVlFRS0RCUkhaVzFsYVc1a1pTQk5kWE4wWlhKemRHRmtkREVMTUFrR0ExVUVDd3dDU1ZReEtUQW5CZ05WQkFNTUlHbHpjM1ZoYm1ObExtZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsTVNzd0tRWUpLb1pJaHZjTkFRa0JGaHgwWlhOMFFHZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsQWhRUzM1dnJ0OFJHSm03RFRVeWZMTHRpTkl5U2N3PT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiZmpEVW9QSU0xNkg0NTRyckt6eXpTTy10UU1FR1FlVFdEem4ydUdMV1RpcyJdLCJ2Y3QiOiJodHRwczovL2NyZWF0b3Itd3MudGc0dS5jaC92MS9zY2hlbWEvZnVocmVyYXVzd2Vpcy1zbmtyZS8wLjAuMSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9vaWQ0dmNpLWlzc3Vlci50ZzR1LmNoL2tkc2ZqYS9jLzdtT1RWeVJwdTZ1cTYzNGVtNGhzSzEiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiejhYbnFvaVZyTGc0SU9HM2FWR2hCbzhQMExTMXltbkFJSWJpUDNpRklhNCIsInkiOiJ5M3lhUVRJOUtPWXZPa1BWN1ZlaHVjTjdHeUg2Y1NSMHpEX3NtUkZGTG5jIn19LCJleHAiOjE3MzU3MzM3MDQsInNjaGVtYV9pZGVudGlmaWVyIjp7ImNyZWRlbnRpYWxJZGVudGlmaWVyIjoiZnVocmVyYXVzd2Vpcy1zbmtyZSIsInZlcnNpb24iOiIwLjAuMSJ9LCJpYXQiOjE3MzQ1MjQxMDQsInJlbmRlciI6eyJ0eXBlIjoiT3ZlcmxheXNDYXB0dXJlQnVuZGxlVjEiLCJvY2EiOiJodHRwczovL29pZDR2Y2ktaXNzdWVyLnRnNHUuY2gvb2NhL0lBRUlRYktlT1FIcjJ3ZXVWWklCWEl6QTNLNzNjT2Z2WVdzMFNxaU9nVU9ORy5qc29uIn19.l6R1bAfIg22rmMET9yd8fJjGEkGzKjoE8CZu5hf_wacuj_bliaCIsrO1mObIuQEmbSRAVEoJOBhpOV3qnwjj_A~WyJubjB5cElBLVZTV0h3ZXdoOFVId0JnIiwibGFzdE5hbWUiLCJhbXJlaW4iXQ~",
        "eyJ4NWMiOlsiTUlJQ3NqQ0NBbGVnQXdJQkFnSVVFdCtiNjdmRVJpWnV3MDFNbnl5N1lqU01rbk13Q2dZSUtvWkl6ajBFQXdJd2djWXhDekFKQmdOVkJBWVRBa1JGTVIwd0d3WURWUVFJREJSSFpXMWxhVzVrWlNCTmRYTjBaWEp6ZEdGa2RERVVNQklHQTFVRUJ3d0xUWFZ6ZEdWeWMzUmhaSFF4SFRBYkJnTlZCQW9NRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1Rc3dDUVlEVlFRTERBSkpWREVwTUNjR0ExVUVBd3dnYVhOemRXRnVZMlV1WjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXhLekFwQmdrcWhraUc5dzBCQ1FFV0hIUmxjM1JBWjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXdIaGNOTWpReE1USTJNVE15TlRVNFdoY05NalV4TVRJMk1UTXlOVFU0V2pDQnhqRUxNQWtHQTFVRUJoTUNSRVV4SFRBYkJnTlZCQWdNRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1SUXdFZ1lEVlFRSERBdE5kWE4wWlhKemRHRmtkREVkTUJzR0ExVUVDZ3dVUjJWdFpXbHVaR1VnVFhWemRHVnljM1JoWkhReEN6QUpCZ05WQkFzTUFrbFVNU2t3SndZRFZRUUREQ0JwYzNOMVlXNWpaUzVuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pURXJNQ2tHQ1NxR1NJYjNEUUVKQVJZY2RHVnpkRUJuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJEWVh0OE0rNUUxQURqNU4yUnYvekl3Qmx2a1RsdDNnc3NjcktQNG93ZzZrbTlFanY1YkhxRFdZK25RaTI5ZXpOSDJ0a2hHcktlMFpzbWVIOVpxVXNJK2pJVEFmTUIwR0ExVWREZ1FXQkJSU1cyQUdZajFkSjVOejg0L1hvakREakgwMFh6QUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF6YTE0WGF0eHJoOFBlYmhvS3dFd0hIYkhFZVA4NlNFNHBaaUh2VklhZlpRQ0lRRDJqcXN1U1FiZUtDdWk5NVJ3Q2txQWdXcnlad29LWE80VG1iK0x1NnlwWHc9PSJdLCJraWQiOiJNSUhsTUlITXBJSEpNSUhHTVFzd0NRWURWUVFHRXdKRVJURWRNQnNHQTFVRUNBd1VSMlZ0WldsdVpHVWdUWFZ6ZEdWeWMzUmhaSFF4RkRBU0JnTlZCQWNNQzAxMWMzUmxjbk4wWVdSME1SMHdHd1lEVlFRS0RCUkhaVzFsYVc1a1pTQk5kWE4wWlhKemRHRmtkREVMTUFrR0ExVUVDd3dDU1ZReEtUQW5CZ05WQkFNTUlHbHpjM1ZoYm1ObExtZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsTVNzd0tRWUpLb1pJaHZjTkFRa0JGaHgwWlhOMFFHZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsQWhRUzM1dnJ0OFJHSm03RFRVeWZMTHRpTkl5U2N3PT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiTjdOMjBOdDFXbGg4Y0o2Nk5WSnhDLUVaSmVpeVBMdXF3MkNzeGtWYy04TSIsIm1SeVZEQVJWTHZDdUd1eUJHaVczWVNSanNWYW42UkR3TXA4RU53M3c2YlkiLCJ5bURGb0FDbmlRemhVMjNRVHF5WDFNWEk0ZklnR0JPcmtJVHhRS044MnZVIl0sInZjdCI6Imh0dHBzOi8vY3JlYXRvci13cy50ZzR1LmNoL3YxL3NjaGVtYS9iYXNpcy1pZC01Ynd1NS8wLjAuMiIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9vaWQ0dmNpLWlzc3Vlci50ZzR1LmNoL2tkc2ZqYS9jL3E3TEdnY25FWTF6VkVGRWtjeTFacVIiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiNExNTW5CYVdZUVppWXMxTVkzQ0ZLcjJZN0RBbWk1cHFJb3FBRDNWdDJjVSIsInkiOiJ6ZWROUGlaSWlQTTFiZHRjMzlwTUlKYWd4ajFOeFRSZkxDejJQR2V2LTJVIn19LCJleHAiOjE3MzU4ODk0ODIsInNjaGVtYV9pZGVudGlmaWVyIjp7ImNyZWRlbnRpYWxJZGVudGlmaWVyIjoiYmFzaXMtaWQtNWJ3dTUiLCJ2ZXJzaW9uIjoiMC4wLjIifSwiaWF0IjoxNzM0Njc5ODgyLCJyZW5kZXIiOnsidHlwZSI6Ik92ZXJsYXlzQ2FwdHVyZUJ1bmRsZVYxIiwib2NhIjoiaHR0cHM6Ly9vaWQ0dmNpLWlzc3Vlci50ZzR1LmNoL29jYS9JQUVaY2Zzc2hnXzlqQ2gwMXUyMFdXNjMxTXBkek1qMldqWVE3eG16aE9wdk8uanNvbiJ9fQ.afFqpVUpmcPdsK4mVzYyaS0jWT9Ziy3bywmM8tJqneXa2mo6embreeyRxSol-1yVv4QdJ_1NoLVTYnYp_yqRUw~WyJnR0ZnNEhtWHI3UkJkSG1Dc3NBc2l3IiwibGFzdE5hbWUiLCJBbXJlaW4iXQ~WyJwNkUtTDBhNW8xR215SEsxYWVjU1FBIiwiZmlyc3ROYW1lcyIsIlBhdHJpY2siXQ~WyIxLVhqcXZkQlM4c2U5T3VKaTdBVUh3IiwiZGF0ZU9mQmlydGgiLCIyMDI0MTIwNSJd~",
        "eyJ4NWMiOlsiTUlJQ3NqQ0NBbGVnQXdJQkFnSVVFdCtiNjdmRVJpWnV3MDFNbnl5N1lqU01rbk13Q2dZSUtvWkl6ajBFQXdJd2djWXhDekFKQmdOVkJBWVRBa1JGTVIwd0d3WURWUVFJREJSSFpXMWxhVzVrWlNCTmRYTjBaWEp6ZEdGa2RERVVNQklHQTFVRUJ3d0xUWFZ6ZEdWeWMzUmhaSFF4SFRBYkJnTlZCQW9NRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1Rc3dDUVlEVlFRTERBSkpWREVwTUNjR0ExVUVBd3dnYVhOemRXRnVZMlV1WjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXhLekFwQmdrcWhraUc5dzBCQ1FFV0hIUmxjM1JBWjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXdIaGNOTWpReE1USTJNVE15TlRVNFdoY05NalV4TVRJMk1UTXlOVFU0V2pDQnhqRUxNQWtHQTFVRUJoTUNSRVV4SFRBYkJnTlZCQWdNRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1SUXdFZ1lEVlFRSERBdE5kWE4wWlhKemRHRmtkREVkTUJzR0ExVUVDZ3dVUjJWdFpXbHVaR1VnVFhWemRHVnljM1JoWkhReEN6QUpCZ05WQkFzTUFrbFVNU2t3SndZRFZRUUREQ0JwYzNOMVlXNWpaUzVuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pURXJNQ2tHQ1NxR1NJYjNEUUVKQVJZY2RHVnpkRUJuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJEWVh0OE0rNUUxQURqNU4yUnYvekl3Qmx2a1RsdDNnc3NjcktQNG93ZzZrbTlFanY1YkhxRFdZK25RaTI5ZXpOSDJ0a2hHcktlMFpzbWVIOVpxVXNJK2pJVEFmTUIwR0ExVWREZ1FXQkJSU1cyQUdZajFkSjVOejg0L1hvakREakgwMFh6QUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF6YTE0WGF0eHJoOFBlYmhvS3dFd0hIYkhFZVA4NlNFNHBaaUh2VklhZlpRQ0lRRDJqcXN1U1FiZUtDdWk5NVJ3Q2txQWdXcnlad29LWE80VG1iK0x1NnlwWHc9PSJdLCJraWQiOiJNSUhsTUlITXBJSEpNSUhHTVFzd0NRWURWUVFHRXdKRVJURWRNQnNHQTFVRUNBd1VSMlZ0WldsdVpHVWdUWFZ6ZEdWeWMzUmhaSFF4RkRBU0JnTlZCQWNNQzAxMWMzUmxjbk4wWVdSME1SMHdHd1lEVlFRS0RCUkhaVzFsYVc1a1pTQk5kWE4wWlhKemRHRmtkREVMTUFrR0ExVUVDd3dDU1ZReEtUQW5CZ05WQkFNTUlHbHpjM1ZoYm1ObExtZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsTVNzd0tRWUpLb1pJaHZjTkFRa0JGaHgwWlhOMFFHZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsQWhRUzM1dnJ0OFJHSm03RFRVeWZMTHRpTkl5U2N3PT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiQVhFQl9kUFRUV3ZZT1FyNXdvVENSWElud3pUNXJWRmR3NkVZNTMwSnRSZyIsIkhidlpkaGo2Q0tSOExiQl9GNjRIaUF1bThhNzRvQ0FuZUY5Rmh5R29jb0EiLCJJa3F6NU9rUTN1ZmVSMzZXU1lqNFJSYm9lY2YzUkhaQzFFM0pqNHdpWXJnIiwibld1MHh6Yms5Tk13OXViXzRrWEFQN2d3S3UzTXNxX2J1MHNucDdyREpSbyIsInVtQmxpTnhUdjBxX2dsVlAyYXNwY1FfN3U2Q0Exc1BwTnF6MWFJLWR5bDAiXSwidmN0IjoiaHR0cHM6Ly9jcmVhdG9yLXdzLnRnNHUuY2gvdjEvc2NoZW1hL3NhbmEtYXVzd2Vpcy1zMTUwcC8wLjAuMiIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9vaWQ0dmNpLWlzc3Vlci50ZzR1LmNoL2tkc2ZqYS9jL2lzblpkdHVQVDR1NGo2OUtTV1JHT2kiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiRWI2SE1uWG5XNUs0OFZLY0x4VTAxLXVEODZ6RWYxY1JHcTZkc2tad254QSIsInkiOiIwc2w1bFF0NDZ3ZFYzdlZvcEVGWTV6UG40UDNPRENmeHdXZUJPQi1aRTJrIn19LCJleHAiOjE3MzU4ODk1MzMsInNjaGVtYV9pZGVudGlmaWVyIjp7ImNyZWRlbnRpYWxJZGVudGlmaWVyIjoic2FuYS1hdXN3ZWlzLXMxNTBwIiwidmVyc2lvbiI6IjAuMC4yIn0sImlhdCI6MTczNDY3OTkzMywicmVuZGVyIjp7InR5cGUiOiJPdmVybGF5c0NhcHR1cmVCdW5kbGVWMSIsIm9jYSI6Imh0dHBzOi8vb2lkNHZjaS1pc3N1ZXIudGc0dS5jaC9vY2EvSUFGOEw5RmY2cDVjTHVJbi1HaVYtdzNwUS1acjVveUsxWlBIczROMXhGeGF5Lmpzb24ifX0.lzsVZ38j2qOXOZflYccMUdBLAYEkP1-iUKrjEWfwdVGMrt08YJUcww3n-_zvVw_jjpR9lyv7-hsP--IziKnCvg~WyJ6cjBKQzF5b05xeTk1cDIxZkNtSlB3IiwibGFzdE5hbWUiLCJBbXJlaW4iXQ~WyJFd2xPZlVDQ21BeWxVUWxkY2p1NkRBIiwiZmlyc3ROYW1lIiwiUGF0cmljayJd~WyItNEJfSnhMUm5tQ29tN2FRTTJuVkVRIiwibm8iLCIxMjM0Il0~WyJoTHVRa3VSTlVwakZOUGlib3RkcFRnIiwiZGF0ZU9mQmlydGgiLCIyMDI0MTIwNSJd~WyIwekE2cWJCWmJNdnBOTlVreC1aM1ZnIiwiaXNzdWVkT24iLCIyMDI0MTIyMCJd~","omppc3N1ZXJBdXRohEOhASahGCFZArYwggKyMIICV6ADAgECAhQS35vrt8RGJm7DTUyfLLtiNIySczAKBggqhkjOPQQDAjCBxjELMAkGA1UEBhMCREUxHTAbBgNVBAgMFEdlbWVpbmRlIE11c3RlcnN0YWR0MRQwEgYDVQQHDAtNdXN0ZXJzdGFkdDEdMBsGA1UECgwUR2VtZWluZGUgTXVzdGVyc3RhZHQxCzAJBgNVBAsMAklUMSkwJwYDVQQDDCBpc3N1YW5jZS5nZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTErMCkGCSqGSIb3DQEJARYcdGVzdEBnZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTAeFw0yNDExMjYxMzI1NThaFw0yNTExMjYxMzI1NThaMIHGMQswCQYDVQQGEwJERTEdMBsGA1UECAwUR2VtZWluZGUgTXVzdGVyc3RhZHQxFDASBgNVBAcMC011c3RlcnN0YWR0MR0wGwYDVQQKDBRHZW1laW5kZSBNdXN0ZXJzdGFkdDELMAkGA1UECwwCSVQxKTAnBgNVBAMMIGlzc3VhbmNlLmdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMSswKQYJKoZIhvcNAQkBFhx0ZXN0QGdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENhe3wz7kTUAOPk3ZG__MjAGW-ROW3eCyxyso_ijCDqSb0SO_lseoNZj6dCLb17M0fa2SEasp7RmyZ4f1mpSwj6MhMB8wHQYDVR0OBBYEFFJbYAZiPV0nk3Pzj9eiMMOMfTRfMAoGCCqGSM49BAMCA0kAMEYCIQDNrXhdq3GuHw95uGgrATAcdscR4_zpITilmIe9Uhp9lAIhAPaOqy5JBt4oK6L3lHAKSoCBavJnCgpc7hOZv4u7rKlfWQMB2BhZAvymZ2RvY1R5cGV4I2NoLnViaXF1ZS5zdHVkaWVyZW5kZW5hdXN3ZWlzLjMxaXEyZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTEyLTE4VDExOjEwOjM3Wml2YWxpZEZyb23AdDIwMjQtMTItMThUMTE6MTA6MzdaanZhbGlkVW50aWzAdDIwMjUtMDEtMDFUMTE6MTA6MzdabHZhbHVlRGlnZXN0c6F4JWNoLnViaXF1ZS5kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLjGsAFggxnlGm31z1CWGEa5BBIuGLYlp5_cccd1ldiIm1mGyi5UBWCBd_7AWLWwoA-6ePUxvi4abDFOtpBX8Wo8B5PDE9DMpJgJYIEWhkue-r51m7uzQXDNZZveT3Q-Meu13B8_lynBL2COLA1ggJg3egNJ_54eyPeFRIbmphkGQeIE7o-bAC-BNX2jvrcMEWCAxtdc_wGO1q2NXdVbprsJ1prDyXB9lCdhgq7mZnq-RzgVYIB8kd3Dy2CMfigy0OdgQMj5MKqbYZ02_zP_mbz07CQO5BlggPlScDiOTaelc6tvDrkTNAO8-bJRlJxV4uiwIOkVqWzkHWCBlAcWP5zkDqcLbc931rmluOf35SkAK4dCIdT5OGoCkrQhYIID9rTi-XtPLZ3eVzSj-r7_fH2ZpbUZDCNmD7dGtrd_QCVggRCKEwGL-c5IH7P2qCpdbH9RrcPgMM5o2rqnP9aAS67wKWCCfpR3prTjz3gr0h1GWEDLl2y-qqaOkJlBqz5Uhbssb2gtYIPHILC5uXyjEphRzL8Uc2iJE0eq0_OuqQf0g8ZXvJ8RibWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggKbZRIp1rTldCEK0bhmDvHQBNBnPltgJkj_yYQfNwwxkiWCBG-bACEy5FzPqAX1sjmc9T7eW9NZIam195QBmzBNO0YG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAOGInq75NzBaH9ibX55givyWI2uaOL0FaGqJtfJK-RreSceL43yXT2DFiaSQGf3I8NdgsyiQCklQjZJhlRc_DHWpuYW1lU3BhY2VzoXglY2gudWJpcXVlLmRldi1zc2ktc2NoZW1hLWNyZWF0b3Itd3MuMYzYGFhWpGZyYW5kb21QH7VltQRBaJzzNVccAOJBhmhkaWdlc3RJRABsZWxlbWVudFZhbHVlak11c3Rlcm1hbm5xZWxlbWVudElkZW50aWZpZXJobGFzdE5hbWXYGFhUpGZyYW5kb21Q3m7qbdd1bOSxasjALM-LTWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlaDIwMjQxMjE4cWVsZW1lbnRJZGVudGlmaWVyaGlzc3VlZE9u2BhYVqRmcmFuZG9tUJSdp-LZWY6QlBtEnbzsvTBoZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWgyMDI1MTIxOHFlbGVtZW50SWRlbnRpZmllcmp2YWxpZFVudGls2BhYXaRmcmFuZG9tUGcEl2krGcUwTmYk0jYN-9poZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWowMS83NjU0MzIxcWVsZW1lbnRJZGVudGlmaWVyb21hdHJpY3VsYXRpb25OctgYWFekZnJhbmRvbVDt0wNifszHOWJI1kY-NdkHaGRpZ2VzdElEBGxlbGVtZW50VmFsdWViQ0hxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhrpGZyYW5kb21Q4KP5vUL4RRT7-aPbqlaG9WhkaWdlc3RJRAVsZWxlbWVudFZhbHVlwHgYMjAyNC0xMi0xOFQxMToxMDozNy4wMjNacWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhlpGZyYW5kb21Qeiw0wwo2Y5Sr41fAx2GBUWhkaWdlc3RJRAZsZWxlbWVudFZhbHVleBhVbml2ZXJzaXTDpHQgTXVzdGVyc3RhZHRxZWxlbWVudElkZW50aWZpZXJoaXNzdWVkQnnYGFhVpGZyYW5kb21QCHDDSiRlIpnmA4J8G_PyJ2hkaWdlc3RJRAdsZWxlbWVudFZhbHVlYkNIcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWFekZnJhbmRvbVBQ3bOvLogJMiOznXFJM0EzaGRpZ2VzdElECGxlbGVtZW50VmFsdWVoMjAwMTA4MTJxZWxlbWVudElkZW50aWZpZXJrZGF0ZU9mQmlydGjYGFhUpGZyYW5kb21Qd0B-48Z4kVftaCv1qyXtm2hkaWdlc3RJRAlsZWxlbWVudFZhbHVlaTEyMzQ1Njc4OXFlbGVtZW50SWRlbnRpZmllcmdiYWRnZU5y2BhYVKRmcmFuZG9tUPLy9Kk3MWbg01PuMimf3RxoZGlnZXN0SUQKbGVsZW1lbnRWYWx1ZWdNYXJ0aW5hcWVsZW1lbnRJZGVudGlmaWVyaWZpcnN0TmFtZdgYWGmkZnJhbmRvbVDhiQ6EGYsbFO2aX-jzc-NgaGRpZ2VzdElEC2xlbGVtZW50VmFsdWXAeBgyMDI1LTAxLTAxVDExOjEwOjM3LjAyM1pxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGU",
        "eyJkb2N1bWVudCI6IlBHUnBaRHBsZUdGdGNHeGxPbXB2YUc1a2IyVS1JRHhvZEhSd09pOHZjMk5vWlcxaExtOXlaeTlpYVhKMGFFUmhkR1UtSUNJeE9Ua3dMVEF4TFRBeFZEQXdPakF3T2pBd1dpSmVYanhvZEhSd09pOHZkM2QzTG5jekxtOXlaeTh5TURBeEwxaE5URk5qYUdWdFlTTmtZWFJsVkdsdFpUNGdMZ284Wkdsa09tVjRZVzF3YkdVNmFtOW9ibVJ2WlQ0Z1BHaDBkSEE2THk5elkyaGxiV0V1YjNKbkwyNWhiV1UtSUNKS2IyaHVJRVJ2WlNJZ0xnbzhaR2xrT21WNFlXMXdiR1U2YW05b2JtUnZaVDRnUEdoMGRIQTZMeTkzZDNjdWR6TXViM0puTHpFNU9Ua3ZNREl2TWpJdGNtUm1MWE41Ym5SaGVDMXVjeU4wZVhCbFBpQThhSFIwY0RvdkwzTmphR1Z0WVM1dmNtY3ZVR1Z5YzI5dVBpQXVDanhrYVdRNlpYaGhiWEJzWlRwcWIyaHVaRzlsUGlBOGFIUjBjRG92TDNOamFHVnRZUzV2Y21jdmRHVnNaWEJvYjI1bFBpQWlLRFF5TlNrZ01USXpMVFExTmpjaUlDNEtQR2gwZEhBNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k5d1pYSnpiMjR2TUQ0Z1BHaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekkyVjRjR2x5WVhScGIyNUVZWFJsUGlBaU1qQXpNQzB3TVMwd01WUXdNRG93TURvd01Gb2lYbDQ4YUhSMGNEb3ZMM2QzZHk1M015NXZjbWN2TWpBd01TOVlUVXhUWTJobGJXRWpaR0YwWlZScGJXVS1JQzRLUEdoMGRIQTZMeTlsZUdGdGNHeGxMbTl5Wnk5amNtVmtaVzUwYVdGc2N5OXdaWEp6YjI0dk1ENGdQR2gwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpJMk55WldSbGJuUnBZV3hUZFdKcVpXTjBQaUE4Wkdsa09tVjRZVzF3YkdVNmFtOW9ibVJ2WlQ0Z0xnbzhhSFIwY0RvdkwyVjRZVzF3YkdVdWIzSm5MMk55WldSbGJuUnBZV3h6TDNCbGNuTnZiaTh3UGlBOGFIUjBjRG92TDNkM2R5NTNNeTV2Y21jdk1UazVPUzh3TWk4eU1pMXlaR1l0YzNsdWRHRjRMVzV6STNSNWNHVS1JRHhvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeU5XWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkQ0Z0xnbzhhSFIwY0RvdkwyVjRZVzF3YkdVdWIzSm5MMk55WldSbGJuUnBZV3h6TDNCbGNuTnZiaTh3UGlBOGFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNamFYTnpkV0Z1WTJWRVlYUmxQaUFpTWpBeU1DMHdNUzB3TVZRd01Eb3dNRG93TUZvaVhsNDhhSFIwY0RvdkwzZDNkeTUzTXk1dmNtY3ZNakF3TVM5WVRVeFRZMmhsYldFalpHRjBaVlJwYldVLUlDNEtQR2gwZEhBNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k5d1pYSnpiMjR2TUQ0Z1BHaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekkybHpjM1ZsY2o0Z1BHUnBaRHBsZUdGdGNHeGxPbWx6YzNWbGNqQS1JQzRLUEdoMGRIQTZMeTlsZUdGdGNHeGxMbTl5Wnk5amNtVmtaVzUwYVdGc2N5OXdaWEp6YjI0dk1ENGdQR2gwZEhCek9pOHZlbXR3TFd4a0xtOXlaeTlrWlhacFkyVkNhVzVrYVc1blBpQmZPbUl3SUM0S1h6cGlNQ0E4YUhSMGNITTZMeTk2YTNBdGJHUXViM0puTDJSbGRtbGpaVUpwYm1ScGJtY2plRDRnSWxwSFJrOXZTQzkxUlhRMU0yOXVablZ3VVRoVVZFcEtVVFFyYWxKcU1IazVaMVpRV1dwd2MzVlNielE5SWw1ZVBHaDBkSEE2THk5M2QzY3Vkek11YjNKbkx6SXdNREV2V0UxTVUyTm9aVzFoSTJKaGMyVTJORUo1ZEdWelFtVS1JQzRLWHpwaU1DQThhSFIwY0hNNkx5OTZhM0F0YkdRdWIzSm5MMlJsZG1salpVSnBibVJwYm1jamVUNGdJazF1ZVhRd1RWWTBRMXBDU1dWUGJsTmxVVzFCVFdSUlVUSjVLMFJQTkVNd09HOXRjMU4wVTJOWlpVMDlJbDVlUEdoMGRIQTZMeTkzZDNjdWR6TXViM0puTHpJd01ERXZXRTFNVTJOb1pXMWhJMkpoYzJVMk5FSjVkR1Z6UW1VLUlDNEsiLCJwcm9vZiI6Ilh6cGlNQ0E4YUhSMGNITTZMeTkzTTJsa0xtOXlaeTl6WldOMWNtbDBlU04yWlhKcFptbGpZWFJwYjI1TlpYUm9iMlEtSUR4a2FXUTZaWGhoYlhCc1pUcHBjM04xWlhJd0kySnNjekV5WHpNNE1TMW5NaTF3ZFdJd01ERS1JQzRLWHpwaU1DQThhSFIwY0hNNkx5OTNNMmxrTG05eVp5OXpaV04xY21sMGVTTmpjbmx3ZEc5emRXbDBaVDRnSW1KaWN5MTBaWEp0ZDJselpTMXphV2R1WVhSMWNtVXRNakF5TXlJZ0xncGZPbUl3SUR4b2RIUndPaTh2ZDNkM0xuY3pMbTl5Wnk4eE9UazVMekF5THpJeUxYSmtaaTF6ZVc1MFlYZ3Ribk1qZEhsd1pUNGdQR2gwZEhCek9pOHZkek5wWkM1dmNtY3ZjMlZqZFhKcGRIa2pSR0YwWVVsdWRHVm5jbWwwZVZCeWIyOW1QaUF1Q2w4NllqQWdQR2gwZEhBNkx5OXdkWEpzTG05eVp5OWtZeTkwWlhKdGN5OWpjbVZoZEdWa1BpQWlNakF5TlMwd01TMHdNVlF3TURvd01Eb3dNRm9pWGw0OGFIUjBjRG92TDNkM2R5NTNNeTV2Y21jdk1qQXdNUzlZVFV4VFkyaGxiV0VqWkdGMFpWUnBiV1UtSUM0S1h6cGlNQ0E4YUhSMGNITTZMeTkzTTJsa0xtOXlaeTl6WldOMWNtbDBlU053Y205dlpsQjFjbkJ2YzJVLUlEeG9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwzTmxZM1Z5YVhSNUkyRnpjMlZ5ZEdsdmJrMWxkR2h2WkQ0Z0xncGZPbUl3SUR4b2RIUndjem92TDNjemFXUXViM0puTDNObFkzVnlhWFI1STNCeWIyOW1WbUZzZFdVLUlDSjFja05NTUd4U00wcFdTMG90YlUxUGJDMVNTemRpYzA4d1Z6TkNUMmgyWVRKdmRFazNUWFJSWjNwM01VeE1XVEF3YmxGVlRqTlZabmxuYUU5cE5tRTBPV0Z4UzAxRVFrSnVSbmhsVGt4UGVIbHdOV1p0TFZaTmRHWjJSelJ6VWxoeWJqVnJPVGgwVmpsQlJYaFhVbDlmY2xGeFQweFJabU5hVWs5WWFVVjZNMXBqTTNveGVVRllRbGRxVUhaRWFqZGFSelZHYTFwM0lsNWVQR2gwZEhCek9pOHZkek5wWkM1dmNtY3ZjMlZqZFhKcGRIa2piWFZzZEdsaVlYTmxQaUF1Q2cifQ"
    ];

    #[test]
    pub fn test_queries() {
        let q = r#"
{
    "credentials" : [
        {
            "id" : "test",
            "format" : "dc+sd-jwt",
            "meta" : {
                "vct_values" : [
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4"
                    ]
            },
            "claims" : [
                {
                    "path" : ["firstName"]
                }
            ]
        }
    ]
}
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
    }
    #[test]
    pub fn test_mdoc_queries() {
        let q = r#"
{
    "credentials" : [
        {
            "id" : "test",
            "format" : "mso_mdoc",
            "meta" : {
                "doctype_value" : "ch.ubique.studierendenausweis.31iq2"
            },
            "claims" : [
                {
                    "path" : ["ch.ubique.dev-ssi-schema-creator-ws.1", "firstName" ]
                }
            ]
        }
    ]
}
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
    }
    #[test]
    pub fn test_mdoc_value_queries() {
        let q = r#"
{
    "credentials" : [
        {
            "id" : "test",
            "format" : "mso_mdoc",
            "meta" : {
                "doctype_value" : "ch.ubique.studierendenausweis.31iq2"
            },
            "claims" : [
                {
                    "path" : ["ch.ubique.dev-ssi-schema-creator-ws.1", "firstName" ],
                    "values" : ["Martina"]
                }
            ]
        }
    ]
}
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
    }

    #[test]
    pub fn request_two_credentials() {
        let q = r#"
{
    "credentials" : [
        {
            "id" : "test",
            "format" : "dc+sd-jwt",
            "meta" : {
                "vct_values" : [
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4"
                    ]
            },
            "claims" : [
                {
                    "path" : ["firstName"]
                }
            ]
        },
        {
            "id" : "test2",
            "format" : "dc+sd-jwt",
            "meta" : {
                "vct_values" : [
                        "https://creator-ws.tg4u.ch/v1/schema/fuhrerausweis-snkre/0.0.1"
                    ]
            },
            "claims" : [
                {
                    "path" : ["lastName"]
                }
            ]
        }
    ]
}
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let result = credential_query.select_credentials_with_info(CREDENTIAL_STORE);
        let creds = result.set_options;
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(2, creds[0].set_options[0].len());
    }
    #[test]
    pub fn test_claims_set() {
        let q = r#"{
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4" ]
              },
              "claims": [
                {"id": "a", "path": ["lastName"]},
                {"id": "b", "path": ["firstName"]},
                {"id": "c", "path": ["matriculationNr"]},
                {"id": "d", "path": ["issuedBy"]},
                {"id": "e", "path": ["dateOfBirth"]},
                {"id" : "f", "path" : ["idontexist"]}
              ],
              "claim_sets": [
                ["f"],
               ["a", "b", "e"],
               ["a", "c", "d"]
              ]
            }
          ]
        }"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
        let disclosure = &creds[0].set_options[0][0].options[0];
        let Credential::SdJwtCredential(sdjwt) = &disclosure.credential else {
            panic!("")
        };
        assert_eq!(
            "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4",
            sdjwt
                .get_as_str(vec![PointerPart::String("vct".into())])
                .unwrap()
        );
        // we should NOT choose the one with dateOfBirth
        assert_eq!(
            vec!["a", "c", "d"],
            disclosure
                .claims_queries
                .iter()
                .map(|a| a.id().unwrap())
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn select_based_on_value() {
        let q = r#"{
          "credentials": [
            {
              "id": "my_credential",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4" ]
              },
              "claims": [
                  {
                    "path": ["lastName"],
                    "values": ["Mustermann"]
                  },
                  {"path": ["firstName"]},
                  {"path": ["render", "oca"]},
                  {
                    "path": ["schema_identifier", "version"],
                    "values": ["0.0.4", "0.0.3"]
                  },
                  {
                    "path": ["issuedBy"],
                    "values": ["Universität Musterstadt"]
                  }
              ]
            }
          ]
        }
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
        assert_eq!(1, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
        let q = r#"{
          "credentials": [
            {
              "id": "my_credential",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                  {
                    "path": ["lastName"],
                    "values": ["Mustermann"]
                  },
                  {"path": ["firstName"]},
                  {"path": ["render", "oca"]},
                  {
                    "path": ["schema_identifier", "version"],
                    "values": ["0.0.5", "0.0.3"]
                  },
                  {
                    "path": ["issuedBy"],
                    "values": ["Universität Musterstadt"]
                  }
              ]
            }
          ]
        }
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        dbg!(&creds);
        assert_eq!(0, creds.len());
    }

    #[test]
    pub fn test_bbs() {
        let q = r#"{
          "credentials": [
            {
              "id": "pid",
              "format": "bbs-termwise",
              "claims": [
                { "path": ["http://schema.org/name"]}
              ]
            }
          ]
        }"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let creds = credential_query.select_credentials(CREDENTIAL_STORE);
        assert_eq!(1, creds.len());
    }

    #[test]
    pub fn request_credential_sets() {
        let q = r#"
{
    "credentials" : [
        {
            "id" : "test",
            "format" : "dc+sd-jwt",
            "meta" : {
                "vct_values" : [
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/studierendenausweis-31iq2/0.0.4"
                    ]
            },
            "claims" : [
                {
                    "path" : ["firstName"]
                }
            ]
        },
        {
            "id" : "test2",
            "format" : "dc+sd-jwt",
            "meta" : {
                "vct_values" : [
                        "https://creator-ws.tg4u.ch/v1/schema/fuhrerausweis-snkre/0.0.1"
                    ]
            },
            "claims" : [
                {
                    "path" : ["lastName"]
                }
            ]
        }
    ],
    "credential_sets": [
        {
            "options": [
                [ "test" ],
                [ "test2" ]
            ]
        },
        {
            "options": [ [ "test" ] ]
        }
    ]
}
"#;
        let credential_query = serde_json::from_str::<DcqlQuery>(q).unwrap();
        let result = credential_query.select_credentials_with_info(CREDENTIAL_STORE);
        let creds = result.set_options;
        assert_eq!(2, creds.len());
        assert_eq!(2, creds[0].set_options.len());
        assert_eq!(1, creds[0].set_options[0].len());
        assert_eq!(1, creds[0].set_options[1].len());
        assert_eq!(1, creds[1].set_options.len());
    }
}

uniffi::setup_scaffolding!();
