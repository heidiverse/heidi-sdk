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

use crate::models::trusted_authority::{TrustedAuthorityMatcher, REGISTERED_MATCHERS};
use crate::models::{SetOption, TrustedAuthority};
#[cfg(feature = "bbs")]
use heidi_credentials_rust::bbs::BbsRust;
use heidi_credentials_rust::models::{Pointer, PointerPart};
use heidi_credentials_rust::sdjwt::SdJwtRust;
use heidi_credentials_rust::{claims_pointer::Selector, w3c::W3CSdJwt};
use heidi_credentials_rust::{mdoc::MdocRust, w3c::W3CVerifiableCredential};
use heidi_util_rust::value::Value;
use models::{
    ClaimsQuery, Credential, CredentialOptions, CredentialQuery, CredentialSetOption, DcqlQuery,
    Disclosure, Meta,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Supported SD-JWT formats. We have, for backwards compatibility included the vc+sd-jwt type used in some earlier drafts
const SDJWT_FORMATS: [&str; 2] = ["dc+sd-jwt", "vc+sd-jwt"];
/// The mdoc format type
const MDOC_FORMATS: [&str; 1] = ["mso_mdoc"];
/// W3C VCDM format type. Note: It overlaps with SD-JWT format type, so we need further heuristics (like @context or so)
const W3C_FORMATS: [&str; 1] = ["vc+sd-jwt"];
/// OpenBadges are just plain JSON-LD with linked data proofs
const OPEN_BADGE_FORMATS: [&str; 1] = ["ldp_vc"];

#[cfg(feature = "bbs")]
/// We use a bbs-termwise type format type
const BBS_FORMATS: [&str; 1] = ["bbs-termwise"];

#[derive(uniffi::Object)]
/// Allow ClaimsPath pointer manipulation/selection via this helper class
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

/// Information score is used to estimate the "data leakage". This is used for ordering
/// result sets.
pub trait InformationScore {
    fn score(&self) -> usize;
}
/// Dangerous properties are have a high information score, and are thus _deprioritized_ during selection
const DANGEROUS_PROPERTIES: [&str; 4] = ["birth", "date", "address", "street"];
/// Hiding properties try to mimick zero knowledge proof behavior and are thus _prioritized_
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

/// Simple trait for converting e.g. strings to actual credential types using parsers.
pub trait CredentialStore {
    fn get(&self) -> Vec<Credential>;
}

/// Provides a simple implementation using known parsers
impl<'a, T: AsRef<[&'a str]>> CredentialStore for T {
    fn get(&self) -> Vec<Credential> {
        self.as_ref()
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    }
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
/// If query matching fails for some reason we return a list of mismatches
/// to be able to improve informations to users.
///
/// Note: Generally most of the credentials won't match as one is expected to only have one credential of a specific type.
///       Thus, only show the mismatches if there actually is no matching credential
pub enum DcqlQueryMismatch {
    /// The referenced credential query is not found. Only used when credential sets are used
    CredentialQueryNotFound { id: String },
    /// If a credential does not satisfy the credential query, we return
    /// a struct explaining why it did not match
    UnsatisfiedCredentialQuery {
        /// Credential query that had no match
        query_id: String,
        /// The credential that failed to match this query
        credential: Credential,
        /// The reason, why this credential did not match the query
        reason: DcqlCredentialQueryMismatch,
    },
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
/// Data type explaining, why a credential did not match the requested credential query
pub enum DcqlCredentialQueryMismatch {
    /// VCT of the credential does not match the one from the query
    SdJwtMeta(SdJwtMetaMismatch),
    /// Doctype does not match the one from the query
    MdocMeta(MdocMetaMismatch),
    #[cfg(feature = "bbs")]
    /// Credential type does not match the one from the query
    BbsMeta(BbsMetaMismatch),
    /// Invalid W3C meta data
    W3CMeta(W3CMetaMismatch),
    /// Credential types does not match the one from the query
    LdpMeta(LdpMetaMismatch),

    /// This credential does not have a matching format
    ExpectedFormat(String),

    /// If credential sets are used, all credential queries need to have an id, otherwise it is invalid
    SomeCredentialQueriesDoNotHaveAnId,
    /// List of claim queries that did not match the requested claims from the credential query
    UnsatisfiedClaimQueries(Vec<DcqlClaimQueryMismatch>),
    /// The credential does not match the trusted authorities matcher (of which we have registered ones)
    UnstatisfiedTrustedAuthority(Vec<TrustedAuthority>),
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
pub enum LdpMetaMismatch {
    InvalidMeta,
    WrongCredentialTypes,
}

#[derive(Debug, Clone, uniffi::Enum, Serialize)]
/// Enum to explain why a claims query did not match
pub enum DcqlClaimQueryMismatch {
    /// The credential does not contain the specified claim
    ClaimQueryPath {
        id: Option<String>,
        path: Vec<PointerPart>,
    },
    /// The value of the claim does not match the one requested in the credential query
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
    /// Check all credentials for a match with this DCQL query. Returns all matching credentials
    /// (or sets), and all credentials that were not matching and why.
    pub fn select_credentials_with_info(
        &self,
        credential_store: impl CredentialStore,
    ) -> DcqlMatchResponse {
        // does the actual parsing of the credentials
        let credentials = credential_store.get();
        // lock the current trusted authorities
        let current_matchers: Vec<Arc<dyn TrustedAuthorityMatcher>> = REGISTERED_MATCHERS
            .lock()
            .map(|a| a.clone())
            .unwrap_or(vec![]);

        match (&self.credential_sets, &self.credentials) {
            // If we have credential sets, check all possible combinations
            (Some(sets), Some(queries)) => {
                let credential_query_map = queries
                    .iter()
                    .map(|a| (a.id.clone(), a))
                    .collect::<HashMap<_, _>>();

                let mut mismatches = Vec::<DcqlQueryMismatch>::new();
                let mut matching_sets = Vec::<CredentialSetOption>::new();

                // go over all sets...
                for set in sets {
                    let mut variations = Vec::<BTreeMap<String, CredentialOptions>>::new();
                    // ... check all options in the set
                    'outer_loop: for option in &set.options {
                        let mut possible_candidates: BTreeMap<String, CredentialOptions> =
                            BTreeMap::new();
                        // each option references a credential query
                        for id in option {
                            // if the credential query is not found, add it as a mismatch and continue
                            let Some(query) = credential_query_map.get(id) else {
                                mismatches.push(DcqlQueryMismatch::CredentialQueryNotFound {
                                    id: id.clone(),
                                });
                                continue 'outer_loop;
                            };

                            let mut matching_creds = Vec::<Disclosure>::new();
                            // check all credentials for matches (we want all, as the user might need to choose between matching credentials)
                            for cred in &credentials {
                                // if we have trusted authority matchers make sure we have at least one match
                                if let Some(trusted_authority) = query.trusted_authorities.as_ref()
                                {
                                    let mut has_match: bool = false;
                                    'authority_loop: for authority in trusted_authority {
                                        // check if we have a registered matcher for the specified type
                                        let matchers_for_type = current_matchers
                                            .iter()
                                            .filter(|a| {
                                                a.query_type() == authority.r#type.as_str().into()
                                            })
                                            .collect::<Vec<_>>();
                                        for matcher in matchers_for_type {
                                            if let Some(true) =
                                                matcher.matches(cred.clone(), authority.clone())
                                            {
                                                has_match = true;
                                                break 'authority_loop;
                                            }
                                        }
                                    }
                                    // if trusted authority is present in the query we reject it, if we don't have a matcher matching it
                                    // The specification only says _SHOULD_ (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-3.10)
                                    // as it is at the verifier's discretion to reject the credential if it does not match.
                                    if !has_match {
                                        mismatches.push(DcqlQueryMismatch::UnsatisfiedCredentialQuery { query_id: id.clone(), credential: cred.clone(), reason: DcqlCredentialQueryMismatch::UnstatisfiedTrustedAuthority(trusted_authority.clone())});
                                        continue;
                                    }
                                }
                                // check if the credential is satisfied
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
                            // if no credential matches, this set cannot be satisfied, and we have to skip it
                            if matching_creds.is_empty() {
                                continue 'outer_loop;
                            }
                            // add this set as a possible candidate
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
            // We don't have any credential sets, so treat all credential query as one big credential set
            (None, Some(queries)) => {
                let mut mismatches = Vec::<DcqlQueryMismatch>::new();
                let mut option = Vec::<SetOption>::new();

                for query in queries {
                    let mut matches = Vec::<Disclosure>::new();

                    for credential in &credentials {
                        if let Some(trusted_authority) = query.trusted_authorities.as_ref() {
                            let mut has_match: bool = false;
                            'authority_loop: for authority in trusted_authority {
                                let matchers_for_type = current_matchers
                                    .iter()
                                    .filter(|a| a.query_type() == authority.r#type.as_str().into())
                                    .collect::<Vec<_>>();
                                for matcher in matchers_for_type {
                                    if let Some(true) =
                                        matcher.matches(credential.clone(), authority.clone())
                                    {
                                        has_match = true;
                                        break 'authority_loop;
                                    }
                                }
                            }
                            if !has_match {
                                mismatches.push(DcqlQueryMismatch::UnsatisfiedCredentialQuery {
                                    query_id: query.id.clone(),
                                    credential: credential.clone(),
                                    reason:
                                        DcqlCredentialQueryMismatch::UnstatisfiedTrustedAuthority(
                                            trusted_authority.clone(),
                                        ),
                                });
                                continue;
                            }
                        }
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
                    //TODO: is this correct? shouldn't we add an empty element if we have no matches to indicate the lack of credential?
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

    /// If we don't care about the debugging features, we can just directly get all set options
    pub fn select_credentials(
        &self,
        credential_store: impl CredentialStore,
    ) -> Vec<CredentialSetOption> {
        self.select_credentials_with_info(credential_store)
            .set_options
    }
}

#[uniffi::export]
/// Returns requested attributes from a query for a specific credential
pub fn get_requested_attributes(
    credential_query: &CredentialQuery,
    credential: Credential,
) -> Value {
    let Ok(claims_queries) = credential.is_satisfied(credential_query) else {
        return Value::Null;
    };
    // all queries match
    // an empty claims query means a RP is requesting all claims
    if claims_queries.is_empty() {
        let mut key_value_match = HashMap::new();
        let Some(claims) = credential_query.claims.as_ref() else {
            return Value::Null;
        };
        for claim in claims {
            // generate a unified body payload type...
            let body = match &credential {
                Credential::SdJwtCredential(sdjwt) => sdjwt.claims.clone(),
                Credential::MdocCredential(mdoc) => mdoc.namespace_map.clone(),
                #[cfg(feature = "bbs")]
                Credential::BbsCredential(bbs) => bbs.body().clone(),
                Credential::W3CCredential(w3c) => w3c.json.clone(),
                Credential::OpenBadge303Credential(vc) => vc.clone().into_value(),
            };

            // ... and try resolve the pointers (as there is also slicing)
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
                // insert every attribute into the object
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
                Credential::OpenBadge303Credential(vc) => vc.clone().into_value(),
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
    /// Check if the credential matches the meta information from the query
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
    /// Check if the credential matches the meta information from the query
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
    /// Check if the credential matches the meta information from the query
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
    /// We don't match meta for W3C for now
    pub fn matches_meta_w3c(_w3c: &W3CSdJwt, _meta: Option<&Meta>) -> Result<(), W3CMetaMismatch> {
        Ok(())
    }
    /// Check if the credential matches the meta information from the query
    pub fn matches_meta_open_badges(
        vc: &W3CVerifiableCredential,
        meta: Option<&Meta>,
    ) -> Result<(), LdpMetaMismatch> {
        match meta {
            Some(Meta::LdpVc { type_values }) => {
                if type_values
                    .iter()
                    .any(|values| values.iter().all(|t| vc.types.contains(t)))
                {
                    return Ok(());
                } else {
                    return Err(LdpMetaMismatch::WrongCredentialTypes);
                }
            }
            None => Ok(()),
            _ => Err(LdpMetaMismatch::InvalidMeta),
        }
    }
    /// Returns the VCT for a sd jwt
    pub fn get_vct(sd_jwt: &SdJwtRust) -> &str {
        sd_jwt
            .claims
            .get("vct")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or("")
    }

    /// Checks if this credential does satisfy the given credential query
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
            Credential::OpenBadge303Credential(_)
                if !OPEN_BADGE_FORMATS.contains(&credential_query.format.as_str()) =>
            {
                return Err(expected_format_error)
            }
            _ => (),
        }
        // check for the meta attribute
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
            Credential::OpenBadge303Credential(vc) => {
                if let Err(e) = Self::matches_meta_open_badges(vc, credential_query.meta.as_ref()) {
                    return Err(DcqlCredentialQueryMismatch::LdpMeta(e));
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
    /// Checks if the claims query matches the given credential
    pub fn matches(&self, credential: &Credential) -> Result<(), DcqlClaimQueryMismatch> {
        // retrieve the data pointed to by the pointer
        // the claims pointer MUST point to one value exactly
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
            Credential::OpenBadge303Credential(c) => c.get(Arc::new(self.path.clone())),
        };

        let Some(data) = data else {
            return Err(DcqlClaimQueryMismatch::ClaimQueryPath {
                path: self.path.clone(),
                id: self.id.clone(),
            });
        };
        if data.is_empty() {
            return Err(DcqlClaimQueryMismatch::ClaimQueryPath {
                id: self.id.clone(),
                path: self.path.clone(),
            });
        }

        // check if data matches any of the values given in the claims query's value property
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
/// Select all credentials matching this DcqlQuery
pub fn select_credentials(query: DcqlQuery, credentials: Vec<String>) -> Vec<CredentialSetOption> {
    query
        .select_credentials(credentials.iter().map(String::as_str).collect::<Vec<_>>())
        .into_iter()
        .collect()
}

#[uniffi::export]
/// Select all credentials matching this DcqlQuery and also return all mismatches.
/// This allows to provide more detailed information to the user on why there was no match.
pub fn select_credentials_with_info(
    query: DcqlQuery,
    credentials: Vec<String>,
) -> DcqlMatchResponse {
    query.select_credentials_with_info(credentials.iter().map(String::as_str).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {

    use heidi_credentials_rust::{models::PointerPart, sdjwt::decode_sdjwt};

    use crate::{
        models::{Credential, DcqlQuery},
        select_credentials_with_info,
    };

    pub const CREDENTIAL_STORE :[&str;7] = [
    "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJsYXN0TmFtZSI6IlNvbWV0aGluZyIsIm1hdHJpY3VsYXRpb25OciI6IlNvbWV0aGluZyIsImlzc3VlZEJ5IjoiU29tZXRoaW5nIiwiZGF0ZU9mQmlydGgiOiJTb21ldGhpbmciLCJzY2hlbWFfaWRlbnRpZmllciI6eyJ2ZXJzaW9uIjoiMC4wLjQifSwidmN0IjoiaHR0cHM6Ly9kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLnViaXF1ZS5jaC92MS9zY2hlbWEvc3R1ZGllcmVuZGVuYXVzd2Vpcy0zMWlxMi8wLjAuNCIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJyNkgxcmQzeWtJWmRLcHRTVVlldk5MT29nT25mTlBqMDBtcVRsa2lXdDN3IiwieSI6InpJdk1USDcwbzBNZzUtQXBHVndVek1RZ1drS2xDeFZkelU2aUZkLVRfcjAiLCJkIjoiYmszcW9yRG5QMWtYdXNzZFZxdTlOc3pxOTBIcm04aG1zTUVPUE4tTEtKVSJ9fSwiX3NkIjpbIk5Ea3JOME9ZM1phVVRGSEpmLUtPa3dfWmU4Ui1WY2FLeS1QbnBLNFpTc00iXX0.gdRHTBGij5EWnylYvzWQrOMM_G3LGJ4madjpzk7xfYaied7IQhwo4XsB4UPiIrAYA0qVdlBD1yO5FM47_VU5gg~WyIyeW5VY0hEYUZhaTVHU1V4OHFsQ1cweWtHTTlOeThmTSIsImZpcnN0TmFtZSIsIlNvbWV0aGluZyJd~",
    "eyJ4NWMiOlsiTUlJQ3NqQ0NBbGVnQXdJQkFnSVVFdCtiNjdmRVJpWnV3MDFNbnl5N1lqU01rbk13Q2dZSUtvWkl6ajBFQXdJd2djWXhDekFKQmdOVkJBWVRBa1JGTVIwd0d3WURWUVFJREJSSFpXMWxhVzVrWlNCTmRYTjBaWEp6ZEdGa2RERVVNQklHQTFVRUJ3d0xUWFZ6ZEdWeWMzUmhaSFF4SFRBYkJnTlZCQW9NRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1Rc3dDUVlEVlFRTERBSkpWREVwTUNjR0ExVUVBd3dnYVhOemRXRnVZMlV1WjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXhLekFwQmdrcWhraUc5dzBCQ1FFV0hIUmxjM1JBWjJWdFpXbHVaR1V0YlhWemRHVnljM1JoWkhRdVpHVXdIaGNOTWpReE1USTJNVE15TlRVNFdoY05NalV4TVRJMk1UTXlOVFU0V2pDQnhqRUxNQWtHQTFVRUJoTUNSRVV4SFRBYkJnTlZCQWdNRkVkbGJXVnBibVJsSUUxMWMzUmxjbk4wWVdSME1SUXdFZ1lEVlFRSERBdE5kWE4wWlhKemRHRmtkREVkTUJzR0ExVUVDZ3dVUjJWdFpXbHVaR1VnVFhWemRHVnljM1JoWkhReEN6QUpCZ05WQkFzTUFrbFVNU2t3SndZRFZRUUREQ0JwYzNOMVlXNWpaUzVuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pURXJNQ2tHQ1NxR1NJYjNEUUVKQVJZY2RHVnpkRUJuWlcxbGFXNWtaUzF0ZFhOMFpYSnpkR0ZrZEM1a1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJEWVh0OE0rNUUxQURqNU4yUnYvekl3Qmx2a1RsdDNnc3NjcktQNG93ZzZrbTlFanY1YkhxRFdZK25RaTI5ZXpOSDJ0a2hHcktlMFpzbWVIOVpxVXNJK2pJVEFmTUIwR0ExVWREZ1FXQkJSU1cyQUdZajFkSjVOejg0L1hvakREakgwMFh6QUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF6YTE0WGF0eHJoOFBlYmhvS3dFd0hIYkhFZVA4NlNFNHBaaUh2VklhZlpRQ0lRRDJqcXN1U1FiZUtDdWk5NVJ3Q2txQWdXcnlad29LWE80VG1iK0x1NnlwWHc9PSJdLCJraWQiOiJNSUhsTUlITXBJSEpNSUhHTVFzd0NRWURWUVFHRXdKRVJURWRNQnNHQTFVRUNBd1VSMlZ0WldsdVpHVWdUWFZ6ZEdWeWMzUmhaSFF4RkRBU0JnTlZCQWNNQzAxMWMzUmxjbk4wWVdSME1SMHdHd1lEVlFRS0RCUkhaVzFsYVc1a1pTQk5kWE4wWlhKemRHRmtkREVMTUFrR0ExVUVDd3dDU1ZReEtUQW5CZ05WQkFNTUlHbHpjM1ZoYm1ObExtZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsTVNzd0tRWUpLb1pJaHZjTkFRa0JGaHgwWlhOMFFHZGxiV1ZwYm1SbExXMTFjM1JsY25OMFlXUjBMbVJsQWhRUzM1dnJ0OFJHSm03RFRVeWZMTHRpTkl5U2N3PT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiM1VDUmFnbFFnZ29BZEMtLU1iN1RnMTFBRUhMb3B0VjJmaDZ0b19MYXBZYyIsIjY3TWw4REh5OFJlYVZQVzRZbU9ielFhSXNpSEJoU181ODdjY0c0VVQzQ1EiLCJBVm5GZEptZTA5dFpoZkFPN2pPSzhpNzE3Uzl1UHBHd0xtVTRXSEk2MGwwIiwiWVNkamd4akdGTjdKTWg5UHl6Z2VFaGtTc0VQXzJrb1hEU2cxaUhPdFc1TSIsImJnTUg1Rkk3OHNCRmo2bTdFZm52Nm1OZDZVVjhCZXJ4bjlNVzR5X0lWUDQiLCJidHozcVNfTXE5eEI4bmVVaDRWeTRzRndGTmM1Y0RsUnQzUlBYaFc5elc0IiwiZW1KcllFN1I4bThTTkpRY3NldFpEVHViNVJlT05HYW1Ma2N5djBNMEZWMCIsInVEei1ZZG1KS2sxWExhYVR1MW91Nk5XNWlMcWJ0R1k0VWw2RTlNVXVNWVUiXSwidmN0IjoiaHR0cHM6Ly9kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLnViaXF1ZS5jaC92MS9zY2hlbWEvc3R1ZGllcmVuZGVuYXVzd2Vpcy0zMWlxMi8wLjAuNCIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9zcHJpbmQtZXVkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9kd2ppb28vYy9pVGRqbFlLRVowVWRnNHB0RWd0Ym5yIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InNHVVBwWFNuZUI2SWVtTTdZUklqbmxVQjZmZUtfbm1tQkN5LXh3ODBiSkEiLCJ5IjoiS1haNkp4Y3cxdUxKNTVDZnJBM0lPRWtGcTA1LXRlYVdjOGlCbHF3RWNSdyJ9fSwiZXhwIjoxNzM1NzI5ODM0LCJzY2hlbWFfaWRlbnRpZmllciI6eyJjcmVkZW50aWFsSWRlbnRpZmllciI6InN0dWRpZXJlbmRlbmF1c3dlaXMtMzFpcTIiLCJ2ZXJzaW9uIjoiMC4wLjQifSwiaWF0IjoxNzM0NTIwMjM0LCJyZW5kZXIiOnsidHlwZSI6Ik92ZXJsYXlzQ2FwdHVyZUJ1bmRsZVYxIiwib2NhIjoiaHR0cHM6Ly9zcHJpbmQtZXVkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9vY2EvSUFKU3l2M3V4R3NSOThxR0dMbnJFSFROMjBaNG9rU2dWMWw1cVFvQnczeUs3Lmpzb24ifX0.eWMps2qbyfpoKwmcF0rVQO4sRzFngKDavhnnUKaIOH0U4VqY2Eb6ELwM-eRmWPNs20B6gAPlSMMTCH05kZIR1A~WyJrZlBSVGF0TGMyVGE0VGdCb1JJQTZ3IiwiZmlyc3ROYW1lIiwiTWFydGluYSJd~WyJDNFRLTWR3U2Y5b2V5UlhtSmU0cld3IiwibGFzdE5hbWUiLCJNdXN0ZXJtYW5uIl0~WyJjVzd3MmlsdEtoOGlMS1l6UFhwX1FnIiwibWF0cmljdWxhdGlvbk5yIiwiMDEvNzY1NDMyMSJd~WyJ6RzR6cWsxa25oN1MtNkhZLVp6ME93IiwiaXNzdWVkQnkiLCJVbml2ZXJzaXTDpHQgTXVzdGVyc3RhZHQiXQ~WyJ2SDVCRFYzTll0R1VnRkVDZFRiMmhRIiwidmFsaWRVbnRpbCIsIjIwMjUxMjE4Il0~WyJfNU4tS2hJUzItOExQVXR0UkJZcjB3IiwiZGF0ZU9mQmlydGgiLCIyMDAxMDgxMiJd~WyJUV05ZZzY1MUZCc2RhY2V2UngyY2NBIiwiYmFkZ2VOciIsIjEyMzQ1Njc4OSJd~WyJ2NnRiWFRacXBKckc5QjBkQy0tMVpnIiwiaXNzdWVkT24iLCIyMDI0MTIxOCJd~",
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
        println!("{:?}", creds[0].set_options[0][0]);
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
                    "values": ["Something"]
                  },
                  {"path": ["firstName"]},
                  {
                    "path": ["schema_identifier", "version"],
                    "values": ["0.0.4", "0.0.3"]
                  },
                  {
                    "path": ["issuedBy"],
                    "values": ["Something"]
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
    #[test]
    fn test_null_value() {
        let sdjwt_str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVmOGFmYzM2YmIxMTY0MWE0ZWFkZjA0YTg0MTU4ZTljIn0.eyJfc2QiOlsiNzdiTmFycXc2cGZ6Zk5YOXQ0MC1FMC03ZDVTRDdadjFja01ZUXRRc0xnMCIsIm5wS09ZZ3ZMUmEwU29KYTUwVzY4eTVVeEVqZXd4SkVsWEtBeVduck05SEUiLCI4aUJZSmp0Y0VldWhnYWZzcjhQaWJuZ1hJcGh2X3Q4M0VMT1lKMFhZWUdBIiwiOWxDaHpmVGsxTkFtLTk4TlFld1JDOFdLMVhYS3lnUkxpTDhtNm5Rcml2WSIsIkFMMmFTV2lHbWFDaUliSWZoSzNmcGJMRGNQYWZtVXdfY050NkQyclFoU3MiLCJDcTVCeWU3cXQxYkVPUXhsTVZ0NG9rWnlYSlVhYnRqMDBQXzdBcUhhcVlFIiwiSUVsYUNKN0RtSFJMYzc1SHBPS056WXRwSHZWYWQ3SkpfbDJnZGg3T1h2RSIsImVkR09IQXpjeWxrVlVxWDBSLU1RU21SMEQzeEZ0Z04xSUJtXzRmSWtWNGMiLCJnNFljNGNCekVMUDV2UFEzUVBJLUhPS3pjakJCQncyZ2hySm5kQUtlMVlRIiwib1Y1VUw5ejZlcUhCWTE0bzVudmVBOFhZcWc1Mk5xSklLSk43aXVYRm9UcyIsIndBYTZpb0xaYkdpOG13dldSbXowdzYxODlRYkk2NG0yREF3c19fSjlrY1kiLCJ4SFBFM2ZQWUNxTkN6UDVaZ0dVeU14WVlUQ1VYSjJuLWNwcV80YXh2OHV3IiwieTlNaVZtRjdhNXBLXy0xWllCT3N6cmJvd0RIRjZSeFlVejhfTDlBMDVvbyIsIkVrX19WeXp1Sm5ST3hNWHJtRU1YcWJQbUlVQ01RN1BlYkwycHRvQWxWM2MiLCJuT2pmZ01MdWRCSXlmRjk1MmhrQUQxdksxclN0a1BRSFZQNjlRY2RrU1VzIiwiYm50N0xib1piaUJtTzdSYlY1Vm5wTHdLaFdxS0FkRnF4bkR6R09PNVQtZyJdLCJuYmYiOjE3MTEyMzg0MDAsInZjdCI6ImNoYXNzZXJhbC12YyIsInZjdF9tZXRhZGF0YV91cmkiOiJodHRwczovL2V4YW1wbGUuY29tIiwidmN0X21ldGFkYXRhX3VyaSNpbnRlZ3JpdHkiOiJpbnRlZ3JpdHkiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDp0ZHc6UW1YdGVIMVV0aUVSRGpZU1lkNHhxRzhRRUJud2txdzdQOUdIdjZKUTl4cWZOSzppZGVudGlmaWVyLXJlZy1yLnRydXN0LWluZnJhLnN3aXl1LmFkbWluLmNoOmFwaTp2MTpkaWQ6YjZhY2ExYTUtOGQ3MS00Y2ZjLWFkNTAtN2Y3MzMxNDM5OWI3IiwiY25mIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiX19tdUJ5djJEQ1pfdy1zSDZicDlta0pTX3NzcHAzSU5fdUt4NmFwM3hhQSIsInkiOiJhMUhwTGxJLVRNTjdRc0szT1FZeElVb2VTYmh3ZFdfdlJvS2FjUXZoM2xNIiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiX19tdUJ5djJEQ1pfdy1zSDZicDlta0pTX3NzcHAzSU5fdUt4NmFwM3hhQSIsInkiOiJhMUhwTGxJLVRNTjdRc0szT1FZeElVb2VTYmh3ZFdfdlJvS2FjUXZoM2xNIn19LCJleHAiOjE3OTgyNDMyMDAsImlhdCI6MTc3NTY5MjgwMCwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7InVyaSI6Imh0dHBzOi8vc3RhdHVzLXJlZy1yLnRydXN0LWluZnJhLnN3aXl1LmFkbWluLmNoL2FwaS92MS9zdGF0dXNsaXN0L2FlMzdjMTRhLWI0NDUtNDUwOS1iOTMwLTM5NjgwMDRmNWMyNS5qd3QiLCJpZHgiOjE3NjkzfX19.Oq8Dz5urIIqxi2KolL_61aBHa3G5D71WaHAq1KIS7m-ciJdsfbtXjqmM-x0s0MhE6wo9bW71LFYjTLP0DG_RPw~WyIxY2MwNjU1N2YwMzU5N2U1Iiwic3RyaW5nIiwiU3RyaW5nIGNsYWltIl0~WyIzYzEzYzFiZmYzMGFiMjUzIiwiaW50IiwxMDAwMDAwXQ~WyI2Nzc5M2I3MjczNzFkNmRmIiwiZG91YmxlIiwxMDAwLjExMV0~WyJhOGY3OWE0ZDFmOGZkN2UzIiwiYm9vbGVhbiIsdHJ1ZV0~WyJlZGEzMTFlNzkzOWUzOWM4IiwibnVsbCIsbnVsbF0~WyI2ZGY1MTQwMTk3ODA4ODQxIiwiZW1wdHkiLCIiXQ~WyJhOWYxNmYwZmQ5NjkwNDhmIiwiZGF0ZSIsIjIwMjUtMDEtMDIiXQ~WyJlNWI2YWQ4MDZmODg2YjQxIiwiZGF0ZV90aW1lIiwiMjAyNS0wMS0wMiwgMTA6MDE6MDIuMTIzIl0~WyJhN2M1NTdlMGM0NzEyZjI3IiwiZGF0ZV90aW1lX3pvbmUiLCIyMDI1LTAxLTAyLCAxMDowMTowMyswMTowMCJd~WyJhNTk5ZGY2ODNmZmU1YzcxIiwidGltZSIsIjA5OjAxOjA0Il0~WyIxZGRkYWU2YmQ2YzQxMjc5IiwiaW1hZ2VfZGF0YV91cmxfanBnIiwiZGF0YTppbWFnZS9qcGVnO2Jhc2U2NCwvOWovNEFBUVNrWkpSZ0FCQVFFQVlBQmdBQUQvNFFBaVJYaHBaZ0FBVFUwQUtnQUFBQWdBQVFFU0FBTUFBQUFCQUFFQUFBQUFBQUQvMndCREFBMEpDZ3dLQ0EwTUN3d1BEZzBRRkNJV0ZCSVNGQ2tkSHhnaU1Tc3pNakFyTHk0MlBFMUNOamxKT2k0dlExeEVTVkJTVjFkWE5FRmZabDVVWlUxVlYxUC8yd0JEQVE0UER4UVNGQ2NXRmlkVE55ODNVMU5UVTFOVFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFQL3dBQVJDQUdBQVFBREFTSUFBaEVCQXhFQi84UUFId0FBQVFVQkFRRUJBUUVBQUFBQUFBQUFBQUVDQXdRRkJnY0lDUW9MLzhRQXRSQUFBZ0VEQXdJRUF3VUZCQVFBQUFGOUFRSURBQVFSQlJJaE1VRUdFMUZoQnlKeEZES0JrYUVJSTBLeHdSVlMwZkFrTTJKeWdna0tGaGNZR1JvbEppY29LU28wTlRZM09EazZRMFJGUmtkSVNVcFRWRlZXVjFoWldtTmtaV1puYUdscWMzUjFkbmQ0ZVhxRGhJV0doNGlKaXBLVGxKV1dsNWlabXFLanBLV21wNmlwcXJLenRMVzJ0N2k1dXNMRHhNWEd4OGpKeXRMVDFOWFcxOWpaMnVIaTQrVGw1dWZvNmVyeDh2UDA5ZmIzK1BuNi84UUFId0VBQXdFQkFRRUJBUUVCQVFBQUFBQUFBQUVDQXdRRkJnY0lDUW9MLzhRQXRSRUFBZ0VDQkFRREJBY0ZCQVFBQVFKM0FBRUNBeEVFQlNFeEJoSkJVUWRoY1JNaU1vRUlGRUtSb2JIQkNTTXpVdkFWWW5MUkNoWWtOT0VsOFJjWUdSb21KeWdwS2pVMk56ZzVPa05FUlVaSFNFbEtVMVJWVmxkWVdWcGpaR1ZtWjJocGFuTjBkWFozZUhsNmdvT0VoWWFIaUltS2twT1VsWmFYbUptYW9xT2twYWFucUttcXNyTzB0YmEzdUxtNndzUEV4Y2JIeU1uSzB0UFUxZGJYMk5uYTR1UGs1ZWJuNk9ucTh2UDA5ZmIzK1BuNi85b0FEQU1CQUFJUkF4RUFQd0RwTVVZcGFYRlNBbUtkaWtwUlRBTzlMUlMwQUZMUlJRQVV0RkxRQWxGTFJRQVVVZDZYRkFDVVV0RkFDVW9vb29BS1dpaWdBeFJTMEdnQktXaWlnQW9vb29BS01VdEhlZ0JLS0tLQUNpaWlnQ3RpbG94UzRvQUtNVVV0QUJTNG9wYUFERkZMUlFBQ2lsb29BS0tPMUZBQlJTMFlvQVNsb29vQUtLS1dnQktXaWlnQW9vcGFBRXBhS0tBQ2lpaWdBb29wYUFFb3BhS0FFbzdVdEpRQlhwUlJTMEFKU2lpbG9BQlMwVXZlZ0JLV2lsRkFDVXRGRkFDVXRGRkFCUlVNOTNCYkp1bm1qakhxekFWa1hmaXZUYmRTSXBETzQvaFFIK1pwQWJ0RmNqL3dtaHlTYlFBZGdaT2Y1VTF2RzJWd0xWVmIxTW1SL0tpNDdNN0NscmpZL0djZ2I5NWFveS83RFlOYXRsNHEwKzV3SkdhQnU0Y2NEOFJSZEJZM2FXbzQ1bzVVM1JTSzYrcW5JcVNtSUtLS1dnQktLV2lnQXBLV2lnQW9vb29BS0tXaWdCS0tXaWdDdlFLS1dnQXBhU2xvQVdpaWlnQmFLS0tBQ2lpcWVwYWpCcHRxMDl3MkFPZzdrK2dvQXRPNnhvV1pncWdaSk5jZHJQalZZWm1oc1FweHdaR0dmeUZZZXQrSmJ2VWl5QmpEQWVrYS93QlRXQmtqN296N21wdVZZdlhlcHZlekdXY3lTTWU3ZjRDcTVjazVBSDU0cUJWTEhuYVBwUTBEamxjbjhLTERMQU01N0FqOERUZ0gvaWpIMXdNVlhpODBIN24rRlQrYXc2amFmWW4rbEFEMUJSdUJnZWdQOUtrTE1QbUMvV29DKzRZQnlmUTBMSTQ0eitkSURSdEw2VzJJa3Q1bVJoMUFQTmRKcFBqRVpFVitNai9ub281SDFGY09XMnZ1QXdhQ3drK1ljTVBTZ0dqMmEzdVlybUpaSVhWMFlaQkI2MU5YazJqYTdkYVZPR1FsMEorWk94RmVqNlBxOXZxdHY1a1J3UndWSjVGVW1TMGFWQW9IU2ltSUtLV2lnQTdVVWQ2S0FDaWlsb0FTaWpGTFRBcjB0SlMwZ0NscEtXZ0FwYVNpZ0JhS0tDYUFJTHk2aXM3WjVwM1ZFVVpKSnJ5dlhOYWsxSzhhVm1KakJ4R3A2QWZTdGZ4M3FqVDM0czBQN3FJWmJucWE0eDg5cVc0MFNGaXh6M29MSE5XckN4a253NUIyMXBSNlF4SUFHZmMxRGtrYUtEWmpMdkk0elUwWWxIVWsvalhUUWFLdVBtR2F1TG9tUjhvVUQvZHpVKzBSZnNtY3NpZVlPVllrZjdWU3BDNWJHMGxmZnJYV1JhQ25HZXZxYXVSYVFGd3B4ajFBbzV4K3pPTmpzcEhPTnBJOXhWdUhTREpuUEdQYXUwajB5QkI5MnAwdElremhBS2x5S1VFY1gvWU85UU1jMW5YK2d6MjRMeGdrRHVLOUhhQlQyR2FobWdWbDJrWnpTNW1odUNaNUxKSXl0aVFmTU8vUTFOYTMwbHZLcnh5c2pDdWw4UmFCdzA4S0RBNUlGY2o1T3hza1lBUGV0WXRNd2xGcG5wL2hyeEdsL0VJcmxsU1lEZzR3R3JwUWE4WHNybVcxbVdXSTdYVS9uWHFYaHpWRjFQVGxjcnRrWDVXSGJQdFZwbWJScjBVVVV4QlJTOTZLQUNpaWltQVVVVVVBVjZXa3BhUUJTMGxMUUFVdEpTMEFGVU5hdmhwMm1UWEhHVlg1Yzl6MnEvWEtlUDVTbWpvZ09OemlrQjUzYzNFbHpQSkpJeFpuTzVpZTVxV3d0VGRUaGNmS090VlFPZzlhNkxRNFFrZS91YWlUc2pTQ3V6WXRiUkk0MVVEQUZYNG9seDBwa0lCQXF6SDFybWJPdEltaWlBN1ZhUk1WSEZqRldFNW9ReHlxTTFNQnhVYWptcGdQbDRxa0pnQnhTNDlxZUtjQUtxeE55RWlvMjZWWlpSVUxERkpvYVpXbWpFaUVNT0RYbmZpUFRUWjM1SS8xYjV4N1Y2UzNTdWY4VVdZdU5QWndQbVRtaUxzeVpxNk9EZFBMMkg4RFhWK0FyMTExQ1Myem1PUmM0ejBJcm1aQVd0L2RSeitGWC9DMDVpMTIyWWQyMm10em1aNndLS1FkS1dySUNsb29vQUtLS0tZQlJSUlFCWHBhU2xwQUZMU1VVQUxSUlJRQVZ5SHhDVUhUb005Zk00SDRWMTljcjQrUkRwVWJzVHVEZ0tLVEdqemhCbDY2alNRUHMrSzVsT0NEWFRhVi9xQVQzcktwc2EwOXphdFd5TWQ2dXFPYW9XL0J5SzBZK1Iwcm5PcEZpT3JDRVZYakJxZEJ4aW1nSjF4VXZ0VUtkS2VUVm9sa29QTlBxQU5Ud1RUdUt3OG1vMjVwMmFhZWFUQkViRGlxVjdFSmJhUkNPQ0RWNXFyVDhSTjlLa2IyUE5iaUl3U1NyMnpVbWdMdDFTMklKVWlRY2daeHpVK29ZTjFKa1pxWFFvMUdyMnlnZnhWMExZNVdlbmpvS2NLYUJTaXRETVdpaWltQVVvcEtXZ0FOSlIyb29BcjB0SlJTQVdpa29vQVdpaWlnQXJuZkhFUmswTXNQNEhCcm9xeVBGUDhBeUw5MXhuNWY2MGdQTEZYZEtxanZYVDJrZmxRcVBTdWVzRjNhaEVQZXVtWTRGWXpPaUJjdFRrak5ha1hTdVlmVWhBZHFkZldrL3RxU05lRGsrOVpxSnJ6STdCY0RwVXNianVhNGhQRkVxbkhsNS9HdEt4OFFlZnhLbTJxNWJBcHBuV293cFhOWmR0ZWh4a0dyd2szTFNLc1RyeDFxUlNLb1NYUWpITlpsenJ4dDJKMmpiK3RVaVdkSmtVMWlPbGNlZkY1RFlhRWozcWFMeENaaGtZUDlLYlJOenBXTlFTREtrZGlLemJYVmxlVHk1U0ZidDcxcFozRE5adFdLT0MxZUpyYlZIamJvZVJVK2dEZnJOcHhuNXF0ZUw0d3M5dEtCeVFRVFRQQ0tidGFpejJCUDZWdEhZNTU3bm9ZcFJTVXRhbVF0RkhlaW1BVVV0SlFBdEZKUlFCV29wS1drQXRGSlJRQXZlaWs3MHVhQUZybmZFV3JLc1U5bXNJbEJVcXgzWXg5SzZHdlBOUll2NGhtT2VHTForbk5aMUpOTFEycFFVbTdtTHBhbHRTWDJCTmJkdysxRFZHMGlFZXJ6RWRBbVIrT0t2U3B2QnJPVDFMaXJhR2REQ0M1ZDhZSE5hU1hWcERIdWVOU3Y5NThBSDg2eTdzdmdJbnJVZzB2N1ZadGw5MC9YTEg5S2ExSHNXbXZyQzRHSXhiQnVtQ1NQMXhVRHI1YkRNZmxuc1FjZy9qVHRGMG01RTZ4emZ1N2RaUkl4ZGNkUFN0bStzVlNZdGFvWGhjOHhrWUErbEVrbHNFVzI3TkZUUzdwdk1DWjVycmJaQzBlZmF1S3Q0L0wxTWJNN2MxM2RnUjVJQjlLejZtdlF6TDVEazlxd3JueVZQemt0NkFEclhUM3NCbkpVSEFyblo3UDkvamVFUU50WS93QVZDRGNyUlRXcUVlWmFxdnB2S2orWnErald4QWJ5UWkvM3hnZ2ZpSzVuV2ROZURWUE1SQThPNEVBNXd3OU0xcWFWcFZ4SFpUWFNPYmVSbkxScDJLK2hCN1ZyeTZibVBOcmF4cFMycWNPaEJ5ZURXdll1VEVGUGIwckgwMlNSNUNzcUttZXFqcG4xSHNhM2JlTFl2MXJKczB0WXcvRjYvd0NqVzdZNk1mNVZINE9RcGN5VCtXV1VMdEJxMzRvamFXemhSUmxqS0FQeEJyWFMzRnBwM2xXdzJtTk1ic2Q4VlhOWmFFY3FsTFUxb3BCSW00Zi9BS3FlS3k5QmVWN0JXbU81eU01OWEweFc4SmMwYm1GU1BKSnhIVVVVVlpBVVVVVUFIYWlqdlJRQlZwS0tUTklCMUpTVVVBT29wdWFXZ0IxY0JmUitYcTEwemZ3a3FQenJ2cTQ3eE5BWTcrVmwvalVQL1QrbFpWVm9iMEhxMFl0b1I5dWx3Yy9JUDUxcXdvR0hTc1BUbXpkdm5xVnJldFNNMWxMWTFXNURjV2c2Z2RhV0NKc0FOR0dyWFNJT09jWXFRV2dIM2VsU21YWXFRUnNCd29VZTlQbkpTSTg4a2NWY0VJWHFhbzM1eXB4VHVPeG1XeWdYZ1BVNXJyclE0ano3VnlkbXBlNUdPZ05kWGJuRU9POUhVT2c5dm01ck12N1o5MjRad2ExQWMwL0NzdUdHUlFJNStPSjFQS3RqMVU0cTJzQ3lZM0s1OWllSzBUYUx5VjQ5cWxqajRwNmcyVTRyUk9Qa0F4MHEwRnd0U0JNQ212d0RVV0VZMnRTQ0pMZVJzWVdkU2ExWUo0NXJZS2piZ1IxeGlzM1ZJaE9rVVJHZDBneCt0V05PUW9BbnBWQkZkVFMwK01SVzZJUDRWQXEzVU5zTVIxTFhUQldpamxxdTgyeFJTMGxMVm1ZVWxGRkFDMGQ2U2lnUlRvcE0wWnBERnpSbWt6Um1nQmMwdWFibWpOQUQ4MXp2aXFNaG9KUU1nZ3EzMHJvTTFRMXVNUzZhNUl5VklJL2xVVFY0bWxOMmtqZ3hiRzAxRWZOa1BtdGVBNDVyTjFINVpJWDlHeFdqYkVNZ05ZUFk2UHRHbmJ1U2VhMFl6eFdWYW41cTBvMjRxRFZEMzVHS3hkWWs4dE1MeVNjQ3RhWjlxNUZjenFWeGk4VXVmbEZVZ1plMG1MQnlldGRIQkhsZUs0cXcxaU5ic29NNDZaUFExMWxycUtwSGtFY2luYlhVbSttaFprQlE4Vk5DNGRRYXhXMTJCcnp5SERnbm9TdUFmeHJSaTVUZXZRODBoN2w4ZGFXcTBVM1kxUHVCcHBpYXNESHRVTWh5RFVoTlF5ZEQ2VW1KbVpkeTdiNjBYL2J6Z1ZmaFIxbFozRzBuN29yTkNlYjRodGZSTWsva2EzMlVOSUNPOU8xN0NqS3laTkVNUnFLZUtRZGFYdlhVdERpYnU3aFMwbEZNQmFLTzFKUUlXaWlqTkFGRE5HYVROSlNHT3pSbW0wVUFPenpTMHpOTG1nQndOSTZySWpJd0JWaGdnMFpvQm9BNVR4SG9pd1dVbHpGS2RrWkIyRWUrT3RVTk5rM1JnWnJyZGFoKzBhVGN4QVpKUTRIdjJyZ3JPYnlrQXpnazFsT0t0b2JRazI5VHBJVGh1dGFFWk8zcldQYlNobFU1NjFjbXUvczlxejlTT2dyQm82VTlDZTZuV05UdVlmU3VXMWE1UmxZcU0rOUxQZHZJVzNOeVRWQ1JIbUErVTR6M3E0eDdtY3B0N0ZPT1FoOEVEbXVnczc2T08zeklTem5nQW5wV2JGcDBqeWdZNU5UblRybEpWUVJOeWNrOXZ6cTNaa3JtUnF3WHdlZGZNalE3ZTVHY2U5ZFRiM1VjaTQzRElyanZzY3NZeXlic2p0U3BKS2pncWR1QmtWTHN5bEpyYzdGOGJzbzJhbWliSXJrSXRZWlNDNXdjOCs5ZEhwdDJMbFR4MEdSN2lvYXNXcFhMNVBOUVhVZ2pqelVqUHQrbFpkL2NaUWdqanQ3MElsc2kwMW1mV0E2b1h3alp4MjZWMHNTTm5jL0hvUFNzTHd3aGFXNW13Y0RDcWZ6TmRGWFJHQzNNSlRld1VVVWQ2ME1oYUtNMFVDRG9hS0tXZ0FvN1VVQ2dETnpSbW01b3pTR096Um1tNW9wQU96Um1tNXBhQUhab0ZOQnBjMEFLZVZJTmVkWHR2OWwxSzRnSTRWemo2ZFJYb3VhNVh4aFo3Zkx2a0hRN0h4K2hwU1YwVkYyWmh4WEpqSXdUMXhXdk9FdWRQT0RsaU9LNS9lTUE5ODRyWXQ1QU5QeGpKN1ZoSkc4V1UxMHhyaVBlak1xamo2MUUxbmV3ajc0ZFBwelhRMk1pK1J0d0FLWmRmdW1MQVpVMHVaM0xpbHVaRUVNOHE4UEdUNzVGWFlZNzBMNVRSS3c3RVNjVTBYZHNyYm1UYTNXckNhckIwMjkrOVA1R3luRHVLSUxsUU1tTkNld1lrMDQ2UmQzQ2tOSUVCNzdlYXZXbDdidU1wSGx2enJXaGJmMUdLVFlwU1RPTHZkQm10U0hFaGRlNUlyZThQeFBiMnY3dy9NUmtmU3IycWMycm9nK2ZGVUhrRU52RTBaSjJyMDlxTldZNkpsbTR1Uzd1Z0pBOWF6cm1UYkVTeDU5VDM2VWswd1VPbzVQWFArZnJTNmZCL2FXcXJFTW1HRTVmbjlLcUt1eVpPeU9rMFMzTnZwc1FZWWR4dmI4YTBNMDNvTUNscnBPWVdqdlJtanZRSVdpa3BhQUZvcEtPMUFDMHRKUzBBWlJvelNVVkl4YVNpaWdCYzBkNmJTMEFPelM1cHRGQUQ2Z3ZvVnVMR2VKd0NHUWo5S2x6VmZVTHhMTzEzdHl6c0VSZjd6SGdDZ0R6T1lOYno3SDZBOGU5V3Z0REJBZDNIYXJXcFdnbHlEd3luZzFpczdSRW8vRER2V1M5NDJlaHZXdDRBcThoYTJZWkVuakhtWXdlbGNiYnl0dkdEVzVIZDdMWVk1NTY5elNsRXFNalJ1dE5pYm9CbkZWUnBCRWdEREFacW10Ym96RUdSdS8zUlZzM1c0Z0UvTG5PUFNwU3NYZE12YWZZdzJpbkpHZSthdlBNaVlCNHlPUGVzaWE1SW1aVklZWTVIOWFyM056bmdQZ2c1eDZVV3VGN0Uyb1hnZGlWZkhPM3JVQW1CdHM1QlpXNXJJdXJqRHNnK2N0em4xcXUxK1ZnS2o3N0hQSGVxNVNPWXVUWEJsa0VOdUN6c2RvOWM1cnN0QXNsc2JWa0gzMndYUHFhNS93enBUSWZ0TndENWg2QS93QU5kRGZYbjltMktYaEdZUk9FbDlsSTYvZ2NWVU5aV1JNL2h1elU3VUE4VTFHVjFES1FWWVpCSGNVNGNWc1lDMHRON1V0QUMwb3B0TFFBdmVpa0ZMUUF0QXBLV2dESXpSU1VacVJqcUtUTkptZ0IxS0tibWlnQjFHYVNxTi9xOWxwNC93QkluVVAvQUhGNVkvaFRBdlBJa2NiUEl3VkZHU3hPQUs0NlhWVjFqeGRaeFJFbTF0eXpML3RNQWVmNVZsNjc0aG0xU1R5MHpGYktlRXp5M3VhaDhKSC9BSXFDTW4rNDM4cWRySU56ZjFLTGJkU3I3NUZZZDNhQ1VaSDN2V3V1MXEzUGxMY3FNaGVIK25yV0hKRmtaRmNyOTFuU3ZlUnphN29ud3cya0dyc2R5R1REZFA1VmJtdGxreUhISHJXZk5aUEdjcDh3OXV0YXBwbWJUUm9RM0FHQUd4VWh1c1Nxd2JranZXTXBJSkJiQnFSVmx5Q0dVZmpSWUxuUVNYeWtod2NOam1xTTkrQkt1RHV4MS9DczQ3MUp5K1Q2Q3BiZlRwN2c1UkR0L3ZOd0tWa2diYkd0TThzb0lCSjZBQ3QvUTlGWXlMUGNMODNWVjdEL0FPdlZqU3RGanRpck1ESko2bnRYVFdrQVVEZ2NWTXBkaW94N2tzRVFqaUF4aXBOWnRCTjRVdW9tSExSczQrbzVIOGhVcUo1azBjUzlXUFBzTzVxMXJKQ2FaY2pzc0wvK2dtcm9yVzVOVjZXT0g4TGVJa2hnU3l2VzJxcHhISWVnSG9hN01ISTRQRmVPQnNjZXRkSDRlOFR2cDRGdmQ3cGJiK0VqbGsvK3RYVEtQWTUwejBITkZVckhWTEsvR2JXNFJ6L2R6aGgrRlhhektGcGFiU21nQmFXa283MEFMUzBsQnBnWTlMU1VWQlFVdFVyelZMS3hCKzBYQ3EzOTBjbjhxNSsrOFpBWld5Zy80SEovZ0thVFlybldNeW9wWnlGVWRTVGdDc1RVZkZWaGFaV0ltNGtIWlB1L25YRTMycTNsKzJiaWRtSFpjNEEvQ3FSTlVvaXViT3BlSjlRdmNxc25rUm4rR1BqOWV0WXpPU1NTU1NlcE5OSHJRYVloYzFvZUhKUEsxNjJKNk1TdjVnMW0xTlp5ZVRld1NmM0pGUDYwbU5Icmx1aXpSdEc0QlZoZ2cxelY3Wk5ZM2JRTmtwMVErb3JvckovdW1yT3FhZUwrenlvL2VweXByR1VlWkdzWmNyT0xlQUhtb3pDQ1FEd2ExVWh5Q0NNRWNFVTFyVTlRS3dUT2hvemY3UGprNnFDZmNVbzBXTEdSR0Q5SzBWUmtZWkg0MXAyNFVwZ25uOHFkMlRZeDdiUjBWZ1JHT0swb3JVSmdBWngyRmFDUmc5TUNwbzRsWG9PYUFJTGFEQnlSZ0NyanVrRVJaaUZVREpKb0xCRnllS3FXMGJhdHFLeGY4dTBSM1NmN1I3Q2hLN3NHeXViT2l3dDVMWGN3SWVYN29QOEFDdllmMXFqNHR1UkJvRjgrZXNld2Y4QzQvclcrK0VUQTZBVnd2eER1dG1td1FEckxMay9RRC9FaXUyRWJhSEpOMzFQUG5vemtVajBnTmFtUTVaR1JneU1WWWRDRGl0N1RmRitvV2VGbFlYTVk3U2RmenJuelREeFNhR2owN1RmRmVuWHVFa2MyMGg3U2RQenJlVmd5QmxJSVBRZzE0bUdyUjAvV2IzVDJ6YlhEb1A3dWNxZndxT1VxNTY1bnBTMXhlbStPRk9FdjdmOEE3YVJmNEd1b3NkVXN0UUdiVzRSei9kemh2eXFXbWgzTHRGSlMwRE9FdmZGdHRGa1cwYlROL2ViNVIvalhQWDNpTy91OGp6dktRL3d4L0wvOWVzZ2swbFVvb200ck9XT1NjbW0wdUtNVlFodEpUalRRd0RjOFVoaTR3S1NuRWdqaW05S0dBaDRwT25JN1VkNmNCa1ZJejFiVFgzUVJ0NnFEWFJXWnlsY3BvVDc5TXRHOVlsL2xYUnhYQ1c4UVo4ODlGSFUxQ0xaVTFmVHZMa056RU9EOThEK2RaNnhocTIyMUIzQkRSSVVQYXFiMlJKMzIvd0F5SG5iM0grTlpWSWEzUnRUbnBabEkyNFBVVkpIQnRPYW1YUGVuY2crMVkyTlJ5S0IycHpPRkhYRlJzMktxVHpNVHRUTE1UZ0FkNm9RMjZta21jUXhETHR3SzZmU0xGYkd6VkJ5eDVZK3ByRmlqWFRVV1JsRXR3M0xaNkQyRmJOaHFjVjZwVWZKS0J5aC9wVzlPTnR6Q3BLK2lMRTdZVTE1cDhRWnQrcDIwR2Y4QVZ4YnZ6UDhBOWF2UjVmbWJGZVQrTUp2TzhUWGVEa0lRZy9BRCt0YnhNSkdHM0ZOUEJwN1V3aXJJQ210MHB3cGhjZEY1b0dOcFFhU2dVaGp3MVNKS3lNQ0dJSTZFR29hWE5BanBOTzhXYWpaNFZwUHRFWS9obDVQNTlhNmF4OGFXRStGdVVrdG1QZkc1ZnpIUDZWNXNEVHcxS3lZN2tGRkZMVEVKaWlscEtBQ21zb1BXbEp3UVBXbG9HUmlNcWNnNEhwU21uSHBUYVZndU5wNkROTU5TUmRhU0dlamVGRjgvUzdOQi9kd1Q2QUUxdFhDT1p6SUI4dlFEMEZaWGdQSDlrcXpkbVpGejM1eWY1aXVyTUlaU3BGWjJMVE14R0IrdnBWdFpWS1lQL3dCY1ZGSmJsV0l4eUtjRXdBZXhwV0dMY29Iak1uVmxQSjlSVlF0Z1ZvUnFwRERKd3d3UldOZGt3eVBHMzhQNjFsVVZ0VGFtN3F3T3hkd3FBbGljQVZwMk5pdHVOL0R6SHEyUHUvU3FtZ3d0UEpKT0JrS2RvK3ZmK2xkQUlHSExNUHdxcWNlckpxUzE1VVpWL0Y4bk5jN0pOTGJYS3lSSGF5SElycXJpUHpHSjdWbFM2YjU4cHdLdG96VE5tMXVWdXJWTGhlQXk1UHNlOWVOMzgvMm5VYm1mT2ZNa1p2ek5lamZhanBtbWFoRkljRkltZVA4QUwvOEFWWGw2MXJEWXpudU9OTU5QTk1OV1FSc3VUM3g2VUQycHhwTVVERU5KVGlLYlNBS0tLVUNnQXAxQW9wZ1IwVVVVQUZKUzBsSUJqOEVIM3A5STR5cEZDbktnMERBMGxMUWFCRERUNC92VXcwNlA3MVQxS1BSUEI3azZGdUI1aW5ZZm9EL1d1MXQzRWtRSTYxdzNnRnZNc2IrSCs2eU4rWUkvcFhYNmRKOG0wOXFVdHh4Mkxrc2U0YmgxRk5XSUVjZEQraHF3UDBwb0hsdng5MDFKUlRlTXFUMnJIMTJNL1p2UFhySHczMC8vQUYvenJxWkkxa1Qzckt1NEF5dEd3M0s0S2tldWFVbzNWaHhsWjNLM2cyNldUVHJoRDFTWFA1Z2Y0VnRzNWtKQTZWaitIOUpiVHJSb2krNlNSdHpzT25zUDgrdGJKQVJjQ2lLc3RRbTA1Tm9oa0hHQlJIR0ZYT0tkam5KcFc0UTB5VGgvSGt3UzJZTHdXK1g5YTROUnhYVStPNTk5ekZIbnF4UDVmL3JybHh4V2tkaUpiaUUxRzJSOUtrTk5xaVJ1YzBVaEhOTDcwQUllVFNVVVVEQ25VZ3AxQWdvb29vQWpvb3BLQmhSUlJTQVEwMU80OURUNlowaytvb0FkU0duVWxBRERTeDlhUTBxOWFRenVQaDNKL3dBVEc2aC92d2J2eUkveHJzcmY5M2NNdnZYQWVCSmZMOFNRTG4vV0k2L3BuK2xlZ1RqWmRBK3RLUTRtb2h5S2YxR0toZ09WcVU4VkJRZVpzVWcvaFRVaEx0azlmNVUySStmT2Y3cWZ6cTZnNkFEclJjQnFJRVhpb0hPVFZsK2hxcWFBRzk2UzRPMkVuMm9IM3FoMUY5bHF4OXFBUEsvRmMzbmEwUUR3aTFrR3JHcFMrZHF0eStjL09SK1hGVmpXc2RqTjdpR21tbkdtbW1JU2c4REhyUlFlVDlLQUVvb3BSUUFDblVDaWdCS1dpbG9BaHBLS0RRTVNscEtLUUMwMStBRDZHblVFWkJGQUJRYVJEbFJTbWdCaG9YclN0U0wxcEROM3d2TDVQaUN3YlBXWlYvUGordGVvMzR3eXRYajlsS1lKNHBSMWpjTVB3TmV4WDR6Q0NPbEVoeExObWN4aXJMZmROVXRPT1k2dXluRVRIMEJyTW9UVFUyMndjOVhKYi9QNFlxNTB6anZVTnV1eTNqWDBVRDlLa3pRQWpmZFAwcXEzUTFhUFEvU3FjcHdLQUdweTladmlLY1EyRWpIb0ZKclNnN211VzhkWFBsYVhLb1BMRGIrZkZBSG13WXNTeDZrNU5LYVJlQlMxc1pDR20wNDAyZ0FIclNkcVU5UHJTVUFKVGhTVW9vQWNLS0JTMEFOcFJRYUtBSUtTaWlrTUtLS0tBRnBhUVV0TUJvNGRoK05PcHJjTUQrRk83VWdHbW1qclRqVFIxcERMTVhTdllMV1Q3VG9OcEwxTFFveCt1Qm12SG9qelhxbmhXWHovQUFuYjVPV1FNaC9Camo5TVVTMkNPNXJhWWZseFY2NC80OTVQOTAxbjZXZW9yUm01aEk5ZUtnc3M5cUtEU1VnQS9kUDBxak9lS3ZIN2grbFowNXl3RkFFc1hFV2E4OStJRnh1ZUdFSHEyZnkvL1hYb1VoMlFINlY1TjR2bjg3V3lvUENMajhUL0FKRk5iaWV4akRwUWFXbTFxWmlHa3BhT2d6UUFoNWFrb0ZGQUFLY0tRZGFkUUFDaWlpZ0FwQ2VLRFRYT0JRQkVLS2F0T3BGQlJSUlFJVVV0SUtVVXdCeGxUU0tjak5PcHE4RXI2VWdBMDN2VDZiM29Ba2o2MTZONEJtMzZOZHdmODg1ZDM0RUQvQTE1d2xkcDhQcmpiZlhrQk9QTWhEZmlwLzhBc2pROWdXNTIybWZmUDFyVGwrNlA5NGZ6RlptbWZmYjYxcHljaGY4QWVIODZ6TkNlaWlrWTRvQVJ6KzdiNlZuRDVwL3BWK1ZzUU9mYXFGdHl4TklCZFJrOHUxWSsxZU42bEw5bzFTNWs2NWNnZmh4L1N2VS9FMTE5bTB5WjgvZFVtdklrNTVQVTFjZHlaYkR6VFRUajBwcHF5QktSK3dGT0FwblVrMEFBRkxpaWxvQUJTMFpwcFlVQUxtazNVekp6UjlhQUhrOFZESzNGT0o0cUdRNUlGSnNwSVZhZlVTbXBLU0JpMFVsTFRFTFNpa3BSUUE2bU53NFByeFR4VFpCbERqdHpRQVVtS1VIS2dpaWdCVnJlOEozSDJmeEJha25oeVl6NzVCQS9YRllJcTNhVEczdUlwbDZ4dUhINEhOTUQxL1N2dnQ5YTBtYjk0ZzlXck8wckJMa0hJSnlEVjJUaTVnSHE1LzhBUVRXUm9YUnlRUFdpVUF4a3IycG9CSjRPQ09RYVhHRndjZStLUUZhZHY5R2Y2Vlh0T0V6VTkwTVc4bVA4ODFERHhEVEE0L3gvZDdMRHlnZVpHQy8xL3BYQXFPSzZUeDFjK2JxVWNJUDNRV1ArZnpybXgwcTQ3RVNGTk5wVFNWUklqSEMvV201R0tHNU5HS0FESm81TkxSUUFtUFdpbHBwb0FTbWs4VXBOTnBERlBTb0dQejFLeHFCdVhxV1VqLy9aIl0~WyJjZjkxMmVmMzc2N2VlMWY5IiwiaW1hZ2VfYmFzZTY0X3BuZyIsImlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFTd0FBQURJQ0FJQUFBRGR2VXNDQUFBQUFYTlNSMElBcnM0YzZRQUFBQVJuUVUxQkFBQ3hqd3Y4WVFVQUFBQUpjRWhaY3dBQUZpVUFBQllsQVVsU0pQQUFBQW5xU1VSQlZIaGU3ZDFSZ3FJNkVJWGhXWmNMY2oydXBqZmpZdVlHNUxaS0txUXFJUjVHL3U5dFpvVEVxaHdFcEh2Ky9BVWdSUWdCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LRUVCQWpoSUFZSVFURUNDRWdSZ2dCTVVJSWlCRkNRSXdRQW1LQ0VONS9icmZyOVhLNS9IbVQvdUp5dmQ1dVAvZjc4a0xnRkQ0WXdoUys2eXA0WlpkclN1T3k0YmI3MjE0dlYrZG13RkY4Sm9RcGYrNzR2VXBSckVUcTU3cTg5T2xTMndZNGxBK0U4TjRXd01WMnBJd01ra0w4WTBhSHNDK0JDU0hFdHhzYndsSUVML01sMzF0VTd2ZjVoazMrK3V2UDhnb0xJZFJZWFY1UThTNGpRMmhIc05xd2xNYnI4OVpwNWVWY0V5cGtWYWZtUFFhRzBNcGdvRmxURk5NV214K0VrM1JRZm82VFBtSzVPem9lSWR6VnVCQWFHYVJWWDRJUTdtcFlDTW5nRnlPRXV4b1d3dnhpalVaOURVSzRLMEtJT0VLNEswS0lPRUs0cXcrR3NINmpVOFo4cG54Nm9IeDZubng1elJEejg3UnZ3ejRlWTkvbktmYjcvU2Z0ZnhwZ2ZYMCsvZFUwVE9PNys4NFF2bjgzdGl5QVQvdzh3U2R2ekl4SjRlT2JqRitYVzJTUTBFUGx0dEw2Vzc1aVdheS9PbkVNWEg5d3RpVDJyaHhmNjlqZitQb1U2L08rei9DN2ZYOXd2enpPMDFaSDN2L3R6ZmdEekxBUVdoK0ZJMkxZZmxEZXFIdElZY0QxeEo1dlBUSndjQVcwdjZldGdYb3lXTnB6dnMvZzJvZzN2dGlSN2ZjWGJFR0RjU0cwVTdqN1cyb01ZZCs2ZWxNWXNORHkrTUR1aXRrRjl5c085TlVockw0NWQvMmJEUXhoY1ZIcytsUkx2QmRKY2JsT1Ywb1AyV1ZVVVdIeFdDMXZYTTJ1WlZEWjkzUVZPRnYrYkNvTTlNVWhMSzZFSjFmMXU0d000VmJ6NWt2ZTVXVmQ0cjB3QzI4ZkdOTEZsZkVPbHRXOEtGMkRaaTIvWmZ1YXI4YWV3MDZQc0JmT0poMEx3U2gyK2NaQ2NhVENRT2tzOTlYeTRsZkx2K1FLOVRsRUNOZC9zeFJzTXQzU2VyelI0THdhREEyaHVUSmV2Uy9DSnVGZVdJdDFjNU5zQkY5WHNzM2VwY1ZwRDJwZjF0VlQrUHErZkllNE5OTHkraGYxZ1pKdzBYTUhDT0hLbnVkbk1ZTkRtTlJ2RlhSOUtrWjdrWGVpM3Z4c3dYald5MGJMYTh2Rk9uVFZsL204VmJDV3hraWVQTVVEa0RsWUNIVUpUTWFITUhIZHNtdU1ZckFYV2U5OXkyYzlpbU9yVXN0ZEF6YUdvMEUrVFVjWWdrVzNIQ21FZzBycjlwRVFKdDU3NStFb0JudXhmcm16L2czWk5WdnVicmVSd3VBaWRjb0hjc3d4SG9ETWNVSVluL3ZlUGhYQ2lmODc1T0lGVXk3V2k2ejEzczVudzFRM05Gb2VXV1pONFdnUlg4eHQyNndjSllTRHFocnl5UkRPNW1lRGxnSnNjbjZSRWV1Rk1vVEJkdmR1NzVXVnhESE9Ebk03UmdnSDFUVG80eUY4Y0VaeDkvWHdENFd3ZTVVNm5UbUVZeW9hSmdyaFlvcGlKWXUxMHNaNjBiTGlKZzNiRWNKTlJ3aGhmTlpqYUVQNFVMbFczQzVWc0xMWnkxMnRiMWt4dlMzZk00VHpsOC9KYlhrYzZNMTZHTWM4ZDFqT2hQRHBDQ0djMlErblBHd1ZLMXJabGs1azIzZ1dURy9MdTFmcGZHd3IxclNzcFNEQjk1WVF3cWZEaEhDV2QyWlJibEM0c3RrR2xmWmJ6NVY0MWt0dnk5dFhxZjh1dE1reHp4MldNeUY4T2xZSWswSU9peDFxcUd5MlNXSi9LV0xmUHZMMXJyZmxiYXUwZUJqemM4eHpoK1ZNQ0o4T0Y4TEVEa21oWGsyVnRVYVlPWDZLd3R1NTNwWTNyRkxubHo4VmpubnVzSndKNGRNUlEyZ2V6a3N0YXFoc3RrbUFmNlgwdGp5NlNxMmlQVndlLyt0ajRWSDViRHZIUEhkWXpvVHc2WkFodEdKU0tsaTRzc2ErblM2aFpkTGI4dUFxTmQrVzU0RUhRaWgzekJEbUhTb1dMRmpaOWN1djg4K05MWDhvY3o2Kzg2cTM1YUZWYWhRc3ZkdzFIaUdVTzFjSTEvdjk3ZnZqNTJsWDE0SHB6eDIvK095VElUVHE1VjdTMmJhT2VRNEpZWEFmaEhDd3JGemxSUldxN09yRndXTnZURy9MSXlITTYrVi9hNklRZHU4anZ2MGVzeDdpWDdreFU2eFhwTEtyL1k3dFFXL0x1MElZR0tzbGhDM2JyR1Z6RGgwVDg2M3JjK2p0eURCSERHR293SkhLWnE4ZCtWSFkyL0pBQ1BPWEJzYmFKWVFObGN6MzRkNkpzV2xTbmZmSlFqaFhxZkZINWEwS2IxUXJVbGx6MTlmdVgzTmorMkFJODdIYzY5bjRhdEV4ejN4dURlczVuN1JyMWxZVFo5VXBuQ3VFTDNXSy9zNFRvelBieFFwVnR0akFGL092Q1B2ZjhzMzkvQnZqZzJIdGJYa2toTWI3Y3F6bndvK1RlZWFadDZsaFFWdTlya3g3cTRIVkdmUjJaSmpSSVh4SXE3bTZoSXRQUEc2WEtsaFpxL0VobnJjeTYyMTVKSVR4OWJ6eHZMeG5ubFlZSExGZk1adFJISDc5ZSsvWHF2UHU3Y2d3bnduaHI3U0ViNDhQbFY4LzAzL0dVcTV1clZEaHloYU8vekhwYmRUNjk5RVEyaVczVDBOcXozZTc1bW5uNS9YNHRIenJFejUyVE9hSnIvYTAvTk92N1BlNFZ1ZDlyaEFXaXh0V1A3bzJWYlo4bElqWW5seHZ5Mk1oM0tyNTg2emFlaUQyY2x0OUtQcm02Vy94NXY0YVY4cjBJTUs2UU5WNTkzWmttREVoM0dXVnArUHFzcmN0OGNwYWMxc3VBYU9UM2hxcnQrWFJFRFl0NkhsT3E1Rzg4L1FPVjlsZmVOYlQ1KzIwSVNHc3E1MzFiQW5jemdsVzFraGdwUlh6S1hQeGpMa2NqTjZXeDBNNDFkeGY4dWNaZFdNSXZmbXBUanN3NjlmTEFFTG9aWi9QbDdudmUveHYxY0h5L3cweHlWZk5jbFIxTVJkTHNaR2hpVm5TV2VMYkRsd25CdE80MVlMUFJWNWVQbmxienQ1eEhtcDNTenlIamtrOWlPdEpyNmFkR2xFYnFMc2pvNHdPNGEvNURzelcveHI3ZWlrK1JzdG55MHEraS9nK1BtSSsrSzJmaGsxMUh2SmZEeHRqelUwTnQvUnh5cEZQZXZqUzBQcFlDUFd5ajhHbStCejJuQWIvclBPRWNKOE1Fa0xzN2pRaHpFNGsyOEt6d3lrdDhPNjhJZVJzRkFkeDR0UFJoaFRtK3lDRDZIYWVFQm8zTmtNUmluMUJBYmlkSjRSbUNwUDVEdmp5RWx2eG16Y2lpRDJjS0lUVzJlU3IrYXV0VjlOZkxQOW00WTRNOW5HcUVCWS9EY095cHplQVppY0xZVkovUUtxQ0FHSmY1d3ZoelBHQVpTNmRyWDc1ODFPUU9Ha0lmejJlYUowdi80eFFUbitiL3ZYMncyY2Z4amw3Q0FFNVFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJNUUlJU0JHQ0FFeFFnaUlFVUpBakJBQ1lvUVFFQ09FZ0JnaEJLVCsvdjBQZnBLTVJjQ0QxdEVBQUFBQVNVVk9SSzVDWUlJPSJd~WyJiNDI4ZDBmNWZiY2VmNDQ0IiwibG9uZ19zdHJpbmciLCJMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwgY29uc2V0ZXR1ciBzYWRpcHNjaW5nIGVsaXRyLCBzZWQgZGlhbSBub251bXkgZWlybW9kIHRlbXBvciBpbnZpZHVudCB1dCBsYWJvcmUgZXQgZG9sb3JlIG1hZ25hIGFsaXF1eWFtIGVyYXQsIHNlZCBkaWFtIHZvbHVwdHVhLiBBdCB2ZXJvIGVvcyBldCBhY2N1c2FtIGV0IGp1c3RvIGR1byBkb2xvcmVzIGV0IGVhIHJlYnVtLiBTdGV0IGNsaXRhIGthc2QgZ3ViZXJncmVuLCBubyBzZWEgdGFraW1hdGEgc2FuY3R1cyBlc3QgTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQuIExvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZXRldHVyIHNhZGlwc2NpbmcgZWxpdHIsIHNlZCBkaWFtIG5vbnVteSBlaXJtb2QgdGVtcG9yIGludmlkdW50IHV0IGxhYm9yZSBldCBkb2xvcmUgbWFnbmEgYWxpcXV5YW0gZXJhdCwgc2VkIGRpYW0gdm9sdXB0dWEuIEF0IHZlcm8gZW9zIGV0IGFjY3VzYW0gZXQganVzdG8gZHVvIGRvbG9yZXMgZXQgZWEgcmVidW0uIFN0ZXQgY2xpdGEga2FzZCBndWJlcmdyZW4sIG5vIHNlYSB0YWtpbWF0YSBzYW5jdHVzIGVzdCBMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldC4gTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNldGV0dXIgc2FkaXBzY2luZyBlbGl0ciwgc2VkIGRpYW0gbm9udW15IGVpcm1vZCB0ZW1wb3IgaW52aWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdXlhbSBlcmF0LCBzZWQgZGlhbSB2b2x1cHR1YS4gQXQgdmVybyBlb3MgZXQgYWNjdXNhbSBldCBqdXN0byBkdW8gZG9sb3JlcyBldCBlYSByZWJ1bS4gU3RldCBjbGl0YSBrYXNkIGd1YmVyZ3Jlbiwgbm8gc2VhIHRha2ltYXRhIHNhbmN0dXMgZXN0IExvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LlxuXG5EdWlzIGF1dGVtIHZlbCBldW0gaXJpdXJlIGRvbG9yIGluIGhlbmRyZXJpdCBpbiB2dWxwdXRhdGUgdmVsaXQgZXNzZSBtb2xlc3RpZSBjb25zZXF1YXQsIHZlbCBpbGx1bSBkb2xvcmUgZXUgZmV1Z2lhdCBudWxsYSBmYWNpbGlzaXMgYXQgdmVybyBlcm9zIGV0IGFjY3Vtc2FuIGV0IGl1c3RvIG9kaW8gZGlnbmlzc2ltIHF1aSBibGFuZGl0IHByYWVzZW50IGx1cHRhdHVtIHp6cmlsIGRlbGVuaXQgYXVndWUgZHVpcyBkb2xvcmUgdGUgZmV1Z2FpdCBudWxsYSBmYWNpbGlzaS4gTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVlciBhZGlwaXNjaW5nIGVsaXQsIHNlZCBkaWFtIG5vbnVtbXkgbmliaCBldWlzbW9kIHRpbmNpZHVudCB1dCBsYW9yZWV0IGRvbG9yZSBtYWduYSBhbGlxdWFtIGVyYXQgdm9sdXRwYXQuXG5cblV0IHdpc2kgZW5pbSBhZCBtaW5pbSB2ZW5pYW0sIHF1aXMgbm9zdHJ1ZCBleGVyY2kgdGF0aW9uIHVsbGFtY29ycGVyIHN1c2NpcGl0IGxvYm9ydGlzIG5pc2wgdXQgYWxpcXVpcCBleCBlYSBjb21tb2RvIGNvbnNlcXVhdC4gRHVpcyBhdXRlbSB2ZWwgZXVtIGlyaXVyZSBkb2xvciBpbiBoZW5kcmVyaXQgaW4gdnVscHV0YXRlIHZlbGl0IGVzc2UgbW9sZXN0aWUgY29uc2VxdWF0LCB2ZWwgaWxsdW0gZG9sb3JlIGV1IGZldWdpYXQgbnVsbGEgZmFjaWxpc2lzIGF0IHZlcm8gZXJvcyBldCBhY2N1bXNhbiBldCBpdXN0byBvZGlvIGRpZ25pc3NpbSBxdWkgYmxhbmRpdCBwcmFlc2VudCBsdXB0YXR1bSB6enJpbCBkZWxlbml0IGF1Z3VlIGR1aXMgZG9sb3JlIHRlIGZldWdhaXQgbnVsbGEgZmFjaWxpc2kuXG5cbk5hbSBsaWJlciB0ZW1wb3IgY3VtIHNvbHV0YSBub2JpcyBlbGVpZmVuZCBvcHRpb24gY29uZ3VlIG5paGlsIGltcGVyZGlldCBkb21pbmcgaWQgcXVvZCBtYXppbSBwbGFjZXJhdCBmYWNlciBwb3NzaW0gYXNzdW0uIExvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ZXIgYWRpcGlzY2luZyBlbGl0LCBzZWQgZGlhbSBub251bW15IG5pYmggZXVpc21vZCB0aW5jaWR1bnQgdXQgbGFvcmVldCBkb2xvcmUgbWFnbmEgYWxpcXVhbSBlcmF0IHZvbHV0cGF0LiBVdCB3aXNpIGVuaW0gYWQgbWluaW0gdmVuaSJd~WyJlYWRhYmIxMGZiNzcwMWMyIiwiY2xhaW0iLCJOZXN0ZWQgZWxlbWVudCJd~WyJmN2ViMjU5MTk2ZDg4ZDNkIiwgIm9iamVjdCIsIHsiX3NkIjogWyJocld5ODFrektTcmN4OXFaMkg3alUwWFFjcjZnMlRnTmFuZl9SUjBOVlQ0Il19XQ~WyJmOTM0ZGFkMjc3OThhY2E0IiwiY2xhaW0iLCJOZXN0ZWQgb2JqZWN0IGVsZW1lbnQgMiJd~WyI0ZDFlY2Y3NGZjOTIxNGY4IiwgeyJfc2QiOiBbInJyVmpWVnZuZjJ3VWtCSzkxdWI3anJqVG9oaC1WNDA0OFlHbkhzS1NzdkkiXX1d~WyI1M2UwZjIxMjMwNjg2YjI3IiwiY2xhaW0iLCJOZXN0ZWQgb2JqZWN0IGVsZW1lbnQgMSJd~WyJhY2FlN2VmZTZmNTM3OTI0IiwgeyJfc2QiOiBbIm4tcHlrV2ZqX2dMdUJUb0JDRmdFQUljak5nV29fdXV5dkFDRFp0X2QxbEkiXX1d~WyI5Y2NlOGU1ZTZlZjRjNmEzIiwgImFycmF5X29iamVjdHMiLCBbeyIuLi4iOiAiTS1GQU5fQTRCMWF5b3B4RHlsTHBsaUdsUXFtamROenNIdkdrSEx4ZWs1MCJ9LCB7Ii4uLiI6ICJKbmoxQk4zbTJxVUxjblh5VGl4aEhaQVhucWlTemk5cFZYckV0bGNzd1Y4In1dXQ~WyIyZDg4ZjU1YTE1MmRiY2Q4IiwgM10~WyIyZDg4ZjU1YTE1MnNiY2Q4IiwgMl0~WyIyZDg4ZjU1YTE1MnNiY2RkIiwgMV0~WyIyZDg4ZnM1YTE1MnNiY2RkIiwgImFycmF5X2ludGVnZXJzIiwgW3siLi4uIjogIkdJdHhLbG1aR3Y4NDg1cFdLLUZYWkswQjQ5SHdOU2RUQ2FrYmJnS1NSZUUifSwgeyIuLi4iOiAiSk1RM0lEcVRlRk5BQmVaY2dxVk1MOC1yazdPTEZDUDhpeDdHQWIzTkdRZyJ9LCB7Ii4uLiI6ICJLODZReXNpS0FINVh4V3dxNXJhaU9xaTFVaFV2ZjZPcE9ua19seEFiSTZFIn1dXQ~WyIyZDg4ZnM1ZjE1MnNiY2RkIiwgImNsYWltIiwgIkNsYWltIGxldmVsIDEiXQ~WyIyZDg4ZnM1ZjE1MmNiY2RkIiwgIm9iamVjdCIsIHsiX3NkIjogWyI3ZmUwWnJTV0V0a2ZfS3hoWjlmZ2JhQVMxTnFrM1R0SG9iVjZzdG5uZDZnIiwgIjJqUTZBZ0p6T1dCT19CQ2pzdGZtYnlvLWpQakNQQU1GZFd1NXVZN0RKSzAiLCAicDc1czNtWTQ4ZFFQTUF1VERCZXFsTjZ3Y19rRWNycUZtN1pfWmppQTVRMCIsICJHLXVsWGdfLXVyUTM1cEUxV0w5V2FmVGZLZkhIT2tZVF80eHdIS1FXejZjIl19XQ~WyIyZDg4ZnM1ZjE1MmNiY2FhIiwgIlN0cmluZyBlbGVtZW50IDMiXQ~WyIyZDg4ZmE1ZjE1MmNiY2FhIiwgIlN0cmluZyBlbGVtZW50IDIiXQ~WyIyYzg4ZmE1ZjE1MmNiY2FhIiwgIlN0cmluZyBlbGVtZW50IDEiXQ~WyIyYzg4ZmE1ZjE1MmNiY2FhIiwgImFycmF5X3N0cmluZ3MiLCBbeyIuLi4iOiAic0FzRFg0eUJpREpiNUVkYnlpN3NJa0lWRWxrSFlBTUpmcFBjcFZhSENWRSJ9LCB7Ii4uLiI6ICJPMUJDOEU3V1FaRGIyTmFla21nRVc1dGhKSFh5OWVDWUVOZWtHNlowem1BIn0sIHsiLi4uIjogIkNjQmlVRXRETUFuZFA1a1pfWTJhVWZaX3NHSl9JRldUZ0FydEtzVHl0eGMifV1d~WyJlY2QyNGE0NmE3OTZlMmZjIiwgImNsYWltIiwgIk9iamVjdCBlbGVtZW50IDIiXQ~WyJkZGY2ZmY1OTM5YTIyNjMzIiwgImNsYWltIiwgIk9iamVjdCBlbGVtZW50IDEiXQ~WyIyZDg4ZnM1ZjE1YWJjZGQiLCB7Il9zZCI6IFsiazVnZ0FRVHhRajF0d2c0SEMtWWdSVDdEQ3BGalMtb2pNVUNsbTdnQUxzbyJdfV0~WyIyZDg4ZnN2ZjE1YWJjZGQiLCB7Il9zZCI6IFsiS2tFbjZVU2JnNnpMcXFvUElHanlwSlllVkZwTjdLQWkwY2ZZcHduWjQtOCJdfV0~WyIyZDg4ZnN2ZjE1YWJjdmQiLCAiYXJyYXlfb2JqZWN0cyIsIFt7Ii4uLiI6ICIzREZjcVQ3SzRORjMycGlEdGFUNlZLMFpRQXd4TVdSV0dyVE9NZS1aWm1vIn0sIHsiLi4uIjogIjkyTExVNFNuNU9ENy1VVWpNRGNabUdHQ0l2WFRJb3VhNlZvYTliSHhMVlkifV1d~";
        let query_requesting_null = r#"{
              "credentials":[
                 {
                    "id":"Elfa",
                    "format":"dc+sd-jwt",
                    "multiple":false,
                    "meta":{
                       "vct_values":[
                          "chasseral-vc"
                       ]
                    },
                    "claims":[
                       {
                          "id":null,
                          "path":[
                             "null"
                          ],
                          "values":null
                       }
                    ],
                    "claim_sets":null,
                    "require_cryptographic_holder_binding":true,
                    "trusted_authorities":null
                 }
              ],
              "credential_sets":null
           }"#;
        let query: DcqlQuery = serde_json::from_str(query_requesting_null).unwrap();
        let result = select_credentials_with_info(query.clone(), vec![sdjwt_str.to_string()]);
        let sdjwt = decode_sdjwt(sdjwt_str).unwrap();
        println!("{:?}", result.set_options);
    }
}

uniffi::setup_scaffolding!();
