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

//! # Trusted Authories
//!
//! This module exposes the `TrustedAuthorityMatcher` trait that can be used to implement
//! trusted authorities matcher according to https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-3.10
//! A predefined set of known types is exposed as `TrustedAuthorityQueryType`, which also contains an other element if new types
//! are to be added.
//!
//! ## Registered Matchers
//!
//! To register matchers, the static function `register_matcher` can be used, which registers a specific matcher
//! for the runtime of this application. This function is safe to be called multiple times and results in an NOP if
//! the defined matcher is already present.

use std::sync::{Arc, LazyLock, Mutex};

use heidi_util_rust::log_error;

use crate::models::{Credential, TrustedAuthority, TrustedAuthorityQueryType};

/// List of currently registered matchers
pub(crate) static REGISTERED_MATCHERS: LazyLock<Mutex<Vec<Arc<dyn TrustedAuthorityMatcher>>>> =
    LazyLock::new(|| {
        // Register default matchers
        Mutex::new(vec![])
    });

#[uniffi::export(with_foreign)]
/// Trait to implement a trusted authority matcher
pub trait TrustedAuthorityMatcher: Send + Sync {
    /// A unique ID identifying this matcher in this runtime. This ID is used
    /// to check, if the matcher is already registered.
    fn id(&self) -> String;
    /// If this matcher can be used with this `trusted_authority` the return value _MUST_ be
    /// some.
    fn matches(&self, value: Credential, trusted_authority: TrustedAuthority) -> Option<bool>;
    /// What kind of trusted_authority type does this matcher match to.
    /// If the type is anything other than one of the predefined ones, use `TrustedAuthorityQueryType::Other`
    fn query_type(&self) -> TrustedAuthorityQueryType;
}

impl PartialEq for dyn TrustedAuthorityMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

#[uniffi::export]
/// Registers this matcher with the DCQL Runtime.
pub fn register_matcher(matcher: Arc<dyn TrustedAuthorityMatcher>) {
    let Ok(mut matcher_lock) = REGISTERED_MATCHERS.lock() else {
        log_error!("DCQL", "Failed to register matcher");
        return;
    };
    if matcher_lock.contains(&matcher) {
        return;
    }
    matcher_lock.push(matcher)
}
