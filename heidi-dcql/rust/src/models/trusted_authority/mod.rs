use std::sync::{Arc, LazyLock, Mutex};

use heidi_util_rust::log_error;

use crate::models::{Credential, TrustedAuthority, TrustedAuthorityQueryType};

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

pub(crate) static REGISTERED_MATCHERS: LazyLock<Mutex<Vec<Arc<dyn TrustedAuthorityMatcher>>>> =
    LazyLock::new(|| {
        // Register default matchers
        Mutex::new(vec![])
    });

#[uniffi::export(with_foreign)]
pub trait TrustedAuthorityMatcher: Send + Sync {
    fn id(&self) -> String;
    fn matches(&self, value: Credential, trusted_authority: TrustedAuthority) -> Option<bool>;
    fn query_type(&self) -> TrustedAuthorityQueryType;
}

impl PartialEq for dyn TrustedAuthorityMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

#[uniffi::export]
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
