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

//! Helper functions for the wallet.
#![deny(clippy::unwrap_used, clippy::expect_used)]
use std::sync::{atomic::AtomicBool, Arc, Mutex};

pub use crate::error::ApiError;
#[cfg(all(feature = "reqwest", feature = "oid4vp", feature = "uniffi"))]
use frost::FrostHsm;
#[cfg(all(feature = "reqwest", feature = "oid4vp", feature = "uniffi"))]
use hsm::Hsm;
use lazy_static::lazy_static;
#[cfg(feature = "uniffi")]
use reqwest::Proxy;
#[cfg(feature = "reqwest")]
use reqwest::{Client, ClientBuilder};

#[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
pub mod backend;
pub mod crypto;
#[cfg(all(feature = "reqwest", feature = "uniffi"))]
pub mod dpop;
pub mod error;
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
pub mod faker;
#[cfg(feature = "oid4vp")]
pub mod formats;
#[cfg(all(feature = "reqwest", feature = "oid4vp"))]
pub mod issuance;
#[cfg(feature = "oid4vp")]
pub mod presentation;
pub mod signing;
pub mod testing;
pub mod util;
#[cfg(feature = "oid4vp")]
pub mod vc;

// #[cfg(feature = "oid4vp")]
#[cfg(feature = "oid4vp")]
pub mod agents;
#[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
pub mod backup;

pub mod frost;
#[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
pub mod hsm;
// #[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
#[cfg(feature = "oid4vp")]
pub mod jwx;
pub mod log;

#[cfg(all(feature = "reqwest", feature = "uniffi"))]
lazy_static! {
    pub static ref PROXY: Mutex<Arc<Option<Proxy>>> = Mutex::new(Arc::new(None));
    pub static ref UNSAFE_TLS: AtomicBool = AtomicBool::new(false);
    pub static ref TRUSTED_CAS: Mutex<Arc<Vec<Vec<u8>>>> = Mutex::new(Arc::new(vec![]));
    pub static ref TRUSTED_ISSUERS: Mutex<Arc<Vec<String>>> = Mutex::new(Arc::new(vec![]));
}

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

/// Get a common reqwest client (e.g. when proxy enabled)
pub fn get_reqwest_client() -> ClientBuilder {
    use std::time::Duration;
    let mut client_builder = ClientBuilder::new();
    #[cfg(not(target_family = "wasm"))]
    {
        client_builder = client_builder.tls_info(true);
        client_builder = client_builder.timeout(Duration::from_secs(10));
    }
    #[cfg(feature = "uniffi")]
    if UNSAFE_TLS.load(std::sync::atomic::Ordering::Relaxed) {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    #[cfg(feature = "uniffi")]
    if let Ok(guard) = PROXY.lock() {
        if let Some(proxy) = guard.as_ref() {
            client_builder = client_builder.proxy(proxy.clone());
        }
    }
    client_builder = client_builder.user_agent(APP_USER_AGENT);
    client_builder
}
#[allow(clippy::unwrap_used)]
pub fn get_default_client() -> Client {
    get_reqwest_client().build().unwrap()
}

#[cfg(all(feature = "uniffi", feature = "reqwest"))]
pub mod uniffi_reqwest {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[cfg_attr(feature = "uniffi", uniffi::export)]
    /// Set trusted issuers/verifiers and trusted CA
    pub fn set_trust(trusted_cas: Vec<Vec<u8>>, trusted_issuers: Vec<String>) {
        let _ = TRUSTED_CAS.lock().map(|mut a| *a = Arc::new(trusted_cas));
        let _ = TRUSTED_ISSUERS
            .lock()
            .map(|mut a| *a = Arc::new(trusted_issuers));
    }

    #[cfg_attr(feature = "uniffi", uniffi::export)]
    /// Set a proxy for the reqwest client
    pub fn set_proxy(ip_address: String, port: u16) {
        let _ = PROXY
            .lock()
            .map(|mut a| *a = Arc::new(Proxy::all(format!("http://{ip_address}:{port}")).ok()));
        UNSAFE_TLS.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg_attr(feature = "uniffi", uniffi::export)]
    pub fn unset_proxy() {
        let _ = PROXY.lock().map(|mut a| *a = Arc::new(None));
    }

    #[async_trait]
    pub trait HsmSupport: Send + Sync {
        fn get_wallet_attestation(&self) -> Option<String>;
        async fn generate_pop(
            &self,
            client_id: String,
            credential_issuer_url: String,
        ) -> Option<String>;
    }

    #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
    pub struct HsmSupportObject(pub Arc<dyn HsmSupport>);

    #[cfg_attr(feature = "uniffi", uniffi::export)]
    impl HsmSupportObject {
        #[cfg_attr(feature = "uniffi", uniffi::constructor)]
        pub fn with_hsm(hsm: Arc<Hsm>) -> Self {
            Self(hsm)
        }
        #[cfg_attr(feature = "uniffi", uniffi::constructor)]
        pub fn with_frost(hsm: Arc<FrostHsm>) -> Self {
            Self(hsm)
        }
    }
}

#[macro_export]
macro_rules! unix_timestamp {
    () => {{
        let now = web_time::SystemTime::now();
        let duration = now
            .duration_since(web_time::UNIX_EPOCH)
            .expect("Tachyonic behaviour");
        duration.as_secs()
    }};
    (ms) => {{
        let now = web_time::SystemTime::now();
        let duration = now
            .duration_since(web_time::UNIX_EPOCH)
            .expect("Tachyonic behaviour");
        duration.as_millis()
    }};
}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
