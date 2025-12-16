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

//! This module implements the needed enpoints for OID4VCI. Currently we differnentiate
//! between PID issuance (leads to NFC reader showing) and other issuance. In the future this will be merged
//! into one flow.
//!
pub mod auth;
pub mod helper;
pub mod metadata;
pub mod models;
pub mod requests;

#[cfg(feature = "uniffi")]
pub use issuance::*;

#[cfg(feature = "uniffi")]
mod issuance {
    use anyhow::{anyhow, Context};
    use heidi_credentials_rust::w3c::parse_w3c_sd_jwt;
    use heidi_util_rust::value::Value;

    use super::auth::{build_refresh_request, ClientAttestation};
    use super::metadata::MetadataFetcher;

    use reqwest::{
        redirect::{Attempt, Policy},
        StatusCode, Url,
    };
    use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
    use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
    use serde::{Deserialize, Serialize};

    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use uniffi::Object;

    use crate::crypto::encryption::ContentDecryptor;
    use crate::error::{BackendError, NetworkError};
    use crate::formats::{CredentialResult, Deferred};

    use crate::issuance::helper::base64_encode_bytes;
    use crate::issuance::models::{
        self, credential_formats, AuthorizationRequestReference,
        CredentialConfigurationsSupportedObject, CredentialIssuerMetadata, CredentialOffer,
        CredentialOfferParameters, CredentialProofs, CredentialResponseEncryption,
        CredentialResponseType, ErrorDetails, InputMode, KeyAttestationMetadata, KeyProofsType,
        PreAuthorizedCode, ProofType, PushedAuthorizationRequest, StringOrInt, TokenRequest,
        TokenResponse,
    };
    use crate::issuance::requests::{
        get_access_token, get_credential, get_credential_with_proofs, get_proof_body,
        try_get_deferred_credential,
    };
    use crate::jwx::EncryptionParameters;
    use crate::{
        backend::WalletBackend,
        dpop::{DpopAuth, DpopWrapper},
        error::GenericError,
        formats::{Credential, CredentialFormat, DeviceBoundTokens},
        frost::FrostHsm,
        get_reqwest_client,
        hsm::Hsm,
        log_debug, log_warn,
        signing::{BatchSigner, KeyType, NativeSigner, SignerFactory},
        uniffi_reqwest::HsmSupportObject,
    };
    use crate::{
        error::CredentialError,
        lock,
        signing::SecureSubject,
        util::{generate_code_challenge, generate_code_verifier},
        ApiError,
    };

    const RESPONSE_TYPE_CODE: &str = "code";

    #[derive(Serialize, Deserialize)]
    #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
    /// OIDC-Settings to be used for the issuance process.
    pub struct OidcSettings {
        pub redirect_url: String,
        pub client_id: String,
        #[allow(unused)]
        // Used in backup/backend
        pub client_secret: Option<String>,
    }

    #[cfg_attr(feature = "uniffi", uniffi::export)]
    #[cfg(feature = "uniffi")]
    impl OidcSettings {
        // #[cfg_attr(feature = "uniffi", uniffi::constructor(default(client_secret = None)))]
        #[uniffi::constructor(default(client_secret = None))]

        /// Construct a new OIDC-Settings Object using no client_secret (Public-Client)
        pub fn new(redirect_url: String, client_id: String, client_secret: Option<String>) -> Self {
            Self {
                redirect_url,
                client_id,
                client_secret,
            }
        }
    }
    #[cfg(not(feature = "uniffi"))]
    impl OidcSettings {
        /// Construct a new OIDC-Settings Object using no client_secret (Public-Client)
        pub fn new(redirect_url: String, client_id: String, client_secret: Option<String>) -> Self {
            Self {
                redirect_url,
                client_id,
                client_secret,
            }
        }
    }

    #[derive(Clone)]
    #[cfg_attr(feature = "uniffi", derive(Object))]
    /// Convenience struct holding the OIDC state and code verifier
    pub struct AuthState {
        #[allow(unused)]
        state: String,

        code_verifier: String,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
    pub enum CredentialType {
        SdJwt,
        Mdoc,
        BbsTermWise,
        W3C,
    }

    #[derive(uniffi::Enum, Clone, Copy)]
    /// Currently we only support RSA-PSS 256 with AES-CBC using HS256 integrity check
    pub enum EncryptionAlgorithm {
        RsaPss256AesCbcHs256,
    }

    #[derive(uniffi::Record, Clone)]
    /// Struct to allow storage of OIDC metadata. Used for caching of metadata
    pub struct OidcMetadata {
        pub oidc_settings: String,
        pub credential_issuer_metadata: String,
        pub authorization_metadata: Option<String>,
        pub credential_configuration_ids: String,
    }

    #[derive(uniffi::Enum, Debug)]
    pub enum AuthorizationStep {
        None,
        EnterTransactionCode {
            numeric: bool,
            length: Option<u64>,
            description: Option<String>,
        },
        BrowseUrl {
            url: String,
            auth_session: Option<String>,
        },
        WithPresentation {
            presentation: String,
            auth_session: String,
            scope: String,
        },
        Finished {
            code: String,
        },
    }

    #[derive(uniffi::Enum, Debug)]
    pub enum CredentialOfferAuthType {
        PreAuthorized,
        Authorization,
        Presentation,
        TransactionCode {
            numeric: bool,
            length: Option<u64>,
            description: Option<String>,
        },
    }

    #[derive(uniffi::Object)]
    pub struct IssuedCredentials {
        pub tokens: DeviceBoundTokens,
        pub credentials: Vec<CredentialResult>,
        pub subjects: Vec<Arc<dyn NativeSigner>>,
    }
    #[uniffi::export]
    impl IssuedCredentials {
        pub fn tokens(&self) -> DeviceBoundTokens {
            self.tokens.clone()
        }
        pub fn credentials(&self) -> Vec<Credential> {
            self.credentials
                .iter()
                .filter_map(|cr| match cr {
                    CredentialResult::CredentialType(c) => Some(c.clone()),
                    CredentialResult::DeferredType(_) => None,
                })
                .collect()
        }
        pub fn deferred(&self) -> Vec<Deferred> {
            self.credentials
                .iter()
                .filter_map(|cr| match cr {
                    CredentialResult::CredentialType(_) => None,
                    CredentialResult::DeferredType(deferred) => Some(deferred.clone()),
                })
                .collect()
        }
        pub fn transaction_ids(&self) -> Vec<String> {
            self.credentials
                .iter()
                .filter_map(|cr| match cr {
                    CredentialResult::CredentialType(_) => None,
                    CredentialResult::DeferredType(deferred) => {
                        Some(deferred.transaction_code.to_string())
                    }
                })
                .collect()
        }
        pub fn subjects(&self) -> Vec<Arc<dyn NativeSigner>> {
            self.subjects.clone()
        }
    }

    fn custom_redirect_policy(attempt: Attempt) -> reqwest::redirect::Action {
        match attempt.url().scheme() {
            "http" | "https" => attempt.follow(),
            _ => attempt.stop(),
        }
    }

    #[derive(uniffi::Object)]
    /// This object stores all the relevant data that is necessary at certain stages.
    pub struct OID4VciIssuance {
        metadata_fetcher: MetadataFetcher,
        client: ClientWithMiddleware,
        wallet_backend: Arc<WalletBackend>,
        dpop_client: Mutex<Arc<ClientWithMiddleware>>,
        auth_key: Arc<dyn NativeSigner>,
        oidc_settings: Arc<OidcSettings>,
        chosen_cred_config_ids: Arc<Mutex<Vec<String>>>,
        credential_issuer_metadata: Arc<Mutex<Option<CredentialIssuerMetadata>>>,
        authorization_request_reference: Arc<Mutex<Option<AuthorizationRequestReference>>>,
        auth_state: Arc<Mutex<Option<AuthState>>>,
        pre_authorized_code: Arc<Mutex<Option<PreAuthorizedCode>>>,
    }

    #[uniffi::export]
    /// If we want to refresh credentials, we start from a saved state of [OidcMetadata].
    pub fn get_issuer(oidc_metadata: OidcMetadata) -> Result<String, ApiError> {
        let credential_issuer_metadata: CredentialIssuerMetadata =
            serde_json::from_str(&oidc_metadata.credential_issuer_metadata)
                .map_err(|e| anyhow!(e))?;
        Ok(credential_issuer_metadata.credential_issuer.to_string())
    }

    #[uniffi::export(async_runtime = "tokio")]
    impl OID4VciIssuance {
        #[uniffi::constructor]
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        /// Start the Issuance process by initializing the struct and get all clients ready
        ///
        /// SAFETY:
        /// The client builder does not fail
        pub fn init_issuance(
            oidc_settings: Arc<OidcSettings>,
            wallet_backend: Arc<WalletBackend>,
            auth_key: Arc<dyn NativeSigner>,
        ) -> Self {
            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let client = ClientBuilder::new(
                get_reqwest_client()
                    .redirect(Policy::custom(custom_redirect_policy))
                    .build()
                    .unwrap(),
            )
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let dpop_client = ClientBuilder::new(
                get_reqwest_client()
                    .redirect(Policy::none())
                    .build()
                    .unwrap(),
            )
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with(DpopWrapper(Arc::new(DpopAuth::new(auth_key.clone(), None))))
            .build();
            let metadata_fetcher = MetadataFetcher::new(client.clone());

            Self {
                metadata_fetcher,
                client,
                wallet_backend,
                dpop_client: Mutex::new(Arc::new(dpop_client)),
                oidc_settings,
                auth_key,
                credential_issuer_metadata: Arc::new(Mutex::new(None)),
                authorization_request_reference: Arc::new(Mutex::new(None)),
                auth_state: Arc::new(Mutex::new(None)),
                chosen_cred_config_ids: Arc::new(Mutex::new(Vec::new())),
                pre_authorized_code: Arc::new(Mutex::new(None)),
            }
        }

        #[uniffi::constructor]
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        /// If we want to refresh credentials, we start from a saved state of [OidcMetadata].
        pub fn from_metadata(
            oidc_metadata: OidcMetadata,
            wallet_backend: Arc<WalletBackend>,
            auth_key: Arc<dyn NativeSigner>,
        ) -> Result<Self, ApiError> {
            let oidc_settings: OidcSettings =
                serde_json::from_str(&oidc_metadata.oidc_settings).map_err(|e| anyhow!(e))?;
            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let client = ClientBuilder::new(get_reqwest_client().build().unwrap())
                .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                .build();
            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let dpop_client = ClientBuilder::new(
                get_reqwest_client()
                    .redirect(Policy::none())
                    .build()
                    .unwrap(),
            )
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with(DpopWrapper(Arc::new(DpopAuth::new(auth_key.clone(), None))))
            .build();
            let metadata_fetcher = MetadataFetcher::new(client.clone());
            let credential_issuer_metadata =
                serde_json::from_str(&oidc_metadata.credential_issuer_metadata)
                    .map_err(|e| anyhow!(e))?;

            let credential_configuration_ids =
                serde_json::from_str(&oidc_metadata.credential_configuration_ids)?;

            Ok(Self {
                metadata_fetcher,
                client,
                wallet_backend,
                dpop_client: Mutex::new(Arc::new(dpop_client)),
                oidc_settings: Arc::new(oidc_settings),
                auth_key,
                credential_issuer_metadata: Arc::new(Mutex::new(Some(credential_issuer_metadata))),
                authorization_request_reference: Arc::new(Mutex::new(None)),
                auth_state: Arc::new(Mutex::new(None)),
                chosen_cred_config_ids: Arc::new(Mutex::new(credential_configuration_ids)),
                pre_authorized_code: Arc::new(Mutex::new(None)),
            })
        }

        pub fn get_issuer_url(self: &Arc<Self>) -> Result<String, ApiError> {
            let cred_issuer_meta_data = {
                let meta_data = self.credential_issuer_metadata.lock()?;
                let Some(meta_data) = meta_data.as_ref() else {
                    return Err(anyhow::anyhow!("").into());
                };
                meta_data.clone()
            };

            Ok(cred_issuer_meta_data.credential_issuer.as_str().into())
        }

        /// Get a saveable state of the issuance process. Usually this is done to be able to refresh the credentials
        /// later on.
        pub fn get_oidc_metadata(self: &Arc<Self>) -> Result<OidcMetadata, ApiError> {
            let oidc_settings =
                serde_json::to_string(self.oidc_settings.as_ref()).map_err(|e| anyhow!(e))?;
            let cred_issuer_meta_data = {
                let meta_data = self.credential_issuer_metadata.lock()?;
                let Some(meta_data) = meta_data.as_ref() else {
                    return Err(anyhow::anyhow!("").into());
                };
                meta_data.clone()
            };
            let credential_issuer_metadata =
                serde_json::to_string(&cred_issuer_meta_data).map_err(|e| anyhow!(e))?;

            let credential_configuration_ids =
                serde_json::to_string(self.chosen_cred_config_ids.lock()?.as_slice())?;

            Ok(OidcMetadata {
                oidc_settings,
                credential_issuer_metadata,
                authorization_metadata: None,
                credential_configuration_ids,
            })
        }

        /// Update the dpop client used by the wallet. This needs to be done after changing the pin e.g.
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        pub fn update_dpop(self: &Arc<Self>, dpop_auth: Arc<DpopAuth>) -> Result<(), ApiError> {
            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let mut client = self.dpop_client.lock()?;
            let dpop_client = ClientBuilder::new(
                get_reqwest_client()
                    .redirect(Policy::none())
                    .build()
                    .unwrap(),
            )
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with(DpopWrapper(dpop_auth.clone()))
            .build();
            *client = Arc::new(dpop_client);
            Ok(())
        }

        /// Sends a PushedAuthorizationRequest to the PID_ISSUER_BASE_URL (sprind pid issuer), to allow issuing eid based sd_jwts
        /// Returns the request_uri which, together with the correct URL, can be used as the `tcTokenURL` for the `Ausweis2SDK`
        pub async fn send_frost_par(
            self: &Arc<Self>,
            offer: String,
            pushed_authorization_request_endpoint: Option<String>,
            code_challenge_methods_supported: Option<Vec<String>>,
            with_wallet_attestation: Option<Arc<FrostHsm>>,
        ) -> Result<String, ApiError> {
            let cred_offer: CredentialOffer = offer
                .parse()
                .map_err(|e| anyhow!("Could not parse offer: {e}"))?;
            let CredentialOffer::CredentialOffer(with_parameters) = cred_offer else {
                return Err(anyhow!("failed to deserialize offer").into());
            };
            let credential_issuer_url = Url::parse(&with_parameters.credential_issuer.clone())
                .map_err(|e| anyhow::anyhow!(e))?;
            let credential_issuer_metadata = self
                .metadata_fetcher
                .get_credential_issuer_metadata(credential_issuer_url.clone())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            {
                let mut cred_meta = self.credential_issuer_metadata.lock()?;
                *cred_meta = Some(credential_issuer_metadata.clone());
            }

            let par_url = pushed_authorization_request_endpoint
                .and_then(|url| Url::parse(&url).ok())
                .clone()
                .context("PushedAuthorizationRequest is mandatory for sprind pid issuer")?;

            let code_challenge_method =
                get_supported_code_challenge_method(code_challenge_methods_supported)?;
            let code_verifier = generate_code_verifier();
            let code_challenge = generate_code_challenge(&code_verifier, &code_challenge_method);
            let state = generate_code_verifier();

            let mut client_attestation = None;
            if let Some(hsm) = with_wallet_attestation {
                let Some(wallet_attestation) = hsm.get_wallet_attestation() else {
                    return Err(anyhow!("No wallet attestation found, call register first").into());
                };

                let Some(pop) = hsm
                    .generate_pop(
                        self.oidc_settings.client_id.clone().clone(),
                        credential_issuer_url.to_string(),
                    )
                    .await
                else {
                    return Err(anyhow!("PoP failed").into());
                };

                client_attestation = Some(ClientAttestation {
                    client_attestation: wallet_attestation,
                    client_attestation_pop: pop,
                })
            }

            let par = PushedAuthorizationRequest {
                response_type: RESPONSE_TYPE_CODE.to_string(),
                client_id: self.oidc_settings.client_id.clone(),
                redirect_uri: Some(self.oidc_settings.redirect_url.clone()),
                scope: Some("pid".to_string()), // XXX
                state: Some(state.clone()),
                code_challenge: Some(code_challenge.clone()),
                code_challenge_method: Some(code_challenge_method.clone()),
                issuer_state: None,
            };

            {
                let mut auth_state = self.auth_state.lock()?;
                *auth_state = Some(AuthState {
                    state,
                    code_verifier,
                });
            }

            let result = self
                .metadata_fetcher
                .push_authorization_request(par_url, par, client_attestation)
                .await
                .map_err(|e| anyhow!("{e}"))?;

            Ok(result.request_uri)
        }
        // TODO: deduplicate code
        /// Returns a list of credentials based on a list of subjects. Uses the batch subject
        /// to issue n signatures at once
        pub async fn get_batch_credentials_with_dpop(
            self: &Arc<Self>,
            device_bound_tokens: DeviceBoundTokens,
            credential_type: CredentialType,
            subjects: Vec<Arc<SecureSubject>>,
            batch_subject: Arc<dyn BatchSigner>,
            is_for_pre_authorized_code: bool,
        ) -> Result<IssuedCredentials, ApiError> {
            // get from scope
            let cred_issuer_meta = {
                let meta = self.credential_issuer_metadata.lock()?;
                let Some(meta_data) = meta.as_ref() else {
                    return Err(anyhow!(
                        "Meta data is empty, have you tried initializing it first?"
                    )
                    .into());
                };
                meta_data.clone()
            };
            let Some((credential_configuration_id, credential_configuration)) = cred_issuer_meta
                .credential_configurations_supported
                .iter()
                .find(|(_, value)| {
                    matches!(
                        (
                            &credential_type,
                            credential_formats::CredentialFormat::from(&value.credential_format)
                        ),
                        (
                            CredentialType::SdJwt,
                            credential_formats::CredentialFormat::VcIetfSdJwt
                        ) | (
                            CredentialType::Mdoc,
                            credential_formats::CredentialFormat::MsoMdoc
                        ) | (
                            CredentialType::BbsTermWise,
                            credential_formats::CredentialFormat::ZkpVc
                        ) | (
                            CredentialType::W3C,
                            credential_formats::CredentialFormat::W3cSdJwt
                        )
                    )
                })
            else {
                return Err(anyhow!("Selected format not supported").into());
            };

            // STEP 5: Exchange access token for credentials
            // let content_decryptor: Option<Box<dyn ContentDecryptor>> = None;

            let dpop_client = self.dpop_client.lock()?.clone();
            let Some(access_token) = device_bound_tokens.access_token.as_ref() else {
                return Err(anyhow!("No accesstoken").into());
            };
            let proof_bodys = get_proof_body(
                subjects.clone(),
                cred_issuer_meta.clone(),
                device_bound_tokens.c_nonce.clone(),
                self.oidc_settings.client_id.clone(),
                is_for_pre_authorized_code,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to get proof: {e}"))?;
            let proof_signatures = batch_subject
                .batch_sign(proof_bodys.clone())
                .map_err(|e| anyhow::anyhow!("failed to get cred: {e}"))?;
            let proofs = proof_bodys
                .into_iter()
                .zip(proof_signatures.into_iter())
                .map(|(body, signature)| {
                    let signature_encoded = base64_encode_bytes(&signature);
                    format!("{body}.{signature_encoded}")
                })
                .collect::<Vec<_>>();

            let credential = match get_credential_with_proofs(
                dpop_client.clone(),
                cred_issuer_meta.clone(),
                access_token.clone(),
                credential_configuration_id.clone(),
                credential_configuration.credential_format.clone(),
                None,
                CredentialProofs::Proofs(KeyProofsType::Jwt(proofs.clone())),
            )
            .await
            {
                Ok(c) => c,
                Err(_) => {
                    let mut cred_issuer_meta = cred_issuer_meta.clone();
                    // hacky workaround to try old RFC
                    cred_issuer_meta.nonce_endpoint = None;

                    get_credential_with_proofs(
                        dpop_client,
                        cred_issuer_meta.clone(),
                        access_token.clone(),
                        credential_configuration_id.clone(),
                        credential_configuration.credential_format.clone(),
                        None,
                        CredentialProofs::Proofs(KeyProofsType::Jwt(proofs)),
                    )
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "failed to get cred (get_batch_credentials_with_dpop): {e:?}"
                        )
                    })?
                }
            };

            let c_nonce = credential.c_nonce.clone();
            let tokens = DeviceBoundTokens {
                access_token: device_bound_tokens.access_token.clone(),
                refresh_token: device_bound_tokens.refresh_token.clone(),
                c_nonce: c_nonce.clone(),
                dpop_key_reference: self.auth_key.key_reference(),
            };
            if let CredentialResponseType::Immediate { credential, .. } = &credential.credential {
                let credential = if let Value::Array(credentials) = credential {
                    credentials
                        .iter()
                        .filter_map(|a| {
                            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
                            // This specification defines the following parameters to be used inside this object:
                            // credential: REQUIRED. Contains one issued Credential. The encoding of the Credential depends on the Credential Format and MAY be a string or an object. Credential Formats expressed as binary data MUST be base64url-encoded and returned as a string. More details are defined in the Credential Format Profiles in Appendix A.
                            //
                            if let Some(cred) = a.get("credential") {
                                cred.as_str()
                            } else {
                                a.as_str()
                            }
                        })
                        .map(|payload| {
                            CredentialResult::CredentialType(Credential {
                                credential: match credential_type {
                                    CredentialType::SdJwt => {
                                        CredentialFormat::SdJwt(payload.to_string())
                                    }
                                    CredentialType::Mdoc => {
                                        CredentialFormat::Mdoc(payload.to_string())
                                    }
                                    CredentialType::BbsTermWise => {
                                        CredentialFormat::BbsTermWise(payload.to_string())
                                    }
                                    CredentialType::W3C => {
                                        CredentialFormat::W3C(payload.to_string())
                                    }
                                },
                            })
                        })
                        .collect()
                } else if let Value::String(payload) = credential {
                    vec![CredentialResult::CredentialType(Credential {
                        credential: match credential_type {
                            CredentialType::SdJwt => CredentialFormat::SdJwt(payload.to_string()),
                            CredentialType::Mdoc => CredentialFormat::Mdoc(payload.to_string()),
                            CredentialType::BbsTermWise => {
                                CredentialFormat::BbsTermWise(payload.to_string())
                            }
                            CredentialType::W3C => CredentialFormat::W3C(payload.to_string()),
                        },
                    })]
                } else {
                    vec![]
                };

                Ok(IssuedCredentials {
                    tokens,
                    credentials: credential,
                    subjects: subjects.into_iter().map(|a| a.signer.clone()).collect(),
                })
            } else if let CredentialResponseType::Deferred { transaction_id } =
                &credential.credential
            {
                Ok(IssuedCredentials {
                    tokens,
                    credentials: vec![CredentialResult::DeferredType(Deferred {
                        transaction_code: transaction_id.to_string(),
                        credential_configuration_id: credential_configuration_id.clone(),
                    })],
                    subjects: subjects.into_iter().map(|a| a.signer.clone()).collect(),
                })
            } else {
                Err(anyhow!("no credential type specified").into())
            }
        }
        pub async fn poll_deferred_credentials(
            self: &Arc<Self>,
            device_bound_tokens: DeviceBoundTokens,
            transaction_id: String,
        ) -> Result<IssuedCredentials, ApiError> {
            let cred_issuer_meta = {
                let meta = self.credential_issuer_metadata.lock()?;
                let Some(meta_data) = meta.as_ref() else {
                    return Err(anyhow!(
                        "Meta data is empty, have you tried initializing it first?"
                    )
                    .into());
                };
                meta_data.clone()
            };

            let dpop_client = self.dpop_client.lock()?.clone();
            let Some(access_token) = &device_bound_tokens.access_token else {
                return Err(anyhow!("Access token is empty").into());
            };
            let credential = try_get_deferred_credential(
                dpop_client,
                cred_issuer_meta,
                TokenResponse {
                    access_token: access_token.to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: None,
                    refresh_token: None,
                    scope: None,
                    c_nonce: None,
                    c_nonce_expires_in: None,
                },
                models::CredentialResponse {
                    credential: CredentialResponseType::Deferred {
                        transaction_id: transaction_id,
                    },
                    c_nonce: None,
                    c_nonce_expires_in: None,
                },
            )
            .await?;

            let tokens = DeviceBoundTokens {
                access_token: device_bound_tokens.access_token.clone(),
                refresh_token: device_bound_tokens.refresh_token.clone(),
                c_nonce: None,
                dpop_key_reference: self.auth_key.key_reference(),
            };

            if let CredentialResponseType::Immediate { credential, .. } = &credential.credential {
                let credential = if let Value::Array(credentials) = credential {
                    credentials
                        .iter()
                        .filter_map(|a| {
                            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
                            // This specification defines the following parameters to be used inside this object:
                            // credential: REQUIRED. Contains one issued Credential. The encoding of the Credential depends on the Credential Format and MAY be a string or an object. Credential Formats expressed as binary data MUST be base64url-encoded and returned as a string. More details are defined in the Credential Format Profiles in Appendix A.
                            //
                            if let Some(cred) = a.get("credential") {
                                cred.as_str()
                            } else {
                                a.as_str()
                            }
                        })
                        .filter_map(|payload| {
                            let Some(credential_type) =
                                resolve_credential_format_single(payload, None)
                            else {
                                return None;
                            };

                            Some(CredentialResult::CredentialType(Credential {
                                credential: match credential_type {
                                    CredentialType::SdJwt => {
                                        CredentialFormat::SdJwt(payload.to_string())
                                    }
                                    CredentialType::Mdoc => {
                                        CredentialFormat::Mdoc(payload.to_string())
                                    }
                                    CredentialType::BbsTermWise => {
                                        CredentialFormat::BbsTermWise(payload.to_string())
                                    }
                                    CredentialType::W3C => {
                                        CredentialFormat::W3C(payload.to_string())
                                    }
                                },
                            }))
                        })
                        .collect()
                } else if let Value::String(payload) = credential {
                    let credential_type =
                        if heidi_credentials_rust::sdjwt::decode_sdjwt(&payload).is_ok() {
                            CredentialType::SdJwt
                        } else if heidi_credentials_rust::mdoc::decode_mdoc(&payload).is_ok() {
                            CredentialType::Mdoc
                        } else if heidi_credentials_rust::bbs::decode_bbs(&payload).is_ok() {
                            CredentialType::BbsTermWise
                        } else {
                            return Err(anyhow!("no credential type specified").into());
                        };
                    vec![CredentialResult::CredentialType(Credential {
                        credential: match credential_type {
                            CredentialType::SdJwt => CredentialFormat::SdJwt(payload.to_string()),
                            CredentialType::Mdoc => CredentialFormat::Mdoc(payload.to_string()),
                            CredentialType::BbsTermWise => {
                                CredentialFormat::BbsTermWise(payload.to_string())
                            }
                            CredentialType::W3C => CredentialFormat::W3C(payload.to_string()),
                        },
                    })]
                } else {
                    vec![]
                };

                Ok(IssuedCredentials {
                    tokens,
                    credentials: credential,
                    subjects: vec![],
                })
            } else if let CredentialResponseType::Deferred {
                transaction_id: _transaction_id,
            } = &credential.credential
            {
                return Ok(IssuedCredentials {
                    tokens,
                    credentials: vec![],
                    subjects: vec![],
                });
            } else {
                Err(anyhow!("no credential type specified").into())
            }
        }

        /// Return N credentials for the n subjects, issuing every signature by itself (e.g. for SE device bound keys)
        pub async fn get_credential_with_dpop(
            self: &Arc<Self>,
            device_bound_tokens: DeviceBoundTokens,
            credential_type: CredentialType,
            subjects: Vec<Arc<SecureSubject>>,
            is_for_pre_authorized_code: bool,
        ) -> Result<IssuedCredentials, ApiError> {
            // get from scope
            let cred_issuer_meta = {
                let meta = self.credential_issuer_metadata.lock()?;
                let Some(meta_data) = meta.as_ref() else {
                    return Err(anyhow!(
                        "Meta data is empty, have you tried initializing it first?"
                    )
                    .into());
                };
                meta_data.clone()
            };
            let Some((credential_configuration_id, credential_configuration)) = cred_issuer_meta
                .credential_configurations_supported
                .iter()
                .find(|(_, value)| {
                    matches!(
                        (
                            &credential_type,
                            credential_formats::CredentialFormat::from(&value.credential_format)
                        ),
                        (
                            CredentialType::SdJwt,
                            credential_formats::CredentialFormat::VcIetfSdJwt
                        ) | (
                            CredentialType::Mdoc,
                            credential_formats::CredentialFormat::MsoMdoc
                        )
                    )
                })
            else {
                return Err(anyhow!("Selected format not supported").into());
            };

            // STEP 5: Exchange access token for credentials
            // let content_decryptor: Option<Box<dyn ContentDecryptor>> = None;
            let dpop_client = self.dpop_client.lock()?.clone();

            let Some(access_token) = device_bound_tokens.access_token.as_ref() else {
                return Err(anyhow!("No accesstoken").into());
            };

            let credential = match get_credential(
                dpop_client.clone(),
                subjects.clone(),
                cred_issuer_meta.clone(),
                access_token.clone(),
                device_bound_tokens.c_nonce.clone(),
                credential_configuration_id.clone(),
                credential_configuration.credential_format.clone(),
                None,
                self.oidc_settings.client_id.clone(),
                is_for_pre_authorized_code,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => {
                    let mut cred_issuer_meta = cred_issuer_meta.clone();
                    cred_issuer_meta.nonce_endpoint = None;
                    get_credential(
                        dpop_client.clone(),
                        subjects.clone(),
                        cred_issuer_meta.clone(),
                        access_token.clone(),
                        device_bound_tokens.c_nonce.clone(),
                        credential_configuration_id.clone(),
                        credential_configuration.credential_format.clone(),
                        None,
                        self.oidc_settings.client_id.clone(),
                        is_for_pre_authorized_code,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to get cred: {e:?}"))?
                }
            };
            let c_nonce = credential.c_nonce.clone();
            let tokens = DeviceBoundTokens {
                access_token: device_bound_tokens.access_token.clone(),
                refresh_token: device_bound_tokens.refresh_token.clone(),
                c_nonce: c_nonce.clone(),
                dpop_key_reference: self.auth_key.key_reference(),
            };
            if let CredentialResponseType::Immediate { credential, .. } = &credential.credential {
                let credential = if let Value::Array(credentials) = credential {
                    credentials
                        .iter()
                        .filter_map(|a| {
                            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
                            // This specification defines the following parameters to be used inside this object:
                            // credential: REQUIRED. Contains one issued Credential. The encoding of the Credential depends on the Credential Format and MAY be a string or an object. Credential Formats expressed as binary data MUST be base64url-encoded and returned as a string. More details are defined in the Credential Format Profiles in Appendix A.
                            //
                            if let Some(cred) = a.get("credential") {
                                cred.as_str()
                            } else {
                                a.as_str()
                            }
                        })
                        .map(|payload| {
                            CredentialResult::CredentialType(Credential {
                                credential: match credential_type {
                                    CredentialType::SdJwt => {
                                        CredentialFormat::SdJwt(payload.to_string())
                                    }
                                    CredentialType::Mdoc => {
                                        CredentialFormat::Mdoc(payload.to_string())
                                    }
                                    CredentialType::BbsTermWise => {
                                        CredentialFormat::BbsTermWise(payload.to_string())
                                    }
                                    CredentialType::W3C => {
                                        CredentialFormat::W3C(payload.to_string())
                                    }
                                },
                            })
                        })
                        .collect()
                } else if let Value::String(payload) = credential {
                    vec![CredentialResult::CredentialType(Credential {
                        credential: match credential_type {
                            CredentialType::SdJwt => CredentialFormat::SdJwt(payload.to_string()),
                            CredentialType::Mdoc => CredentialFormat::Mdoc(payload.to_string()),
                            CredentialType::BbsTermWise => {
                                CredentialFormat::BbsTermWise(payload.to_string())
                            }
                            CredentialType::W3C => CredentialFormat::W3C(payload.to_string()),
                        },
                    })]
                } else {
                    vec![]
                };

                Ok(IssuedCredentials {
                    tokens,
                    credentials: credential,
                    subjects: subjects
                        .into_iter()
                        .map(|subject| subject.signer.clone())
                        .collect(),
                })
            } else if let CredentialResponseType::Deferred { transaction_id } =
                &credential.credential
            {
                Ok(IssuedCredentials {
                    tokens,
                    credentials: vec![CredentialResult::DeferredType(Deferred {
                        transaction_code: transaction_id.to_string(),
                        credential_configuration_id: credential_configuration_id.clone(),
                    })],
                    subjects: subjects
                        .into_iter()
                        .map(|subject| subject.signer.clone())
                        .collect(),
                })
            } else {
                Err(anyhow!("no credential type specified").into())
            }
        }

        /// Uses the finalize_url returned by the `Ausweis2SDK` to first fetch a access_token with DPoP
        pub async fn token_request_with_dpop(
            self: &Arc<Self>,
            finish_url: String,
            token_endpoint: Option<String>,
        ) -> Result<DeviceBoundTokens, ApiError> {
            let dpop_client = self.dpop_client.lock()?.clone();
            let request = dpop_client.get(finish_url).build()?;
            let result = dpop_client.execute(request).await?;

            //redirect uri contains code and state
            let location_header: Url = result
                .headers()
                .get("location")
                .context("the response did not include a location header")?
                .to_str()
                .context("The location header value had invalid utf8 characters")?
                .parse()
                .context("the location header was a invalid url")?;

            let code = location_header
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.to_string())
                .context("We didn't find a code in the redirect uri")?;

            let auth_state = {
                let state = lock!(self.auth_state => |e|  { Err(anyhow!("{e}").into()) });
                let Some(state) = state.as_ref().cloned() else {
                    return Err(anyhow!(
                        "No auth state; be sure to call one of the init functions first"
                    )
                    .into());
                };
                state.clone()
            };

            let Some(token_endpoint) = token_endpoint.and_then(|url| Url::parse(&url).ok()) else {
                return Err(anyhow!("No token URL").into());
            };
            let dpop_client = self.dpop_client.lock()?.clone();

            let token_response = {
                dpop_client
                    .post(token_endpoint)
                    .form(&TokenRequest::AuthorizationCode {
                        code: code.to_string(),
                        code_verifier: Some(auth_state.code_verifier.clone()),
                        redirect_uri: Some(self.oidc_settings.redirect_url.clone()),
                        client_id: Some(self.oidc_settings.client_id.clone()),
                    })
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<TokenResponse>()
                    .await?
            };

            Ok(DeviceBoundTokens {
                access_token: Some(token_response.access_token.clone()),
                refresh_token: token_response.refresh_token.clone(),
                c_nonce: token_response.c_nonce.clone(),
                dpop_key_reference: self.auth_key.key_reference(),
            })
        }

        /// Refresh the tokens
        pub async fn refresh_token(
            self: &Arc<Self>,
            tokens: DeviceBoundTokens,
            token_endpoint: Option<String>,
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
            dpop_signing_alg_values_supported: Option<Vec<String>>,
            with_hsm_wallet_attestation: Option<Arc<HsmSupportObject>>,
        ) -> Result<DeviceBoundTokens, ApiError> {
            let Some(refresh_token) = tokens.refresh_token else {
                return Err(anyhow!("No refresh token").into());
            };
            let Some(token_endpoint) = token_endpoint.and_then(|url| Url::parse(&url).ok()).clone()
            else {
                return Err(anyhow!("No token URL").into());
            };

            let client_attestation = self
                .get_optional_client_attestation(
                    with_hsm_wallet_attestation,
                    token_endpoint_auth_methods_supported,
                )
                .await?;

            let use_dpop = can_use_dpop(dpop_signing_alg_values_supported, self.auth_key.alg())?;
            let client = if use_dpop {
                let dpop_client = self.dpop_client.lock()?.clone();
                (*dpop_client).clone()
            } else {
                self.client.clone()
            };

            let refresh_request = build_refresh_request(
                &client,
                token_endpoint,
                self.oidc_settings.client_id.clone(),
                refresh_token.clone(),
                client_attestation,
            )?;
            let token_response = refresh_request
                .send()
                .await?
                .error_for_status()?
                .json::<TokenResponse>()
                .await?;
            let new_token_set = DeviceBoundTokens {
                access_token: Some(token_response.access_token),
                refresh_token: token_response.refresh_token.or(Some(refresh_token)),
                c_nonce: token_response.c_nonce,
                dpop_key_reference: tokens.dpop_key_reference,
            };

            Ok(new_token_set)
        }

        pub async fn get_credential_offer_auth_type(
            self: Arc<Self>,
            offer: &str,
        ) -> Result<CredentialOfferAuthType, ApiError> {
            let cred_offer = resolve_credential_offer(offer, &self.client).await?;
            self.get_credential_offer_auth_type_with_credential_offer(cred_offer)
                .await
        }

        pub async fn get_credential_offer_auth_type_with_credential_offer_json(
            self: Arc<Self>,
            cred_offer: String,
        ) -> Result<CredentialOfferAuthType, ApiError> {
            let cred_offer: CredentialOfferParameters = serde_json::from_str(&cred_offer)?;
            self.get_credential_offer_auth_type_with_credential_offer(cred_offer)
                .await
        }

        // Initialize the issuance process and return information about the necessary authorization
        // step before finalizing the issuance.
        // - parse/resolve the offer parameters
        // - fetch metadata from the credential issuer
        // - Unless a pre-authorized code is available from the offer, fetch the authorization server metadata and prepare the authorization request, and return it as URL:
        //   - if PAR is available, send the pushed authorization request. The URI of the registered
        //     request is returned as part of the request URL.
        pub async fn initialize_issuance(
            self: Arc<Self>,
            offer: &str,
            code_challenge_methods_supported: Option<Vec<String>>,
            first_party_usage: bool,
            pushed_authorization_request_endpoint: Option<String>,
            authorization_endpoint: Option<String>,
            authorization_challenge_endpoint: Option<String>,
            with_hsm_wallet_attestation: Option<Arc<Hsm>>,
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
        ) -> Result<AuthorizationStep, ApiError> {
            let cred_offer = resolve_credential_offer(offer, &self.client).await?;
            self.initialize_issuance_with_credential_offer(
                cred_offer,
                code_challenge_methods_supported,
                first_party_usage,
                pushed_authorization_request_endpoint,
                authorization_endpoint,
                authorization_challenge_endpoint,
                with_hsm_wallet_attestation,
                token_endpoint_auth_methods_supported,
            )
            .await
        }

        pub async fn initialize_issuance_with_credential_offer_json(
            self: Arc<Self>,
            cred_offer: String,
            code_challenge_methods_supported: Option<Vec<String>>,
            first_party_usage: bool,
            pushed_authorization_request_endpoint: Option<String>,
            authorization_endpoint: Option<String>,
            authorization_challenge_endpoint: Option<String>,
            with_hsm_wallet_attestation: Option<Arc<Hsm>>,
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
        ) -> Result<AuthorizationStep, ApiError> {
            let cred_offer: CredentialOfferParameters = serde_json::from_str(&cred_offer)?;
            self.initialize_issuance_with_credential_offer(
                cred_offer,
                code_challenge_methods_supported,
                first_party_usage,
                pushed_authorization_request_endpoint,
                authorization_endpoint,
                authorization_challenge_endpoint,
                with_hsm_wallet_attestation,
                token_endpoint_auth_methods_supported,
            )
            .await
        }

        /// Continues the authorization_challenge
        /// In our cases this should always succeed.
        pub async fn continue_authorization(
            self: Arc<Self>,
            auth_session: String,
            scope: String,
            authorization_challenge_endpoint: Option<String>,
            presentation_during_issuance_session: Option<String>,
        ) -> Result<AuthorizationStep, ApiError> {
            let endpoint = authorization_challenge_endpoint
                .and_then(|url| Url::parse(&url).ok())
                .clone()
                .ok_or(ApiError::from(anyhow::anyhow!(
                    "no authorization-challenge endpoint"
                )))?
                .clone();
            let client = self.dpop_client.lock()?.clone();
            let challenge_auth_request = client.post(endpoint);
            let mut params = vec![
                ("client_id", self.oidc_settings.client_id.as_str()),
                ("auth_session", auth_session.as_str()),
            ];
            if let Some(inner) = presentation_during_issuance_session.as_ref() {
                params.push(("presentation_during_issuance_session", inner.as_str()));
            }
            params.push(("scope", scope.as_str()));
            let result = challenge_auth_request.form(&params).send().await?;
            // if it is a bad request, we must parse the json to
            // check what needs to be done later
            if result.status() == StatusCode::BAD_REQUEST {
                let error: serde_json::Value = result.json().await?;
                // we expect a presentation
                let presentation = error
                    .get("presentation")
                    .and_then(|v| v.as_str())
                    .ok_or(ApiError::from(anyhow::anyhow!("no presentation found")))?
                    .to_string();
                let auth_session = error
                    .get("auth_session")
                    .and_then(|a| a.as_str())
                    .map(|a| a.to_string())
                    .unwrap_or(auth_session);
                return Ok(AuthorizationStep::WithPresentation {
                    presentation,
                    auth_session,
                    scope,
                });
            } else {
                let code_object: serde_json::Value = result.json().await?;
                if let Some(code) = code_object
                    .get("authorization_code")
                    .and_then(|a| a.as_str())
                {
                    return Ok(AuthorizationStep::Finished {
                        code: code.to_string(),
                    });
                } else {
                    return Err(ApiError::from(anyhow::anyhow!("No auth codde")));
                }
            }
        }

        pub async fn finalize_issuance(
            self: Arc<Self>,
            code: Option<String>,
            tx_code: Option<String>,
            num_credentials_per_type: u32,
            signer_factory: Arc<dyn SignerFactory>,
            dpop_signing_alg_values_supported: Option<Vec<String>>,
            token_endpoint: Option<String>,
            is_for_pre_authorized_code: bool,
        ) -> Result<IssuedCredentials, ApiError> {
            // Determine if authorization server supports DPoP or not
            let use_dpop = can_use_dpop(dpop_signing_alg_values_supported, self.auth_key.alg())?;

            // Initialize the wallet either with the regular client or the DPoP client

            let client = if use_dpop {
                let dpop_client = self.dpop_client.lock()?.clone();
                dpop_client
            } else {
                Arc::new(self.client.clone())
            };

            let token_response = {
                let pre_authorized_code = self.pre_authorized_code.lock()?.clone();

                if let Some(pre_authorized_code) = pre_authorized_code {
                    let meta_data = {
                        let Ok(meta_data) = self.credential_issuer_metadata.lock() else {
                            return Err(anyhow::anyhow!("").into());
                        };
                        let Some(meta_data) = meta_data.as_ref() else {
                            return Err(anyhow::anyhow!("").into());
                        };
                        meta_data.clone()
                    };

                    let Some(token_endpoint) = token_endpoint
                        .and_then(|url| Url::parse(&url).ok())
                        .or_else(|| meta_data.token_endpoint.and_then(|a| Url::parse(&a).ok()))
                    else {
                        return Err(anyhow!("No token endpoint").into());
                    };

                    // TODO: add client attestation here
                    // TODO Workaround for now, as the issuer expects the client_id for the Pre-Authorized Code Token request, even though it shouldn't
                    let mut mutable_token_endpoint = token_endpoint.clone();
                    let token_endpoint_with_client_id = mutable_token_endpoint
                        .query_pairs_mut()
                        .append_pair("client_id", &self.oidc_settings.client_id)
                        .finish()
                        .clone();

                    get_access_token(
                        client.clone(),
                        token_endpoint_with_client_id,
                        TokenRequest::PreAuthorizedCode {
                            pre_authorized_code: pre_authorized_code.pre_authorized_code.clone(),
                            tx_code,
                        },
                    )
                    .await
                    .map_err(|e| match e.downcast_ref::<ErrorDetails>() {
                        Some(e) => {
                            let desc = e.error_description.to_lowercase();
                            if e.status.as_u16() == 400
                                && (desc.contains("transaction code") || desc.contains("tx_code"))
                            {
                                ApiError::Credential(CredentialError::InvalidTransactionCode)
                            } else {
                                ApiError::Backend(BackendError::Network(NetworkError::Response(
                                    format!("{e}"),
                                )))
                            }
                        }
                        _ => e.into(),
                    })?
                } else if let Some(auth_code) = code {
                    let auth_state = {
                        let state = self.auth_state.lock()?;
                        let Some(state) = state.as_ref().cloned() else {
                            return Err(anyhow::anyhow!("").into());
                        };
                        state.clone()
                    };

                    let Some(token_endpoint) =
                        token_endpoint.and_then(|url| Url::parse(&url).ok()).clone()
                    else {
                        return Err(anyhow!("No token endpoint").into());
                    };

                    get_access_token(
                        client.clone(),
                        token_endpoint,
                        TokenRequest::AuthorizationCode {
                            code: auth_code,
                            code_verifier: Some(auth_state.code_verifier.clone()),
                            redirect_uri: Some(self.oidc_settings.redirect_url.clone()),
                            client_id: Some(self.oidc_settings.client_id.clone()),
                        },
                    )
                    .await
                    .map_err(|e| match e.downcast_ref::<ErrorDetails>() {
                        Some(e) => {
                            let desc = e.error_description.to_lowercase();
                            if e.status.as_u16() == 400
                                && (desc.contains("transaction code") || desc.contains("tx_code"))
                            {
                                ApiError::Credential(CredentialError::InvalidTransactionCode)
                            } else {
                                ApiError::Backend(BackendError::Network(NetworkError::Response(
                                    format!("{e}"),
                                )))
                            }
                        }
                        _ => e.into(),
                    })?
                } else {
                    return Err(anyhow!("Neither pre-authorized code nor code provided").into());
                }
            };
            log_debug!("ISSUANCE", &format!("{:?}", token_response));

            self.get_credentials(
                client.clone(),
                token_response,
                num_credentials_per_type,
                signer_factory,
                is_for_pre_authorized_code,
            )
            .await
        }

        // Request issuance of more credentials, after "finalize_issuance" returned a first set of
        // credentials. Typcially, tokens is the result of refresh_token().
        pub async fn supplement_issuance(
            self: &Arc<Self>,
            tokens: DeviceBoundTokens,
            num_credentials_per_type: u32,
            dpop_signing_alg_values_supported: Option<Vec<String>>,
            signer_factory: Arc<dyn SignerFactory>,
            is_for_pre_authorized_code: bool,
        ) -> Result<IssuedCredentials, ApiError> {
            let tokens = TokenResponse {
                access_token: tokens.access_token.ok_or(anyhow!("no access token"))?,
                token_type: String::new(),
                expires_in: None, // lost
                refresh_token: tokens.refresh_token,
                scope: None, // ?
                c_nonce: tokens.c_nonce,
                c_nonce_expires_in: None, // lost
            };

            let use_dpop = can_use_dpop(dpop_signing_alg_values_supported, self.auth_key.alg())?;

            let client = if use_dpop {
                let dpop_client = self.dpop_client.lock()?.clone();
                dpop_client
            } else {
                Arc::new(self.client.clone())
            };

            self.get_credentials(
                client,
                tokens,
                num_credentials_per_type,
                signer_factory,
                is_for_pre_authorized_code,
            )
            .await
        }
    }

    impl OID4VciIssuance {
        pub async fn get_credential_offer_auth_type_with_credential_offer(
            self: Arc<Self>,
            cred_offer: CredentialOfferParameters,
        ) -> Result<CredentialOfferAuthType, ApiError> {
            if let Some(pre_authorized_code) = cred_offer
                .grants
                .as_ref()
                .and_then(|grants| grants.pre_authorized_code.clone())
            {
                let mut pre_code = self
                    .pre_authorized_code
                    .lock()
                    .map_err(|_| ApiError::from(anyhow::anyhow!("lock error")))?;

                *pre_code = Some(pre_authorized_code.clone());

                if let Some(tx_code) = pre_authorized_code.tx_code {
                    let numeric = !tx_code
                        .input_mode
                        .is_some_and(|input_mode| input_mode == InputMode::Text);
                    return Ok(CredentialOfferAuthType::TransactionCode {
                        numeric,
                        length: tx_code.length,
                        description: tx_code.description,
                    });
                } else {
                    return Ok(CredentialOfferAuthType::PreAuthorized);
                }
            }

            let credential_issuer_url = Url::parse(&cred_offer.credential_issuer.clone())
                .map_err(|e| anyhow::anyhow!(e))?;
            let credential_issuer_metadata = self
                .metadata_fetcher
                .get_credential_issuer_metadata(credential_issuer_url.clone())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            {
                let mut cred_meta = self
                    .credential_issuer_metadata
                    .lock()
                    .map_err(|_| ApiError::from(anyhow::anyhow!("lock error")))?;
                *cred_meta = Some(credential_issuer_metadata.clone());
            }

            //TODO: don't unwrap url parse
            let auth_server = get_authorization_server(
                &credential_issuer_metadata
                    .authorization_servers
                    .iter()
                    .map(|a| Url::parse(a).unwrap())
                    .collect::<Vec<Url>>(),
                &cred_offer,
            )
            .map_err(|_| ApiError::from(anyhow::anyhow!("server selection error")))?;

            let auth_metadata = self
                .metadata_fetcher
                .get_authorization_server_metadata(auth_server.to_owned())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if auth_metadata.authorization_challenge_endpoint.is_some() {
                return Ok(CredentialOfferAuthType::Presentation);
            }

            Ok(CredentialOfferAuthType::Authorization)
        }

        async fn initialize_issuance_with_credential_offer(
            self: Arc<Self>,
            cred_offer: CredentialOfferParameters,
            code_challenge_methods_supported: Option<Vec<String>>,
            first_party_usage: bool,
            pushed_authorization_request_endpoint: Option<String>,
            authorization_endpoint: Option<String>,
            authorization_challenge_endpoint: Option<String>,
            with_hsm_wallet_attestation: Option<Arc<Hsm>>,
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
        ) -> Result<AuthorizationStep, ApiError> {
            // let credential_issuer_url = cred_offer.credential_issuer.clone();
            let credential_issuer_url = Url::parse(&cred_offer.credential_issuer).map_err(|e| {
                ApiError::Generic(GenericError::Inner(crate::error::InnerError::Anyhow(
                    anyhow!(e),
                )))
            })?;
            let credential_issuer_metadata = self
                .metadata_fetcher
                .get_credential_issuer_metadata(credential_issuer_url.clone())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            {
                let mut cred_meta = self.credential_issuer_metadata.lock()?;
                *cred_meta = Some(credential_issuer_metadata.clone());
            }

            // Select all supported credential configurations and as a byproduct determine necessary "scopes" for authorization
            let mut scopes = HashSet::new();
            let mut chosen_cred_config_ids = Vec::new();
            for id in cred_offer.credential_configuration_ids.iter() {
                if let Some(config) = credential_issuer_metadata
                    .credential_configurations_supported
                    .get(id)
                {
                    if !is_supported_credential_configuration(config) {
                        continue;
                    }
                    chosen_cred_config_ids.push(id);
                    if let Some(scope) = &config.scope {
                        scopes.insert(scope.clone());
                    }
                }
            }
            {
                let mut ccf = lock!(self.chosen_cred_config_ids => |_e| {
                    Err(anyhow!("poison").into())
                });
                *ccf = chosen_cred_config_ids.into_iter().cloned().collect();
            }
            let scope: String = scopes.into_iter().collect::<Vec<_>>().join(" ");

            if let Some(pre_authorized_code) = cred_offer
                .grants
                .as_ref()
                .and_then(|grants| grants.pre_authorized_code.clone())
            {
                let mut pre_code = self.pre_authorized_code.lock()?;

                *pre_code = Some(pre_authorized_code.clone());
                if let Some(tx_code) = pre_authorized_code.tx_code {
                    let numeric = !tx_code
                        .input_mode
                        .is_some_and(|input_mode| input_mode == InputMode::Text);
                    return Ok(AuthorizationStep::EnterTransactionCode {
                        numeric,
                        length: tx_code.length,
                        description: tx_code.description,
                    });
                }
                return Ok(AuthorizationStep::None);
            }

            let code_challenge_method =
                get_supported_code_challenge_method(code_challenge_methods_supported)?;
            let code_verifier = generate_code_verifier();
            let code_challenge = generate_code_challenge(&code_verifier, &code_challenge_method);
            let state = generate_code_verifier();
            {
                let mut auth_state = self.auth_state.lock()?;
                *auth_state = Some(AuthState {
                    state: state.clone(),
                    code_verifier,
                });
            }
            let grant_authorization_code_issuer_state = cred_offer.grants.as_ref().and_then(|g| {
                g.authorization_code
                    .as_ref()
                    .and_then(|a| a.issuer_state.as_ref())
            });

            if first_party_usage {
                return self
                    .handle_first_party(
                        authorization_challenge_endpoint,
                        code_challenge,
                        code_challenge_method,
                        state,
                        scope,
                        grant_authorization_code_issuer_state,
                        None,
                    )
                    .await;
            }

            if let Some(par_url) = pushed_authorization_request_endpoint
                .as_ref()
                .and_then(|url| Url::parse(url).ok())
            {
                let client_attestation = self
                    .get_optional_client_attestation(
                        with_hsm_wallet_attestation
                            .map(|hsm| Arc::new(HsmSupportObject::with_hsm(hsm))),
                        token_endpoint_auth_methods_supported,
                    )
                    .await?;
                let par = PushedAuthorizationRequest {
                    response_type: RESPONSE_TYPE_CODE.to_string(),
                    client_id: self.oidc_settings.client_id.clone(),
                    redirect_uri: Some(self.oidc_settings.redirect_url.clone()),
                    scope: Some(scope.clone()),
                    state: Some(state.clone()),
                    code_challenge: Some(code_challenge.clone()),
                    code_challenge_method: Some(code_challenge_method.clone()),
                    issuer_state: grant_authorization_code_issuer_state.cloned(),
                };

                let result = self
                    .metadata_fetcher
                    .push_authorization_request(par_url.clone(), par, client_attestation)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to push authorization requewst: {e}"))?;

                {
                    let mut arf = self.authorization_request_reference.lock()?;
                    *arf = Some(result.clone());
                }

                let mut endpoint = authorization_endpoint
                    .as_ref()
                    .and_then(|url| Url::parse(url).ok())
                    .ok_or(ApiError::from(anyhow::anyhow!("no authorization endpoint")))?
                    .clone();
                let mut query_parameters = endpoint.query_pairs_mut();
                query_parameters.append_pair("client_id", &self.oidc_settings.client_id);
                query_parameters.append_pair("request_uri", result.request_uri.as_str());
                Ok(AuthorizationStep::BrowseUrl {
                    url: query_parameters.finish().to_string(),
                    auth_session: None,
                })
            } else {
                // Return URL for auth without PAR
                let mut endpoint = authorization_endpoint
                    .as_ref()
                    .and_then(|url| Url::parse(url).ok())
                    .ok_or(ApiError::from(anyhow::anyhow!("no authorization endpoint")))?
                    .clone();
                let mut query_parameters = endpoint.query_pairs_mut();
                query_parameters.append_pair("response_type", RESPONSE_TYPE_CODE);
                query_parameters.append_pair("client_id", &self.oidc_settings.client_id);
                query_parameters.append_pair("redirect_uri", &self.oidc_settings.redirect_url);
                query_parameters.append_pair("scope", &scope);
                query_parameters.append_pair("state", &state);
                query_parameters.append_pair("code_challenge", &code_challenge);
                query_parameters.append_pair("code_challenge_method", &code_challenge_method);
                if let Some(issuer_state) = grant_authorization_code_issuer_state {
                    query_parameters.append_pair("issuer_state", issuer_state);
                }
                Ok(AuthorizationStep::BrowseUrl {
                    url: query_parameters.finish().to_string(),
                    auth_session: None,
                })
            }
        }

        async fn handle_first_party(
            self: &Arc<Self>,
            authorization_challenge_endpoint: Option<String>,
            code_challenge: String,
            code_challenge_method: String,
            _state: String,
            scope: String,
            issuer_state: Option<&String>,
            auth_session: Option<&String>,
        ) -> Result<AuthorizationStep, ApiError> {
            // do auth request and return the 400

            let endpoint = authorization_challenge_endpoint
                .ok_or(ApiError::from(anyhow::anyhow!(
                    "no authorization challenge endpoint"
                )))?
                .clone();
            let client = self.dpop_client.lock()?.clone();
            let challenge_auth_request = client.post(endpoint);
            let mut parameters = vec![
                ("client_id", self.oidc_settings.client_id.as_str()),
                ("code_challenge", code_challenge.as_str()),
                ("code_challenge_method", code_challenge_method.as_str()),
                ("scope", scope.as_str()),
                ("response_type", "code"),
            ];
            if let Some(issuer_state) = issuer_state {
                parameters.push(("issuer_state", issuer_state.as_str()))
            }
            if let Some(auth_session) = auth_session {
                parameters.push(("auth_session", auth_session.as_str()))
            }
            let result = challenge_auth_request.form(&parameters).send().await?;
            // if it is a bad request, we must parse the json to
            // check what needs to be done later
            if result.status() == StatusCode::BAD_REQUEST {
                let error: serde_json::Value = result.json().await?;
                let msg = error
                    .get("error")
                    .and_then(|v| v.as_str())
                    .ok_or(ApiError::from(anyhow::anyhow!("no presentation found")))?;
                if msg != "insufficient_authorization" {
                    //we have something not expected, an error or so.
                    return Err(ApiError::from(anyhow::anyhow!("State error, {}", msg)));
                }
                let auth_session = error
                    .get("auth_session")
                    .and_then(|a| a.as_str())
                    .map(|a| a.to_string())
                    .or(auth_session.map(|a| a.to_string()));
                return self.handle_next_step(error, auth_session, scope);
            }
            if result.status() == StatusCode::OK {
                let body: serde_json::Value = result.json().await?;
                let code = body
                    .get("authorization_code")
                    .and_then(|a| a.as_str())
                    .ok_or(ApiError::from(anyhow::anyhow!("no auth code")))?;
                return Ok(AuthorizationStep::Finished {
                    code: code.to_string(),
                });
            }
            Err(ApiError::from(anyhow::anyhow!("Unexpected return value")))
        }
        fn handle_next_step(
            self: &Arc<Self>,
            body: serde_json::Value,
            auth_session: Option<String>,
            scope: String,
        ) -> Result<AuthorizationStep, ApiError> {
            if let (Some(presentation), Some(auth_session)) = (
                body.get("presentation").and_then(|v| v.as_str()),
                auth_session.clone(),
            ) {
                Ok(AuthorizationStep::WithPresentation {
                    presentation: presentation.to_string(),
                    auth_session: auth_session.to_string(),
                    scope,
                })
            } else if let Some(browse) = body.get("open_browser").and_then(|v| v.as_str()) {
                Ok(AuthorizationStep::BrowseUrl {
                    url: browse.to_string(),
                    auth_session,
                })
            } else {
                Err(ApiError::from(anyhow::anyhow!("Unknown auth method")))
            }
        }
    }

    async fn _try_extract_code(
        client: &Arc<ClientWithMiddleware>,
        result: reqwest::Response,
    ) -> Result<AuthorizationStep, ApiError> {
        let l = result
            .headers()
            .get("location")
            .ok_or(ApiError::from(anyhow::anyhow!("no presentation found")))?
            .to_str()
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string();
        let url: Url = l
            .parse()
            .map_err(|_| anyhow::anyhow!("Could not parse url"))?;
        if let Some((_, code)) = url.query_pairs().find(|(key, _)| key == "code") {
            return Ok(AuthorizationStep::Finished {
                code: code.to_string(),
            });
        }
        let result = client.get(url).send().await?;
        let l = result
            .headers()
            .get("location")
            .ok_or(ApiError::from(anyhow::anyhow!("no presentation found")))?
            .to_str()
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string();
        let url: Url = l
            .parse()
            .map_err(|_| anyhow::anyhow!("Could not parse url"))?;
        if let Some((_, code)) = url.query_pairs().find(|(key, _)| key == "code") {
            Ok(AuthorizationStep::Finished {
                code: code.to_string(),
            })
        } else {
            Err(anyhow::anyhow!("No code").into())
        }
    }

    impl OID4VciIssuance {
        pub async fn get_credentials(
            self: &Arc<Self>,
            client: Arc<ClientWithMiddleware>,
            tokens: TokenResponse,
            num_credentials_per_type: u32,
            signer_factory: Arc<dyn SignerFactory>,
            is_for_pre_authorized_code: bool,
        ) -> Result<IssuedCredentials, ApiError> {
            // get from scope
            let cred_config_ids = {
                let cred_config_ids = self.chosen_cred_config_ids.lock()?;
                let cred_config_ids = &*cred_config_ids;
                if cred_config_ids.is_empty() {
                    return Err(anyhow::anyhow!("no configuration chosen").into());
                };
                cred_config_ids.clone()
            };
            log_warn!("ISSUANCE", &format!("{cred_config_ids:?}"));
            let credential_issuer_metadata = self
                .credential_issuer_metadata
                .lock()?
                .clone()
                .ok_or(anyhow!("no metadata"))?;
            log_warn!("ISSUANCE", &format!("{credential_issuer_metadata:?}"));
            // Quirk: issuer.eudiw.dev does not support "proofs"
            // Request only 1 credential in each request, but make num_credentials_per_type requests for each credential config id.
            let (batch_size, cred_config_ids) = if credential_issuer_metadata
                .credential_issuer
                .as_str()
                .starts_with("https://issuer.eudiw.dev")
            {
                let num_cred_config_ids = cred_config_ids.len();
                (
                    1,
                    cred_config_ids
                        .into_iter()
                        .cycle()
                        .take(num_cred_config_ids * num_credentials_per_type as usize)
                        .collect(),
                )
            } else {
                (num_credentials_per_type as usize, cred_config_ids)
            };
            log_warn!("ISSUANCE", &format!("{batch_size:?}"));

            let mut credentials: Vec<CredentialResult> = vec![];
            let mut subjects = vec![];
            let mut token_response = tokens;
            for cred_config_id in &cred_config_ids {
                let deferred_issuance;
                let cred_config = credential_issuer_metadata
                    .credential_configurations_supported
                    .get(cred_config_id)
                    .ok_or(anyhow!("No configuration found"))?;
                // if we have a bbs force issuance of just one credential
                let batch_size = if matches!(
                    credential_formats::CredentialFormat::from(&cred_config.credential_format),
                    credential_formats::CredentialFormat::ZkpVc
                ) {
                    1
                } else {
                    batch_size
                };
                let key_attestations_required = get_key_attestations_required(cred_config);
                dbg!(key_attestations_required);
                log_warn!("ISSUANCE", &format!("{key_attestations_required:?}"));

                // Check if cryptographic binding is required
                let requires_cryptographic_binding = is_cryptographic_binding_required(cred_config);
                log_warn!(
                    "ISSUANCE",
                    &format!(
                        "Cryptographic binding required: {}",
                        requires_cryptographic_binding
                    )
                );

                let key_type = if !requires_cryptographic_binding {
                    // Claim-based binding: use no keys (no biometric prompt)
                    log_warn!(
                        "ISSUANCE",
                        "Using no key for claim-based binding (no biometric prompt)"
                    );
                    KeyType::None
                } else {
                    // Standard cryptographic binding
                    get_appropriate_key_type(key_attestations_required)
                };
                let curr_subjects: Vec<_> = if key_type == KeyType::None {
                    vec![]
                } else {
                    std::iter::repeat_with(|| signer_factory.new_signer(key_type))
                        .take(batch_size)
                        .collect()
                };
                let credential_response = self
                    .get_credentials_one_config(
                        client.clone(),
                        &curr_subjects,
                        key_attestations_required,
                        credential_issuer_metadata.clone(),
                        cred_config_id.clone(),
                        cred_config.credential_format.clone(),
                        &token_response,
                        key_type,
                        is_for_pre_authorized_code,
                    )
                    .await?;
                log_warn!("ISSUANCE", &format!("fetch credentials"));

                match credential_response {
                    CredentialResponseTypeInternal::Immediate(credential_response) => {
                        let cred_mapped = credential_response
                            .credentials
                            .into_iter()
                            .map(|credential| {
                                CredentialResult::CredentialType(Credential { credential })
                            })
                            .collect::<Vec<CredentialResult>>();
                        credentials.extend(cred_mapped);
                        token_response.c_nonce = credential_response.c_nonce;
                        deferred_issuance = false;
                    }
                    CredentialResponseTypeInternal::Deferred(deferred) => {
                        credentials.push(CredentialResult::DeferredType(deferred));
                        deferred_issuance = true;
                    }
                }
                subjects.extend(curr_subjects);
                if deferred_issuance {
                    break;
                }
            }
            log_warn!("ISSUANCE", &format!("success"));
            Ok(IssuedCredentials {
                tokens: DeviceBoundTokens {
                    access_token: Some(token_response.access_token.clone()),
                    refresh_token: token_response.refresh_token.clone(),
                    c_nonce: token_response.c_nonce.clone(),
                    dpop_key_reference: self.auth_key.key_reference(),
                },
                credentials,
                subjects,
            })
        }

        // Fetch a single credential configuration from the credential endpoint.
        #[allow(clippy::too_many_arguments)]
        async fn get_credentials_one_config(
            &self,
            client: Arc<ClientWithMiddleware>,
            subjects: &Vec<Arc<dyn NativeSigner>>,
            key_attestations_required: Option<&KeyAttestationMetadata>,
            credential_issuer_metadata: CredentialIssuerMetadata,
            credential_configuration_id: String,
            // credential_format only kept here for backwards compatibility with pre-draft15 issuer. Remove.
            credential_format: Value,
            token_response: &TokenResponse,
            key_type: KeyType,
            is_for_pre_authorized_code: bool,
        ) -> Result<CredentialResponseTypeInternal, ApiError> {
            // STEP 5: Exchange access token for credentials
            let content_decryptor: Option<Box<dyn ContentDecryptor>> =
                match &credential_issuer_metadata.credential_response_encryption {
                    Some(CredentialResponseEncryption {
                        alg_values_supported,
                        enc_values_supported,
                        encryption_required: _,
                    }) => {
                        let decryption_parameters = EncryptionParameters::new_decryptor(
                            &alg_values_supported[0],
                            &enc_values_supported[0],
                        );
                        Some(Box::new(decryption_parameters))
                    }
                    _ => None,
                };
            log_warn!("ISSUANCE", &format!("Cnonce: {:?}", token_response.c_nonce));
            let c_nonce = if token_response.c_nonce.is_some() {
                token_response.c_nonce.clone()
            } else if let Some(nonce_endpoint) = credential_issuer_metadata.nonce_endpoint.clone() {
                let nonce_response: serde_json::Value = self
                    .client
                    .post(nonce_endpoint)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                log_warn!(
                    "ISSUANCE",
                    &format!("Fetched new nonce: {:?}", nonce_response)
                );
                let Some(serde_json::Value::String(c_nonce)) = nonce_response.get("c_nonce") else {
                    return Err(anyhow!("no nonce returned from nonce endpoint").into());
                };
                Some(c_nonce.clone())
            } else {
                // No c_nonce from token (or credential) response (expected for issuer compliant with openid4vci draft version 14),
                // nor nonce_endpoint (expected for issuer compliant with openid4vci draft version 15)
                // We can continue and attempt to send a proof without nonce, but it will probably not work.
                None
            };

            let credential_response = if let Some(key_attestation_metadata) =
                key_attestations_required
            {
                let issuer_id = credential_issuer_metadata.credential_issuer.to_string();
                let key_attestation = self
                    .wallet_backend
                    .get_key_attestation(
                        c_nonce.clone(),
                        Some(issuer_id),
                        key_attestation_metadata.key_storage.clone(),
                        key_attestation_metadata.user_authentication.clone(),
                        subjects.clone(),
                    )
                    .await?;

                let proof = if key_type == KeyType::None {
                    CredentialProofs::NoProof
                } else {
                    CredentialProofs::Proofs(KeyProofsType::Attestation(vec![key_attestation]))
                };

                get_credential_with_proofs(
                    client.clone(),
                    credential_issuer_metadata.clone(),
                    token_response.access_token.clone(),
                    credential_configuration_id.clone(),
                    credential_format.clone(),
                    content_decryptor,
                    proof,
                )
                .await
                .map_err(|e| anyhow::anyhow!("failed to get cred: {e:?}"))?
            } else {
                log_warn!("ISSUANCE", &format!("start issuing"));
                let subjects = subjects
                    .iter()
                    .map(|s| Arc::new(SecureSubject::with_signer(s.clone())))
                    .collect::<Vec<Arc<SecureSubject>>>();
                log_warn!(
                    "ISSUANCE",
                    &format!("gathered all subjects ({})", subjects.len())
                );
                let content_decryptor: Option<Box<dyn ContentDecryptor>> =
                    match &credential_issuer_metadata.credential_response_encryption {
                        Some(CredentialResponseEncryption {
                            alg_values_supported,
                            enc_values_supported,
                            encryption_required: _,
                        }) => {
                            let decryption_parameters = EncryptionParameters::new_decryptor(
                                &alg_values_supported[0],
                                &enc_values_supported[0],
                            );
                            Some(Box::new(decryption_parameters))
                        }
                        _ => None,
                    };
                let result = match get_credential(
                    client.clone(),
                    subjects.clone(),
                    credential_issuer_metadata.clone(),
                    token_response.access_token.clone(),
                    c_nonce.clone(),
                    credential_configuration_id.clone(),
                    credential_format.clone(),
                    content_decryptor,
                    self.oidc_settings.client_id.clone(),
                    is_for_pre_authorized_code,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        log_warn!(
                            "ISSUANCE",
                            &format!("failed to get cred on first try: {e:?}")
                        );
                        let mut credential_issuer_metadata = credential_issuer_metadata.clone();
                        credential_issuer_metadata.nonce_endpoint = None;
                        let content_decryptor: Option<Box<dyn ContentDecryptor>> =
                            match &credential_issuer_metadata.credential_response_encryption {
                                Some(CredentialResponseEncryption {
                                    alg_values_supported,
                                    enc_values_supported,
                                    encryption_required: _,
                                }) => {
                                    let decryption_parameters = EncryptionParameters::new_decryptor(
                                        &alg_values_supported[0],
                                        &enc_values_supported[0],
                                    );
                                    Some(Box::new(decryption_parameters))
                                }
                                _ => None,
                            };
                        get_credential(
                            client,
                            subjects,
                            credential_issuer_metadata.clone(),
                            token_response.access_token.clone(),
                            e.c_nonce,
                            credential_configuration_id.clone(),
                            credential_format.clone(),
                            content_decryptor,
                            self.oidc_settings.client_id.clone(),
                            is_for_pre_authorized_code,
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("failed to get cred: {e:?}"))?
                    }
                };
                log_warn!("ISSUANCE", &format!("finished request"));
                result
            };
            log_warn!("ISSUANCE", &format!("got everything"));
            // let tokens = Some(DeviceBoundTokens {
            //     access_token: Some(token_response.access_token.to_string()),
            //     refresh_token: token_response.refresh_token.clone(),
            //     c_nonce: c_nonce.clone(),
            //     dpop_key_reference: self.auth_key.key_reference(),
            // });
            // Try to resolve deferred response immediately. If it doesn't work right away, we'll give up.
            // The deferred cred response could mean it will take days for this to appear; this doesnt
            // fit into our setup now.
            let credential_response = match credential_response.credential {
                CredentialResponseType::Immediate { .. } => credential_response,
                CredentialResponseType::Deferred { transaction_id } => {
                    return Ok(CredentialResponseTypeInternal::Deferred(Deferred {
                        transaction_code: transaction_id.to_string(),
                        credential_configuration_id: credential_configuration_id.clone(),
                    }))
                }
            };
            log_warn!("ISSUANCE", &format!("{:?}", credential_response));

            if let CredentialResponseType::Immediate { credential, .. } =
                &credential_response.credential
            {
                let payloads = if let Value::Array(credentials) = credential {
                    log_debug!("ISSUANCE", "we have array valued response");
                    credentials
                        .iter()
                        .filter_map(|a| {
                            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
                            // This specification defines the following parameters to be used inside this object:
                            // credential: REQUIRED. Contains one issued Credential. The encoding of the Credential depends on the Credential Format and MAY be a string or an object. Credential Formats expressed as binary data MUST be base64url-encoded and returned as a string. More details are defined in the Credential Format Profiles in Appendix A.
                            //
                            if let Some(cred) = a.get("credential") {
                                cred.as_str()
                            } else {
                                a.as_str()
                            }
                        })
                        .collect()
                } else if let Value::String(payload) = credential {
                    vec![payload.as_str()]
                } else {
                    return Err(anyhow!("Malformed credential response").into());
                };
                if payloads.is_empty() {
                    log_warn!(
                        "ISSUANCE",
                        "payloads is empty...value of credential is not a string"
                    );
                }

                let Some(format) = resolve_credential_format(&payloads, Some(&credential_format))
                else {
                    return Err(anyhow!("Invalid credential format {credential_format:?}").into());
                };

                Ok(CredentialResponseTypeInternal::Immediate(
                    CredentialResponse {
                        credentials: payloads
                            .into_iter()
                            .map(|payload| match format {
                                CredentialType::SdJwt => {
                                    CredentialFormat::SdJwt(payload.to_string())
                                }
                                CredentialType::Mdoc => CredentialFormat::Mdoc(payload.to_string()),
                                CredentialType::BbsTermWise => {
                                    CredentialFormat::BbsTermWise(payload.to_string())
                                }
                                CredentialType::W3C => CredentialFormat::W3C(payload.to_string()),
                            })
                            .collect(),
                        c_nonce: credential_response.c_nonce,
                        c_nonce_expires_in: credential_response.c_nonce_expires_in.map(
                            |a| match a {
                                StringOrInt::Int(i) => i,
                                StringOrInt::String(a) => a.parse().unwrap_or(3600),
                            },
                        ),
                    },
                ))
            } else {
                Err(anyhow::anyhow!("No credential result").into())
            }
        }

        async fn get_optional_client_attestation(
            &self,
            with_hsm_wallet_attestation: Option<Arc<HsmSupportObject>>,
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
        ) -> Result<Option<ClientAttestation>, ApiError> {
            let cred_issuer_metadata = self
                .credential_issuer_metadata
                .lock()?
                .clone()
                .ok_or(anyhow!("no metadata"))?;

            if let Some(hsm) = with_hsm_wallet_attestation {
                let Some(wallet_attestation) = hsm.0.get_wallet_attestation() else {
                    return Err(anyhow!("No wallet attestation found, call register first").into());
                };
                let pop = hsm
                    .0
                    .generate_pop(
                        self.oidc_settings.client_id.clone(),
                        cred_issuer_metadata.credential_issuer.to_string(),
                    )
                    .await
                    .ok_or(anyhow!("PoP failed"))?;

                Ok(Some(ClientAttestation {
                    client_attestation: wallet_attestation,
                    client_attestation_pop: pop,
                }))
            } else if should_send_wallet_attestation(token_endpoint_auth_methods_supported) {
                let wallet_attestation = self
                    .wallet_backend
                    .get_wallet_attestation(self.auth_key.clone())
                    .await?;
                let pop = self.wallet_backend.generate_wallet_attestation_pop(
                    self.auth_key.clone(),
                    self.oidc_settings.client_id.clone(),
                    cred_issuer_metadata.credential_issuer.to_string(),
                    None,
                )?;
                Ok(Some(ClientAttestation {
                    client_attestation: wallet_attestation,
                    client_attestation_pop: pop,
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn resolve_credential_format(
        payloads: &Vec<&str>,
        format: Option<&Value>,
    ) -> Option<CredentialType> {
        let mut formats = payloads
            .iter()
            .map(|payload| resolve_credential_format_single(payload, format))
            .collect::<Vec<_>>();
        log_debug!(
            "ISSUANCE",
            &format!("formats[{}/{}] {:?}", formats.len(), payloads.len(), format)
        );
        formats.dedup();

        log_warn!(
            "ISSUANCE",
            &format!("Resolved credential formats: {:?}", formats)
        );

        if formats.len() == 1 {
            return formats[0];
        }
        log_debug!(
            "ISSUANCE",
            &format!("formats[{}] {:?}", formats.len(), format)
        );

        return None;
    }

    fn resolve_credential_format_single(
        payload: &str,
        format: Option<&Value>,
    ) -> Option<CredentialType> {
        if let Some(format) = format {
            match credential_formats::CredentialFormat::from(format) {
                credential_formats::CredentialFormat::W3cSdJwt => {
                    // NOTE: This is a workaround, as W3C SD-JWTs have the same
                    // format as non-W3C SD-JWTs.
                    // We can distinguish them by checking if the @context is present.
                    log_debug!("ISSUANCE", &format!("we have sdjwt: {:?}", format));
                    if parse_w3c_sd_jwt(payload)
                        .map(|c| c.json.get("@context").is_some())
                        .unwrap_or(false)
                    {
                        Some(CredentialType::W3C)
                    } else {
                        Some(CredentialType::SdJwt)
                    }
                }
                credential_formats::CredentialFormat::MsoMdoc => Some(CredentialType::Mdoc),
                credential_formats::CredentialFormat::ZkpVc => Some(CredentialType::BbsTermWise),
                _ => {
                    log_debug!("ISSUANCE", &format!("invalid format: {:?}", format));
                    None
                }
            }
        } else {
            let sdjwt = heidi_credentials_rust::sdjwt::decode_sdjwt(payload);
            let w3c = parse_w3c_sd_jwt(payload);

            match (sdjwt, w3c) {
                (Ok(_), Ok(w3c)) => {
                    if w3c.json.get("@context").is_some() {
                        return Some(CredentialType::W3C);
                    }
                    return Some(CredentialType::SdJwt);
                }
                (Ok(_), Err(_)) => return Some(CredentialType::SdJwt),
                (Err(_), Ok(_)) => return Some(CredentialType::W3C),
                (Err(e), Err(e2)) => {
                    log_debug!("ISSUANCE", &format!("invalid format: {e}/{e2}"));
                    ()
                }
            };

            return if heidi_credentials_rust::mdoc::decode_mdoc(&payload).is_ok() {
                Some(CredentialType::Mdoc)
            } else if heidi_credentials_rust::bbs::decode_bbs(&payload).is_ok() {
                Some(CredentialType::BbsTermWise)
            } else {
                log_debug!("ISSUANCE", &format!("invalid format: {:?}", format));
                None
            };
        }
    }

    // Simplified openid4vci::credential_response::CredentialResponse for only Immediate credentials
    // and already format-tagged.
    struct CredentialResponse {
        credentials: Vec<CredentialFormat>,
        c_nonce: Option<String>,
        #[allow(unused)]
        c_nonce_expires_in: Option<u64>,
    }
    enum CredentialResponseTypeInternal {
        Immediate(CredentialResponse),
        Deferred(Deferred),
    }
    // Parse the credential offer string; if its a credential_offer_uri, go fetch and parse it.
    pub async fn resolve_credential_offer(
        offer: &str,
        client: &ClientWithMiddleware,
    ) -> Result<CredentialOfferParameters, ApiError> {
        let cred_offer: CredentialOffer = offer
            .parse()
            .map_err(|e| anyhow!("Could not parse offer: {e}"))?;
        match cred_offer {
            CredentialOffer::CredentialOffer(cred_offer_params) => Ok(cred_offer_params),
            CredentialOffer::CredentialOfferUri(credential_offer_uri) => client
                .get(credential_offer_uri)
                .send()
                .await?
                .error_for_status()?
                .json::<CredentialOfferParameters>()
                .await
                .map_err(|e| -> ApiError {
                    anyhow!("fetching credential offer failed: {e}").into()
                }),
        }
    }

    fn can_use_dpop(
        dpop_signing_alg_values_supported: Option<Vec<String>>,
        key_alg: String,
    ) -> Result<bool, ApiError> {
        let dpop_support = match dpop_signing_alg_values_supported {
            Some(dpop) => dpop.clone(),
            _ => vec![],
        };

        let has_dpop = !dpop_support.is_empty();
        if has_dpop && !dpop_support.contains(&key_alg) {
            return Err(anyhow!("Authorization server requests DPoP with an algorithm that do not match the wallet's key. Wallet key: {}, Supported: {}.",
                    key_alg, dpop_support.join(", ")).into());
        }
        Ok(has_dpop)
    }

    fn should_send_wallet_attestation(
        token_endpoint_auth_methods_supported: Option<Vec<String>>,
    ) -> bool {
        if let Some(token_endpoint_auth_methods_supported) = token_endpoint_auth_methods_supported {
            let attest_method = "attest_jwt_client_auth".to_string();
            if token_endpoint_auth_methods_supported.contains(&attest_method) {
                return true;
            }
        }
        // TODO: wallet attestation override issuer list
        false
    }

    fn get_supported_code_challenge_method(
        code_challenge_methods_supported: Option<Vec<String>>,
    ) -> Result<String, ApiError> {
        if let Some(code_challenge_methods_supported) = code_challenge_methods_supported {
            // Something is defined
            for m in ["S256".to_string(), "plain".to_string()] {
                if code_challenge_methods_supported.contains(&m) {
                    return Ok(m);
                }
            }
            return Err(anyhow!(
                "Authorization server does not support any known PKCE code challenge method"
            )
            .into());
        }
        // If nothing specified, assume sending S256 is fine
        Ok("S256".to_string())
    }

    fn get_authorization_server(
        authorization_servers: &[Url],
        cred_offer: &CredentialOfferParameters,
    ) -> Result<Url, ApiError> {
        let expected_auth_server = cred_offer.grants.as_ref().and_then(|grants| {
            grants
                .pre_authorized_code
                .as_ref()
                .and_then(|p| p.authorization_server.as_ref())
                .or_else(|| {
                    grants
                        .authorization_code
                        .as_ref()
                        .and_then(|c| c.authorization_server.as_ref())
                })
        });

        if let Some(expected_auth_server) = expected_auth_server.and_then(|a| Url::parse(a).ok()) {
            if authorization_servers.contains(&expected_auth_server) {
                Ok(expected_auth_server.clone())
            } else {
                Err(anyhow!("Credential offer specified authorization server {} which is not present in the list of authorization servers", expected_auth_server.to_string()).into())
            }
        } else if let Some(auth_server) = authorization_servers.first() {
            Ok(auth_server.to_owned())
        } else {
            // fallback
            Url::parse(&cred_offer.credential_issuer).map_err(|e| {
                ApiError::Generic(GenericError::Inner(crate::error::InnerError::Anyhow(
                    anyhow!(e),
                )))
            })
        }
    }

    fn is_supported_credential_configuration(
        cred_config: &CredentialConfigurationsSupportedObject,
    ) -> bool {
        if !matches!(
            credential_formats::CredentialFormat::from(&cred_config.credential_format),
            credential_formats::CredentialFormat::VcIetfSdJwt
                | credential_formats::CredentialFormat::MsoMdoc
                | credential_formats::CredentialFormat::ZkpVc
        ) {
            return false;
        }
        if let Some(key_proof_metadata) = cred_config.proof_types_supported.get(&ProofType::Jwt) {
            if !key_proof_metadata
                .proof_signing_alg_values_supported
                .contains(&"ES256".to_string())
            {
                return false;
            }
            if let Some(ref key_attestations_required) =
                key_proof_metadata.key_attestations_required
            {
                if !is_supported_key_attestation(key_attestations_required) {
                    return false;
                }
            }
        } else if !cred_config.proof_types_supported.is_empty() {
            return false;
        }
        true
    }

    fn is_supported_key_attestation(key_attestation_metadata: &KeyAttestationMetadata) -> bool {
        let levels = [
            "iso_18045_basic",
            "iso_18045_enhanced-basic",
            "iso_18045_moderate",
            "iso_18045_high",
        ];
        (key_attestation_metadata.key_storage.is_empty()
            || key_attestation_metadata
                .key_storage
                .iter()
                .any(|v| levels.contains(&v.as_str())))
            && (key_attestation_metadata.user_authentication.is_empty()
                || key_attestation_metadata
                    .user_authentication
                    .iter()
                    .any(|v| levels.contains(&v.as_str())))
    }

    fn get_key_attestations_required(
        cred_config: &CredentialConfigurationsSupportedObject,
    ) -> Option<&KeyAttestationMetadata> {
        return cred_config
            .proof_types_supported
            .get(&ProofType::Jwt)
            .and_then(|pt| pt.key_attestations_required.as_ref());
    }

    /// Check if cryptographic binding is required for the credential configuration.
    /// Returns false if cryptographic_binding_methods_supported is empty (claim-based binding).
    fn is_cryptographic_binding_required(
        cred_config: &CredentialConfigurationsSupportedObject,
    ) -> bool {
        // If cryptographic_binding_methods_supported is empty, no cryptographic binding is required
        !cred_config
            .cryptographic_binding_methods_supported
            .is_empty()
    }

    fn get_appropriate_key_type(
        key_attestations_required: Option<&KeyAttestationMetadata>,
    ) -> KeyType {
        if let Some(key_attestation_metadata) = key_attestations_required {
            // Flatten the required key_storage and user_authentication key attestation requirements into a single list.
            // We'll just use the "max" of either of the two to determine the type of key that we
            // create.
            let key_attestation_required_levels: Vec<&str> = key_attestation_metadata
                .key_storage
                .iter()
                .map(AsRef::as_ref)
                .chain(
                    key_attestation_metadata
                        .user_authentication
                        .iter()
                        .map(AsRef::as_ref),
                )
                .collect();

            if key_attestation_required_levels.contains(&"iso_18045_high") {
                KeyType::RemoteHSM
            } else if key_attestation_required_levels.contains(&"iso_18045_moderate")
                || key_attestation_required_levels.contains(&"iso_18045_enhanced-basic")
            {
                KeyType::DeviceBound
            } else {
                KeyType::Software
            }
        } else {
            KeyType::DeviceBound
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod test_issuance {
        use super::*;
        use crate::get_reqwest_client;
        use crate::issuance::models::AuthorizationCode;
        use crate::testing::new_native_signer;
        use crate::{crypto::signing::SoftwareKeyPair, issuance::models::Grants};
        use reqwest::Url;
        use reqwest_middleware::ClientBuilder;
        use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
        use serde_json::json;
        use std::{
            io::BufReader,
            net::TcpListener,
            sync::{Arc, Once},
        };

        fn setup_proxy() {
            static SET_PROXY: Once = Once::new();
            SET_PROXY.call_once(|| {
                // crate::uniffi_reqwest::set_proxy("127.0.0.1".to_string(), 8080);
            });
        }

        const TEST_BACKEND_URL: &str = "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1";

        #[tokio::test]
        // WARNING: This test case works as long as the demo issuer by bundesdruckerei.de is running. In case it stops, another real life demo issuer needs to be found.
        async fn test_resolve_credential_offer() {
            setup_proxy();

            let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
            let client = ClientBuilder::new(get_reqwest_client().build().unwrap())
                .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                .build();

            let err_cases = [""];
            let ok_cases = [
            (
                "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fdemo.pid-issuer.bundesdruckerei.de%2Fc1%22%2C%22credential_configuration_ids%22%3A%5B%22pid-sd-jwt%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%7D%7D%7D",
                CredentialOfferParameters {
                    credential_issuer: "https://demo.pid-issuer.bundesdruckerei.de/c1".parse().unwrap(),
                    credential_configuration_ids: vec![
                        "pid-sd-jwt".to_string(),
                    ],
                    grants: Some(Grants {
                        authorization_code: Some(AuthorizationCode{ issuer_state: None, authorization_server: None }),
                        pre_authorized_code: None,
                    }),
                },
            ), (
                // Created via: https://issuer.eudiw.dev/credential_offer
                "https://tester.issuer.eudiw.dev/credential_offer?credential_offer={%22credential_issuer%22:%20%22https://issuer.eudiw.dev%22,%20%22credential_configuration_ids%22:%20[%22eu.europa.ec.eudi.pid_jwt_vc_json%22,%20%22eu.europa.ec.eudi.loyalty_mdoc%22],%20%22grants%22:%20{%22authorization_code%22:%20{}}}",
                CredentialOfferParameters {
                    credential_issuer: "https://issuer.eudiw.dev".parse().unwrap(),
                    credential_configuration_ids: vec![
                        "eu.europa.ec.eudi.pid_jwt_vc_json".to_string(),
                        "eu.europa.ec.eudi.loyalty_mdoc".to_string(),
                    ],
                    grants: Some(Grants {
                        authorization_code: Some(AuthorizationCode{ issuer_state: None, authorization_server: None }),
                        pre_authorized_code: None,
                    }),
                },
            )
        ];

            for c in err_cases.into_iter() {
                assert!(resolve_credential_offer(c, &client).await.is_err());
            }

            for (c, expected) in ok_cases.into_iter() {
                let offer = resolve_credential_offer(c, &client).await.unwrap();
                assert!(
                    offer == expected,
                    "unexpected result for {c}:\n\t{offer:?}\n\t{expected:?}"
                );
            }
        }

        // #[tokio::test]
        // These tests need a running backend, ignoring for now
        async fn test_issuance_par() {
            setup_proxy();

            let offer = get_demo_credential_offer_authorization_code()
                .await
                .unwrap();
            run_test_issuance(offer).await;
        }

        // #[tokio::test]
        // These tests need a running backend, ignoring for now
        async fn test_issuance_preauth() {
            setup_proxy();

            let offer = get_demo_credential_offer_preauth().await.unwrap();
            run_test_issuance(offer).await;
        }

        async fn run_test_issuance(offer: String) {
            static MUTEX: Mutex<()> = Mutex::new(());
            let _lock = MUTEX.lock();

            dbg!(&offer);

            let auth_key = new_native_signer();
            let issuance = Arc::new(OID4VciIssuance::init_issuance(
                Arc::new(OidcSettings::new(
                    "http://localhost:3001/".to_string(),
                    "c3ce7a6c-2bbb-4abe-909c-41bc9463d3c5".to_string(),
                    None,
                )),
                Arc::new(WalletBackend::new(TEST_BACKEND_URL.to_string())),
                auth_key.clone(),
            ));

            // XXX: no auth metadata, these tests are broken now :(
            let auth_step = issuance
                .clone()
                .initialize_issuance(&offer, None, false, None, None, None, None, None)
                .await
                .unwrap();
            dbg!(&auth_step);

            let bind_url = format!("0.0.0.0:{}", 3001);
            let listener = TcpListener::bind(&bind_url).unwrap();

            let mut code = None;
            let mut _state = None;
            let mut tx_code = None;
            match auth_step {
                AuthorizationStep::BrowseUrl { url, .. } => {
                    dbg!(&url);
                    let _ = open::that(url);
                    if let Some(mut stream) = listener.incoming().flatten().next() {
                        {
                            let mut reader = BufReader::new(&stream);
                            use std::io::BufRead;
                            let mut request_line = String::new();
                            reader.read_line(&mut request_line).unwrap();

                            let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                            let url = Url::parse(&("http://localhost".to_string() + redirect_url))
                                .unwrap();
                            for (key, value) in url.query_pairs() {
                                if key == "code" {
                                    code = Some(value.to_string());
                                } else if key == "state" {
                                    _state = Some(value.to_string());
                                }
                            }
                        }

                        let message = "Go back to your terminal :)";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                            message.len(),
                            message
                        );
                        use std::io::Write;
                        stream.write_all(response.as_bytes()).unwrap();
                    }
                }
                AuthorizationStep::EnterTransactionCode { .. } => {
                    println!("Enter transaction code: {:?}", auth_step);
                    tx_code = Some(std::io::stdin().lines().next().unwrap().unwrap());
                }
                AuthorizationStep::None => {}
                AuthorizationStep::WithPresentation { .. } => {}
                AuthorizationStep::Finished { .. } => {}
            }

            dbg!(&_state);

            let num_credentials_per_type = 20;
            let expected_num_types = 2;
            let is_for_pre_authorized_code = false;
            let credentials = issuance
                .clone()
                .finalize_issuance(
                    code,
                    tx_code,
                    num_credentials_per_type,
                    Arc::new(TestSignerFactory {}),
                    None,
                    None,
                    is_for_pre_authorized_code,
                )
                .await
                .unwrap();
            println!("got {} credentials", credentials.credentials.len());
            assert!(
                credentials.credentials.len()
                    == expected_num_types * num_credentials_per_type as usize
            );

            let metadata = issuance.get_oidc_metadata().unwrap();
            let tokens = credentials.tokens.clone();
            drop(issuance);
            drop(credentials);

            if tokens.refresh_token.is_none() {
                println!("no refresh token, test ends here");
                return;
            }
            supplement_test_issuance(metadata, auth_key, tokens, is_for_pre_authorized_code).await;
        }

        async fn supplement_test_issuance(
            metadata: OidcMetadata,
            auth_key: Arc<dyn NativeSigner>,
            tokens: DeviceBoundTokens,
            is_for_pre_authorized_code: bool,
        ) {
            // Reconstitute issuance from stored metadata:
            let issuance = Arc::new(
                OID4VciIssuance::from_metadata(
                    metadata,
                    Arc::new(WalletBackend::new(TEST_BACKEND_URL.to_string())),
                    auth_key.clone(),
                )
                .unwrap(),
            );
            let signer_factory = Arc::new(TestSignerFactory {});

            // Token refresh:
            let tokens = issuance
                .refresh_token(tokens, None, None, None, None)
                .await
                .unwrap();

            // ... aaand get more stuff.
            let credentials = issuance
                .clone()
                .supplement_issuance(
                    tokens,
                    2,
                    None,
                    signer_factory.clone(),
                    is_for_pre_authorized_code,
                )
                .await
                .unwrap();
            let more_credentials = issuance
                .clone()
                .supplement_issuance(
                    credentials.tokens,
                    3,
                    None,
                    signer_factory.clone(),
                    is_for_pre_authorized_code,
                )
                .await
                .unwrap();

            println!(
                "got {} and {} more credentials",
                credentials.credentials.len(),
                more_credentials.credentials.len(),
            );
        }

        async fn get_demo_credential_offer_authorization_code() -> Result<String, ApiError> {
            // hard coded flow ID in issuer, resulting in a cred offer for a UB-Employee-Badge.
            let auth_flow_id = "a4ab63cf-3937-4560-93c9-8cca8c5f4531";
            let cred_offer: CredentialOfferParameters = get_reqwest_client()
            .build()?
            .post("https://sprind-eudi-issuer-ws-dev.ubique.ch/gemeinde-musterstadt/c/credential-offer")
            .json(&json!({"authFlowId": auth_flow_id}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

            let cred_offer: String = serde_json::to_string(&cred_offer)?;
            let offer = format!(
                "openid-credential-offer://?{}",
                serde_urlencoded::to_string([("credential_offer", cred_offer)])?
            );
            Ok(offer)
        }

        async fn get_demo_credential_offer_preauth() -> Result<String, ApiError> {
            let cred_offer_request_data = json!({
              "data": {
                "schemaIdentifier": {
                  "credentialIdentifier": "schema-for-testing-s2hx4",
                  "version": "0.0.1"
                },
                "attributes": {
                  "testAttribut": {
                    "value": "Test value",
                    "attributeType": "STRING"
                  },
                  "name": {
                    "value": "Hans Muster",
                    "attributeType": "STRING"
                  },
                  "department": {
                    "value": "Systems",
                    "attributeType": "STRING"
                  },
                  "dateofbirth": {
                    "value": "20000102",
                    "attributeType": "STRING"
                  }
                }
              }
            })
            .to_string();
            let cred_offer_request_token = base64_encode_bytes(
                &(cred_offer_request_data + ".thissignatureisignored").as_bytes(),
            );
            let cred_offer: CredentialOfferParameters = get_reqwest_client()
            .build()?
            .post("https://sprind-eudi-issuer-ws-dev.ubique.ch/gemeinde-musterstadt/c/credential-offer")
            .json(&json!({"token": cred_offer_request_token}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

            let cred_offer: String = serde_json::to_string(&cred_offer)?;
            let offer = format!(
                "openid-credential-offer://?{}",
                serde_urlencoded::to_string([("credential_offer", cred_offer)])?
            );
            Ok(offer)
        }

        #[derive(Clone, Copy, Debug)]
        pub struct TestSignerFactory {}

        impl SignerFactory for TestSignerFactory {
            fn new_signer(&self, _key_type: KeyType) -> Arc<dyn NativeSigner> {
                Arc::new(SoftwareKeyPair::new())
            }
        }
    }
}
