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

//! This module contains structs/methods to fetch metadata from OID4VCI endpoints.
use std::marker::PhantomData;

use oid4vc::oid4vci::{
    credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters},
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata,
    },
    credential_offer::AuthorizationRequestReference,
    token_request::TokenRequest,
    token_response::TokenResponse,
};

use crate::ApiError;

use super::auth::{
    build_pushed_authorization_request, ClientAttestation, PushedAuthorizationRequest,
};

use reqwest::Url;
use reqwest_middleware::ClientWithMiddleware;
use serde::de::DeserializeOwned;

/// Convenienve struct for easier fetching of metadata
pub struct MetadataFetcher<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub client: ClientWithMiddleware,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> MetadataFetcher<CFC> {
    pub fn new(client: ClientWithMiddleware) -> Self {
        Self {
            client,
            phantom: PhantomData,
        }
    }
    /// Issue a pusehd AuthroizationRequest to a issuer authorization server
    pub async fn push_authorization_request(
        &self,
        par_endpoint: Url,
        auth_request: PushedAuthorizationRequest,
        with_client_attestation: Option<ClientAttestation>,
    ) -> Result<AuthorizationRequestReference, ApiError> {
        let req = build_pushed_authorization_request(
            &self.client,
            par_endpoint,
            auth_request,
            with_client_attestation,
        )?;
        req.send()
            .await
            .map_err(|e| {
                println!("--> {e}");
                e
            })?
            .error_for_status()?
            .json()
            .await
            .map_err(|e| e.into())
    }

    /// Get metadata for a authorization server
    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata, ApiError> {
        let mut oauth_authorization_server_endpoint = credential_issuer_url.clone();
        let mut oidc_authorization_server_endpoint = credential_issuer_url.clone();

        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|e| anyhow::anyhow!("unable to parse credential issuer url: {e:?}"))?
            .push(".well-known")
            .push("oauth-authorization-server");
        oidc_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|e| anyhow::anyhow!("unable to parse credential issuer url: {e:?}"))?
            .push(".well-known")
            .push("openid-configuration");
        let response = self
            .client
            .get(oidc_authorization_server_endpoint.clone())
            .send()
            .await?;
        // Try oidc first, then oauth as fallback. Report both errors if neither works.
        let res_oidc = match response.error_for_status() {
            // Note: and_then does not work with async
            Ok(response) => response.json::<AuthorizationServerMetadata>().await,
            Err(e) => Err(e),
        };
        match res_oidc {
            Ok(res) => Ok(res),
            Err(err_oidc) => {
                // try oauth next
                let response = self
                    .client
                    .get(oauth_authorization_server_endpoint.clone())
                    .send()
                    .await?;
                let res_oauth = match response.error_for_status() {
                    Ok(response) => response.json::<AuthorizationServerMetadata>().await,
                    Err(e) => Err(e),
                };
                match res_oauth {
                    Ok(res) => Ok(res),
                    Err(err_oauth) => {
                        Err(anyhow::anyhow!("Failed to get authorization server metadata\n\
                                             [oidc]: {err_oidc} ({oidc_authorization_server_endpoint})\n\
                                             [oauth]: {err_oauth} ({oauth_authorization_server_endpoint})").into())
                    }
                }
            }
        }
    }
    /// Get metadata for the credential issuer
    pub async fn get_credential_issuer_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<CredentialIssuerMetadata<CFC>, ApiError> {
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();

        openid_credential_issuer_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .push(".well-known")
            .push("openid-credential-issuer");

        self.client
            .get(openid_credential_issuer_endpoint)
            .send()
            .await?
            .error_for_status()?
            .json::<CredentialIssuerMetadata<CFC>>()
            .await
            .map_err(|e| {
                anyhow::anyhow!("Parsing of openid-credential-issuer endpoint failed: {e}").into()
            })
    }
    /// Fetch access token
    pub async fn get_access_token(
        &self,
        token_endpoint: Url,
        token_request: TokenRequest,
    ) -> Result<TokenResponse, ApiError> {
        self.client
            .post(token_endpoint)
            .form(&token_request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(|e| e.into())
    }
}
