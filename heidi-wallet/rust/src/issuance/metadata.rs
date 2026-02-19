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

use crate::{
    issuance::models::{
        AuthorizationRequestReference, AuthorizationServerMetadata, CredentialIssuerMetadata,
        PushedAuthorizationRequest, TokenRequest, TokenResponse,
    },
    ApiError,
};

use super::auth::{build_pushed_authorization_request, ClientAttestation};

use reqwest::Url;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};

/// Convenienve struct for easier fetching of metadata
pub struct MetadataFetcher {
    pub client: ClientWithMiddleware,
}

impl MetadataFetcher {
    pub fn new(client: ClientWithMiddleware) -> Self {
        Self { client }
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
        // try openid-federation
        //
        let res_oidf = openidconnect_federation::DefaultFederationRelation::new_from_url(
            credential_issuer_url.as_str(),
        );
        if let Ok(mut res_oidf) = res_oidf {
            let _ = res_oidf.build_trust();
            let is_valid = res_oidf.verify().is_ok();
            // TODO: we should pass a trust store here, so we can resolve the correct path
            let metdata = res_oidf.resolve_metadata(None);
            if is_valid {
                if let Some(authorization_server_metadata) =
                    metdata.get("oauth_authorization_server")
                {
                    let authorization_server_metadata: serde_json::Value =
                        authorization_server_metadata.clone().into();
                    if let Ok(auth_md) = serde_json::from_value::<AuthorizationServerMetadata>(
                        authorization_server_metadata,
                    ) {
                        return Ok(auth_md);
                    }
                }
            }
        }

        let oauth_authorization_server_endpoint = append_path(
            credential_issuer_url.clone(),
            vec![".well-known", "oauth-authorization-server"],
        )?;
        if let Ok(metadata) = self
            .client
            .get(oauth_authorization_server_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        let oauth_ietf_authorization_server_endpoint = prepend_path(
            credential_issuer_url.clone(),
            vec![".well-known", "oauth-authorization-server"],
        )?;
        if let Ok(metadata) = self
            .client
            .get(oauth_ietf_authorization_server_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        let oidc_authorization_server_endpoint = append_path(
            credential_issuer_url.clone(),
            vec![".well-known", "openid-configuration"],
        )?;
        if let Ok(metadata) = self
            .client
            .get(oidc_authorization_server_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        let oidc_ietf_authorization_server_endpoint = prepend_path(
            credential_issuer_url.clone(),
            vec![".well-known", "openid-configuration"],
        )?;
        if let Ok(metadata) = self
            .client
            .get(oidc_ietf_authorization_server_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        return Err(anyhow::anyhow!("Failed to get authorization server metadata").into());
    }

    /// Get metadata for the credential issuer
    pub async fn get_credential_issuer_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<CredentialIssuerMetadata, ApiError> {
        // try openid-federation
        let res_oidf = openidconnect_federation::DefaultFederationRelation::new_from_url(
            credential_issuer_url.as_str(),
        );
        if let Ok(mut res_oidf) = res_oidf {
            let _ = res_oidf.build_trust();
            let is_valid = res_oidf.verify().is_ok();
            // TODO: we should pass a trust store here, so we can resolve the correct path
            let metdata = res_oidf.resolve_metadata(None);
            if is_valid {
                if let Some(credential_issuer_metadata) = metdata.get("openid_credential_issuer") {
                    let credential_issuer_metadata: serde_json::Value =
                        credential_issuer_metadata.clone().into();
                    if let Ok(credential_issuer_metadata) =
                        serde_json::from_value::<CredentialIssuerMetadata>(
                            credential_issuer_metadata,
                        )
                    {
                        return Ok(credential_issuer_metadata);
                    }
                }
            }
        }

        // Try ietf well-known as per https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-
        // (The .well-known/openid-credential-issuer is **prepended** to the credential issuer url)
        let ietf_credential_issuer_endpoint = prepend_path(
            credential_issuer_url.clone(),
            vec![".well-known", "openid-credential-issuer"],
        )?;

        if let Ok(metadata) = self
            .client
            .get(ietf_credential_issuer_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<CredentialIssuerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        // Try openid-connect well-known https://openid.net/specs/openid-connect-discovery-1_0-final.html#ProviderConfig
        // (The .well-known/openid-credential-issuer is just appended to the credential issuer url)
        let oidc_credential_issuer_endpoint = append_path(
            credential_issuer_url,
            vec![".well-known", "openid-credential-issuer"],
        )?;

        if let Ok(metadata) = self
            .client
            .get(oidc_credential_issuer_endpoint)
            .header("Accept", "application/json")
            .send()
            .await?
            .json::<CredentialIssuerMetadata>()
            .await
        {
            return Ok(metadata);
        }

        return Err(anyhow::anyhow!("Failed to get credential issuer metadata").into());
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

fn append_path(mut url: Url, path: Vec<&str>) -> Result<Url, anyhow::Error> {
    let mut path_segments = url
        .path_segments()
        .ok_or(anyhow::anyhow!("unable to parse credential issuer url"))?
        .collect::<Vec<_>>();
    if path_segments.last() == Some(&"") {
        path_segments.pop();
    }
    for p in path {
        path_segments.push(p);
    }
    url.set_path(&path_segments.join("/"));
    Ok(url)
}

fn prepend_path(mut url: Url, path: Vec<&str>) -> Result<Url, anyhow::Error> {
    let mut path_segments = url
        .path_segments()
        .ok_or(anyhow::anyhow!("unable to parse credential issuer url"))?
        .collect::<Vec<_>>();

    // Remove the trailing slash if is the only path segment (e.g., https://example.com/)
    if path_segments.len() == 1 && path_segments[0].is_empty() {
        path_segments.pop();
    }

    for p in path.into_iter().rev() {
        path_segments.insert(0, p);
    }
    url.set_path(&path_segments.join("/"));
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct UntypedMetadata {
    authorization_server_metadata: heidi_util_rust::value::Value,
    credential_issuer_metadata: heidi_util_rust::value::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_path() {
        let url = Url::parse("https://example.com/issuer").unwrap();
        let endpoint = append_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/issuer/.well-known/openid-credential-issuer"
        );

        let url = Url::parse("https://example.com/issuer/").unwrap();
        let endpoint = append_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/issuer/.well-known/openid-credential-issuer"
        );

        let url = Url::parse("https://example.com/issuer/path").unwrap();
        let endpoint = append_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/issuer/path/.well-known/openid-credential-issuer"
        );

        let url = Url::parse("https://example.com/").unwrap();
        let endpoint = append_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer"
        );

        let url = Url::parse("https://example.com").unwrap();
        let endpoint = append_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer"
        );
    }

    #[test]
    fn test_prepend_path() {
        let url = Url::parse("https://example.com/issuer").unwrap();
        let endpoint = prepend_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer/issuer"
        );

        let url = Url::parse("https://example.com/issuer/").unwrap();
        let endpoint = prepend_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer/issuer/"
        );

        let url = Url::parse("https://example.com/issuer/path").unwrap();
        let endpoint = prepend_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer/issuer/path"
        );

        let url = Url::parse("https://example.com/").unwrap();
        let endpoint = prepend_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer"
        );

        let url = Url::parse("https://example.com").unwrap();
        let endpoint = prepend_path(url, vec![".well-known", "openid-credential-issuer"]).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.com/.well-known/openid-credential-issuer"
        );
    }
}
