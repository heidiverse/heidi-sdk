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

use monostate::MustBe;
use reqwest::header::HeaderMap;
use reqwest::Url;
use reqwest_middleware::{ClientWithMiddleware, RequestBuilder};
use serde::Serialize;

pub use oid4vc::oid4vci::authorization_request::PushedAuthorizationRequest;

use crate::ApiError;

pub struct ClientAttestation {
    pub client_attestation: String,
    pub client_attestation_pop: String,
}

impl ClientAttestation {
    fn as_form_params(&self) -> ClientAssertionFormParams {
        ClientAssertionFormParams {
            client_assertion_type: MustBe!(
                "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
            ),
            client_assertion: format!(
                "{}~{}",
                &self.client_attestation, &self.client_attestation_pop
            ),
        }
    }

    fn as_headers(&self) -> Result<HeaderMap, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert("OAuth-Client-Attestation", self.client_attestation.parse()?);
        headers.insert(
            "OAuth-Client-Attestation-PoP",
            self.client_attestation_pop.parse()?,
        );
        Ok(headers)
    }
}

// Client attestion was submitted as form parameters in draft-ietf-oauth-attestation-based-client-auth versions 00 and 01.
#[derive(Serialize)]
pub struct ClientAssertionFormParams {
    client_assertion_type:
        MustBe!("urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"),
    // concatenated format client_attestation~client_attestation_pop
    pub client_assertion: String,
}

#[derive(Serialize)]
struct PushedAuthorizationRequestWithOptionalClientAssertion {
    #[serde(flatten)]
    pushed_authorization_request: PushedAuthorizationRequest,
    #[serde(flatten)]
    client_assertion: Option<ClientAssertionFormParams>,
}

#[derive(Serialize)]
struct TokenRefreshRequestWithOptionalClientAssertion {
    grant_type: MustBe!("refresh_token"),
    client_id: String,
    refresh_token: String,
    #[serde(flatten)]
    client_assertion: Option<ClientAssertionFormParams>,
}

pub fn build_pushed_authorization_request(
    client: &ClientWithMiddleware,
    par_endpoint: Url,
    auth_request: PushedAuthorizationRequest,
    with_client_attestation: Option<ClientAttestation>,
) -> Result<RequestBuilder, ApiError> {
    let auth_params = PushedAuthorizationRequestWithOptionalClientAssertion {
        pushed_authorization_request: auth_request,
        client_assertion: with_client_attestation.as_ref().map(|a| a.as_form_params()),
    };
    let mut auth_headers = HeaderMap::new();
    if let Some(client_attestation) = with_client_attestation {
        auth_headers = client_attestation.as_headers()?;
    }
    Ok(client
        .post(par_endpoint)
        .headers(auth_headers)
        .form(&auth_params))
}

pub fn build_refresh_request(
    client: &ClientWithMiddleware,
    token_endpoint: Url,
    client_id: String,
    refresh_token: String,
    with_client_attestation: Option<ClientAttestation>,
) -> Result<RequestBuilder, ApiError> {
    let auth_params = TokenRefreshRequestWithOptionalClientAssertion {
        grant_type: MustBe!("refresh_token"),
        client_id,
        refresh_token,
        client_assertion: with_client_attestation.as_ref().map(|a| a.as_form_params()),
    };
    let mut auth_headers = HeaderMap::new();
    if let Some(client_attestation) = with_client_attestation {
        auth_headers = client_attestation.as_headers()?;
    }
    Ok(client
        .post(token_endpoint)
        .headers(auth_headers)
        .form(&auth_params))
}
