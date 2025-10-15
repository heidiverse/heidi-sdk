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

//! Provides REST-Api abstractions for the Backup API.
//! It handles OAUTH, and everything needed for loading, creating
//! and deleting the backup files.

use crate::error::BackendError;
use crate::error::BackupApiError;
use crate::issuance::OidcSettings;
use crate::lock;
use crate::ApiError;
use reqwest::redirect::Policy;
use reqwest::Client;
use reqwest::Url;
use reqwest_cookie_store::CookieStore;
use reqwest_cookie_store::CookieStoreMutex;
use serde_json::json;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use uniffi::Object;

#[derive(Object)]
/// Expose a REST-Client to the frontend, handling authentication and OAUTH and such.
pub struct Backuper {
    client: Client,
    email: String,
    base_url: String,
    cookie_store: Arc<CookieStoreMutex>,
    bearer_token: Mutex<Option<String>>,
    oidc_settings: Arc<OidcSettings>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Backuper {
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Create a Client based on the oidc_settings, the base_url and the email to use (authentication)
    ///
    /// SAFETY:
    /// client builder does not panic
    #[cfg(feature = "reqwest")]
    pub fn new(oidc_settings: Arc<OidcSettings>, base_url: String, email: String) -> Self {
        use crate::get_reqwest_client;

        let cookie_store = Arc::new(CookieStoreMutex::new(CookieStore::new(None)));
        Self {
            client: get_reqwest_client()
                .cookie_provider(cookie_store.clone())
                .build()
                .unwrap(),
            email,
            oidc_settings,
            base_url,
            cookie_store,
            bearer_token: Mutex::new(None),
        }
    }
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Create a rest client with a preconfigured token. Use this
    /// if you already initialized a backup instance before.
    ///
    /// SAFETY:
    // Client builder does not panic
    #[cfg(feature = "reqwest")]
    pub fn with_token(
        access_token: String,
        oidc_settings: Arc<OidcSettings>,
        base_url: String,
        email: String,
    ) -> Self {
        use crate::get_reqwest_client;

        let cookie_store: Arc<CookieStoreMutex> =
            Arc::new(CookieStoreMutex::new(CookieStore::new(None)));
        Self {
            client: get_reqwest_client()
                .cookie_provider(cookie_store.clone())
                .build()
                .unwrap(),
            email,
            oidc_settings,
            base_url,
            cookie_store,
            bearer_token: Mutex::new(Some(access_token)),
        }
    }
    /// Start the email verification
    pub async fn verify_user_start(self: &Arc<Self>) -> Result<(), ApiError> {
        let url = format!("{}/v1/user/verify/start", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&json!({"email" : self.email}))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.json::<BackupApiError>().await?;
            return Err(BackendError::BackupApiError(error).into());
        }
        Ok(())
    }
    /// Post the email OTP and finalize authentication
    pub async fn verify_user_finalize(
        self: &Arc<Self>,
        verification_code: String,
    ) -> Result<(), ApiError> {
        let url = format!("{}/v1/user/verify/finalize", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&json!({"email" : self.email, "verificationCode": verification_code}))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.json::<BackupApiError>().await?;
            return Err(BackendError::BackupApiError(error).into());
        }
        Ok(())
    }

    /// Upload [blob]. [blob] will be additionally encrypted at rest, using a key
    /// derived from a master_secret (backend secret) and your email address. Hence it
    /// is important to always use the same address!
    pub async fn create_backup(self: &Arc<Self>, blob: String) -> Result<(), ApiError> {
        let url = format!("{}/v1/backup", self.base_url);
        let token = {
            let lock = lock!(self.bearer_token => |e| { Err(BackendError::ParseError(format!("{e}")).into()) });
            lock.as_ref().unwrap_or(&String::new()).to_owned()
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"blob" : blob, "email": self.email}))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.json::<BackupApiError>().await?;
            return Err(BackendError::BackupApiError(error).into());
        }
        Ok(())
    }

    /// Retrieve a previously uploaded backup
    pub async fn get_backup(self: &Arc<Self>) -> Result<String, ApiError> {
        let url = format!("{}/v1/backup/get", self.base_url);

        let token = {
            let lock = lock!(self.bearer_token => |e| { Err(BackendError::ParseError(format!("{e}")).into())});
            lock.as_ref().unwrap_or(&String::new()).to_owned()
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"email": self.email}))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response
                .json::<BackupApiError>()
                .await
                .map_err(|e| BackendError::ParseError(e.to_string()))?;
            return Err(BackendError::BackupApiError(error).into());
        }

        let json_response = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| BackendError::ParseError(e.to_string()))?;
        let Some(Value::String(blob)) = json_response.get("blob") else {
            return Err(BackendError::ParseError("blob not found".to_string()).into());
        };

        Ok(blob.clone())
    }

    /// Delete backup
    pub async fn delete_backup(self: &Arc<Self>) -> Result<(), ApiError> {
        let url = format!("{}/v1/backup/delete", self.base_url);
        let token = {
            let lock = lock!(self.bearer_token => |e| { Err(BackendError::ParseError(format!("{e}")).into()) });
            lock.as_ref().unwrap_or(&String::new()).to_owned()
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"email": self.email}))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response
                .json::<BackupApiError>()
                .await
                .map_err(|e| BackendError::ParseError(e.to_string()))?;
            return Err(BackendError::BackupApiError(error).into());
        }
        Ok(())
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Get an access_token to be used for REST calls on the backup API. The
    /// token contains the hash of the email address, authenticating any requests.
    ///
    /// TODO: in production we would use a mobile flow, using e.g. PKCE and/or DPoP
    ///
    /// SAFETY:
    /// CLient builder does not panic
    ///
    #[cfg(feature = "reqwest")]
    pub async fn get_token(self: &Arc<Self>) -> Result<String, BackendError> {
        use crate::get_reqwest_client;

        let cookie_jar = self.cookie_store.clone();
        // Client builder does never fail!
        let client = get_reqwest_client()
            .redirect(Policy::none())
            .cookie_provider(cookie_jar)
            .build()
            .unwrap();

        let client_id = self.oidc_settings.client_id.as_str(); //"oauth-client";
        let redirect_uri = self.oidc_settings.redirect_url.as_str(); // "http://localhost:8080/oauth";
        let response_type = "code";

        let response = client
            .get(format!("{}/oauth2/authorize", self.base_url))
            .query(&[
                ("response_type", response_type),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| BackendError::TokenError(format!("{e}")))?;

        if !response.status().is_redirection() {
            let error = response
                .json::<BackupApiError>()
                .await
                .map_err(|e| BackendError::ParseError(e.to_string()))?;
            return Err(BackendError::BackupApiError(error));
        }

        let location_header: Url = response
            .headers()
            .get("Location")
            .ok_or_else(|| BackendError::TokenError("No location header".to_string()))?
            .to_str()
            .map_err(|e| {
                BackendError::TokenError(format!("Failed to parse url from location header ({e})"))
            })?
            .parse()
            .map_err(|e| BackendError::TokenError(format!("Not a valid url: {e}")))?;

        let headers: HashMap<Cow<_>, Cow<_>> = location_header.query_pairs().collect();
        let code = headers
            .get("code")
            .ok_or_else(|| BackendError::TokenError("No code in redirect uri".to_string()))?;

        let mut params = HashMap::<String, String>::new();
        params.insert("code".to_string(), code.to_string());
        params.insert("redirect_uri".to_string(), redirect_uri.to_string());
        params.insert("grant_type".to_string(), "authorization_code".to_string());
        let response = client
            .post(format!("{}/oauth2/token", self.base_url))
            .form(&params)
            .basic_auth(client_id, self.oidc_settings.client_secret.as_ref())
            .send()
            .await
            .map_err(|e| BackendError::TokenError(format!("{e}")))?;

        if !response.status().is_success() {
            let error = response
                .json::<BackupApiError>()
                .await
                .map_err(|e| BackendError::ParseError(e.to_string()))?;
            return Err(BackendError::BackupApiError(error));
        }

        let response = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| BackendError::TokenError(format!("{e}")))?;

        let access_token = response
            .get("access_token")
            .ok_or_else(|| BackendError::TokenError("No access_token in response".to_string()))?
            .as_str()
            .ok_or_else(|| BackendError::TokenError("AccessToken not a string".to_string()))?
            .to_string();

        {
            let mut lock =
                lock!(self.bearer_token => |e| { Err(BackendError::TokenError(format!("{e}"))) });
            *lock = Some(access_token.clone());
        }
        // TODO: return the whole token response and handle in constructor
        Ok(access_token.to_string())
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use crate::{backup::backend::Backuper, issuance::OidcSettings};

    // To test this we need a valid email address

    // #[tokio::test]
    async fn test_start_backup() {
        let oidc_settings = Arc::new(OidcSettings::new(
            "http://localhost:8080/oauth".into(),
            "oauth-client".into(),
            Some("secret".into()),
        ));
        let backup = Arc::new(Backuper::new(
            oidc_settings,
            "https://sprind-eudi-backup-ws-dev.ubique.ch".to_string(),
            "valid@ubique.ch".to_string(),
        ));
        backup.verify_user_start().await.unwrap();
    }

    // #[tokio::test]
    async fn test_verify_user_finalize() {
        let code = "824000".to_string();
        let oidc_settings = Arc::new(OidcSettings::new(
            "http://localhost:8080/oauth".into(),
            "oauth-client".into(),
            Some("secret".into()),
        ));
        let backup = Arc::new(Backuper::new(
            oidc_settings,
            "https://sprind-eudi-backup-ws-dev.ubique.ch".to_string(),
            "valud@ubique.ch".to_string(),
        ));
        backup.verify_user_finalize(code).await.unwrap();
        let token = backup.get_token().await.unwrap();
        println!("{token}");

        backup.create_backup("12345".to_string()).await.unwrap();
        let backup_restored = backup.get_backup().await.unwrap();
        assert_eq!(backup_restored, "12345".to_string());
        backup.delete_backup().await.unwrap();
        assert!(backup.get_backup().await.is_err());
    }
}
