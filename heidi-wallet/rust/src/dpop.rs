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
//! Implement a reqwet middleware being able to handle DPoP. It should automatically
//! retry requests using the fresh nonce returned from the failed response.

use anyhow::{anyhow, bail, ensure, Context};
use http::StatusCode;
use models::Payload;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    PublicKey,
};
use reqwest::header::HeaderName;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::Digest;
use task_local_extensions::Extensions;

use crate::signing::NativeSigner;

pub mod models {
    use monostate::MustBe;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Header {
        /// A field with the value dpop+jwt, which explicitly types the DPoP proof JWT
        /// as recommended in [Section 3.11](https://rfc-editor.org/rfc/rfc8725#section-3.11)
        /// of [RFC8725](https://datatracker.ietf.org/doc/html/rfc8725).
        pub typ: MustBe!("dpop+jwt"),

        /// An identifier for a JWS asymmetric digital signature algorithm from
        /// [IANA.JOSE.ALGS](https://www.iana.org/assignments/jose/).
        /// It MUST NOT be none or an identifier for a symmetric
        /// algorithm (Message Authentication Code (MAC)).
        pub alg: String,

        /// Represents the public key chosen by the client in JSON Web Key (JWK)
        /// [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) format as
        /// defined in [Section 4.1.3](https://rfc-editor.org/rfc/rfc7515#section-4.1.3)
        /// of [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515).
        /// It MUST NOT contain a private key.
        pub jwk: Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Payload {
        /// Unique identifier for the DPoP proof JWT. The value MUST be assigned such that
        /// there is a negligible probability that the same value will be assigned to any
        /// other DPoP proof used in the same context during the time window of validity.
        /// Such uniqueness can be accomplished by encoding (base64url or any other suitable
        /// encoding) at least 96 bits of pseudorandom data or by using a version 4 Universally
        /// Unique Identifier (UUID) string according to [RFC4122](https://datatracker.ietf.org/doc/html/rfc4122).
        /// The jti can be used by the server for replay detection and prevention;
        /// see [Section 11.1](https://datatracker.ietf.org/doc/html/rfc9449#Token_Replay).
        pub jti: String,

        /// The value of the HTTP method ([Section 9.1](https://rfc-editor.org/rfc/rfc9110#section-9.1)
        /// of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110)) of the request to
        /// which the JWT is attached.
        pub htm: String,

        /// The HTTP target URI ([Section 7.1](https://rfc-editor.org/rfc/rfc9110#section-7.1)
        /// of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110)) of the request to
        /// which the JWT is attached, without query and fragment parts.
        pub htu: String,

        /// Creation timestamp of the JWT
        /// ([Section 4.1.6](https://rfc-editor.org/rfc/rfc7519#section-4.1.6) of
        /// [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)).
        pub iat: u64,

        /// When the DPoP proof is used in conjunction with the presentation of an access token
        /// in protected resource access (see Section 7), the DPoP proof MUST also contain the
        /// following claim:
        ///
        /// Hash of the access token. The value MUST be the result of a base64url encoding (as
        /// defined in [Section 2](https://rfc-editor.org/rfc/rfc7515#section-2) of
        /// [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515)) the SHA-256
        /// [SHS](https://dx.doi.org/10.6028/NIST.FIPS.180-4) hash of the ASCII encoding of
        /// the associated access token's value.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ath: Option<String>,

        /// When the authentication server or resource server provides a DPoP-Nonce HTTP header
        /// in a response (see Sections [8](https://datatracker.ietf.org/doc/html/rfc9449#ASNonce)
        /// and [9](https://datatracker.ietf.org/doc/html/rfc9449#RSNonce)), the DPoP proof MUST
        /// also contain the following claim:
        ///
        /// A recent nonce provided via the DPoP-Nonce HTTP header.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nonce: Option<String>,
    }

    impl Header {}
}

/// Get the P256 public key from the jwk
pub fn public_key_from_jwk(jwk: &Value) -> anyhow::Result<PublicKey> {
    ensure!(
        jwk.get("kty")
            .context("JWK does not have 'kty' field")?
            .as_str()
            .context("JWK 'kty' field is not a string")?
            == "EC",
        "Only EC key types are supported."
    );

    ensure!(
        jwk.get("crv")
            .context("JWK does not have 'crv' field")?
            .as_str()
            .context("JWK 'crv' field is not a string")?
            == "P-256",
        "Only P-256 curve supported."
    );
    // The jwk JOSE Header Parameter does not contain a private key.
    ensure!(jwk.get("d").is_none(), "Only public keys are supported.");

    let x_bytes = base64_url_decode(
        &jwk.get("x")
            .context("JWK does not have 'x' field")?
            .as_str()
            .context("JWK 'x' field is not a string")?,
    )?;

    let y_bytes = base64_url_decode(
        &jwk.get("y")
            .context("JWK does not have 'y' field")?
            .as_str()
            .context("JWK 'y' field is not a string")?,
    )?;

    let mut encoded = vec![0x04];
    encoded.extend_from_slice(&x_bytes);
    encoded.extend_from_slice(&y_bytes);

    Ok(PublicKey::from_sec1_bytes(&encoded)?)
}

/// Validate dpop
pub fn validate_dpop(
    http_method: String,
    http_uri: String,
    http_headers: Vec<(String, String)>,
    nonce: Option<String>,
    accepted_timewindow: Option<fn(&Payload) -> bool>,
    access_token_public_key: Option<PublicKey>,
) -> anyhow::Result<()> {
    let jwt = http_headers
        .iter()
        .find_map(|(name, value)| (name.to_lowercase() == "dpop").then_some(value))
        .context("No DPoP Header present!")?;

    // 1. There is not more than one DPoP HTTP request header field.
    ensure!(
        http_headers
            .iter()
            .filter(|(name, _)| name.to_lowercase() == "dpop")
            .count()
            == 1,
        "More than one DPoP Header present!"
    );

    // 2. The DPoP HTTP request header field value is a single and well-formed JWT.
    let mut jwt_iter = jwt.split('.');
    let header = serde_json::from_str::<models::Header>(&String::from_utf8(base64_decode_bytes(
        &jwt_iter
            .next()
            .context("JWT Header not present!")?
            .as_bytes(),
    )?)?)?;

    let payload = jwt_iter
        .next()
        .context("JWT Payload not present!")?
        .as_bytes();

    let signature = jwt_iter.next().context("JWT Signature not present!")?;
    let signature = base64_url_decode(&signature)?;
    let signature = Signature::from_bytes((&signature[..]).into())
        .context("Failed to deserialize signature")?;

    ensure!(jwt_iter.next().is_none(), "JWT had more that 3 parts!");

    // 3. All required claims per Section 4.2 are contained in the JWT.
    let payload = serde_json::from_str::<models::Payload>(&String::from_utf8(
        base64_decode_bytes(&payload)?,
    )?)?;

    // 4. The typ JOSE Header Parameter has the value dpop+jwt.
    // Already validated as the 'typ' Header is a 'MustBe!("dpop+jwt")'

    // 5. The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is acceptable per local policy.
    ensure!(header.alg == "ES256", "Only 'ES256' Algorithm supported.");

    // 6. The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter.
    let public_key = public_key_from_jwk(&header.jwk)
        .context("Failed to decode PublicKey from JWK in header")?;

    let verifying_key = VerifyingKey::from(public_key);

    let to_verify = jwt.split('.').take(2).collect::<Vec<_>>().join(".");

    ensure!(
        verifying_key
            .verify(to_verify.as_bytes(), &signature)
            .is_ok(),
        "Failed to verify signature of JWT"
    );

    // 7. The jwk JOSE Header Parameter does not contain a private key. This is checked by `public_key_from_jwk`.

    // 8. The htm claim matches the HTTP method of the current request.
    ensure!(
        payload.htm == http_method,
        "'htm' claim does not match the HTTP Method."
    );

    // 9. The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.
    ensure!(
        payload.htu == http_uri,
        "'htu' claim does not match the HTTP URI."
    );

    // 10. If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value.
    if let Some(nonce) = nonce.as_ref() {
        ensure!(
            payload
                .nonce
                .as_ref()
                .context("Payload missing 'nonce' claim.")?
                == nonce,
            "'nonce' claim does not match the provided nonce"
        )
    }

    // 11. The creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window (see Section 11.1).
    if let Some(check) = accepted_timewindow {
        ensure!(
            check(&payload),
            "Creation time of the JWT is not acceptable"
        )
    }

    // 12. If presented to a protected resource in conjunction with an access token
    if let Some(pk) = access_token_public_key {
        let token = &http_headers
            .iter()
            .find_map(|(name, value)| (name.to_lowercase() == "authorization").then_some(value))
            .context("No Authorization Header present!")?
            .split(' ')
            .nth(1)
            .context("Malformed Authorization Header")?;

        // 12.1 ensure that the value of the ath claim equals the hash of that access token
        let mut hasher = sha2::Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();

        ensure!(
            payload.ath.context("Missing 'ath' claim in JWT.")? == base64_encode_bytes(&hash),
            "'ath' claim does not match access token hash!"
        );

        // 12.2 confirm that the public key to which the access token is bound matches the public key from the DPoP proof
        ensure!(
            public_key == pk,
            "PublicKey provided in the JWK does not match expected PublicKey."
        )
    }

    Ok(())
}
/// Create a dpop header for specific HTTP request, optionally using a access_token
pub fn create_dpop(
    secret_key: Arc<dyn NativeSigner>,
    method: String,
    uri: String,
    timestamp: u64,
    access_token: Option<String>,
    nonce: Option<String>,
) -> anyhow::Result<String> {
    let jwk = serde_json::from_str::<Value>(&secret_key.public_key_jwk())?;
    let alg = secret_key.alg();
    let header: models::Header = serde_json::from_value(json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk,
    }))?;

    let ath = if let Some(token) = access_token {
        let mut hasher = sha2::Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();

        Some(base64_encode_bytes(&hash))
    } else {
        None
    };

    let payload = models::Payload {
        jti: uuid::Uuid::new_v4().to_string(),
        htm: method,
        htu: uri,
        iat: timestamp,
        ath,
        nonce,
    };

    let to_sign = format!(
        "{}.{}",
        base64_url_encode(&header)?,
        base64_url_encode(&payload)?
    );

    let Ok(signature) = secret_key.sign_bytes(to_sign.as_bytes().to_vec()) else {
        bail!("Failed to sign");
    };
    let Ok(signature) = Signature::from_slice(&signature) else {
        bail!("could not deserialize signature");
    };

    let signature = base64_encode_bytes(&signature.to_bytes());

    Ok(format!("{}.{}", to_sign, signature))
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// Expose the middleware over the FFI-boundary
pub struct DpopAuth {
    native_signer: Arc<dyn NativeSigner>,
    nonce: RwLock<Option<String>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl DpopAuth {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    /// Construct a new DPoP-Auth using a [NativeSigner] (ususally SE bound keys)
    pub fn new(native_signer: Arc<dyn NativeSigner>, nonce: Option<String>) -> Self {
        Self {
            native_signer,
            nonce: RwLock::new(nonce),
        }
    }
    /// Return the key reference of the DPoP key. This reference is used to fetch
    /// the respective key later.
    pub fn get_key_reference(self: &Arc<Self>) -> Vec<u8> {
        self.native_signer.key_reference().clone()
    }

    pub fn get_key_alg(self: &Arc<Self>) -> String {
        self.native_signer.alg()
    }

    pub fn get_key(self: &Arc<Self>) -> Arc<dyn NativeSigner> {
        self.native_signer.clone()
    }
}

impl DpopAuth {
    /// Update the nonce used for authentication
    fn update_nonce(&self, response: &Response) {
        let Some(dpop_nonce) = response
            .headers()
            .get("dpop-nonce")
            .and_then(|a| a.to_str().ok())
        else {
            return;
        };
        let _ = self.nonce.write().map(|mut a| {
            *a = Some(dpop_nonce.to_string());
        });
    }
    /// prepare the request to contain the correct headers for DPoP authentication
    fn prepare_dpop(&self, req: &mut Request) -> anyhow::Result<String> {
        let method = req.method().to_string();
        let mut url = req.url().clone();
        url.set_query(None);
        url.set_fragment(None);
        let start = SystemTime::now();
        let timestamp = unix_timestamp(start);

        if let Some(auth) = req.headers_mut().get_mut("authorization") {
            let Ok(auth_str) = auth.to_str() else {
                bail!("invalid utf8");
            };
            let auth_header = auth_str.replace("Bearer", "DPoP");
            let Ok(auth_header) = auth_header.parse() else {
                bail!("invalid header value");
            };
            *auth = auth_header;
        }

        let auth_header = if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(auth_header) = auth.to_str() {
                let header = auth_header.replace("DPoP ", "").trim().to_string();

                Some(header)
            } else {
                None
            }
        } else {
            None
        };
        let Ok(mut nonce_lock) = self.nonce.write() else {
            bail!("could not lock nonce");
        };

        let dpop = match create_dpop(
            self.native_signer.clone(),
            method,
            url.to_string(),
            timestamp.as_secs(),
            auth_header,
            nonce_lock.take(),
        ) {
            Ok(dpop) => dpop,
            Err(e) => return Err(e),
        };

        Ok(dpop)
    }
}

#[allow(clippy::expect_used)]
/// Calculate the duration since UNIX_EPOCH. This should never panic, as time, ideally, runs forward.
fn unix_timestamp(start: SystemTime) -> std::time::Duration {
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
}

pub(crate) struct DpopWrapper(pub(crate) Arc<DpopAuth>);
#[async_trait::async_trait]
#[allow(clippy::unwrap_used)]
/// We allow unwrap in here, since it is only on the header value and name (which we know are valid names)
impl Middleware for DpopAuth {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let request_clone = req.try_clone();
        let next_clone = next.clone();

        let dpop = match self.prepare_dpop(&mut req) {
            Ok(dpop) => dpop,
            Err(e) => {
                return Err(reqwest_middleware::Error::Middleware(anyhow!(
                    "Could not generate dpop: {e}"
                )));
            }
        };

        req.headers_mut()
            .append("dpop".parse::<HeaderName>().unwrap(), dpop.parse().unwrap());
        let response = next.run(req, extensions).await;
        let Ok(response) = response else {
            return Err(reqwest_middleware::Error::Middleware(anyhow!(
                "executing request failed"
            )));
        };
        if response.status().is_client_error() {
            let status = response.status().clone();
            let headers = response.headers().clone();
            let json = response.text().await?;

            let mut resp = http::Response::new(json.to_string());
            *resp.headers_mut() = headers;
            *resp.status_mut() = status;

            let response = reqwest::Response::from(resp);
            if status == StatusCode::BAD_REQUEST {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json) {
                    if let Some(true) = json
                        .get("error")
                        .and_then(|a| a.as_str())
                        .map(|a| a != "use_dpop_nonce")
                    {
                        return Ok(response);
                    }
                }
            }

            self.update_nonce(&response);
            let Some(mut request_clone) = request_clone else {
                println!("request clone was none");
                return Ok(response);
            };
            let dpop = match self.prepare_dpop(&mut request_clone) {
                Ok(dpop) => dpop,
                Err(e) => {
                    return Err(reqwest_middleware::Error::Middleware(anyhow!(
                        "Could not generate dpop: {e}"
                    )));
                }
            };

            request_clone
                .headers_mut()
                .append("dpop".parse::<HeaderName>().unwrap(), dpop.parse().unwrap());
            let response = next_clone.run(request_clone, extensions).await;
            let Ok(response) = response else {
                return Err(reqwest_middleware::Error::Middleware(anyhow!(
                    "executing request failed"
                )));
            };

            self.update_nonce(&response);
            return Ok(response);
        }

        self.update_nonce(&response);
        return Ok(response);
    }
}

impl Deref for DpopWrapper {
    type Target = Arc<DpopAuth>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait::async_trait]
impl Middleware for DpopWrapper {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        self.0.handle(req, extensions, next).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{create_dpop, public_key_from_jwk, validate_dpop, DpopAuth};
    use std::net::TcpListener;
    use std::sync::Arc;

    use crate::error::SigningError;
    use crate::issuance::helper::bytes_to_ec_jwk;
    use crate::signing::NativeSigner;
    use did_key::{generate, KeyMaterial, P256KeyPair};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::{ecdsa::VerifyingKey, PublicKey, SecretKey};
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockGuard, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_dpop_middleware() {
        async fn mount_mocks(addr: &str, mocks: Vec<Mock>) -> (MockServer, Vec<MockGuard>) {
            // let mocks = mocks.to_vec();

            let mock_server = MockServer::builder()
                .listener(TcpListener::bind(addr).unwrap())
                .start()
                .await;
            let mut guards = vec![];
            for m in mocks {
                let guard = m.mount_as_scoped(&mock_server).await;
                guards.push(guard);
            }
            (mock_server, guards)
        }

        let kp = generate::<P256KeyPair>(None);

        let secret_key = SecretKey::from_bytes(kp.private_key_bytes().as_slice().into()).unwrap();
        let signer = Arc::new(TestSigner(secret_key));
        let signer_clone = signer.clone();
        let signer_clone2 = signer.clone();

        let (_guard_1234, _server_1234) = mount_mocks(
            "127.0.0.1:1234",
            vec![
                Mock::given(method("GET"))
                    .and(path("/dpop"))
                    .and(header_exists("dpop"))
                    .respond_with(move |req: &wiremock::Request| {
                        let method = req.method.to_string();
                        let headers = req
                            .headers
                            .iter()
                            .map(|(a, b)| (a.to_string(), b.to_str().unwrap().to_string()))
                            .collect::<Vec<(String, String)>>();
                        let mut uri = req.url.clone();
                        uri.set_fragment(None);
                        uri.set_query(None);
                        // for some reason wiremock does not add the port
                        let _ = uri.set_port(Some(1234));
                        let key = signer_clone.0.public_key();

                        let result =
                            validate_dpop(method, uri.to_string(), headers, None, None, if req.headers.get("authorization").is_some() { Some(key) } else { None });
                        ResponseTemplate::new(if result.is_ok() { 200 } else { 401 })
                            .set_body_string("body")
                    }),
                Mock::given(method("GET"))
                    .and(path("/dpop_with_nonce"))
                    .and(header_exists("dpop"))
                    .respond_with(move |req: &wiremock::Request| {
                        let _header = req.headers.get("dpop").unwrap();
                        let signer_clone = signer_clone2.clone();
                        let method = req.method.to_string();
                        let headers = req
                            .headers
                            .iter()
                            .map(|(a, b)| (a.to_string(), b.to_str().unwrap().to_string()))
                            .collect::<Vec<(String, String)>>();
                        let mut uri = req.url.clone();
                        uri.set_fragment(None);
                        uri.set_query(None);
                        // for some reason wiremock does not add the port
                        let _ = uri.set_port(Some(1234));
                        let key = signer_clone.0.public_key();

                        let result =
                            validate_dpop(method, uri.to_string(), headers, Some("1234".to_string()), None, if req.headers.get("authorization").is_some() { Some(key) } else { None });
                        ResponseTemplate::new(if result.is_ok() { 200 } else { 401 })
                            .set_body_string("body")
                    }),
                Mock::given(method("GET")).and(path("/token")).respond_with(
                    move |req: &wiremock::Request| {
                        let _header = req.headers.get("dpop").unwrap();

                        let method = req.method.to_string();
                        let headers = req
                            .headers
                            .iter()
                            .map(|(a, b)| (a.to_string(), b.to_str().unwrap().to_string()))
                            .collect::<Vec<(String, String)>>();
                        let mut uri = req.url.clone();
                        uri.set_fragment(None);
                        uri.set_query(None);
                        // for some reason wiremock does not add the port
                        let _ = uri.set_port(Some(1234));

                        let result =
                            validate_dpop(method, uri.to_string(), headers, None, None, None);
                        // token_table.lock().unwrap().insert("spxP0XgdwAg5ACtOsmNlMp".to_string(), )
                        if result.is_ok() {
                            ResponseTemplate::new(200)
                                .insert_header("DPoP-Nonce", "1234")
                                .set_body_string(r#"
                                {"access_token":"spxP0XgdwAg5ACtOsmNlMp","token_type":"DPoP","expires_in":3600,"c_nonce":"8xZJLDUCl83eEfz99W5RIY","c_nonce_expires_in":3600}
                                "#)
                        } else {
                            ResponseTemplate::new(401).set_body_string("body")
                        }
                    },
                ),
            ],
        )
            .await;
        // test dpop without access_token
        let middleware = DpopAuth::new(signer, None);
        let client = ClientBuilder::new(Client::new()).with(middleware).build();
        let request = client.get("http://localhost:1234/dpop").build().unwrap();
        let result = client.execute(request).await.unwrap();
        assert_eq!(200, result.status());

        //request an access_token bound to a key (and nonce)
        let request = client.get("http://localhost:1234/token").build().unwrap();
        let result = client.execute(request).await.unwrap();
        assert_eq!(200, result.status());
        let token: serde_json::Value = result.json().await.unwrap();
        let access_token = token
            .get("access_token")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let request = client
            .get("http://localhost:1234/dpop_with_nonce")
            .header("Authorization".to_string(), format!("DPoP {access_token}"))
            .build()
            .unwrap();
        let result = client.execute(request).await.unwrap();
        assert_eq!(200, result.status());

        let request = client
            .get("http://localhost:1234/dpop_with_nonce")
            .header("Authorization".to_string(), format!("DPoP {access_token}"))
            .build()
            .unwrap();
        let result = client.execute(request).await.unwrap();
        // this request should fail, since we used our nonce
        assert_eq!(401, result.status());
    }
    #[test]
    fn should_decode_jwk() {
        let jwk = json!({
            "kty":"EC",
            "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
            "crv":"P-256"
        });

        let result = public_key_from_jwk(&jwk);

        assert!(result.is_ok());

        let _ = VerifyingKey::from(result.unwrap());
    }

    #[test]
    fn should_validate_proof() {
        let proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik\
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR\
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE\
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj\
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia\
 WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg\
 4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
            .to_string();

        let method = "POST".into();
        let uri = "https://server.example.com/token".into();
        let headers = vec![("DPoP".into(), proof)];

        validate_dpop(method, uri, headers, None, None, None).unwrap();
    }

    #[test]
    fn should_validate_proof_with_auth() {
        let proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik\
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR\
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE\
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj\
 oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z\
 WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF\
 c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E\
 OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
            .to_string();

        let method = "GET".to_string();
        let uri = "https://resource.example.org/protectedresource".to_string();

        let access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU".to_string();
        let public_key = public_key_from_jwk(&json!({
            "kty":"EC",
            "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
            "crv":"P-256"
        }))
        .unwrap();

        let headers = vec![
            ("DPoP".to_string(), proof),
            ("Authorization".to_string(), format!("DPoP {access_token}")),
        ];

        validate_dpop(method, uri, headers, None, None, Some(public_key)).unwrap();
    }

    #[derive(Debug)]
    struct TestSigner(SecretKey);
    impl NativeSigner for TestSigner {
        fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError> {
            self.sign_bytes(msg.as_bytes().to_vec())
        }
        fn key_reference(&self) -> Vec<u8> {
            vec![]
        }
        fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError> {
            let signing_key = SigningKey::from(&self.0);
            let (signature, _) = signing_key.sign(&msg);
            Ok(signature.to_vec())
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.public_key().to_sec1_bytes().to_vec()
        }

        fn key_id(&self) -> String {
            todo!()
        }

        fn jwt_header(&self) -> String {
            todo!()
        }

        fn alg(&self) -> String {
            "ES256".to_string()
        }
        fn public_key_jwk(&self) -> String {
            bytes_to_ec_jwk(self.public_key().clone()).unwrap_or_default()
        }

        fn private_key(&self) -> Result<Vec<u8>, SigningError> {
            todo!()
        }

        fn private_key_exportable(&self) -> bool {
            todo!()
        }
        fn key_attestation(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn should_create_dpop() {
        let kp = generate::<P256KeyPair>(None);

        let secret_key = SecretKey::from_bytes(kp.private_key_bytes().as_slice().into()).unwrap();

        let dpop = create_dpop(
            Arc::new(TestSigner(secret_key)),
            "GET".to_string(),
            "https://example.com/token".to_string(),
            0,
            None,
            Some("123".to_string()),
        )
        .unwrap();

        println!("{dpop}");
    }

    #[test]
    fn should_validate_roundtrip() {
        let kp = generate::<P256KeyPair>(None);

        let secret_key = SecretKey::from_bytes(kp.private_key_bytes().as_slice().into()).unwrap();
        let public_key = PublicKey::from_sec1_bytes(kp.public_key_bytes().as_slice()).unwrap();

        let dpop = create_dpop(
            Arc::new(TestSigner(secret_key)),
            "GET".to_string(),
            "https://example.com/token".to_string(),
            0,
            Some("token".to_string()),
            Some("123".to_string()),
        )
        .unwrap();

        validate_dpop(
            "GET".to_string(),
            "https://example.com/token".to_string(),
            vec![
                ("DPoP".to_string(), dpop),
                ("Authorization".to_string(), "DPoP token".to_string()),
            ],
            Some("123".to_string()),
            None,
            Some(public_key),
        )
        .unwrap();
    }
}
