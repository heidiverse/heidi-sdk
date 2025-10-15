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

use anyhow::anyhow;

use josekit::{
    jwe::{JweEncrypter, JweHeader},
    jwk::JwkSet,
    jwt::{self, JwtPayload},
    Map, Value,
};
use serde::{Deserialize, Serialize};

use crate::{log_warn, ApiError};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionParameters {
    jwk: josekit::jwk::Jwk,
    authorization_encrytped_response_alg: String,
    authorization_encrypted_response_enc: String,
}

impl EncryptionParameters {
    pub fn encrypt(
        &self,
        claims: Map<String, Value>,
        apu: Option<Vec<u8>>,
        apv: Option<Vec<u8>>,
    ) -> Result<String, ApiError> {
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption(self.authorization_encrypted_response_enc.clone());
        log_warn!("PEX", &self.authorization_encrypted_response_enc);
        header.set_algorithm(self.authorization_encrytped_response_alg.clone());
        log_warn!("PEX", &self.authorization_encrytped_response_alg);
        if self
            .authorization_encrytped_response_alg
            .starts_with("ECDH-ES")
        {
            let Some(apu) = apu else {
                return Err(anyhow!("No apu!").into());
            };
            let Some(apv) = apv else {
                return Err(anyhow!("No apv!").into());
            };
            header.set_agreement_partyuinfo(apu);
            header.set_agreement_partyvinfo(apv);
        }

        let payload = JwtPayload::from_map(claims).map_err(|e| anyhow!(e))?;

        let encrypter = match self.authorization_encrytped_response_alg.as_str() {
            "ECDH-ES" => Box::new(
                josekit::jwe::ECDH_ES
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "ECDH-ES+A128KW" => Box::new(
                josekit::jwe::ECDH_ES_A128KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "ECDH-ES+A192KW" => Box::new(
                josekit::jwe::ECDH_ES_A192KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "ECDH-ES+A256KW" => Box::new(
                josekit::jwe::ECDH_ES_A256KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "RSA1_5" => Box::new(
                #[allow(deprecated)]
                josekit::jwe::RSA1_5
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "RSA-OAEP" => Box::new(
                josekit::jwe::RSA_OAEP
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "A128KW" => Box::new(
                josekit::jwe::A128KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "A192KW" => Box::new(
                josekit::jwe::A192KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            "A256KW" => Box::new(
                josekit::jwe::A256KW
                    .encrypter_from_jwk(&self.jwk)
                    .map_err(|e| anyhow!(e))?,
            ) as Box<dyn JweEncrypter>,
            _ => return Err(anyhow!("Algorithm not supported").into()),
        };

        /*
        pub use AesgcmkwJweAlgorithm::A128gcmkw as A128GCMKW;
        pub use AesgcmkwJweAlgorithm::A192gcmkw as A192GCMKW;
        pub use AesgcmkwJweAlgorithm::A256gcmkw as A256GCMKW;

        pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw as PBES2_HS256_A128KW;
        pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw as PBES2_HS384_A192KW;
        pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw as PBES2_HS512_A256KW;


        pub use RsaesJweAlgorithm::RsaOaep256 as RSA_OAEP_256;
        pub use RsaesJweAlgorithm::RsaOaep384 as RSA_OAEP_384;
        pub use RsaesJweAlgorithm::RsaOaep512 as RSA_OAEP_512;
        */

        jwt::encode_with_encrypter(&payload, &header, encrypter.as_ref())
            .map_err(|e| anyhow!(e).into())
    }
}

impl TryFrom<&heidi_util_rust::value::Value> for EncryptionParameters {
    type Error = ApiError;

    fn try_from(value: &heidi_util_rust::value::Value) -> Result<Self, Self::Error> {
        let jwks: serde_json::Value = value
            .get("jwks")
            .ok_or_else(|| anyhow!("no jwks"))?
            .to_owned()
            .transform()
            .ok_or_else(|| anyhow!("transform to value failed"))?;

        let jwks: JwkSet = JwkSet::from_map(
            jwks.as_object()
                .ok_or_else(|| anyhow!("no encryption use"))?
                .clone(),
        )
        .map_err(|e| anyhow!(e))?;
        let jwk = jwks
            .keys()
            .into_iter()
            .find(|e| e.is_for_key_operation("enc"))
            .ok_or_else(|| anyhow!("no encryption use"))?
            .to_owned();
        // for now only support ECDH-ES
        let jwt_alg = jwk.algorithm().unwrap_or("ECDH-ES");
        let (authorization_encrytped_response_alg, authorization_encrypted_response_enc) = match (
            value
                .get("authorization_encrypted_response_alg")
                .and_then(|a| a.as_str()),
            value
                .get("authorization_encrypted_response_enc")
                .and_then(|a| a.as_str()),
        ) {
            (None, None) => (String::from(jwt_alg), String::from("A256GCM")),
            (Some(alg), Some(enc)) => (alg.to_string(), enc.to_string()),
            _ => return Err(anyhow!("incompatible encryption algorithms").into()),
        };
        log_warn!("PEX", &format!("{:?}", serde_json::to_string(&jwk)));
        Ok(Self {
            jwk,
            authorization_encrytped_response_alg,
            authorization_encrypted_response_enc,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use josekit::{
        jwe::JweHeader,
        jwk::Jwk,
        jwt::{self, JwtPayload},
    };
    use serde_json::json;

    use crate::presentation::helper::AuthorizationRequest;

    use super::EncryptionParameters;

    #[test]
    fn test_parsing() {
        let client_metadata = r#"{
          "response_uri": "https://demo.certification.openid.net/test/a/heidi-wallet/responseuri",
          "aud": "https://self-issued.me/v2",
          "client_id_scheme": "x509_san_dns",
          "presentation_definition": {
            "id": "************************************",
            "input_descriptors": [
              {
                "id": "full_credential_for_sd-jwt",
                "name": "All credentials descriptor for SD-JWT format",
                "purpose": "To verify the disclosure of all attributes for the SD-JWT format",
                "format": {
                  "dc+sd-jwt": {}
                },
                "group": [
                  "A"
                ],
                "constraints": {
                  "fields": [
                    {
                      "path": [
                        "$['given_name']"
                      ],
                      "purpose": "API test",
                      "name": "given_name",
                      "intent_to_retain": false,
                      "optional": false
                    }
                  ],
                  "limit_disclosure": "required"
                }
              }
            ],
            "name": "IC card check",
            "purpose": "ID card, all attributes",
            "submission_requirements": [
              {
                "name": "sample submission requirement",
                "purpose": "We only need a submission for one of two formats",
                "rule": "PICK",
                "count": 1,
                "from": "A"
              }
            ]
          },
          "response_type": "vp_token",
          "nonce": "oNNUXH7ygrKy-._~",
          "client_id": "demo.certification.openid.net",
          "client_metadata": {
            "vp_formats": {
              "dc+sd-jwt": {
                "sd-jwt_alg_values": [
                  "RS256",
                  "RS384",
                  "RS512",
                  "PS256",
                  "PS384",
                  "PS512",
                  "ES256",
                  "ES256K",
                  "ES384",
                  "ES512",
                  "EdDSA",
                  "Ed25519",
                  "Ed448"
                ],
                "kb-jwt_alg_values": [
                  "RS256",
                  "RS384",
                  "RS512",
                  "PS256",
                  "PS384",
                  "PS512",
                  "ES256",
                  "ES256K",
                  "ES384",
                  "ES512",
                  "EdDSA",
                  "Ed25519",
                  "Ed448"
                ]
              }
            },
            "jwks": {
              "keys": [
                {
                  "kty": "EC",
                  "use": "enc",
                  "crv": "P-256",
                  "x": "q483qsEP_LacxLokQJwjFeP478z79FLQKz4Ina7UXnA",
                  "y": "brI5t4BdlFDueRdMDytcUcTgXZJnxX8gmzcQ-xoMbXA",
                  "alg": "ECDH-ES"
                }
              ]
            }
          },
          "response_mode": "direct_post.jwt"
        }"#;
        let ar: AuthorizationRequest = serde_json::from_str(&client_metadata).unwrap();
        println!("{ar:?}");
        // let Some(client_metadata) = ar.body.extension.client_metadata else {
        //     panic!("")
        // };
        let client_metadata = heidi_util_rust::value::Value::from_serialize(
            &ar.body.extension.client_metadata.unwrap(),
        )
        .unwrap()
        .get("client_metadata")
        .unwrap()
        .to_owned();

        let encryption = EncryptionParameters::try_from(&client_metadata).unwrap();
        let obj = json!({
            "vp_token" : "test",
            "presentation_submission" : "other"
        })
        .as_object()
        .unwrap()
        .to_owned();
        let response = encryption
            .encrypt(
                obj,
                Some(vec![1, 2, 3, 4, 56, 7]),
                Some(vec![2, 3, 4, 5, 1, 23]),
            )
            .unwrap();

        println!("{response:?}")
    }
    #[test]
    fn test_encryption() {
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A256GCM");
        header.set_algorithm("ECDH-ES");

        header.set_agreement_partyuinfo([1, 2, 3, 4, 5, 6]);
        header.set_agreement_partyvinfo([1, 23, 4, 56, 6]);
        let mut payload = JwtPayload::new();
        payload.set_subject("test");
        payload
            .set_claim("test", Some(josekit::Value::String("".to_string())))
            .unwrap();

        let jwk = r#"{
              "kty": "EC",
              "use": "enc",
              "crv": "P-256",
              "x": "q483qsEP_LacxLokQJwjFeP478z79FLQKz4Ina7UXnA",
              "y": "brI5t4BdlFDueRdMDytcUcTgXZJnxX8gmzcQ-xoMbXA",
              "alg": "ECDH-ES"
            }"#;

        let encrypter = josekit::jwe::ECDH_ES
            .encrypter_from_jwk(&Jwk::from_bytes(jwk.as_bytes()).unwrap())
            .unwrap();
        let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter).unwrap();
        println!("{jwt}");

        let private_key = Jwk::from_bytes( r#"{"alg":"ECDH-ES", "use" : "enc","crv":"P-256","d":"cshSFzFpe3WD6RklqgkkXX1GFT3wYYjLzyS2-cAb81w","kty":"EC","x":"q483qsEP_LacxLokQJwjFeP478z79FLQKz4Ina7UXnA","y":"brI5t4BdlFDueRdMDytcUcTgXZJnxX8gmzcQ-xoMbXA"}"#).unwrap();
        let decryptor = josekit::jwe::ECDH_ES
            .decrypter_from_jwk(&private_key)
            .unwrap();
        let (payload, _header) = jwt::decode_with_decrypter(jwt.as_bytes(), &decryptor).unwrap();
        println!("{payload:?}")
    }
}
