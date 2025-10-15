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

use std::sync::Arc;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Verifier;
use rand::rngs::OsRng;
use crate::crypto::{base64_url_decode, SignatureCreator};

pub enum KeyType {
    P256,
}
#[derive(Debug, Clone)]
pub enum KeyPair {
    P256 {
        private_key: p256::SecretKey,
        public_key: p256::PublicKey,
    },
}

pub fn generate_keypair() -> KeyPair {
    let private_key = p256::SecretKey::random(&mut OsRng);
    let public_key = private_key.public_key();
    KeyPair::P256 {
        private_key,
        public_key,
    }
}
pub fn from_private_key(private_key: Vec<u8>) -> Option<KeyPair> {
    let private_key = p256::SecretKey::from_slice(&private_key).ok()?;
    let public_key = private_key.public_key();
    Some(KeyPair::P256 {
        private_key,
        public_key,
    })
}
pub fn from_private_jwk_string(private_key: &str) -> Option<KeyPair> {
    let private_key = p256::SecretKey::from_jwk_str(private_key).ok()?;
    let public_key = private_key.public_key();
    Some(KeyPair::P256 {
        private_key,
        public_key,
    })
}


impl KeyPair {
    pub fn sign_with_key(&self, message: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        match self {
            Self::P256 { private_key, .. } => {
                let signing_key: SigningKey = private_key.into();
                let signature: Signature = signing_key.sign(&message);
                Ok(signature.to_vec())
            }
        }
    }
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::P256 {
                private_key,
                public_key: _,
            } => private_key.to_bytes().to_vec(),
        }
    }
    pub fn public_key_sec1(&self) -> Vec<u8> {
        match self {
            Self::P256 {
                private_key: _,
                public_key,
            } => public_key.to_sec1_bytes().to_vec(),
        }
    }
    pub fn jwk_string(&self) -> String {
        match self {
            Self::P256 {
                private_key: _,
                public_key,
            } => public_key.to_jwk_string(),
        }
    }
    pub fn private_jwk_string(&self) -> String {
        match self {
            Self::P256 {
                private_key: pk,
                public_key: _,
            } => pk.to_jwk_string().to_string(),
        }
    }
}

use crate::SigningError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SoftwareKeyPair(KeyPair);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct VerificationKey(VerifyingKey);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl VerificationKey {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_coords(x: String, y: String) -> Self {
        let x_bytes = base64_url_decode(x);
        let y_bytes = base64_url_decode(y);
        let mut key_bytes = vec![0x04];
        key_bytes.extend_from_slice(x_bytes.as_slice());
        key_bytes.extend_from_slice(y_bytes.as_slice());
        let vp : VerifyingKey = VerifyingKey::from_sec1_bytes(&key_bytes).unwrap();
        Self(vp)
    }

    fn verify(self: Arc<Self>, signature: Vec<u8>, data: Vec<u8>) -> bool {
        let sig = if let Ok(sig) = Signature::from_slice(&signature)  {
            println!("normal");
            sig
        } else if let Ok(sig) = Signature::from_der(&signature) {
            println!("from der");
            sig
        }
        else {
            return false;
        };
        self.0.verify(&data, &sig).map(|_| true).unwrap_or(false)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SoftwareKeyPair {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Self {
        Self(generate_keypair())
    }
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_private_key(private_key: Vec<u8>) -> Arc<Self> {
        Arc::new(Self(
            from_private_key(private_key).unwrap_or(generate_keypair()),
        ))
    }
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_jwk_string(jwk_string: &str) -> Arc<Self> {
      Arc::new(Self(from_private_jwk_string(jwk_string).unwrap_or(generate_keypair())))
    }

    pub fn sign_with_key(&self, message: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        self.0.sign_with_key(message)
    }
    pub fn jwk_string(&self) -> String {
        self.0.jwk_string()
    }
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.0.public_key_sec1()
    }
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.0.private_key_bytes()
    }
    pub fn private_jwk_string(&self) -> String {
        self.0.private_jwk_string()
    }
    pub fn as_signature_creator(self: Arc<Self>) -> Arc<dyn SignatureCreator> {
        self.clone()
    }
}

impl SignatureCreator for SoftwareKeyPair {
    fn alg(&self) -> String {
        match self.0 { KeyPair::P256 { .. } => { String::from("ES256")} }
    }

    fn sign(&self, bytes: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        self.0.sign_with_key(bytes)
    }
}

// impl NativeSigner for SoftwareKeyPair {
//     fn key_reference(&self) -> Vec<u8> {
//         let id: [u8; 32] = rand::random();
//         id.to_vec()
//     }
//
//     fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError> {
//         self.sign_bytes(msg.as_bytes().to_vec())
//     }
//
//     fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError> {
//         self.0
//             .sign_with_key(msg)
//             .map_err(|_| SigningError::FailedToSign)
//     }
//
//     fn public_key(&self) -> Vec<u8> {
//         self.0.public_key_sec1()
//     }
//
//     fn key_id(&self) -> String {
//         let digest = Sha256::digest(&self.0.public_key_sec1()).to_vec();
//         base64::prelude::BASE64_STANDARD_NO_PAD.encode(&digest)
//     }
//
//     fn jwt_header(&self) -> String {
//         let jwk = self.public_key_jwk();
//         let output =
//             format!("{{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\",\"jwk\" : {jwk} }}");
//         output
//     }
//
//     fn alg(&self) -> String {
//         String::from("ES256")
//     }
//
//     fn public_key_jwk(&self) -> String {
//         self.0.jwk_string()
//     }
//
//     fn private_key(&self) -> Result<Vec<u8>, SigningError> {
//         Ok(self.0.private_key_bytes())
//     }
//
//     fn private_key_exportable(&self) -> bool {
//         true
//     }
//
//     fn key_attestation(&self) -> Option<String> {
//         None
//     }
// }
