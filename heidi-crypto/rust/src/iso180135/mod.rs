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

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadMut};
use heidi_util_rust::log::{LogPriority, log};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Copy, Clone)]
pub enum KeyType {
    P256,
    P384,
    P521,
    Ed25519,
    #[cfg(feature = "x448")]
    Ed448,
}

pub enum EphemeralSecretKey {
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
    Ed25519(x25519_dalek::EphemeralSecret),
    #[cfg(feature = "x448")]
    Ed448(x448::Secret),
}

impl EphemeralSecretKey {
    pub fn random(key_type: KeyType) -> Self {
        match key_type {
            KeyType::P256 => Self::P256(p256::ecdh::EphemeralSecret::random(&mut OsRng)),
            KeyType::P384 => Self::P384(p384::ecdh::EphemeralSecret::random(&mut OsRng)),
            KeyType::P521 => Self::P521(p521::ecdh::EphemeralSecret::random(&mut OsRng)),
            KeyType::Ed25519 => {
                Self::Ed25519(x25519_dalek::EphemeralSecret::random_from_rng(&mut OsRng))
            }
            #[cfg(feature = "x448")]
            KeyType::Ed448 => {
                // Problems with different trait versions, fill bytes here directly
                use rand::RngCore;
                let mut bytes = [0u8; 56];
                OsRng.fill_bytes(&mut bytes);
                Self::Ed448(x448::Secret::from(bytes))
            }
        }
    }
    pub fn public_key(k: &Self) -> Vec<u8> {
        match k {
            EphemeralSecretKey::P256(ephemeral_secret) => {
                ephemeral_secret.public_key().to_sec1_bytes().to_vec()
            }
            EphemeralSecretKey::P384(ephemeral_secret) => {
                ephemeral_secret.public_key().to_sec1_bytes().to_vec()
            }
            EphemeralSecretKey::P521(ephemeral_secret) => {
                ephemeral_secret.public_key().to_sec1_bytes().to_vec()
            }
            EphemeralSecretKey::Ed25519(ephemeral_secret) => {
                x25519_dalek::PublicKey::from(ephemeral_secret)
                    .to_bytes()
                    .to_vec()
            }
            #[cfg(feature = "x448")]
            EphemeralSecretKey::Ed448(ephemeral_secret) => {
                x448::PublicKey::from(ephemeral_secret).as_bytes().to_vec()
            }
        }
    }
    pub fn diffie_hellman(self, peer_public_key: &[u8]) -> Option<Vec<u8>> {
        Some(match self {
            EphemeralSecretKey::P256(ephemeral_secret) => {
                let pub_key = p256::PublicKey::from_sec1_bytes(peer_public_key).ok()?;
                ephemeral_secret
                    .diffie_hellman(&pub_key)
                    .raw_secret_bytes()
                    .to_vec()
            }
            EphemeralSecretKey::P384(ephemeral_secret) => {
                let pub_key = p384::PublicKey::from_sec1_bytes(peer_public_key).ok()?;
                ephemeral_secret
                    .diffie_hellman(&pub_key)
                    .raw_secret_bytes()
                    .to_vec()
            }
            EphemeralSecretKey::P521(ephemeral_secret) => {
                let pub_key = p521::PublicKey::from_sec1_bytes(peer_public_key).ok()?;
                ephemeral_secret
                    .diffie_hellman(&pub_key)
                    .raw_secret_bytes()
                    .to_vec()
            }
            EphemeralSecretKey::Ed25519(ephemeral_secret) => {
                let mut pub_key = [0u8; 32];
                if peer_public_key.len() != 32 {
                    return None;
                }
                pub_key.copy_from_slice(&peer_public_key[..32]);
                let pub_key = x25519_dalek::PublicKey::try_from(pub_key).ok()?;
                ephemeral_secret
                    .diffie_hellman(&pub_key)
                    .to_bytes()
                    .to_vec()
            }
            #[cfg(feature = "x448")]
            EphemeralSecretKey::Ed448(ephemeral_secret) => {
                let pub_key = x448::PublicKey::from_bytes(peer_public_key)?;
                ephemeral_secret
                    .to_diffie_hellman(&pub_key)?
                    .as_bytes()
                    .to_vec()
            }
        })
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EphemeralKey {
    key: Arc<Mutex<Option<EphemeralSecretKey>>>,
    public_key: Vec<u8>,
    role: Role,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    SkReader,
    SkDevice,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EphemeralKey {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(role: Role, key_type: KeyType) -> Self {
        let ephemeral_secret = EphemeralSecretKey::random(key_type);
        let public_key = EphemeralSecretKey::public_key(&ephemeral_secret);
        Self {
            key: Arc::new(Mutex::new(Some(ephemeral_secret))),
            public_key,
            role,
        }
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    pub fn get_session_cipher(
        &self,
        session_transcript: &[u8],
        peer_public_key: &[u8],
    ) -> Option<Arc<SessionCipher>> {
        let Ok(mut guard) = self.key.lock() else {
            return None;
        };
        let Some(k) = guard.take() else {
            return None;
        };
        let shared_secret = k.diffie_hellman(peer_public_key)?;
        let sk_reader_key =
            hkdf_iso_180135(shared_secret.as_slice(), session_transcript, Role::SkReader);
        let sk_device_key =
            hkdf_iso_180135(shared_secret.as_slice(), session_transcript, Role::SkDevice);
        Some(Arc::new(SessionCipher {
            sk_reader_key,
            sk_device_key,
            sk_reader_msg_count: 1.into(),
            sk_device_msg_count: 1.into(),
            role: self.role,
        }))
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hkdf_iso_180135(key_material: &[u8], session_transcript: &[u8], role: Role) -> Vec<u8> {
    let hashed_session_transcript = Sha256::digest(session_transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(&hashed_session_transcript), key_material);
    let mut key_output = vec![0; 32];
    let _ = hkdf.expand(
        match role {
            Role::SkReader => "SKReader".as_bytes(),
            Role::SkDevice => "SKDevice".as_bytes(),
        },
        &mut key_output,
    );
    return key_output;
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SessionCipher {
    sk_reader_key: Vec<u8>,
    sk_device_key: Vec<u8>,
    sk_reader_msg_count: AtomicU32,
    sk_device_msg_count: AtomicU32,
    role: Role,
}
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SessionCipher {
    fn encrypt_reader(&self, data: &[u8]) -> Option<Vec<u8>> {
        let epoch = self.sk_reader_msg_count.fetch_add(1, Ordering::Relaxed);
        log(
            LogPriority::DEBUG,
            "ISO",
            &format!("encrypt reader epoch {}", epoch),
        );
        encrypt_epoch_iso_180135(data, &self.sk_reader_key, Role::SkReader, epoch)
    }
    fn decrypt_reader(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let epoch = self.sk_reader_msg_count.fetch_add(1, Ordering::Relaxed);
        decrypt_epoch_iso_180135(ciphertext, &self.sk_reader_key, Role::SkReader, epoch)
    }
    fn encrypt_device(&self, data: &[u8]) -> Option<Vec<u8>> {
        let epoch = self.sk_device_msg_count.fetch_add(1, Ordering::Relaxed);
        log(
            LogPriority::DEBUG,
            "ISO",
            &format!("encrypt device epoch {}", epoch),
        );
        encrypt_epoch_iso_180135(data, &self.sk_device_key, Role::SkDevice, epoch)
    }
    fn decrypt_device(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let epoch = self.sk_device_msg_count.fetch_add(1, Ordering::Relaxed);
        decrypt_epoch_iso_180135(ciphertext, &self.sk_device_key, Role::SkDevice, epoch)
    }

    pub fn encrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self.role {
            Role::SkReader => self.encrypt_reader(data),
            Role::SkDevice => self.encrypt_device(data),
        }
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        match self.role {
            Role::SkReader => self.decrypt_device(ciphertext),
            Role::SkDevice => self.decrypt_reader(ciphertext),
        }
    }
}

pub const MDOC_READER_IDENTIFIER: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const MDOC_IDENTIFIER: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encrypt_epoch_iso_180135(
    data: &[u8],
    key: &[u8],
    role: Role,
    epoch: u32,
) -> Option<Vec<u8>> {
    let mut cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(match role {
        Role::SkReader => &MDOC_READER_IDENTIFIER,
        Role::SkDevice => &MDOC_IDENTIFIER,
    });
    nonce[8..].copy_from_slice(&epoch.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce);
    Some(cipher.encrypt(nonce, data).ok()?)
}
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn decrypt_epoch_iso_180135(
    ciphertext: &[u8],
    key: &[u8],
    role: Role,
    epoch: u32,
) -> Option<Vec<u8>> {
    let mut cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(match role {
        Role::SkReader => &MDOC_READER_IDENTIFIER,
        Role::SkDevice => &MDOC_IDENTIFIER,
    });
    nonce[8..].copy_from_slice(&epoch.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce);
    Some(cipher.decrypt(nonce, ciphertext).ok()?)
}

#[cfg(test)]
mod tests {
    use crate::iso180135::{
        EphemeralKey, KeyType, Role, decrypt_epoch_iso_180135, encrypt_epoch_iso_180135,
    };

    #[test]
    pub fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let data = b"Hello, World!";
        let encrypted = encrypt_epoch_iso_180135(data, &key, Role::SkReader, 1).unwrap();
        let decrypted = decrypt_epoch_iso_180135(&encrypted, &key, Role::SkReader, 1).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
    #[test]
    pub fn test_encrypt_decrypt_sk_device() {
        for key_type in [
            KeyType::P256,
            KeyType::P384,
            KeyType::P521,
            KeyType::Ed25519,
            #[cfg(feature = "x448")]
            KeyType::Ed448,
        ] {
            let mdoc_reader = EphemeralKey::new(Role::SkReader, key_type);
            let mdoc = EphemeralKey::new(Role::SkDevice, key_type);
            let mdoc_reader_session = mdoc_reader
                .get_session_cipher(&vec![], &mdoc.public_key())
                .unwrap();
            let mdoc_session = mdoc
                .get_session_cipher(&vec![], &mdoc_reader.public_key())
                .unwrap();

            let cipher_reader_to_mdoc = mdoc_reader_session.encrypt(b"hallo").unwrap();
            let decrypted = mdoc_session.decrypt(&cipher_reader_to_mdoc).unwrap();
            assert_eq!(b"hallo", decrypted.as_slice());
            let cipher_mdoc_to_reader = mdoc_session.encrypt("hallo zurück".as_bytes()).unwrap();
            let decrypted = mdoc_reader_session.decrypt(&cipher_mdoc_to_reader).unwrap();
            assert_eq!("hallo zurück".as_bytes(), decrypted.as_slice());
            let cipher_mdoc_to_reader = mdoc_session.encrypt("hallo zurück".as_bytes()).unwrap();
            let decrypted = mdoc_reader_session.decrypt(&cipher_mdoc_to_reader).unwrap();
            assert_eq!("hallo zurück".as_bytes(), decrypted.as_slice());
            let cipher_mdoc_to_reader = mdoc_session.encrypt("hallo zurück".as_bytes()).unwrap();
            let decrypted = mdoc_reader_session.decrypt(&cipher_mdoc_to_reader).unwrap();
            assert_eq!("hallo zurück".as_bytes(), decrypted.as_slice());
            let cipher_mdoc_to_reader = mdoc_session.encrypt("hallo zurück".as_bytes()).unwrap();
            let decrypted = mdoc_reader_session.decrypt(&cipher_mdoc_to_reader).unwrap();
            assert_eq!("hallo zurück".as_bytes(), decrypted.as_slice());
            let cipher_reader_to_mdoc = mdoc_reader_session.encrypt(b"hallo").unwrap();
            let decrypted = mdoc_session.decrypt(&cipher_reader_to_mdoc).unwrap();
            assert_eq!(b"hallo", decrypted.as_slice());
        }
    }
}
