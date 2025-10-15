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
    atomic::{AtomicU32, Ordering},
    Arc,
};

use aes_gcm::{aead::AeadMut, Aes256Gcm, KeyInit, Nonce};
use heidi_util_rust::log::{log, LogPriority};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EphemeralKey {
    key: p256::ecdh::EphemeralSecret,
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
    pub fn new(role: Role) -> Self {
        Self {
            key: p256::ecdh::EphemeralSecret::random(&mut OsRng),
            role,
        }
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_sec1_bytes().to_vec()
    }
    pub fn get_session_cipher(
        &self,
        session_transcript: &[u8],
        peer_public_key: &[u8],
    ) -> Option<Arc<SessionCipher>> {
        let peer_public_key = p256::PublicKey::from_sec1_bytes(peer_public_key).ok()?;
        let shared_secret = self.key.diffie_hellman(&peer_public_key);
        let sk_reader_key = hkdf_iso_180135(
            shared_secret.raw_secret_bytes(),
            session_transcript,
            Role::SkReader,
        );
        let sk_device_key = hkdf_iso_180135(
            shared_secret.raw_secret_bytes(),
            session_transcript,
            Role::SkDevice,
        );
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
        decrypt_epoch_iso_180135, encrypt_epoch_iso_180135, EphemeralKey, Role,
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
        let mdoc_reader = EphemeralKey::new(Role::SkReader);
        let mdoc = EphemeralKey::new(Role::SkDevice);
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
