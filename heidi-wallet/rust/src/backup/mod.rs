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

//! This module provides crypto operations to generate and restore the backups.
//! The module uses shamir secret sharing to generate a secret key, used to encrypt
//! the backup with AES-GCM. After encryption the backup is split into equal parts.
//!
//! Restoring a backup does the reverse part, it assembles the encrypted blob from its parts
//! and uses the key shares to reconstruct the secret part. We don't have authenticity checks on the
//! shamir secret part, but the AES-GCM decryption gives us a TAG which tells us if the file is integre.
use std::io::{Cursor, Read};

#[cfg(feature = "reqwest")]
pub mod backend;
#[cfg(target_family = "wasm")]
pub mod wasm;

use aes_gcm::{aead::Aead, Aes256Gcm};
use anyhow::{bail, Context};
use ark_secp256r1::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use elliptic_curve::generic_array::GenericArray;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use secret_sharing_and_dkg::{
    common::{Share, Shares},
    shamir_ss::deal_random_secret,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use anyhow::anyhow;

use crate::{error::BackupError, unix_timestamp};

use crate::frost::{FrostBackup, PassphraseBackup, Split};
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Backup {
    shares: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Create a backup from a file, generating [number_of_shares] key shares and backup parts. If used with frost,
/// it appends the relevant FROST signature keys to the backup payload.
///
/// In the current implementation, due to implementation ease, the frost blob is put inside the backup file. In a future implementation,
/// the frost blob would be stored outside the backup, to allow possible emergency pass usage without restoring the backup.
fn create_backup(
    file: Vec<u8>,
    number_of_shares: u16,
    with_frost: Option<FrostBackup>,
) -> Result<Backup, BackupError> {
    // generate key shares
    let (secret, key_shares, _) =
        deal_random_secret::<_, Fr>(&mut OsRng, number_of_shares, number_of_shares)
            .map_err(|e| BackupError::CreatingSharedSecretFailed(anyhow!("{e:?}")))?;
    // derive key material using HKDF based on the shamir secret
    let (key, mut ivs) = derive_key_material(secret, number_of_shares, b"email".to_vec())
        .map_err(|e| BackupError::DeriveKeyMaterialFailed(anyhow!(e)))?;

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| BackupError::DeriveKeyMaterialFailed(anyhow!(e)))?;

    let shasum = Sha256::digest(&file).to_vec();

    let Some(iv) = ivs.pop() else {
        return Err(BackupError::DeriveKeyMaterialFailed(anyhow!("too few IVs")));
    };
    let nonce = GenericArray::from_slice(&iv);
    let result = cipher
        .encrypt(nonce, file.as_slice())
        .map_err(|e| BackupError::EncryptionFailed(anyhow!(e)))?;
    // split the encrypted file into n parts
    #[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
    let file_parts = split_file(result, number_of_shares, with_frost)?;

    #[cfg(not(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp")))]
    let file_parts = split_file(result, number_of_shares)?;

    let mut shares = vec![];
    let mut my_shares = key_shares.0;
    // define a specific order on the keys
    my_shares.sort_by(|a, b| a.id.cmp(&b.id));
    let timestamp = unix_timestamp!();
    // serialize the secret share using CBOR encoding and appending the file.
    for (file_part, share) in file_parts.iter().zip(my_shares) {
        let mut share: SerializeableShare = (share.id, share.threshold, share.share)
            .try_into()
            .map_err(|e| BackupError::SerializationFailed(anyhow!("{e}")))?;
        share.timestamp = timestamp;
        share.shasum = shasum.clone();
        let mut final_bytes = vec![];
        ciborium::into_writer(&share, &mut final_bytes)
            .map_err(|e| BackupError::SerializationFailed(anyhow!(e)))?;
        let size = (final_bytes.len() as u64).to_be_bytes();
        for byte in size.iter().rev() {
            final_bytes.insert(0, *byte);
        }
        final_bytes.extend_from_slice(file_part);
        shares.push(final_bytes);
    }
    Ok(Backup { shares })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Deserialize all backup parts to recover the shamir secret, using it
/// to derive the AES key material and decrypt the file.
pub fn reconstruct(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, BackupError> {
    let mut serializable_shares = vec![];
    let mut shasum: Option<Vec<u8>> = None;
    let mut timestamp: Option<u64> = None;
    for share in shares {
        let mut c = Cursor::new(share);
        let mut length_buffer: [u8; 8] = [0; 8];
        c.read_exact(&mut length_buffer)
            .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;
        let size = u64::from_be_bytes(length_buffer);
        let mut share_bytes = vec![0; size as usize];
        c.read_exact(&mut share_bytes)
            .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;
        let mut cipher_text = vec![];
        c.read_to_end(&mut cipher_text)
            .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;

        let share: SerializeableShare = ciborium::from_reader(Cursor::new(&share_bytes))
            .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;

        if let (Some(timestamp), Some(shasum)) = (timestamp.as_ref(), shasum.as_ref()) {
            if timestamp != &share.timestamp || shasum != &share.shasum {
                return Err(BackupError::RestoreFailed(anyhow!(
                    "Share mismatch {} vs {} | {:?} vs {:?}",
                    timestamp,
                    share.timestamp,
                    shasum,
                    share.shasum
                )));
            }
        } else {
            timestamp = Some(share.timestamp);
            shasum = Some(share.shasum.clone());
        }

        serializable_shares.push((share, cipher_text));
    }
    let file_shares = serializable_shares
        .into_iter()
        .filter_map(|(a, b)| Share::<Fr>::try_from(a).ok().map(|a| (a, b)))
        .collect::<Vec<_>>();
    let shares = Shares(file_shares.iter().map(|a| a.0.clone()).collect::<Vec<_>>());
    let secret = shares
        .reconstruct_secret()
        .map_err(|e| BackupError::RestoreFailed(anyhow!("{e:?}")))?;
    let (key, mut ivs) = derive_key_material(secret, shares.0.len() as u16, b"email".to_vec())
        .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;
    // let mut file_parts = vec![];
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;

    let combined_encrypted_file =
        combine_file(file_shares.iter().map(|(_, a)| a.clone()).collect())?;

    let Some(iv) = ivs.pop() else {
        return Err(BackupError::RestoreFailed(anyhow!("Not enough IVs")));
    };
    let nonce = GenericArray::from_slice(&iv);
    let result = cipher
        .decrypt(nonce, combined_encrypted_file.as_slice())
        .map_err(|e| BackupError::RestoreFailed(anyhow!(e)))?;

    Ok(result)
}

/// Helper function to split a file into n parts, appending the frost part if needed.
fn split_file(
    file: Vec<u8>,
    shares: u16,
    #[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))] with_frost: Option<
        FrostBackup,
    >,
) -> Result<Vec<Vec<u8>>, BackupError> {
    let mut file_parts: Vec<Vec<u8>> = vec![vec![]; shares as usize];

    for (index, byte) in file.iter().enumerate() {
        let index = index % (shares as usize);
        let Some(array) = file_parts.get_mut(index) else {
            return Err(BackupError::SplitFileFailed(anyhow!(
                "index larger than number of shares"
            )));
        };
        array.push(*byte);
    }
    #[cfg(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp"))]
    if let Some(frost_parts) = with_frost {
        if file_parts.len() != frost_parts.splits.len() {
            return Err(BackupError::SplitFileFailed(anyhow!(
                "Frost parts do not match backup parts"
            )));
        }
        file_parts = file_parts
            .into_iter()
            .zip(frost_parts.splits)
            .map(|(file_part, frost_part)| FileBackup {
                file: file_part,
                frost_part: Some(FrostPart {
                    split: frost_part,
                    passphrase_share: frost_parts.pass_phrase_part.clone(),
                    public_key_package: frost_parts.pub_key_package.clone(),
                }),
            })
            .map(|fb| {
                let mut writer = vec![];
                let _ = ciborium::into_writer(&fb, &mut writer);
                writer
            })
            .collect();
    } else {
        file_parts = file_parts
            .into_iter()
            .map(|file| FileBackup {
                file,
                frost_part: None,
            })
            .map(|fb| {
                let mut writer = vec![];
                let _ = ciborium::into_writer(&fb, &mut writer);
                writer
            })
            .collect();
    }
    #[cfg(not(all(feature = "uniffi", feature = "reqwest", feature = "oid4vp")))]
    {
        file_parts = file_parts
            .into_iter()
            .map(|file| FileBackup {
                file,
                frost_part: None,
            })
            .map(|fb| {
                let mut writer = vec![];
                let _ = ciborium::into_writer(&fb, &mut writer);
                writer
            })
            .collect();
    }
    Ok(file_parts)
}

/// Reverse function of [split_file] recovering the backuped file from backup parts.
fn combine_file(files: Vec<Vec<u8>>) -> Result<Vec<u8>, BackupError> {
    let mut files = files
        .into_iter()
        .filter_map(|f| {
            let Ok(file_backup) = ciborium::from_reader::<FileBackup, _>(Cursor::new(&f)) else {
                return None;
            };
            Some(file_backup.file)
        })
        .collect::<Vec<_>>();
    files.iter_mut().for_each(|a| a.reverse());
    let shares = files.len();
    let file_length: usize = files.iter().map(|a| a.len()).sum();
    let mut file = vec![];
    for i in 0..file_length {
        let i = i % shares;
        let Some(bytes) = files.get_mut(i) else {
            return Err(BackupError::RestoreFailed(anyhow!(
                "index larger than number of shares"
            )));
        };
        let Some(byte) = bytes.pop() else {
            continue;
        };
        file.push(byte);
    }
    Ok(file)
}

/// Derive key material using HKDF<Sha256> to derive an AES secret key and an IV.
fn derive_key_material(
    secret: Fr,
    number_of_shares: u16,
    seed: Vec<u8>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), anyhow::Error> {
    let mut serialized_secret = vec![];
    if secret
        .serialize_uncompressed(&mut serialized_secret)
        .is_err()
    {
        bail!("Could not serialize")
    }
    let derived_secret = Hkdf::<Sha256>::new(Some(seed.as_slice()), &serialized_secret);
    let mut out = [0u8; 32];
    derived_secret
        .expand(&[], &mut out)
        .context("HKDF expand failed")?;
    let key = out.to_vec();
    let mut ivs = vec![];
    for _ in 0..number_of_shares {
        let mut out = [0u8; 12];
        derived_secret
            .expand(&[], &mut out)
            .context("HKDF expand failed")?;
        ivs.push(out.to_vec());
    }
    Ok((key, ivs))
}

/// This section contains some helper structs to have a more convenient of handling the respective parts and allowing
/// easy serialization and deserialization.

#[derive(Serialize, Deserialize)]
struct FileBackup {
    file: Vec<u8>,
    frost_part: Option<FrostPart>,
}
#[derive(Serialize, Deserialize)]
struct FrostPart {
    split: Split,
    passphrase_share: PassphraseBackup,
    public_key_package: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializeableShare {
    id: u16,
    threshold: u16,
    share: Vec<u8>,
    timestamp: u64,
    shasum: Vec<u8>,
}

impl TryFrom<(u16, u16, Fr)> for SerializeableShare {
    type Error = anyhow::Error;

    fn try_from(value: (u16, u16, Fr)) -> Result<Self, Self::Error> {
        let mut output = vec![];
        if value.2.serialize_compressed(&mut output).is_err() {
            bail!("Could not serialize");
        }
        Ok(SerializeableShare {
            id: value.0,
            threshold: value.1,
            share: output,
            timestamp: 0,
            shasum: vec![],
        })
    }
}
impl TryFrom<SerializeableShare> for Share<Fr> {
    type Error = anyhow::Error;

    fn try_from(value: SerializeableShare) -> Result<Self, Self::Error> {
        let Ok(share) = Fr::deserialize_compressed(Cursor::new(value.share)) else {
            bail!("Could not deserialize")
        };
        Ok(Share {
            id: value.id,
            threshold: value.threshold,
            share,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Cursor;

    use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm};
    use ark_secp256r1::Fr;
    use ark_serialize::CanonicalSerialize;
    use hkdf::Hkdf;
    use lipsum::lipsum;
    use rand::{rngs::OsRng, RngCore};
    use secret_sharing_and_dkg::{common::Shares, shamir_ss::deal_random_secret};
    use sha2::Sha256;

    use crate::backup::{combine_file, create_backup, reconstruct, SerializeableShare};

    use super::FileBackup;

    #[test]
    fn test_serialize_frost() {
        let data = vec![1, 3, 4, 5, 6];
        let backup = FileBackup {
            file: data,
            frost_part: None,
        };
        let mut bytes = vec![];
        ciborium::into_writer(&backup, &mut bytes).unwrap();
        let _b: FileBackup = ciborium::from_reader(Cursor::new(&bytes)).unwrap();
    }

    #[test]
    fn test_share_reconstruct_even() {
        let number_of_shares = 2;
        let mut data = vec![u8::default(); 20_000_000];
        rand::thread_rng().fill_bytes(&mut data);
        let backup = create_backup(data.clone(), number_of_shares, None).unwrap();
        assert_eq!(backup.shares.len(), number_of_shares as usize);

        let encrypted_data = combine_file(backup.shares.clone()).unwrap();

        let reconstructed_data = reconstruct(backup.shares).unwrap();
        assert_eq!(reconstructed_data, data);

        assert_ne!(encrypted_data, data);
    }
    #[test]
    fn test_share_reconstruct_uneven() {
        let number_of_shares = 2;
        let mut data = vec![u8::default(); 20_000_001];
        rand::thread_rng().fill_bytes(&mut data);
        let backup = create_backup(data.clone(), number_of_shares, None).unwrap();
        assert_eq!(backup.shares.len(), number_of_shares as usize);

        let encrypted_data = combine_file(backup.shares.clone()).unwrap();

        let reconstructed_data = reconstruct(backup.shares).unwrap();
        assert_eq!(reconstructed_data, data);

        assert_ne!(encrypted_data, data);
    }

    #[test]
    fn test_share_reconstruct_text() {
        let number_of_shares = 2;
        let lorem_ipsum = lipsum(1);
        let data = lorem_ipsum.as_bytes().to_vec();

        let backup = create_backup(data.clone(), number_of_shares, None).unwrap();
        assert_eq!(backup.shares.len(), number_of_shares as usize);

        let encrypted_data = combine_file(backup.shares.clone()).unwrap();

        let reconstructed_data = reconstruct(backup.shares).unwrap();
        assert_eq!(reconstructed_data, data);

        assert_ne!(encrypted_data, data);

        let text = std::str::from_utf8(&reconstructed_data).unwrap();
        assert_eq!(text.to_string(), lorem_ipsum);
    }

    #[test]
    fn test_share_try_reconstruct_different_shares() {
        let number_of_shares = 2;
        let lorem_ipsum_1 = lipsum(20048);
        let data_1 = lorem_ipsum_1.as_bytes().to_vec();

        let backup_1 = create_backup(data_1.clone(), number_of_shares, None).unwrap();
        assert_eq!(backup_1.shares.len(), number_of_shares as usize);

        let number_of_shares = 2;
        let lorem_ipsum_2 = lipsum(21048);
        let data_2 = lorem_ipsum_2.as_bytes().to_vec();

        let backup_2 = create_backup(data_2.clone(), number_of_shares, None).unwrap();
        assert_eq!(backup_2.shares.len(), number_of_shares as usize);

        let wrong_shares = vec![
            backup_1.shares.first().unwrap().to_owned(),
            backup_2.shares.first().unwrap().to_owned(),
        ];
        assert!(reconstruct(wrong_shares).is_err());
        let wrong_shares = vec![
            backup_1.shares.get(1).unwrap().to_owned(),
            backup_2.shares.first().unwrap().to_owned(),
        ];
        assert!(reconstruct(wrong_shares).is_err());
        let wrong_shares = vec![
            backup_1.shares.get(1).unwrap().to_owned(),
            backup_2.shares.get(1).unwrap().to_owned(),
        ];
        assert!(reconstruct(wrong_shares).is_err());
        let wrong_shares = vec![
            backup_1.shares.first().unwrap().to_owned(),
            backup_2.shares.get(1).unwrap().to_owned(),
        ];
        assert!(reconstruct(wrong_shares.clone()).is_err());

        let correct_1 = reconstruct(backup_1.shares).unwrap();
        let correct_2 = reconstruct(backup_2.shares).unwrap();

        assert_eq!(data_1, correct_1);
        assert_eq!(data_2, correct_2);
    }

    #[test]
    fn test_serialize() {
        let (secret, shares, _) = deal_random_secret::<_, Fr>(&mut OsRng, 2, 3).unwrap();
        let mut serialized_secret = vec![];
        let _ = secret.serialize_uncompressed(&mut serialized_secret);
        let derived_secret = Hkdf::<Sha256>::new(Some(b"heidi_backup"), &serialized_secret);
        let mut out = [0u8; 32];
        derived_secret.expand(&[], &mut out).unwrap();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&out).unwrap();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = cipher.encrypt(&nonce, "1234".as_bytes()).unwrap();
        let share1_serialize = shares.0.first().unwrap().to_owned();
        let share1_serialize: SerializeableShare = (
            share1_serialize.id,
            share1_serialize.threshold,
            share1_serialize.share,
        )
            .try_into()
            .unwrap();
        let json_share: String = serde_json::to_string(&share1_serialize).unwrap();
        let share1_serialize: SerializeableShare = serde_json::from_str(&json_share).unwrap();
        let share1 = share1_serialize.try_into().unwrap();
        let share2 = shares.0.get(2).unwrap().to_owned();

        let shares2 = Shares(vec![share1, share2]);
        let secret_reconstructed: Fr = shares2.reconstruct_secret().unwrap();
        let mut serialized_reconstructed_secret = vec![];
        secret_reconstructed
            .serialize_compressed(&mut serialized_reconstructed_secret)
            .unwrap();
        let derived_reconstructed_secret =
            Hkdf::<Sha256>::new(Some(b"heidi_backup"), &serialized_reconstructed_secret);
        let mut out_reconstructed = [0u8; 32];
        derived_reconstructed_secret
            .expand(&[], &mut out_reconstructed)
            .unwrap();
        let decipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&out_reconstructed).unwrap();
        let result = decipher.decrypt(&nonce, cipher.as_slice()).unwrap();
        assert_eq!("1234".as_bytes(), result.as_slice());
    }
}
