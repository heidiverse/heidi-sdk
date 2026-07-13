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

use crate::value::Value;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ciborium::Value as CborValue;
use flate2::read::ZlibDecoder;
use std::{
    fmt::{Display, Formatter},
    io::Read,
};
pub mod log;
pub mod metadata;
pub mod value;

#[derive(Debug, Clone, uniffi::Error)]
pub enum CborParseError {
    InvalidEncoding,
    NoCbor,
    NoIssuerAuth,
    NoNamespaces,
    NamespaceNotMap,
}
impl Display for CborParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(uniffi::Error, Debug)]
pub enum DeflateError {
    BufferOverflow,
    Other,
}
impl Display for DeflateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

const MAX_SIZE: u64 = 32 * 1024 * 1024;

#[uniffi::export]
pub fn deflate(input: Vec<u8>) -> Vec<u8> {
    deflate_upto_max_size(input, MAX_SIZE).unwrap_or_default()
}
#[uniffi::export]
pub fn deflate_upto_max_size(input: Vec<u8>, max_size: u64) -> Result<Vec<u8>, DeflateError> {
    let mut zliber = ZlibDecoder::new(&input[..]);
    let mut output = vec![];
    let mut buf = vec![0; 32 * 1024];
    loop {
        match zliber.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                output.extend_from_slice(&buf[..n]);
                if output.len() > max_size as usize {
                    return Err(DeflateError::BufferOverflow);
                }
            }
            Err(_) => return Err(DeflateError::Other),
        }
    }

    Ok(output)
}
#[uniffi::export]
pub fn deflate_string(input: String) -> Vec<u8> {
    let Ok(input) = BASE64_URL_SAFE_NO_PAD.decode(&input) else {
        return vec![];
    };
    deflate(input)
}

#[cfg(test)]
mod test_deflate {
    use std::io::{Read, Write};

    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use flate2::{read::GzDecoder, write::ZlibEncoder, Compression};

    use crate::{deflate, deflate_upto_max_size, DeflateError, MAX_SIZE};

    #[test]
    fn deflater() {
        let lst = "eNrtwSEBAAAAAiAn-H-tI6xAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAywAP4AAR";
        let lst = BASE64_URL_SAFE_NO_PAD.decode(lst).unwrap();
        let output = deflate(lst);
        assert!(!output.is_empty());
    }
    #[test]
    fn test_zip_bomb() {
        let zip_bomb = include_bytes!("../bomb.gz");
        let mut gzdecoder = GzDecoder::new(&zip_bomb[..]);
        let mut gz_bytes = vec![];
        gzdecoder.read_to_end(&mut gz_bytes).unwrap();
        let mut compressed = ZlibEncoder::new(vec![], Compression::best());
        compressed.write_all(&gz_bytes[..]).unwrap();
        let zlib_stream = compressed.finish().unwrap();
        let output = deflate(zlib_stream.to_vec());
        println!("{}", zlib_stream.len());
        println!("{}", output.len());
        assert!(output.len() <= 32 * 1024);
        let output = deflate_upto_max_size(zlib_stream.to_vec(), MAX_SIZE)
            .err()
            .unwrap();
        assert!(matches!(output, DeflateError::BufferOverflow));
    }
}

#[uniffi::export]
pub fn encode_cbor(cbor: Value) -> Result<Vec<u8>, CborParseError> {
    let cbor_val: CborValue = cbor.into();
    let mut result = vec![];
    ciborium::into_writer(&cbor_val, &mut result).map_err(|_| CborParseError::InvalidEncoding)?;
    Ok(result)
}
#[uniffi::export]
pub fn decode_cbor(cbor: Vec<u8>) -> Result<Value, CborParseError> {
    ciborium::from_reader::<CborValue, _>(cbor.as_slice())
        .map(Value::from)
        .map_err(|_| CborParseError::NoCbor)
}

#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __deregister_frame() {}

#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __register_frame() {}

uniffi::setup_scaffolding!();
