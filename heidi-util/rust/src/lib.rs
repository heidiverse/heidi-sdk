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

#[uniffi::export]
pub fn deflate(input: Vec<u8>) -> Vec<u8> {
    let mut zliber = ZlibDecoder::new(&input[..]);
    let mut output = vec![];
    let _ = zliber.read_to_end(&mut output).unwrap();
    output
}
#[uniffi::export]
pub fn deflate_string(input: String) -> Vec<u8> {
    let Ok(input) = BASE64_URL_SAFE_NO_PAD.decode(&input) else {
        return vec![];
    };
    let mut zliber = ZlibDecoder::new(&input[..]);
    let mut output = vec![];
    let _ = zliber.read_to_end(&mut output).unwrap();
    output
}

#[cfg(test)]
mod test_deflate {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

    use crate::deflate;

    #[test]
    fn deflater() {
        let lst = "eNrtwSEBAAAAAiAn-H-tI6xAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAywAP4AAR";
        let lst = BASE64_URL_SAFE_NO_PAD.decode(lst).unwrap();
        let output = deflate(lst);
        assert!(!output.is_empty());
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

uniffi::setup_scaffolding!();
