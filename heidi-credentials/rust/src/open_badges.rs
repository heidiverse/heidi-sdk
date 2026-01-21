use std::{
    fmt::{Display, Formatter},
    io::Cursor,
};

use serde::{Deserialize, Serialize};

use crate::w3c::{
    JsonLDParseError, W3CVerifiableCredential, parse_and_canonicalize_w3c_json_ld,
    parse_canonicalized_w3c_json_ld,
};

#[derive(Debug, Clone, uniffi::Error)]
pub enum ParseError {
    JsonLd(JsonLDParseError),
    NoInfoChunks,
    CorruptedChunks,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct OpenBadges303Credential {
    pub data: W3CVerifiableCredential,

    pub original: String,

    pub image_bytes: Vec<u8>,
}

impl OpenBadges303Credential {
    pub async fn parse(
        image_bytes: Vec<u8>,
        additional_context: Vec<String>,
    ) -> Result<Self, ParseError> {
        let p = png::Decoder::new(Cursor::new(image_bytes.clone()));
        let info = p.read_info().map_err(|_| ParseError::NoInfoChunks)?;

        let mut credential = String::new();
        for chunk in &info.info().utf8_text {
            credential.push_str(&chunk.get_text().map_err(|_| ParseError::CorruptedChunks)?);
        }
        let original = credential.clone();

        let data = parse_and_canonicalize_w3c_json_ld(credential, additional_context)
            .await
            .map_err(|e| ParseError::JsonLd(e))?;

        Ok(Self {
            data,
            original,
            image_bytes,
        })
    }

    pub fn parse_canonicalized(image_bytes: Vec<u8>) -> Result<Self, ParseError> {
        let p = png::Decoder::new(Cursor::new(image_bytes.clone()));
        let info = p.read_info().map_err(|_| ParseError::NoInfoChunks)?;

        let mut credential = String::new();
        for chunk in &info.info().utf8_text {
            credential.push_str(&chunk.get_text().map_err(|_| ParseError::CorruptedChunks)?);
        }

        let data =
            parse_canonicalized_w3c_json_ld(&credential).map_err(|e| ParseError::JsonLd(e))?;

        Ok(Self {
            data,
            original: credential,
            image_bytes,
        })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn parse_open_badges_303_credential(
    image_bytes: Vec<u8>,
    additional_context: Vec<String>,
) -> Result<OpenBadges303Credential, ParseError> {
    OpenBadges303Credential::parse(image_bytes, additional_context).await
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_open_badges_303_credential_canonicalized(
    image_bytes: Vec<u8>,
) -> Result<OpenBadges303Credential, ParseError> {
    OpenBadges303Credential::parse_canonicalized(image_bytes)
}
