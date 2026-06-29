use std::{
    fmt::{Display, Formatter},
    io::Cursor,
    sync::Arc,
};

use heidi_crypto_rust::crypto::SignatureCreator;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ldp::sign_unsecured_document,
    w3c::{
        JsonLDParseError, W3CVerifiableCredential, parse_and_canonicalize_w3c_json_ld,
        parse_canonicalized_w3c_json_ld,
    },
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
    pub original_data: W3CVerifiableCredential,

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
        let original_data =
            parse_canonicalized_w3c_json_ld(&credential).map_err(|e| ParseError::JsonLd(e))?;

        let data = parse_and_canonicalize_w3c_json_ld(credential, additional_context)
            .await
            .map_err(|e| ParseError::JsonLd(e))?;

        Ok(Self {
            data,
            original,
            original_data,
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
        let original_data = data.clone();

        Ok(Self {
            data,
            original: credential,
            original_data,
            image_bytes,
        })
    }

    pub async fn create(
        mut vc: W3CVerifiableCredential,
        signer: Arc<dyn SignatureCreator>,
        created: String,
        verification_method: String,
    ) -> Self {
        let unsecured_document = serde_json::to_value(&vc).unwrap();
        let proof_options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": created,
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
        });

        let proof = sign_unsecured_document(unsecured_document, proof_options, signer)
            .await
            .unwrap();
        vc.embedded_proof = Some(proof.into());

        Self {
            data: vc.clone(),
            original: serde_json::to_string(&vc).unwrap(),
            original_data: vc,
            image_bytes: vec![],
        }
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use heidi_crypto_rust::crypto::signing::SoftwareKeyPair;
    use heidi_util_rust::value::Value;

    use crate::{
        ldp::verify_secured_document_string, open_badges::OpenBadges303Credential,
        w3c::W3CVerifiableCredential,
    };

    #[tokio::test]
    async fn test_create_open_badge_vc() {
        let data = W3CVerifiableCredential {
            context: vec![
                Value::String("https://www.w3.org/ns/credentials/v2".to_string()),
                Value::String("https://heidi-entity-ws-dev.ubique.ch/public/v2/schema/master-diplom-mirfc/1.1.0/context".to_string()),
            ],
            id: None,
            types: vec![],
            name: None,
            description: None,
            issuer: None,
            credential_subject: Some(Value::Object(HashMap::from([
                ("type".to_string(), Value::String("CredentialSubject".to_string())),
                ("given_name".to_string(), Value::String("John".to_string())),
                ("family_name".to_string(), Value::String("Doe".to_string())),
                ("birth_date".to_string(), Value::String("1990-01-01".to_string())),
                ("course".to_string(), Value::String("Computer Science".to_string())),
            ]))),
            valid_from: None,
            valid_until: None,
            status: None,
            credential_schema: None,
            refresh_service: None,
            terms_of_use: None,
            evidence: None,
            embedded_proof: None,
        };

        let signer = Arc::new(SoftwareKeyPair::new());
        // TODO: Figure out how to serialize it.
        let mut pub_key_bytes = vec![0x80, 0x24];
        pub_key_bytes.extend_from_slice(signer.public_key_compressed().as_slice());
        let pub_key_multibase = multibase::encode(multibase::Base::Base58Btc, pub_key_bytes);
        let created = "2024-01-01T00:00:00Z".to_string();
        let verification_method = format!("did:key:{pub_key_multibase}#{pub_key_multibase}");

        let vc = OpenBadges303Credential::create(data, signer, created, verification_method).await;

        assert!(vc.data.embedded_proof.is_some());

        assert!(verify_secured_document_string(vc.original).await)
    }
}
