use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use heidi_util_rust::value::Value;
use reqwest::Url;
use reqwest_middleware::ClientWithMiddleware;

use crate::{
    crypto::encryption::ContentDecryptor,
    issuance::models::{
        CredentialErrorResponse, CredentialIssuerMetadata, CredentialProofs, CredentialRequest,
        CredentialResponseType, ErrorAsCredentialErrorResponse, ErrorForStatusDetailed,
        KeyProofType, KeyProofsType, ProofType, TokenRequest, TokenResponse,
    },
    signing::SecureSubject,
    ApiError,
};

pub async fn get_access_token(
    client: Arc<ClientWithMiddleware>,
    token_endpoint: Url,
    token_request: TokenRequest,
) -> anyhow::Result<TokenResponse> {
    client
        .post(token_endpoint)
        .form(&token_request)
        .send()
        .await?
        .error_for_status_detailed()
        .await?
        .json()
        .await
        .map_err(|e| e.into())
}

pub async fn get_proof_body(
    subjects: Vec<Arc<SecureSubject>>,
    credential_issuer_metadata: CredentialIssuerMetadata,
    c_nonce: Option<String>,
    client_id: String,
    is_for_pre_authorized: bool,
) -> Result<Vec<String>, ApiError> {
    let nonce = c_nonce
        .as_ref()
        .ok_or(anyhow::anyhow!("No c_nonce found."))?; // XXX
    let timestamp = SystemTime::now();
    let timestamp = timestamp
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let mut proofs = vec![];
    for subject in &subjects {
        let mut builder = KeyProofType::builder()
            .proof_type(ProofType::Jwt)
            .signer(subject.clone());
        // `iss` MUST not be set when in pre-authorized-flow https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1-2.2.2.1
        if !is_for_pre_authorized {
            builder = builder.iss(client_id.clone());
        }
        let Ok(kpt) = builder
            .aud(credential_issuer_metadata.credential_issuer.clone())
            .iat(timestamp.as_secs() as i64)
            .exp((timestamp + std::time::Duration::from_secs(360)).as_secs() as i64)
            .nonce(nonce.clone())
            .build_no_sign()
            .await
        else {
            continue;
        };
        if let KeyProofType::Jwt { jwt } = kpt {
            proofs.push(jwt);
        }
    }
    Ok(proofs)
}

pub async fn get_credential_with_proofs(
    client: Arc<ClientWithMiddleware>,
    credential_issuer_metadata: CredentialIssuerMetadata,
    access_token: String,
    credential_configuration_id: String,
    credential_format: Value,
    content_decryptor: Option<Box<dyn ContentDecryptor>>,
    proofs: CredentialProofs,
) -> Result<crate::issuance::models::CredentialResponse, CredentialErrorResponse> {
    let credential_response_encryption = if let Some(content_decryptor) = content_decryptor.as_ref()
    {
        Some(content_decryptor.encryption_specification())
    } else {
        None
    };

    // Backwards compatibility hack to only send appropriate fields in request:
    // No surefire way to find out which version, but draft 15 compatible issuer will very
    // likely have a nonce endpoint.
    let is_openid4vci_draft15_issuer = credential_issuer_metadata.nonce_endpoint.is_some();
    let credential_request = if is_openid4vci_draft15_issuer {
        CredentialRequest {
            credential_configuration_id: Some(credential_configuration_id),
            credential_format: None,
            proof: proofs,
            credential_response_encryption: credential_response_encryption.clone(),
            //TODO: Implement credential_identifier
            credential_identifier: None,
        }
    } else {
        CredentialRequest {
            credential_configuration_id: None,
            credential_format: Some(credential_format),
            proof: proofs,
            credential_response_encryption: credential_response_encryption.clone(),
            //TODO: Implement credential_identifier
            credential_identifier: None,
        }
    };

    let response = client
        .post(credential_issuer_metadata.credential_endpoint.clone())
        .bearer_auth(access_token.clone())
        .json(&credential_request)
        .send()
        .await
        .map_err(|e| CredentialErrorResponse {
            error: "unknown_error_during_send".to_string(),
            error_description: Some(format!("{e}")),
            c_nonce: None,
            c_nonce_expires_in: None,
        })?
        .as_credential_error_response()
        .await?;
    let text = response.text().await.map_err(|e| CredentialErrorResponse {
        error: "unknown_error_during_text".to_string(),
        error_description: Some(format!("{e}")),
        c_nonce: None,
        c_nonce_expires_in: None,
    })?;
    println!("{text}");
    serde_json::from_str::<crate::issuance::models::CredentialResponse>(&text).map_err(|e| {
        CredentialErrorResponse {
            error: "unknown_error_parsing".to_string(),
            error_description: Some(format!("{e}")),
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    })
}

pub async fn get_credential(
    client: Arc<ClientWithMiddleware>,
    subjects: Vec<Arc<SecureSubject>>,
    credential_issuer_metadata: CredentialIssuerMetadata,
    access_token: String,
    c_nonce: Option<String>,
    credential_configuration_id: String,
    credential_format: Value,
    content_decryptor: Option<Box<dyn ContentDecryptor>>,
    client_id: String,
    is_for_pre_authorized: bool,
) -> Result<crate::issuance::models::CredentialResponse, CredentialErrorResponse> {
    let timestamp = SystemTime::now();
    let timestamp = timestamp
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let mut proofs = vec![];
    for subject in &subjects {
        let mut builder = KeyProofType::builder()
            .proof_type(ProofType::Jwt)
            .signer(subject.clone());
        // `iss` MUST not be set when in pre-authorized-flow https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1-2.2.2.1
        if !is_for_pre_authorized {
            builder = builder.iss(client_id.clone());
        }
        let mut kpb = builder
            .aud(credential_issuer_metadata.credential_issuer.clone())
            .iat(timestamp.as_secs() as i64)
            .exp((timestamp + std::time::Duration::from_secs(360)).as_secs() as i64);
        if let Some(nonce) = &c_nonce {
            kpb = kpb.nonce(nonce);
        }
        let Ok(kpt) = kpb.build().await else {
            continue;
        };
        if let KeyProofType::Jwt { jwt } = kpt {
            proofs.push(jwt);
        }
    }
    get_credential_with_proofs(
        client,
        credential_issuer_metadata,
        access_token,
        credential_configuration_id,
        credential_format,
        content_decryptor,
        CredentialProofs::Proofs(KeyProofsType::Jwt(proofs)),
    )
    .await
}

pub async fn try_get_deferred_credential(
    client: Arc<ClientWithMiddleware>,
    credential_issuer_metadata: CredentialIssuerMetadata,
    token_response: TokenResponse,
    credential_response: crate::issuance::models::CredentialResponse,
) -> anyhow::Result<crate::issuance::models::CredentialResponse> {
    let CredentialResponseType::Deferred { transaction_id } = credential_response.credential else {
        bail!("not a deferred credential");
    };
    let Some(deferred_endpoint) = credential_issuer_metadata
        .deferred_credential_endpoint
        .as_ref()
    else {
        bail!("deferred credentials not  supported by remote");
    };
    let mut map = serde_json::Map::new();
    map.insert(
        "transaction_id".to_string(),
        serde_json::Value::String(transaction_id),
    );
    let transaction_id: serde_json::Value = serde_json::Value::Object(map);
    client
        .post(deferred_endpoint.to_owned())
        .bearer_auth(token_response.access_token.clone())
        .json(&transaction_id)
        .send()
        .await?
        .error_for_status_detailed()
        .await?
        .json::<crate::issuance::models::CredentialResponse>()
        .await
        .map_err(|e| e.into())
}
