use std::collections::HashMap;

use openidconnect_federation::models::trust_chain::{TrustAnchor, TrustStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct FederationResult {
    is_valid: bool,
    metadata: HashMap<String, crate::value::Value>,
}

#[derive(uniffi::Error, Debug)]
pub enum MetadataFetchError {
    FetchFailed(String),
    BuildTrustError(String),
}

impl std::fmt::Display for MetadataFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataFetchError::FetchFailed(inner) => {
                write!(f, "OpenID Federation failed to fetch metadata: {inner}")
            }
            MetadataFetchError::BuildTrustError(inner) => {
                write!(f, "OpenID Federation failed to build trust: {inner}")
            }
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
/// Use openid-federation to fetch a certain entity types
pub async fn fetch_metadata_from_issuer_url(
    url: &str,
    trust_store: Option<Vec<String>>,
) -> Result<FederationResult, MetadataFetchError> {
    let mut res_oidf =
        match openidconnect_federation::DefaultFederationRelation::new_from_url_async(url).await {
            Ok(res_oidf) => res_oidf,
            Err(e) => {
                return Err(MetadataFetchError::FetchFailed(format!(
                    "Federation failed with: {e}"
                )))
            }
        };
    res_oidf.build_trust_async().await.map_err(|e| {
        MetadataFetchError::BuildTrustError(format!("Failed to construct trust: {e}"))
    })?;
    let is_valid = res_oidf.verify().is_ok();
    let trust_store = trust_store.map(|a| {
        TrustStore(
            a.into_iter()
                .map(|sub| TrustAnchor::Subject(sub))
                .collect::<Vec<_>>(),
        )
    });
    let metadata = res_oidf.resolve_metadata(trust_store.as_ref());
    let mut new_metadata = HashMap::new();
    for (k, data) in metadata {
        let intermediate: serde_json::Value = data.into();
        new_metadata.insert(k, intermediate.into());
    }
    Ok(FederationResult {
        is_valid,
        metadata: new_metadata,
    })
}
