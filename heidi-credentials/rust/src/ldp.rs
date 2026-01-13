use std::{fmt::Display, pin::Pin, sync::Arc};

use heidi_util_rust::value::Value;
use json_ld::{ChainLoader, ReqwestLoader};
use static_iref::iri;
use tokio::task::JoinError;

use crate::{
    claims_pointer::Selector,
    json_ld::{JsonLdDocument, loader::StaticLoader},
};

#[derive(Debug, Clone, uniffi::Error)]
pub enum ParseError {
    JoinError(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct LdpVC {
    /// The credential document type
    pub doctype: Vec<String>,

    /// The credential as a JSON-LD object
    pub data: Value,
}

impl LdpVC {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.data.clone()).ok()
    }
}

const CONTEXT_W3C: &'static str = include_str!("../jsonld/www.w3.org/ns/credentials/v2");

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn parse_ldp_vc(credential: String) -> Result<LdpVC, ParseError> {
    let vc = tokio::task::spawn_blocking(move || {
        let handle = tokio::runtime::Handle::current();
        let local = tokio::task::LocalSet::new();

        // Use the handle to block, and let the local set run the future
        handle.block_on(local.run_until(async move {
            let loader = ChainLoader::new(
                StaticLoader::new()
                    .with_document("https://www.w3.org/ns/credentials/v2", CONTEXT_W3C),
                ReqwestLoader::new(),
            );
            let context = vec![
                iri!("https://www.w3.org/ns/credentials/v2").to_owned(),
                iri!("https://www.w3.org/ns/credentials/examples/v2").to_owned(),
            ];

            let flattened = JsonLdDocument::new(credential.as_str(), &loader)
                .flattened()
                .await;
            let flattened = JsonLdDocument::new(&flattened.to_string(), &loader);

            let frame = serde_json::json!({
                "@type": "https://www.w3.org/2018/credentials#VerifiableCredential"
            });
            let framed = flattened.framed(&frame).await;

            let document = JsonLdDocument::new(&framed.to_string(), &loader)
                .compacted(context)
                .await;

            document
        }))
    })
    .await
    .map_err(|e| ParseError::JoinError(e.to_string()))?;

    todo!()
}
