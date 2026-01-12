use std::{fmt::Display, pin::Pin, sync::Arc};

use heidi_util_rust::value::Value;
use json_ld::{ChainLoader, ReqwestLoader};

use crate::{
    claims_pointer::Selector,
    json_ld::{JsonLdDocument, loader::StaticLoader},
};

#[derive(Debug, Clone, uniffi::Error)]
pub enum ParseError {
    Stuff,
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

fn test(credential: String) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async move {
        let loader = ChainLoader::new(
            StaticLoader::new().with_document("https://www.w3.org/ns/credentials/v2", CONTEXT_W3C),
            ReqwestLoader::new(),
        );

        // credential is now safely owned inside this async block
        let flattened = JsonLdDocument::new(credential.as_str(), loader)
            .flattened()
            .await;

        println!("FLATTENED: {}", flattened);
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn parse_ldp_vc(credential: String) -> Result<LdpVC, ParseError> {
    // Just await the function directly
    test(credential).await;

    todo!()
}
