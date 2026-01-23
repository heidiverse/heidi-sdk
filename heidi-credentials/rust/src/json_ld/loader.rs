use std::{borrow::Cow, collections::HashMap};

use json_ld::{LoadError, Loader, RemoteDocument};
use json_syntax::Parse;

#[derive(Debug)]
pub enum Error {
    NotFound,

    Parse(json_syntax::parse::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotFound => write!(f, "Document not found"),
            Error::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Default, Debug, Clone)]
pub struct StaticLoader {
    documents: HashMap<String, Cow<'static, str>>,
}

impl StaticLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_document<S: Into<Cow<'static, str>>>(&mut self, url: &str, content: S) {
        self.documents.insert(url.to_string(), content.into());
    }

    pub fn with_document<S: Into<Cow<'static, str>>>(mut self, url: &str, content: S) -> Self {
        self.add_document(url, content);
        self
    }
}

impl Loader for StaticLoader {
    async fn load(&self, url: &iref::Iri) -> Result<RemoteDocument<iref::IriBuf>, LoadError> {
        if let Some(contents) = self.documents.get(url.as_str()) {
            let (doc, _) = json_syntax::Value::parse_str(&contents)
                .map_err(|e| LoadError::new(url.to_owned(), Error::Parse(e)))?;
            Ok(RemoteDocument::new(
                Some(url.to_owned()),
                Some("application/ld+json".parse().unwrap()),
                doc,
            ))
        } else {
            Err(LoadError::new(url.to_owned(), Error::NotFound))
        }
    }
}

pub struct FallbackLoader<L1: Loader, L2: Loader> {
    primary: L1,
    fallback: L2,
}

impl<L1: Loader, L2: Loader> FallbackLoader<L1, L2> {
    pub fn new(primary: L1, fallback: L2) -> Self {
        Self { primary, fallback }
    }
}

impl<L1: Loader, L2: Loader> Loader for FallbackLoader<L1, L2> {
    async fn load(&self, url: &iref::Iri) -> Result<RemoteDocument<iref::IriBuf>, LoadError> {
        match self.primary.load(url).await {
            Ok(doc) => Ok(doc),
            Err(_) => self.fallback.load(url).await,
        }
    }
}
