use std::sync::{Arc, LazyLock, Mutex};

use heidi_util_rust::log_error;

use crate::models::{parser::builtin::AllPurposeParser, Credential};

/// List of currently registered matchers
pub(crate) static REGISTERED_PARSERS: LazyLock<Mutex<Vec<Arc<dyn CredentialParser>>>> =
    LazyLock::new(|| {
        // Register default matchers
        let all_purpose = Arc::new(AllPurposeParser);
        Mutex::new(vec![all_purpose])
    });

#[uniffi::export(with_foreign)]
/// Trait to implement a credential parser
pub trait CredentialParser: Send + Sync {
    /// A unique ID identifying this parser in this runtime. This ID is used
    /// to check, if the parser is already registered.
    fn id(&self) -> String;
    fn from_str(&self, credential: String) -> Option<Credential>;
}

impl PartialEq for dyn CredentialParser {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

#[uniffi::export]
/// Registers this matcher with the DCQL Runtime.
pub fn register_parser(matcher: Arc<dyn CredentialParser>) {
    let Ok(mut matcher_lock) = REGISTERED_PARSERS.lock() else {
        log_error!("DCQL", "Failed to register parser");
        return;
    };
    if matcher_lock.contains(&matcher) {
        return;
    }
    matcher_lock.push(matcher)
}

mod builtin {
    use std::sync::Arc;

    #[cfg(feature = "bbs")]
    use heidi_credentials_rust::bbs::decode_bbs;
    use heidi_credentials_rust::{
        bbs::BbsRust,
        claims_pointer::Selector,
        mdoc::{decode_mdoc, MdocRust},
        sdjwt::{decode_sdjwt, SdJwtRust},
        w3c::{parse_w3c_sd_jwt, W3CSdJwt, W3CVerifiableCredential},
    };
    use heidi_util_rust::value::Value;

    use crate::{
        models::{parser::CredentialParser, Credential, CredentialLike, Meta},
        MetaMismatch, BBS_FORMATS, MDOC_FORMATS, OPEN_BADGE_FORMATS, SDJWT_FORMATS, W3C_FORMATS,
    };

    impl CredentialLike for SdJwtRust {
        fn get_body(&self) -> Value {
            self.claims.clone()
        }

        fn serialize(&self) -> String {
            serde_json::to_string(&self).unwrap()
        }

        fn format_specifiers(&self) -> Vec<String> {
            SDJWT_FORMATS.iter().map(|a| a.to_string()).collect()
        }

        fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch> {
            Credential::matches_meta_sdjwt(&self, meta.as_ref())
                .err()
                .map(|a| MetaMismatch::SdJwtMetaMismatch(a))
        }

        fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            SdJwtRust::get(&self, selector)
        }
    }

    impl CredentialLike for W3CSdJwt {
        fn get_body(&self) -> Value {
            self.json.clone()
        }

        fn serialize(&self) -> String {
            serde_json::to_string(&self).unwrap()
        }

        fn format_specifiers(&self) -> Vec<String> {
            W3C_FORMATS.iter().map(|a| a.to_string()).collect()
        }

        fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch> {
            Credential::matches_meta_w3c(&self, meta.as_ref())
                .err()
                .map(|a| MetaMismatch::W3CMetaMismatch(a))
        }

        fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            W3CSdJwt::get(&self, selector)
        }
    }
    impl CredentialLike for MdocRust {
        fn get_body(&self) -> Value {
            self.namespace_map.clone()
        }

        fn serialize(&self) -> String {
            serde_json::to_string(&self).unwrap()
        }

        fn format_specifiers(&self) -> Vec<String> {
            MDOC_FORMATS.iter().map(|a| a.to_string()).collect()
        }

        fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch> {
            Credential::matches_meta_mdoc(&self, meta.as_ref())
                .err()
                .map(|a| MetaMismatch::MdocMetaMismatch(a))
        }

        fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            MdocRust::get(&self, selector)
        }
    }
    impl CredentialLike for BbsRust {
        fn get_body(&self) -> Value {
            self.body()
        }

        fn serialize(&self) -> String {
            serde_json::to_string(&self).unwrap()
        }

        fn format_specifiers(&self) -> Vec<String> {
            BBS_FORMATS.iter().map(|a| a.to_string()).collect()
        }

        fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch> {
            Credential::matches_meta_bbs(&self, meta.as_ref())
                .err()
                .map(|a| MetaMismatch::BbsMetaMismatch(a))
        }

        fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            BbsRust::get(&self, selector)
        }
    }
    impl CredentialLike for W3CVerifiableCredential {
        fn get_body(&self) -> Value {
            self.clone().into_value()
        }

        fn serialize(&self) -> String {
            serde_json::to_string(&self).unwrap()
        }

        fn format_specifiers(&self) -> Vec<String> {
            OPEN_BADGE_FORMATS.iter().map(|a| a.to_string()).collect()
        }

        fn matches_meta(&self, meta: Option<Meta>) -> Option<MetaMismatch> {
            Credential::matches_meta_open_badges(&self, meta.as_ref())
                .err()
                .map(|a| MetaMismatch::LdpMetaMismatch(a))
        }

        fn get(self: Arc<Self>, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            W3CVerifiableCredential::get(&self, selector)
        }
    }

    pub struct AllPurposeParser;
    impl CredentialParser for AllPurposeParser {
        #[doc = " A unique ID identifying this parser in this runtime. This ID is used"]
        #[doc = " to check, if the parser is already registered."]
        fn id(&self) -> String {
            "all-purpose".to_string()
        }

        fn from_str(&self, credential: String) -> Option<Credential> {
            let s = credential.as_str();
            let sdjwt = decode_sdjwt(s);
            let w3c = parse_w3c_sd_jwt(s);

            match (sdjwt, w3c) {
                (Ok(sdjwt), Ok(w3c)) => {
                    // NOTE: This is a hack, there should be a type hint somewhere

                    // To distinguish between W3C and SD-JWT credentials,
                    // we check if the W3C credential has a context.
                    return if w3c.json.get("@context").is_some() {
                        Some(Credential::W3CCredential(Arc::new(w3c)))
                    } else {
                        Some(Credential::SdJwtCredential(Arc::new(sdjwt)))
                    };
                }
                (Ok(sdjwt), _) => return Some(Credential::SdJwtCredential(Arc::new(sdjwt))),
                (_, Ok(w3c)) => return Some(Credential::W3CCredential(Arc::new(w3c))),

                // Fallthrough to other formats
                _ => (),
            };

            if let Ok(vc) = serde_json::from_str::<W3CVerifiableCredential>(s) {
                if vc.types.contains(&"OpenBadgeCredential".to_string()) {
                    return Some(Credential::OpenBadge303Credential(Arc::new(vc)));
                }
            }

            if let Ok(mdoc) = decode_mdoc(s) {
                return Some(Credential::MdocCredential(Arc::new(mdoc)));
            }
            #[cfg(feature = "bbs")]
            if let Ok(bbs) = decode_bbs(s) {
                return Some(Credential::BbsCredential(Arc::new(bbs)));
            }
            None
        }
    }
}
