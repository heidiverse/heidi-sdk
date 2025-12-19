use oidcf::models::transformer;
use oidcf::models::{EntityConfig, EntityStatement};
use openidconnect_federation as oidcf;
use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FederationError {
    JwtParsingFailed(anyhow::Error),
    FetchingFailed(anyhow::Error),
    ValidationFailed(anyhow::Error),
}

impl Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::JwtParsingFailed(e) => {
                f.write_str(&format!("FederationError::JwtParsingFailed: {e}"))
            }
            FederationError::FetchingFailed(e) => {
                f.write_str(&format!("FederationError::FetchingFailed: {e}"))
            }
            FederationError::ValidationFailed(e) => {
                f.write_str(&format!("FederationError::ValidationFailed: {e}"))
            }
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OidcfTrustChainInfo {
    trust_anchor_keys: Vec<String>,      // JWKs
    subordinate_statements: Vec<String>, // JWTs
    leaf: OidcfLeafInfo,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OidcfLeafInfo {
    domain: String,
    // extracted metadata
    display_name: String,
    logo_uri: Option<String>,
    credential_configurations_supported: Option<Vec<String>>,
}

#[uniffi::export]
pub fn oidcf_trust_chain_from_url(url: &str) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_fetch_error = |e: oidcf::models::errors::FederationError| {
        FederationError::FetchingFailed(anyhow::anyhow!(e))
    };

    let mut trust_chain =
        oidcf::DefaultFederationRelation::new_from_url(url).map_err(wrap_fetch_error)?;

    validate_oidf_trust_chain(&mut trust_chain)?;
    to_oidf_trust_chain_info(trust_chain)
}

#[uniffi::export]
pub fn oidcf_trust_chain_from_presentation_request(
    presentation_request_jwt: String,
) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_parse_error = |e: heidi_jwt::models::errors::JwtError| {
        FederationError::JwtParsingFailed(anyhow::anyhow!(e))
    };
    let wrap_fetch_error = |e: oidcf::models::errors::FederationError| {
        FederationError::FetchingFailed(anyhow::anyhow!(e))
    };
    let wrap_validation_error = |e: heidi_jwt::models::errors::JwtError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    let jwt = presentation_request_jwt
        .parse::<heidi_jwt::jwt::Jwt<serde_json::Value>>()
        .map_err(wrap_parse_error)?;

    let oidf_trust_chain = jwt
        .payload_unverified()
        .insecure()
        .get("trust_chain")
        .and_then(as_vec_string);
    let iss = jwt
        .payload_unverified()
        .insecure()
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut trust_chain = if let Some(oidf_trust_chain) = oidf_trust_chain {
        dbg!(&oidf_trust_chain);
        oidcf::DefaultFederationRelation::from_trust_cache(&oidf_trust_chain).or(Err(
            FederationError::ValidationFailed(anyhow::anyhow!("invalid trust_chain")),
        ))?
    } else if let Some(iss) = iss {
        oidcf::DefaultFederationRelation::new_from_url(&iss).map_err(wrap_fetch_error)?
    } else {
        return Err(FederationError::FetchingFailed(anyhow::anyhow!(
            "no trust_chain nor iss in presentation request"
        )));
    };

    validate_oidf_trust_chain(&mut trust_chain)?;

    let leaf = trust_chain
        .trust_entities
        .values()
        .flat_map(|e| e.entity_config.as_ref())
        .find(|e| matches!(e, EntityConfig::Leaf(_)))
        .ok_or(FederationError::ValidationFailed(anyhow::anyhow!(
            "invalid trust chain, no leaf found"
        )))?;
    jwt.verify_signature(&leaf.jwks())
        .map_err(wrap_validation_error)?;

    to_oidf_trust_chain_info(trust_chain)
}

fn validate_oidf_trust_chain(
    trust_chain: &mut oidcf::DefaultFederationRelation,
) -> Result<(), FederationError> {
    let wrap_validation_error = |e: oidcf::models::errors::FederationError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    trust_chain.build_trust().map_err(wrap_validation_error)?;
    trust_chain
        .verify()
        .map_err(|e| wrap_validation_error(e.first().unwrap().clone()))?;
    Ok(())
}

fn to_oidf_trust_chain_info(
    mut trust_chain: oidcf::DefaultFederationRelation,
) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_validation_error = |e: oidcf::models::errors::FederationError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    trust_chain.build_trust().map_err(wrap_validation_error)?;
    trust_chain
        .verify()
        .map_err(|e| wrap_validation_error(e.first().unwrap().clone()))?;

    let trust_anchor_keys: Vec<_> = trust_chain
        .trust_entities
        .values()
        .flat_map(|e| e.entity_config.as_ref())
        .filter(|e| matches!(e, EntityConfig::TrustAnchor(_)))
        .flat_map(|ta| {
            let jwks = ta.jwks();
            let keys = jwks
                .0
                .keys()
                .into_iter()
                .map(|jwk| serde_json::to_string(&jwk.to_public_key().unwrap()).unwrap())
                .collect::<Vec<_>>();
            keys.into_iter()
        })
        .collect();
    let subordinate_statements: Vec<_> = trust_chain
        .leaf
        .subordinate_statement
        .iter()
        .map(|jwt| jwt.jwt_at(0))
        .collect();

    let leaf = if let Some(EntityConfig::Leaf(leaf)) = trust_chain.leaf.entity_config {
        let pld = leaf.payload_unverified();
        to_leaf_info(pld.insecure())
    } else {
        return Err(FederationError::ValidationFailed(anyhow::anyhow!(
            "no leaf"
        )));
    };

    Ok(OidcfTrustChainInfo {
        trust_anchor_keys,
        subordinate_statements,
        leaf,
    })
}

fn as_vec_string(v: &serde_json::Value) -> Option<Vec<String>> {
    v.as_array().map(|a| {
        a.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect()
    })
}

fn to_leaf_info(leaf: &EntityStatement) -> OidcfLeafInfo {
    let domain = leaf.sub();

    let cred_issuer = leaf
        .metadata
        .as_ref()
        .and_then(|v| v.get("openid_credential_issuer"));
    let credential_configurations_supported = cred_issuer
        .and_then(|v| v.get("credential_configurations_supported"))
        .and_then(|v| v.as_object())
        .map(|v| v.keys().cloned().collect::<Vec<_>>());

    // Many different places to get display name and logo from:
    // We just try and pick the first that we find ; no particular order of precedence is defined

    // Attempt to information from credential issuer display metadata
    // - openid_credential_issuer.display[0].name
    // - openid_credential_issuer.display[0].logo.uri
    let cred_issuer_display = cred_issuer
        .and_then(|v| v.get("display"))
        .and_then(|v| v.as_array())
        .and_then(|v| v.first()); // TODO: select based on language?
    let mut display_name = cred_issuer_display
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut logo_uri = cred_issuer_display
        .and_then(|v| v.get("logo"))
        .and_then(|v| v.get("uri"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Alternatively use credential verifier metadata
    //  - OpenID Federation Wallet Architectures 1.0 draft 03
    //  -> openid_credential_verifier metadata as defined in OpenID4VP
    //  -> OpenID4VP "Verifier Metadata"
    //  -> RFC 7591
    //
    // - openid_credential_verifier.client_name
    // - openid_credential_verifier.logo_uri
    let cred_verifier = leaf
        .metadata
        .as_ref()
        .and_then(|v| v.get("openid_credential_verifier"));

    display_name = display_name.or_else(|| {
        cred_verifier
            .and_then(|v| v.get("client_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    logo_uri = logo_uri.or_else(|| {
        cred_verifier
            .and_then(|v| v.get("logo_uri"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    // Alternatively use metadata defined by openid-federation.
    // According to OpenID Federation Wallet Architectures 1.0 draft 03,
    // these can exist on any of the Entity Types (openid_credential_issuer, openid_credential_verifier, federation_entity, ...)
    //  - *.display_name
    //  - *.organization_name
    //  - *.logo_uri
    let federation_entity = leaf
        .metadata
        .as_ref()
        .and_then(|v| v.get("federation_entity"));

    let oidf_display_name = |obj: &Option<&transformer::Value>| {
        obj.and_then(|v| v.get("display_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                obj.and_then(|v| v.get("organization_name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    };
    let oidf_logo_uri = |obj: &Option<&transformer::Value>| {
        obj.and_then(|v| v.get("logo_uri"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    display_name = display_name
        .or_else(|| oidf_display_name(&federation_entity))
        .or_else(|| oidf_display_name(&cred_issuer))
        .or_else(|| oidf_display_name(&cred_verifier));
    logo_uri = logo_uri
        .or_else(|| oidf_logo_uri(&federation_entity))
        .or_else(|| oidf_logo_uri(&cred_issuer))
        .or_else(|| oidf_logo_uri(&cred_verifier));

    let display_name = display_name.unwrap_or("".to_string());

    OidcfLeafInfo {
        domain,
        display_name,
        logo_uri,
        credential_configurations_supported,
    }
}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
