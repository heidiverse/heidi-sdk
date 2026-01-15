use std::{fmt::Display, sync::Arc};

use heidi_util_rust::value::Value;
use iref::IriBuf;
use json_ld::{ChainLoader, ReqwestLoader};
use static_iref::iri;
use tokio::{runtime::Handle, task::LocalSet};

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

    /// The credential as a JSON-LD object. The structure of this object follows the W3C Verifiable
    /// Credentials Data Model and the JSON-LD is framed and compacted.
    pub data: Value,

    /// The original credential
    pub original: String,
}

impl LdpVC {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.data.clone()).ok()
    }
}

const CONTEXT_W3C: &'static str = include_str!("../jsonld/www.w3.org/ns/credentials/v2");

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn parse_ldp_vc(
    credential: String,
    additional_context: Vec<String>,
) -> Result<LdpVC, ParseError> {
    let original = credential.clone();
    let vc = tokio::task::spawn_blocking(move || {
        let handle = Handle::current();
        let local = LocalSet::new();

        // Use the handle to block, and let the local set run the future
        handle.block_on(local.run_until(async move {
            let loader = ChainLoader::new(
                StaticLoader::new()
                    .with_document("https://www.w3.org/ns/credentials/v2", CONTEXT_W3C),
                ReqwestLoader::new(),
            );
            let mut context = vec![iri!("https://www.w3.org/ns/credentials/v2").to_owned()];
            context.extend(
                additional_context
                    .into_iter()
                    .filter_map(|c| IriBuf::new(c).ok()),
            );

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

    // Both "type" and "@type" are valid keys for the credential type
    let doctype = vc
        .get("type")
        .or_else(|| vc.get("@type"))
        .and_then(|value| {
            value.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            })
        })
        .unwrap_or_default();

    Ok(LdpVC {
        doctype,
        data: vc.into(),
        original,
    })
}

#[cfg(test)]
mod tests {
    const OPEN_BADGE_VC: &str = r#"
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
  ],
  "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ?v=3_0",
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  "name": "AI Act",
  "evidence": [],
  "issuer": {
    "id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0",
    "type": [
      "Profile"
    ],
    "name": "Open Educational Badges",
    "url": "https://openbadges.education",
    "email": "annika@mycelia.education"
  },
  "validFrom": "2025-12-04T08:37:40.379213+00:00",
  "credentialSubject": {
    "type": [
      "AchievementSubject"
    ],
    "identifier": [
      {
        "type": "IdentityObject",
        "identityHash": "sha256$79a12f688e1bd35f85ad4ee1c71b5d7c942ea289aecf616159a20dc0d5af2419",
        "identityType": "emailAddress",
        "hashed": true,
        "salt": "6800b252df744e47b9d9837371a1618a"
      }
    ],
    "achievement": {
      "id": "https://api.openbadges.education/public/badges/1l5y_22PSauVhLYihoqmVw?v=3_0",
      "type": [
        "Achievement"
      ],
      "name": "AI Act",
      "description": "Dieser Workshop bietet eine solide Einf\u00fchrung in KI mit besonderem Schwerpunkt auf dem Grundlagenwissen, das f\u00fcr einen verantwortungsvollen Umgang mit KI erforderlich ist - im Einklang mit den Anforderungen des EU-AI-Act. Die Teilnehmenden erhalten Einblicke in die Funktionsweise von KI-Systemen, wo ihre Grenzen und Risiken liegen und was eine verantwortungsvolle Nutzung in der Praxis bedeutet. Mit einer Mischung aus interaktivem Input und praktischer Reflexion st\u00e4rkt das Training das Vertrauen und das Bewusstsein f\u00fcr den Umgang mit der sich entwickelnden KI-Landschaft und gibt rechtliche Grundlagen.",
      "achievementType": "Badge",
      "criteria": {
        "narrative": ""
      },
      "image": {
        "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/image",
        "type": "Image"
      }
    },
    "activityStartDate": "2025-12-04T00:00:00+00:00",
    "activityLocation": {
      "type": [
        "Address"
      ],
      "addressLocality": "Z\u00fcrich",
      "postalCode": "8001"
    }
  },
  "credentialStatus": {
    "id": "https://api.openbadges.education/public/assertions/DwwWNnYoQ9aiBjnPMhPcxQ/revocations",
    "type": "1EdTechRevocationList"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2025-12-04T08:37:40.379213+00:00",
      "verificationMethod": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0#key-0",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5hTkyXpMzQx671RKemdnj2GpmHCUthKY1KxYRVT8renbL81MTrnVbBGfR3QfwJVu8j32ZZdpvuwPvBVYxLEbuA5z"
    }
  ]
}
    "#;

    #[tokio::test]
    async fn test_parse_open_badge_vc() {
        let ldp_vc = super::parse_ldp_vc(
            OPEN_BADGE_VC.to_string(),
            vec![
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json".to_string(),
                "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json".to_string(),
            ],
        )
        .await
        .expect("Failed to parse LDP VC");

        assert!(ldp_vc.doctype.contains(&"OpenBadgeCredential".to_string()));

        assert_eq!(ldp_vc.original, OPEN_BADGE_VC.to_string());

        assert_eq!(
            Some("AI Act"),
            ldp_vc
                .data
                .get("credentialSubject")
                .and_then(|v| v.get("achievement"))
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
        );
    }
}
