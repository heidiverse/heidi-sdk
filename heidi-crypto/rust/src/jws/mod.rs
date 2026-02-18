use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use heidi_jwt::{Jwk, jwt::verifier_for_jwk};
use heidi_util_rust::value::Value;

#[uniffi::export]

/// Validate a detached JWS with a JWK, this function assumes that the header has been validated beforehand.
pub fn validate_detached_jws_with_jwk(
    header_b64: &str,
    signature_b64: &str,
    payload: &str,
    jwk: &Value,
) -> bool {
    let raw_body = payload.as_bytes();

    let mut signing_input: Vec<u8> = Vec::new();
    signing_input.extend_from_slice(header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(&raw_body);

    let Ok(signature) = BASE64_URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };

    let Some(jwk) = jwk.transform::<Jwk>() else {
        return false;
    };

    let Some(verifier) = verifier_for_jwk(jwk) else {
        return false;
    };

    return verifier.verify(&signing_input, &signature).is_ok();
}

#[cfg(test)]
mod tests {
    use heidi_util_rust::value::Value;

    #[test]
    fn test_validate_detached_jws_with_jwk() {
        let jwk_value: Value = serde_json::json!({
            "x": "cTZ_dcVbHvRaOcqyrh8XxISpzT0ZY0K4sc1i6g_MhwI",
            "y": "Yknl0kJdq6lp36caafouXKx8HhVBJkcdqTNMW5qBcbY",
            "crv": "P-256",
            "kty": "EC",
            "kid":"version-assertion-1"
        })
        .into();

        let header_b64 = "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJkaWQ6dGR3OlFtYkJLVFYyZFpKYlZvNW0zSkVqWDZrQjhLUWEzanVqWThwSEZOakJ5bWNzeW46aWRlbnRpZmllci1yZWctci50cnVzdC1pbmZyYS5zd2l5dS5hZG1pbi5jaDphcGk6djE6ZGlkOjRkYzZkMDVkLWQ2ZjYtNGRiNi1hNWNhLTUwZmVmNTEyOWUwMCN2ZXJzaW9uLWFzc2VydGlvbi0xIiwidHlwIjoiSk9TRSIsImFsZyI6IkVTMjU2In0";
        let signature_b64 = "9eq3qh5EPZWBnVdpMxhTuAMVoxmzEo9zMpAAVFpJeEYCji60VltL8v0M9ZUtsyjknTrZRFCI_7foJEYeWQgDeg";

        let payload = r#"{"app_id":"ch.admin.foitt.swiyucheck","default_message":[{"body":"Please update the application to continue using the service.","locale":"en-US","title":"Update Required"}],"default_support_lifetime_days":90,"device_blacklist":["samsung-sm-g610f","huawei-mha-l29"],"minimum_os_version":"13.0","platform":"android","store_url":"https://play.google.com/store/apps/details?id=ch.admin.foitt.swiyucheck","versions":[{"message":[{"body":"This version is no longer supported. Please update to continue.","locale":"en-US","title":"Update Required"},{"body":"Diese Version wird nicht mehr unterstützt. Bitte aktualisieren Sie die App.","locale":"de-CH","title":"Aktualisierung erforderlich"}],"release_date":"2025-12-05","support_guaranteed_until":"2026-08-31","update_type":"forced","version":"1.11.0"}]}"#;

        assert!(super::validate_detached_jws_with_jwk(
            header_b64,
            signature_b64,
            payload,
            &jwk_value
        ));

        // Negative case: tampered payload should fail
        let tampered_payload = r#"{"app_id":"ch.admin.foitt.tampered"}"#;
        assert!(!super::validate_detached_jws_with_jwk(
            header_b64,
            signature_b64,
            tampered_payload,
            &jwk_value
        ));
    }
}
