package ch.ubique.heidi.trust.framework.oidcfederation

import ch.ubique.heidi.trust.framework.JWKTrustAnchorProvider

private val DEFAULT_TRUST_ANCHORS: List<String> = listOf(
    """{"kty":"EC","crv":"P-256","x":"HlgP6Ce_023fhGJWnLdILu83u-Fudi4MBesi6drVe2M","y":"VM1E-9_iPeuv0HLh1OFFKdBUTUOv1nBOO--UDfzGGjY"}"""
);

class StaticJWKTrustAnchorProvider(
    // Cannonicalized JWKs (fields as ordered by josekit::jwk::to_public_key)
    private val trustAnchors: List<String> = DEFAULT_TRUST_ANCHORS
) : JWKTrustAnchorProvider {

    override fun isTrusted(cannonicalizedJWK: String): Boolean {
        return trustAnchors.contains(cannonicalizedJWK);
    }
}