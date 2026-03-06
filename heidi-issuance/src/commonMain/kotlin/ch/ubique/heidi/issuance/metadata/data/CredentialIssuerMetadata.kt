package ch.ubique.heidi.issuance.metadata.data

import kotlinx.serialization.Serializable

@Serializable
sealed class CredentialIssuerMetadata {
    @Serializable
    data class Signed(
        override val claims: CredentialIssuerMetadataClaims,
        val originalJwt: String,
        val originalUrl: String,
    ) : CredentialIssuerMetadata()

    @Serializable
    class Unsigned(
        override val claims: CredentialIssuerMetadataClaims
    ) : CredentialIssuerMetadata()

    abstract val claims: CredentialIssuerMetadataClaims
}