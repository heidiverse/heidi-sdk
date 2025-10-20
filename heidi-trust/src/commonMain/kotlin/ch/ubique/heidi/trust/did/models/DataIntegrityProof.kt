package ch.ubique.heidi.trust.did.models

import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCanonicalJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.EdDsaPublicKey
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value

@Serializable
data class DataIntegrityProof(
    val type: String,
    val cryptosuite: String,
    val verificationMethod: String,
    val proofValue: String,
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        fun fromValue(value: Value): DataIntegrityProof =
            json.decodeFromString(value.toCanonicalJson())
    }

    val keyId
        get() = verificationMethod.substringAfter("did:key:").split('#')[0]

    fun verify(
        rawValue: Value,
        document: Value,
        key: EdDsaPublicKey,
    ): Boolean {
        if (this.type != "DataIntegrityProof")
            return false

        // "eddsa-jcs-2022" is the only supported cryptosuite
        // https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
        if (this.cryptosuite != "eddsa-jcs-2022")
            return false

        val proofConfigMap = (rawValue.asObject() ?: return false)
            .filterKeys { it != "proofValue" }
            .toMutableMap()

        val proofConfig = Value.Object(proofConfigMap)

        val proofConfigHash = sha256Rs(proofConfig.toCanonicalJson().encodeToByteArray())
        val transformedDocumentHash = sha256Rs(document.toCanonicalJson().encodeToByteArray())
        val hashData = proofConfigHash + transformedDocumentHash

        val isVerified = runCatching { key.verify(hashData, this.proofValue) }
            .getOrNull() ?: return false
        return isVerified
    }
}