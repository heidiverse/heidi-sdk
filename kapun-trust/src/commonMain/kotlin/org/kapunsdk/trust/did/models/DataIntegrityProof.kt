package org.kapunsdk.trust.did.models

import org.kapunsdk.util.extensions.asObject
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.toCanonicalJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uniffi.kapun_crypto_rust.EdDsaPublicKey
import uniffi.kapun_crypto_rust.sha256Rs
import uniffi.kapun_util_rust.Value

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