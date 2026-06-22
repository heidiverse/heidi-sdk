package ch.ubique.heidi.credentials

import ch.ubique.heidi.util.extensions.*
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value

object JwkThumbprint {
    private val EC_KEYS: List<String> = listOf("crv", "kty", "x", "y")
    private val RSA_KEYS: List<String> = listOf("e", "kty", "n")
    private val OKP_KEYS: List<String> = listOf("crv", "kty", "x")

    fun getEncryptionKey(jwks: Value): Value? {
        return jwks.asArray()
            ?.firstOrNull { it["use"].asString() == "enc" }
    }

    fun thumbprint(jwk: Value): ByteArray? {
        val jwk = jwk.asObject() ?: return null

        return when (jwk["kty"]?.asString()) {
            "EC" -> {
                val map = Value.Object(jwk.filterKeys { EC_KEYS.contains(it) })
                    .toCanonicalJson()
                sha256Rs(map.encodeToByteArray())
            }
            "RSA" -> {
                val map = Value.Object(jwk.filterKeys { RSA_KEYS.contains(it) })
                    .toCanonicalJson()
                sha256Rs(map.encodeToByteArray())
            }
            "OKP" -> {
                val map = Value.Object(jwk.filterKeys { OKP_KEYS.contains(it) })
                    .toCanonicalJson()
                sha256Rs(map.encodeToByteArray())
            }
            else -> throw Exception("Unsupported kty: ${jwk["kty"]}")
        }
    }
}