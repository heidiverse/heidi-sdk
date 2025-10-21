package ch.ubique.heidi.trust.did.webvh10

import ch.ubique.heidi.trust.did.models.DataIntegrityProof
import ch.ubique.heidi.trust.did.models.DidLogEntry
import ch.ubique.heidi.trust.did.models.ResolveException
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCanonicalJson
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.EdDsaPublicKey
import uniffi.heidi_crypto_rust.MultiHash
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value


// https://identity.foundation/didwebvh/v1.0/#verify-the-entry-hash
fun DidLogEntry.WebVH10.verifyEntryHash(previousEntryId: String): Boolean {
    // Determine the hash algorithm used by theDID Controller
    // from the multihash entryHash value.
    val entryHash = MultiHash.Companion.fromBase58btc(versionId.entryHash)

    // Only SHA2-256 is accepted in did:webvh:1.0
    // https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    if (entryHash.code() != 0x12UL) // SHA2-256
        return false

    // Extract the versionId (first item) in the DID log entry,
    // and remove from it the version number and dash prefix,
    // leaving the log entry entryHash.
    val entry = Value.Object(mapOf(
        "versionId" to Value.String(previousEntryId),
        "versionTime" to rawValue["versionTime"],
        "parameters" to rawValue["parameters"],
        "state" to rawValue["state"],
    ))
    val hash = MultiHash.Companion.create(
        0x12UL,
        sha256Rs(entry.toCanonicalJson().encodeToByteArray())
    )

    return hash.toBase58btc() == versionId.entryHash
}

fun DidLogEntry.WebVH10.verifyIntegrityProof(keys: List<String>): Boolean {
    for ((proof, raw) in proofs) {
        val keyId = proof.keyId
        val key = keys.find { it == keyId }?.let { EdDsaPublicKey.Companion.fromMultibase(it) }
            ?: return false

        if (!verifyProof(proof, raw, key))
            return false
    }

    return true
}

private fun DidLogEntry.WebVH10.verifyProof(
    proof: DataIntegrityProof,
    raw: Value,
    key: EdDsaPublicKey,
): Boolean {
    if (proof.type != "DataIntegrityProof")
        return false

    // "eddsa-jcs-2022" is the only supported cryptosuite
    // https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
    if (proof.cryptosuite != "eddsa-jcs-2022")
        return false

    return verifyDidDocSignature(proof, raw, key)
}

internal fun DidLogEntry.WebVH10.verifyDidDocSignature(
    proof: DataIntegrityProof,
    raw: Value,
    key: EdDsaPublicKey,
): Boolean {
    val document = Value.Object(
        rawValue
            .v1
            .filterKeys { it != "proof" }
            .toMutableMap())

    val proofConfigMap = (raw.asObject() ?: return false)
        .filterKeys { it != "proofValue" }
        .toMutableMap()
    if (document["@context"] !is Value.Null) {
        proofConfigMap["@context"] = document["@context"]
    }
    val proofConfig = Value.Object(proofConfigMap)

    val proofConfigHash = sha256Rs(proofConfig.toCanonicalJson().encodeToByteArray())
    val transformedDocumentHash = sha256Rs(document.toCanonicalJson().encodeToByteArray())
    val hashData = proofConfigHash + transformedDocumentHash

    val isVerified = runCatching { key.verify(hashData, proof.proofValue) }
        .getOrNull() ?: return false
    return isVerified
}

// https://identity.foundation/didwebvh/v1.0/#verify-scid
fun DidLogEntry.WebVH10.verifyScid(): Boolean {
    val scid = parameters.scid ?: return false

    val scidHash = MultiHash.Companion.fromBase58btc(scid)

    // Only SHA2-256 is accepted in did:webvh:1.0
    // https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    if (scidHash.code() != 0x12UL) // SHA2-256
        return false

    val preliminaryEntryString = Json.Default.encodeToString(
        Value.Object(mapOf(
            "versionId" to Value.String("{SCID}"),
            "versionTime" to rawValue["versionTime"],
            "parameters" to rawValue["parameters"],
            "state" to rawValue["state"],
        )))
        .replace(scid, "{SCID}")
    val preliminaryEntry = Json.Default.decodeFromString<Value>(preliminaryEntryString)

    val hash = MultiHash.Companion.create(
        0x12UL,
        sha256Rs(preliminaryEntry.toCanonicalJson().encodeToByteArray())
    )

    return hash.toBase58btc() == scid
}

fun DidLogEntry.WebVH10.verifyUpdateKeyHashes(
    nextKeyHashes: List<String>,
): Boolean {
    val nextKeyMultiHashes = nextKeyHashes.map { MultiHash.Companion.fromBase58btc(it) }

    // Only SHA2-256 is accepted in did:webvh:1.0
    if (nextKeyMultiHashes.any { it.code() != 0x12UL })
        throw ResolveException("Unsupported Key Hash algorithm")

    for (key in parameters.updateKeys ?: listOf()) {
        val keyHash = MultiHash.Companion.create(0x12UL, sha256Rs(key.encodeToByteArray()))

        if (!nextKeyHashes.contains(keyHash.toBase58btc()))
            return false
    }

    return true
}
