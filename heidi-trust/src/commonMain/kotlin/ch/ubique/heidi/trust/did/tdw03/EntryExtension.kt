package ch.ubique.heidi.trust.did.tdw03

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


// https://identity.foundation/didwebvh/v0.3/#verify-the-entry-hash
fun DidLogEntry.Tdw03.verifyEntryHash(previousEntryId: String): Boolean {
    // Determine the hash algorithm used by theDID Controller
    // from the multihash entryHash value.
    val entryHash = MultiHash.Companion.fromBase58btc(versionId.entryHash)

    // Only SHA2-256 is accepted in did:tdw:0.3
    // https://identity.foundation/didwebvh/v0.3/#did-method-processes
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    if (entryHash.code() != 0x12UL) // SHA2-256
        return false

    // Extract the versionId (first item) in the DID log entry,
    // and remove from it the version number and dash prefix,
    // leaving the log entry entryHash.
    val entry = Value.Array(listOf(
        Value.String(previousEntryId),
        rawValue[1],
        rawValue[2],
        rawValue[3],
    ))
    val hash = MultiHash.Companion.create(
        0x12UL,
        sha256Rs(entry.toCanonicalJson().encodeToByteArray())
    )

    return hash.toBase58btc() == versionId.entryHash
}

fun DidLogEntry.Tdw03.verifyIntegrityProof(keys: List<String>): Boolean {
    for ((proof, raw) in proofs) {
        val keyId = proof.keyId
        val key = keys.find { it == keyId }?.let { EdDsaPublicKey.Companion.fromMultibase(it) }
            ?: return false

        if (!verifyProof(proof, raw, key))
            return false
    }

    return true
}

private fun DidLogEntry.Tdw03.verifyProof(
    proof: DataIntegrityProof,
    raw: Value,
    key: EdDsaPublicKey,
): Boolean {
    if (proof.type != "DataIntegrityProof")
        return false

    // "eddsa-jcs-2022" is the only supported cryptosuite
    // https://identity.foundation/didwebvh/v0.3/#did-method-processes
    if (proof.cryptosuite != "eddsa-jcs-2022")
        return false

    return verifyDidDocSignature(proof, raw, key)
            // WARNING: This is a hack to make it work with implementations that do not add the
            // `@context` to the `ToBeSigned` part of the didDocument, all though the
            // [eddsa-jcs-2022](https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022)
            // needs it (e.g. Swiyu in the current implementation)
            || verifyDidDocSignature(proof, raw, key, addContext = false)
}

private fun DidLogEntry.Tdw03.verifyDidDocSignature(
    proof: DataIntegrityProof,
    raw: Value,
    key: EdDsaPublicKey,
    addContext: Boolean = true,
): Boolean {
    val didDoc = rawValue[3]["value"]

    val proofConfigMap = (raw.asObject() ?: return false)
        .filterKeys { it != "proofValue" }
        .toMutableMap()
    if (didDoc["@context"] !is Value.Null && addContext) {
        proofConfigMap["@context"] = didDoc["@context"]
    }
    val proofConfig = Value.Object(proofConfigMap)

    val proofConfigHash = sha256Rs(proofConfig.toCanonicalJson().encodeToByteArray())
    val transformedDocumentHash = sha256Rs(didDoc.toCanonicalJson().encodeToByteArray())
    val hashData = proofConfigHash + transformedDocumentHash

    val isVerified = runCatching { key.verify(hashData, proof.proofValue) }
        .getOrNull() ?: return false
    return isVerified
}

fun DidLogEntry.Tdw03.verifyScid(): Boolean {
    val scid = parameters.scid ?: return false

    val scidHash = MultiHash.Companion.fromBase58btc(scid)

    // Only SHA2-256 is accepted in did:tdw:0.3
    // https://identity.foundation/didwebvh/v0.3/#did-method-processes
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    if (scidHash.code() != 0x12UL) // SHA2-256
        return false

    val preliminaryEntryString = Json.Default.encodeToString(
        Value.Array(listOf(
            Value.String("{SCID}"),
            rawValue[1],
            rawValue[2],
            rawValue[3]
        )))
        .replace(scid, "{SCID}")
    val preliminaryEntry = Json.Default.decodeFromString<Value>(preliminaryEntryString)

    val hash = MultiHash.Companion.create(
        scidHash.code(),
        sha256Rs(preliminaryEntry.toCanonicalJson().encodeToByteArray())
    )

    return hash.toBase58btc() == scid
}

fun DidLogEntry.Tdw03.verifyUpdateKeyHashes(
    nextKeyHashes: List<String>,
): Boolean {
    val nextKeyMultiHashes = nextKeyHashes.map { MultiHash.Companion.fromBase58btc(it) }

    // Only SHA2-256 is accepted in did:tdw:0.3
    // https://identity.foundation/didwebvh/v0.3/#did-method-processes
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    if (nextKeyMultiHashes.any { it.code() != 0x12UL })
        throw ResolveException("Unsupported Key Hash algorithm")

    for (key in parameters.updateKeys ?: listOf()) {
        val keyHash = MultiHash.Companion.create(0x12UL, sha256Rs(key.encodeToByteArray()))

        if (!nextKeyHashes.contains(keyHash.toBase58btc()))
            return false
    }

    return true
}