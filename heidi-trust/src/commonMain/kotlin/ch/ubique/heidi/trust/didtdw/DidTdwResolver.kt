@file:OptIn(ExperimentalTime::class)

package ch.ubique.heidi.trust.didtdw

import ch.ubique.heidi.trust.didtdw.DidTdwResolver.Proof.DataIntegrityProof
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCanonicalJson
import ch.ubique.heidi.util.extensions.transform
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.DidVerificationDocument
import uniffi.heidi_crypto_rust.EdDsaPublicKey
import uniffi.heidi_crypto_rust.MultiHash
import uniffi.heidi_crypto_rust.parseDidVerificationDocument
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

data class DidTdwResolver(
    val entries: List<Entry>
) {
    class ResolveException(message: String) : Exception(message)

    data class Entry(
        internal val versionId: VersionId,
        internal val versionTime: Instant,
        internal val parameters: Parameters,
        internal val state: Value,
        internal val proof: Proof,

        internal val rawValue: Value.Array
    ) {
        companion object {
            private val json = Json { ignoreUnknownKeys = true }

            fun parse(str: String): Entry {
                val array = json.decodeFromString<Value>(str)
                    .asArray() ?: throw ResolveException("Log Entry is not an array")

                if (array.size != 5)
                    throw ResolveException("Invalid Log Entry: array of size ${array.size} found")

                val versionId = array[0]
                val versionTime = array[1]
                val parameters = array[2]
                val state = array[3]
                val proof = array[4]

                return Entry(
                    versionId = versionId.asString()?.let {
                        val split = it.split('-')
                        VersionId(version = split[0].toInt(), entryHash = split[1])
                    } ?: throw ResolveException("VersionId is not a String"),
                    versionTime = versionTime.asString()?.let {
                        Instant.parse(it)
                    } ?: throw ResolveException("VersionTime is not a String"),
                    parameters = parameters.transform<Parameters>()
                        ?: throw ResolveException("Couldn't parse parameters"),
                    state = state,
                    proof = proof.transform<List<Value>>()?.let { proofs ->
                        Proof(proofs.map { Pair(
                                it.transform() ?: throw ResolveException("Couldn't parse DataIntegrityProof"),
                                it)
                            }
                        )
                    } ?: throw ResolveException("Couldn't parse Data Integrity Proof"),
                    rawValue = Value.Array(array)
                )
            }
        }

        fun doc(): DidVerificationDocument? =
            parseDidVerificationDocument(this.state["value"])

        // https://identity.foundation/didwebvh/v0.3/#verify-the-entry-hash
        fun verifyEntryHash(previousEntryId: String): Boolean {
            // Determine the hash algorithm used by theDID Controller
            // from the multihash entryHash value.
            val entryHash = MultiHash.fromBase58btc(versionId.entryHash)

            // TODO: The hash algorithm MUST be one listed in the parameters
            //  defined by the version of the did:tdw specification being
            //  used by the DID Controller based on the method parameters
            //  item set in the current or most recent prior log entry.
            // Currently only SHA2-256 is supported, see table below:
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
            val hash = MultiHash.create(
                0x12UL,
                sha256Rs(entry.toCanonicalJson().encodeToByteArray())
            )

            return hash.toBase58btc() == versionId.entryHash
        }

        fun verifyIntegrityProof(keys: List<String>): Boolean {
            for ((proof, raw) in proof.proofs) {
                val keyId = proof.keyId
                val key = keys.find { it == keyId }?.let { EdDsaPublicKey.fromMultibase(it) }
                    ?: return false

                if (!verifyProof(proof, raw, key))
                    return false
            }

            return true
        }

        private fun verifyProof(
            proof: DataIntegrityProof,
            raw: Value,
            key: EdDsaPublicKey,
        ): Boolean {
            if (proof.type != "DataIntegrityProof")
                return false

            // Currently only "eddsa-jcs-2022" is supported
            // TODO: Add support for more crypto suites
            if (proof.cryptosuite != "eddsa-jcs-2022")
                return false

            return verifyDidDocSignature(proof, raw, key)
                    // WARNING: This is a hack to make it work with Swiyu
                    || verifyDidDocSignature(proof, raw, key, addContext = false)
        }

        private fun verifyDidDocSignature(
            proof: DataIntegrityProof,
            raw: Value,
            key: EdDsaPublicKey,
            addContext: Boolean = true,
        ): Boolean {
            val didDoc = this.rawValue[3]["value"]

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

        fun verifyScid(): Boolean {
            val scid = parameters.scid ?: return false

            val scidHash = MultiHash.fromBase58btc(scid)

            // TODO: The hash algorithm MUST be one listed in the parameters
            //  defined by the version of the did:tdw specification being
            //  used by the DID Controller based on the method parameters
            //  item set in the current or most recent prior log entry.
            // Currently only SHA2-256 is supported, see table below:
            // https://github.com/multiformats/multicodec/blob/master/table.csv
            if (scidHash.code() != 0x12UL) // SHA2-256
                return false

            val preliminaryEntryString = Json.encodeToString(Value.Array(listOf(
                Value.String("{SCID}"),
                rawValue[1],
                rawValue[2],
                rawValue[3]
            )))
                .replace(scid, "{SCID}")
            val preliminaryEntry = Json.decodeFromString<Value>(preliminaryEntryString)

            val hash = MultiHash.create(
                scidHash.code(),
                sha256Rs(preliminaryEntry.toCanonicalJson().encodeToByteArray())
            )

            return hash.toBase58btc() == scid
        }

        fun verifyUpdateKeyHashes(
            nextKeyHashes: List<String>,
        ): Boolean {
            val nextKeyMultiHashes = nextKeyHashes.map { MultiHash.fromBase58btc(it) }

            // TODO: Currently on SHA2-256 is supported
            if (nextKeyMultiHashes.any { it.code() != 0x12UL })
                throw ResolveException("Unsupported Key Hash algorithm")

            for (key in parameters.updateKeys ?: listOf()) {
                val keyHash = MultiHash.create(0x12UL, sha256Rs(key.encodeToByteArray()))

                if (!nextKeyHashes.contains(keyHash.toBase58btc()))
                    return false
            }

            return true
        }
    }

    data class VersionId(
        val version: Int,
        val entryHash: String,
    ) {
        override fun toString(): String =
            "$version-$entryHash"
    }

    @Serializable
    data class Parameters(
        val method: String?,
        val scid: String?,
        val updateKeys: List<String>?,
        val portable: Boolean = false,
        val prerotation: Boolean = false,
        val nextKeyHashes: List<String>?,
        val witness: Value?,
        val deactivated: Boolean?,
        val ttl: Int?,
    )

    data class Proof(internal val proofs: List<Pair<DataIntegrityProof, Value>>) {
        @Serializable
        data class DataIntegrityProof(
            val type: String,
            val cryptosuite: String,
            val verificationMethod: String,
            val created: String,
            val proofPurpose: String,
            val challenge: String,
            val proofValue: String,
        ) {
            val keyId
                get() = verificationMethod.substringAfter("did:key:").split('#')[0]
        }
    }

    // https://identity.foundation/didwebvh/v0.3/#read-resolve
    fun resolveLatest(verify: Boolean = true): Entry {
        var latest = entries.maxByOrNull { it.versionId.version }
            ?: throw ResolveException("No entries to choose from")

        if (!verify) return latest

        var previousTime: Instant? = null
        var updateKeys: List<String> = entries.first().parameters.updateKeys
            ?: throw ResolveException("First entry must have updateKeys")
        var previousEntryId: String = entries.first().parameters.scid
            ?: throw ResolveException("First entry must have an SCID")
        var prerotation = false
        var nextKeyHashes = listOf<String>()

        for ((i, entry) in entries.withIndex()) {
            if (entry.parameters.method != null
                && entry.parameters.method != "did:tdw:0.3")
                throw ResolveException("Only did:tdw:0.3 is supported at the moment.")

            // 2. Verify Data Integrity Proof
            if (!entry.verifyIntegrityProof(updateKeys))
                throw ResolveException("Couldn't verify Data Integrity Proof.")
            // It is safe to update the updateKeys now
            if (entry.parameters.updateKeys != null)
                updateKeys = entry.parameters.updateKeys

            // 3.1 The version number MUST be 1 for the the first
            // log entry and MUST be incremented by one for each
            // subsequent log entry.
            if (entry.versionId.version != i + 1)
                throw ResolveException("Entry doesn't have consecutive version id: ${entry.versionId}")

            // 3.3 Verify entry.versionId.entryHash
            if (!entry.verifyEntryHash(previousEntryId))
                throw ResolveException("Couldn't verify entryHash of entry: ${entry.versionId}")
            previousEntryId = entry.versionId.toString()

            // 4.1 The versionTime MUST be a valid ISO8601 date/time
            // string. The versionTime for each log entry MUST be
            // greater than the previous entry’s time.
            if (previousTime != null && previousTime >= entry.versionTime)
                throw ResolveException("Entry doesn't have consecutive version time: ${entry.versionTime}")

            // 4.2 The versionTime of the last entry MUST be earlier than
            // the current time.
            if (Clock.System.now() <= entry.versionTime)
                throw ResolveException("Entry lies in the future, versionTime = ${entry.versionTime}")
            previousTime = entry.versionTime

            // 6. Verify SCID of the first log entry
            if (i == 0) {
                // When processing the first DID log entry, verify
                // the SCID (defined in the parameters) according to
                // the SCID Generation and Verification section of
                // the specification.
                if (!entry.verifyScid())
                    throw ResolveException("SCID could not be verified of entry: ${entry.versionId}")
            }

            // 8. If Key Pre-Rotation is being used, the hash of
            //  all updateKeys entries in the parameters item MUST
            //  match a hash in the active array of nextKeyHashes
            //  parameter, as defined in the Pre-Rotation section of
            //  this specification.

            // Once the value is set to true in a DID log entry it
            // MUST NOT be set to false in a subsequent entry.
            if (prerotation && ! entry.parameters.prerotation)
                throw ResolveException("It is not allowed to disable pre-rotation")

            prerotation = entry.parameters.prerotation

            if (prerotation) {
                if (!entry.verifyUpdateKeyHashes(nextKeyHashes))
                    throw ResolveException("updateKeys are not registered in nextKeyHashes for entry: ${entry.versionId}")

                // A new nextKeyHashes list MUST be in the parameters
                // of the log currently being processed. If not,
                // terminate the resolution process with an error.
                if (entry.parameters.nextKeyHashes == null
                    || entry.parameters.nextKeyHashes.isEmpty()) {
                    throw ResolveException("nextKeyHashes parameter must be present in entry: ${entry.versionId}")
                }
            }
            // Update nextKeyHashes
            entry.parameters.nextKeyHashes?.let { nextKeyHashes = it }
        }

        return latest
    }

    companion object {
        fun parse(jsonl: List<String>): DidTdwResolver =
            DidTdwResolver(jsonl.map { Entry.parse(it) })
    }
}