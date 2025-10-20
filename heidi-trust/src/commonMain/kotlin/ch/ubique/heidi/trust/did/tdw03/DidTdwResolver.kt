@file:OptIn(ExperimentalTime::class)

package ch.ubique.heidi.trust.did.tdw03

import ch.ubique.heidi.trust.did.DidResolver
import ch.ubique.heidi.trust.did.models.DidLogEntry
import ch.ubique.heidi.trust.did.models.ResolveException
import ch.ubique.heidi.trust.did.models.WitnessProof
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

data class DidTdwResolver(val entries: List<DidLogEntry>) : DidResolver {
    companion object {
        fun parse(jsonl: List<String>): DidTdwResolver =
            DidTdwResolver(jsonl.map { DidLogEntry.parse(it) })
    }

    // https://identity.foundation/didwebvh/v0.3/#read-resolve
    override fun resolveLatest(verify: Boolean, witnesses: List<WitnessProof>?): DidLogEntry {
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
            if ((entry.parameters.method != null
                && entry.parameters.method != "did:tdw:0.3")
                || entry !is DidLogEntry.Tdw03)
                throw ResolveException("did:tdw:0.3 entry expected!")

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
            if (prerotation && entry.parameters.prerotation == false)
                throw ResolveException("It is not allowed to disable pre-rotation")

            prerotation = entry.parameters.prerotation == true

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
}