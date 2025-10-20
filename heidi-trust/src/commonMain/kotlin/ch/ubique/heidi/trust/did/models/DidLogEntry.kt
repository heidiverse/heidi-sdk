@file:OptIn(ExperimentalTime::class)

package ch.ubique.heidi.trust.did.models

import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.fromJsonElement
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.safeTransform
import ch.ubique.heidi.util.extensions.transform
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import uniffi.heidi_crypto_rust.DidVerificationDocument
import uniffi.heidi_crypto_rust.parseDidVerificationDocument
import uniffi.heidi_util_rust.Value
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

sealed interface DidLogEntry {
    data class Tdw03(
        override val versionId: VersionId,
        override val versionTime: Instant,
        override val parameters: Parameters,
        override val state: Value,
        override val proofs: List<Pair<DataIntegrityProof, Value>>,

        internal val rawValue: Value.Array,
    ) : DidLogEntry

    data class WebVH10(
        override val versionId: VersionId,
        override val versionTime: Instant,
        override val parameters: Parameters,
        override val state: Value,
        override val proofs: List<Pair<DataIntegrityProof, Value>>,

        internal val rawValue: Value.Object,
    ) : DidLogEntry

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        fun parse(str: String): DidLogEntry {
            val json = Value.fromJsonElement(json.decodeFromString<JsonElement>(str))

            return json.asArray()?.let { parseArray(it) }
                ?: json.asObject()?.let { parseObject(it) }
                ?: throw ResolveException("Couldn't parse DidLogEntry")
        }

        private fun parseArray(array: List<Value>): DidLogEntry {
            if (array.size != 5)
                throw ResolveException("Invalid Log Entry: array of size ${array.size} found")

            val versionId = array[0]
            val versionTime = array[1]
            val parameters = array[2]
            val state = array[3]
            val proof = array[4]

            return DidLogEntry.Tdw03(
                versionId = versionId.asString()?.let {
                    val split = it.split('-')
                    VersionId(version = split[0].toInt(), entryHash = split[1])
                } ?: throw ResolveException("VersionId is not a String"),
                versionTime = versionTime.asString()?.let {
                    Instant.Companion.parse(it)
                } ?: throw ResolveException("VersionTime is not a String"),
                parameters = parameters.transform<Parameters>()
                    ?: throw ResolveException("Couldn't parse parameters"),
                state = state,
                proofs = proof.transform<List<Value>>()?.map { Pair(
                    it.transform() ?: throw ResolveException("Couldn't parse DataIntegrityProof"),
                    it)
                } ?: throw ResolveException("Couldn't parse Data Integrity Proof"),
                rawValue = Value.Array(array)
            )
        }

        private fun parseObject(obj: Map<String, Value>): DidLogEntry {
            return DidLogEntry.WebVH10(
                versionId = obj["versionId"]?.asString()?.let {
                    val split = it.split('-')
                    VersionId(version = split[0].toInt(), entryHash = split[1])
                } ?: throw ResolveException("VersionId is not a String"),
                versionTime = obj["versionTime"]?.asString()?.let {
                    Instant.Companion.parse(it)
                } ?: throw ResolveException("VersionTime is not a String"),
                parameters = obj["parameters"]?.safeTransform<Parameters>()
                    ?: throw ResolveException("Couldn't parse parameters"),
                state = obj["state"] ?: throw ResolveException("Did Log entry doesn't have a state"),
                proofs = obj["proof"]?.transform<List<Value>>()?.map { Pair(
                    it.transform() ?: throw ResolveException("Couldn't parse DataIntegrityProof"),
                    it)
                } ?: throw ResolveException("Couldn't parse Data Integrity Proof"),
                rawValue = Value.Object(obj)
            )
        }
    }

    val versionId: VersionId
    val versionTime: Instant
    val parameters: Parameters
    val state: Value
    val proofs: List<Pair<DataIntegrityProof, Value>>


    fun doc(): DidVerificationDocument? =
        parseDidVerificationDocument(this.state["value"])
}