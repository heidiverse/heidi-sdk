/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package ch.ubique.heidi.credentials

import ch.ubique.heidi.credentials.sdjwt.SdJwtVcSignatureResolver
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.*
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_util_rust.Value
import kotlin.io.encoding.Base64

sealed class W3C {
    companion object {
        val W3C_FORMATS: Array<String> = arrayOf("vc+sd-jwt")

        // NOTE: In the future other W3C formats can be supported
        fun parse(credential: String): W3C =
            SdJwt(parseW3cSdJwt(credential))
    }

    abstract val docType: String

    abstract fun asJson(): Value

    abstract fun presentation(): SdJwtBuilder

    abstract fun getOriginalNumClaims(): Int

    abstract fun getNumDisclosed(): Int

    abstract fun isSignatureValid(): Boolean

    data class SdJwt(val inner: W3cSdJwt) : W3C() {
        override val docType: String = inner.doctype

        override fun asJson(): Value =
            inner.json

        override fun presentation(): SdJwtBuilder =
            SdJwtBuilder.fromW3c(inner)

        override fun getOriginalNumClaims(): Int =
            inner.numDisclosures.toInt()

        override fun getNumDisclosed(): Int =
            inner.numDisclosures.toInt()

        override fun isSignatureValid(): Boolean
            = SdJwtVcSignatureResolver.isSignatureValid(inner.originalJwt)

        companion object {
            fun create(
                claims: Value,
                disclosures: List<ClaimsPointer>,
                keyId: String,
                key: SignatureCreator,
                pubKeyJwk: Value?
            ): SdJwt? {
                if (claims !is Value.Object) {
                    return null;
                }

                val header = Header(alg = key.alg(), kid = keyId)
                val keyClaims = claims.asObject()!!.toMutableMap()

                if (pubKeyJwk != null) {
                    keyClaims.put("cnf", Value.Object(mapOf("jwk" to pubKeyJwk)))
                }

                val claimObject = Value.Object(keyClaims)

                val sdJwt = createDisclosureForObject(claimObject, disclosures, 1)

                val headerEncoded = base64UrlEncode(
                    Json.encodeToString(Header.serializer(), header).encodeToByteArray()
                )
                val sdJwtDisclosure = sdJwt.getOrNull() ?: return null
                val bodyEncoded = base64UrlEncode(
                    Json.encodeToString(sdJwtDisclosure.disclosedObject).encodeToByteArray()
                )
                val msgPayload = "$headerEncoded.$bodyEncoded"
                val signature = base64UrlEncode(key.sign(msgPayload.encodeToByteArray()))
                val jwt = "$msgPayload.$signature"
                val disclosureString = sdJwtDisclosure.disclosure.joinToString("~")

                return SdJwt(parseW3cSdJwt("$jwt~$disclosureString~"))
            }
        }
    }

    data class OpenBadge303(private val inner: LdpVc) : W3C() {
        val originalJsonLd = inner.original

        override val docType: String
            get() = inner.doctype.firstOrNull { it != "VerifiableCredential" }
                ?: "VerifiableCredential"

        val name: String?
            get() = inner.data["name"].asString()

        val achievement: Value
            get() = inner.data["credentialSubject"]["achievement"]

        val issuerName: String?
            get() = inner.data["issuer"]["name"].asString()

        val pngBytes: ByteArray? by lazy {
            inner.pngBytesB64?.let { Base64.decode(it) }
        }

        private val isValid by lazy {
            // TODO: Can we get rid of the runBlocking?
            runBlocking { ldpVerifyProof(inner) }
        }

        override fun asJson(): Value = inner.data

        override fun presentation(): SdJwtBuilder {
            TODO()
        }

        fun asVerifiablePresentation(): Result<String> = runCatching {
            val proof = Value.Object(mapOf(
                "@context" to Value.Array(listOf(
                    Value.String("https://www.w3.org/2018/credentials/v1"),
                    Value.String("https://w3id.org/security/data-integrity/v2")
                )),
                "type" to Value.Array(listOf(
                    Value.String("VerifiablePresentation")
                )),
                "verifiableCredential" to Value.Array(listOf(
                    this.inner.data
                )),
                // TODO: Proof
            ))

            json.encodeToString(proof)
        }

        override fun getOriginalNumClaims(): Int = 0
        override fun getNumDisclosed(): Int = 0

        override fun isSignatureValid(): Boolean = isValid

        fun serialized(): String =
            Json.encodeToString(this.inner)

        companion object {
            suspend fun parse(credential: String): OpenBadge303 =
                OpenBadge303(parseOpenBadges(Base64.decode(credential), listOf(
                    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
                )))

            fun parseCompacted(credential: String): OpenBadge303 =
                OpenBadge303(Json.decodeFromString(credential))
        }
    }
}
