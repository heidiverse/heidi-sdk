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
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.*
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_util_rust.Value

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

    data class OpenBadge303(private val data: Data) : W3C() {
        /**
         * Helper class to store precomputed information such that we don't have to recompute it
         * again every time we load the credential.
         */
        @Serializable
        data class Data(
            val credential: OpenBadges303Credential,

            // NOTE: To check the credential validity network requests must be potentially made, as
            //       such it is favorable to cache this value. But do note, that if the credential
            //       expires, this value won't be updated.
            val isValid: Boolean,
        )

        override val docType: String
            get() = data.credential.data.types.firstOrNull { it != "VerifiableCredential" }
                ?: "VerifiableCredential"

        val types: List<String>
            get() = data.credential.data.types

        val name: String?
            get() = when (val name = data.credential.data.name) {
                is LocalizableString.ManyLvo -> name.v1.firstOrNull()?.value
                is LocalizableString.OneLvo -> name.v1.value
                is LocalizableString.String -> name.v1
                null -> null
            }

        val achievement: Value
            get() = data.credential.data.credentialSubject?.get("achievement") ?: Value.Null

        val issuerName: String?
            get() = data.credential.data.issuer?.get("name")?.asString()

        val pngBytes: ByteArray = data.credential.imageBytes

        private val dataAsJson: Value by lazy {
            w3cCredentialAsJson(data.credential.originalData)
        }

        val originalString: String
            get() = this.data.credential.original

        override fun asJson(): Value = dataAsJson

        override fun presentation(): SdJwtBuilder {
            throw Exception("Use `asVerifiablePresentation()` instead")
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
                "verifiableCredential" to Value.Array(listOf(dataAsJson)),
            ))

            json.encodeToString(proof)
        }

        override fun getOriginalNumClaims(): Int = 0
        override fun getNumDisclosed(): Int = 0

        override fun isSignatureValid(): Boolean = data.isValid

        fun serialized(): String =
            Json.encodeToString(this.data)

        fun asW3CCredential(): W3cVerifiableCredential =
            data.credential.originalData

        companion object {
            val OPEN_BADGE_FORMATS: Array<String> = arrayOf("ldp_vc")

            suspend fun parse(bytes: ByteArray): OpenBadge303 {
                val credential = parseOpenBadges303Credential(bytes, listOf(
                    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
                ))

                val isValid = verifySecuredDocumentString(credential.original)

                return OpenBadge303(Data(credential, isValid))
            }

            fun parseSerialized(credential: String): OpenBadge303 =
                OpenBadge303(Json.decodeFromString(credential))
        }
    }
}
