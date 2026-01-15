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
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.json
import kotlinx.coroutines.runBlocking
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

    data class OpenBadge303(private val inner: LdpVc) : W3C() {
        val originalJsonLd = inner.original

        override val docType: String
            get() = inner.doctype.firstOrNull { it != "VerifiableCredential" }
                ?: "VerifiableCredential"

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

        companion object {
            val SAMPLE = """
                {
                  "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
                  ],
                  "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ?v=3_0",
                  "type": [
                    "VerifiableCredential",
                    "OpenBadgeCredential"
                  ],
                  "name": "Competent Developer",
                  "proof": {
                    "type": "DataIntegrityProof",
                    "created": "2026-01-15T12:10:16.064699+00:00",
                    "cryptosuite": "eddsa-rdfc-2022",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z3o81trEVFipGK3UxHfmYhJgiFz8pqHZyJqkCWo6oxvoZzqEJCb5xsPmDn6eNt92aNUgXQHqeY8gpsjkhPtp3PELq",
                    "verificationMethod": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0#key-0"
                  },
                  "credentialStatus": {
                    "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ/revocations",
                    "type": "1EdTechRevocationList"
                  },
                  "credentialSubject": {
                    "type": "AchievementSubject",
                    "achievement": {
                      "id": "https://api.openbadges.education/public/badges/i_5bFW5cS1umulncJIoaKQ?v=3_0",
                      "type": "Achievement",
                      "criteria": {
                        "narrative": ""
                      },
                      "achievementType": "Badge",
                      "image": {
                        "id": "https://api.openbadges.education/public/assertions/5geq-uh_Ss6uWeDrkM_jLQ/image",
                        "type": "Image"
                      },
                      "description": "Implemented Open Badges in Heidi Wallet",
                      "name": "Competent Developer"
                    },
                    "identifier": [
                      {
                        "type": "IdentityObject",
                        "hashed": true,
                        "identityHash": "sha256$43542fe801368f236d83612930b5031532593f4691595c951f3b3c0f5ebf8590",
                        "identityType": "emailAddress",
                        "salt": "cd56023d11e144a995542bcd90a2107f"
                      }
                    ]
                  },
                  "evidence": [],
                  "issuer": {
                    "id": "https://api.openbadges.education/public/issuers/h6VCjbRBR7eC22jwUz45JA?v=3_0",
                    "type": "Profile",
                    "email": "annika@mycelia.education",
                    "name": "Open Educational Badges",
                    "url": "https://openbadges.education"
                  },
                  "validFrom": "2026-01-15T12:10:16.064699+00:00",
                  "validUntil": "2028-10-11T12:10:16.064530+00:00"
                } 
            """.trimIndent()

            suspend fun parse(credential: String): OpenBadge303 =
                OpenBadge303(parseLdpVc(credential, listOf(
                    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                    "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
                )))

            fun parseCompacted(credential: String): OpenBadge303 =
                OpenBadge303(parseLdpVcCompacted(credential))
        }
    }
}
