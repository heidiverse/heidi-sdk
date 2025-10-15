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

package ch.ubique.heidi.util.json

import ch.ubique.heidi.credentials.Mdoc
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.dcql.ClaimHasNoValueException
import ch.ubique.heidi.dcql.ClaimValueNotAllowed
import ch.ubique.heidi.dcql.DcqlPresentation
import ch.ubique.heidi.dcql.InvalidDocTypeException
import ch.ubique.heidi.dcql.InvalidVctValueException
import ch.ubique.heidi.dcql.NoClaimSetQueryOptionSatisfiedException
import ch.ubique.heidi.dcql.NoCredentialSetQueryOptionSatisfiedException
import ch.ubique.heidi.dcql.NotAllClaimsProvidedException
import ch.ubique.heidi.dcql.checkDcqlPresentation
import ch.ubique.heidi.dcql.getVpToken
import ch.ubique.heidi.dcql.parseDcqlQuery
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCbor
import ch.ubique.heidi.util.json.TestDcql.TestSigner
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.CertificateData
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_crypto_rust.SubjectIdentifier
import uniffi.heidi_crypto_rust.X509PublicKey
import uniffi.heidi_crypto_rust.createCert
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.encodeCbor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class TestDcqlVerification {
    private val privateKeySignature =
        """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "8hL67MEiG_Fi0R0w3ZuLVEy3iQRaqpQHVJDu5FxqvEA",
            "y": "l16hzZH8v5HZrk15FVxjd4naGaKQTgVTg0lfWH1-rXw",
            "d": "upRQppmj4FakCuueGQFOWVfLJ-5MgmgJ_bWoI57FsbY" 
        }
        """.trimIndent()
    private val privateKeyKeyBinding =
        """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "r6H1rd3ykIZdKptSUYevNLOogOnfNPj00mqTlkiWt3w",
            "y": "zIvMTH70o0Mg5-ApGVwUzMQgWkKlCxVdzU6iFd-T_r0",
            "d": "bk3qorDnP1kXussdVqu9Nszq90Hrm8hmsMEOPN-LKJU"
        }
        """.trimIndent()

    private val audience = "test-audience-1"
    private val nonce = "test-nonce-1"

    private val responseUri = "https://example.com/response"
    private val mdocGeneratedNonce = "test-nonce-1"

    private val keyId = "TestKey-1"
    private val issuerKey = SoftwareKeyPair.fromJwkString(privateKeySignature)
    private val issuerSigner = TestSigner(issuerKey)
    private val deviceKeyJwk = Json.decodeFromString<Value>(privateKeyKeyBinding)
    private val keyBindingKey = TestSigner(SoftwareKeyPair.fromJwkString(privateKeyKeyBinding))

    private fun verify(query: DcqlQuery, vpTokens: DcqlPresentation) = checkDcqlPresentation(
        query,
        vpTokens,
        { type, vpToken, _ ->
            when (type) {
                CredentialType.SdJwt -> mapOf("type" to "sdjwt", "content" to vpToken)
                CredentialType.Mdoc -> mapOf("type" to "mdoc", "content" to vpToken)
                CredentialType.BbsTermwise -> mapOf("type" to "bbs-termwise", "content" to vpToken)
                CredentialType.W3C_VCDM -> mapOf("type" to "w3c", "content" to vpToken)
                else -> mapOf()
            }
        })


    private fun createSdJwk(
        claims: String,
        disclosures: List<List<String>>
    ): SdJwt = SdJwt.create(
        claims = Json.decodeFromString<Value>(claims),
        disclosures = disclosures.map { it.toClaimsPointer()!! },
        keyId = keyId,
        key = issuerSigner,
        pubKeyJwk = deviceKeyJwk,
    )!!

    private fun createMDoc(
        data: Value,
        docType: String,
    ): Mdoc {
        val jwkPublic = Json.decodeFromString<Value>(issuerKey.jwkString())

        return Mdoc.create(
            properties = data,
            signer = issuerSigner,
            docType = docType,
            certificateChain = listOf(
                createCert(
                    CertificateData(
                        issuer = SubjectIdentifier(commonName = "Issuer"),
                        subject = SubjectIdentifier(commonName = "Subject"),
                        notBefore = Clock.System.now().toEpochMilliseconds() / 1000 - 1,
                        notAfter = Clock.System.now().toEpochMilliseconds() / 1000
                                + 86400 * 365,
                    ),
                    X509PublicKey.P256(
                        jwkPublic["x"].asString()!!,
                        jwkPublic["y"].asString()!!,
                    ),
                    issuerKey.asSignatureCreator()
                )!!
            ),
            deviceKey = deviceKeyJwk
        ).getOrNull()!!
    }

    private fun createW3C(
        claims: String,
        disclosures: List<List<String>>
    ): W3C = W3C.SdJwt.create(
        claims = Json.decodeFromString<Value>(claims),
        disclosures = disclosures.map { it.toClaimsPointer()!! },
        keyId = keyId,
        key = issuerSigner,
        pubKeyJwk = deviceKeyJwk,
    )!!

    private fun createPresentation(
        query: CredentialQuery,
        credential: SdJwt,
        disclosures: List<List<String>>? = null,
    ): DcqlPresentation = mapOf(
        query.id to credential
            .getVpToken(
                query,
                audience,
                null,
                null,
                nonce,
                keyBindingKey,
                overrideDisclosures = disclosures?.map { it.toClaimsPointer()!!.path }
            ).getOrNull()!!
    )

    private fun createPresentation(
        query: CredentialQuery,
        credential: Mdoc,
    ): DcqlPresentation = mapOf(
        query.id to credential
            .getVpToken(
                query,
                sha256Rs(encodeCbor(listOf(audience, mdocGeneratedNonce).toCbor())),
                sha256Rs(encodeCbor(listOf(responseUri, mdocGeneratedNonce).toCbor())),
                nonce,
                keyBindingKey,
            ).getOrNull()!!
    )

    private fun createPresentation(
        query: CredentialQuery,
        credential: W3C,
        disclosures: List<List<String>>? = null,
    ): DcqlPresentation = mapOf(
        query.id to credential
            .getVpToken(
                query,
                audience,
                null,
                null,
                nonce,
                keyBindingKey,
                overrideDisclosures = disclosures?.map { it.toClaimsPointer()!!.path }
            ).getOrNull()!!
    )

    @Test
    fun testVerifySdJwtQueryWithClaims() {
        val sdJwt = createSdJwk(
            """
                {
                    "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                    "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "given_name": "John",
                    "family_name": "Doe",
                    "address": {
                        "street_address": "Teststr. 1"
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], sdJwt)

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf("pid" to mapOf("type" to "sdjwt", "content" to dcqlPresentation["pid"] as String))
        )
    }

    @Test
    fun testVerifySdJwtQueryWithClaims_ClaimHasNoValueException() {
        val sdJwt = createSdJwk(
            """
                {
                    "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                    "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "given_name": "John",
                    "family_name": "Doe",
                    "address": {
                        "street_address": "Teststr. 1"
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            sdJwt,
            disclosures = listOf(
                listOf("family_name"),
                listOf("address", "street_address"),
            )
        )

        assertFailsWith<ClaimHasNoValueException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifySdJwtQueryWithClaims_ClaimValueNotAllowed() {
        val sdJwt = createSdJwk(
            """
                {
                    "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                    "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "given_name": "John",
                    "family_name": "Doe",
                    "address": {
                        "street_address": "Teststr. 1"
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            sdJwt
        )


        val query_with_value_restriction = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {"path": ["given_name"], "values": ["test"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<ClaimValueNotAllowed> {
            verify(query_with_value_restriction, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifySdJwtQueryWithClaimSet() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://credentials.example.com/identity_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "postal_code": "1234",
                "last_name": "Doe",
                "date_of_birth": "2000-01-01"
            }
            """.trimIndent(),
            listOf(
                listOf("postal_code"),
                listOf("last_name"),
                listOf("date_of_birth"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [ "https://credentials.example.com/identity_credential" ]
                        },
                        "claims": [
                            {"id": "a", "path": ["last_name"]},
                            {"id": "b", "path": ["postal_code"]},
                            {"id": "c", "path": ["locality"]},
                            {"id": "d", "path": ["region"]},
                            {"id": "e", "path": ["date_of_birth"]}
                        ],
                        "claim_sets": [
                            ["a", "c", "d", "e"],
                            ["a", "b", "e"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], sdJwt)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifySdJwtQueryWithClaimSet_NoClaimSetQueryOptionSatisfiedException() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://credentials.example.com/identity_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "postal_code": "1234",
                "last_name": "Doe",
                "date_of_birth": "2000-01-01"
            }
            """.trimIndent(),
            listOf(
                listOf("postal_code"),
                listOf("last_name"),
                listOf("date_of_birth"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [ "https://credentials.example.com/identity_credential" ]
                        },
                        "claims": [
                            {"id": "a", "path": ["last_name"]},
                            {"id": "b", "path": ["postal_code"]},
                            {"id": "c", "path": ["locality"]},
                            {"id": "d", "path": ["region"]},
                            {"id": "e", "path": ["date_of_birth"]}
                        ],
                        "claim_sets": [
                            ["a", "c", "d", "e"],
                            ["a", "b", "c"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            sdJwt
        )

        assertFailsWith<NoClaimSetQueryOptionSatisfiedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifySdJwtQueryWithoutClaims() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address")
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt"
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], sdJwt)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifySdJwtQueryWithoutClaims_NotAllClaimsProvidedException() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt"
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            sdJwt,
            disclosures = listOf(
                listOf("given_name"),
            )
        )

        assertFailsWith<NotAllClaimsProvidedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifySdJwtQueryWithMeta() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [
                                "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                            ]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], sdJwt)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifySdJwtQueryWithMeta_InvalidVctValueException() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            disclosures = listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": [
                                "https://example.com"
                            ]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            sdJwt,
            disclosures = listOf(
                listOf("given_name"),
            )
        )

        assertFailsWith<InvalidVctValueException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifySdJwtSetQuery() {
        val sdJwt1 = createSdJwk(
            """
            {
                "vct": "https://credentials.example.com/reduced_identity_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )
        val sdJwt2 = createSdJwk(
            """
            {
                "vct": "https://cred.example/residence_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "postal_code": "1234",
                "locality": "here",
                "region": "Zurich"
            }
            """.trimIndent(),
            listOf(
                listOf("postal_code"),
                listOf("locality"),
                listOf("region"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://othercredentials.example/pid"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                        },
                        "claims": [
                            {"path": ["family_name"]},
                            {"path": ["given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://cred.example/residence_credential"]
                        },
                        "claims": [
                            {"path": ["postal_code"]},
                            {"path": ["locality"]},
                            {"path": ["region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://company.example/company_rewards"]
                        },
                        "claims": [
                            {"path": ["rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation =
            createPresentation(
                query.credentials!![2],
                sdJwt1
            ) + createPresentation(
                query.credentials!![3],
                sdJwt2
            )

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf(
                "pid_reduced_cred_1" to mapOf(
                    "type" to "sdjwt",
                    "content" to dcqlPresentation["pid_reduced_cred_1"] as String
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to "sdjwt",
                    "content" to dcqlPresentation["pid_reduced_cred_2"] as String
                ),
            )
        )
    }

    @Test
    fun testVerifySdJwtSetQuery_NoCredentialSetQueryOptionSatisfiedException() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://credentials.example.com/reduced_identity_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://othercredentials.example/pid"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                        },
                        "claims": [
                            {"path": ["family_name"]},
                            {"path": ["given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://cred.example/residence_credential"]
                        },
                        "claims": [
                            {"path": ["postal_code"]},
                            {"path": ["locality"]},
                            {"path": ["region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://company.example/company_rewards"]
                        },
                        "claims": [
                            {"path": ["rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![2],
            sdJwt
        )

        assertFailsWith<NoCredentialSetQueryOptionSatisfiedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    /////////////// MDOC ////////////////

    @Test
    fun testVerifyMDocQueryWithClaims() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyMDocQueryWithClaims_ClaimHasNoValueException() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        val query_with_more_claims = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<ClaimHasNoValueException> {
            verify(query_with_more_claims, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyMDocQueryWithClaims_ClaimValueNotAllowed() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name" ]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        val query_limiting_values = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"], "values": ["test"] },
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<ClaimValueNotAllowed> {
            verify(query_limiting_values, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyMDocQueryWithClaimSet() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"id": "a", "path": ["org.iso.18013.5.1", "family_name"]},
                            {"id": "b", "path": ["org.iso.18013.5.1", "given_name"]},
                            {"id": "c", "path": ["org.iso.18013.5.1", "not_here"]},
                            {"id": "d", "path": ["com.example.wrong.namespace", "also_not_here"]},
                            {"id": "e", "path": ["org.iso.18013.5.1", "birth_date"]}
                        ],
                        "claim_sets": [
                            ["a", "c", "d", "e"],
                            ["a", "b", "e"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], mdoc)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyMDocQueryWithClaimSet_NoClaimSetQueryOptionSatisfiedException() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"id": "a", "path": ["org.iso.18013.5.1", "family_name"]},
                            {"id": "b", "path": ["org.iso.18013.5.1", "given_name"]}
                        ],
                        "claim_sets": [
                            ["a"],
                            ["b"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        val query_with_different_set_option = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"id": "a", "path": ["org.iso.18013.5.1", "family_name"]},
                            {"id": "b", "path": ["org.iso.18013.5.1", "given_name"]}
                        ],
                        "claim_sets": [
                            ["a", "b"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<NoClaimSetQueryOptionSatisfiedException> {
            verify(query_with_different_set_option, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyMDocQueryWithoutClaims() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc"
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], mdoc)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyMDocQueryWithoutClaims_NotAllClaimsProvidedException() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc,
        )

        val query_without_claims = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc"
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<NotAllClaimsProvidedException> {
            verify(query_without_claims, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyMDocQueryWithMeta() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "com.example.doctype.test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "meta": {
                            "doctype_value": "com.example.doctype.test"
                        },
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyMDocQueryWithMeta_InvalidDocTypeException() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "com.example.doctype.test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "meta": {
                            "doctype_value": "com.example.doctype.another-test"
                        },
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            mdoc
        )

        assertFailsWith<InvalidDocTypeException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyMDocSetQuery() {
        val mdoc1 = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to "Jones",
                    "given_name" to "Ava",
                    "birth_date" to "2007-03-25",
                )
            ).toCbor(),
            "com.example.doctype.test"
        )

        val mdoc2 = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "postal_code" to "1234",
                    "locality" to "here",
                    "region" to "Zurich",
                )
            ).toCbor(),
            "com.example.doctype.test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://othercredentials.example/pid"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "family_name"]},
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "birth_date"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "postal_code"]},
                            {"path": ["org.iso.18013.5.1", "locality"]},
                            {"path": ["org.iso.18013.5.1", "region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://company.example/company_rewards"]
                        },
                        "claims": [
                            {"path": ["rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation =
            createPresentation(
                query.credentials!![2],
                mdoc1
            ) + createPresentation(
                query.credentials!![3],
                mdoc2
            )

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyMDocSetQuery_NoCredentialSetQueryOptionSatisfiedException() {
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "rewards_number" to "123-123-123"
                )
            ).toCbor(),
            "com.example.doctype.test"
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://othercredentials.example/pid"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                        },
                        "claims": [
                            {"path": ["family_name"]},
                            {"path": ["given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://cred.example/residence_credential"]
                        },
                        "claims": [
                            {"path": ["postal_code"]},
                            {"path": ["locality"]},
                            {"path": ["region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![4],
            mdoc
        )

        assertFailsWith<NoCredentialSetQueryOptionSatisfiedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    /////////////// W3C ////////////////

    @Test
    fun testVerifyW3CQueryWithClaims() {
        val w3c = createW3C(
            """
                {
                    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                    "type": [
                        "VerifiableCredential",
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                    ],
                    "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "credentialSubject": {
                        "given_name": "John",
                        "family_name": "Doe",
                        "address": {
                            "street_address": "Teststr. 1"
                        }
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], w3c)

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf("pid" to mapOf("type" to "w3c", "content" to dcqlPresentation["pid"] as String))
        )
    }

    @Test
    fun testVerifyW3CQueryWithClaims_ClaimHasNoValueException() {
        val w3c = createW3C(
            """
                {
                    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                    "type": [
                        "VerifiableCredential",
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                    ],
                    "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "credentialSubject": {
                        "given_name": "John",
                        "family_name": "Doe",
                        "address": {
                            "street_address": "Teststr. 1"
                        }
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            w3c,
            disclosures = listOf(
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        assertFailsWith<ClaimHasNoValueException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyW3CQueryWithClaims_ClaimValueNotAllowed() {
        val w3c = createW3C(
            """
                {
                    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                    "type": [
                        "VerifiableCredential",
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                    ],
                    "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "credentialSubject": {
                        "given_name": "John",
                        "family_name": "Doe",
                        "address": {
                            "street_address": "Teststr. 1"
                        }
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            w3c
        )


        val query_with_value_restriction = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"], "values": ["test"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        assertFailsWith<ClaimValueNotAllowed> {
            verify(query_with_value_restriction, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyW3CQueryWithClaimSet() {
        val w3c = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://credentials.example.com/identity_credential"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "postal_code": "1234",
                    "last_name": "Doe",
                    "date_of_birth": "2000-01-01"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "postal_code"),
                listOf("credentialSubject", "last_name"),
                listOf("credentialSubject", "date_of_birth"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"id": "a", "path": ["credentialSubject", "last_name"]},
                            {"id": "b", "path": ["credentialSubject", "postal_code"]},
                            {"id": "c", "path": ["credentialSubject", "locality"]},
                            {"id": "d", "path": ["credentialSubject", "region"]},
                            {"id": "e", "path": ["credentialSubject", "date_of_birth"]}
                        ],
                        "claim_sets": [
                            ["a", "c", "d", "e"],
                            ["a", "b", "e"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], w3c)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyW3CQueryWithClaimSet_NoClaimSetQueryOptionSatisfiedException() {
        val w3c = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://credentials.example.com/identity_credential"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "postal_code": "1234",
                    "last_name": "Doe",
                    "date_of_birth": "2000-01-01"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "postal_code"),
                listOf("credentialSubject", "last_name"),
                listOf("credentialSubject", "date_of_birth"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"id": "a", "path": ["credentialSubject", "last_name"]},
                            {"id": "b", "path": ["credentialSubject", "postal_code"]},
                            {"id": "c", "path": ["credentialSubject", "locality"]},
                            {"id": "d", "path": ["credentialSubject", "region"]},
                            {"id": "e", "path": ["credentialSubject", "date_of_birth"]}
                        ],
                        "claim_sets": [
                            ["a", "c", "d", "e"],
                            ["a", "b", "c"]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            w3c
        )

        assertFailsWith<NoClaimSetQueryOptionSatisfiedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyW3CQueryWithoutClaims() {
        val w3c = createW3C(
            """
                {
                    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                    "type": [
                        "VerifiableCredential",
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                    ],
                    "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "credentialSubject": {
                        "given_name": "John",
                        "family_name": "Doe",
                        "address": {
                            "street_address": "Teststr. 1"
                        }
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], w3c)

        assertTrue(
            verify(query, dcqlPresentation).isSuccess
        )
    }

    @Test
    fun testVerifyW3CQueryWithoutClaims_NotAllClaimsProvidedException() {
        val w3c = createW3C(
            """
                {
                    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                    "type": [
                        "VerifiableCredential",
                        "https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4"
                    ],
                    "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                    "credentialSubject": {
                        "given_name": "John",
                        "family_name": "Doe",
                        "address": {
                            "street_address": "Teststr. 1"
                        }
                    }
                }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            )
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![0],
            w3c,
            disclosures = listOf(
                listOf("credentialSubject", "given_name"),
            )
        )

        assertFailsWith<NotAllClaimsProvidedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }

    @Test
    fun testVerifyW3CSetQuery() {
        val w3c = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://credentials.example.com/reduced_identity_credential"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "address": {
                        "street_address": "Teststr. 1"
                    }
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            ),
        )
        val w3c2 = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://cred.example/residence_credential"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "postal_code": "1234",
                    "locality": "here",
                    "region": "Zurich"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "postal_code"),
                listOf("credentialSubject", "locality"),
                listOf("credentialSubject", "region"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "postal_code"]},
                            {"path": ["credentialSubject", "locality"]},
                            {"path": ["credentialSubject", "region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation =
            createPresentation(
                query.credentials!![2],
                w3c
            ) + createPresentation(
                query.credentials[3],
                w3c2
            )

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf(
                "pid_reduced_cred_1" to mapOf(
                    "type" to "w3c",
                    "content" to dcqlPresentation["pid_reduced_cred_1"] as String
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to "w3c",
                    "content" to dcqlPresentation["pid_reduced_cred_2"] as String
                ),
            )
        )
    }

    @Test
    fun testVerifyW3CSetQuery_NoCredentialSetQueryOptionSatisfiedException() {
        val w3c = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://credentials.example.com/reduced_identity_credential"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "address": {
                        "street_address": "Teststr. 1"
                    }
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "given_name"),
                listOf("credentialSubject", "family_name"),
                listOf("credentialSubject", "address", "street_address"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "given_name"]},
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "family_name"]},
                            {"path": ["credentialSubject", "given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "postal_code"]},
                            {"path": ["credentialSubject", "locality"]},
                            {"path": ["credentialSubject", "region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "rewards_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(
            query.credentials!![2],
            w3c
        )

        assertFailsWith<NoCredentialSetQueryOptionSatisfiedException> {
            verify(query, dcqlPresentation).getOrThrow()
        }
    }


    /////////////// MIXED ////////////////

    @Test
    fun testVerifySetQueryMixed() {
        val sdJwt = createSdJwk(
            """
            {
                "vct": "https://credentials.example.com/reduced_identity_credential",
                "iss": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "given_name": "John",
                "family_name": "Doe",
                "address": {
                    "street_address": "Teststr. 1"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("given_name"),
                listOf("family_name"),
                listOf("address", "street_address"),
            ),
        )
        val mdoc = createMDoc(
            mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "rewards_number" to "123-123-123"
                )
            ).toCbor(),
            "com.example.doctype.test"
        )
        val w3c = createW3C(
            """
            {
                "@context": [ "https://www.w3.org/ns/credentials/v2" ],
                "type": [
                    "VerifiableCredential",
                    "https://credentials.example.com/PizzaCustomer"
                ],
                "issuer": "https://sprind-eudi-issuer-ws-dev.ubique.ch",
                "credentialSubject": {
                    "customer_number": "123-333-456-77"
                }
            }
            """.trimIndent(),
            listOf(
                listOf("credentialSubject", "customer_number"),
            ),
        )

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://othercredentials.example/pid"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                        },
                        "claims": [
                            {"path": ["family_name"]},
                            {"path": ["given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "rewards_number"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://company.example/company_rewards"]
                        },
                        "claims": [
                            {"path": ["rewards_number"]}
                        ]
                    },
                    {
                        "id": "pizza_customer",
                        "format": "vc+sd-jwt",
                        "claims": [
                            {"path": ["credentialSubject", "customer_number"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "purpose": "Identification",
                        "options": [
                            [ "pid" ],
                            [ "other_pid" ],
                            [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                        ]
                    },
                    {
                        "purpose": "Show your rewards card",
                        "required": false,
                        "options": [
                            [ "nice_to_have" ]
                        ]
                    },
                    {
                        "purpose": "Pizza",
                        "options": [
                            [ "pizza_customer" ]
                        ],
                        "required": true
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation =
            createPresentation(
                query.credentials!![2],
                sdJwt
            ) + createPresentation(
                query.credentials[3],
                mdoc
            ) + createPresentation(
                query.credentials[5],
                w3c
            )

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf(
                "pid_reduced_cred_1" to mapOf(
                    "type" to "sdjwt",
                    "content" to dcqlPresentation["pid_reduced_cred_1"] as String
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to "mdoc",
                    "content" to dcqlPresentation["pid_reduced_cred_2"] as String
                ),
                "pizza_customer" to mapOf(
                    "type" to "w3c",
                    "content" to dcqlPresentation["pizza_customer"] as String
                )
            )
        )
    }

}
