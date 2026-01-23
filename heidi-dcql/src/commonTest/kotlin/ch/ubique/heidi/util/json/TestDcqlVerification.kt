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
import kotlinx.coroutines.runBlocking
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
import kotlin.io.encoding.Base64
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
                CredentialType.SdJwt -> mapOf(
                    "type" to Value.String("sdjwt"),
                    "content" to Value.String(vpToken)
                )
                CredentialType.Mdoc -> mapOf(
                    "type" to Value.String("mdoc"),
                    "content" to Value.String(vpToken)
                )
                CredentialType.BbsTermwise -> mapOf(
                    "type" to Value.String("bbs-termwise"),
                    "content" to Value.String(vpToken)
                )
                CredentialType.W3C_VCDM -> mapOf(
                    "type" to Value.String("w3c"),
                    "content" to Value.String(vpToken)
                )
                CredentialType.OpenBadge303 -> mapOf(
                    "type" to Value.String("ldp_vc"),
                    "content" to Value.String(vpToken)
                )
                else -> emptyMap<String, Value>()
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

    private fun createPresentation(
        query: CredentialQuery,
        credential: W3C.OpenBadge303,
    ): DcqlPresentation = mapOf(
        query.id to credential.asVerifiablePresentation().getOrThrow()
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
            mapOf("pid" to mapOf(
                "type" to Value.String("sdjwt"),
                "content" to Value.String(dcqlPresentation["pid"] as String)
            ))
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
                    "type" to Value.String("sdjwt"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_1"] as String)
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to Value.String("sdjwt"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_2"] as String)
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
            mapOf("pid" to mapOf(
                "type" to Value.String("w3c"),
                "content" to Value.String(dcqlPresentation["pid"] as String)
            ))
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

    // NOTE: Disabled as counting the original number of claims does not work properly.
    // @Test
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
                    "type" to Value.String("w3c"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_1"] as String)
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to Value.String("w3c"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_2"] as String)
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

    /////////// OPEN BADGES //////////////

    @Test
    fun testOpenBadgeVerification() = runBlocking {
        val credential = W3C.OpenBadge303.parse(Base64.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAlgAAAJYCAYAAAC+ZpjcAAALj2lUWHRvcGVuYmFkZ2VzAAAAAAB7CiAgIkBjb250ZXh0IjogWwogICAgImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsCiAgICAiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9vYi92M3AwL2NvbnRleHQtMy4wLjMuanNvbiIsCiAgICAiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9vYi92M3AwL2V4dGVuc2lvbnMuanNvbiIKICBdLAogICJpZCI6ICJodHRwczovL2FwaS5vcGVuYmFkZ2VzLmVkdWNhdGlvbi9wdWJsaWMvYXNzZXJ0aW9ucy9Ed3dXTm5Zb1E5YWlCam5QTWhQY3hRP3Y9M18wIiwKICAidHlwZSI6IFsKICAgICJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsCiAgICAiT3BlbkJhZGdlQ3JlZGVudGlhbCIKICBdLAogICJuYW1lIjogIkFJIEFjdCIsCiAgImV2aWRlbmNlIjogW10sCiAgImlzc3VlciI6IHsKICAgICJpZCI6ICJodHRwczovL2FwaS5vcGVuYmFkZ2VzLmVkdWNhdGlvbi9wdWJsaWMvaXNzdWVycy9oNlZDamJSQlI3ZUMyMmp3VXo0NUpBP3Y9M18wIiwKICAgICJ0eXBlIjogWwogICAgICAiUHJvZmlsZSIKICAgIF0sCiAgICAibmFtZSI6ICJPcGVuIEVkdWNhdGlvbmFsIEJhZGdlcyIsCiAgICAidXJsIjogImh0dHBzOi8vb3BlbmJhZGdlcy5lZHVjYXRpb24iLAogICAgImVtYWlsIjogImFubmlrYUBteWNlbGlhLmVkdWNhdGlvbiIKICB9LAogICJ2YWxpZEZyb20iOiAiMjAyNS0xMi0wNFQwODozNzo0MC4zNzkyMTMrMDA6MDAiLAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJ0eXBlIjogWwogICAgICAiQWNoaWV2ZW1lbnRTdWJqZWN0IgogICAgXSwKICAgICJpZGVudGlmaWVyIjogWwogICAgICB7CiAgICAgICAgInR5cGUiOiAiSWRlbnRpdHlPYmplY3QiLAogICAgICAgICJpZGVudGl0eUhhc2giOiAic2hhMjU2JDc5YTEyZjY4OGUxYmQzNWY4NWFkNGVlMWM3MWI1ZDdjOTQyZWEyODlhZWNmNjE2MTU5YTIwZGMwZDVhZjI0MTkiLAogICAgICAgICJpZGVudGl0eVR5cGUiOiAiZW1haWxBZGRyZXNzIiwKICAgICAgICAiaGFzaGVkIjogdHJ1ZSwKICAgICAgICAic2FsdCI6ICI2ODAwYjI1MmRmNzQ0ZTQ3YjlkOTgzNzM3MWExNjE4YSIKICAgICAgfQogICAgXSwKICAgICJhY2hpZXZlbWVudCI6IHsKICAgICAgImlkIjogImh0dHBzOi8vYXBpLm9wZW5iYWRnZXMuZWR1Y2F0aW9uL3B1YmxpYy9iYWRnZXMvMWw1eV8yMlBTYXVWaExZaWhvcW1Wdz92PTNfMCIsCiAgICAgICJ0eXBlIjogWwogICAgICAgICJBY2hpZXZlbWVudCIKICAgICAgXSwKICAgICAgIm5hbWUiOiAiQUkgQWN0IiwKICAgICAgImRlc2NyaXB0aW9uIjogIkRpZXNlciBXb3Jrc2hvcCBiaWV0ZXQgZWluZSBzb2xpZGUgRWluZlx1MDBmY2hydW5nIGluIEtJIG1pdCBiZXNvbmRlcmVtIFNjaHdlcnB1bmt0IGF1ZiBkZW0gR3J1bmRsYWdlbndpc3NlbiwgZGFzIGZcdTAwZmNyIGVpbmVuIHZlcmFudHdvcnR1bmdzdm9sbGVuIFVtZ2FuZyBtaXQgS0kgZXJmb3JkZXJsaWNoIGlzdCAtIGltIEVpbmtsYW5nIG1pdCBkZW4gQW5mb3JkZXJ1bmdlbiBkZXMgRVUtQUktQWN0LiBEaWUgVGVpbG5laG1lbmRlbiBlcmhhbHRlbiBFaW5ibGlja2UgaW4gZGllIEZ1bmt0aW9uc3dlaXNlIHZvbiBLSS1TeXN0ZW1lbiwgd28gaWhyZSBHcmVuemVuIHVuZCBSaXNpa2VuIGxpZWdlbiB1bmQgd2FzIGVpbmUgdmVyYW50d29ydHVuZ3N2b2xsZSBOdXR6dW5nIGluIGRlciBQcmF4aXMgYmVkZXV0ZXQuIE1pdCBlaW5lciBNaXNjaHVuZyBhdXMgaW50ZXJha3RpdmVtIElucHV0IHVuZCBwcmFrdGlzY2hlciBSZWZsZXhpb24gc3RcdTAwZTRya3QgZGFzIFRyYWluaW5nIGRhcyBWZXJ0cmF1ZW4gdW5kIGRhcyBCZXd1c3N0c2VpbiBmXHUwMGZjciBkZW4gVW1nYW5nIG1pdCBkZXIgc2ljaCBlbnR3aWNrZWxuZGVuIEtJLUxhbmRzY2hhZnQgdW5kIGdpYnQgcmVjaHRsaWNoZSBHcnVuZGxhZ2VuLiIsCiAgICAgICJhY2hpZXZlbWVudFR5cGUiOiAiQmFkZ2UiLAogICAgICAiY3JpdGVyaWEiOiB7CiAgICAgICAgIm5hcnJhdGl2ZSI6ICIiCiAgICAgIH0sCiAgICAgICJpbWFnZSI6IHsKICAgICAgICAiaWQiOiAiaHR0cHM6Ly9hcGkub3BlbmJhZGdlcy5lZHVjYXRpb24vcHVibGljL2Fzc2VydGlvbnMvRHd3V05uWW9ROWFpQmpuUE1oUGN4US9pbWFnZSIsCiAgICAgICAgInR5cGUiOiAiSW1hZ2UiCiAgICAgIH0KICAgIH0sCiAgICAiYWN0aXZpdHlTdGFydERhdGUiOiAiMjAyNS0xMi0wNFQwMDowMDowMCswMDowMCIsCiAgICAiYWN0aXZpdHlMb2NhdGlvbiI6IHsKICAgICAgInR5cGUiOiBbCiAgICAgICAgIkFkZHJlc3MiCiAgICAgIF0sCiAgICAgICJhZGRyZXNzTG9jYWxpdHkiOiAiWlx1MDBmY3JpY2giLAogICAgICAicG9zdGFsQ29kZSI6ICI4MDAxIgogICAgfQogIH0sCiAgImNyZWRlbnRpYWxTdGF0dXMiOiB7CiAgICAiaWQiOiAiaHR0cHM6Ly9hcGkub3BlbmJhZGdlcy5lZHVjYXRpb24vcHVibGljL2Fzc2VydGlvbnMvRHd3V05uWW9ROWFpQmpuUE1oUGN4US9yZXZvY2F0aW9ucyIsCiAgICAidHlwZSI6ICIxRWRUZWNoUmV2b2NhdGlvbkxpc3QiCiAgfSwKICAicHJvb2YiOiBbCiAgICB7CiAgICAgICJ0eXBlIjogIkRhdGFJbnRlZ3JpdHlQcm9vZiIsCiAgICAgICJjcnlwdG9zdWl0ZSI6ICJlZGRzYS1yZGZjLTIwMjIiLAogICAgICAiY3JlYXRlZCI6ICIyMDI1LTEyLTA0VDA4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"
        ))

        val query = parseDcqlQuery(
            """
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "ldp_vc",
                        "claims": [
                            {"path": ["credentialSubject", "achievement", "name"]},
                            {"path": ["credentialSubject", "achievement", "achievementType"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
        )

        val dcqlPresentation = createPresentation(query.credentials!![0], credential)

        assertEquals(
            verify(query, dcqlPresentation).getOrThrow(),
            mapOf("pid" to mapOf(
                "type" to Value.String("ldp_vc"),
                "content" to Value.String(dcqlPresentation["pid"] as String))
            )
        )
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
                    "type" to Value.String("sdjwt"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_1"] as String)
                ),
                "pid_reduced_cred_2" to mapOf(
                    "type" to Value.String("mdoc"),
                    "content" to Value.String(dcqlPresentation["pid_reduced_cred_2"] as String)
                ),
                "pizza_customer" to mapOf(
                    "type" to Value.String("w3c"),
                    "content" to Value.String(dcqlPresentation["pizza_customer"] as String)
                )
            )
        )
    }
}
