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

import ch.ubique.heidi.credentials.ClaimsPointer
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.util.extensions.*
import ch.ubique.heidi.credentials.get
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.dcql.checkDcqlPresentation
import ch.ubique.heidi.dcql.getVpToken
import ch.ubique.heidi.dcql.trustedAuthority.DidAuthorityMatcher
import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.registerMatcher
import uniffi.heidi_util_rust.Value
import uniffi.heidi_dcql_rust.selectCredentials
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class TestDcql {
    class TestSigner(private val kp : SoftwareKeyPair) : SignatureCreator {
        override fun alg(): String {
            return "ES256"
        }

        override fun sign(bytes: ByteArray): ByteArray {
            return kp.signWithKey(bytes)
        }
    }

    val privateKeySignature = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"8hL67MEiG_Fi0R0w3ZuLVEy3iQRaqpQHVJDu5FxqvEA\",\"y\":\"l16hzZH8v5HZrk15FVxjd4naGaKQTgVTg0lfWH1-rXw\",\"d\":\"upRQppmj4FakCuueGQFOWVfLJ-5MgmgJ_bWoI57FsbY\"}"
    val privateKeyKeyBinding = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"r6H1rd3ykIZdKptSUYevNLOogOnfNPj00mqTlkiWt3w\",\"y\":\"zIvMTH70o0Mg5-ApGVwUzMQgWkKlCxVdzU6iFd-T_r0\",\"d\":\"bk3qorDnP1kXussdVqu9Nszq90Hrm8hmsMEOPN-LKJU\"}"
    val uniQuery = " {\n" +
            "    \"credentials\" : [\n" +
            "        {\n" +
            "            \"id\" : \"confirmation-of-matriculation\",\n" +
            "            \"format\" :  \"dc+sd-jwt\",\n" +
            "            \"trusted_authorities\" : [{" +
            "              \"type\" : \"did\"," +
            "               \"values\" : [\"did:example\"] " +
            "            }]," +
            "            \"meta\" : {\n" +
            "                \"vct_values\" : [\"https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4\"]\n" +
            "            },\n" +
            "            \"claims\" : [\n" +
            "                 {\n" +
            "                    \"path\" : [\"unv\", \"enrolledAt\"],\n" +
            "                    \"values\" : [\"Universität Musterstadt\"]\n" +
            "                },\n" +
            "                {\n" +
            "                    \"path\" : [\"unv\", \"subjects\", 0, \"major\"],\n" +
            "                    \"values\" : [true]\n" +
            "                },\n" +
            "                {\n" +
            "                    \"path\" : [\"unv\", \"subjects\", 0, \"currentEcts\"]\n" +
            "                }\n" +
            "            ]\n" +
            "        }\n" +
            "    ]\n" +
            " }"
    val matrikulationsBstMusterstadt = "{\n" +
            "  \"vct\": \"https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4\",\n" +
            "  \"iss\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch\",\n" +
            "  \"render\": {\n" +
            "    \"type\": \"OverlaysCaptureBundleV1\",\n" +
            "    \"oca\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch/oca/IAJSyv3uxGsR98qGGLnrEHTN20Z4okSgV1l5qQoBw3yK7.json\"\n" +
            "  },\n" +
            "  \"unv\" : {\n" +
            "    \"matriculationNr\": \"01/7654321\",\n" +
            "    \"enrolledAt\": \"<<UNIVERSITY>>\",\n" +
            "    \"subjects\" : <<SUBJECTS>>\n" +
            "  },\n" +
            "  \"roles\" : [\n" +
            "        \"Student\"\n" +
            "  ]\n" +
            "}\n"
    val subjects1 = "[\n" +
            "        { \n" +
            "            \"title\" : \"Computer Science\",\n" +
            "            \"major\" : true,\n" +
            "            \"currentEcts\" : 42,\n" +
            "            \"neededEcts\" : 120\n" +
            "        },\n" +
            "        {\n" +
            "        \"title\": \"Philosophy\",\n" +
            "        \"major\": false,\n" +
            "        \"currentEcts\": 12,\n" +
            "        \"neededEcts\": 60\n" +
            "        }\n" +
            "    ]"

    val rolesJson = "{\n" +
            "  \"vct\": \"testArray\",\n" +
            "  \"iss\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch\",\n" +
            "  \"render\": {\n" +
            "    \"type\": \"OverlaysCaptureBundleV1\",\n" +
            "    \"oca\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch/oca/IAJSyv3uxGsR98qGGLnrEHTN20Z4okSgV1l5qQoBw3yK7.json\"\n" +
            "  },\n" +
            "  \"roles\" : [\n" +
            "        {\n" +
            "            \"name\" : \"Role1\",\n" +
            "            \"parentRoles\" : [\n" +
            "                { \n" +
            "                    \"name\" : \"Role2\"\n" +
            "                }\n" +
            "            ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"Role3\"\n" +
            "        }\n" +
            "  ]\n" +
            "}"
    val rolesJson2 = "{\n" +
            "  \"vct\": \"testArray\",\n" +
            "  \"iss\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch\",\n" +
            "  \"render\": {\n" +
            "    \"type\": \"OverlaysCaptureBundleV1\",\n" +
            "    \"oca\": \"https://sprind-eudi-issuer-ws-dev.ubique.ch/oca/IAJSyv3uxGsR98qGGLnrEHTN20Z4okSgV1l5qQoBw3yK7.json\"\n" +
            "  },\n" +
            "  \"roles\" : [\n" +
            "        {\n" +
            "            \"name\" : \"Role1\",\n" +
            "            \"parentRoles\" : [\n" +
            "                { \n" +
            "                    \"name\" : \"Role2\"\n" +
            "                }\n" +
            "            ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"name\": \"Role3\",\n" +
            "            \"parentRoles\" : [\n" +
            "                { \n" +
            "                    \"name\" : \"Role1\"\n" +
            "                }\n" +
            "            ]\n" +
            "        }\n" +
            "  ]\n" +
            "}"
    val rolesQueryParentRoles = " {\n" +
            "    \"credentials\" : [\n" +
            "        {\n" +
            "            \"id\" : \"test-parent-role\",\n" +
            "            \"format\" :  \"dc+sd-jwt\",\n" +
            "            \"meta\" : {\n" +
            "                \"vct_values\" : [\"https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4\", \"testArray\"]\n" +
            "            },\n" +
            "            \"claims\" : [\n" +
            "                 {\n" +
            "                    \"path\" : [\"roles\", 0, \"parentRoles\", null, \"name\"],\n" +
            "                    \"values\" : [  \"Role2\" ]\n" +
            "                }\n" +
            "            ]\n" +
            "        }\n" +
            "    ]\n" +
            " }"
    val rolesQueryParentRoles2 = " {\n" +
            "    \"credentials\" : [\n" +
            "        {\n" +
            "            \"id\" : \"test-parent-role\",\n" +
            "            \"format\" :  \"dc+sd-jwt\",\n" +
            "            \"meta\" : {\n" +
            "                \"vct_values\" : [\"https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4\", \"testArray\"]\n" +
            "            },\n" +
            "            \"claims\" : [\n" +
            "                 {\n" +
            "                    \"path\" : [\"roles\", null, \"parentRoles\", null, \"name\"],\n" +
            "                    \"values\" : [  \"Role2\", \"Role1\" ]\n" +
            "                }\n" +
            "            ]\n" +
            "        }\n" +
            "    ]\n" +
            " }"
    val rolesQueryAllNames = " {\n" +
            "    \"credentials\" : [\n" +
            "        {\n" +
            "            \"id\" : \"test-parent-role\",\n" +
            "            \"format\" :  \"dc+sd-jwt\",\n" +
            "            \"meta\" : {\n" +
            "                \"vct_values\" : [\"https://dev-ssi-schema-creator-ws.ubique.ch/v1/schema/matrikulations-bst/0.0.4\", \"testArray\"]\n" +
            "            },\n" +
            "            \"claims\" : [\n" +
            "                 {\n" +
            "                    \"path\" : [\"roles\", null, \"name\"],\n" +
            "                    \"values\" : [  \"Role1\", \"Role3\" ]\n" +
            "                }\n" +
            "            ]\n" +
            "        }\n" +
            "    ]\n" +
            " }"
    fun createMusterMatriculationConf(university: String, subjects: Value) : Value {
        val payload = matrikulationsBstMusterstadt.replace("<<UNIVERSITY>>", university).replace("<<SUBJECTS>>", Json.encodeToString(Value.serializer() ,subjects))
        return Json.decodeFromString<Value>(payload)
    }
    @Test
    fun createAKey() {
        val jwk = SoftwareKeyPair().privateJwkString()
        println(jwk)
    }

    @Test
    fun immatrikulationsBst() {
        val claims1: Value = createMusterMatriculationConf("Universität Musterstadt", Json.decodeFromString(subjects1))
        val claims2: Value = createMusterMatriculationConf("Universität Musterwil", Json.decodeFromString(subjects1))
        val disclosures : List<ClaimsPointer> = listOf(
            listOf("unv", "matriculationNr").toClaimsPointer()!!,
            listOf("unv", "enrolledAt").toClaimsPointer()!!,
            listOf("unv", "subjects", null).toClaimsPointer()!!,
            listOf("unv", "subjects", null, "currentEcts").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
        )
        val sdjwt1 = SdJwt.create(claims1, disclosures, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val sdjwt2 = SdJwt.create(claims2, disclosures, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        assertEquals(sdjwt1.innerJwt.disclosuresMap.size, sdjwt2.innerJwt.disclosuresMap.size)
        assertEquals(sdjwt1.innerJwt.disclosuresMap.size, 7)
        val store = listOf(sdjwt1.innerJwt.originalSdjwt, sdjwt2.innerJwt.originalSdjwt)
        val query: DcqlQuery = Json.decodeFromString(uniQuery)
        // this should register the did matcher
        val didMatcher = DidAuthorityMatcher()
        val results = selectCredentials(query, store)[0].setOptions[0][0]
        assertEquals(results.options.size, 1)
        assertEquals(results.id, "confirmation-of-matriculation")
        val selectedCredential = results.options[0].credential
        assertIs<Credential.SdJwtCredential>(selectedCredential)

        val enrolledAt = selectedCredential.v1.claims[listOf("unv", "enrolledAt").toClaimsPointer()!!][0].asString()!!
        assertEquals(enrolledAt, "Universität Musterstadt")
        val respectiveQuery = query.credentials!!.first { it.id == results.id }
        val vpToken = SdJwt(selectedCredential.v1).getVpToken(respectiveQuery,"test", null, null, "1234", TestSigner(
            SoftwareKeyPair.fromJwkString(privateKeyKeyBinding))).getOrThrow()

        val parsedVpToken = SdJwt.parse(vpToken)
        assertEquals(parsedVpToken.innerJwt.disclosuresMap.size, 3)
        assertEquals(parsedVpToken.innerJwt.claims[listOf("unv", "enrolledAt").toClaimsPointer()!!][0].asString()!!, "Universität Musterstadt")
        assertEquals(parsedVpToken.innerJwt.claims[listOf("unv", "subjects", 0, "currentEcts").toClaimsPointer()!!][0].asLong()!!, 42)
        assertEquals(parsedVpToken.innerJwt.claims[listOf("unv", "subjects", 1, "title").toClaimsPointer()!!].size, 0)

        val pres = mapOf<String, String>(results.id to vpToken)
        assertTrue(checkDcqlPresentation(query, pres, { _, _, _ -> emptyMap<String, Value>() }).isSuccess)
    }
    @Test
    fun testRolesParentRoles() {
        val claims1: Value = createMusterMatriculationConf("Universität Musterstadt", Json.decodeFromString(subjects1))
        val claims2: Value = createMusterMatriculationConf("Universität Musterwil", Json.decodeFromString(subjects1))
        val disclosureswrong : List<ClaimsPointer> = listOf(
            listOf("unv", "matriculationNr").toClaimsPointer()!!,
            listOf("unv", "enrolledAt").toClaimsPointer()!!,
            listOf("unv", "subjects", null).toClaimsPointer()!!,
            listOf("unv", "subjects", null, "currentEcts").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
        )
        val sdjwt1 = SdJwt.create(claims1, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val sdjwt2 = SdJwt.create(claims2, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        val claims : Value = Json.decodeFromString(rolesJson)
        val claims3 : Value = Json.decodeFromString(rolesJson2)
        val rolesParentRolesQuery : DcqlQuery = Json.decodeFromString(rolesQueryParentRoles)
        val rolesParentRolesQuery2 : DcqlQuery = Json.decodeFromString(rolesQueryParentRoles2)
        val disclosures : List<ClaimsPointer> = listOf(
            listOf("roles").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
            listOf("roles", null, "name").toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null).toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null, "name").toClaimsPointer()!!,
        )
        val rolesSdjwt = SdJwt.create(claims, disclosures, "1234", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val rolesSdjwt2 = SdJwt.create(claims3, disclosures, "1234", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        assertEquals(rolesSdjwt.innerJwt.disclosuresMap.size, 7)
        val sdjwt = SdJwt(rolesSdjwt.innerJwt)
        val result = selectCredentials(rolesParentRolesQuery, listOf(sdjwt.innerJwt.originalSdjwt, sdjwt1.innerJwt.originalSdjwt, sdjwt2.innerJwt.originalSdjwt))
        val result2 = selectCredentials(rolesParentRolesQuery2, listOf(rolesSdjwt2.innerJwt.originalSdjwt, sdjwt1.innerJwt.originalSdjwt, sdjwt2.innerJwt.originalSdjwt))
        val result3 = selectCredentials(rolesParentRolesQuery2, listOf(rolesSdjwt.innerJwt.originalSdjwt, sdjwt1.innerJwt.originalSdjwt, sdjwt2.innerJwt.originalSdjwt))

        assertEquals(1, result.size)
        assertEquals(1, result2.size)
        assertEquals(1, result3.size)
        // we only have one set
        val setOption = result[0].setOptions[0][0]
        assertEquals(setOption.options.size, 1)
        val selectedCredential = setOption.options[0].credential
        assertIs<Credential.SdJwtCredential>(selectedCredential)
        val credentialQuery = rolesParentRolesQuery.credentials!!.first { it.id == setOption.id}
        val vpToken = SdJwt(selectedCredential.v1).getVpToken(credentialQuery, "123", null, null, "123", TestSigner(
            SoftwareKeyPair.fromJwkString(privateKeyKeyBinding))).getOrThrow()

        val parsedVpToken = SdJwt.parse(vpToken)
        val parentRoleNamePointer = listOf("roles", null, "parentRoles", null, "name").toClaimsPointer()!!
        val rolesNamePointer = listOf("roles", null, "name").toClaimsPointer()!!
        assertEquals(parsedVpToken.innerJwt.claims[parentRoleNamePointer].size, 1)
        assertEquals(parsedVpToken.innerJwt.claims[rolesNamePointer].size, 0)
        assertEquals(parsedVpToken.innerJwt.claims[parentRoleNamePointer][0].asString()!!, "Role2")

        val pres = mapOf<String, String>(credentialQuery.id to vpToken)
        assertTrue(checkDcqlPresentation(rolesParentRolesQuery, pres, { _, _, _ -> emptyMap<String, Value>() }).isSuccess)

        assertTrue(checkDcqlPresentation(
            rolesParentRolesQuery2,
            mapOf(credentialQuery.id to SdJwt(
                (result2[0].setOptions[0][0].options[0].credential as Credential.SdJwtCredential).v1
            ).getVpToken(credentialQuery, "123", null, null, "123", TestSigner(
                SoftwareKeyPair.fromJwkString(privateKeyKeyBinding)
            )).getOrThrow()),
            { _, _, _ -> emptyMap<String, Value>() }
        ).isSuccess)
        assertTrue(checkDcqlPresentation(
            rolesParentRolesQuery2,
            mapOf(credentialQuery.id to SdJwt(
                (result3[0].setOptions[0][0].options[0].credential as Credential.SdJwtCredential).v1
            ).getVpToken(credentialQuery, "123", null, null,"123", TestSigner(
                SoftwareKeyPair.fromJwkString(privateKeyKeyBinding)
            )).getOrThrow()),
            { _, _, _ -> emptyMap<String, Value>() }
        ).isSuccess)
    }
    @Test
    fun testRolesAllNamesRoles() {
        val claims1: Value = createMusterMatriculationConf("Universität Musterstadt", Json.decodeFromString(subjects1))
        val claims2: Value = createMusterMatriculationConf("Universität Musterwil", Json.decodeFromString(subjects1))
        val disclosureswrong : List<ClaimsPointer> = listOf(
            listOf("unv", "matriculationNr").toClaimsPointer()!!,
            listOf("unv", "enrolledAt").toClaimsPointer()!!,
            listOf("unv", "subjects", null).toClaimsPointer()!!,
            listOf("unv", "subjects", null, "currentEcts").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
        )
        val sdjwt1 = SdJwt.create(claims1, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val sdjwt2 = SdJwt.create(claims2, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        val claims : Value = Json.decodeFromString(rolesJson)
        val rolesAllNamesQuery : DcqlQuery = Json.decodeFromString(rolesQueryAllNames)
        val disclosures : List<ClaimsPointer> = listOf(
            listOf("roles").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
            listOf("roles", null, "name").toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null).toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null, "name").toClaimsPointer()!!,
        )
        val rolesSdjwt = SdJwt.create(claims, disclosures, "1234", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        assertEquals(rolesSdjwt.innerJwt.disclosuresMap.size, 7)
        val sdjwt = SdJwt(rolesSdjwt.innerJwt)
        val result = selectCredentials(rolesAllNamesQuery, listOf(sdjwt.innerJwt.originalSdjwt, sdjwt1.innerJwt.originalSdjwt, sdjwt2.innerJwt.originalSdjwt))
        assertEquals(1, result.size)
        // we only have one set
        val setOption = result[0].setOptions[0][0]
        assertEquals(setOption.options.size, 1)
        val selectedCredential = setOption.options[0].credential
        assertIs<Credential.SdJwtCredential>(selectedCredential)
        val credentialQuery = rolesAllNamesQuery.credentials!!.first { it.id == setOption.id}
        val vpToken = SdJwt(selectedCredential.v1).getVpToken(credentialQuery, "123", null, null, "123", TestSigner(
            SoftwareKeyPair.fromJwkString(privateKeyKeyBinding))).getOrThrow()

        val parsedVpToken = SdJwt.parse(vpToken)
        val parentRoleNamePointer = listOf("roles", null, "parentRoles", null, "name").toClaimsPointer()!!
        val rolesNamePointer = listOf("roles", null, "name").toClaimsPointer()!!
        assertEquals(parsedVpToken.innerJwt.claims[parentRoleNamePointer].size, 0)
        assertEquals(parsedVpToken.innerJwt.claims[rolesNamePointer].size, 2)
        assertEquals(parsedVpToken.innerJwt.claims[rolesNamePointer][0].asString()!!, "Role1")
        assertEquals(parsedVpToken.innerJwt.claims[rolesNamePointer][1].asString()!!, "Role3")
    }
    @Test
    fun generateTestOutput() {
        val claims1: Value = createMusterMatriculationConf("Universität Musterstadt", Json.decodeFromString(subjects1))
        val claims2: Value = createMusterMatriculationConf("Universität Musterwil", Json.decodeFromString(subjects1))
        val disclosureswrong : List<ClaimsPointer> = listOf(
            listOf("unv", "matriculationNr").toClaimsPointer()!!,
            listOf("unv", "enrolledAt").toClaimsPointer()!!,
            listOf("unv", "subjects", null).toClaimsPointer()!!,
            listOf("unv", "subjects", null, "currentEcts").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
        )
        val sdjwt1 = SdJwt.create(claims1, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val sdjwt2 = SdJwt.create(claims2, disclosureswrong, "123", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        val claims : Value = Json.decodeFromString(rolesJson)
        val claims3 : Value = Json.decodeFromString(rolesJson2)
        val rolesAllNamesQuery : DcqlQuery = Json.decodeFromString(rolesQueryAllNames)
        val disclosures : List<ClaimsPointer> = listOf(
            listOf("roles").toClaimsPointer()!!,
            listOf("roles", null).toClaimsPointer()!!,
            listOf("roles", null, "name").toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null).toClaimsPointer()!!,
            listOf("roles", null, "parentRoles", null, "name").toClaimsPointer()!!,
        )
        val rolesSdjwt = SdJwt.create(claims, disclosures, "1234", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!
        val rolesSdjwt2 = SdJwt.create(claims3, disclosures, "1234", TestSigner(SoftwareKeyPair.fromJwkString(privateKeySignature)), Json.decodeFromString(privateKeyKeyBinding))!!

        println("---")
        println("issuerKey: $privateKeySignature")
        println("kbKey: $privateKeyKeyBinding")
        println("---")
        println("sdjwt1: ${sdjwt1.innerJwt.originalSdjwt}")
        println("sdjwt2: ${sdjwt2.innerJwt.originalSdjwt}")
        println("rolesSdjwt1: ${rolesSdjwt.innerJwt.originalSdjwt}")
        println("rolesSdjwt2: ${rolesSdjwt2.innerJwt.originalSdjwt}")
        println("---")
        println(uniQuery)
        println("Expected: sdjwt1")
        println("Expected Property: [\"unv\", \"enrolledAt\"] == \"Universität Musterstadt\" ")
        println("Expected Property: [\"unv\", \"subjects\", 0, \"currentEcts\"] == 42 ")
        println("Expected Property: [\"unv\", \"subjects\", 1, \"title\"] == UNDEFINED ")
        println("---")
        println(rolesQueryParentRoles)
        println("Expected: rolesSdjwt1")
        println("Expected Property [rolesSdjwt1]: [\"roles\", null, \"parentRoles\", null, \"name\"] == \"Role2\"")
        println("---")
        println(rolesQueryParentRoles2)
        println("Expected: rolesSdjwt2")
        println("Expected Property: [\"roles\", null, \"parentRoles\", null, \"name\"] == [\"Role2\", \"Role1\"]")
        println("---")
        println(rolesQueryAllNames)
        println("Expected: rolesSdjwt1, rolesSdjwt2")
        println("Expected Property [rolesSdjwt1]: [\"roles\", null, \"name\"] == \"Role1\"")
        println("Expected Property [rolesSdjwt2]: [\"roles\", null, \"name\"] == \"Role3\"")
        println("---")
    }
}
