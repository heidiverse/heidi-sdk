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
import ch.ubique.heidi.credentials.asSelector
import ch.ubique.heidi.credentials.get

import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asLong
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asString
import kotlinx.serialization.json.Json
import okio.internal.commonToUtf8String
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_credentials_rust.BuilderException

import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_util_rust.Value
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

import ch.ubique.heidi.util.extensions.*
import kotlin.test.assertFailsWith


class SdJwtTests {
    @Test
    fun recursiveDisclosure() {
        val jwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.qsI0EJs0DdWOwWjl4acRpVISStrvl1mwrumox26e-hRVtoEPy520qw1QX5pMdcZ0rKrpAuWJW0RRmKueQwaK5Q~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
        val sdjwt = SdJwt.parse(jwt)
        val allNationalities = listOf(PointerPart.String("nationalities"),PointerPart.Null(false))
        val presentation = sdjwt.presentation()
        presentation.addDisclosure(allNationalities)
    }
    @Test
    fun testError() {
        val jwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.qsI0EJs0DdWOwWjl4acRpVISStrvl1mwrumox26e-hRVtoEPy520qw1QX5pMdcZ0rKrpAuWJW0RRmKueQwaK5Q~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
        val sdjwt = SdJwt.parse(jwt)
        val p = sdjwt.presentation()
        assertFailsWith(BuilderException.InvalidPath::class) {
            p.addDisclosure(listOf(PointerPart.String("irgend"), PointerPart.String("en"), PointerPart.String("gugus")))
        }
    }
    @Test
    fun testCommitments() {
        val jsonString = "{" +
                "\"dob\" : 1958,\n" +
                "\"test\" : \"terstValue\"\n" +
                "}"
        val claims : Value = Json.decodeFromString(jsonString)
        val o = claims.asObject()!!
        val disclosures = mutableListOf<ClaimsPointer>()
        val alwaysVisible = listOf("sub", "iss", "exp", "cnf", "updated_at")
        for(k in o) {
            if(k.key in alwaysVisible) {
                continue
            }
            disclosures.add(listOf(k.key).toClaimsPointer()!!)
        }
        val kb = SoftwareKeyPair()
        val kbValue : Value = Json.decodeFromString(kb.jwkString())
        val sdjwt = SdJwt.create(claims, disclosures, "123", TestSigner(SoftwareKeyPair()), kbValue, "ec_pedersen")!!
        val sd = sdjwt.get("_sd".asSelector())[0]
    }
    @Test
    // Issuance following https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html#name-example-sd-jwt
    fun testIssuance() {
        val jsonString = "{\n" +
                "  \"sub\": \"user_42\",\n" +
                "  \"given_name\": \"John\",\n" +
                "  \"family_name\": \"Doe\",\n" +
                "  \"email\": \"johndoe@example.com\",\n" +
                "  \"phone_number\": \"+1-202-555-0101\",\n" +
                "  \"phone_number_verified\": true,\n" +
                "  \"address\": {\n" +
                "    \"street_address\": \"123 Main St\",\n" +
                "    \"locality\": \"Anytown\",\n" +
                "    \"region\": \"Anystate\",\n" +
                "    \"country\": \"US\"\n" +
                "  },\n" +
                "  \"birthdate\": \"1940-01-01\",\n" +
                "  \"updated_at\": 1570000000,\n" +
                "  \"nationalities\": [\n" +
                "    \"US\",\n" +
                "    \"DE\"\n" +
                "  ]\n" +
                "}\n"
        val claims : Value = Json.decodeFromString(jsonString)
        val o = claims.asObject()!!
        val disclosures = mutableListOf<ClaimsPointer>()
        val alwaysVisible = listOf("sub", "iss", "exp", "cnf", "updated_at")
        for(k in o) {
            if(k.key == "nationalities") {
                disclosures.add(listOf("nationalities", null).toClaimsPointer()!!)
            }
            if(k.key in alwaysVisible) {
                continue
            }
            disclosures.add(listOf(k.key).toClaimsPointer()!!)
        }
        val kb = SoftwareKeyPair()
        val kbValue : Value = Json.decodeFromString(kb.jwkString())
        val sdjwt = SdJwt.create(claims, disclosures, "123", TestSigner(SoftwareKeyPair()), kbValue, "ec_pedersen")!!
        val sd = sdjwt.get("_sd".asSelector())[0]
        val nationalities = sdjwt.get("nationalities".asSelector())[0]
        assertIs<Value.Array>(sd)
        assertIs<Value.Array>(nationalities)
        assertEquals(8, sd.v1.size)
        assertEquals("US", nationalities.v1[0].asString())
        assertEquals("DE", nationalities.v1[1].asString())
        val claimsString = base64UrlDecode(sdjwt.innerJwt.originalJwt.split(".")[1]).commonToUtf8String()
        val jwt : Value = Json.decodeFromString(claimsString)

        for(e in jwt["nationalities"].asArray()!!) {
            assertTrue(e.isObject())
            assertTrue(e.asObject()!!.containsKey("..."))
        }
        val newParsed : Value = Json.decodeFromString(jsonString)
        for(o in newParsed.asObject()!!) {
            val e = sdjwt.get(o.key.asSelector())[0]
            assertEquals(e, o.value)
        }
    }
    @Test
    // https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html#name-considerations-on-nested-da
    fun testNestedObjects() {
        val kb = SoftwareKeyPair()
        val kbValue : Value = Json.decodeFromString(kb.jwkString())
        val jsonString = "{\n" +
                "  \"sub\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\",\n" +
                "  \"address\": {\n" +
                "    \"street_address\": \"Schulstr. 12\",\n" +
                "    \"locality\": \"Schulpforta\",\n" +
                "    \"region\": \"Sachsen-Anhalt\",\n" +
                "    \"country\": \"DE\"\n" +
                "  }\n" +
                "}"
        val claims : Value = Json.decodeFromString(jsonString)

        // Flat SD-JWT https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html#name-example-flat-sd-jwt
        val flatSdJwt = SdJwt.create(claims, listOf(listOf("address").toClaimsPointer()!!), "123", TestSigner(
            SoftwareKeyPair()), kbValue)!!
        assertEquals(1, flatSdJwt.get("_sd".asSelector())[0].asArray()!!.size)
        assertEquals(1, flatSdJwt.innerJwt.disclosuresMap.size)
        // Structured SD-JWT
        val disclosuresStructured = listOf(listOf("address","street_address").toClaimsPointer()!!, listOf("address","locality").toClaimsPointer()!!, listOf("address","region").toClaimsPointer()!!)
        val structuredSdJwt = SdJwt.create(claims, disclosuresStructured,  "123", TestSigner(
            SoftwareKeyPair()), kbValue)!!
        assertEquals(3, structuredSdJwt.get(listOf("address","_sd").toClaimsPointer()!!)[0].asArray()!!.size)
        assertEquals(3, structuredSdJwt.innerJwt.disclosuresMap.size)

        // Recursive SD-JWT
        val disclosuresRecursive = listOf(listOf("address").toClaimsPointer()!!,listOf("address","street_address").toClaimsPointer()!!, listOf("address","locality").toClaimsPointer()!!, listOf("address","region").toClaimsPointer()!!)
        val recursiveSdJwt = SdJwt.create(claims, disclosuresRecursive,  "123", TestSigner(
            SoftwareKeyPair()), kbValue)!!
        assertEquals(1, recursiveSdJwt.get("_sd".asSelector())[0].asArray()!!.size)
        assertEquals(4, recursiveSdJwt.innerJwt.disclosuresMap.size)
    }
    @Test
    fun testDeeplyNestedPresentation() {
        val kb = SoftwareKeyPair()
        val kbValue : Value = Json.decodeFromString(kb.jwkString())
        val deeplyNested = "{\n" +
                "  \"object\" : {\n" +
                "    \"array\" : [\n" +
                "      {\n" +
                "        \"key1\" : \"object[0].key1\"\n" +
                "      },\n" +
                "      {\n" +
                "        \"key1\" : \"object[0].key2\"\n" +
                "      }\n" +
                "    ]\n" +
                "  },\n" +
                "  \"array\" : [\n" +
                "    1,2,3\n" +
                "  ],\n" +
                "  \"other\" : [\n" +
                "    {\n" +
                "      \"test\" : 1\n" +
                "    },\n" +
                "    { \n" +
                "      \"test\" : 1\n" +
                "    }\n" +
                "  ]\n" +
                "}"
        val claims : Value = Json.decodeFromString(deeplyNested)
        val disclosurse = listOf(
            listOf("object", "array", null, "key1").toClaimsPointer()!!,
            listOf("object", "array", null).toClaimsPointer()!!,
            listOf("object").toClaimsPointer()!!,
            listOf("array", null).toClaimsPointer()!!,
            listOf("other").toClaimsPointer()!!
        )
        val sdjwt = SdJwt.create(claims, disclosurse,"123", TestSigner(SoftwareKeyPair()),kbValue)!!
        assertEquals("object[0].key1", sdjwt[listOf("object", "array", 0, "key1").toClaimsPointer()!!][0].asString())
        assertEquals("object[0].key2", sdjwt[listOf("object", "array", 1, "key1").toClaimsPointer()!!][0].asString())
        assertEquals(1L, sdjwt[listOf("other",  0, "test").toClaimsPointer()!!][0].asLong())
    }

    @Test
    fun testSdjwt() {
        val jwt = "eyJ4NWMiOlsiTUlJQmR6Q0NBUjZnQXdJQkFnSUlVRnhlZWxSbld6WXdDZ1lJS29aSXpqMEVBd0l3THpFTE1Ba0dBMVVFQmhNQ1EwZ3hEekFOQmdOVkJBb01CbFZpYVhGMVpURVBNQTBHQTFVRUF3d0dVbTl2ZEVOQk1CNFhEVEkxTURNd05qQTNNall4T1ZvWERUSTJNRE13TmpBM01qWXhPVm93VlRFUU1BNEdBMVVFQXd3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQ2d3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQnd3SFpDMTBjblZ6ZERFUU1BNEdBMVVFQ0F3SFpDMTBjblZ6ZERFTE1Ba0dBMVVFQmhNQ1EwZ3dXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUzI2WWUzZ2NnTzI5aVlzSExHRmlkT0tPWFl5c29Ddy9MMmZZRmR5UjlhK1R0MFNKUDlpRXhzU2VmMlp2b0c0MkpRanJsT1Rnb0hPckdmYlpkU1M0Sk1NQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQ3IwTmdRbk1GZUFqS1l0cDltODRGNkJwTWRqTTA1ZUlLNGNXUk1mU2FhbEFpQU5VelZpaU5rczVMbzN6ZjFMVmR0ZitFc1RoQW9VaHNmNzAvdVZ1R2w4RUE9PSJdLCJraWQiOiJNRDh3TTZReE1DOHhDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFLREFaVlltbHhkV1V4RHpBTkJnTlZCQU1NQmxKdmIzUkRRUUlJVUZ4ZWVsUm5Xelk9IiwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3N1YW5jZV9kYXRlIjoiMjAyNS0wNC0yMlQxNTo1ODoxMFoiLCJ2Y3QiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvY3JlZGVudGlhbHMvcGlkLzEuMCIsImV4cGlyeV9kYXRlIjoiMjAyNS0wNS0wNlQxNTo1ODoxMFoiLCJpc3MiOiJodHRwczovL2hlaWRpLWlzc3Vlci13cy1kZXYudWJpcXVlLmNoL2QtdHJ1c3QvYy9RaGpncE1oZ3drbFdETFg2azczVHZIIiwiX3NkIjpbIjNkTldCeFNzQVJvR2JJRHAyVWY4YTRkdzZ0UkxETFVMV3RoVnF2T2dvMzAiLCI2R3gtV1V3R0VRNjBiY3lacG1DbldPb0FqVUV5aC1ZZDhnNUhCdjY0WmJjIiwiN182TnQ3cndUeXY4UU80bGswSmtvUU80em1XYVpGX2QtX3dKNDNsTG9UdyIsIkE2eV9ZaUh4aERmcHAtdGpKajRNVEdYcnI4YmNMLWhYZVJoSEZLV3F6dmsiLCJFWXpMcTR6WTJaV0MyQVdEbUVsU3NGMl9wNGwyTE1VanpYQjZCcHBuVzlJIiwiSHdzc0RvQ0NGQVRlVDZjQS16RmlFY3BhOGMxb1QxQVozTy1KNjg5dERDZyIsIkxXcWJzWXdFWlpKUDg1aGU2RDBReDNPRmVpaGxtVV9xR3o2TU05Z2EwTzQiLCJONHBEdmhBSzF2ZmhZSUVBSmZKSGNvQ0NmdS1tM1RDWDRRUXRESFYtb2FBIiwiT1I1Ml8xTzBnbG1KNFhMVklVM1RJTC10LTVxZkRKYzVrbVJfN0JzWEhfNCIsIlNpSkdpQ2tYZF9NWjdybWNEbW1vQkZEcFRYa2dkNlctU0JQT3FNak1vaTAiLCJWT3gxalRWWVUtdnpFakd2eXdvTjRSOHdYZzV1LUZweTlERUg5LXJSY2M0IiwiX00wMEhsUGZWUFNHcWJXRDViNXFvdjVDNl9OTTRKRlFTZUgxY1hxOHlzZyIsImJlT08tWFJ5S1BPVGdGU1FjTEZLYlRVaVJhUEpPdmd6ZUo1MndwXzBqOWciLCJkeGRwWEdkMk1hNkt0Ym5yX3h6M2xhdU5EZHlIczV0cFNXRURXaDN2OUdVIiwiaHNBdmZnaUR1d1dqNnUtZFJGNmk2NW1jTHVlcldZc1gxNmZrZVpnUmpNNCIsImh1am4wNFVZaTdiOEhDdkJqTGVFZnY1RGI1cG90YXV1SktBOWx3b2xPRDQiLCJqR0lYU1kwX3FZLTZ0R2lPWTV2aXBVM1JEcWllYXRfc1R2MHhfcHhPZnZrIiwiamhfdjc3QjBPenk0YmVjQ25ub3BaWmtPM2lkN1o1aFYzNlF3bFRST3B6RSIsIm5PS1ZpOEdBWnV1eTluV0lCT1YtUk84emFTcC1uOXlmY25PYndERlh0ZkEiLCJ2Q3pEXzdaUlUwWDhHdnNDYUZwVHo0WnhXcWVVT09jd2dFMXNIR0NTOVZRIiwieDljalNWdDdCSUJCcWJwaE4yZGdfbmhmeV9nSHMxb2tKN2VFb0tiOHZaVSJdLCJpc3N1aW5nX2NvdW50cnkiOiJDSCIsImlzc3VpbmdfYXV0aG9yaXR5IjoiQ0giLCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJhLVk3VmdDWUtlUEZsRURKa1RScEFvQkpFYVVIbGd6RnF2ZDN1YkpaUkMwIiwieSI6IkV4Tk02NEdGSFJkbWhRcHY5R2FOR3hkeVRKdDdRdzJINDhGR051UC1rTzQifX0sImV4cCI6MTc0NjU0NzA5MCwic2NoZW1hX2lkZW50aWZpZXIiOnsiY3JlZGVudGlhbElkZW50aWZpZXIiOiJlYy1waWQtdHZreWkiLCJ2ZXJzaW9uIjoiMy4wLjAifSwiaWF0IjoxNzQ1MzM3NDkwLCJyZW5kZXIiOnsidHlwZSI6Ik92ZXJsYXlzQ2FwdHVyZUJ1bmRsZVYxIiwib2NhIjoiaHR0cHM6Ly9oZWlkaS1pc3N1ZXItd3MtZGV2LnViaXF1ZS5jaC9vY2EvSUEwLWwxWEUteUVrcHNfcEJxbUtaNFNNWDlOWV95R1ZrSDJVaVR6b3cxNmkuanNvbiJ9fQ.NTU1uRk5ydK_EUtqVQQsPrd7YJqslMceF9Lb2Um94V2WBnHSP-nvUs9qvozcnwSqyHRyym7V1qVZQC1KyXPA8g~WyJURmx3M3M2SWh4SDVEUVd6ekhEdUJ3IiwiZGF0ZV9vZl9pc3N1YW5jZSIsIjIwMjUtMDQtMjIiXQ~WyJpMWdnenMxNjhDZkhXZy11bVZVMUx3IiwiYmlydGhkYXRlIiwiRGF0ZSBvZiBCaXJ0aCJd~WyJiam0xUXpiTG9ueUFFbFljT0xIVU5BIiwicGVyc29uYWxfYWRtaW5pc3RyYXRpdmVfbnVtYmVyIiwiIl0~WyJkTDd2Q3drTUVJM1VCMzU4ckZIV3hBIiwiYWdlX2luX3llYXJzIiwxXQ~WyJEYkdXY0pMNDBtaE9VSi1jaGkyV0t3IiwiYWdlX2JpcnRoX3llYXIiLDFd~WyI5dzI2MDdLVV9xaUFwWXFxbk1jdTFnIiwiaXNzdWluZ19qdXJpc2RpY3Rpb24iLCIiXQ~WyJUWmRPRi10aDZuTUNNcXFLZ192Yk5BIiwidHJ1c3RfYW5jaG9yIiwiIl0~WyJZQ3R4R2E4bEtZMUxqOF9yZUVTSndBIiwiZW1haWwiLCIiXQ~WyI5M0dVcjZZY2FCN2thaHQyYVRBZ01nIiwiZG9jdW1lbnRfbnVtYmVyIiwiIl0~WyJWbDVXdUgtYW1rem5weGdIcDAyTkh3Iiwic2V4IiwxXQ~WyJ0MktNUXNKanJDdTVjOVB5SWMzNFdBIiwiZ2l2ZW5fbmFtZSIsIkdpdmVuIE5hbWUiXQ~WyJmSUc5MDNLbjhMSWdQMWJuVEt3VVZ3IiwiYmlydGhfZ2l2ZW5fbmFtZSIsIiJd~WyJXeTZady1EQ1ByVXRtYmNrVmoxYVpBIiwicGljdHVyZSIsIiJd~WyJZc0ZRd1VvSlpaM2FnRndhWnRZQ09BIiwiYmlydGhfZmFtaWx5X25hbWUiLCIiXQ~WyJjOG0tTGZ1RzJtYU5rRUlCVGtzZVlRIiwibmF0aW9uYWxpdHkiLCJOYXRpb25hbGl0eSJd~WyJxQ3hGVGRBNzNhWjBIakVrenJST1lBIiwiZGF0ZV9vZl9leHBpcnkiLCIyMDI1LTA0LTIyIl0~WyJFeEhLX3djdU9oR0J0MGdLbVVHRXZnIiwicGhvbmVfbnVtYmVyIiwiIl0~WyJWaWtzZU1oaVk1aUJEd0pZTjk0ZlZ3IiwiZmFtaWx5X25hbWUiLCJGYW1pbGl5IE5hbWUiXQ~WyJpeFFVaTZGYm5qZDB5VTAwNGxwY1VRIiwibG9jYWxpdHkiLCIiXQ~WyJScDNnaGZRVXZkaEVZaGMtdkg3QXJ3IiwiaG91c2VfbnVtYmVyIiwiIl0~WyJxdVRxWFdjZzFnNU5qZV9lRWhSblZBIiwiY291bnRyeSIsIkNvdW50cnkgb2YgUmVzaWRlbmNlIl0~WyJFR1k1YzZNU2l0eXA2cGpsRjJuaUh3IiwicG9zdGFsX2NvZGUiLCIiXQ~WyJ3aWdhNmxJYUNHVTFUdW1HQllnRE9BIiwicmVnaW9uIiwiIl0~WyJVUU4xME1TYVdnMnN0V3lPRlpnSG9nIiwiZm9ybWF0dGVkIiwiQWRkcmVzcyJd~WyIwZzZRNDR0LVhVdUdMMlRMcVlUTEFnIiwic3RyZWV0X2FkZHJlc3MiLCIiXQ~WyJoRmlSMG9VY1JNbEdhS3FiMFN4N1BRIiwiYWRkcmVzcyIseyJfc2QiOlsiNkRRcElOUjFLS2RPNUg0ckI3RHR0LURjOS1YeGhYa3dyRVZfdWgwWkxtTSIsIjlILWRRVjd6cDlUa0ZlN0p2VVV3NUtwYnJJQ081X29ZWTdYaEEyZHFwSFkiLCJIUGdudmdiVUM5UXBpQ3JJblRLeE11U01XbTJ5bF8zdE51WTVaVm4tYzBzIiwiYk9YQ3BRVVI4ZzhpSEV4Mm80QWVWaWV5d1dzYmZTQnpBVldva0pQaVU2OCIsImVlaGJkaVJJTjdfWHl5V05Zb1dQYkRQMTVPQnk2VUFDeXV4MTE4OUlMR2MiLCJ4eGZfNGpaV1NBcGVFOGpjTmFDRmg1UTRXUllGMFVlUktvc0YtMnFkLWwwIiwiemlEU0NKeHVkazdDOVltcWhuZnEzT2pVTm9aLUo3Y2FMNlBIN3FXNmgtUSJdfV0~WyJaaHFqYlRfNm5qSzRRRnUwMEc3RkhnIiwiMTYiLHRydWVd~WyJfRUVtckdIUlV5UXFiTG9TUGxOUF9nIiwiMTgiLHRydWVd~WyJwOHhKTjZhSFJhTk1TT241WWw3Z3NBIiwiMjEiLHRydWVd~WyJydXFVOV9mWnNTZ2NjS3pBT1dYSmtnIiwiNjUiLHRydWVd~WyJqLTQ0aEs4TGx5dWpCVnBKcFRsT2JnIiwiYWdlX2VxdWFsX29yX292ZXIiLHsiX3NkIjpbIkJnRTR0VjUySTYwM1VTLWpZVkZQOFRrYUdjSFllV1lBWXRiSG1vSjB0QkkiLCJSaE5RVjF3SGMtOGFjeEwxWU1UNC1FbzZ0QUt5WU00Q0RBY1l1QnNsSGNRIiwiVlJTbktROXlrbFR3Tkd4Vk5SQmZBYmJ0NW1DNFl0eTV4amFEQVR1MndKRSIsIlc0RFJTWlVNR2Njd1VkTm53ZmVvdGI3UlE0Y1RUZTZYS2YzOXVNNVg3S2siXX1d~WyJXYTJfWjVjdWw1aFFHQ2ZLTjhtb0hnIiwibG9jYWxpdHkiLCJQbGFjZSBvZiBCaXJ0aCJd~WyJ6VVNKdnJ1WVNoOF9lTGVTc2g0MHV3IiwicmVnaW9uIiwiIl0~WyJfMXdxMXdieDNpMFZYNUY2NHJxTS1RIiwiY291bnRyeSIsIkNvdW50cnkgb2YgQmlydGgiXQ~WyItMC1TaWpuU0h0SXNPS1ZZRGdELTRnIiwicGxhY2Vfb2ZfYmlydGgiLHsiX3NkIjpbIklsbGpmOFRXSXRzdHRwMUpNMjYyZi1Md2pUYzlkcTE0WDkyUEhCYmd0MGsiLCJjM1k5dWFTM2s4aVJwOEdxc3VtNlpRTndUMHIzRFhJWVJXY294V3pUM1JjIiwiejc3Tm00QVhKZEtLZUloc1F0SWNxbm1SOE8zRkFUa3pvUlp4bUxTX3h6ZyJdfV0~"
        val result = SdJwt.parse(jwt)
        println("$result")
    }

    @Test
    fun testNestedDisclosuresPresentation() {
        val keys = SoftwareKeyPair()
        val pubKeyJwt = Json.decodeFromString<Value>(keys.jwkString())
        val issuer = TestSigner(SoftwareKeyPair())

        val claims = Value.Object(mapOf(
            "place_of_birth" to Value.Object(mapOf(
                "country" to Value.String("Switzerland"),
                "locality" to Value.String("Zürich")
            ))
        ))

        val disclosures = listOf<ClaimsPointer>(
            listOf("place_of_birth").toClaimsPointer()!!,
            listOf("place_of_birth", "country").toClaimsPointer()!!,
            listOf("place_of_birth", "locality").toClaimsPointer()!!
        )

        val sdJwt = SdJwt.create(
            claims = claims,
            disclosures = disclosures,
            keyId = "issuer-key-id",
            key = issuer,
            pubKeyJwk = pubKeyJwt)!!

        val presentation = sdJwt.presentation()
        presentation.addDisclosure(listOf(
            PointerPart.String("place_of_birth")))
        val vpToken = presentation.build(TestSigner(keys))

        val parsed = SdJwt.parse(vpToken)
        val disclosedClaims = parsed.innerJwt.claims
        assertEquals(claims["place_of_birth"]["country"], disclosedClaims["place_of_birth"]["country"])
        assertEquals(claims["place_of_birth"]["locality"], disclosedClaims["place_of_birth"]["locality"])
    }

}
