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
import ch.ubique.heidi.credentials.get
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.util.extensions.isSame
import ch.ubique.heidi.util.extensions.toCbor
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.CertificateData
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_crypto_rust.SubjectIdentifier
import uniffi.heidi_crypto_rust.X509PublicKey
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.createCert
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.MapEntry
import uniffi.heidi_util_rust.OrderedMap
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import ch.ubique.heidi.util.extensions.*
import kotlin.time.Clock
import kotlin.time.ExperimentalTime


@OptIn(ExperimentalTime::class)
class Mdoc {
    val mdoc = "omppc3N1ZXJBdXRohEOhASahGCFZArYwggKyMIICV6ADAgECAhQS35vrt8RGJm7DTUyfLLtiNIySczAKBggqhkjOPQQDAjCBxjELMAkGA1UEBhMCREUxHTAbBgNVBAgMFEdlbWVpbmRlIE11c3RlcnN0YWR0MRQwEgYDVQQHDAtNdXN0ZXJzdGFkdDEdMBsGA1UECgwUR2VtZWluZGUgTXVzdGVyc3RhZHQxCzAJBgNVBAsMAklUMSkwJwYDVQQDDCBpc3N1YW5jZS5nZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTErMCkGCSqGSIb3DQEJARYcdGVzdEBnZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTAeFw0yNDExMjYxMzI1NThaFw0yNTExMjYxMzI1NThaMIHGMQswCQYDVQQGEwJERTEdMBsGA1UECAwUR2VtZWluZGUgTXVzdGVyc3RhZHQxFDASBgNVBAcMC011c3RlcnN0YWR0MR0wGwYDVQQKDBRHZW1laW5kZSBNdXN0ZXJzdGFkdDELMAkGA1UECwwCSVQxKTAnBgNVBAMMIGlzc3VhbmNlLmdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMSswKQYJKoZIhvcNAQkBFhx0ZXN0QGdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENhe3wz7kTUAOPk3ZG__MjAGW-ROW3eCyxyso_ijCDqSb0SO_lseoNZj6dCLb17M0fa2SEasp7RmyZ4f1mpSwj6MhMB8wHQYDVR0OBBYEFFJbYAZiPV0nk3Pzj9eiMMOMfTRfMAoGCCqGSM49BAMCA0kAMEYCIQDNrXhdq3GuHw95uGgrATAcdscR4_zpITilmIe9Uhp9lAIhAPaOqy5JBt4oK6L3lHAKSoCBavJnCgpc7hOZv4u7rKlfWQMB2BhZAvymZ2RvY1R5cGV4I2NoLnViaXF1ZS5zdHVkaWVyZW5kZW5hdXN3ZWlzLjMxaXEyZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTEyLTE4VDExOjEwOjM3Wml2YWxpZEZyb23AdDIwMjQtMTItMThUMTE6MTA6MzdaanZhbGlkVW50aWzAdDIwMjUtMDEtMDFUMTE6MTA6MzdabHZhbHVlRGlnZXN0c6F4JWNoLnViaXF1ZS5kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLjGsAFgg23BGu4LdRj7yPGXxcLDk_epZFqj8iRrYzq-gp1HVV6wBWCBuk-TqGMPpKa-pVRg2wctLqb01cBrByeop19V7D54fgAJYIDHcOh7Qrjv4VmHftCXSfms4cS_J5NHrSbTzY17T3UW3A1ggAggJhjj_k2XJWniIZQwWvAIvJUFOkpApczHUkU4Q5zQEWCAWD7tIx-kCXHJLzeviVkjq3N4w2w7qlKiHldV8AcC1zAVYIMsD8NLVyXUYbNMCKgqlezVeBadyqAKP7A7v_lIGpiTxBlggNKvz9ayo9ac7U-Mpv7z_3crWGRLNwJwjLIJpUBZJO50HWCCrDQ67BngIcDJTeDD8eVrN1Ivfu3dXG2JRBe5qidsOOQhYIAjnwHdCN28IWaiH6m7Oq9HpxMtxSLeYq3IDxE_MfycVCVgggveVj1GHSyz2aebxGhGsofV6IamFOPYtyaA9WVTMiawKWCA1UFjXVRmSMsc93rIAc4AVeS3R0h7OiYeo2dAAVMmhVQtYIHwiMpcGndwX3UBbe13BbFL6QW8zHoGdgiJLmco2EImTbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggalOOa-fMSY0g1p5i8c-BesIi-5JQMYPP7BEjLgzazl4iWCB3G5WR4cYYeWY0RCIVgrC5j37o2aUUafG9w-r1wOw9x29kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAYlPPfiD3bl7pOL6vtlgTudD3JIJ5IQKE7K0rVVXfIKtO6ZKJB73k2IlYIoIcR0rxainfl1u65PX4L4j2zTuvYmpuYW1lU3BhY2VzoXglY2gudWJpcXVlLmRldi1zc2ktc2NoZW1hLWNyZWF0b3Itd3MuMYzYGFhrpGZyYW5kb21Q6uuwtYHxyyuPlXpIR-HUKmhkaWdlc3RJRABsZWxlbWVudFZhbHVlwHgYMjAyNC0xMi0xOFQxMToxMDozNy4wMjVacWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhWpGZyYW5kb21QIuzmtjT92G_cQQCzrBITqWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlak11c3Rlcm1hbm5xZWxlbWVudElkZW50aWZpZXJobGFzdE5hbWXYGFhUpGZyYW5kb21QPaU3yGmm728d8VTiUaTnNGhkaWdlc3RJRAJsZWxlbWVudFZhbHVlaTEyMzQ1Njc4OXFlbGVtZW50SWRlbnRpZmllcmdiYWRnZU5y2BhYVKRmcmFuZG9tULa1ffJG7gni8VSESFDupqpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWgyMDI0MTIxOHFlbGVtZW50SWRlbnRpZmllcmhpc3N1ZWRPbtgYWFWkZnJhbmRvbVB7TISRkZ3ROYPZZi0LQ4YCaGRpZ2VzdElEBGxlbGVtZW50VmFsdWViQ0hxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYaaRmcmFuZG9tUDGdMbXtJ8TbIBKLKBSHR9JoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDEtMDFUMTE6MTA6MzcuMDI1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWFSkZnJhbmRvbVDkneH7P_ynyRrUH8ERTyHzaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVnTWFydGluYXFlbGVtZW50SWRlbnRpZmllcmlmaXJzdE5hbWXYGFhXpGZyYW5kb21Qx98jL5scaybVlNk5kNR7dGhkaWdlc3RJRAdsZWxlbWVudFZhbHVlaDIwMDEwODEycWVsZW1lbnRJZGVudGlmaWVya2RhdGVPZkJpcnRo2BhYVqRmcmFuZG9tUJEm7q_3068JNHX5PAKZITtoZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWgyMDI1MTIxOHFlbGVtZW50SWRlbnRpZmllcmp2YWxpZFVudGls2BhYXaRmcmFuZG9tUPC-V7TJgFNFeJ-fiqCeYURoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZWowMS83NjU0MzIxcWVsZW1lbnRJZGVudGlmaWVyb21hdHJpY3VsYXRpb25OctgYWFekZnJhbmRvbVAjXwpwMZWKKgDLpBVmew8baGRpZ2VzdElECmxlbGVtZW50VmFsdWViQ0hxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhlpGZyYW5kb21Q7dpm6J4EvICXj4m8076g_mhkaWdlc3RJRAtsZWxlbWVudFZhbHVleBhVbml2ZXJzaXTDpHQgTXVzdGVyc3RhZHRxZWxlbWVudElkZW50aWZpZXJoaXNzdWVkQnk"
    val decodedMdoc = Mdoc.parse(mdoc)
    @Test
    fun testMdoc() {
        val decodedcbor = decodeCbor(base64UrlDecode(mdoc))
        val issuerAuth = decodedMdoc.mdoc.originalDecoded[listOf("issuerAuth").toClaimsPointer()!!]
        assertTrue(decodedMdoc.mdoc.originalDecoded.isSame(decodedcbor))
        val encodedMdoc = encodeCbor(decodedMdoc.mdoc.originalDecoded)
        val certs = decodedMdoc.extracX5c().getOrThrow()
        assertTrue(decodedMdoc.verify().getOrThrow())
        assertEquals(mdoc, base64UrlEncode(encodedMdoc))
    }

    @Test
    fun testExtensions() {
        val string : Value = Value.String("test")
        assertTrue { string.isSame("test".toCbor()) }
        val innerBytes = ByteArray(3) { it.toByte() }
        val bytes: Value = Value.Bytes(innerBytes)
        assertTrue { bytes.isSame(innerBytes.toCbor()) }
        assertTrue { string.isSame(string.toCbor()) }
        val tag : Value = Value.Tag(24UL, listOf(bytes))
        assertTrue { tag.isSame(Pair(24, innerBytes).toCbor()) }
        assertTrue { tag.isSame(Pair(24L, innerBytes).toCbor()) }
        val obj : Value = Value.OrderedObject(OrderedMap(listOf(MapEntry(Value.String("test"), Value.Number(JsonNumber.Integer(1))))))
        assertTrue { obj.isSame(mapOf("test" to 1).toCbor()) }
    }

    @Test
    fun testCreation() {
        val kbKey= SoftwareKeyPair()
        val issuerKey = SoftwareKeyPair()
        val issuerSigner = TestSigner(issuerKey)
        val data = mapOf(
            "ch.ubique.test" to mapOf(
                "test" to 1,
                "nestedObject" to mapOf(
                    "inner" to "yes"
                )
            )
        ).toCbor()
        val jwkPublic: Value = Json.decodeFromString(issuerKey.jwkString())
        val pubKey = X509PublicKey.P256(jwkPublic["x"].asString()!!, jwkPublic["y"].asString()!!)
        val certData = CertificateData(issuer = SubjectIdentifier(commonName = "Issuer"), subject = SubjectIdentifier(commonName = "Subject"),
           notBefore =  Clock.System.now().toEpochMilliseconds()/1000, notAfter = Clock.System.now().toEpochMilliseconds() /1000 + 86400 * 365)
        val cert = createCert(certData, pubKey, issuerKey.asSignatureCreator())!!
        val createdMdoc = Mdoc.create(data, issuerSigner,"test", listOf(cert), Json.decodeFromString(kbKey.jwkString())).getOrThrow()
        assertTrue { createdMdoc.verify().getOrThrow() }
    }
    @Test
    fun testMdl() {
        val kbKey= SoftwareKeyPair()
        val issuerKey = SoftwareKeyPair()
        val issuerSigner = TestSigner(issuerKey)
        val data = mapOf(
            "org.iso.18013.5.1" to mapOf(
                "family_name" to "Jones",
                "given_name" to "Ava",
                "birth_date" to "2007-03-25"
            )
        ).toCbor()
        val jwkPublic: Value = Json.decodeFromString(issuerKey.jwkString())
        val pubKey = X509PublicKey.P256(jwkPublic["x"].asString()!!, jwkPublic["y"].asString()!!)
        val certData = CertificateData(issuer = SubjectIdentifier(commonName = "Issuer", country = "CH"), subject = SubjectIdentifier(commonName = "Subject", country = "CH"),
            notBefore =  Clock.System.now().toEpochMilliseconds()/1000, notAfter = Clock.System.now().toEpochMilliseconds() /1000 + 86400 * 365)
        val cert = createCert(certData, pubKey, issuerKey.asSignatureCreator())!!
        val createdMdoc = Mdoc.create(data, issuerSigner,"org.iso.18013.5.1.mDL", listOf(cert), Json.decodeFromString(kbKey.jwkString())).getOrThrow()
        assertTrue { createdMdoc.verify().getOrThrow() }
    }
}
