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

import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.util.extensions.*
import uniffi.heidi_crypto_rust.VerificationKey
import uniffi.heidi_crypto_rust.X509Certificate
import uniffi.heidi_crypto_rust.X509PublicKey
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.extractCerts
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_credentials_rust.MdocRust
import uniffi.heidi_util_rust.OrderedMap
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_util_rust.Value
import uniffi.heidi_credentials_rust.currentDateTimeString
import uniffi.heidi_credentials_rust.dateTimeStringInDays
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_credentials_rust.decodeMdoc
import uniffi.heidi_util_rust.encodeCbor
import uniffi.heidi_credentials_rust.random32Bytes

sealed interface MdocErrors {
    data class InvalidFormat(val msg: String) : MdocErrors, Throwable(msg)
    data class UnsupportedAlgorithm(val alg: String) : MdocErrors,
        Throwable(message = "Alg $alg is unsupported")
}

class Mdoc(val mdoc: MdocRust) {
    companion object {
        val MDOC_FORMATS: Array<String> = arrayOf("mso_mdoc")
        fun mdlPresentation(documentRequest: DocumentRequest, sessionTranscript: Value, signers: List<SignatureCreator>, mdocs: List<Mdoc>): ByteArray? {
            if(documentRequest !is DocumentRequest.Mdl) {
                return null
            }
            val documents = mutableListOf<Value>()
            for((mdoc, signer) in mdocs.zip(signers)) {
                val docType = mdoc.doctype()!!
                val mdlRequest = documentRequest.documents.find { it.documentType == docType }!!
                val token = mdoc.getMdlToken(mdlRequest, sessionTranscript, signer).getOrNull()!!
                documents.add(token)
            }
            return encodeCbor(mapOf(
                "version" to "1.0",
                "documents" to documents,
                "status" to 0
            ).toCbor())
        }

        fun parse(data: String): Mdoc {
            return Mdoc(decodeMdoc(data))
        }

        fun create(
            properties: Value,
            signer: SignatureCreator,
            docType: String,
            certificateChain: List<ByteArray>,
            deviceKey: Value
        ): Result<Mdoc> {
            val valueDigests = mutableMapOf<String, MutableMap<Int, Value>>()
            val namespaces = mutableMapOf<String, MutableList<Value>>()
            for (entry in properties.asOrderedObject()?.entries!!) {
                val namespace = entry.key.asString()!!
                val namespaceEntries = valueDigests.getOrPut(namespace) { mutableMapOf() }
                val namespacesList = namespaces.getOrPut(namespace) { mutableListOf() }
                var counter = 0
                for (v in entry.value.asOrderedObject()!!.entries) {
                    val randomData = random32Bytes()
                    val dataElement = encodeCbor(
                        mapOf(
                            "digestID" to counter,
                            "random" to randomData,
                            "elementIdentifier" to v.key,
                            "elementValue" to v.value
                        ).toCbor()
                    )
                    val isDataItem = sha256Rs(encodeCbor((24 to dataElement).toCbor())).toCbor()
                    namespaceEntries.put(counter, isDataItem)
                    namespacesList.add((24 to dataElement).toCbor())
                    counter += 1
                }
                valueDigests.put(namespace, namespaceEntries)
                namespaces.put(namespace, namespacesList)
            }
            // We only support ES256 for now
            if (deviceKey["kty"].asString() != "EC") {
                return Result.failure(MdocErrors.UnsupportedAlgorithm(deviceKey["kty"].asString()!!))
            }
            val deviceKey = mapOf(
                1 to 2,
                -1 to 1,
                -2 to base64UrlDecode(deviceKey["x"].asString()!!),
                -3 to base64UrlDecode(deviceKey["y"].asString()!!),
            )
            val now = currentDateTimeString()
            val exp = dateTimeStringInDays(14UL)
            val mso = mapOf(
                "version" to "1.0",
                "digestAlgorithm" to "SHA-256",
                "valueDigests" to valueDigests,
                "deviceKeyInfo" to mapOf(
                    "deviceKey" to deviceKey
                ),
                "docType" to docType,
                "validityInfo" to mapOf(
                    "signed" to (0 to now),
                    "validFrom" to (0 to now),
                    "validUntil" to (0 to exp)
                )

            ).toCbor()
            val protectedHeaders = mapOf(1 to -7).toCbor()
            val coseSign1 = encodeCbor(coseSign1(protectedHeaders, mso))
            val signature = signer.sign(coseSign1)

            val issuerAuth = listOf(
                // algorithm
                encodeCbor(protectedHeaders),
                // x5c
                mapOf(
                    33 to if (certificateChain.size == 1) {
                        certificateChain[0]
                    } else {
                        certificateChain
                    }
                ),
                // payload
                encodeCbor((24 to encodeCbor(mso)).toCbor()),
                // signature
                signature
            ).toCbor()
            val mdoc = base64UrlEncode(
                encodeCbor(
                    mapOf(
                        "issuerAuth" to issuerAuth,
                        "nameSpaces" to namespaces
                    ).toCbor()
                )
            )
            return Result.success(Mdoc.parse(mdoc))
        }
    }

    fun doctype(): String? {
        val result = this.mdoc.issuerAuth[listOf("docType").toClaimsPointer()!!]
        if (result.size != 1) {
            return null
        }
        return result[0].asString()
    }

    fun version(): String? {
        val result = this.mdoc.issuerAuth[listOf("version").toClaimsPointer()!!]
        if (result.size != 1) {
            return null
        }
        return result[0].asString()
    }

    fun getSessionTranscript(
        cliendIdHash: ByteArray,
        responseUriHash: ByteArray,
        nonce: String
    ): Value {
        val handover = listOf(cliendIdHash, responseUriHash, nonce).toCbor()
        return listOf(null, null, handover).toCbor()
    }

    fun deviceSignature(
        signer: SignatureCreator,
        docType: String,
        sessionTranscript: Value
    ): Value {
        val emptyMapBytes = encodeCbor(Value.OrderedObject(OrderedMap(listOf()))).toCbor()
        val taggedNameSpace = Pair(24, emptyMapBytes).toCbor()
        val deviceAuthentication = listOf(
            "DeviceAuthentication",
            sessionTranscript,
            docType,
            taggedNameSpace
        ).toCbor()
        val deviceAuthenticationBytes =
            encodeCbor(Pair(24, encodeCbor(deviceAuthentication)).toCbor()).toCbor()
        val protectedHeaderBytes = encodeCbor(mapOf(1 to -7).toCbor()).toCbor()
        val sigStructure = listOf(
            "Signature1",
            protectedHeaderBytes,
            ByteArray(0),
            deviceAuthenticationBytes
        ).toCbor()
        val signature = signer.sign(encodeCbor(sigStructure))
        return listOf(
            protectedHeaderBytes,
            mapOf<String, String>(),
            null,
            signature
        ).toCbor()
    }

    fun getIssuerSigned(attributes: Map<String, String>): Result<Value> {
        var issuerSigned = this.mdoc.originalDecoded
        var originalIssuerAuth = issuerSigned.get("issuerAuth")
        var namespaces = mutableMapOf<String, MutableList<Value>>()
        val namespaceRegex = Regex("\\$\\[[\"'](?<namespace>.+?)[\"']].*")
        val attributePath = Regex("\\[[\"'](?<path>.+?)[\"']]")
        for (attr in attributes) {
            val match = namespaceRegex.matchEntire(attr.key) ?: continue
            val namespaceName = match.groups["namespace"]?.value ?: continue
            val theNamespace = this.mdoc.originalDecoded["nameSpaces"][namespaceName]
            val attrPath = attr.key.replace("\$['${namespaceName}']", "")
            val pathSegments = mutableListOf<Any>()
            for (m in attributePath.findAll(attrPath)) {
                val p = m.groups["path"]?.value ?: return Result.failure(Throwable("invalid path"))
                pathSegments.add(p)
            }
            val attrName = pathSegments.firstOrNull() ?: return Result.failure(Throwable("invalid path"))
            val pair = theNamespace.asArray()
                ?.map { value ->
                    Pair(value, decodeCbor(value.asTag()!!.value[0].asBytes()!!))
                }?.first { it.second["elementIdentifier"].asString()!! == attrName } ?:  return Result.failure(Throwable("Namespace is NOT an array!"))

            val namespaceElements = namespaces.getOrPut(namespaceName) { mutableListOf() }
            namespaceElements.add(pair.first.toCbor())
        }
        return Result.success(
            mapOf(
                "issuerAuth" to originalIssuerAuth,
                "nameSpaces" to namespaces
            ).toCbor()
        )
    }

    fun getIssuerSigned(documentRequest: DocumentRequest.MdlDocument): Result<Value> {
        var issuerSigned = this.mdoc.originalDecoded
        var originalIssuerAuth = issuerSigned.get("issuerAuth")
        var namespaces = mutableMapOf<String, MutableList<Value>>()

        for (attr in documentRequest.requestedDocumentItems) {
            val theNamespace = this.mdoc.originalDecoded["nameSpaces"][attr.namespace]
            val pair = theNamespace.asArray()!!
                .map { value ->
                    Pair(value, decodeCbor(value.asTag()!!.value[0].asBytes()!!))
                }.first { it.second["elementIdentifier"].asString()!! == attr.elementIdentifier }

            val namespaceElements = namespaces.getOrPut(attr.namespace) { mutableListOf() }
            namespaceElements.add(pair.first.toCbor())
        }
        return Result.success(
            mapOf(
                "issuerAuth" to originalIssuerAuth,
                "nameSpaces" to namespaces
            ).toCbor()
        )
    }

    fun getMdlToken(
        documentRequest: DocumentRequest.MdlDocument,
        sessionTranscript: Value,
        signer: SignatureCreator
    ): Result<Value> {
        val issuerSigned = this.getIssuerSigned(documentRequest).getOrNull()
            ?: return Result.failure(Throwable("Failed to build IssuerSigned"))
        val coseSign1 = this.deviceSignature(signer, this.doctype()!!, sessionTranscript)
        val deviceNameSpacesBytes = encodeCbor(mapOf<String, String>().toCbor()).toCbor()
        return Result.success(getPreparedDocument(coseSign1, issuerSigned, deviceNameSpacesBytes))
    }

    fun getVpToken(
        attributes: Map<String, String>,
        clientIdHash: ByteArray,
        responseUriHash: ByteArray,
        nonce: String,
        signer: SignatureCreator
    ): Result<String> {
        val issuerSigned = getIssuerSigned(attributes).getOrNull() ?: return Result.failure(
            Throwable("Failed to build IssuerSigned")
        )
        val sessionTranscript = this.getSessionTranscript(clientIdHash, responseUriHash, nonce)
        val token = this.buildToken(signer, issuerSigned, sessionTranscript)
        return Result.success(
            base64UrlEncode(encodeCbor(token))
        )
    }

    fun getPreparedDocument(
        coseSign1: Value,
        issuerSigned: Value,
        deviceNameSpacesBytes: Value
    ): Value {
        return mapOf(
            "docType" to this.doctype(),
            "issuerSigned" to issuerSigned,
            "deviceSigned" to mapOf(
                "nameSpaces" to Pair(24, deviceNameSpacesBytes),
                "deviceAuth" to mapOf(
                    "deviceSignature" to coseSign1
                )
            ),
        ).toCbor()
    }

    fun buildToken(signer: SignatureCreator, issuerSigned: Value, sessionTranscript: Value): Value {
        val coseSign1 = this.deviceSignature(signer, this.doctype()!!, sessionTranscript)
        val deviceNameSpacesBytes = encodeCbor(mapOf<String, String>().toCbor()).toCbor()
        val document = getPreparedDocument(coseSign1, issuerSigned, deviceNameSpacesBytes)
        val vpToken = mapOf(
            "version" to this.version(), "documents" to listOf(
                document,
            ),
            "status" to 0
        ).toCbor()
        return vpToken
    }

    fun extracX5c(): Result<List<X509Certificate>> {
        val certs = this.mdoc.originalDecoded["issuerAuth"][1].asOrderedObject()!!
        val certBytes = certs.get(Value.Number(JsonNumber.Integer(33)))!!.asBytes()!!
        val parsedCerts = extractCerts(certBytes);
        return Result.success(parsedCerts)
    }

    fun getProtectedHeaders(): Value {
        val result = this.mdoc.originalDecoded["issuerAuth"][0].asBytes()!!
        return decodeCbor(result)
    }

    fun getMso(): Value {
        val result = this.mdoc.originalDecoded["issuerAuth"][2].asBytes()!!
        val taggedValue = decodeCbor(result).asTag()!!
        return decodeCbor(taggedValue.value[0].asBytes()!!)
    }

    fun getSignature(): ByteArray {
        return this.mdoc.originalDecoded["issuerAuth"][3].asBytes()!!
    }

    fun verify(): Result<Boolean> {
        val chain = this.extracX5c().getOrThrow()[0]
        val pubKey = chain.publicKey
        if (pubKey is X509PublicKey.P256) {
            val verifyingKey = VerificationKey.fromCoords(pubKey.x, pubKey.y)
            val protectedHeaders = this.getProtectedHeaders()
            val mso = this.getMso()
            val cose1 = coseSign1(protectedHeaders, mso)
            return Result.success(verifyingKey.verify(this.getSignature(), encodeCbor(cose1)))
        } else {
            return Result.failure(Throwable("Key not supported"))
        }
    }
}

fun coseSign1(protectedHeaders: Value, mso: Value): Value {
    return listOf(
        "Signature1",
        encodeCbor(protectedHeaders),
        ByteArray(0),
        encodeCbor((24 to encodeCbor(mso)).toCbor())
    ).toCbor()
}
