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

package ch.ubique.heidi.dcql

import ch.ubique.heidi.credentials.SdJwtErrors
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.SdJwt.Companion.SD_JWT_FORMATS
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asBoolean
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_credentials_rust.SpecVersion
import uniffi.heidi_dcql_rust.ClaimsQuery
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_util_rust.Value

data class InvalidClaimsQuery(val claim: ClaimsQuery) : Exception("Invalid claims Query")

fun SdJwt.getVpToken(authRequestObject: Value,
                     inputDescriptorId: String,
                     audience: String,
                     transactionData: List<String>?,
                     specVersion: SpecVersion?,
                     nonce: String,
                     signer: SignatureCreator,
                     overrideDisclosures: List<List<PointerPart>>? = null) : Result<String> {
    val builder = this.presentation()
    builder.withAudience(audience)
    builder.withNonce(nonce)
    if (transactionData != null && specVersion != null) {
        builder.withTransactionData(transactionData, specVersion);
    }
    // useful for tests
    overrideDisclosures?.let {
        it.forEach { ptr -> builder.addDisclosure(ptr) }
        return Result.success(builder.build(signer))
    }
    val inputDescriptors = authRequestObject["presentation_definition"]["input_descriptors"].asArray() ?: return Result.failure(SdJwtErrors.InvalidFormat(""))
    val inputDescriptor = inputDescriptors.find { it["id"].asString() == inputDescriptorId } ?: return Result.failure(SdJwtErrors.InvalidFormat(""))
    inputDescriptor["constraints"]["fields"].asArray()?.forEach {
        val path = it["path"].asArray() ?: return@forEach
//        val optional = it["optional"].asBoolean() ?: false
//        // if it is optional we never disclose it
//        if (optional) {
//            return@forEach
//        }

        for (p in path) {
            val key = p.asString() ?: continue
            transformDisclosurePath(key)?.let { ptr ->
                // Don't fail if addDisclosures fails.
                // Maybe the verifier doesn't care
                runCatching { builder.addDisclosure(ptr) }
            }
        }
    }
    return Result.success(builder.build(signer))
}

val ARRAY_INDICES = Regex("\\[(\\d+)]")
val PROPERTY_INDICES = Regex("\\[('.+?')]")

fun transformDisclosurePath(path: String) : List<PointerPart>? {
    val p2 = path.replace(ARRAY_INDICES, "/$1")
    val p3 = p2.replace(PROPERTY_INDICES, "/$1")
    return p3.replace("$", "")
        .replace(".", "/")
        .replace("[", "")
        .replace("]", "")
        .replace("'", "")
        .replace("\"", "")
        .trimStart('/').split("/").toClaimsPointer()?.path

}

fun SdJwt.getVpToken(
    query: CredentialQuery,
    audience: String,
    transactionData: List<String>?,
    specVersion: SpecVersion?,
    nonce: String,
    signer: SignatureCreator?,
    overrideDisclosures: List<List<PointerPart>>? = null
): Result<String> {
    if (!SD_JWT_FORMATS.contains(query.format)) {
        return Result.failure(SdJwtErrors.InvalidFormat(query.format))
    }
    val builder = this.presentation()
    return builder.getVpToken(
        this.innerJwt.claims,
        query,
        audience,
        transactionData,
        specVersion,
        nonce,
        signer,
        overrideDisclosures
    )
}
