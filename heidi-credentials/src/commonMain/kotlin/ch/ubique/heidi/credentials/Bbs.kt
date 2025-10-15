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

import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.BbsBuilderObject
import uniffi.heidi_credentials_rust.BbsClaimBasedPresentationRust
import uniffi.heidi_credentials_rust.BbsPresentationRust
import uniffi.heidi_credentials_rust.BbsRust
import uniffi.heidi_credentials_rust.bbsGetBody
import uniffi.heidi_credentials_rust.bbsPresentationGetClaims
import uniffi.heidi_credentials_rust.decodeBbs
import uniffi.heidi_util_rust.Value

class Bbs(val inner: BbsRust) {
    companion object {
        val BBS_TERMWISE_FORMATS: Array<String> = arrayOf("bbs-termwise")

        fun parse(str: String): Bbs {
            return Bbs(decodeBbs(str))
        }
    }
    fun body() : Value {
        return bbsGetBody(this.inner)
    }

    fun presentation(issuerPk: String, issuerId: String, issuerKeyId: String): BbsBuilderObject =
        BbsBuilderObject(inner, issuerPk, issuerId, issuerKeyId)
}

class BbsPresentation(val inner: BbsPresentationRust) {
    companion object {
        fun parse(vpToken: String): BbsPresentation =
            BbsPresentation(BbsPresentationRust.parse(vpToken))
    }

    fun claims(): Value = bbsPresentationGetClaims(inner)

    fun vcTypes(): List<String> = inner.getVcTypes()

    fun getOriginalNumClaims(): Int = inner.getNumOriginalClaims()

    fun getNumDisclosed(): Int = inner.getNumDisclosed()

    fun verify(
        definition: String,
        verifyingKeys: Map<String, String>,
        issuerPk: String,
        issuerId: String,
        issuerKeyId: String,
        dbMessage: ByteArray,
        dbSecpLabel: ByteArray,
        dbTomLabel: ByteArray,
        dbBlsLabel: ByteArray,
        dbBppSetupLabel: ByteArray
    ): String {
        val claims = inner.verify(
            definition,
            verifyingKeys,
            issuerPk,
            issuerId,
            issuerKeyId,
            dbMessage,
            dbSecpLabel,
            dbTomLabel,
            dbBlsLabel,
            dbBppSetupLabel
        )
        return Json.encodeToString(claims)
    }
}

class BbsClaimBasedPresentation(val inner: BbsClaimBasedPresentationRust) {
    companion object {
        fun parse(
            vpToken: String,
            dbMessage: ByteArray,
            dbSecpLabel: ByteArray,
            dbTomLabel: ByteArray,
            dbBlsLabel: ByteArray,
            dbBppSetupLabel: ByteArray,
            issuerPk: String,
            issuerId: String,
            issuerKeyId: String,
        ): BbsClaimBasedPresentation =
            BbsClaimBasedPresentation(BbsClaimBasedPresentationRust.parse(
                vpToken = vpToken,
                dbMessage = dbMessage,
                dbSecpLabel = dbSecpLabel,
                dbTomLabel = dbTomLabel,
                dbBlsLabel = dbBlsLabel,
                dbBppSetupLabel = dbBppSetupLabel,
                issuerPk = issuerPk,
                issuerId = issuerId,
                issuerKeyId = issuerKeyId
            ))
    }

    fun addDisclosureRequirements(requirements: List<String>) =
        inner.addDisclosureRequirement(requirements)

    fun addEqualClaimsRequirement(key1: String, key2: String) =
        inner.addEqualClaimsRequirement(key1, key2)

    fun verify() =
        inner.verify(2U)
}
