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

package ch.ubique.heidi.wallet.credentials.presentation

import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyAssurance
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.process.presentation.CredentialSelection
import ch.ubique.heidi.wallet.process.presentation.DocumentCandidates
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.DcqlQueryMismatch

data class CredentialUseCaseUiModel(
	val purpose: String?,
	val credentials:  Map<String, List<CredentialSelectionUiModel>>,
	val credentialSelection : CredentialSelection,
	val optional: Boolean = false)

data class PresentationUiModel(
    val clientId: String,
    val credentialUseCases:  List<CredentialUseCaseUiModel>,
    val purpose : String?,
    val name : String?,
    val loA: LoA,
    val authorizationRequestForDiagnostics: AuthorizationRequestDiagnostics?
)

sealed interface AuthorizationRequestDiagnostics {
    data class Generic(val request: String) : AuthorizationRequestDiagnostics

    data class Dcql(
        val info: DcqlMismatchInfo,
    ) : AuthorizationRequestDiagnostics
}

data class DcqlMismatchInfo(
    val query: DcqlQuery,
    val mismatches: List<DcqlQueryMismatch>,
    val identityMap: Map<String, Pair<Long, CredentialType>>
)


//TODO: how do we decide LoA? Is SD-JWT and MDOC the smae or is one preferred?
fun PresentationUiModel.bestCredentialFor(useCaseIndex: Int, responseId: String, identityName: String, loa: LoA, preferSdJwt: Boolean) : CredentialSelectionUiModel? {
    return this.credentialUseCases[useCaseIndex].bestCredentialFor(responseId,identityName,loa,preferSdJwt)
}

fun CredentialUseCaseUiModel.bestCredentialFor(responseId: String, identityName: String, loa: LoA, preferSdJwt: Boolean) : CredentialSelectionUiModel? {
    return this.credentials[responseId]?.bestCredentialFor(identityName,loa,preferSdJwt)
}
fun List<CredentialSelectionUiModel>.bestCredentialFor(identityName: String, loa: LoA, preferSdJwt: Boolean) : CredentialSelectionUiModel? {
    val credentialsForIdentity = this.filter { it.identityUiModel is IdentityUiModel.IdentityUiCredentialModel && it.identityUiModel.name == identityName }
        .let { credentials ->
            if (preferSdJwt) credentials.sortedByDescending { it.format == CredentialType.SdJwt } else credentials
        }

    val loaHigh = credentialsForIdentity.filter {
        it.keyAssurance == KeyAssurance.CloudHigh
    }
    val emergency = credentialsForIdentity.filter {
        it.keyAssurance == KeyAssurance.EmergencyHigh
    }
    val loaMedium = credentialsForIdentity.filter {
        it.keyAssurance == KeyAssurance.HardwareMedium
    }
    val loaLow = credentialsForIdentity.filter {
        it.keyAssurance == KeyAssurance.SoftwareLow
    }

    return when(loa) {
        LoA.Low -> loaLow.firstOrNull() ?: loaMedium.firstOrNull() ?: loaHigh.firstOrNull() ?: emergency.first()
        LoA.Medium -> loaMedium.firstOrNull() ?: loaHigh.firstOrNull() ?: emergency.firstOrNull()
        LoA.High -> loaHigh.firstOrNull() ?: emergency.firstOrNull()
    }
}

