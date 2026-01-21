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

package ch.ubique.heidi.wallet.process.presentation.proximity

import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.dcql.toReadableString
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.framework.germany.EU_TRUST_FRAMEWORK_ID
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.transform
import ch.ubique.heidi.wallet.credentials.LocalizedKeyValue
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.credentials.presentation.CredentialUseCaseUiModel
import ch.ubique.heidi.wallet.credentials.presentation.LoA
import ch.ubique.heidi.wallet.credentials.presentation.PresentationUiModel
import ch.ubique.heidi.wallet.credentials.presentation.ZkpUiModel
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.extensions.decodeMetadata
import ch.ubique.heidi.wallet.extensions.pop
import ch.ubique.heidi.wallet.keyvalue.KeyValueEntry
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.ProcessStep
import ch.ubique.heidi.wallet.process.legacy.presentation.PresentationWorkflow
import ch.ubique.heidi.wallet.process.presentation.CredentialSelection
import ch.ubique.heidi.wallet.process.presentation.PresentationProcess
import ch.ubique.heidi.wallet.process.presentation.PresentationProcessKt
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import uniffi.heidi_util_rust.Value
import uniffi.heidi_wallet_rust.ApiException
import uniffi.heidi_wallet_rust.VerifiableCredential
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class ProximityPresentationProcess(
    private val signingProvider: SigningProvider,
    private val trustController: TrustFrameworkController,
    private val identityRepository: IdentityRepository,
    private val credentialsRepository: CredentialsRepository,
    private val activityRepository: ActivityRepository,
    private val keyValueRepository: KeyValueRepository,
    private val viewModelFactory: ViewModelFactory,
    private val json: Json,

) : PresentationProcess(trustController) {

    private lateinit var presentationProcess: PresentationProcessKt

    private var presentationScope: String? = null
    private var authSession: String? = null

    suspend fun startPresentationProcess(engagementData: String): ProximityPresentationProcessStep {
        return try {
            presentationProcess = PresentationProcessKt.initializeMdl(signingProvider)
            ProximityPresentationProcessStep.QrCodeEngagementReady(engagementData)
        } catch (e: ApiException) {
            val info = e.asErrorState()
            ProximityPresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            ProximityPresentationProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "TODO", cause = e
            )
        }
    }

    suspend fun continueWithCredentialSelection(documentRequest: DocumentRequest, sessionTranscript: Value): ProximityPresentationProcessStep {
        try {
            presentationProcess.putDocumentRequest(documentRequest)
            presentationProcess.putSessionTranscript(sessionTranscript)
            val allIdentities =
                getAllIdentities().mapNotNull { viewModelFactory.getIdentityUiModel(it) }

            val unusedCredentials = getMatchingCredentials(documentRequest, false, Clock.System.now())

            if (unusedCredentials.isEmpty()) {
                // If no unused credentials are available, still show the credential selection but without any use cases. That way the trust data can still be displayed
                return ProximityPresentationProcessStep.CredentialSelection(
                    PresentationUiModel(
                        clientId = presentationProcess.getClientId(),
                        credentialUseCases = emptyList(),
                        purpose = "",
                        name = "",
                        loA = //TODO: fix this?
                        LoA.Low,
                        authorizationRequestForDiagnostics = null,
                    ),
                    AgentInformation(
                        AgentType.VERIFIER,
                        "MDL",
                        "MDL",
                        isTrusted = true,
                        isVerified = true,
                        trustFrameworkId = EU_TRUST_FRAMEWORK_ID,
                        logoUri = null
                    ),
                    validationInfo = null,
                )
            } else {
                val credentialUseCaseList = unusedCredentials.map { cs ->
                    when (cs) {
                        is CredentialSelection.ProximityCredentialSelection -> {
                            //TODO: handle multiple sets
                            CredentialUseCaseUiModel(null, cs.presentableCredentials.withIndex().associate {
                                val key = "document:${it.index}"
                                key to
                                        it.value.map { matchingCredential ->
                                            allIdentities.first { identity ->
                                                if(identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                                    TODO("Handle deferred")
                                                }
                                                identity.credentials.map { it.id }
                                                    .contains(matchingCredential.credential.id)
                                            }.let { identity ->
                                                val credential =
                                                    credentialsRepository.getById(matchingCredential.credential.id)

                                                var presentableCredential: CredentialSelectionUiModel =
                                                    viewModelFactory.getPresentableCredentialUiModel(
                                                        matchingCredential,
                                                        identity,
                                                        credential?.fk_oca_bundle_url
                                                    )

                                                presentableCredential
                                            }
                                        }
                            }, cs)
                        }

                        is CredentialSelection.DcqlCredentialSelection -> {
                            val nonEmptySetOption =
                                cs.dcqlSetOptions.setOptions.find { it.all { other -> other.credentialOptions.isNotEmpty() } }
                                    ?: cs.dcqlSetOptions.setOptions[0]
                            CredentialUseCaseUiModel(
                                cs.purpose,
                                nonEmptySetOption.associate {
                                    it.queryId to it.credentialOptions.map { matchingCredential ->
                                        allIdentities.first { identity ->
                                            if(identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                                TODO("Handle deferred")
                                            }
                                            identity.credentials.map { it.id }
                                                .contains(matchingCredential.selectedVerifiableCredential.id)
                                        }.let { identity ->
                                            val ocaBundleUrl =
                                                credentialsRepository.getById(matchingCredential.selectedVerifiableCredential.id)?.fk_oca_bundle_url
                                            val credentialQuery =
                                                cs.dcqlQuery.credentials?.first { cq -> cq.id == it.queryId }
                                            if (credentialQuery == null) {
                                                return ProximityPresentationProcessStep.Error(
                                                    errorMessage = "Matching Credential query not found; this should not happen"
                                                )
                                            }
                                            viewModelFactory.getPresentableCredentialUiModelFromDcql(
                                                it.queryId,
                                                credentialQuery,
                                                matchingCredential.selectedVerifiableCredential,
                                                matchingCredential.selectedCredential,
                                                identity,
                                                ocaBundleUrl,
                                                cs.dcqlSetOptions.zkpOptions
                                            )
                                        }
                                    }
                                },
                                credentialSelection = cs,
                                zkpInfo = cs.dcqlSetOptions.zkpOptions?.let {
                                    ZkpUiModel(
                                        equalityProofs = it.equalityProofClaims.map { claim ->
                                            claim.path.joinToString("/") { p -> p.toReadableString() }
                                        }
                                    )
                                }
                            )
                        }

                        is CredentialSelection.PexCredentialSelection -> {
                            //TODO: handle multiple sets
                            CredentialUseCaseUiModel(null, cs.presentableCredentials.associate {
                                val key =
                                    it.map { it.responseId }.firstOrNull() ?: "<NO_CREDENTIAL>"
                                key to
                                        it.map { matchingCredential ->
                                            allIdentities.first { identity ->
                                                if(identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                                    TODO("Handle deferred")
                                                }
                                                identity.credentials.map { it.id }
                                                    .contains(matchingCredential.credential.id)
                                            }.let { identity ->
                                                val credential =
                                                    credentialsRepository.getById(matchingCredential.credential.id)

                                                var presentableCredential: CredentialSelectionUiModel =
                                                    viewModelFactory.getPresentableCredentialUiModel(
                                                        matchingCredential,
                                                        identity,
                                                        credential?.fk_oca_bundle_url
                                                    )

                                                // If we have an Mdoc credential, prefer an SD-JWT credential for the values
                                                if (credential?.credential_type == CredentialType.Mdoc) {
                                                    if(identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                                        TODO("Handle deferred")
                                                    }
                                                    identity.getCredentialUiModel(viewModelFactory).firstOrNull { it.type == CredentialType.SdJwt }
                                                        ?.let { credentialsRepository.getById(it.id) }
                                                        ?.let { sdjwt ->
                                                            val selection =
                                                                presentationProcess.getMatchingCredentials(
                                                                    listOf(
                                                                        VerifiableCredential(
                                                                            id = sdjwt.id,
                                                                            identityId = identity.id,
                                                                            name = sdjwt.name,
                                                                            metadata = sdjwt.metadata,
                                                                            payload = sdjwt.payload
                                                                        )
                                                                    ), null
                                                                )
                                                                    .firstOrNull() as? CredentialSelection.PexCredentialSelection
                                                            selection?.presentableCredentials?.firstOrNull()
                                                                ?.firstOrNull()?.let {
                                                                val sdjwtPresentableCredential =
                                                                    viewModelFactory.getPresentableCredentialUiModel(
                                                                        it,
                                                                        identity,
                                                                        sdjwt.fk_oca_bundle_url
                                                                    )
                                                                presentableCredential =
                                                                    CredentialSelectionUiModel(
                                                                        credentialId = presentableCredential.credentialId,
                                                                        identityUiModel = presentableCredential.identityUiModel,
                                                                        // filter vct from the values as it is sdjwt only. TODO: define "credential specific" attributes, to filter out
                                                                        values = sdjwtPresentableCredential.values.filter { it.attributeName != "vct" },
                                                                        format = presentableCredential.format,
                                                                        keyAssurance = presentableCredential.keyAssurance,
                                                                        credential = presentableCredential.credential,
                                                                        presentableCredential = presentableCredential.presentableCredential,
                                                                        responseId = presentableCredential.responseId,
                                                                        requiresCryptographicHolderBinding = true
                                                                    )
                                                            }
                                                        }
                                                }
                                                presentableCredential
                                            }
                                        }
                            }, cs)
                        }
                    }
                }

                return ProximityPresentationProcessStep.CredentialSelection(
                    PresentationUiModel(
                        "",
                        credentialUseCaseList,
                        "",
                        "",
                        //TODO: fix this?
                        LoA.Low,
                        null,
                    ),
                    AgentInformation(
                        AgentType.VERIFIER,
                        "MDL",
                        "MDL",
                        isTrusted = true,
                        isVerified = true,
                        trustFrameworkId = EU_TRUST_FRAMEWORK_ID,
                        logoUri = null
                    ),
                    validationInfo = ValidationInfo(isValid = true),
                )
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            return ProximityPresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            return ProximityPresentationProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "TODO", cause = e
            )
        }
    }

    suspend fun continueWithSelectedCredential(
        credentialMapping: Map<String, CredentialSelectionUiModel>,
    ): ProcessStep {
        try {
            val credentialsWithPin = credentialMapping.filter {
                it.value.credential.decodeMetadata()?.let {
                    it.keyMaterial is KeyMaterial.Cloud
                } == true
            }.entries.toMutableList()

            val credentialsWithFrost = credentialMapping.filter {
                it.value.credential.decodeMetadata()?.let {
                    it.keyMaterial is KeyMaterial.Frost
                } == true
            }.entries.toMutableList()

            for (entry in credentialMapping) {
                presentationProcess.putVerifiableCredential(entry.key, entry.value.credential)
                presentationProcess.putVerificationContent(
                    credRepresentative = entry.key,
                    content = json.encodeToString(entry.value.values.map { attr ->
                        LocalizedKeyValue(
                            attr.attributeName,
                            attr.attributeValue?.asString() ?: "",
                            attr.label
                        )
                    })
                )
                entry.value.presentableCredential?.let {
                    presentationProcess.putPresentableCredential(entry.key, it)
                }
            }

            return continueWithPinOrPassphrase(credentialsWithPin, credentialsWithFrost)
        } catch (e: ApiException) {
            val info = e.asErrorState()
            return ProximityPresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            return ProximityPresentationProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "TODO", cause = e
            )
        }
    }

    suspend fun continueWithPinOrPassphrase(
        credentialsWithPin: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
        credentialsWithFrost: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
        viewModel: Map.Entry<String, CredentialSelectionUiModel>? = null,
        pin: String? = null,
        passphrase: String? = null,
    ): ProcessStep {
        if (viewModel != null && pin != null) {
            presentationProcess.putPin(viewModel.key, pin)
        }

        if (viewModel != null && passphrase != null) {
            presentationProcess.putPassphrase(viewModel.key, passphrase)
        }

        val c = credentialsWithPin.pop()
        if (c != null) {
            return ProximityPresentationProcessStep.EnterPin(
                c,
                credentialsWithPin,
                credentialsWithFrost
            )
        } else {
            val d = credentialsWithFrost.pop()
            if (d != null) {
                val frostBlob = identityRepository.getById(d.value.credential.identityId)?.frostBlob
                //TODO: what happens if this is null?
                if (frostBlob != null) {
                    presentationProcess.putFrost(d.key, frostBlob)
                }
                return ProximityPresentationProcessStep.EnterPassphrase(d, credentialsWithFrost)
            } else {
                return finalize()
            }
        }
    }

    suspend fun finalize(): ProximityPresentationProcessStep {
        try {
            val email = keyValueRepository.getFor(KeyValueEntry.BACKUP_EMAIL_USED)
            val result = presentationProcess.presentCredentials(email, true)
            when (result) {
                is PresentationWorkflow.ProximitySuccess -> {
                    val usedCredentials = presentationProcess.getUsedCredentials()
                    for (c in usedCredentials) {
                        val cred: VerifiableCredential = c["credential"].transform()
                            ?: return ProximityPresentationProcessStep.Error(errorMessage = "Credential has invalid format")
                        val content: String = c["content"].asString() ?: "{}"

                        // Only use the credential if it is refreshable
                        val identity = identityRepository.getById(cred.identityId)
                        val isRefreshable = identity?.tokens?.refreshToken != null
                        val isClaimBound = cred.decodeMetadata()?.keyMaterial is KeyMaterial.Local.ClaimBased
                        if (!isClaimBound && isRefreshable && cred.decodeMetadata()?.credentialType != CredentialType.BbsTermwise) {
                            credentialsRepository.useCredential(cred.id)
                        }

                        // TODO UBMW: Insert agent information instead of trust data
//                        activityRepository.insertVerification(
//                            content,
//                            trustFlow.agentInformation.identityTrust,
//                            trustFlow.agentInformation.verificationTrust,
//                            trustFlow.agentInformation.isVerified,
//                            trustFlow.agentInformation.isTrusted,
//                            cred.identityId,
//                            cred.id,
//                            trustFlow.agentInformation.trustFrameworkId,
//                            baseUrl = trustFlow.agentInformation.domain
//                        )
                    }

                    return ProximityPresentationProcessStep.Success(
                        result.token
                    )
                }

                is PresentationWorkflow.Error -> {
                    return ProximityPresentationProcessStep.Error(
                        errorMessage = "Credential presentation error",
                        errorCode = result.code,
                        cause = result.error
                    )
                }

                else -> {
                    return ProximityPresentationProcessStep.Error(errorMessage = "Unknown credential presentation result")
                }
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            return ProximityPresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            return ProximityPresentationProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "TODO", cause = e
            )
        }
    }

    private fun getAllIdentities() = identityRepository.getAll()

    private suspend fun getMatchingCredentials(
		documentRequest: DocumentRequest,
		used: Boolean,
		validAt: Instant?,
    ): List<CredentialSelection> {
        val credentials = credentialsRepository.getAllCredentials()

        return presentationProcess.getMatchingCredentialsProximity(documentRequest, credentials, validAt)
    }
}
