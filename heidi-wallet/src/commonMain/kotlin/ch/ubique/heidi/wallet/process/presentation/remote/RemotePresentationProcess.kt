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

package ch.ubique.heidi.wallet.process.presentation.remote

import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.credentials.models.metadata.KeyMaterialType
import ch.ubique.heidi.dcql.toReadableString
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.transform
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.credentials.LocalizedKeyValue
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialStore
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.credentials.presentation.CredentialUseCaseUiModel
import ch.ubique.heidi.wallet.credentials.presentation.PresentationUiModel
import ch.ubique.heidi.wallet.credentials.presentation.getRequestedLoa
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.extensions.decodeMetadata
import ch.ubique.heidi.wallet.extensions.pop
import ch.ubique.heidi.wallet.keyvalue.KeyValueEntry
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.ProcessStep
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.wallet.process.legacy.presentation.PresentationWorkflow
import ch.ubique.heidi.wallet.process.presentation.CredentialSelection
import ch.ubique.heidi.wallet.process.presentation.PresentationProcess
import ch.ubique.heidi.wallet.process.presentation.PresentationProcessKt
import io.ktor.client.HttpClient
import io.ktor.http.Url
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import uniffi.heidi_wallet_rust.ApiException
import uniffi.heidi_wallet_rust.GenericException
import uniffi.heidi_wallet_rust.VerifiableCredential

import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.credentials.presentation.ZkpUiModel
import ch.ubique.heidi.wallet.process.refresh.eaa.EaaRefreshProcess
import ch.ubique.heidi.wallet.process.refresh.eaa.EaaRefreshProcessStep
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import ch.ubique.heidi.wallet.process.presentation.ErrorModel
import uniffi.heidi_wallet_rust.Credential
import uniffi.heidi_wallet_rust.KeyType
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class RemotePresentationProcess(
    private val client: HttpClient,
    private val signingProvider: SigningProvider,
    private val trustController: TrustFrameworkController,
    private val identityRepository: IdentityRepository,
    private val credentialsRepository: CredentialsRepository,
    private val activityRepository: ActivityRepository,
    private val keyValueRepository: KeyValueRepository,
    private val viewModelFactory: ViewModelFactory,
    private val json: Json,
) : PresentationProcess(trustController), KoinComponent {

	private lateinit var presentationProcess: PresentationProcessKt

	private var presentationScope: String? = null
	private var authSession: String? = null
	private var isDCApi: Boolean = false
	private var selectedId: String? = null

	suspend fun startPresentationProcess(
		qrCodeData: String,
		presentationScope: String? = null,
		authSession: String? = null,
		isDCApi: Boolean = false,
		selectedId: String? = null,
		origin: String? = null,
		useLegacyVpToken: Boolean = false,
	): RemotePresentationProcessStep {
		return try {
			presentationProcess = PresentationProcessKt.initialize(qrCodeData, client, signingProvider, origin = origin, useLegacyVpToken = useLegacyVpToken)
			initializeMetadata(qrCodeData, origin, presentationProcess.authRequest!!, presentationProcess.data?.originalJwt).getOrThrow()
			this.presentationScope = presentationScope
			this.authSession = authSession
			this.isDCApi = isDCApi
			this.selectedId = selectedId
			if (isDCApi && presentationProcess.getDraftVersion().version >= 28) {
				checkOrigins(origin, presentationProcess.authRequest!!.expectedOrigins).isFailure
					&& return RemotePresentationProcessStep.Error(
						errorMessage = "Origin $origin is not in the list of expected origins: ${presentationProcess.authRequest!!.expectedOrigins}",
					)
			}
			RemotePresentationProcessStep.ConnectionDetails(trustFlow.agentInformation)
		} catch (e: ApiException) {
			val info = e.asErrorState()

			if ((e is ApiException.Generic)
				&& (e.v1 is GenericException.Network)
				&& (e.v1.status == 404.toUShort())) {
				RemotePresentationProcessStep.Error(
					errorMessage = "The presentation request is expired. Please regenerate it and try again.",
					errorCode = info.code,
					cause = info.cause
				)
			} else {
				RemotePresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
			}
		} catch (e: Exception) {
			RemotePresentationProcessStep.Error(errorMessage = e.message ?: e::class.simpleName ?: "TODO", cause = e)
		}
	}

	suspend fun continueAfterConnectionTrust(): ProcessStep {
		return if (presentationProcess.isQes()) {
			RemotePresentationProcessStep.QesProcessStep.Preview(trustFlow.agentInformation)
		} else {
			continueWithCredentialSelection()
		}
	}

	suspend fun continueAfterCreationAcceptance(): ProcessStep {
		return RemotePresentationProcessStep.QesProcessStep.SignDocument(trustFlow.agentInformation, presentationProcess.getQesAuthorizationDocuments())
	}

    suspend fun continueWithCredentialSelection(allowUsedCredentials: Boolean = false): RemotePresentationProcessStep {
        try {
            val allIdentities = getAllIdentities().mapNotNull { viewModelFactory.getIdentityUiModel(it) }

			// Load credentials that have not yet been used
			val requestedLoA = trustFlow.agentInformation.getRequestedLoa()

			val validationInfo = trustFlow.validatePresentationRequest(presentationProcess.authRequest!!)

            val unusedCredentials = getMatchingCredentials(allowUsedCredentials, Clock.System.now())
                .map { it.filterForRequestedLoa(requestedLoA) }
				.shuffled()

			var isStatisfied = unusedCredentials.all {
				if(it is CredentialSelection.DcqlCredentialSelection) {
					it.dcqlSetOptions.setOptions.isNotEmpty()
				} else {
					true
				}
			}


            if (!isStatisfied) {
                // Determine if we can refresh and/or fallback to used credentials
                val usedMatches = getMatchingCredentials(true, Clock.System.now())
				isStatisfied = usedMatches.all {
					if(it is CredentialSelection.DcqlCredentialSelection) {
						it.dcqlSetOptions.setOptions.isNotEmpty()
					} else {
						true
					}
				}

                // Inspect identities referenced by allowed documents to decide if refresh is possible
                val allowedDocs = trustFlow.getAllowedDocuments(presentationProcess.authRequest!!, true)
                val identityIds = allowedDocs.map { it.identityId }.toSet()
                val refreshable = identityIds.any { id ->
                    identityRepository.getById(id)?.tokens?.refreshToken != null
                }

				if (refreshable && isStatisfied) {
					return RemotePresentationProcessStep.OutOfTokens(
						isRefreshable = refreshable,
						identityIdsToRefresh = identityIds,
					)
				} else {
					return buildCredentialSelectionFromMatches(unusedCredentials, allIdentities, validationInfo)
				}
            } else {
                return buildCredentialSelectionFromMatches(unusedCredentials, allIdentities, validationInfo)
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            return RemotePresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            return RemotePresentationProcessStep.Error(errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error", cause = e)
        }
    }

    private fun buildCredentialSelectionFromMatches(
        matches: List<CredentialSelection>,
        allIdentities: List<IdentityUiModel>,
        validationInfo: ValidationInfo?,
    ): RemotePresentationProcessStep {
        val credentialUseCaseList = matches.map { cs ->
            when (cs) {
                is CredentialSelection.ProximityCredentialSelection -> {
                    CredentialUseCaseUiModel(null, cs.presentableCredentials.associate {
                        val key = it.map { it.responseId }.firstOrNull() ?: "<NO_CREDENTIAL>"
								key to
										it.map { matchingCredential ->
                            allIdentities.first { identity ->
                                if (identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                    return@first false
                                }
                                identity.credentials.map { it.id }.contains(matchingCredential.credential.id)
                            }.let { identity ->
                                val credential = credentialsRepository.getById(matchingCredential.credential.id)

                                var presentableCredential: CredentialSelectionUiModel =
                                    viewModelFactory.getPresentableCredentialUiModel(
                                        matchingCredential,
                                        identity,
                                        credential?.fk_oca_bundle_url
                                    )

                                // If we have an Mdoc credential, prefer an SD-JWT credential for the values
                                if (credential?.credential_type == CredentialType.Mdoc) {
                                    if (identity !is IdentityUiModel.IdentityUiCredentialModel) {
                                        NotImplementedError("This should not happen")
                                    }
                                    identity.credentials.firstOrNull { it.credentialType == CredentialType.SdJwt }
                                        ?.let { credentialsRepository.getById(it.id) }
                                        ?.let { sdjwt ->
                                            val selection = presentationProcess.getMatchingCredentials(
                                                listOf(
                                                    VerifiableCredential(
                                                        id = sdjwt.id,
                                                        identityId = identity.id,
                                                        name = sdjwt.name,
                                                        metadata = sdjwt.metadata,
                                                        payload = sdjwt.payload
                                                    )
                                                ), null
                                            ).firstOrNull() as? CredentialSelection.PexCredentialSelection
                                            selection?.presentableCredentials?.firstOrNull()?.firstOrNull()?.let {
                                                val sdjwtPresentableCredential =
                                                    viewModelFactory.getPresentableCredentialUiModel(
                                                        it,
                                                        identity,
                                                        sdjwt.fk_oca_bundle_url
                                                    )
                                                presentableCredential = CredentialSelectionUiModel(
                                                    credentialId = presentableCredential.credentialId,
                                                    identityUiModel = presentableCredential.identityUiModel,
                                                    // filter vct from the values as it is sdjwt only. TODO: define "credential specific" attributes, to filter out
                                                    values = sdjwtPresentableCredential.values.filter { it.attributeName != "vct" },
                                                    format = presentableCredential.format,
                                                    keyAssurance = presentableCredential.keyAssurance,
                                                    credential = presentableCredential.credential,
                                                    presentableCredential = presentableCredential.presentableCredential,
                                                    responseId = presentableCredential.responseId,
                                                    requiresCryptographicHolderBinding = true,
                                                )
                                            }
                                        }
                                }
                                presentableCredential
                            }
                        }
                    }, cs)
                }
                is CredentialSelection.DcqlCredentialSelection -> {
					if(cs.dcqlSetOptions.setOptions.isEmpty()) {
						return RemotePresentationProcessStep.CredentialSelection(
							PresentationUiModel(
								clientId = presentationProcess.getClientId(),
								credentialUseCases = emptyList(),
								purpose = "",
								name = "",
								loA = trustFlow.agentInformation.getRequestedLoa(),
								authorizationRequestForDiagnostics = presentationProcess.getAuthorizationRequestForDiagnostics(),
							),
							trustFlow.agentInformation,
							validationInfo = validationInfo,
						)
					}
                    val nonEmptySetOption =
                        cs.dcqlSetOptions.setOptions.find { it.all { other -> other.credentialOptions.isNotEmpty() } }
                            ?: cs.dcqlSetOptions.setOptions[0]
                    val zkpOptions = cs.dcqlSetOptions.zkpOptions
                    CredentialUseCaseUiModel(
                        cs.purpose,
                        nonEmptySetOption.associate {
                            it.queryId to it.credentialOptions.map { matchingCredential ->
                                allIdentities.first { identity ->
                                    identity is IdentityUiModel.IdentityUiCredentialModel &&
                                            identity.credentials.map { it.id }
                                                .contains(matchingCredential.selectedVerifiableCredential.id)
                                }.let { identity ->
                                    val ocaBundleUrl =
                                        credentialsRepository.getById(matchingCredential.selectedVerifiableCredential.id)?.fk_oca_bundle_url
                                    val credentialQuery =
                                        cs.dcqlQuery.credentials?.first { cq -> cq.id == it.queryId }
                                    if (credentialQuery == null) {
                                        return RemotePresentationProcessStep.CredentialSelection(
                                            PresentationUiModel(
                                                clientId = presentationProcess.getClientId(),
                                                credentialUseCases = emptyList(),
                                                purpose = "",
                                                name = "",
                                                loA = trustFlow.agentInformation.getRequestedLoa(),
                                                authorizationRequestForDiagnostics = presentationProcess.getAuthorizationRequestForDiagnostics(),
                                            ),
                                            trustFlow.agentInformation,
                                            validationInfo = validationInfo,
                                        )
                                    }
                                    viewModelFactory.getPresentableCredentialUiModelFromDcql(
                                        it.queryId,
                                        credentialQuery,
                                        matchingCredential.selectedVerifiableCredential,
                                        matchingCredential.selectedCredential,
                                        identity,
                                        ocaBundleUrl,
                                        zkpOptions
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
                        })
                }
                is CredentialSelection.PexCredentialSelection -> {
                    //TODO: handle multiple sets. currently we just chose the first available one
                    CredentialUseCaseUiModel(null, cs.presentableCredentials.associate {
                        val key = it.map { it.responseId }.firstOrNull() ?: "<NO_CREDENTIAL>"
                        key to it.map { matchingCredential ->
                            allIdentities.first { identity ->
                                identity is IdentityUiModel.IdentityUiCredentialModel &&
                                        identity.credentials.map { it.id }.contains(matchingCredential.credential.id)
                            }.let { identity ->
                                val credential = credentialsRepository.getById(matchingCredential.credential.id)

                                var presentableCredential: CredentialSelectionUiModel =
                                    viewModelFactory.getPresentableCredentialUiModel(
                                        matchingCredential,
                                        identity,
                                        credential?.fk_oca_bundle_url
                                    )
                                // If we have an Mdoc credential, prefer an SD-JWT credential for the values
                                if (identity is IdentityUiModel.IdentityUiCredentialModel && credential?.credential_type == CredentialType.Mdoc) {
                                    identity.credentials.firstOrNull { it.credentialType == CredentialType.SdJwt }
                                        ?.let { credentialsRepository.getById(it.id) }
                                        ?.let { sdjwt ->
                                            val selection = presentationProcess.getMatchingCredentials(
                                                listOf(
                                                    VerifiableCredential(
                                                        id = sdjwt.id,
                                                        identityId = identity.id,
                                                        name = sdjwt.name,
                                                        metadata = sdjwt.metadata,
                                                        payload = sdjwt.payload
                                                    )
                                                ), null
                                            ).firstOrNull() as? CredentialSelection.PexCredentialSelection
                                            selection?.presentableCredentials?.firstOrNull()?.firstOrNull()?.let {
                                                val sdjwtPresentableCredential =
                                                    viewModelFactory.getPresentableCredentialUiModel(
                                                        it,
                                                        identity,
                                                        sdjwt.fk_oca_bundle_url
                                                    )
                                                presentableCredential = CredentialSelectionUiModel(
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

        return RemotePresentationProcessStep.CredentialSelection(
            PresentationUiModel(
                presentationProcess.getClientId(),
                credentialUseCaseList,
                "",
                "",
                trustFlow.agentInformation.getRequestedLoa(),
                presentationProcess.getAuthorizationRequestForDiagnostics(),
            ),
            trustFlow.agentInformation,
            validationInfo = validationInfo,
        )
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
			return RemotePresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
		} catch (e: Exception) {
			return RemotePresentationProcessStep.Error(errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error", cause = e)
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
			return RemotePresentationProcessStep.EnterPin(c, credentialsWithPin, credentialsWithFrost)
		} else {
			val d = credentialsWithFrost.pop()
			if (d != null) {
				val frostBlob = identityRepository.getById(d.value.credential.identityId)?.frostBlob
				if (frostBlob != null) {
					presentationProcess.putFrost(d.key, frostBlob)
				} else {
					return RemotePresentationProcessStep.Error(errorMessage = "Frost Blob is null")
				}
				return RemotePresentationProcessStep.EnterPassphrase(d, credentialsWithFrost)
			} else {
				return finalizeWithSelectedCredential()
			}
		}
	}

	private suspend fun finalizeWithSelectedCredential(): ProcessStep {
		return if (presentationProcess.isQes()) {
			val creationDocuments = presentationProcess.getQesCreationAcceptanceDocuments()
			Logger.debug("creationDocuments: $creationDocuments")
			if (creationDocuments.isEmpty()) {
				RemotePresentationProcessStep.QesProcessStep.SignDocument(trustFlow.agentInformation, presentationProcess.getQesAuthorizationDocuments())
			} else {
				RemotePresentationProcessStep.QesProcessStep.CreationAcceptance(trustFlow.agentInformation, creationDocuments)
			}
		} else {
			finalize()
		}
	}

    suspend fun finalize(): RemotePresentationProcessStep {
		try {
			val email = keyValueRepository.getFor(KeyValueEntry.BACKUP_EMAIL_USED)
			val result = presentationProcess.presentCredentials(email, false)
			when (result) {
				is PresentationWorkflow.DcApiSuccess -> {
					val element = json.encodeToString(result.vpToken)
					val usedCredentials = presentationProcess.getUsedCredentials()
					for (c in usedCredentials) {
						val cred: VerifiableCredential = c["credential"].transform()
							?: return RemotePresentationProcessStep.Error(errorMessage = "Credential has invalid format")
						val content: String = c["content"].asString() ?: "{}"

						// Only use the credential if it is refreshable
						val identity = identityRepository.getById(cred.identityId)
						val isRefreshable = identity?.tokens?.refreshToken != null
						val isClaimBound = cred.decodeMetadata()?.keyMaterial is KeyMaterial.Local.ClaimBased
						if (!isClaimBound && isRefreshable && cred.decodeMetadata()?.credentialType != CredentialType.BbsTermwise) {
							credentialsRepository.useCredential(cred.id)
						}

						activityRepository.insertVerification(
							content,
							trustFlow.agentInformation.identityTrust,
							trustFlow.agentInformation.verificationTrust,
							trustFlow.agentInformation.isVerified,
							trustFlow.agentInformation.isTrusted,
							cred.identityId,
							cred.id,
							trustFlow.agentInformation.trustFrameworkId,
							baseUrl = trustFlow.agentInformation.domain,
						)
					}
					return RemotePresentationProcessStep.DcApiSuccess(
						element
					)
				}
				is PresentationWorkflow.Success -> {
					val usedCredentials = presentationProcess.getUsedCredentials()
					for (c in usedCredentials) {
						val cred: VerifiableCredential = c["credential"].transform()
							?: return RemotePresentationProcessStep.Error(errorMessage = "Credential has invalid format")
						val content: String = c["content"].asString() ?: "{}"

						Logger.debug("UBSM: checking if we can set credential as set")
						// Only use the credential if it is refreshable
						val identity = identityRepository.getById(cred.identityId)
						val isRefreshable = identity?.tokens?.refreshToken != null
						val isClaimBound = cred.decodeMetadata()?.keyMaterial is KeyMaterial.Local.ClaimBased
						if (!isClaimBound && isRefreshable && cred.decodeMetadata()?.credentialType != CredentialType.BbsTermwise) {
							Logger.debug("UBSM: setting credential as used ${cred.id}")
							credentialsRepository.useCredential(cred.id)
						} else {
							Logger.debug("UBSM: we cannot set credential as used, refreshtoken: ${identity?.tokens?.refreshToken} credentialType : ${cred.decodeMetadata()?.credentialType}")
						}


						activityRepository.insertVerification(
							content,
							trustFlow.agentInformation.identityTrust,
							trustFlow.agentInformation.verificationTrust,
							trustFlow.agentInformation.isVerified,
							trustFlow.agentInformation.isTrusted,
							cred.identityId,
							cred.id,
							trustFlow.agentInformation.trustFrameworkId,
							baseUrl = trustFlow.agentInformation.domain
						)
					}

					return RemotePresentationProcessStep.Success(
						message = result.message,
						redirectUri = result.redirectUri,
						presentationScope = presentationScope,
						authSession = authSession,
						pdiSession = result.presentationDuringIssuanceSession,
						isQes = presentationProcess.isQes(),
					)
				}
				is PresentationWorkflow.Error -> {
					return RemotePresentationProcessStep.Error(
						errorMessage = "Credential presentation error",
						errorCode = result.code,
						cause = result.error
					)
				}
				else -> {
					return RemotePresentationProcessStep.Error(errorMessage = "Unknown credential presentation result")
				}
			}
		} catch (e: ApiException) {
			val info = e.asErrorState()
			return RemotePresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
		} catch (e: Exception) {
			return RemotePresentationProcessStep.Error(errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error", cause = e)
		}
    }

    /**
     * Refresh credentials for the given identities and, if successful, rerun credential selection.
     * Returns an Error step if refresh fails for all identities.
     */
    suspend fun refreshAndReSelect(identityIds: Set<Long>): ProcessStep {
        // Lazy inject refresh dependencies here to avoid changing constructor
        val secureHardwareAccess: SecureHardwareAccess by inject()
        val ocaRepository: OcaRepository by inject()
        val ocaServiceController: OcaServiceController by inject()

        return try {
            var anySuccess = false
            var lastError: EaaRefreshProcessStep.Error? = null
            for (id in identityIds) {
                val identity = identityRepository.getById(id) ?: continue
                val identityUi = viewModelFactory.getIdentityUiModel(identity) ?: continue
                val refresh = EaaRefreshProcess(
                    trustController,
                    credentialsRepository,
                    identityRepository,
                    secureHardwareAccess,
                    signingProvider,
                    ocaRepository,
                    ocaServiceController,
                    activityRepository,
                    keyValueRepository,
                )
                when (val res = refresh.startEaaRefresh(identityUi)) {
                    is EaaRefreshProcessStep.Success -> anySuccess = true
                    is EaaRefreshProcessStep.Error -> { lastError = res }
                }
            }
            if (anySuccess) {
                continueWithCredentialSelection()
            } else {
                val isRefreshable = identityIds.any { id ->
                    identityRepository.getById(id)?.tokens?.refreshToken != null
                }
                val model = ErrorModel(
                    message = lastError?.errorMessage ?: "No credentials refreshed",
                    code = lastError?.errorCode,
                    cause = lastError?.cause,
                )
                RemotePresentationProcessStep.OutOfTokens(
                    isRefreshable = isRefreshable,
                    identityIdsToRefresh = identityIds,
                    error = model,
                )
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            RemotePresentationProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            RemotePresentationProcessStep.Error(errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error", cause = e)
        }
    }

//    suspend fun continueWithRandomUsedSelection(): ProcessStep {
//        val allIdentities = getAllIdentities().mapNotNull { viewModelFactory.getIdentityUiModel(it) }
//        val identityUiById = allIdentities.associateBy { it.id }
//        val requestedLoA = trustFlow.agentInformation.getRequestedLoa()
//        val usedMatches = getMatchingCredentials(true, Clock.System.now())
//            .map { it.filterForRequestedLoa(requestedLoA) }
//        if (usedMatches.isEmpty()) {
//            return RemotePresentationProcessStep.Error(errorMessage = "No matching credentials available")
//        }
//
//        val selection = hashMapOf<String, CredentialSelectionUiModel>()
//
//        usedMatches.forEach { cs ->
//            when (cs) {
//                is CredentialSelection.PexCredentialSelection -> {
//                    // For each responseId group, pick one random credential if available
//                    cs.presentableCredentials.forEach { group ->
//                        if (group.isEmpty()) return@forEach
//                        val chosen = group.random()
//                        val identity = identityUiById[chosen.credential.identityId]
//                            ?: return@forEach
//                        val credential = credentialsRepository.getById(chosen.credential.id)
//                        val vm = viewModelFactory.getPresentableCredentialUiModel(
//                            chosen,
//                            identity,
//                            credential?.fk_oca_bundle_url
//                        )
//                        selection[vm.responseId] = vm
//                    }
//                }
//                is CredentialSelection.DcqlCredentialSelection -> {
//                    val nonEmptySetOption =
//                        cs.dcqlSetOptions.setOptions.find { it.all { other -> other.credentialOptions.isNotEmpty() } }
//                            ?: cs.dcqlSetOptions.setOptions.firstOrNull()
//                    nonEmptySetOption?.forEach { setOption ->
//                        val options = setOption.credentialOptions
//                        if (options.isEmpty()) return@forEach
//                        val chosen = options.random()
//                        val identity = identityUiById[chosen.selectedVerifiableCredential.identityId]
//                            ?: return@forEach
//                        val ocaBundleUrl = credentialsRepository.getById(chosen.selectedVerifiableCredential.id)?.fk_oca_bundle_url
//                        val credentialQuery = cs.dcqlQuery.credentials?.firstOrNull { it.id == setOption.queryId }
//                            ?: return@forEach
//                        val vm = viewModelFactory.getPresentableCredentialUiModelFromDcql(
//                            setOption.queryId,
//                            credentialQuery,
//                            chosen.selectedVerifiableCredential,
//                            chosen.selectedCredential,
//                            identity,
//                            ocaBundleUrl
//                        )
//                        selection[setOption.queryId] = vm
//                    }
//                }
//                is CredentialSelection.ProximityCredentialSelection -> {
//                    // Not applicable for remote flow
//                }
//            }
//        }
//
//        if (selection.isEmpty()) {
//            return RemotePresentationProcessStep.Error(errorMessage = "No matching credentials available")
//        }
//
//        return continueWithSelectedCredential(selection)
//    }

    private fun getAllIdentities() = identityRepository.getAll()

	private suspend fun getMatchingCredentials(
		used: Boolean,
		validAt: Instant?,
	): List<CredentialSelection> {
		val credentials = trustFlow.getAllowedDocuments(presentationProcess.authRequest!!, used)
			.map { VerifiableCredential(it.id, it.identityId, it.name, Json.encodeToString(it.metadata), it.payload) }

		return presentationProcess.getMatchingCredentials(credentials, validAt)
	}

	private fun checkOrigins(origin: String?, expectedOrigins: List<String>?): Result<Unit> {
		val originHost = origin?.let { Url(it).host }
		val expectedHosts = expectedOrigins?.map { it.removePrefix("https://").removePrefix("http://") }?.toSet()

		if (originHost == null || expectedHosts.isNullOrEmpty() || !expectedHosts.contains(originHost)) {
			return Result.failure(
				IllegalArgumentException("Origin $origin is not in the list of expected origins: $expectedOrigins")
			)
		}
		return Result.success(Unit)
	}

}
