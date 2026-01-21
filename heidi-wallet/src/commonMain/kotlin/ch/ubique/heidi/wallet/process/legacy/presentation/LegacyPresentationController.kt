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

package ch.ubique.heidi.wallet.process.legacy.presentation

import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.dcql.toReadableString
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.wallet.ProximityWallet
import ch.ubique.heidi.proximity.wallet.ProximityWalletState
import ch.ubique.heidi.trust.framework.swiss.SWISS_TRUST_FRAMEWORK_ID
import ch.ubique.heidi.trust.framework.swiss.SwissTrustFramework
import ch.ubique.heidi.trust.framework.swiss.model.TrustData
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
import ch.ubique.heidi.wallet.credentials.presentation.ZkpUiModel
import ch.ubique.heidi.wallet.credentials.presentation.getRequestedLoa
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.extensions.decodeMetadata
import ch.ubique.heidi.wallet.extensions.pop
import ch.ubique.heidi.wallet.keyvalue.KeyValueEntry
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.presentation.CredentialSelection
import ch.ubique.heidi.wallet.process.presentation.PresentationProcessKt
import io.ktor.client.HttpClient
import io.ktor.http.Url
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.dsl.module
import uniffi.heidi_wallet_rust.AgentInfo
import uniffi.heidi_wallet_rust.ApiException
import uniffi.heidi_wallet_rust.VerifiableCredential
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

//TODO: cleanup the code e.g. remove unneeded references and such
//TODO: make more smaller functions
@OptIn(ExperimentalTime::class)
@Deprecated("Use PresentationController for remote presentation. Will be removed once Proximity is migrated to the new ProcessStep pipeline")
class LegacyPresentationController private constructor(
	private val credentialsRepository: CredentialsRepository,
	private val identityRepository: IdentityRepository,
	private val activityRepository: ActivityRepository,
	private val client: HttpClient,
	private val credentialStore: CredentialStore,
	private val signingProvider: SigningProvider,
	private val viewModelFactory: ViewModelFactory,
	private val keyValueRepository: KeyValueRepository,
	private val json: Json,
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				LegacyPresentationController(
					get(),
					get(),
					get(),
					get(),
					get(),
					get(),
					get(),
					get(),
					get(),
					scope,
				)
			}
		}
	}

	private val stateMutable = MutableStateFlow<PresentationWorkflow>(initialState())
	val state = stateMutable.asStateFlow()

	private var proximityWallet: ProximityWallet? = null

	private fun initialState() = PresentationWorkflow.Idle

	private val asyncJobs = mutableMapOf<String, Job>()
	private fun launchSingleJob(label: String, block: suspend () -> Unit) {
		asyncJobs[label]?.cancel()
		asyncJobs[label] = scope.launch(Dispatchers.IO) {
			block()
		}
	}

	fun resetState() {
		asyncJobs.values.forEach { it.cancel() }
		stateMutable.update { initialState() }

		proximityWallet?.disconnect()
		proximityWallet = null
	}

	fun startProximityPresentationWithQrCode(
		qrCodeData: String,
		//TODO: UBAF use booleans to decide the presentation flow
		trustedConnectionAlwaysAsk: Boolean,
		untrustedConnectionAlwaysAsk: Boolean,
	) {
		stateMutable.update { PresentationWorkflow.Loading(state.value) }

		launchSingleJob(::startProximityPresentationWithQrCode.name) {
			try {
				val parameters = Url(qrCodeData).parameters
				val verifierName = requireNotNull(parameters["name"])
				val publicKey = requireNotNull(parameters["key"])
				val serviceUuid = requireNotNull(parameters["uuid"])

				proximityWallet = ProximityWallet.create(ProximityProtocol.OPENID4VP, scope, serviceUuid)

				proximityWallet?.startEngagement(verifierName)

				val trustData = TrustData.Verification(
					baseUrl = verifierName,
					identity = null,
					identityJwt = null,
					verification = null,
					verificationJwt = null,
					isTrusted = false,
					isVerified = false
				)
				collectProximityWalletState(trustData)
			} catch (e: ApiException) {
				stateMutable.update {
					val innerError = e.asErrorState()
					PresentationWorkflow.Error(innerError.code, e)
				}
			} catch (e: Exception) {
				stateMutable.update {
					PresentationWorkflow.Error(e.message ?: e::class.simpleName ?: "Internal Error", retry = ::resetState)
				}
			}
		}
	}

	private fun collectProximityWalletState(trustData: TrustData.Verification) {
		launchSingleJob(::collectProximityWalletState.name) {
			proximityWallet?.walletState?.collect { state ->
				when (state) {
					is ProximityWalletState.Initial -> stateMutable.update { PresentationWorkflow.Idle }
					is ProximityWalletState.ReadyForEngagement -> TODO("Not yet supported")
					is ProximityWalletState.Connecting -> stateMutable.update { PresentationWorkflow.Loading(stateMutable.value) }
					is ProximityWalletState.Connected -> stateMutable.update { PresentationWorkflow.Loading(stateMutable.value) }
					is ProximityWalletState.RequestingDocuments -> {
						when (val request = state.request) {
							is DocumentRequest.Mdl -> TODO("Not yet supported")
							is DocumentRequest.OpenId4Vp -> continueProximityWithCredentialSelection(
								trustData,
								request.parJwt
							)
						}
					}
					is ProximityWalletState.SubmittingDocuments -> stateMutable.update { PresentationWorkflow.Loading(stateMutable.value) }
					is ProximityWalletState.PresentationCompleted -> stateMutable.update { PresentationWorkflow.Success("Successfully presented credential") }
					is ProximityWalletState.Disconnected -> {
						proximityWallet = null
						resetState()
					}
					is ProximityWalletState.Error -> stateMutable.update {
						PresentationWorkflow.Error(
							state.throwable.message ?: state.throwable::class.simpleName ?: "Proximity Error", retry = ::resetState
						)
					}
				}
			}
		}
	}

	private fun continueProximityWithCredentialSelection(trustData: TrustData.Verification, parJwt: String) {
		stateMutable.update { PresentationWorkflow.Loading(stateMutable.value) }

		launchSingleJob(::continueProximityWithCredentialSelection.name) {
			try {
				val process = PresentationProcessKt.initializeProximity(parJwt, client, signingProvider)
				val agentInfo = process.getAgentInfo()

				continueWithCredentialSelection(trustData, process, agentInfo)

			} catch (e: ApiException) {
				stateMutable.update {
					val innerError = e.asErrorState()
					PresentationWorkflow.Error(innerError.code, e)
				}
			} catch (e: Exception) {
				stateMutable.update {
					PresentationWorkflow.Error(e.message ?: e::class.simpleName ?: "Internal Error", retry = ::resetState)
				}
			}
		}
	}

	private fun continueWithCredentialSelection(
		trustData: TrustData.Verification,
		process: PresentationProcessKt,
		agentInfo: AgentInfo,
	) {
		stateMutable.update {
			PresentationWorkflow.Loading(stateMutable.value)
		}

		launchSingleJob(::continueWithCredentialSelection.name) {
			try {
				val allIdentities = getAllIdentities().mapNotNull { viewModelFactory.getIdentityUiModel(it) }
				val schemaIds = trustData.verification?.schemaIds
					?: trustData.verification?.schemaId?.let { listOf(it) }
					?: emptyList()

				// Load credentials that have not yet been used
				val requestedLoA = agentInfo.getRequestedLoa()

				val unusedCredentials = getMatchingCredentials(process, schemaIds, false, Clock.System.now())
					.map {
						it.filterForRequestedLoa(requestedLoA)
					}

				if (unusedCredentials.isEmpty()) {
					//TODO: With DCQL we can have multiple different credential sets with multiple
					// options each. It is not clear how we should refresh which credentials...
					stateMutable.update { PresentationWorkflow.NoMatchingCredential }
				} else {
					val credentialUseCaseList = unusedCredentials.map { cs ->
						when (cs) {
							is CredentialSelection.ProximityCredentialSelection -> {
								throw NotImplementedError("Proximty selection should be in new flow")
							}
                            is CredentialSelection.DcqlCredentialSelection -> {
								//TODO: handle multiple sets
								CredentialUseCaseUiModel(
                                    cs.purpose,
                                    cs.dcqlSetOptions.setOptions[0].associate {
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
                                                if(credentialQuery == null) {
                                                    stateMutable.update {
                                                        PresentationWorkflow.Error("Matching Credential query not found; this should not happen")
                                                    }
                                                    return@launchSingleJob
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
									val key = it.map { it.responseId }.firstOrNull() ?: "<NO_CREDENTIAL>"
									key to
									it.map { matchingCredential->
										allIdentities.first { identity ->
											identity is IdentityUiModel.IdentityUiCredentialModel && identity.credentials.map { it.id }.contains(matchingCredential.credential.id)
										}.let { identity ->
											val ocaBundleUrl = credentialsRepository.getById(matchingCredential.credential.id)?.fk_oca_bundle_url
											viewModelFactory.getPresentableCredentialUiModel(matchingCredential, identity, ocaBundleUrl)
										}
									}
								}, cs)
							}
                        }
					}

					val viewmodel = PresentationUiModel(
						process.getClientId(),
						credentialUseCaseList,
						"",
						"",
						agentInfo.getRequestedLoa(),
						process.getAuthorizationRequestForDiagnostics(),
					)

					stateMutable.update {
						PresentationWorkflow.CredentialSelection(
							trustData,
							process,
							viewmodel,
							proximityWallet != null,
							::continueWithSelectedCredential
						)
					}
				}
			} catch (e: ApiException) {
				stateMutable.update {
					val innerError = e.asErrorState()
					PresentationWorkflow.Error(innerError.code, e)
				}
			} catch (e: Exception) {
				stateMutable.update {
					PresentationWorkflow.Error(e.message ?: e::class.simpleName ?: "Internal Error", retry = ::resetState)
				}
			}
		}
	}

	private fun getMatchingCredentials(
		process: PresentationProcessKt,
		schemaId: List<String>?,
		used: Boolean,
		validAt: Instant?,
	): List<CredentialSelection> {
		// TODO UBMW: Proximity
//		val credentials = if (proximityWallet != null) {
		val credentials = if (true) {
			// Return all credentials without checking for the schemaId for proximity only for showcase
			credentialStore.getAllWhere(used)
		} else {
			schemaId?.let { schemaIds ->
				schemaIds.fold(mutableListOf()) { accumulator, value ->
					accumulator.addAll(credentialStore.getAllWhereSchemaId(used, value))
					accumulator
				}
			} ?: emptyList()
		}
		return process.getMatchingCredentials(credentials, validAt)
	}

	private fun continueWithPinOrPassphrase(
		trustData: TrustData.Verification,
		process: PresentationProcessKt,
		credentialsWithPin: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		credentialsWithFrost: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
	) {
		val c = credentialsWithPin.pop()
		if(c != null) {
			stateMutable.update {
				PresentationWorkflow.EnterPin(
					trustData,
					process,
					c,
					credentialsWithPin,
					credentialsWithFrost,
					::continueWithPinOrPassphrase
				)
			}
		} else {
			val d = credentialsWithFrost.pop()
			if(d != null) {
				val frostBlob = identityRepository.getById(d.value.credential.identityId)?.frostBlob
				//TODO: what happens if this is null?
				if(frostBlob != null) {
					process.putFrost(d.key, frostBlob)
				}
				stateMutable.update {
					PresentationWorkflow.EnterPassphrase(trustData, process, d, credentialsWithFrost, ::continueWithPinOrPassphrase)
				}
			} else {
				finalizeWithSelectedCredential(trustData,process)
			}
		}
	}

	private fun continueWithSelectedCredential(
		trustData: TrustData.Verification,
		process: PresentationProcessKt,
		credentialMapping: HashMap<String, CredentialSelectionUiModel>,
	) {
		stateMutable.update { PresentationWorkflow.Loading(state.value) }

		try {
			//TODO: check for schema id?
			val schemaId = trustData.verification?.schemaIds ?: trustData.verification?.schemaId?.let { listOf(it)} ?: listOf()

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
			for(entry in credentialMapping) {
				process.putVerifiableCredential(entry.key, entry.value.credential)
				process.putVerificationContent(entry.key,json.encodeToString(entry.value.values.map { attr ->
					LocalizedKeyValue(
						attr.attributeName,
						attr.attributeValue?.asString() ?: "",
						attr.label
					)
				}))
				entry.value.presentableCredential?.let {
					process.putPresentableCredential(entry.key, it)
				}
			}

			continueWithPinOrPassphrase(trustData,process,credentialsWithPin, credentialsWithFrost)
		} catch (e: ApiException) {
			stateMutable.update {
				val innerError = e.asErrorState()
				PresentationWorkflow.Error(innerError.code, e)
			}
		} catch (e: Exception) {
			stateMutable.update {
				PresentationWorkflow.Error(e.message ?: e::class.simpleName ?: "Internal Error", retry = ::resetState)
			}
		}
	}

	private fun finalizeWithSelectedCredential(
		trustData: TrustData.Verification,
		process: PresentationProcessKt,
	) {
		stateMutable.update {
			PresentationWorkflow.Loading(stateMutable.value)
		}

		launchSingleJob(::finalizeWithSelectedCredential.name) {
			try {
				val email = keyValueRepository.getFor(KeyValueEntry.BACKUP_EMAIL_USED)
				val result = process.presentCredentials(email, false)
				if(result is PresentationWorkflow.Success) {
					val usedCredentials = process.getUsedCredentials()
					for (c in usedCredentials) {
						val cred : VerifiableCredential? = c["credential"].transform()
						if (cred == null) {
							stateMutable.update { PresentationWorkflow.Error("Credential has invalid format") }
							return@launchSingleJob
						}
						val content: String = c["content"].asString() ?: "{}"

						// Only use the credential if it is refreshable
						val identity = identityRepository.getById(cred.identityId)
						val isRefreshable = identity?.tokens?.refreshToken != null
						val isClaimBound = cred.decodeMetadata()?.keyMaterial is KeyMaterial.Local.ClaimBased
						if (!isClaimBound && isRefreshable && cred.decodeMetadata()?.credentialType != CredentialType.BbsTermwise) {
							credentialsRepository.useCredential(cred.id)
						}

						activityRepository.insertVerification(content, trustData.identityJwt,
							trustData.verificationJwt,
							trustData.isVerified,
							trustData.isTrusted,
							cred.identityId,
							cred.id,
							SWISS_TRUST_FRAMEWORK_ID
							)
					}
				}
				stateMutable.update { result }
			} catch (e: ApiException) {
				stateMutable.update {
					val innerError = e.asErrorState()
					PresentationWorkflow.Error(innerError.code, e)
				}
			} catch (e: Exception) {
				Logger.debug(msg = e.stackTraceToString())
				stateMutable.update {
					PresentationWorkflow.Error(e.message ?: e::class.simpleName ?: "Internal Error", retry = ::resetState)
				}
			}
		}
	}

	private fun getAllIdentities() = identityRepository.getAll()
}
