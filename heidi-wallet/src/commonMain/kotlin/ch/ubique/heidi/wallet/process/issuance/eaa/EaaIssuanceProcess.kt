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

package ch.ubique.heidi.wallet.process.issuance.eaa

import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.identity.IdentityModel
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial

import ch.ubique.heidi.credentials.models.metadata.Tokens
import ch.ubique.heidi.issuance.metadata.data.CredentialConfiguration
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.util.random.RandomGenerator
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.layout.deferredCard
import ch.ubique.heidi.visualization.oca.model.OcaBundleJson
import ch.ubique.heidi.visualization.oca.processing.OcaProcessor
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.credential.DeferredCredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.issuer.IssuerRepository
import ch.ubique.heidi.wallet.credentials.metadata.asMetadataFormat
import ch.ubique.heidi.wallet.credentials.metadata.fromNative
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccessControl
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.environment.EnvironmentController
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.extensions.decodeMetadata
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.issuance.IssuanceProcess
import io.ktor.client.plugins.ClientRequestException
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.*
import uniffi.heidi_wallet_rust.*

open class EaaIssuanceProcess(
    private val signingProvider: SigningProvider,
    private val issuerRepository: IssuerRepository,
    private val identityRepository: IdentityRepository,
    private val activityRepository: ActivityRepository,
    private val secureHardwareAccess: SecureHardwareAccess,
    private val keyValueRepository: KeyValueRepository,
    private val viewModelFactory: ViewModelFactory,
    private val json: Json,
    trustController: TrustFrameworkController,
    private val credentialsRepository: CredentialsRepository,
    private val deferredCredentialsRepository: DeferredCredentialsRepository,
    private val ocaRepository: OcaRepository,
    private val ocaServiceController: OcaServiceController,
    private val db: HeidiDatabase,
) : IssuanceProcess(
    trustController,
    credentialsRepository,
    deferredCredentialsRepository,
    ocaRepository,
    ocaServiceController,
    json,
) {

    private lateinit var issuance: Oid4VciIssuance

    suspend fun startIssuance(
        credentialOfferString: String,
    ): EaaIssuanceProcessStep {
        return try {
            initializeMetadata(credentialOfferString).getOrThrow()

            EaaIssuanceProcessStep.ConnectionDetails(trustFlow.agentInformation)
        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(
                errorMessage = info.messageOrCode,
                errorCode = info.code,
                cause = info.cause
            )
        }catch (e: ClientRequestException) {
            if (e.response.status == HttpStatusCode.NotFound) {
                EaaIssuanceProcessStep.Error(
                    errorMessage = "The credential offer is expired. Please regenerate it and try again.",
                    errorCode = e.response.status.value.toString(),
                    cause = e
                )
            } else {
                EaaIssuanceProcessStep.Error(
                    errorMessage = e.message,
                    errorCode = e.response.status.value.toString(),
                    cause = e
                )
            }
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun startDeferred(transactionId: String): EaaIssuanceProcessStep {
        return try {
            val identityEntity =
                deferredCredentialsRepository.getIdentityForTransactionId(transactionId)!!
            val identity = identityRepository.getById(identityEntity.id)!!
            val deferredCredential = deferredCredentialsRepository.getForTransactionId(transactionId)!!
            val subjects = deferredCredential.decodeMetadata()!!
            val credentialIssuerMetadata : CredentialIssuerMetadata = json.decodeFromString(identity.issuer.credentialIssuerMetadata)
            trustFlowFromSaved(credentialIssuerMetadata.claims.credentialIssuer, json.decodeFromString(identity.credentialConfigurationIds!!), credentialIssuerMetadata)

            val oidcMetadata =
                OidcMetadata(
                    identity.oidcSettings ?: "",
                    identity.issuer.credentialIssuerMetadata,
                    identity.issuer.authorizationServerMetadata,
                    identity.credentialConfigurationIds ?: "",
                )
            val walletBackend = WalletBackend(EnvironmentController.getHsmBackendUrl())

            val dpopSigner =
                secureHardwareAccess.getHardwareSigner(identity.tokens.dpopKeyReference)!!

            issuance = Oid4VciIssuance.fromMetadata(oidcMetadata, walletBackend, dpopSigner)
            val everything =  issuance.pollDeferredCredentials(
                DeviceBoundTokens(
                    identity.tokens.accessToken,
                    identity.tokens.refreshToken,
                    null,
                    identity.tokens.dpopKeyReference
                ), transactionId
            )
			val credentials = everything.credentials()
			if (credentials.isNotEmpty()) {
				val credentialInsertions = mutableListOf<CredentialInsertion>()
				for ((credential, signer) in credentials zip subjects) {
					val metadata = signer.copy(credentialType = credential.credential.asMetadataFormat())
					val insertion = buildCredentialInsertion(identity.name, credential, metadata) ?: continue
					credentialInsertions += insertion
				}

				val insertedCredentialIds = db.transactionWithResult {
					val result = credentialInsertions.mapNotNull { insertion ->
						executeCredentialInsertion(insertion)?.id
					}
                    deferredCredentialsRepository.useTransactionId(transactionId)
					return@transactionWithResult result
				}

                if (insertedCredentialIds.isNotEmpty()) {
                    activityRepository.insertIssuance(
                        baseUrl = trustFlow.agentInformation.domain,
                        identityJwt = trustFlow.agentInformation.identityTrust,
                        issuanceJwt = trustFlow.agentInformation.issuanceTrust,
                        isVerified = trustFlow.agentInformation.isVerified,
                        isTrusted = trustFlow.agentInformation.isTrusted,
                        identityId = identity.id,
                        credentialId = insertedCredentialIds.last(),
                        trustFlow.agentInformation.trustFrameworkId
                    )

                    val updatedIdentity = identityRepository.getById(identity.id)
                    if (updatedIdentity == null) {
                        EaaIssuanceProcessStep.Error("Failed to insert identity")
                    } else {
                        val uiModel = viewModelFactory.getIdentityUiModel(updatedIdentity)
                        if (uiModel != null) {
                            EaaIssuanceProcessStep.CredentialOffer(trustFlow.agentInformation, uiModel)
                        } else {
                            EaaIssuanceProcessStep.Error("Inserted identity could not be parsed")
                        }
                    }
                } else {
                    EaaIssuanceProcessStep.Error("No credentials inserted")
                }
            } else {
                EaaIssuanceProcessStep.Error(errorMessage = "Not Ready")
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun loadCredentialPreview(oidcSettings: OidcSettings): EaaIssuanceProcessStep {
        return try {
            // For software key use SoftwareKeyPair().asNativeSigner()
            val signer = signingProvider.createHardwareSigner(SecureHardwareAccessControl.NONE)
            val walletBackend = WalletBackend(EnvironmentController.getHsmBackendUrl())
            issuance = Oid4VciIssuance.initIssuance(oidcSettings, walletBackend, signer)

            val credOfferJson = json.encodeToString(credentialOffer)
            val authType = issuance.getCredentialOfferAuthTypeWithCredentialOfferJson(credOfferJson)
            when (authType) {
                is CredentialOfferAuthType.PreAuthorized -> {
                    continueWithEaaIssuance()
                }

                else -> {
                    EaaIssuanceProcessStep.CredentialOfferPreview(
                        trustFlow.agentInformation,
                        authType
                    )
                }
            }

        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun continueWithEaaIssuance(): EaaIssuanceProcessStep {
        return try {
            val credentialOfferJson = json.encodeToString(credentialOffer)
            // Use the already parsed credential offer to avoid fetching it twice
            val authorizationStep = issuance.initializeIssuanceWithCredentialOfferJson(
                credentialOfferJson,
                authorizationServerMetadata.codeChallengeMethodsSupported,
                authorizationServerMetadata.authorizationChallengeEndpoint != null,
                authorizationServerMetadata.pushedAuthorizationRequestEndpoint,
                authorizationServerMetadata.authorizationEndpoint,
                authorizationServerMetadata.authorizationChallengeEndpoint,
                null,
                authorizationServerMetadata.tokenEndpointAuthMethodsSupported,
            )

            when (authorizationStep) {
                is AuthorizationStep.None -> {
                    finalizeEaaIssuance()
                }

                is AuthorizationStep.EnterTransactionCode -> {
                    EaaIssuanceProcessStep.TransactionCode(
                        isNumeric = authorizationStep.numeric,
                        length = authorizationStep.length?.toInt(),
                        description = authorizationStep.description
                    )
                }

                is AuthorizationStep.BrowseUrl -> {
                    EaaIssuanceProcessStep.PushedAuthorization(authorizationStep.url)
                }

                is AuthorizationStep.Finished -> {
                    finalizeEaaIssuance(authorizationCode = authorizationStep.code)
                }

                is AuthorizationStep.WithPresentation -> {
                    EaaIssuanceProcessStep.Presentation(
                        authorizationStep.presentation,
                        authorizationStep.scope,
                        authorizationStep.authSession
                    )
                }
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun continueAfterPresentation(
        authSession: String,
        scope: String,
        pdiSession: String?
    ): EaaIssuanceProcessStep {
        return try {
            val step = issuance.continueAuthorization(
                authSession,
                scope,
                authorizationServerMetadata.authorizationChallengeEndpoint,
                pdiSession,
            )

            if (step is AuthorizationStep.Finished) {
                finalizeEaaIssuance(authorizationCode = step.code)
            } else {
                EaaIssuanceProcessStep.Error(errorMessage = "Unexpected error, we did not get code after presentation")
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun finalizeEaaIssuance(
        transactionCode: String? = null,
        authorizationCode: String? = null
    ): EaaIssuanceProcessStep {
        return try {
            // Always fallback to 1 credential, if the batch credential endpoint isn't available
            var numberOfCredentials =
                credentialIssuerMetadata.claims.batchCredentialIssuance?.batchSize?.let { it / 2 }
                    ?: 1
			numberOfCredentials = maxOf(numberOfCredentials, 1)

            val credentials = issuance.finalizeIssuance(
                code = authorizationCode,
                txCode = transactionCode,
                numCredentialsPerType = numberOfCredentials.toUInt(),
                signerFactory = object : SignerFactory {
                    override fun newSigner(keyType: KeyType) =
                        signingProvider.createSigner(keyType)
                            ?: throw Exception("Could not create signer for key type: ${keyType.name}")
                },
                authorizationServerMetadata.dpopSigningAlgValuesSupported,
                authorizationServerMetadata.tokenEndpoint,
                // if the authorization code is null, we are in a preauthorized code flow
                authorizationCode == null
            )

            val tokens = Tokens.fromNative(credentials.tokens())
            val oidcMetadata = issuance.getOidcMetadata()

            val issuer = issuerRepository.insert(
                issuance.getIssuerUrl(),
                oidcMetadata.credentialIssuerMetadata,
                json.encodeToString(authorizationServerMetadata),
            )

            val identityName = RandomGenerator().generateAlphanumericString(15)
            val identity = identityRepository.insertIdentity(
                identityName,
                tokens,
                oidcMetadata.oidcSettings,
                issuer.url,
                oidcMetadata.credentialConfigurationIds,
                isPid = false
            )
            //TODO: currently we only ever have one configuration if deferred issuance
            // we should make deferred issuance a bit more lenient to all the possible values
            if (credentials.transactionIds().isNotEmpty()) {
                val d = credentials.deferred().first()
                val credConfig =
                    credentialIssuerMetadata.claims.credentialConfigurationsSupported[d.credentialConfigurationId]
                val credentialMetadatas = credentials.subjects().map { signer ->
                    if (signer.privateKeyExportable()) {
                        CredentialMetadata(
                            keyMaterial = KeyMaterial.Local.SoftwareBacked(
                                privateKey = signer.privateKey()
                            ),
                            credentialType = when (credConfig?.format) {
                                "dc+sd-jwt", "vc+sd-jwt" -> CredentialType.SdJwt
                                "mso_mdoc" -> CredentialType.Mdoc
                                "zkp_vc" -> CredentialType.BbsTermwise
                                "jwt_vc_json" -> CredentialType.W3C_VCDM
                                else -> CredentialType.Unknown
                            }
                        )
                    } else {
                        CredentialMetadata(
                            keyMaterial = KeyMaterial.Local.HardwareBacked(
                                deviceKeyReference = signer.keyReference(),
                                publicKey = signer.publicKey()
                            ),
                            credentialType = when (credConfig?.format) {
                                "dc+sd-jwt", "vc+sd-jwt" -> CredentialType.SdJwt
                                "mso_mdoc" -> CredentialType.Mdoc
                                "zkp_vc" -> CredentialType.BbsTermwise
                                "jwt_vc_json" -> CredentialType.W3C_VCDM
                                else -> CredentialType.Unknown
                            }
                        )
                    }
                }
                val doctype = when (credConfig) {
                    is CredentialConfiguration.Mdoc -> credConfig.doctype
                    is CredentialConfiguration.SdJwt -> credConfig.vct
                    is CredentialConfiguration.SdJwtVcdm -> ""
                    is CredentialConfiguration.Unknown -> ""
                    null -> ""
                }

                val deferredEntry = insertDeferredCredential(
                    identityName,
                    d.transactionCode,
                    doctype,
                    credentialMetadatas
                )

                return if (deferredEntry == null) {
                    EaaIssuanceProcessStep.Error("Failed to insert identity")
                } else {
                    val updatedIdentity = identityRepository.getById(identity.id)
                    val card = extractDeferredCardDetails(updatedIdentity, identityName, ocaServiceController, ocaRepository)
                    val uiModel = viewModelFactory.getIdentityUiModel(deferredEntry, card)

                    if (uiModel != null) {
                        EaaIssuanceProcessStep.CredentialOffer(trustFlow.agentInformation, uiModel)
                    } else {
                        EaaIssuanceProcessStep.Error("Inserted identity could not be parsed")
                    }
                }
            }


            val insertedCredentialIds = if (credentials.subjects().isNotEmpty()) {
                (credentials.credentials() zip credentials.subjects()).mapNotNull { (credential, signer) ->

                    val credentialMetadata = if (signer.privateKeyExportable()) {
                        CredentialMetadata(
                            keyMaterial = KeyMaterial.Local.SoftwareBacked(
                                privateKey = signer.privateKey()
                            ),
                            credentialType = credential.credential.asMetadataFormat()
                        )
                    } else {
                        CredentialMetadata(
                            keyMaterial = KeyMaterial.Local.HardwareBacked(
                                deviceKeyReference = signer.keyReference(),
                                publicKey = signer.publicKey()
                            ),
                            credentialType = credential.credential.asMetadataFormat()
                        )
                    }

                    val insertedCredential =
                        insertCredential(identity.name, credential, credentialMetadata)
                    return@mapNotNull insertedCredential?.id
                }
            } else {
                credentials.credentials().mapNotNull { credential ->
                    val credentialMetadata = CredentialMetadata(KeyMaterial.Local.ClaimBased(), credential.credential.asMetadataFormat())
                    val insertedCredential =
                        insertCredential(identity.name, credential, credentialMetadata)
                    return@mapNotNull insertedCredential?.id
                }
            }


            if (insertedCredentialIds.isNotEmpty()) {
                activityRepository.insertIssuance(
                    baseUrl = trustFlow.agentInformation.domain,
                    identityJwt = trustFlow.agentInformation.identityTrust,
                    issuanceJwt = trustFlow.agentInformation.issuanceTrust,
                    isVerified = trustFlow.agentInformation.isVerified,
                    isTrusted = trustFlow.agentInformation.isTrusted,
                    identityId = identity.id,
                    credentialId = insertedCredentialIds.last(),
                    trustFlow.agentInformation.trustFrameworkId
                )

                val updatedIdentity = identityRepository.getById(identity.id)
                if (updatedIdentity == null) {
                    EaaIssuanceProcessStep.Error("Failed to insert identity")
                } else {
                    val uiModel = viewModelFactory.getIdentityUiModel(updatedIdentity)
                    if (uiModel != null) {
                        EaaIssuanceProcessStep.CredentialOffer(trustFlow.agentInformation, uiModel)
                    } else {
                        EaaIssuanceProcessStep.Error("Inserted identity could not be parsed")
                    }
                }
            } else {
                EaaIssuanceProcessStep.Error("No credentials inserted")
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    fun acceptCredentialOffer(): EaaIssuanceProcessStep {
        // TODO We currently import the credentials before the user accepts the credential offer. Ideally
        //     we would check the signed metadata and use the display to create a credential preview before the process
        //     starts.
        return EaaIssuanceProcessStep.Success
    }

    private suspend fun extractDeferredCardDetails(updatedIdentity: IdentityModel?, identityName: String, ocaServiceController: OcaServiceController, ocaRepository: OcaRepository) : LayoutData.Card {
        val json = Json { ignoreUnknownKeys = true }

        if (updatedIdentity != null) {
            val jsonElem = updatedIdentity.issuer.credentialIssuerMetadata.let {
                json.parseToJsonElement(
                    it
                )
            }
            val ids = updatedIdentity.credentialConfigurationIds
                ?.let { json.parseToJsonElement(it) }
                ?.jsonArray

            val id = ids?.firstOrNull()?.jsonPrimitive?.content
            val credConfigs = jsonElem.jsonObject["credential_configurations_supported"]!!.jsonObject
            val selectedConfig = id?.let { credConfigs[it] }?.jsonObject

            if (selectedConfig != null) {
                val vctUrl = selectedConfig["vct"].toString()
                val vctJson = runCatching { ocaServiceController.getDataFromUrl(vctUrl) }.getOrNull() ?: return deferredCard(identityName)
                val ocaUrl = findUriRecursively(Json.parseToJsonElement(vctJson), "oca")
                val ocaJson = ocaUrl?.let { runCatching {   ocaServiceController.getDataFromUrl(it) }.getOrNull() } ?: return deferredCard(identityName)

                ocaRepository.insertOrUpdateOca(identityName, ocaJson)
                val ocaProcessor = OcaProcessor(userLanguage = viewModelFactory.getStringResourceProvider().getString("language_key"), payload = ocaJson, ocaBundle = json.decodeFromString<OcaBundleJson>(ocaJson))
                return ocaProcessor.process(LayoutType.CARD) as LayoutData.Card
            }
        }
        return deferredCard(identityName)
    }

    private fun findUriRecursively(element: JsonElement?, key: String): String? {
        return when (element) {
            is JsonObject -> {
                if (key in element) {
                    val ocaObj = element[key]
                    if (ocaObj is JsonObject) {
                        return ocaObj["uri"]?.jsonPrimitive?.contentOrNull
                    }
                }
                element.values.firstNotNullOfOrNull { findUriRecursively(it, key) }
            }
            is JsonArray -> {
                element.firstNotNullOfOrNull { findUriRecursively(it, key) }
            }
            else -> null
        }
    }
}
