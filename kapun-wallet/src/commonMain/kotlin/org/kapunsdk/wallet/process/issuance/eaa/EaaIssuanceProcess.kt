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

package org.kapunsdk.wallet.process.issuance.eaa

import org.kapunsdk.credentials.models.credential.CredentialMetadata
import org.kapunsdk.credentials.models.credential.CredentialType
import org.kapunsdk.credentials.models.identity.IdentityModel
import org.kapunsdk.credentials.models.metadata.KeyMaterial

import org.kapunsdk.credentials.models.metadata.Tokens
import org.kapunsdk.issuance.metadata.data.CredentialConfiguration
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.trust.TrustFrameworkController
import org.kapunsdk.util.random.RandomGenerator
import org.kapunsdk.visualization.layout.LayoutData
import org.kapunsdk.visualization.layout.LayoutType
import org.kapunsdk.visualization.layout.deferredCard
import org.kapunsdk.visualization.oca.model.OcaBundleJson
import org.kapunsdk.visualization.oca.processing.OcaProcessor
import org.kapunsdk.wallet.KapunDatabase
import org.kapunsdk.wallet.credentials.ViewModelFactory
import org.kapunsdk.wallet.credentials.activity.ActivityRepository
import org.kapunsdk.wallet.credentials.credential.CredentialsRepository
import org.kapunsdk.wallet.credentials.credential.DeferredCredentialsRepository
import org.kapunsdk.wallet.credentials.identity.IdentityRepository
import org.kapunsdk.wallet.credentials.issuer.IssuerRepository
import org.kapunsdk.wallet.credentials.metadata.asMetadataFormat
import org.kapunsdk.wallet.credentials.metadata.fromNative
import org.kapunsdk.wallet.credentials.oca.OcaRepository
import org.kapunsdk.wallet.credentials.oca.networking.OcaServiceController
import org.kapunsdk.wallet.crypto.SecureHardwareAccess
import org.kapunsdk.wallet.crypto.SecureHardwareAccessControl
import org.kapunsdk.wallet.crypto.SigningProvider
import org.kapunsdk.wallet.environment.EnvironmentController
import org.kapunsdk.wallet.extensions.asErrorState
import org.kapunsdk.wallet.extensions.decodeMetadata
import org.kapunsdk.wallet.keyvalue.KeyValueRepository
import io.ktor.client.plugins.ClientRequestException
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.*
import uniffi.kapun_wallet_rust.*

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
    private val db: KapunDatabase,
) : org.kapunsdk.wallet.process.issuance.IssuanceProcess(
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
    ): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
        return try {
            initializeMetadata(credentialOfferString).getOrThrow()

            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.ConnectionDetails(trustFlow.agentInformation)
        } catch (e: ApiException) {
            val info = e.asErrorState()
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = info.messageOrCode,
                errorCode = info.code,
                cause = info.cause
            )
        }catch (e: ClientRequestException) {
            if (e.response.status == HttpStatusCode.NotFound) {
                _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                    errorMessage = "The credential offer is expired. Please regenerate it and try again.",
                    errorCode = e.response.status.value.toString(),
                    cause = e
                )
            } else {
                _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                    errorMessage = e.message,
                    errorCode = e.response.status.value.toString(),
                    cause = e
                )
            }
        } catch (e: Exception) {
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun startDeferred(transactionId: String): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
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
                        _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error("Failed to insert identity")
                    } else {
                        val uiModel = viewModelFactory.getIdentityUiModel(updatedIdentity)
                        if (uiModel != null) {
                            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.CredentialOffer(trustFlow.agentInformation, uiModel)
                        } else {
                            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error("Inserted identity could not be parsed")
                        }
                    }
                } else {
                    _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error("No credentials inserted")
                }
            } else {
                _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = "Not Ready")
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun loadCredentialPreview(oidcSettings: OidcSettings): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
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
                    _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.CredentialOfferPreview(
                        trustFlow.agentInformation,
                        authType
                    )
                }
            }

        } catch (e: ApiException) {
            val info = e.asErrorState()
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun continueWithEaaIssuance(): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
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
                    _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.TransactionCode(
                        isNumeric = authorizationStep.numeric,
                        length = authorizationStep.length?.toInt(),
                        description = authorizationStep.description
                    )
                }

                is AuthorizationStep.BrowseUrl -> {
                    _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.PushedAuthorization(authorizationStep.url)
                }

                is AuthorizationStep.Finished -> {
                    finalizeEaaIssuance(authorizationCode = authorizationStep.code)
                }

                is AuthorizationStep.WithPresentation -> {
                    _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Presentation(
                        authorizationStep.presentation,
                        authorizationStep.scope,
                        authorizationStep.authSession
                    )
                }
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun continueAfterPresentation(
        authSession: String,
        scope: String,
        pdiSession: String?
    ): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
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
                _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = "Unexpected error, we did not get code after presentation")
            }
        } catch (e: ApiException) {
            val info = e.asErrorState()
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
        } catch (e: Exception) {
            _root_ide_package_.org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep.Error(
                errorMessage = e.message ?: e::class.simpleName ?: "Unknown Error",
                cause = e
            )
        }
    }

    suspend fun finalizeEaaIssuance(
        transactionCode: String? = null,
        authorizationCode: String? = null
    ): org.kapunsdk.wallet.process.issuance.eaa.EaaIssuanceProcessStep {
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
                authorizationCode == null,
                authorizationServerMetadata.preAuthorizedGrandAnonymousAccessSupported ?: false
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

            val credentialInsertions = if (credentials.subjects().isNotEmpty()) {
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

                    buildCredentialInsertion(identity.name, credential, credentialMetadata)
                }
            } else {
                credentials.credentials().mapNotNull { credential ->
                    val credentialMetadata = CredentialMetadata(KeyMaterial.Local.ClaimBased(), credential.credential.asMetadataFormat())
                    buildCredentialInsertion(identity.name, credential, credentialMetadata)
                }
            }

            val insertedCredentialIds = db.transactionWithResult {
                val insertedIds = credentialInsertions.mapNotNull { insertion ->
                    executeCredentialInsertion(insertion)?.id
                }

                if (insertedIds.isNotEmpty()) {
                    activityRepository.insertIssuance(
                        baseUrl = trustFlow.agentInformation.domain,
                        identityJwt = trustFlow.agentInformation.identityTrust,
                        issuanceJwt = trustFlow.agentInformation.issuanceTrust,
                        isVerified = trustFlow.agentInformation.isVerified,
                        isTrusted = trustFlow.agentInformation.isTrusted,
                        identityId = identity.id,
                        credentialId = insertedIds.last(),
                        trustFlow.agentInformation.trustFrameworkId
                    )
                }

                insertedIds
            }


            if (insertedCredentialIds.isNotEmpty()) {

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
