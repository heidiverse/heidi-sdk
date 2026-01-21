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

package ch.ubique.heidi.wallet.process.refresh.eaa

import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.credentials.models.metadata.Tokens
import ch.ubique.heidi.issuance.metadata.data.AuthorizationServerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.util.extensions.json
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.util.random.RandomGenerator
import ch.ubique.heidi.wallet.CredentialEntity
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.format.mdoc.MdocUtils
import ch.ubique.heidi.wallet.credentials.format.sdjwt.getRenderMetadata
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.credentials.metadata.asMetadataFormat
import ch.ubique.heidi.wallet.credentials.metadata.fromNative
import ch.ubique.heidi.wallet.credentials.metadata.toNative
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.environment.EnvironmentController
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.keyvalue.KeyValueEntry
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import io.ktor.client.plugins.ResponseException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_wallet_rust.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class EaaRefreshProcess(
	private val trustController: TrustFrameworkController,
	private val credentialsRepository: CredentialsRepository,
	private val identityRepository: IdentityRepository,
	private val secureHardwareAccess: SecureHardwareAccess,
	private val signingProvider: SigningProvider,
	private val ocaRepository: OcaRepository,
	private val ocaServiceController: OcaServiceController,
	private val activityRepository: ActivityRepository,
	private val keyValueRepository: KeyValueRepository,
) {

	suspend fun startEaaRefresh(identityUiModel: IdentityUiModel): EaaRefreshProcessStep {
		if (identityUiModel !is IdentityUiModel.IdentityUiCredentialModel) {
			return EaaRefreshProcessStep.Error("Identity not found")
		}
		val identity = identityRepository.getById(identityUiModel.id) ?: return EaaRefreshProcessStep.Error("Identity not found")
		if (identity.tokens.refreshToken == null) {
			return EaaRefreshProcessStep.Error("Identity cannot be refreshed (no refresh token)")
		}
		try {
			val authorizationServerMetadata = identity.issuer.authorizationServerMetadata?.let {
				val json = Json {
					ignoreUnknownKeys = true
					explicitNulls = false
				}
				json.decodeFromString<AuthorizationServerMetadata>(it)
			}

			val oidcMetadata = OidcMetadata(
				identity.oidcSettings ?: "",
				identity.issuer.credentialIssuerMetadata,
				identity.issuer.authorizationServerMetadata,
				identity.credentialConfigurationIds ?: "",
			)
			val credentialIssuerMetadata: CredentialIssuerMetadata? =
				runCatching { json.decodeFromString<CredentialIssuerMetadata>(identity.issuer.credentialIssuerMetadata) }.getOrNull()
			val walletBackend = WalletBackend(EnvironmentController.getHsmBackendUrl())
			val dpopSigner = secureHardwareAccess.getHardwareSigner(identity.tokens.dpopKeyReference)!!
			val issuance = Oid4VciIssuance.fromMetadata(oidcMetadata, walletBackend, dpopSigner)
			val tokens = issuance.refreshToken(
				identity.tokens.toNative(),
				authorizationServerMetadata?.tokenEndpoint,
				authorizationServerMetadata?.tokenEndpointAuthMethodsSupported,
				authorizationServerMetadata?.dpopSigningAlgValuesSupported,
				null,
			)

			val agentInformation = credentialIssuerMetadata?.let {
				trustController.startIssuanceFlow(
					it.credentialIssuer,
					identity.credentialConfigurationIds?.let { json.decodeFromString<List<String>>(it) } ?: emptyList(),
					it
				).agentInformation
			}

			identityRepository.updateTokens(identity.id, Tokens.fromNative(tokens))
			val numberOfCredentials =
				credentialIssuerMetadata?.batchCredentialIssuance?.batchSize?.let { it.toUInt() / 2u } ?: keyValueRepository.getFor(
					KeyValueEntry.MAX_CREDENTIALS
				)
					?.toUIntOrNull() ?: 1u

			val credentials = issuance.supplementIssuance(
				tokens = tokens,
				numCredentialsPerType = numberOfCredentials,
				dpopSigningAlgValuesSupported = authorizationServerMetadata?.dpopSigningAlgValuesSupported,
				signerFactory = object : SignerFactory {
					override fun newSigner(keyType: KeyType) = requireNotNull(signingProvider.createSigner(keyType))
				},
				true
			)

			val insertedCredentialIds =
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

					val insertedCredential = insertCredential(identity.name, credential, credentialMetadata)
					return@mapNotNull insertedCredential?.id
				}

			if (insertedCredentialIds.isNotEmpty()) {
				// TODO UBMW: Insert agent information instead of trust data
				activityRepository.insertIssuance(
					baseUrl = agentInformation?.domain ?: "",
					identityJwt =  agentInformation?.identityTrust,
					issuanceJwt = agentInformation?.issuanceTrust,
					isVerified = agentInformation?.isVerified ?: false,
					isTrusted = agentInformation?.isTrusted ?: false,
					identityId = identity.id,
					frameworkId = agentInformation?.trustFrameworkId,
					credentialId = insertedCredentialIds.last()
				)
			} else {
				Logger.error("No refreshed credentials")
			}
		} catch (e: ApiException) {
			Logger.error("ApiException " + e.asErrorState().code)
			Logger.error(e.stackTraceToString())
			val info = e.asErrorState()
			return EaaRefreshProcessStep.Error(errorMessage = info.messageOrCode, errorCode = info.code, cause = info.cause)
		} catch (e: Exception) {
			Logger.error("Exception: " + (e.message ?: e::class.simpleName))
			Logger.error(e.stackTraceToString())
			return EaaRefreshProcessStep.Error(e.message ?: e::class.simpleName ?: "")
		}

		return EaaRefreshProcessStep.Success
	}

	private suspend fun loadOcaBundleForCredential(credential: Credential): String? {
		val credentialFormat = credential.credential
		if (credentialFormat.asMetadataFormat() == CredentialType.SdJwt) {
			val sdJwt = SdJwt.parse(credential.credential.getPayload())
			val renderMetadata = sdJwt.getRenderMetadata()
			val ocaUrl = renderMetadata?.render?.oca
			if (ocaUrl != null) {
				val existing = ocaRepository.getForUrl(ocaUrl)

				val now = Clock.System.now().toEpochMilliseconds()
				if (existing == null || now - existing.updatedAt >= 5.minutes.inWholeMilliseconds) {
					try {
						val ocaBundle = ocaServiceController.getOcaBundleForUrl(ocaUrl)
						ocaRepository.insertOrUpdateOca(ocaUrl, ocaBundle)
					} catch (e: ResponseException) {
						return null
					}
				}
				return ocaUrl
			}
		}
		return null
	}

	protected suspend fun insertCredential(
		identityName: String,
		credential: Credential,
		metadata: CredentialMetadata,
	): CredentialEntity? {
		val ocaBundleUrl = loadOcaBundleForCredential(credential)

		val credentialType = credential.credential.asMetadataFormat()
		val credentialPayload = credential.credential.getPayload()

		val docType = when (credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credential.credential.getPayload()).getMetadata().vct
			CredentialType.Mdoc -> MdocUtils.getDocType(credentialPayload)
			CredentialType.BbsTermwise -> kotlin.runCatching {
				val cred = Json.parseToJsonElement(base64UrlDecode(credentialPayload).decodeToString())
				val document = cred.jsonObject["document"]!!
				val bbs = Json.parseToJsonElement( bbsJson(base64UrlDecode(document.jsonPrimitive.content).decodeToString()) ?: "{}")
				bbs.jsonObject["https://www.w3.org/2018/credentials#credentialSubject"]!!.jsonObject["@id"]!!.jsonPrimitive.content

			}.getOrNull() ?: return null
			CredentialType.W3C_VCDM -> W3C.parse(credentialPayload).docType
            CredentialType.OpenBadge303 -> W3C.OpenBadge303.parseSerialized(credentialPayload).docType
            CredentialType.Unknown -> {
				// Don't insert this credential if it's an unknown type
				return null
			}
		}

		val credentialName = RandomGenerator().generateAlphanumericString(12)
		return credentialsRepository.insertCredential(
			name = credentialName,
			metadata = json.encodeToString(metadata),
			keyMaterialType = metadata.keyMaterial.type,
			credentialType = credentialType,
			payload = credentialPayload,
			docType = docType,
			ocaBundleUrl = ocaBundleUrl,
			identityName = identityName,
		)
	}

	private fun CredentialFormat.getPayload(): String {
		return when (this) {
			is CredentialFormat.Mdoc -> this.v1
			is CredentialFormat.SdJwt -> this.v1
			is CredentialFormat.BbsTermWise -> this.v1
			is CredentialFormat.W3c -> this.v1
		}
	}
}
