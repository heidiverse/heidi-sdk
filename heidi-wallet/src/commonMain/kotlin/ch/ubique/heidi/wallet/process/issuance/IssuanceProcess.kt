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

package ch.ubique.heidi.wallet.process.issuance

import ch.ubique.heidi.credentials.Bbs
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.identity.DeferredIdentity
import ch.ubique.heidi.credentials.models.metadata.KeyMaterialType
import ch.ubique.heidi.issuance.credential.offer.CredentialOfferParameters
import ch.ubique.heidi.issuance.credential.offer.CredentialOfferRepository
import ch.ubique.heidi.issuance.metadata.MetadataRepository
import ch.ubique.heidi.issuance.metadata.data.AuthorizationServerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadataClaims
import ch.ubique.heidi.trust.TrustFlow
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.random.RandomGenerator
import ch.ubique.heidi.wallet.CredentialEntity
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.credential.DeferredCredentialsRepository
import ch.ubique.heidi.wallet.credentials.format.mdoc.MdocUtils
import ch.ubique.heidi.wallet.credentials.format.sdjwt.getRenderMetadata
import ch.ubique.heidi.wallet.credentials.metadata.asMetadataFormat
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import io.ktor.client.plugins.ResponseException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_wallet_rust.Credential
import uniffi.heidi_wallet_rust.CredentialFormat
import uniffi.heidi_wallet_rust.bbsJson
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
abstract class IssuanceProcess(
	private val trustController: TrustFrameworkController,
	private val credentialsRepository: CredentialsRepository,
	private val deferredCredentialsRepository: DeferredCredentialsRepository,
	private val ocaRepository: OcaRepository,
	private val ocaServiceController: OcaServiceController,
	private val json: Json,
) {

	private val credentialOfferRepository = CredentialOfferRepository()
	private val metadataRepository = MetadataRepository()

	protected lateinit var credentialOfferString: String
	protected lateinit var credentialOffer: CredentialOfferParameters
	protected lateinit var credentialIssuerMetadata: CredentialIssuerMetadata
	protected lateinit var authorizationServerMetadata: AuthorizationServerMetadata
	protected lateinit var trustFlow: TrustFlow

	protected suspend fun initializeMetadata(credentialOfferString: String): Result<Unit> {
		this.credentialOfferString = credentialOfferString
		credentialOffer = credentialOfferRepository.parseCredentialOffer(credentialOfferString)
			?: return Result.failure(IllegalArgumentException("Invalid credential offer string"))

		credentialIssuerMetadata = metadataRepository.getCredentialIssuerMetadata(credentialOffer.credentialIssuer)

		val authorizationServerUrl = metadataRepository.getAuthorizationServerBaseUrl(
			credentialIssuerMetadata.claims.authorizationServers ?: emptyList(),
			credentialOffer
		) ?: return Result.failure(IllegalStateException("No authorization server found"))
		authorizationServerMetadata = metadataRepository.getAuthorizationServerMetadata(authorizationServerUrl)

		trustFlow = startTrustFlow().getOrElse { return Result.failure(it) }

		return Result.success(Unit)
	}
	protected suspend fun trustFlowFromSaved(credentialIssuer :String, credentialConfigurationIds: List<String>, credentialIssuerMetadata: CredentialIssuerMetadata): Result<Unit> {
		trustFlow =  runCatching {
			trustController.startIssuanceFlow(
				credentialIssuer,
				credentialConfigurationIds,
				credentialIssuerMetadata
			)
		}.getOrElse { return Result.failure(it) }
		return Result.success(Unit)
	}

	protected open suspend fun startTrustFlow(): Result<TrustFlow> {
		return runCatching {
			trustController.startIssuanceFlow(
				credentialOffer.credentialIssuer,
				credentialOffer.credentialConfigurationIds,
				credentialIssuerMetadata
			)
		}
	}

	protected fun insertDeferredCredential(identityName: String, transactionId: String, docType: String, metadatas: List<CredentialMetadata>) : DeferredIdentity? {
		return deferredCredentialsRepository.insert(identityName,transactionId, json.encodeToString(metadatas), docType)
	}

	protected data class CredentialInsertion(
		val identityName: String,
		val credentialName: String,
		val metadataJson: String,
		val keyMaterialType: KeyMaterialType,
		val credentialType: CredentialType,
		val payload: String,
		val docType: String,
		val ocaBundleUrl: String?,
	)

	protected suspend fun buildCredentialInsertion(
		identityName: String,
		credential: Credential,
		metadata: CredentialMetadata,
	): CredentialInsertion? {
		val ocaBundleUrl =
			loadOcaBundleForCredential(credential) ?: loadOcaFromMetadata(credentialIssuerMetadata.claims, credential, metadata)

		val credentialType = credential.credential.asMetadataFormat()
		val credentialPayload = credential.credential.getPayload()

		val docType = when (credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credential.credential.getPayload()).getMetadata().vct
			CredentialType.Mdoc -> MdocUtils.getDocType(credentialPayload)
			CredentialType.BbsTermwise -> runCatching {
				// TODO: Get Issuer Id / Public Key / ... Metadata
				val cred = Json.parseToJsonElement(base64UrlDecode(credentialPayload).decodeToString())
				val document = cred.jsonObject["document"]!!
				val bbs = Json.parseToJsonElement( bbsJson(base64UrlDecode(document.jsonPrimitive.content).decodeToString()) ?: "{}")
				bbs.jsonObject["https://www.w3.org/2018/credentials#credentialSubject"]!!.jsonObject["@id"]!!.jsonPrimitive.content
			}.getOrNull() ?: return null
			CredentialType.W3C_VCDM -> W3C.parse(credential.credential.getPayload()).docType
            CredentialType.OpenBadge303 -> W3C.OpenBadge303
                .parseSerialized(credential.credential.getPayload())
                .docType
			CredentialType.Unknown -> {
				// Don't insert this credential if it's an unknown type
				return null
			}
		}

		return CredentialInsertion(
			identityName = identityName,
			credentialName = RandomGenerator().generateAlphanumericString(12),
			metadataJson = json.encodeToString(metadata),
			keyMaterialType = metadata.keyMaterial.type,
			credentialType = credentialType,
			payload = credentialPayload,
			docType = docType,
			ocaBundleUrl = ocaBundleUrl,
		)
	}

	protected fun executeCredentialInsertion(insertion: CredentialInsertion): CredentialEntity? {
		return credentialsRepository.insertCredential(
			name = insertion.credentialName,
			metadata = insertion.metadataJson,
			keyMaterialType = insertion.keyMaterialType,
			credentialType = insertion.credentialType,
			payload = insertion.payload,
			docType = insertion.docType,
			ocaBundleUrl = insertion.ocaBundleUrl,
			identityName = insertion.identityName,
		)
	}

	protected suspend fun insertCredential(
		identityName: String,
		credential: Credential,
		metadata: CredentialMetadata,
	): CredentialEntity? {
		val insertion = buildCredentialInsertion(identityName, credential, metadata) ?: return null
		return executeCredentialInsertion(insertion)
	}

	private suspend fun loadOcaFromMetadata(
        credentialIssuerMetadata: CredentialIssuerMetadataClaims,
        credential: Credential,
        metadata: CredentialMetadata,
	): String? {
		val credentialType = credential.credential.asMetadataFormat()
		val credentialPayload = when (credential.credential) {
			is CredentialFormat.Mdoc -> credential.credential.v1
			is CredentialFormat.SdJwt -> credential.credential.v1
			is CredentialFormat.BbsTermWise -> credential.credential.v1
			is CredentialFormat.W3c -> credential.credential.v1
            is CredentialFormat.OpenBadge -> credential.credential.v1
		}
		val docType = when (credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credentialPayload).getMetadata().vct
			CredentialType.Mdoc -> MdocUtils.getDocType(credentialPayload)
			CredentialType.BbsTermwise -> return null
			CredentialType.W3C_VCDM -> W3C.parse(credentialPayload).docType
            CredentialType.OpenBadge303 -> W3C.OpenBadge303
                .parse(Base64.UrlSafe.decode(credentialPayload)).docType
            CredentialType.Unknown -> {
				// Don't insert this credential if it's an unknown type
				return null
			}
		}
		val ocaBundle = ocaServiceController.getOcaFromMetadata("de", credentialIssuerMetadata, credential, metadata) ?: return null
		val ocaUrl = "metadata://$docType"
		ocaRepository.insertOrUpdateOca(ocaUrl, ocaBundle)
		return ocaUrl
	}

	private suspend fun loadOcaBundleForCredential(credential: Credential): String? {
		val credentialFormat = credential.credential
		val ocaUrl = when (credentialFormat) {
			is CredentialFormat.SdJwt -> {
				val sdJwt = SdJwt.parse(credential.credential.getPayload())
				val renderMetadata = sdJwt.getRenderMetadata()
				renderMetadata?.render?.oca
			}
			is CredentialFormat.Mdoc -> return null
			is CredentialFormat.BbsTermWise -> {
				val bbs = Bbs.parse(credential.credential.getPayload()).body()
				bbs["http://schema.org/ocaUrl"].asString()
			}
			is CredentialFormat.W3c -> {
				val cred = W3C.parse(credential.credential.getPayload())
				cred.asJson()["render"]["oca"].asString()
			}
            is CredentialFormat.OpenBadge -> return null
		}

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

		return null
	}

	private fun CredentialFormat.getPayload(): String {
		return when (this) {
			is CredentialFormat.Mdoc -> this.v1
			is CredentialFormat.SdJwt -> this.v1
			is CredentialFormat.BbsTermWise -> this.v1
			is CredentialFormat.W3c -> this.v1
            is CredentialFormat.OpenBadge -> this.v1
		}
	}

}
