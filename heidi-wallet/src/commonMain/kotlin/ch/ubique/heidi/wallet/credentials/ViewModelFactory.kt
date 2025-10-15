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

package ch.ubique.heidi.wallet.credentials

import ch.ubique.heidi.credentials.Bbs
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.identity.DeferredIdentity
import ch.ubique.heidi.credentials.models.identity.IdentityModel
import ch.ubique.heidi.credentials.models.metadata.KeyAssurance
import ch.ubique.heidi.credentials.toJson
import ch.ubique.heidi.trust.revocation.RevocationCheck
import ch.ubique.heidi.util.extensions.asLong
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.jsonObjectOrNull
import ch.ubique.heidi.util.extensions.jsonPrimitiveOrNull
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.layout.deferredCard
import ch.ubique.heidi.visualization.oca.OcaType
import ch.ubique.heidi.visualization.oca.model.OcaBundleJson
import ch.ubique.heidi.visualization.oca.model.content.AttributeType
import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import ch.ubique.heidi.visualization.oca.processing.OcaProcessor
import ch.ubique.heidi.visualization.oca.processing.ProcessedAttribute
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialUiModel
import ch.ubique.heidi.wallet.credentials.format.sdjwt.getRenderMetadata
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.credentials.mapping.FallbackIdentityMapper
import ch.ubique.heidi.wallet.credentials.mapping.OcaIdentityMapper
import ch.ubique.heidi.wallet.credentials.mapping.defaults.OcaBundleFactory
import ch.ubique.heidi.wallet.credentials.metadata.getPublicKey
import ch.ubique.heidi.wallet.credentials.metadata.toKeyAssurance
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.resources.StringResourceProvider
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.getRequestedAttributes
import uniffi.heidi_wallet_rust.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class ViewModelFactory private constructor(
	private val activityRepository: ActivityRepository,
	private val ocaRepository: OcaRepository,
	private val ocaIdentityMapper: OcaIdentityMapper,
	private val fallbackIdentityMapper: FallbackIdentityMapper,
	private val json: Json,
	private val stringResourceProvider: StringResourceProvider,
) {
	companion object {
		val koinModule = module {
			factoryOf(::ViewModelFactory)
		}
		val inMemoryCache = mutableMapOf<String, IdentityUiModel?>()
	}

	@OptIn(ExperimentalEncodingApi::class)
	fun getCredentialViewModel(
		credential: CredentialModel,
		frostBlob: String?,
	): CredentialUiModel {
		val publicKey = credential.metadata.keyMaterial.getPublicKey(frostBlob)?.let { Base64.encode(it) }
		val (iat, exp) = when (credential.metadata.credentialType) {
			CredentialType.SdJwt -> {
				val metadata = SdJwt.parse(credential.payload).getMetadata()
				metadata.issuedAt to metadata.expiresAt
			}
			CredentialType.Mdoc -> {
				val mdoc = mdocAsJsonRepresentation(credential.payload)?.let {
					json.parseToJsonElement(it)
				} as? JsonObject
				val iat = mdoc?.get("iat")?.jsonPrimitiveOrNull()?.longOrNull
				val exp = mdoc?.get("exp")?.jsonPrimitiveOrNull()?.longOrNull
				iat to exp
			}
			CredentialType.BbsTermwise -> {
				null to null
			}
			CredentialType.W3C_VCDM -> {
				val claims = W3C.parse(credential.payload).asJson()
				val validFrom = claims["iat"].asLong()
				val validUntil = claims["exp"].asLong()

				validFrom to validUntil
			}
			CredentialType.Unknown -> null to null
		}

		val jsonPayload = when (credential.metadata.credentialType) {
			CredentialType.SdJwt -> {
				SdJwt.parse(credential.payload).toJson()
			}
			CredentialType.Mdoc -> {
				mdocAsJsonRepresentation(credential.payload)
			}
			CredentialType.BbsTermwise -> runCatching {
				val cred = Json.parseToJsonElement(base64UrlDecode(credential.payload).decodeToString())
				val document = cred.jsonObject["document"]!!
				bbsJson(base64UrlDecode(document.jsonPrimitive.content).decodeToString())
			}.getOrNull() ?: ""
			CredentialType.W3C_VCDM -> Json.encodeToString(W3C.parse(credential.payload).asJson())
			CredentialType.Unknown -> ""
		}

		val signatureVerified = when (credential.metadata.credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credential.payload).isSignatureValid()
			CredentialType.Mdoc -> null
			CredentialType.BbsTermwise -> null
			CredentialType.W3C_VCDM -> W3C.parse(credential.payload).isSignatureValid()
			CredentialType.Unknown -> null
		}

		return CredentialUiModel(
			id = credential.id,
			type = credential.metadata.credentialType,
			storage = credential.metadata.keyMaterial.storage,
			keyMaterialType = credential.metadata.keyMaterial.type,
			publicKey = publicKey,
			uuid = credential.name,
			issuedAt = iat,
			expiresAt = exp,
			isUsed = credential.isUsed,
			jsonPayload = jsonPayload,
			originalPayload = credential.payload,
			signatureVerified = signatureVerified
		)
	}

	fun getIdentityUiModel(deferred: DeferredIdentity, card: LayoutData.Card = getDeferredCard(deferred.identityName)) : IdentityUiModel {
		return IdentityUiModel.IdentityUiDeferredModel(
			deferred.id,
			deferred.identityName,
			false,
			deferred.transactionId,
			deferred.docType,
			card = card,
			frostBlob = null,
			credentialUiModel = emptyList()
		)
	}

	//TODO: We need to also do this for mdoc only schemas
	//TODO: What about EAAs? How do we represent them? We should still use something like IdentityUiModel to combine them, but something less "personal identity" based
	fun getIdentityUiModel(identity: IdentityModel, revocationCheck: RevocationCheck? = null): IdentityUiModel? {
		val activities = activityRepository.getActivities(identity.credentials.map { it.id })
		inMemoryCache[identity.name]?.let {
			if (it.credentials.size == identity.credentials.size && it.activities.size == activities.size) {
				return it
			}
			return when (it) {
				is IdentityUiModel.IdentityUiCredentialModel -> it.copy(credentials =  identity.credentials, activities = activities)
				is IdentityUiModel.IdentityUiDeferredModel -> it.copy(credentials = identity.credentials, activities = activities)
			}
		}

		val credential = identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.SdJwt }
			?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.Mdoc }
			?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.BbsTermwise }
			?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.W3C_VCDM }
			?: return null
		var possibleSdJwt: SdJwt? = null
		var possibleBbs: Bbs? = null
		var possibleW3C: W3C? = null

		val credentialType = credential.metadata.credentialType
		val jsonContent = when (credentialType) {
			CredentialType.SdJwt -> {
				possibleSdJwt = runCatching {  SdJwt.parse(credential.payload) }.getOrNull() ?: return null
				possibleSdJwt.toJson()
			}
			//TODO: improve the mdocAsJsonRepresentation
			CredentialType.Mdoc -> mdocAsJsonRepresentation(credential.payload) ?: return null
			CredentialType.BbsTermwise -> runCatching {
				possibleBbs = Bbs.parse(credential.payload)
				json.encodeToString(possibleBbs.body())
			}.getOrNull() ?: return null
			CredentialType.W3C_VCDM -> {
				possibleW3C = W3C.parse(credential.payload)
				Json.encodeToString(possibleW3C.asJson())
			}
			CredentialType.Unknown -> return null
		}
		var isRevoked = false
		if(revocationCheck != null) {
			val usableCredentials = identity.credentials.filter { !it.isUsed }
			for(c in usableCredentials) {
				val newContent = when (credentialType) {
					CredentialType.SdJwt -> runCatching { SdJwt.parse(c.payload).toJson() }.getOrNull() ?: continue
					//TODO: improve the mdocAsJsonRepresentation
					CredentialType.Mdoc -> mdocAsJsonRepresentation(c.payload) ?: return null
					CredentialType.BbsTermwise -> continue
					CredentialType.W3C_VCDM -> Json.encodeToString(W3C.parse(c.payload).asJson())
					CredentialType.Unknown -> return null
				}
				val jsonElement = json.parseToJsonElement(newContent)
				val url = jsonElement.jsonObject["status"]?.jsonObjectOrNull()?.get("status_list")?.jsonObjectOrNull()?.get("uri")?.jsonPrimitiveOrNull()?.contentOrNull
				val index = jsonElement.jsonObject["status"]?.jsonObjectOrNull()?.get("status_list")?.jsonObjectOrNull()?.get("idx")?.jsonPrimitiveOrNull()?.longOrNull
				if(url != null && index != null) {
					//TODO: this should not be run blocking
					isRevoked = isRevoked || runBlocking { revocationCheck.check(url, index.toInt()) }
				}
			}
		}

		try {
			val jsonContent = jsonContent ?: return null
			val uiModel = when (credentialType) {
				CredentialType.SdJwt -> {
					val sdJwt = possibleSdJwt ?: return null
					val metadata = sdJwt.getMetadata()
					val renderMetadata = sdJwt.getRenderMetadata()
					val ocaType = renderMetadata?.render?.oca?.let { OcaType.Reference(it) }
						?: OcaBundleFactory.getBuiltInOcaType(metadata.vct)
                    ocaType?.let {
						ocaIdentityMapper.mapIdentity(
							ocaRepository = ocaRepository,
							it,
							identity,
							jsonContent,
							activities,
							identity.credentials
						)
                    } ?: fallbackIdentityMapper.mapIdentity(
						CredentialType.SdJwt,
						identity,
						jsonContent,
						activities,
						identity.credentials
					)
				}
				CredentialType.Mdoc -> {
					val jsonElement = json.parseToJsonElement(jsonContent)
					if (jsonElement is JsonObject) {
//						val ocaType = OcaBundleFactory.getBuiltInOcaType(credential.docType)
						//TODO make mdoc only identity mapper for known types
						val ocaType = identity.credentials.firstOrNull()?.let {  OcaType.BuiltIn.FromMetadata("metadata://${it.docType}") }
						ocaType?.let {
							ocaIdentityMapper.mapIdentity(
								ocaRepository = ocaRepository,
								it,
								identity,
								jsonContent,
								activities,
								identity.credentials
							)
						} ?: fallbackIdentityMapper.mapIdentity(
							CredentialType.SdJwt,
							identity,
							jsonContent,
							activities,
							identity.credentials
						)
					} else {
						fallbackIdentityMapper.mapIdentity(
							CredentialType.Mdoc,
							identity,
							jsonContent,
							activities,
							identity.credentials
						)
					}
				}
				CredentialType.BbsTermwise -> {
					val bbs = possibleBbs ?: return null
					val ocaType = bbs.body()["http://schema.org/ocaUrl"].asString()?.let { OcaType.Reference(it) } ?: identity.credentials.firstOrNull()?.let {  OcaType.BuiltIn.FromMetadata("metadata://${it.docType}") }
					ocaType?.let {
						ocaIdentityMapper.mapIdentity(
							ocaRepository = ocaRepository,
							it,
							identity,
							jsonContent,
							activities,
							identity.credentials
						)
					} ?: fallbackIdentityMapper.mapIdentity(
						CredentialType.SdJwt,
						identity,
						jsonContent,
						activities,
						identity.credentials
					)
				}

				CredentialType.W3C_VCDM -> {
					val cred = possibleW3C ?: return null
					val ocaType = cred.asJson()["render"]["oca"].asString()?.let { OcaType.Reference(it) }
						?: OcaBundleFactory.getBuiltInOcaType(cred.docType)

					ocaType?.let {
						ocaIdentityMapper.mapIdentity(
							ocaRepository = ocaRepository,
							it,
							identity,
							jsonContent,
							activities,
							identity.credentials
						)
					} ?: fallbackIdentityMapper.mapIdentity(
						CredentialType.W3C_VCDM,
						identity,
						jsonContent,
						activities,
						identity.credentials
					)
				}
				CredentialType.Unknown -> null
			}
			val newModel = uiModel?.copy(isRevoked = isRevoked)
			inMemoryCache[identity.name] = newModel
			return newModel
		} catch (e: SerializationException) {
			Logger.error("Could not map identity", e)
			return null
		}
	}

	fun getPresentableCredentialUiModelFromDcql(
		queryId: String,
		credentialQuery: CredentialQuery,
		verifiableCredential: VerifiableCredential,
		credential: Credential,
		identity: IdentityUiModel,
		ocaBundleUrl: String? = null,
	): CredentialSelectionUiModel {
		val metadata = CredentialMetadata.fromString(verifiableCredential.metadata)
		val credentialType = metadata?.credentialType ?: CredentialType.Unknown
		val keyAssurance = metadata?.keyMaterial?.toKeyAssurance()

		// Try to get the OCA Bundle for this credential
		val ocaJson = ocaBundleUrl?.let { ocaRepository.getForUrl(it) }?.content
		val ocaBundle = ocaJson?.let { runCatching { json.decodeFromString<OcaBundleJson>(ocaJson) }.getOrNull() }

		val processor = ocaBundle?.let { bundle ->
			val jsonPayload = getCredentialJsonPayload(verifiableCredential)
			val languageKey = stringResourceProvider.getString("language_key")
			jsonPayload?.let { OcaProcessor(languageKey, it, bundle) }
		}

		val valueMaps = getRequestedAttributes(credentialQuery, credential)
		val vm = valueMaps.asObject()!!.mapValues { Json.encodeToString(it) }
		val attributes = mapPresentableValues(vm, processor)

		return CredentialSelectionUiModel(
			verifiableCredential.id,
			identity,
			attributes,
			credentialType,
			keyAssurance ?: KeyAssurance.SoftwareLow,
			verifiableCredential,
			responseId = queryId
		)

	}

	fun getPresentableCredentialUiModel(
		presentableCredential: PresentableCredential,
		identity: IdentityUiModel,
		ocaBundleUrl: String? = null,
	): CredentialSelectionUiModel {
		val metadata = CredentialMetadata.fromString(presentableCredential.credential.metadata)
		val credentialType = metadata?.credentialType ?: CredentialType.Unknown
		val keyAssurance = metadata?.keyMaterial?.toKeyAssurance()

		// Try to get the OCA Bundle for this credential
		val ocaJson = ocaBundleUrl?.let { ocaRepository.getForUrl(it) }?.content
		val ocaBundle = ocaJson?.let { runCatching { json.decodeFromString<OcaBundleJson>(ocaJson) }.getOrNull() }

		val processor = ocaBundle?.let { bundle ->
			val jsonPayload = getCredentialJsonPayload(presentableCredential.credential)
			val languageKey = stringResourceProvider.getString("language_key")
			jsonPayload?.let { OcaProcessor(languageKey, it, bundle) }
		}

		val attributes = mapPresentableValues(presentableCredential.values, processor)

		return CredentialSelectionUiModel(
			presentableCredential.credential.id,
			identity,
			attributes,
			credentialType,
			keyAssurance ?: KeyAssurance.SoftwareLow,
			presentableCredential.credential,
			presentableCredential,
			presentableCredential.responseId

		)
	}

	fun getStringResourceProvider(): StringResourceProvider {
		return stringResourceProvider
	}

	private fun getCredentialJsonPayload(credential: VerifiableCredential): String? {
		val metadata = CredentialMetadata.fromString(credential.metadata) ?: return null
		val credentialType = metadata.credentialType
		return when (credentialType) {
			CredentialType.SdJwt -> runCatching { SdJwt.parse(credential.payload).toJson()}.getOrNull() ?: return null
			//TODO: improve the mdocAsJsonRepresentation
			CredentialType.Mdoc -> mdocAsJsonRepresentation(credential.payload) ?: return null
			CredentialType.BbsTermwise -> runCatching {
				val cred = Json.parseToJsonElement(base64UrlDecode(credential.payload).decodeToString())
				val document = cred.jsonObject["document"]!!
				bbsJson(base64UrlDecode(document.jsonPrimitive.content).decodeToString())!!
			}.getOrNull() ?: return null
			CredentialType.W3C_VCDM -> Json.encodeToString(W3C.parse(credential.payload).asJson())
			CredentialType.Unknown -> return null
		}
	}

	private fun mapPresentableValues(
		map: Map<String, String>,
		processor: OcaProcessor?,
	): List<ProcessedAttribute> {
		val mDocTranslation = mapOf(
			"/given_name" to "label_firstname",
			"/age_in_years" to "label_age_in_years",
			"/age_over_12" to "label_age_over_12",
			"/nationality" to "label_nationality",
			"/age_over_18" to "label_age_over_18",
			"/age_over_14" to "label_age_over_14",
			"/age_over_16" to "label_age_over_16",
			"/age_over_21" to "label_age_over_21",
			"/family_name" to "label_lastname",
			"/family_name_birth" to "label_birth_lastname",
			"/birth_date" to "label_birthdate",
			"/age_over_65" to "label_age_over_65",
			"/issuing_authority" to "label_issuing_authority",
			"/birth_place" to "label_birthplace",
			"/issuing_country" to "label_issuing_country",
			"/age_birth_year" to "label_birth_year",
			"/resident_city" to "label_resident_city",
			"/resident_postal_code" to "label_resident_postal_code",
			"/resident_street" to "label_resident_street"
		)

		val sdJwtTranslations = mapOf(
			"/given_name" to "label_firstname",
			"/age_in_years" to "label_age_in_years",
			"/age_equal_or_over/12" to "label_age_over_12",
			"/nationalities" to "label_nationality",
			"/age_equal_or_over/18" to "label_age_over_18",
			"/age_equal_or_over/14" to "label_age_over_14",
			"/age_equal_or_over/16" to "label_age_over_16",
			"/age_equal_or_over/21" to "label_age_over_21",
			"/family_name" to "label_lastname",
			"/birth_family_name" to "label_birth_lastname",
			"/birthdate" to "label_birthdate",
			"/age_equal_or_over/65" to "label_age_over_65",
			"/issuing_authority" to "label_issuing_authority",
			"/place_of_birth/locality" to "label_birthplace",
			"/issuing_country" to "label_issuing_country",
			"/age_birth_year" to "label_birth_year",
			"/address/locality" to "label_resident_city",
			"/address/postal_code" to "label_resident_postal_code",
			"/address/street_address" to "label_resident_street"
		)

		val maps = listOf(mDocTranslation, sdJwtTranslations)

		val localizedKeyValues = map.map { entry ->
			val disclosurePath = getDisclosurePath(entry.key)

			// Try to use the OCA processor to process the attribute or fallback to the old manual mapping
			processor?.processAttribute(disclosurePath)
				?: processor?.processAttribute(disclosurePath.trim('/'))
				?: run {
					val name = disclosurePath.trim('/')
					val value = runCatching { unwrapPresentableValue(entry.value) } .getOrNull() ?: entry.value
					val label = maps.firstNotNullOfOrNull { it[disclosurePath] } ?: name
					ProcessedAttribute(
						attributeName = name,
						attributeType = AttributeType.Text,
						attributeValue = AttributeValue.Text(value),
						label = label
					)
				}
		}

		return sortProcessedAttributes(localizedKeyValues)
	}

	private fun unwrapPresentableValue(jsonString: String): String {
		return when (val jsonElement = Json.parseToJsonElement(jsonString)) {
			is JsonPrimitive -> {
				// Check if the JsonPrimitive is a double and remove .0 if it has no fractional part
				jsonElement.doubleOrNull?.let {
					if (it.toLong().toDouble() == it) {
						it.toLong().toString()
					} else {
						jsonElement.content
					}
				} ?: jsonElement.content
			}
			is JsonArray -> {
				if (jsonElement.isNotEmpty()) {
					unwrapPresentableValue(jsonElement.first().toString())
				} else {
					""
				}
			}
			is JsonObject -> {
				jsonElement["countryName"]?.let {
					unwrapPresentableValue(it.toString())
				} ?: jsonElement["value"]?.let {
					unwrapPresentableValue(it.toString())
				} ?: jsonElement.values.firstOrNull()?.let {
					unwrapPresentableValue(it.toString())
				} ?: ""
			}

		}
	}

	private fun sortProcessedAttributes(values: List<ProcessedAttribute>): List<ProcessedAttribute> {
		val importanceOrder = listOf(
			"label_firstname",
			"label_lastname",
			"label_birth_lastname",
			"label_birthdate",
			"label_nationality",
			"label_issuing_country",
			"label_issuing_authority",
			"label_birthplace",
			"label_resident_city",
			"label_resident_street",
			"label_resident_postal_code",
			"label_birth_year",
			"label_age_in_years",
			"label_age_over_12",
			"label_age_over_14",
			"label_age_over_16",
			"label_age_over_18",
			"label_age_over_21",
			"label_age_over_65"
		)

		val importanceMap = importanceOrder.withIndex().associate { it.value to it.index }

		return values.sortedWith(compareBy { importanceMap[it.attributeName] ?: Int.MAX_VALUE })
	}

	private fun getDeferredCard(identityName: String) : LayoutData.Card {
		val ocaBundleModel = ocaRepository.getForUrl(identityName)
		val oca_json = ocaBundleModel?.content

		if (oca_json == null) {
			return deferredCard(identityName)
		}

		val ocaProcessor = OcaProcessor(userLanguage = stringResourceProvider.getString("language_key"), payload = oca_json.toString(), ocaBundle = json.decodeFromString<OcaBundleJson>(oca_json.toString()))
		return ocaProcessor.process(LayoutType.CARD) as LayoutData.Card
	}
}
