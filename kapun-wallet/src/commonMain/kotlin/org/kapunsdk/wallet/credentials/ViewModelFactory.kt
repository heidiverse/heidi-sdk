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

package org.kapunsdk.wallet.credentials

import org.kapunsdk.credentials.Bbs
import org.kapunsdk.credentials.SdJwt
import org.kapunsdk.credentials.W3C
import org.kapunsdk.credentials.models.credential.CredentialMetadata
import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.credentials.models.credential.CredentialType
import org.kapunsdk.credentials.models.identity.DeferredIdentity
import org.kapunsdk.credentials.models.identity.IdentityModel
import org.kapunsdk.credentials.models.metadata.KeyAssurance
import org.kapunsdk.credentials.toJson
import org.kapunsdk.toReadableString
import org.kapunsdk.trust.revocation.RevocationCheck
import org.kapunsdk.util.extensions.asLong
import org.kapunsdk.util.extensions.asObject
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.jsonObjectOrNull
import org.kapunsdk.util.extensions.jsonPrimitiveOrNull
import org.kapunsdk.util.log.Logger
import org.kapunsdk.visualization.layout.LayoutData
import org.kapunsdk.visualization.layout.LayoutType
import org.kapunsdk.visualization.layout.deferredCard
import org.kapunsdk.visualization.oca.OcaType
import org.kapunsdk.visualization.oca.model.OcaBundleJson
import org.kapunsdk.visualization.oca.model.content.AttributeType
import org.kapunsdk.visualization.oca.processing.AttributeValue
import org.kapunsdk.visualization.oca.processing.OcaProcessor
import org.kapunsdk.visualization.oca.processing.ProcessedAttribute
import org.kapunsdk.wallet.credentials.activity.ActivityRepository
import org.kapunsdk.wallet.credentials.credential.CredentialUiModel
import org.kapunsdk.wallet.credentials.format.sdjwt.getRenderMetadata
import org.kapunsdk.wallet.credentials.identity.IdentityUiModel
import org.kapunsdk.wallet.credentials.mapping.FallbackIdentityMapper
import org.kapunsdk.wallet.credentials.mapping.OcaIdentityMapper
import org.kapunsdk.wallet.credentials.mapping.defaults.OcaBundleFactory
import org.kapunsdk.wallet.credentials.metadata.getPublicKey
import org.kapunsdk.wallet.credentials.metadata.toKeyAssurance
import org.kapunsdk.wallet.credentials.oca.OcaRepository
import org.kapunsdk.wallet.credentials.presentation.CredentialSelectionUiModel
import org.kapunsdk.wallet.process.presentation.ZkpOptions
import org.kapunsdk.wallet.resources.StringResourceProvider
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import org.kapunsdk.util.extensions.get
import org.kapunsdk.wallet.credentials.metadata.getPublicKey
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
import uniffi.kapun_crypto_rust.base64UrlDecode
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.getRequestedAttributes
import uniffi.kapun_wallet_rust.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Instant

class ViewModelFactory private constructor(
	private val activityRepository: org.kapunsdk.wallet.credentials.activity.ActivityRepository,
	private val ocaRepository: org.kapunsdk.wallet.credentials.oca.OcaRepository,
	private val ocaIdentityMapper: org.kapunsdk.wallet.credentials.mapping.OcaIdentityMapper,
	private val fallbackIdentityMapper: org.kapunsdk.wallet.credentials.mapping.FallbackIdentityMapper,
	private val json: Json,
	private val stringResourceProvider: StringResourceProvider,
) {
	companion object {
		private const val MAX_PRESENTATION_CACHE_ENTRIES = 64
		private val inMemoryCache = LinkedHashMap<String, org.kapunsdk.wallet.credentials.identity.IdentityUiModel?>()

		val koinModule = module {
			factoryOf(::ViewModelFactory)
		}
	}

	fun pruneIdentityCache(validIdentityNames: Set<String>) {
		inMemoryCache.keys.retainAll(validIdentityNames)
	}

	@OptIn(ExperimentalEncodingApi::class)
	fun getCredentialViewModel(
		credential: CredentialModel,
		frostBlob: String?,
	): org.kapunsdk.wallet.credentials.credential.CredentialUiModel {
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
            CredentialType.OpenBadge303 -> {
                val vc = W3C.OpenBadge303.parseSerialized(credential.payload).asJson()
                val validFrom = vc["validFrom"].asString()?.let { Instant.parse(it).epochSeconds }
                val validUntil = vc["validUntil"].asString()?.let { Instant.parse(it).epochSeconds }

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
            CredentialType.OpenBadge303 -> Json.encodeToString(
                W3C.OpenBadge303.parseSerialized(credential.payload).asJson())
            CredentialType.Unknown -> ""
		}

		val signatureVerified = when (credential.metadata.credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credential.payload).isSignatureValid()
			CredentialType.Mdoc -> null
			CredentialType.BbsTermwise -> null
			CredentialType.W3C_VCDM -> W3C.parse(credential.payload).isSignatureValid()
            CredentialType.OpenBadge303 -> W3C.OpenBadge303
                .parseSerialized(credential.payload)
                .isSignatureValid()
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
		inMemoryCache[identity.name]?.let {
			if (it.credentials.size == identity.credentials.size) {
				return it
			}
			val activities = activityRepository.getActivities(identity.credentials.map { it.id })
			val updated = when (it) {
				is IdentityUiModel.IdentityUiCredentialModel -> it.copy(
					name = identity.name,
					credentials = identity.credentials,
					activities = activities,
					frostBlob = identity.frostBlob,
					credentialUiModel = emptyList(),
				)
				is IdentityUiModel.IdentityUiDeferredModel -> it.copy(
					name = identity.name,
					credentials = identity.credentials,
					activities = activities,
					frostBlob = identity.frostBlob,
					credentialUiModel = emptyList(),
				)
			}
			inMemoryCache[identity.name] = updated
			trimPresentationCache()
			return updated
		}
		val activities = activityRepository.getActivities(identity.credentials.map { it.id })

		val credential = identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.SdJwt }
			?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.Mdoc }
			?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.BbsTermwise }
            ?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.W3C_VCDM }
            ?: identity.credentials.firstOrNull { it.metadata.credentialType == CredentialType.OpenBadge303 }
			?: return null
		var possibleSdJwt: SdJwt? = null
		var possibleBbs: Bbs? = null
		var possibleW3C: W3C? = null
        var possibleOpenBadge303: W3C.OpenBadge303? = null

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
            CredentialType.OpenBadge303 -> {
                possibleOpenBadge303 = W3C.OpenBadge303.parseSerialized(credential.payload)
                Json.encodeToString(possibleOpenBadge303.asJson())
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
                    CredentialType.OpenBadge303 -> continue // TODO: OpenBadges implement status list
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
                CredentialType.OpenBadge303 -> {
					val vc = possibleOpenBadge303 ?: return null
					val ocaType = OcaType.Reference("metadata://${vc.docType}")

					val overrides = mapOf(
						"~credentialImage" to AttributeValue.Image(
							value = vc.pngBytes,
							format = "image/png"
						)
					)

					return ocaIdentityMapper.mapIdentity(
						ocaRepository = ocaRepository,
						ocaType,
						identity,
						jsonContent,
						activities,
						identity.credentials,
						attributeValueOverrides = overrides,
					) ?: fallbackIdentityMapper.mapIdentity(
						CredentialType.OpenBadge303,
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
			trimPresentationCache()
			return newModel
		} catch (e: SerializationException) {
			Logger.error("Could not map identity", e)
			return null
		}
	}

	private fun trimPresentationCache() {
		while (inMemoryCache.size > MAX_PRESENTATION_CACHE_ENTRIES) {
			val oldestKey = inMemoryCache.entries.firstOrNull()?.key ?: break
			inMemoryCache.remove(oldestKey)
		}
	}

	fun getPresentableCredentialUiModelFromDcql(
		queryId: String,
		credentialQuery: CredentialQuery,
		verifiableCredential: VerifiableCredential,
		credential: Credential,
		identity: IdentityUiModel,
		ocaBundleUrl: String? = null,
		zkpOptions: org.kapunsdk.wallet.process.presentation.ZkpOptions?,
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
        val hiddenAttributesList = zkpOptions?.equalityProofClaims?.map { claim ->
            getDisclosurePath(claim.path.joinToString("/") { it.toReadableString() })
        } ?: emptyList()
		val attributes = mapPresentableValues(vm, hiddenAttributesList, processor)

		return CredentialSelectionUiModel(
			verifiableCredential.id,
			identity,
			attributes,
			credentialType,
			keyAssurance ?: KeyAssurance.SoftwareLow,
			verifiableCredential,
			responseId = queryId,
            requiresCryptographicHolderBinding = credentialQuery.requireCryptographicHolderBinding != false
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

		val attributes = mapPresentableValues(presentableCredential.values, emptyList(), processor)

		return CredentialSelectionUiModel(
			presentableCredential.credential.id,
			identity,
			attributes,
			credentialType,
			keyAssurance ?: KeyAssurance.SoftwareLow,
			presentableCredential.credential,
			presentableCredential,
			presentableCredential.responseId,
            requiresCryptographicHolderBinding = true
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
            CredentialType.OpenBadge303 -> Json.encodeToString(
                W3C.OpenBadge303.parseSerialized(credential.payload).asJson())
            CredentialType.Unknown -> return null
		}
	}

	private fun mapPresentableValues(
		map: Map<String, String>,
        hiddenAttributes: List<String>,
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
			val attribute = processor?.processAttribute(disclosurePath)
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
            attribute.copy(isHidden = hiddenAttributes.contains(disclosurePath))
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

private fun String.truncate(maxLimit: Int): String {
    return if (this.length > maxLimit) {
        this.take(maxLimit - 3) + "..."
    } else {
        this
    }
}
