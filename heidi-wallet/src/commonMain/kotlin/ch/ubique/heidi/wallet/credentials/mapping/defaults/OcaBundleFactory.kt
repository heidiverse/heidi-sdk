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

package ch.ubique.heidi.wallet.credentials.mapping.defaults

import ch.ubique.heidi.issuance.extensions.getLocalizedLabel
import ch.ubique.heidi.issuance.metadata.data.CredentialConfiguration
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialMetadataClaim
import ch.ubique.heidi.issuance.metadata.data.Display
import ch.ubique.heidi.visualization.oca.OcaType
import ch.ubique.heidi.visualization.oca.model.CaptureBase
import ch.ubique.heidi.visualization.oca.model.OcaBundleJson
import ch.ubique.heidi.visualization.oca.model.SAID_HASH_PLACEHOLDER
import ch.ubique.heidi.visualization.oca.model.content.AttributeType
import ch.ubique.heidi.visualization.oca.model.content.Encoding
import ch.ubique.heidi.visualization.oca.model.content.TextShade
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.ClusterOrderingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.UbiqueStyleJsonOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.CharacterEncodingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.FormatOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.InformationOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.LabelOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.TemplateOverlay
import ch.ubique.heidi.visualization.stylejson.model.StyleJson
import ch.ubique.heidi.wallet.resources.StringResourceProvider
import io.ktor.util.toLowerCasePreservingASCIIRules
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.*

internal object OcaBundleFactory {
	val dateTimeRegex =
		Regex("(\\d\\d\\d\\d[-.]\\d\\d[-.]\\d\\d|\\d\\d[-.]\\d\\d[-.]\\d\\d\\d\\d)(.?\\d\\d:\\d\\d((:\\d\\d(\\.\\d+)?)?(Z|[+-]\\d\\d:\\d\\d)?)?)?")
	val hiddenProperties = listOf("/cnf", "/_sd", "/...", "/_sd_alg")

	fun getBuiltInOcaType(vct: String): OcaType.BuiltIn? {
		return when (vct) {
			"eu.europa.ec.eudi.pid.1",
			"urn:eu.europa.ec.eudi:pid:1",
			"https://example.bmi.bund.de/credential/pid/1.0",
			"https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
				-> OcaType.BuiltIn.EuPid
			"betaid-sdjwt" -> OcaType.BuiltIn.SwissBetaId
			else -> OcaType.BuiltIn.FromMetadata("metadata://$vct")
		}
	}

	/**
	 * Create a OCA Bundle from a metadata display field
	 *
	 *  @param vct The vct for which we want an OCA
	 */
	@OptIn(ExperimentalStdlibApi::class)
	fun createOcaFromDisplayMetadata(
		locale: String,
		stringResourceProvider: StringResourceProvider,
		backgroundImage: String?,
		metadata: CredentialIssuerMetadata?,
		vct: String,
		jsonContent: String,
	): OcaBundleJson? {
		val captureBaseSaid = ""
		val propertyType = mutableMapOf<String, AttributeType>()
		val attributeEncoding = mutableMapOf<String, Encoding>()
		val obj = runCatching { Json.decodeFromString<JsonObject>(jsonContent) }.getOrNull() ?: return null
		addKeysAndTypesForObject(obj, propertyType, attributeEncoding, "")
		val captureBase = CaptureBase(attributes = propertyType)
		val credentialMetadata = metadata?.credentialConfigurationsSupported?.values?.firstOrNull {
			when (it) {
				is CredentialConfiguration.Mdoc -> it.doctype == vct
				is CredentialConfiguration.SdJwt -> it.vct == vct
				else -> false
			}
		}
		val cardTitle = credentialMetadata?.display?.firstOrNull()?.name ?: vct
		var cardColor =
			credentialMetadata?.display?.firstOrNull()?.backgroundColor?.replace("#", "")?.toLowerCasePreservingASCIIRules()
				?.hexToLong() ?: 0xFF000000
		// cardColor should not be transparent
		if (cardColor.and(0xFF000000) == 0L) {
			cardColor = cardColor.or(0xFF000000)
		}
		val attributeNames = propertyType.mapValues { it.key }.toMutableMap()
		attributeNames.putAll(
			mapOf(
				"/given_name" to stringResourceProvider.getString("id_first_name"),
				"/family_name" to stringResourceProvider.getString("id_last_name"),
				"/birthdate" to stringResourceProvider.getString("id_date_of_birth"),
				"/birth_family_name" to stringResourceProvider.getString("id_birth_family_name"),
				"/place_of_birth/locality" to stringResourceProvider.getString("id_place_of_birth"),
				"/nationalities" to stringResourceProvider.getString("id_nationality"),
				"/address/formatted" to stringResourceProvider.getString("id_address"),
				"/issuing_country" to stringResourceProvider.getString("id_issuing_country"),
				"/issuing_authority" to stringResourceProvider.getString("id_issuing_authority"),
				"/iat" to stringResourceProvider.getString("id_issued_on"),
				"/exp" to stringResourceProvider.getString("id_valid_until"),
			)
		)
		val attributeOrdering = propertyType.mapValues { it.key.length }

		val credentialMetadataClusterOrderingOverlay =
			getCredentialMetadataClusterOrderingOverlay(metadata, vct, locale, captureBaseSaid)

		val defaultClusterOrderingOverlay = ClusterOrderingOverlay(
			clusterOrder = mapOf(
				"main" to 1,
				"address" to 2,
				"additional" to 3,
			),
			clusterLabels = emptyMap(),
			attributeClusterOrder = mapOf(
				"main" to mapOf(
					"/given_name" to 1,
					"/family_name" to 2,
					"/birthdate" to 3,
					"/birth_family_name" to 4,
					"/place_of_birth/locality" to 5,
					"/nationalities" to 6,

					),
				"address" to mapOf(
					"/address/formatted" to 1,
				),
				"additional" to attributeOrdering,
			),
			captureBase = captureBaseSaid,
			language = locale,
		)

		val overlays = listOf(
			CharacterEncodingOverlay(
				defaultCharacterEncoding = Encoding.UTF_8,
				attributeCharacterEncoding = attributeEncoding,
				captureBase = captureBaseSaid,
			),
			FormatOverlay(
				attributeFormats = mapOf(
					"/birthdate" to "yyyy-MM-dd",
					"/exp" to "timestamp",
					"/iat" to "timestamp",
				),
				captureBase = captureBaseSaid,
			),
			InformationOverlay(
				attributeInformation = emptyMap(),
				captureBase = captureBaseSaid,
				language = locale,
			),
			LabelOverlay(
				attributeLabels = attributeNames,
				attributeCategories = emptyList(),
				categoryLabels = emptyMap(),
				captureBase = captureBaseSaid,
				language = locale,
			),
			TemplateOverlay(
				attributeTemplates = mapOf(
					"/address/formatted" to "{{ /address/street_address }}, {{ /address/postal_code }}, {{ /address/locality }}, {{ /address/country }}",
				),
				captureBase = captureBaseSaid,
			),
			UbiqueStyleJsonOverlay(
				title = cardTitle,
				subtitle = "",
				cardColor = cardColor ?: 0xFFE1DEC2,
				textColor = TextShade.DARK,
				backgroundCard = backgroundImage,
				orderedProperties = emptyList(),
				captureBase = captureBaseSaid,
				language = locale,
				frontOverlays = null,
			),
			credentialMetadataClusterOrderingOverlay ?: defaultClusterOrderingOverlay
		)
		return OcaBundleJson(captureBase, overlays)
	}

	private fun getCredentialMetadataClusterOrderingOverlay(
		metadata: CredentialIssuerMetadata?,
		vct: String,
		locale: String,
		captureBaseSaid: String,
	): ClusterOrderingOverlay? {

		if (metadata == null || metadata.credentialMetadata?.claims == null) {
			return null
		}

		val claims: List<CredentialMetadataClaim> = metadata.credentialMetadata?.claims ?: return null

		val clusterFirstIndex = linkedMapOf<String, Int>()
		val attributeOrderByCluster = linkedMapOf<String, LinkedHashMap<String, Int>>()

		val allClusterNames: Set<String> =
			claims.asSequence()
				.filter { it.path.size > 1 }
				.map { it.path.first() }
				.toSet()

		claims.forEach { claim ->
			if (claim.path.size > 1) {
				val cluster = claim.path.first()

				if (cluster !in clusterFirstIndex) {
					clusterFirstIndex[cluster] = clusterFirstIndex.size + 1
				}

				val attr: String = "/" + claim.path.drop(1).joinToString("/")
				val perCluster = attributeOrderByCluster.getOrPut(cluster) { linkedMapOf() }
				if (attr !in perCluster) {
					perCluster[attr] = perCluster.size + 1
				}
			}
		}

		val additionalTopLevelKeys = claims.asSequence()
			.filter { it.path.size == 1 }
			.map { it.path.first() }
			.filter { it !in allClusterNames } // exclude cluster labels
			.distinct()
			.sorted() // deterministic order, no assumption on input order
			.toList()

		if (additionalTopLevelKeys.isNotEmpty()) {
			// ensure "additional" is last
			if ("additional" !in clusterFirstIndex) {
				clusterFirstIndex["additional"] = clusterFirstIndex.size + 1
			}
			val additionalMap = attributeOrderByCluster.getOrPut("additional") { linkedMapOf() }
			additionalTopLevelKeys.forEach { key ->
				val attr = "/$key"
				if (attr !in additionalMap) {
					additionalMap[attr] = additionalMap.size + 1
				}
			}
		}

		val topLevelByName: Map<String, CredentialMetadataClaim> =
			claims.filter { it.path.size == 1 }.associateBy { it.path.first() }

		val clusterLabels: Map<String, String?> =
			clusterFirstIndex.keys.associateWith { cluster ->
				topLevelByName[cluster]?.display.getLocalizedLabel(locale)
			}

		val attributeClusterOrder: Map<String, Map<String, Int>> =
			attributeOrderByCluster.mapValues { (_, v) -> v.toMap() }

		return ClusterOrderingOverlay(
			clusterOrder = clusterFirstIndex.toMap(),
			clusterLabels = clusterLabels,
			attributeClusterOrder = attributeClusterOrder,
			captureBase = captureBaseSaid,
			language = locale,
		)
	}

	private fun addKeysAndTypesForObject(
		obj: JsonObject,
		map: MutableMap<String, AttributeType>,
		formatTypes: MutableMap<String, Encoding>,
		currentPath: String,
	) {
		for (entry in obj) {
			val newPath = "$currentPath/${entry.key}"
			if (hiddenProperties.contains(newPath)) {
				continue
			}
			val innerObj = entry.value
			when (innerObj) {
				is JsonObject -> addKeysAndTypesForObject(innerObj, map, formatTypes, newPath)
				is JsonPrimitive -> {
					val ty = if (innerObj.isString) {
						if (dateTimeRegex.matches(innerObj.content)) {
							AttributeType.DateTime
							// iVBOR is the starting string of base64 encoded PNG images.
						} else if (innerObj.content.startsWith("data:") || innerObj.content.startsWith("iVBOR")) {
							formatTypes.put(newPath, Encoding.BASE_64)
							AttributeType.Binary
						} else {
							AttributeType.Text
						}
					} else {
						innerObj.booleanOrNull?.let { AttributeType.Boolean } ?: innerObj.intOrNull?.let { AttributeType.Numeric }
						?: innerObj.longOrNull?.let { AttributeType.Numeric }
						?: innerObj.doubleOrNull?.let { AttributeType.Numeric } ?: AttributeType.Text
					}
					map.put(newPath, ty)
				}
				is JsonArray -> {
					val ubytes = runCatching {
						val bytes: List<UByte> = Json.decodeFromJsonElement(ListSerializer(UByte.serializer()), innerObj)
					}.isSuccess
					val bytes = runCatching {
						val bytes: List<Byte> = Json.decodeFromJsonElement(ListSerializer(Byte.serializer()), innerObj)
					}.isSuccess
					if (ubytes or bytes) {
						map.put(newPath, AttributeType.Array(AttributeType.Binary))
					} else {
						map.put(newPath, AttributeType.Array(AttributeType.Text))
					}
				}
				is JsonNull -> {
					map.put(newPath, AttributeType.Text)
				}
			}
		}
	}

	/**
	 * Creates an OCA bundle for the german EUID PID credential.
	 *
	 * @param locale The locale of the user (aka device language)
	 * @param stringResourceProvider A platform specific provider for localized strings
	 */
	fun createEuidPidBundle(
		locale: String,
		stringResourceProvider: StringResourceProvider,
		isEmergencyPass: Boolean,
	): OcaBundleJson {
		val captureBaseSaid = SAID_HASH_PLACEHOLDER
		val captureBase = CaptureBase(
			attributes = mapOf(
				"/place_of_birth/locality" to AttributeType.Text,
				"/address/locality" to AttributeType.Text,
				"/address/country" to AttributeType.Text,
				"/address/postal_code" to AttributeType.Numeric,
				"/address/street_address" to AttributeType.Text,
				"/address/formatted" to AttributeType.Text,
				"/issuing_country" to AttributeType.Text,
				"/issuing_authority" to AttributeType.Text,
				"/age_equal_or_over/12" to AttributeType.Boolean,
				"/age_equal_or_over/14" to AttributeType.Boolean,
				"/age_equal_or_over/16" to AttributeType.Boolean,
				"/age_equal_or_over/18" to AttributeType.Boolean,
				"/age_equal_or_over/21" to AttributeType.Boolean,
				"/age_equal_or_over/65" to AttributeType.Boolean,
				"/family_name" to AttributeType.Text,
				"/given_name" to AttributeType.Text,
				"/birthdate" to AttributeType.DateTime,
				"/age_birth_year" to AttributeType.Numeric,
				"/age_in_years" to AttributeType.Numeric,
				"/birth_family_name" to AttributeType.Text,
				"/nationalities" to AttributeType.Array(AttributeType.Text),
				"/exp" to AttributeType.DateTime,
				"/iat" to AttributeType.DateTime,
			),
			flaggedAttributes = listOf(
				"/place_of_birth/locality",
				"/address/locality",
				"/address/country",
				"/address/postal_code",
				"/address/street_address",
				"/address/formatted",
				"/family_name",
				"/given_name",
				"/birthdate",
				"/age_birth_year",
				"/birth_family_name",
				"/nationalities",
			)
		)

		val overlays = listOf(
			CharacterEncodingOverlay(
				defaultCharacterEncoding = Encoding.UTF_8,
				captureBase = captureBaseSaid,
			),
			FormatOverlay(
				attributeFormats = mapOf(
					"/birthdate" to "yyyy-MM-dd",
					"/exp" to "timestamp",
					"/iat" to "timestamp",
				),
				captureBase = captureBaseSaid,
			),
			InformationOverlay(
				attributeInformation = emptyMap(),
				captureBase = captureBaseSaid,
				language = locale,
			),
			LabelOverlay(
				attributeLabels = mapOf(
					"/given_name" to stringResourceProvider.getString("id_first_name"),
					"/family_name" to stringResourceProvider.getString("id_last_name"),
					"/birthdate" to stringResourceProvider.getString("id_date_of_birth"),
					"/birth_family_name" to stringResourceProvider.getString("id_birth_family_name"),
					"/place_of_birth/locality" to stringResourceProvider.getString("id_place_of_birth"),
					"/nationalities" to stringResourceProvider.getString("id_nationality"),
					"/address/formatted" to stringResourceProvider.getString("id_address"),
					"/issuing_country" to stringResourceProvider.getString("id_issuing_country"),
					"/issuing_authority" to stringResourceProvider.getString("id_issuing_authority"),
					"/iat" to stringResourceProvider.getString("id_issued_on"),
					"/exp" to stringResourceProvider.getString("id_valid_until"),
				),
				attributeCategories = emptyList(),
				categoryLabels = emptyMap(),
				captureBase = captureBaseSaid,
				language = locale,
			),
			TemplateOverlay(
				attributeTemplates = mapOf(
					"/address/formatted" to "{{ /address/street_address }}, {{ /address/postal_code }}, {{ /address/locality }}, {{ /address/country }}",
				),
				captureBase = captureBaseSaid,
			),
			UbiqueStyleJsonOverlay(
				title = "{{ /family_name }} {{ /given_name }}",
				subtitle = stringResourceProvider.getString("id_title"),
				cardColor = if (isEmergencyPass) 0xFFECD0F7 else 0xFFE1DEC2,
				textColor = TextShade.DARK,
				backgroundCard = runBlocking {
					if (isEmergencyPass) EMERGENCY_PASS_CARD else PID_CARD
				},
				orderedProperties = emptyList(),
				captureBase = captureBaseSaid,
				language = locale,
				frontOverlays = null
			),
			ClusterOrderingOverlay(
				clusterOrder = mapOf(
					"main" to 1,
					"address" to 2,
					"additional" to 3,
				),
				clusterLabels = emptyMap(),
				attributeClusterOrder = mapOf(
					"main" to mapOf(
						"/given_name" to 1,
						"/family_name" to 2,
						"/birthdate" to 3,
						"/birth_family_name" to 4,
						"/place_of_birth/locality" to 5,
						"/nationalities" to 6,

						),
					"address" to mapOf(
						"/address/formatted" to 1,
					),
					"additional" to mapOf(
						"/issuing_country" to 1,
						"/issuing_authority" to 2,
						"/iat" to 3,
						"/exp" to 4,
					)
				),
				captureBase = captureBaseSaid,
				language = locale,
			)
		)

		return OcaBundleJson(captureBase, overlays)
	}

	/**
	 * Built-in OCA bundle for the Swiss Beta ID.
	 * Claims and labels are taken from here: https://bcs.admin.ch/bcs-web/issuer-agent/oid4vci/.well-known/openid-credential-issuer (as of 11.04.2025)
	 */
	fun createSwissBetaIdBundle(
		locale: String,
		stringResourceProvider: StringResourceProvider,
	): OcaBundleJson {
		val captureBaseSaid = SAID_HASH_PLACEHOLDER
		val captureBase = CaptureBase(
			attributes = mapOf(
				"/sex" to AttributeType.Text,
				"/age_over_16" to AttributeType.Boolean,
				"/age_over_18" to AttributeType.Boolean,
				"/age_over_65" to AttributeType.Boolean,
				"/personal_administrative_number" to AttributeType.Text,
				"/place_of_origin" to AttributeType.Text,
				"/verification_organization" to AttributeType.Text,
				"/expiry_date" to AttributeType.DateTime,
				"/issuing_authority" to AttributeType.Text,
				"/reference_id_expiry_date" to AttributeType.DateTime,
				"/portrait" to AttributeType.Binary,
				"/nationality" to AttributeType.Text,
				"/birth_place" to AttributeType.Text,
				"/issuance_date" to AttributeType.DateTime,
				"/given_name" to AttributeType.Text,
				"/birth_date" to AttributeType.DateTime,
				"/verification_type" to AttributeType.Text,
				"/age_birth_year" to AttributeType.Numeric,
				"/document_number" to AttributeType.Text,
				"/issuing_country" to AttributeType.Text,
				"/family_name" to AttributeType.Text,
				"/additional_person_info" to AttributeType.Text,
			),
			flaggedAttributes = listOf(
				"/sex",
				"/personal_administrative_number",
				"/place_of_origin",
				"/portrait",
				"/nationality",
				"/birth_place",
				"/given_name",
				"/birth_date",
				"/age_birth_year",
				"/document_number",
				"/issuing_country",
				"/family_name",
				"/additional_person_info",
			)
		)

		val overlays = listOf(
			CharacterEncodingOverlay(
				defaultCharacterEncoding = Encoding.UTF_8,
				captureBase = captureBaseSaid,
			),
			FormatOverlay(
				captureBase = captureBaseSaid,
				attributeFormats = mapOf(
					"/expiry_date" to "yyyy-MM-dd",
					"/reference_id_expiry_date" to "yyyy-MM-dd",
					"/portrait" to "image/png",
					"/issuance_date" to "yyyy-MM-dd",
					"/birth_date" to "yyyy-MM-dd",
				)
			),
			LabelOverlay(
				captureBase = captureBaseSaid,
				attributeLabels = mapOf(
					"/sex" to stringResourceProvider.getString("swiss_beta_id_label_sex"),
					"/age_over_16" to stringResourceProvider.getString("swiss_beta_id_label_age_over_16"),
					"/age_over_18" to stringResourceProvider.getString("swiss_beta_id_label_age_over_18"),
					"/age_over_65" to stringResourceProvider.getString("swiss_beta_id_label_age_over_65"),
					"/personal_administrative_number" to stringResourceProvider.getString("swiss_beta_id_label_personal_administrative_number"),
					"/place_of_origin" to stringResourceProvider.getString("swiss_beta_id_label_place_of_origin"),
					"/verification_organization" to stringResourceProvider.getString("swiss_beta_id_label_verification_organization"),
					"/expiry_date" to stringResourceProvider.getString("swiss_beta_id_label_expiry_date"),
					"/issuing_authority" to stringResourceProvider.getString("swiss_beta_id_label_issuing_authority"),
					"/reference_id_expiry_date" to stringResourceProvider.getString("swiss_beta_id_label_reference_id_expiry_date"),
					"/portrait" to stringResourceProvider.getString("swiss_beta_id_label_portrait"),
					"/nationality" to stringResourceProvider.getString("swiss_beta_id_label_nationality"),
					"/birth_place" to stringResourceProvider.getString("swiss_beta_id_label_birth_place"),
					"/issuance_date" to stringResourceProvider.getString("swiss_beta_id_label_issuance_date"),
					"/given_name" to stringResourceProvider.getString("swiss_beta_id_label_given_name"),
					"/birth_date" to stringResourceProvider.getString("swiss_beta_id_label_birth_date"),
					"/verification_type" to stringResourceProvider.getString("swiss_beta_id_label_verification_type"),
					"/age_birth_year" to stringResourceProvider.getString("swiss_beta_id_label_age_birth_year"),
					"/document_number" to stringResourceProvider.getString("swiss_beta_id_label_document_number"),
					"/issuing_country" to stringResourceProvider.getString("swiss_beta_id_label_issuing_country"),
					"/family_name" to stringResourceProvider.getString("swiss_beta_id_label_family_name"),
					"/additional_person_info" to stringResourceProvider.getString("swiss_beta_id_label_additional_person_info"),
				),
				attributeCategories = emptyList(),
				categoryLabels = emptyMap(),
				language = locale,
			),
			UbiqueStyleJsonOverlay(
				captureBase = captureBaseSaid,
				title = stringResourceProvider.getString("swiss_beta_id_subtitle"),
				subtitle = "{{ /family_name }} {{ /given_name }}",
				cardColor = 0xFF4A5F77,
				textColor = TextShade.LIGHT,
				orderedProperties = listOf(
					"/document_number",
					"/portrait",
					"/family_name",
					"/given_name",
					"/birth_date",
					"/sex",
					"/place_of_origin",
					"/birth_place",
					"/nationality",
					"/personal_administrative_number",
					"/additional_person_info",
					"/age_over_16",
					"/age_over_18",
					"/age_over_65",
					"/age_birth_year",
					"/issuance_date",
					"/expiry_date",
					"/reference_id_type",
					"/reference_id_expiry_date",
					"/verification_type",
					"/verification_organization",
					"/issuing_authority",
					"/issuing_country",
				),
				language = locale,
				frontOverlays = listOf(
					StyleJson.StyleOverlay(
						content = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAQAAADa613fAAAAt0lEQVR42u3YMQ4BQRiG4a2p3UMi0Wlcih5n2GYTWS6gcBahdZGfSqHZWdNMxvN+/WSe9m8aSZIkSaqiWMYzcV3ZkFWkdgEBAQEBAQEBAQEBAQEBAQEBKQ4S6zi8tx/Y7rM+GfIYfPV70xzIOcppBlIT5AQCAgICApIB6UFAQEBAQDIgx1og89iMWpv8rXtsR25S5jnoWstdCwQEBAQEBAQEBAQEBAQEBOSfIYu4Ja5tJEmSJP3UC98M2ozRcV9yAAAAAElFTkSuQmCC",
						contentType = StyleJson.StyleOverlay.OverlayContentType.Image,
						position = StyleJson.StyleOverlay.OverlayPosition.BottomLeft,
					),
					StyleJson.StyleOverlay(
						content = "/portrait",
						contentType = StyleJson.StyleOverlay.OverlayContentType.Image,
						position = StyleJson.StyleOverlay.OverlayPosition.BottomRight,
					)
				)
			),
			ClusterOrderingOverlay(
				captureBase = captureBaseSaid,
				clusterOrder = mapOf(
					"main" to 1,
					"meta" to 2,
				),
				clusterLabels = emptyMap(),
				attributeClusterOrder = mapOf(
					"main" to mapOf(
						"/given_name" to 1,
						"/family_name" to 2,
						"/portrait" to 3,
						"/sex" to 4,
						"/birth_date" to 5,
						"/age_birth_year" to 6,
						"/age_over_16" to 7,
						"/age_over_18" to 8,
						"/age_over_65" to 9,
						"/place_of_origin" to 10,
						"/birth_place" to 11,
						"/nationality" to 12,
						"/personal_administrative_number" to 13,
						"/additional_person_info" to 14,
					),
					"meta" to mapOf(
						"/document_number" to 1,
						"/issuance_date" to 2,
						"/expiry_date" to 3,
						"/reference_id_expiry_date" to 4,
						"/issuing_authority" to 5,
						"/issuing_country" to 6,
						"/verification_type" to 7,
						"/verification_organization" to 8,
					)
				),
				language = locale,
			)
		)

		return OcaBundleJson(captureBase, overlays)
	}

}
