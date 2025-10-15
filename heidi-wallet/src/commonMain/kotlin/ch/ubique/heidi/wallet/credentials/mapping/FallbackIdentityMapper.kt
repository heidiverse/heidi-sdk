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

package ch.ubique.heidi.wallet.credentials.mapping

import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.identity.IdentityModel
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.credentials.models.metadata.KeyMaterialType
import ch.ubique.heidi.util.extensions.fromSecondsOrMillis
import ch.ubique.heidi.util.extensions.jsonObjectOrNull
import ch.ubique.heidi.util.extensions.jsonPrimitiveOrNull
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutSection
import ch.ubique.heidi.visualization.layout.LayoutSectionProperty
import ch.ubique.heidi.visualization.layout.deferredCard
import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import ch.ubique.heidi.wallet.credentials.activity.ActivityUiModel
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.credentials.issuer.getDisplayName
import ch.ubique.heidi.wallet.credentials.signature.Signature
import ch.ubique.heidi.wallet.credentials.signature.SignatureValidationState
import ch.ubique.heidi.wallet.resources.StringResourceProvider
import kotlinx.serialization.json.*
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class FallbackIdentityMapper(
	private val stringResourceProvider: StringResourceProvider,
) {

	companion object {
		val koinModule = module {
			factoryOf(::FallbackIdentityMapper)
		}

		/** Standard properties from the SD-JWT spec that should not be displayed */
		private val filteredProperties = setOf("_sd", "_sd_alg", "cnf", "exp", "iat", "iss", "nbf", "sub")
	}

	private val json = Json { ignoreUnknownKeys = true }

	fun mapIdentity(
		credentialType: CredentialType,
		identity: IdentityModel,
		payload: String,
		activities: List<ActivityUiModel>,
		credentials: List<CredentialModel>,
	): IdentityUiModel.IdentityUiCredentialModel? {
		val hasEmergencyPass = identity.emergencyTokens != null
		val hasOnlyEmergencyPass = hasEmergencyPass && identity.credentials.all {
			it.metadata.keyMaterial is KeyMaterial.Frost || it.metadata.keyMaterial is KeyMaterial.Unusable
		}

		val root = json.parseToJsonElement(payload).jsonObjectOrNull() ?: return null
		val credentialJson = when (credentialType) {
			CredentialType.SdJwt -> {
				root["verified_claims"]?.jsonObjectOrNull()
					?.get("claims")?.jsonObjectOrNull()
					?.let { it.values.singleOrNull()?.jsonObjectOrNull() ?: it }
					?: root
			}
			CredentialType.Mdoc -> {
				root.entries.firstOrNull { it.key.contains(".") }
					?.let { root[it.key] as? JsonObject } ?: root
			}
			CredentialType.BbsTermwise -> root
			CredentialType.W3C_VCDM -> root
			CredentialType.Unknown -> root
		}

		val firstName = credentialJson["given_name"]?.jsonPrimitive?.content
		val lastName = credentialJson["last_name"]?.jsonPrimitive?.content
		val iss = credentialJson["iss"]?.jsonPrimitiveOrNull()?.contentOrNull ?: root["iss"]?.jsonPrimitiveOrNull()?.contentOrNull ?: ""
		val exp = credentialJson["exp"]?.jsonPrimitiveOrNull()?.longOrNull ?: root["exp"]?.jsonPrimitiveOrNull()?.longOrNull

		val expiresAt = exp?.let {
			// TODO According to RFC 7519 this should be in seconds
			Instant.fromSecondsOrMillis(it)
		}

		val validationState = expiresAt?.let {
			if (it < Clock.System.now()) SignatureValidationState.EXPIRED else SignatureValidationState.VALID
		} ?: SignatureValidationState.INVALID

		val userLocale = stringResourceProvider.getString("language_key")
		val issuerName = identity.issuer.getDisplayName(userLocale)

		val title = if (firstName != null || lastName != null) {
			listOfNotNull(firstName, lastName).joinToString(" ")
		} else {
			issuerName
		}
		val subtitle = if (identity.isPid) {
			stringResourceProvider.getString("id_title")
		} else {
			stringResourceProvider.getString("wallet_documents_placeholder_title")
		}


		return IdentityUiModel.IdentityUiCredentialModel(
			id = identity.id,
			name = identity.name,
			card = deferredCard(identity.name),
			title = title,
			subtitle = subtitle,
			signature = Signature(validationState, iss),
			detailList = LayoutData.DetailList(
				sections = listOfNotNull(
					LayoutSection(
						sectionTitle = null,
						sectionContent = credentialJson.jsonObject.entries.filter { it.key !in filteredProperties }.map { (key, element) ->
							val value = (element as? JsonPrimitive)?.contentOrNull ?: element.toString()
							LayoutSectionProperty(
								value = AttributeValue.Raw(value),
								label = stringResourceProvider.getString(key),
								information = null,
							)
						}
					),
					expiresAt?.let {
						LayoutSection(
							sectionTitle = null,
							sectionContent = listOf(
								LayoutSectionProperty(
									value = AttributeValue.Timestamp(it),
									label = stringResourceProvider.getString("id_valid_until"),
									information = null,
								)
							)
						)
					}
				)
			),
			hasEmergencyPass,
			hasOnlyEmergencyPass,
			credentials = credentials,
			activities = activities,
			isPid = identity.isPid,
			isUsable = credentials.any { it.keyMaterialType != KeyMaterialType.UNUSABLE },
			isRefreshable = identity.tokens.refreshToken != null,
			isRevoked = false,
			docType = identity.credentials.firstOrNull()?.docType ?: "",
			frostBlob = identity.frostBlob,
			credentialUiModel = emptyList()
		)
	}

}
