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

package org.kapunsdk.wallet.credentials.mapping

import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.credentials.models.identity.IdentityModel
import org.kapunsdk.visualization.layout.LayoutData
import org.kapunsdk.visualization.layout.LayoutType
import org.kapunsdk.visualization.oca.OcaType
import org.kapunsdk.visualization.oca.model.OcaBundleJson
import org.kapunsdk.visualization.oca.processing.OcaProcessor
import org.kapunsdk.wallet.credentials.activity.ActivityUiModel
import org.kapunsdk.wallet.credentials.identity.IdentityUiModel
import org.kapunsdk.wallet.credentials.issuer.getDisplayName
import org.kapunsdk.wallet.credentials.mapping.defaults.OcaBundleFactory
import org.kapunsdk.credentials.models.metadata.KeyMaterial
import org.kapunsdk.credentials.models.metadata.KeyMaterialType
import org.kapunsdk.visualization.oca.processing.AttributeValue
import org.kapunsdk.wallet.credentials.oca.OcaRepository
import org.kapunsdk.wallet.credentials.signature.Signature
import org.kapunsdk.wallet.credentials.signature.SignatureValidationState
import org.kapunsdk.wallet.resources.StringResourceProvider
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module

class OcaIdentityMapper(
	private val stringResourceProvider: StringResourceProvider,
) {

	companion object {
		val koinModule = module {
			factoryOf(::OcaIdentityMapper)
		}
	}

	private val json = Json { ignoreUnknownKeys = true }

	fun mapIdentity(
		ocaRepository: OcaRepository,
		ocaType: OcaType,
		identity: IdentityModel,
		payload: String,
		activities: List<ActivityUiModel>,
		credentials: List<CredentialModel>,
		attributeValueOverrides: Map<String, AttributeValue<*>> = mapOf()
	): IdentityUiModel.IdentityUiCredentialModel? {
		val languageKey = stringResourceProvider.getString("language_key")

		val hasEmergencyPass = identity.emergencyTokens != null
		val hasOnlyEmergencyPass = hasEmergencyPass && identity.credentials.all {
			it.metadata.keyMaterial is KeyMaterial.Frost || it.metadata.keyMaterial is KeyMaterial.Unusable
		}

		val ocaBundle = when (ocaType) {
			is OcaType.Reference -> {
				val ocaJson = ocaRepository.getForUrl(ocaType.url)
				if (ocaJson != null) {
					try {
						json.decodeFromString<OcaBundleJson>(ocaJson.content)
					} catch (e: SerializationException) {
						return null
					}
				} else {
					// TODO Should schedule it for download or something
					return null
				}
			}
			is OcaType.BuiltIn.EuPid -> OcaBundleFactory.createEuidPidBundle(
				languageKey,
				stringResourceProvider,
				hasOnlyEmergencyPass
			)
			is OcaType.BuiltIn.SwissBetaId -> OcaBundleFactory.createSwissBetaIdBundle(
				languageKey,
				stringResourceProvider
			)
			is OcaType.BuiltIn.FromMetadata -> {
				val ocaJson = ocaRepository.getForUrl(ocaType.url)
				if (ocaJson != null) {
					try {
						json.decodeFromString<OcaBundleJson>(ocaJson.content)
					} catch (e: SerializationException) {
						return null
					}
				} else {
					// TODO Should schedule it for download or something
					return null
				}
			}
        }

		val processor = OcaProcessor(
			languageKey,
			payload,
			ocaBundle,
			attributeValueOverrides = attributeValueOverrides
		)
		val cardData = processor.process(LayoutType.CARD) as LayoutData.Card
		val listData = processor.process(LayoutType.DETAIL_LIST) as LayoutData.DetailList

		val userLocale = stringResourceProvider.getString("language_key")
		val issuerName = identity.issuer.getDisplayName(userLocale)

		return IdentityUiModel.IdentityUiCredentialModel(
			id = identity.id,
			name = identity.name,
			card = cardData,
			title = cardData.title ?: "title",
			subtitle = cardData.subtitle ?: "subtitle",
			signature = Signature(SignatureValidationState.VALID, issuerName),
			detailList = listData,
			hasEmergencyPass = hasEmergencyPass,
			hasOnlyEmergencyPass = hasOnlyEmergencyPass,
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
