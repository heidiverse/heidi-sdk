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

package ch.ubique.heidi.visualization.oca.model.overlay.presentation

import ch.ubique.heidi.util.extensions.toArgb
import ch.ubique.heidi.visualization.layout.LayoutCardImage
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.oca.model.SAID_HASH_PLACEHOLDER
import ch.ubique.heidi.visualization.oca.model.content.AttributeName
import ch.ubique.heidi.visualization.oca.model.content.SAID
import ch.ubique.heidi.visualization.oca.model.content.TextShade
import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.MetaOverlay
import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import ch.ubique.heidi.visualization.oca.processing.ProcessedAttribute
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
data class AriesBrandingOverlay(
	@SerialName("logo") val logo: String? = null,
	@SerialName("background_image") val backgroundImage: String? = null,
	@SerialName("background_image_slice") val backgroundImageSlice: String? = null,
	@SerialName("primary_background_color") val primaryBackgroundColor: String? = null,
	@SerialName("secondary_background_color") val secondaryBackgroundColor: String? = null,
	@SerialName("primary_attribute") val primaryAttribute: AttributeName? = null,
	@SerialName("secondary_attribute") val secondaryAttribute: AttributeName? = null,
	@SerialName("issued_date_attribute") val issuedDateAttribute: AttributeName? = null,
	@SerialName("expiry_date_attribute") val expiryDateAttribute: AttributeName? = null,
	@SerialName("capture_base") override val captureBase: SAID,
	@SerialName("type") override val type: String = "spec/overlays/branding/1.0",
	@SerialName("digest") override val digest: SAID = SAID_HASH_PLACEHOLDER,
) : PresentationOverlay {
	override fun updateDigest(digest: SAID, captureBase: SAID): Overlay = copy(digest = digest, captureBase = captureBase)
	override fun presentsAttributes() = listOfNotNull(
		primaryAttribute,
		secondaryAttribute,
		issuedDateAttribute,
		expiryDateAttribute
	)

	@OptIn(ExperimentalEncodingApi::class)
	fun process(
		layoutType: LayoutType,
		meta: MetaOverlay?,
		attributeProcessor: (AttributeName) -> ProcessedAttribute?,
	): LayoutData? {
		return when (layoutType) {
			LayoutType.CARD -> {
				val backgroundImage = when {
					backgroundImage?.startsWith("http") == true -> LayoutCardImage.Url(backgroundImage)
					backgroundImage != null -> LayoutCardImage.Base64(Base64.decode(backgroundImage))
					else -> null
				}

				LayoutData.Card(
					credentialName = meta?.name,
					issuerName = meta?.issuerName,
					title = primaryAttribute?.let {
						(attributeProcessor.invoke(it)?.attributeValue as? AttributeValue.Text)?.value
					},
					subtitle = secondaryAttribute?.let {
						(attributeProcessor.invoke(it)?.attributeValue as? AttributeValue.Text)?.value
					},
					textColor = TextShade.DARK, // TODO Make dependent on background color
					cardColor = primaryBackgroundColor?.toArgb(),
					backgroundImage = backgroundImage,
					overlays = null,
				)
			}
			LayoutType.DETAIL_LIST -> null
		}
	}
}
