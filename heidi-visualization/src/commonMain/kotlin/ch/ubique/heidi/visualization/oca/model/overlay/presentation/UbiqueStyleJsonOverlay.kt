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

import ch.ubique.heidi.visualization.layout.*
import ch.ubique.heidi.visualization.layout.LayoutCardOverlayContent.*
import ch.ubique.heidi.visualization.oca.model.SAID_HASH_PLACEHOLDER
import ch.ubique.heidi.visualization.oca.model.content.AttributeName
import ch.ubique.heidi.visualization.oca.model.content.SAID
import ch.ubique.heidi.visualization.oca.model.content.TextShade
import ch.ubique.heidi.visualization.oca.model.overlay.Localized
import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.MetaOverlay
import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import ch.ubique.heidi.visualization.oca.processing.ProcessedAttribute
import ch.ubique.heidi.visualization.stylejson.model.StyleJson.StyleOverlay
import ch.ubique.heidi.visualization.stylejson.model.StyleJsonSchema
import ch.ubique.heidi.visualization.stylejson.template.StyleJsonTemplate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
data class UbiqueStyleJsonOverlay(
	@SerialName("title") val title: String,
	@SerialName("subtitle") val subtitle: String,
	@SerialName("cardColor") val cardColor: Long,
	@SerialName("textColor") val textColor: TextShade = TextShade.DARK,
	@SerialName("backgroundCard") val backgroundCard: String? = null,
	@SerialName("orderedProperties") val orderedProperties: List<AttributeName>,
	@SerialName("capture_base") override val captureBase: SAID,
	@SerialName("type") override val type: String = "ubique/overlays/style_json/1.0",
	@SerialName("language") override val language: String,
	@SerialName("frontOverlays") val frontOverlays: List<StyleOverlay>? = null,
	@SerialName("digest") override val digest: SAID = SAID_HASH_PLACEHOLDER,
) : PresentationOverlay, Localized {
	override fun updateDigest(digest: SAID, captureBase: SAID): Overlay =
		copy(digest = digest, captureBase = captureBase)

	companion object {
		fun fromStyleJson(schema: StyleJsonSchema, captureBase: SAID, language: String): UbiqueStyleJsonOverlay {
			return UbiqueStyleJsonOverlay(
				schema.style.title,
				schema.style.subtitle,
				schema.style.cardColor,
				schema.style.textColor.toTextShade(),
				schema.style.backgroundCard,
				schema.style.orderedProperties,
				frontOverlays = schema.style.frontOverlays,
				captureBase = captureBase,
				language = language,
			)
		}
	}

	override fun presentsAttributes() = orderedProperties


	@OptIn(ExperimentalEncodingApi::class)
	fun parseLayoutCardImage(input: String?): LayoutCardImage? {
		return when {
			input?.startsWith("http") == true -> LayoutCardImage.Url(input)
			!input.isNullOrEmpty() -> {
				runCatching {
					val data = if (input.startsWith("data:")) {
						// Strip the data URI prefix and decode base64
						Base64.decode(input.substringAfter(","))
					} else {
						Base64.decode(input)
					}
					LayoutCardImage.Base64(data)
				}.getOrElse { null }
			}
			else -> null
		}
	}

	fun parseLayoutCardImage(input: ProcessedAttribute): LayoutCardImage? {
		return when (input.attributeValue) {
			is AttributeValue.Image -> {
				return LayoutCardImage.Base64(input.attributeValue.value)
			}
			is AttributeValue.Text -> {
				if (input.attributeValue.value.startsWith("http")) {
					return LayoutCardImage.Url(input.attributeValue.value)
				}
				return null
			}
			else -> null
		}
	}

	fun process(
		layoutType: LayoutType,
		meta: MetaOverlay?,
		attributeProcessor: (AttributeName) -> ProcessedAttribute?,
	): LayoutData {
		return when (layoutType) {
			LayoutType.CARD -> {
				val backgroundImage = parseLayoutCardImage(backgroundCard)
				val overlays = processFrontOverlays(frontOverlays, attributeProcessor)

				LayoutData.Card(
					credentialName = meta?.name,
					issuerName = meta?.issuerName,
					title = StyleJsonTemplate(title).interpolate { attributeProcessor(it)?.attributeValue?.asString() },
					subtitle = StyleJsonTemplate(subtitle).interpolate { attributeProcessor(it)?.attributeValue?.asString() },
					textColor = textColor,
					cardColor = cardColor,
					backgroundImage = backgroundImage,
					overlays = overlays
				)
			}
			LayoutType.DETAIL_LIST -> {
				val sectionContent = orderedProperties.mapNotNull { attributeName ->
					attributeProcessor.invoke(attributeName)?.let { attribute ->
						LayoutSectionProperty(
							attribute.attributeValue,
							attribute.label,
							attribute.information,
						)
					}
				}
				LayoutData.DetailList(
					sections = listOf(
						LayoutSection(
							sectionTitle = null,
							sectionContent = sectionContent,
						)
					)
				)
			}
		}
	}

	private fun processFrontOverlays(
		frontOverlays: List<StyleOverlay>?,
		attributeProcessor: (AttributeName) -> ProcessedAttribute?,
	): List<LayoutCardOverlay>? {
		return frontOverlays?.mapNotNull { overlay ->
			val attribute = attributeProcessor.invoke(overlay.content)
			when (overlay.contentType) {
				StyleOverlay.OverlayContentType.Text -> {
					val overlayContent =
						attribute?.attributeValue?.asString()?.let { Text(it) } ?: Text(overlay.content)
					LayoutCardOverlay(overlayContent, overlay.position)
				}
				StyleOverlay.OverlayContentType.Image -> {
					val image = attribute?.let { parseLayoutCardImage(it) }
						?: parseLayoutCardImage(overlay.content)
						?: return@mapNotNull null
					LayoutCardOverlay(
						LayoutCardOverlayContent.Image(image, ImageType.Regular),
						overlay.position
					)
				}
				StyleOverlay.OverlayContentType.ImageLogo -> {
					val image = attribute?.let { parseLayoutCardImage(it) }
						?: parseLayoutCardImage(overlay.content)
						?: return@mapNotNull null
					LayoutCardOverlay(
						LayoutCardOverlayContent.Image(image, ImageType.Logo),
						overlay.position
					)
				}
				StyleOverlay.OverlayContentType.ImageIcon -> {
					val image = attribute?.let { parseLayoutCardImage(it) }
						?: parseLayoutCardImage(overlay.content)
						?: return@mapNotNull null
					LayoutCardOverlay(
						LayoutCardOverlayContent.Image(image, ImageType.Icon),
						overlay.position
					)
				}
			}
		}
	}
}
