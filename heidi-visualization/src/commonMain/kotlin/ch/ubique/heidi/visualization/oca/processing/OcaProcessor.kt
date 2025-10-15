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

package ch.ubique.heidi.visualization.oca.processing

import ch.ubique.heidi.util.extensions.fromSecondsOrMillis
import ch.ubique.heidi.util.extensions.jsonObjectOrNull
import ch.ubique.heidi.util.extensions.jsonPrimitiveOrNull
import ch.ubique.heidi.util.json.JsonPointer
import ch.ubique.heidi.visualization.extensions.isPng
import ch.ubique.heidi.visualization.extensions.tryDecodeBase64
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.visualization.extensions.verifyIntegrity
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.oca.model.OcaBundleJson
import ch.ubique.heidi.visualization.oca.model.content.AttributeName
import ch.ubique.heidi.visualization.oca.model.content.AttributeType
import ch.ubique.heidi.visualization.oca.model.content.Encoding
import ch.ubique.heidi.visualization.oca.model.overlay.Localized
import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import ch.ubique.heidi.visualization.oca.model.overlay.input.ConformanceOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.input.EntryOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.input.UnitOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.AriesBrandingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.ClusterOrderingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.UbiqueStyleJsonOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.*
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.AttributeMappingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.SubsetOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.TemplateOverlay
import ch.ubique.heidi.visualization.stylejson.template.StyleJsonTemplate
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class OcaProcessor(
	userLanguage: String,
	private val payload: String,
	private val ocaBundle: OcaBundleJson,
	val isBundleValid : Boolean = ocaBundle.verifyIntegrity()
) {
	private val payloadJson = Json.parseToJsonElement(payload)

	// Overlays that are either non-localized or match the users device language
	private val matchingOverlays = ocaBundle.overlays.filter { it !is Localized || it.matches(userLanguage) }

	fun process(layoutType: LayoutType): LayoutData {
		val metaOverlay = getOverlay<MetaOverlay>()
		return when (layoutType) {
			LayoutType.CARD -> {
				val styleJsonOverlay = getOverlay<UbiqueStyleJsonOverlay>()
				val ariesBrandingOverlay = getOverlay<AriesBrandingOverlay>()

				styleJsonOverlay?.process(layoutType, metaOverlay) { processAttribute(it) }
					?: ariesBrandingOverlay?.process(layoutType, metaOverlay) { processAttribute(it) }
					?: LayoutData.Raw(payload)
			}
			LayoutType.DETAIL_LIST -> {
				val clusterOrderingOverlay = getOverlay<ClusterOrderingOverlay>()
				val styleJsonOverlay = getOverlay<UbiqueStyleJsonOverlay>()

				clusterOrderingOverlay?.process(layoutType) { processAttribute(it) }
					?: styleJsonOverlay?.process(layoutType, metaOverlay) { processAttribute(it) }
					?: LayoutData.Raw(payload)
			}
		}
	}

	fun processAttribute(
		originalAttributeName: AttributeName,
	): ProcessedAttribute? {
		val capturedAttributes = ocaBundle.captureBase.attributes
		val flaggedAttributes = ocaBundle.captureBase.flaggedAttributes

		// Map the attribute name
		val attributeMappingOverlay = getOverlay<AttributeMappingOverlay>()
		val attributeName = attributeMappingOverlay?.mapAttributeName(originalAttributeName) ?: originalAttributeName

		// Filter attribute if it isn't in the subset
		val subsetOverlay = getOverlay<SubsetOverlay>()
		if (subsetOverlay != null && !subsetOverlay.isContained(attributeName)) {
			return null
		}

		val attributeType = capturedAttributes[attributeName] ?: return null
		val isFlagged = flaggedAttributes.contains(attributeName)

		// Encode and format the attribute
		val templateOverlay = getOverlay<TemplateOverlay>()
		val encodingOverlay = getOverlay<CharacterEncodingOverlay>()
		val formatOverlay = getOverlay<FormatOverlay>()
		val attributeValue = resolveAttributeValue(
			attributeName,
			attributeType,
			encodingOverlay?.getEncoding(attributeName) ?: Encoding.UTF_8,
			formatOverlay?.getFormat(attributeName),
			templateOverlay?.getTemplate(attributeName),
		)

		// Annotate attribute
		val unitOverlay = getOverlay<UnitOverlay>()
		val labelOverlay = getOverlay<LabelOverlay>()
		val informationOverlay = getOverlay<InformationOverlay>()
		val standardOverlay = getOverlay<StandardOverlay>()
		val conformanceOverlay = getOverlay<ConformanceOverlay>()

		val processedAttribute = ProcessedAttribute(
			attributeName = attributeName,
			attributeType = attributeType,
			attributeValue = attributeValue,
			label = labelOverlay?.getLabel(attributeName) ?: attributeName,
			information = informationOverlay?.getInformation(attributeName),
			standard = standardOverlay?.getStandard(attributeName),
			unit = unitOverlay?.getUnit(attributeName),
			isFlagged = isFlagged,
			isMandatory = conformanceOverlay?.isMandatory(attributeName) ?: false,
		)

		return processedAttribute
	}

	@OptIn(ExperimentalEncodingApi::class)
	private fun resolveAttributeValue(
		attributeName: String,
		attributeType: AttributeType,
		encoding: Encoding,
		format: String?,
		template: String?,
	): AttributeValue<*>? {
		val rawValue = if (template != null) {
			StyleJsonTemplate(template).interpolate { resolveRawAttributeValue(it) }
		} else {
			// Resolve attribute value by its attribute name (which may or may not be a JSON Pointer)
			resolveRawAttributeValue(attributeName) ?: return null
		}

		// Check if the raw attribute value resolves to a value in an entry overlay
		val entryValue = resolveEntryValue(attributeName, rawValue)
		if (entryValue != null) {
			return AttributeValue.Text(entryValue)
		}

		val attributeValue = when (attributeType) {
			is AttributeType.Array -> {
				when(attributeType.contentType) {
					is AttributeType.Binary -> {
						val bytes = rawValue.trim('[', ']').split(",").map {
							val ubyte = runCatching { it.trim().toUByte().toByte() }
							if(ubyte.isSuccess) {
								ubyte.getOrThrow()
							} else {
								it.trim().toByte()
							}
						}.toByteArray()
						AttributeValue.Image(bytes, format)
					}
					else -> {
						val values = rawValue.trim('[', ']').split(",").map { AttributeValue.Text(it) }
						AttributeValue.Array(values)
					}
				}
			}
			AttributeType.Binary -> {
				// The format of the attribute is specified (it is an image), try decoding it and return an image with bytes
				when {
					format?.startsWith("image/") == true -> {
						rawValue.tryDecodeBase64()?.let {
							AttributeValue.Image(it, format)
						} ?: AttributeValue.Raw(rawValue, format)
					}
					// the format is specified, but it is not a picture, return the values as is
					format != null -> AttributeValue.Raw(rawValue, format)
					else -> {
						// it is a binary attribute. We don't know the format, as such we try to "guess" the format
						// by looking at the content. We handle data urls, containing base64 erncoded binary data, and
						// base64 encoded png data.
						val dataUrlScheme = "data:(.*);base64,(.*)".toRegex()
						val matches = dataUrlScheme.matchEntire(rawValue)?.groupValues
						val mediaType = matches?.getOrNull(1)
						val data = matches?.getOrNull(2)
						// iVBOR is the starting string of Base64 encoded PNG images.
						val realData = data ?: if (rawValue.isPng()) { rawValue } else { null }
						realData.tryDecodeBase64()?.let { AttributeValue.Image(it, format) } ?: AttributeValue.Raw(rawValue, format)
					}
				}
			}
			AttributeType.Boolean -> AttributeValue.Bool(rawValue.toBoolean())
			AttributeType.DateTime -> {
				if (format.equals("timestamp", ignoreCase = true)) {
					val instant = Instant.fromSecondsOrMillis(rawValue.toLong())
					AttributeValue.Timestamp(instant)
				} else {
					val sanitizedFormat = (format ?: "YYYY-MM-DDTHH:mm:ssZ").sanitizeDateTimePattern()
					parseDateTime(rawValue, sanitizedFormat)?.let {
						AttributeValue.DateTime(it)
					} ?: parseDate(rawValue, sanitizedFormat)?.let {
						AttributeValue.Date(it)
					} ?: AttributeValue.Raw(rawValue)
				}
			}
			AttributeType.Numeric -> AttributeValue.Text(rawValue) // TODO Parse to Double/Long or leave as String?
			AttributeType.Reference -> TODO("Reference not yet implemented")
			AttributeType.Text -> {
				val linkRegex = """Link\[(.+)]""".toRegex()
				val match = format?.let { linkRegex.matchEntire(it) }

				if (match != null) {
					val (typeStr) = match.destructured
					val linkType = try {
						AttributeValue.LinkType.valueOf(typeStr)
					} catch (e: IllegalArgumentException) {
						Logger.error("Unknown LinkType: $typeStr in value: $rawValue")
						null
					}

					if (linkType != null) {
						AttributeValue.Link(value = rawValue, linkType = linkType)
					} else {
						AttributeValue.Text(rawValue)
					}
				} else {
					AttributeValue.Text(rawValue)
				}
			}
			AttributeType.Unknown -> AttributeValue.Raw(rawValue)
		}

		return attributeValue
	}

	private fun tryResolveW3CProperty(path: String): String? =
		JsonPointer("credentialSubject/${path.trim('/')}").resolveString(payloadJson)

	private fun tryResolveBbsProperty(normalizedPath: String) : String? {
		val np = normalizedPath.trim('/')
		val parts = np.split("/")
		if(parts.isEmpty()) {
			return null
		}
		var currentElement = payloadJson
		if(parts.size > 1) {
			for (part in parts.subList(0, parts.size - 2)) {
				currentElement = when (currentElement) {
					is JsonObject -> currentElement.jsonObject["http://schema.org/$part"] as JsonElement
					is JsonArray -> currentElement.jsonArray[part.toInt()]
					else -> return null
				}
			}
		}
		val finalElement = parts.last()
		currentElement = when (currentElement) {
			is JsonObject -> currentElement.jsonObject["http://schema.org/$finalElement"] as JsonElement
			is JsonArray -> currentElement.jsonArray[finalElement.toInt()]
			else -> return null
		}
		return when(currentElement) {
			is JsonObject -> currentElement["@value"]?.jsonPrimitiveOrNull()?.contentOrNull
			is JsonPrimitive -> currentElement.contentOrNull
			else -> null
		}
	}

	/**
	 * Resolves an attribute from the payload JSON by its JSON pointer.
	 */
	private fun resolveRawAttributeValue(path: String): String? {
		val p = if(path.startsWith("/")) {
			path
		} else {
			"/${path.replace(".", "/")}"
		}
		val jsonObj = payloadJson.jsonObjectOrNull()
		val value = jsonObj?.get(p.trim('/'))?.jsonPrimitiveOrNull()?.contentOrNull
			?: runCatching { tryResolveBbsProperty(p) }.getOrNull()
			?: runCatching { tryResolveW3CProperty(p) }.getOrNull()

		return value
			?: JsonPointer(p).resolveString(payloadJson)
	}

	private fun resolveEntryValue(attributeName: AttributeName, rawValue: String): String? {
		val entryOverlay = getOverlay<EntryOverlay>() ?: return null
		return entryOverlay.getEntry(attributeName, rawValue)
	}

	private fun String.sanitizeDateTimePattern(): String {
		return this
			.replace("Y", "y") // "Year of the week" is not supported by KotlinX DateTime
			.replace("D", "d") // "Day in year" is not supported by KotlinX DateTime
	}

	@OptIn(FormatStringsInDatetimeFormats::class)
	private fun parseDateTime(rawValue: String, format: String): LocalDateTime? {
		return try {
			val formatter = LocalDateTime.Format { byUnicodePattern(format) }
			LocalDateTime.parse(rawValue, formatter)
		} catch (e: Exception) {
			null
		}
	}

	@OptIn(FormatStringsInDatetimeFormats::class)
	private fun parseDate(rawValue: String, format: String): LocalDate? {
		return try {
			val formatter = LocalDate.Format { byUnicodePattern(format) }
			LocalDate.parse(rawValue, formatter)
		} catch (e: Exception) {
			null
		}
	}

	private inline fun <reified T : Overlay> getOverlay(): T? {
		return matchingOverlays.filterIsInstance<T>().firstOrNull()
			?: ocaBundle.overlays.filterIsInstance<T>().firstOrNull()
	}

}
