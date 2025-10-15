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

package ch.ubique.heidi.visualization.oca.serialization

import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import ch.ubique.heidi.visualization.oca.model.overlay.input.*
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.AriesBrandingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.ClusterOrderingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.SensitiveOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.UbiqueStyleJsonOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.*
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.AttributeMappingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.EntryCodeMappingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.SubsetOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.transformation.TemplateOverlay
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal object OverlaySerializer : JsonContentPolymorphicSerializer<Overlay>(Overlay::class) {

	private val typeRegex = ".+\\/overlays\\/(.+)\\/.+".toRegex()

	override fun selectDeserializer(element: JsonElement): DeserializationStrategy<Overlay> {
		val json = element.jsonObject
		val type = json.getValue("type").jsonPrimitive.content

		val overlayName = typeRegex.matchEntire(type)?.groupValues?.get(1)
			?: throw IllegalArgumentException("Overlay type does not conform to type spec: $type")

		// TODO There's probably a better way rather than hardcoding all the overlay types
		return when (overlayName) {
			"branding" -> AriesBrandingOverlay.serializer()
			"cardinality" -> CardinalityOverlay.serializer()
			"character_encoding" -> CharacterEncodingOverlay.serializer()
			"cluster_ordering" -> ClusterOrderingOverlay.serializer()
			"conditional" -> ConditionalOverlay.serializer()
			"conformance" -> ConformanceOverlay.serializer()
			"entry" -> EntryOverlay.serializer()
			"entry_code" -> EntryCodeOverlay.serializer()
			"entry_code_mapping" -> EntryCodeMappingOverlay.serializer()
			"format" -> FormatOverlay.serializer()
			"information" -> InformationOverlay.serializer()
			"label" -> LabelOverlay.serializer()
			"mapping" -> AttributeMappingOverlay.serializer()
			"meta" -> MetaOverlay.serializer()
			"sensitive" -> SensitiveOverlay.serializer()
			"standard" -> StandardOverlay.serializer()
			"style_json" -> UbiqueStyleJsonOverlay.serializer()
			"subset" -> SubsetOverlay.serializer()
			"unit" -> UnitOverlay.serializer()
			"template" -> TemplateOverlay.serializer()
			// TODO UnitMappingOverlay is missing because the spec defines the same name as for the UnitOverlay?
			else -> throw IllegalArgumentException("Unknown overlay type: $type")
		}
	}
}
