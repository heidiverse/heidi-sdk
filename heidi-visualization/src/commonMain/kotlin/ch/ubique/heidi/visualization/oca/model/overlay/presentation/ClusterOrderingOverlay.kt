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

import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutSection
import ch.ubique.heidi.visualization.layout.LayoutSectionProperty
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.oca.model.SAID_HASH_PLACEHOLDER
import ch.ubique.heidi.visualization.oca.model.content.AttributeName
import ch.ubique.heidi.visualization.oca.model.content.SAID
import ch.ubique.heidi.visualization.oca.model.overlay.Localized
import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import ch.ubique.heidi.visualization.oca.processing.ProcessedAttribute
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClusterOrderingOverlay(
	@SerialName("cluster_order") val clusterOrder: Map<String, Int>,
	@SerialName("cluster_labels") val clusterLabels: Map<String, String?>,
	@SerialName("attribute_cluster_order") val attributeClusterOrder: Map<String, Map<AttributeName, Int>>,
	@SerialName("capture_base") override val captureBase: SAID,
	@SerialName("type") override val type: String = "admin-ch/overlays/cluster_ordering/1.0",
	@SerialName("language") override val language: String,
	@SerialName("digest") override val digest: SAID = SAID_HASH_PLACEHOLDER,
) : PresentationOverlay, Localized {
	override fun updateDigest(digest: SAID, captureBase: SAID): Overlay = copy(digest = digest, captureBase = captureBase)
	override fun presentsAttributes() = attributeClusterOrder.values.flatMap { it.keys }

	fun process(
		layoutType: LayoutType,
		attributeProcessor: (AttributeName) -> ProcessedAttribute?
	): LayoutData? {
		return when (layoutType) {
			LayoutType.CARD -> null
			LayoutType.DETAIL_LIST -> {
				val sections = clusterOrder.keys
					.sortedBy { clusterOrder.getValue(it) }
					.map { clusterKey ->
						val sectionContent = attributeClusterOrder[clusterKey]?.let { attributeMap ->
							attributeMap.keys
								.sortedBy { attributeMap.getValue(it) }
								.mapNotNull { attributeName ->
									attributeProcessor.invoke(attributeName)?.let { attribute ->
										LayoutSectionProperty(
											attribute.attributeValue,
											attribute.label,
											attribute.information,
										)
									}
								}
						}
						LayoutSection(
							sectionTitle = clusterLabels[clusterKey],
							sectionContent = sectionContent ?: emptyList()
						)
					}
				LayoutData.DetailList(sections)
			}
		}
	}
}
