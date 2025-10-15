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

package ch.ubique.heidi.visualization.oca.model.overlay.transformation

import ch.ubique.heidi.visualization.oca.model.SAID_HASH_PLACEHOLDER
import ch.ubique.heidi.visualization.oca.model.content.AttributeName
import ch.ubique.heidi.visualization.oca.model.content.SAID
import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AttributeMappingOverlay(
	@SerialName("attribute_mapping") val attributeMapping: Map<AttributeName, AttributeName>,
	@SerialName("capture_base") override val captureBase: SAID,
	@SerialName("type") override val type: String = "spec/overlays/mapping/1.0",
	@SerialName("digest") override val digest: SAID = SAID_HASH_PLACEHOLDER,
) : TransformationOverlay {

	fun mapAttributeName(input: AttributeName) = attributeMapping[input] ?: input
	override fun updateDigest(digest: SAID, captureBase: SAID): Overlay = copy(digest = digest, captureBase = captureBase)
}
