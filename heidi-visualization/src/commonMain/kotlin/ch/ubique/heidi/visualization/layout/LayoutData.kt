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

package ch.ubique.heidi.visualization.layout

import ch.ubique.heidi.visualization.oca.model.content.TextShade

fun deferredCard(name: String) : LayoutData.Card {
	return LayoutData.Card(
		name,
		"",
		"Deferred Issuance: $name",
		"Touch for issuance trial",
		TextShade.DARK,
		0xffffffffL,
		null,
		null
	)
}
sealed interface LayoutData {

	data class Card(
		val credentialName: String?,
		val issuerName: String?,
		val title: String?,
		val subtitle: String?,
		val textColor: TextShade,
		val cardColor: Long?,
		val backgroundImage: LayoutCardImage?,
		val overlays: List<LayoutCardOverlay>?
	) : LayoutData

	data class DetailList(val sections: List<LayoutSection>) : LayoutData

	data class Raw(val payload: String) : LayoutData

}
