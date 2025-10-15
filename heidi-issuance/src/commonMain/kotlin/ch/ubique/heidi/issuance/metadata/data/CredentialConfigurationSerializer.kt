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

package ch.ubique.heidi.issuance.metadata.data

import ch.ubique.heidi.util.extensions.jsonPrimitiveOrNull
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

internal class CredentialConfigurationSerializer :
	JsonContentPolymorphicSerializer<CredentialConfiguration>(CredentialConfiguration::class) {

	companion object {
		private const val FORMAT_MDOC = "mso_mdoc"
		private const val FORMAT_SD_JWT = "dc+sd-jwt"
		private const val FORMAT_LEGACY_SD_JWT = "vc+sd-jwt"
		private const val FORMAT_W3C_VCDM = "vc+sd-jwt"
	}

	override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialConfiguration> {
		val json = element.jsonObject
		val format = json.getValue("format").jsonPrimitiveOrNull()?.contentOrNull

		if (format == FORMAT_W3C_VCDM && (json["vct"] == null)) {
			return CredentialConfiguration.SdJwtVcdm.serializer()
		}

		return when (format) {
			FORMAT_MDOC -> CredentialConfiguration.Mdoc.serializer()
			FORMAT_SD_JWT, FORMAT_LEGACY_SD_JWT -> CredentialConfiguration.SdJwt.serializer()
			else -> CredentialConfiguration.Unknown.serializer()
		}
	}
}
