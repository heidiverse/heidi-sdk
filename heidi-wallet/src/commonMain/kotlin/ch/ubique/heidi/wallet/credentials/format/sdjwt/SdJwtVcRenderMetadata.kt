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

package ch.ubique.heidi.wallet.credentials.format.sdjwt

import ch.ubique.heidi.credentials.sdjwt.SdJwtVcMetadata
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * An extension to the IETF standard SD-JWT VC Metadata (see [SdJwtVcMetadata]) with the OCA reference from the Swiss OCA spec (see https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
 */
data class SdJwtVcRenderMetadata(
	@SerialName("render") val render: SdJwtVcRender? = null,
)

@Serializable
data class SdJwtVcRender(
	@SerialName("type") val type: String,
	@SerialName("oca") val oca: String,
)
