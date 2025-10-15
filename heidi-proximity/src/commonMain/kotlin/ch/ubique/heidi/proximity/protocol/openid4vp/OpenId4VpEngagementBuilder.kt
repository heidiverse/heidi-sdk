/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.proximity.protocol.openid4vp

import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import kotlin.uuid.Uuid

internal class OpenId4VpEngagementBuilder(
	private val verifierName: String,
	private val encodedPublicKey: String,
	private val serviceUuid: Uuid,
) : EngagementBuilder {

	companion object {
		private const val KEY_VERIFIER_NAME = "name"
		private const val KEY_PUBLIC_KEY = "key"
		private const val KEY_SERVICE_UUID = "uuid" // UUID isn't part of the official OpenID4VP specification
	}

	override fun createQrCodeForEngagement(): String {
		// TODO Use an URI-builder (which doesn't exist yet in the KMP Standard Library)
		return buildString {
			append(OpenId4VpTransportProtocol.OPENID4VP_SCHEME)
			append("://")
			append(OpenId4VpTransportProtocol.OPENID4VP_PATH)
			append("?")
			append("$KEY_VERIFIER_NAME=$verifierName")
			append("&")
			append("$KEY_PUBLIC_KEY=$encodedPublicKey")
			append("&")
			append("$KEY_SERVICE_UUID=$serviceUuid")
		}
	}
}
