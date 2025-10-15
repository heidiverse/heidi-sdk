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

package ch.ubique.heidi.wallet.credentials.activity

import ch.ubique.heidi.trust.framework.swiss.model.TrustData
import ch.ubique.heidi.wallet.credentials.LocalizedKeyValue
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed interface ActivityUiModel {
	val id: Long
	val type: ActivityType
	val insertedAt: String
	val frameworkId: String?

	@Serializable
	data class Issuance(
		override val id: Long,
		override val frameworkId: String?,
		@SerialName("activityType") override val type: ActivityType,
		override val insertedAt: String,
		val issuanceTrustData: TrustData.Issuance,
	) : ActivityUiModel

	@Serializable
	data class Proof(
		override val id: Long,
		override val frameworkId: String?,
		@SerialName("activityType") override val type: ActivityType,
		override val insertedAt: String,
		val values: List<LocalizedKeyValue>?,
		val verificationTrustData: TrustData.Verification,
	) : ActivityUiModel
}
