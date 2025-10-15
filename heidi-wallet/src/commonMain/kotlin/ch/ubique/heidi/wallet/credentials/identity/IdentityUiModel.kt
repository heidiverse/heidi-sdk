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

package ch.ubique.heidi.wallet.credentials.identity

import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.wallet.credentials.activity.ActivityUiModel
import ch.ubique.heidi.wallet.credentials.credential.CredentialUiModel
import ch.ubique.heidi.wallet.credentials.signature.Signature
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.deferredCard
import ch.ubique.heidi.wallet.credentials.ViewModelFactory

sealed interface IdentityUiModel {
	val id : Long
	val isUsable: Boolean
	val name: String
	val docType: String
	val hasEmergencyPass: Boolean
	val hasOnlyEmergencyPass: Boolean
	val card: LayoutData.Card
	val isPid: Boolean
	val title: String
	val subtitle: String
	val credentials: List<CredentialModel>
	val activities: List<ActivityUiModel>
	val isRevoked: Boolean
	val isRefreshable: Boolean
	val frostBlob: String?
	var credentialUiModel : List<CredentialUiModel>
	fun getCredentialUiModel(viewModelFactory: ViewModelFactory) : List<CredentialUiModel> {
		if (credentialUiModel.isEmpty() || credentialUiModel.size != credentials.size) {
			credentialUiModel = credentials.map { viewModelFactory.getCredentialViewModel(it, frostBlob) }
		}
		return credentialUiModel
	}
	fun getCredentialUiModelForSingle(cred: CredentialModel, viewModelFactory: ViewModelFactory) : CredentialUiModel {
		return viewModelFactory.getCredentialViewModel(cred, frostBlob)
	}
	fun getCredentialUiModelForCredentialId(credId: Long, viewModelFactory: ViewModelFactory) : CredentialUiModel? {
		val cred = credentials.firstOrNull{ it.id == credId } ?: return null
		return viewModelFactory.getCredentialViewModel(cred, frostBlob)
	}
	data class IdentityUiCredentialModel(
		override val id: Long,
		override val name: String,
		override val card: LayoutData.Card,
		override val title: String,
		override val subtitle: String,
		val signature: Signature,
		val detailList: LayoutData.DetailList,
		override val hasEmergencyPass: Boolean,
		override val hasOnlyEmergencyPass: Boolean,
		override val credentials: List<CredentialModel>,
		override val activities: List<ActivityUiModel>,
		override val isPid: Boolean,
		override val isUsable: Boolean,
		override val isRevoked: Boolean,
		override val isRefreshable: Boolean,
		override val docType: String,
		override val frostBlob: String?,
		override var credentialUiModel: List<CredentialUiModel>,
		) : IdentityUiModel
	data class IdentityUiDeferredModel(
		override val id: Long,
		override val name : String,
		override val isUsable: Boolean,
		val transactionId: String,
		override val docType: String,
		override val hasEmergencyPass: Boolean = false,
		override val hasOnlyEmergencyPass: Boolean = false,
		override val card: LayoutData.Card,
		override val isPid: Boolean = false,
		override val title: String = card.title ?: "",
		override val subtitle: String = card.subtitle ?: "",
		override val credentials: List<CredentialModel> = emptyList(),
		override val activities: List<ActivityUiModel> = emptyList(),
		override val isRevoked: Boolean = false,
		override val isRefreshable: Boolean = false,
		override val frostBlob: String?,
		override var credentialUiModel: List<CredentialUiModel>,
	) : IdentityUiModel
	fun isDeferred() : Boolean {
		return this is IdentityUiDeferredModel
	}
}
