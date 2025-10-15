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

package ch.ubique.heidi.wallet.extensions

import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.issuer.IssuerModel
import ch.ubique.heidi.credentials.models.metadata.KeyMaterialType
import ch.ubique.heidi.credentials.models.oca.OcaBundleModel
import ch.ubique.heidi.util.extensions.toBoolean
import ch.ubique.heidi.wallet.CredentialEntity
import ch.ubique.heidi.wallet.DeferredCredentialEntity
import ch.ubique.heidi.wallet.IssuerEntity
import ch.ubique.heidi.wallet.OcaBundleEntity
import uniffi.heidi_wallet_rust.VerifiableCredential
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

inline fun DeferredCredentialEntity.decodeMetadata(): List<CredentialMetadata>? {
	return CredentialMetadata.fromStringToList(this.metadata)
}

inline fun CredentialEntity.decodeMetadata(): CredentialMetadata? {
	return CredentialMetadata.fromString(this.metadata)
}

inline fun VerifiableCredential.decodeMetadata(): CredentialMetadata? {
	return CredentialMetadata.fromString(this.metadata)
}

fun IssuerEntity.toModel() = IssuerModel(
	url = url,
	credentialIssuerMetadata = credential_issuer_metadata,
	authorizationServerMetadata = authorization_server_metadata,
)

fun OcaBundleEntity.toModel() = OcaBundleModel(
	url = url,
	content = content,
	updatedAt = updated_at,
)

fun CredentialEntity.toModel(
	ocaBundleProvider: (String) -> OcaBundleModel?,
): CredentialModel? {
	return this.decodeMetadata()?.let { metadata ->
		CredentialModel(
			this.id,
			this.fk_identity_id,
			this.name,
			metadata,
			this.key_material_type,
			this.credential_type,
			this.payload,
			this.doc_type,
			this.fk_oca_bundle_url?.let { ocaBundleProvider.invoke(it) },
			this.used.toBoolean(),
			this.created_at
		)
	}
}

@OptIn(ExperimentalTime::class)
fun DeferredCredentialEntity.toModel() : CredentialModel? {
	return this.decodeMetadata()?.firstOrNull()?.let { metadata ->
		CredentialModel(
			this.id,
			this.fk_identity_id,
			this.transaction_id,
			metadata,
			KeyMaterialType.UNUSABLE,
			CredentialType.Unknown,
			this.transaction_id,
			this.doc_type,
			null,
			false,
			Clock.System.now().toEpochMilliseconds()
		)
	}
}
