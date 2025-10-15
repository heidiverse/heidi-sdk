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

package ch.ubique.heidi.wallet.credentials.credential

import ch.ubique.heidi.credentials.models.credential.CredentialType
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.heidi_wallet_rust.VerifiableCredential

// TODO Now that this is no longer used in Rust, we can get rid of it and use the CredentialsRepository directly?
class CredentialStore private constructor(private val repository: CredentialsRepository) {
	companion object {
		val koinModule = module {
			singleOf(::CredentialStore)
		}
	}

	fun getAllWhere(used: Boolean): List<VerifiableCredential> = repository.getAllWhere(used)
		.map { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }

	fun getAllWhereSchemaId(used: Boolean, schemaId: String): List<VerifiableCredential> = repository.getAllWhere(used, schemaId)
		.map { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }

	fun getUnusedMdoc() = repository.getAllWhere(
		used = false,
		types = setOf(CredentialType.Mdoc)
	).map { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }

	fun getUnusedMdocOfType(docType: String) = repository.getUnusedByTypeAndDocType(
		CredentialType.Mdoc,
		docType
	).map { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }

	fun getByIdentityId(identityId: Long) = repository.getAllFor(identityId)
		.map { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }

	fun getByName(name: String) = repository.getByName(name)?.let { VerifiableCredential(it.id, it.fk_identity_id, it.name, it.metadata, it.payload) }
}
