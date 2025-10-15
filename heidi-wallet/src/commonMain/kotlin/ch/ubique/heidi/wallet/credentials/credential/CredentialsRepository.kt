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

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToList
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyMaterialType
import ch.ubique.heidi.credentials.models.oca.OcaBundleModel
import ch.ubique.heidi.trust.framework.DocumentProvider
import ch.ubique.heidi.util.extensions.toLong
import ch.ubique.heidi.wallet.CredentialEntity
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.extensions.toModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.map
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.bind
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class CredentialsRepository private constructor(db: HeidiDatabase) : DocumentProvider {
	companion object {
		val koinModule = module {
			singleOf(::CredentialsRepository).bind<DocumentProvider>()
		}
	}

	private val queries = db.credentialQueries
	private val ocaBundleQueries = db.ocaBundleQueries

	override suspend fun getAllCredentials(): List<CredentialModel> {
		return getAllEntities().mapNotNull { it.toModel { url -> getOcaBundleForCredential(url) } }
	}

	override suspend fun getCredentialsByDocType(docType: String, includeUsedCredentials: Boolean): List<CredentialModel> {
		return getAllWhere(used = includeUsedCredentials, schemaId = docType)
			.mapNotNull { it.toModel { url -> getOcaBundleForCredential(url) } }
	}

	fun clear() {
		queries.clear()
	}

	fun getAllEntities() = queries.getAll().executeAsList()

	fun fullInsert(
		id: Long,
		name: String,
		metadata: String,
		keyMaterialType: KeyMaterialType,
		credentialType: CredentialType,
		payload: String,
		docType: String,
		ocaBundleUrl: String?,
		identityId: Long,
		used: Boolean,
		createdAt: Long,
	) = queries.fullInsert(
		id,
		name,
		metadata,
		keyMaterialType,
		credentialType,
		payload,
		docType,
		ocaBundleUrl,
		identityId,
		used.toLong(),
		createdAt,
	)

	fun insertCredential(
		name: String,
		metadata: String,
		keyMaterialType: KeyMaterialType,
		credentialType: CredentialType,
		payload: String,
		docType: String,
		ocaBundleUrl: String?,
		identityName: String,
	) = queries.transactionWithResult {
		queries.insert(name, metadata, keyMaterialType, credentialType, payload, docType, ocaBundleUrl, identityName, Clock.System.now().toEpochMilliseconds())
		val credential = queries.getByName(name).executeAsOne()
		return@transactionWithResult credential
	}

	fun getAll() = queries.getAll().executeAsList()

	fun getAllUnusedFlow() = queries.getAllUnused().asFlow().mapToList(Dispatchers.IO).map { it.onlyUsable() }

	fun getAllFor(identityId: Long) = queries.getByIdentity(identityId).executeAsList().onlyUsable()

	fun getAllWhere(
		used: Boolean,
		schemaId: String,
		types: Set<CredentialType> = CredentialType.SUPPORTED,
	) = queries.getAllByTypesAndDocTypeWhere(used.toLong(), types, schemaId).executeAsList().onlyUsable()

	fun getAllWhere(
		used: Boolean,
		types: Set<CredentialType> = CredentialType.SUPPORTED,
	) = queries.getAllByTypesWhere(used.toLong(), types).executeAsList().onlyUsable()

	fun getUnusedByTypeAndDocType(
		type: CredentialType,
		docType: String,
	) = queries.getUnusedByTypeAndDocType(type, docType).executeAsList().onlyUsable()

	fun getById(id: Long) = queries.getById(id).executeAsOneOrNull()

	fun getByName(name: String) = queries.getByName(name).executeAsOneOrNull()

	fun removeByName(name: String) = queries.removeByName(name)

	fun updateMetadataById(id: Long, metadata: String) = queries.updateMetadataById(metadata = metadata, id = id)

	fun useCredential(id: Long) {
		queries.transaction {
			queries.useCredential(id)
		}
	}

	/**
	 * Filters out credentials that don't have a usable key material
	 */
	private fun List<CredentialEntity>.onlyUsable() = this.filter { it.key_material_type != KeyMaterialType.UNUSABLE }

	private fun getOcaBundleForCredential(ocaBundleUrl: String): OcaBundleModel? {
		return ocaBundleQueries.getByUrl(ocaBundleUrl).executeAsOneOrNull()?.toModel()
	}

}
