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

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToList
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.identity.IdentityModel
import ch.ubique.heidi.credentials.models.issuer.IssuerModel
import ch.ubique.heidi.credentials.models.metadata.Tokens
import ch.ubique.heidi.credentials.models.oca.OcaBundleModel

import ch.ubique.heidi.util.extensions.toBoolean
import ch.ubique.heidi.util.extensions.toLong
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.IdentityEntity
import ch.ubique.heidi.wallet.extensions.toModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

class IdentityRepository private constructor(db: HeidiDatabase) {
	companion object {
		val koinModule = module {
			singleOf(::IdentityRepository)
		}
	}

	private val queries = db.identityQueries
	private val issuerQueries = db.issuerQueries
	private val credentialQueries = db.credentialQueries
	private val activityQueries = db.activityQueries
	private val ocaBundleQueries = db.ocaBundleQueries

	private val json = Json { ignoreUnknownKeys = true }

	fun clear() {
		queries.clear()
	}

	fun getAllEntities() = queries.getAll().executeAsList()

	fun fullInsert(
		id: Long,
		name: String,
		tokens: String,
		frostBlob: String?,
		emergencyTokens: String?,
		oidcSettings: String?,
		issuerUrl: String,
		credentialConfigurationIds: String?,
		isPid: Boolean,
	) = queries.fullInsert(
		id,
		name,
		tokens,
		frostBlob,
		emergencyTokens,
		oidcSettings,
		issuerUrl,
		credentialConfigurationIds,
		isPid.toLong(),
	)

	fun getAll(): List<IdentityModel> {
		return queries.getAll()
			.executeAsList()
			.map { it.toModel() }
	}

	fun getPids(): List<IdentityModel> {
		return queries.getPids()
			.executeAsList()
			.map { it.toModel() }
	}

	fun getNonPids(withIssuerData : Boolean = true): List<IdentityModel> {
		return queries.getNonPids()
			.executeAsList()
			.map { it.toModel(withIssuerData) }
	}

	fun getNonPidCount(): Long {
		return queries.getNonPidCount().executeAsOne()
	}

	fun hasId(): Boolean {
		return queries.existId().executeAsOneOrNull() ?: false
	}

	fun getById(id: Long) = queries.getById(id).executeAsOneOrNull()?.toModel()

	fun getByActivityId(activityId: Long) = queries.getByActivityId(activityId).executeAsOneOrNull()?.toModel()

	fun getAllAsFlow(): Flow<List<IdentityModel>> {
		val identitiesFlow = queries.getAll()
			.asFlow()
			.mapToList(Dispatchers.IO)
			.combine(activityQueries.getAll().asFlow().mapToList(Dispatchers.IO)) { identities, _ ->
				identities // make sure that activities updates trigger the flow
			}

		return combine(
			identitiesFlow,
			issuerQueries.getAll().asFlow().mapToList(Dispatchers.IO),
			credentialQueries.getAll().asFlow().mapToList(Dispatchers.IO)
		) { identities, issuers, credentials ->
			identities.mapNotNull { identity ->
				issuers.firstOrNull { it.url == identity.fk_issuer_url }?.toModel()?.let { issuer ->
					IdentityModel(
						identity.id,
						identity.name,
						Json.decodeFromString<Tokens>(identity.tokens),
						identity.emergency_tokens?.let { Json.decodeFromString<Tokens>(it) },
						identity.frost_blob,
						identity.oidc_settings,
						issuer,
						identity.credential_configuration_ids,
						credentials.filter { it.fk_identity_id == identity.id }
							.mapNotNull { it.toModel { url -> getOcaBundleForCredential(url) } },
						identity.is_pid?.toBoolean() ?: false,
					)
				}
			}

		}
	}

	fun insertIdentity(
		name: String,
		tokens: Tokens,
		oidcSettings: String?,
		issuerUrl: String,
		credentialConfigurationIds: String,
		isPid: Boolean,
	): IdentityModel {
		return queries.transactionWithResult {
			queries.insert(
				name,
				json.encodeToString(tokens),
				oidcSettings,
				issuerUrl,
				credentialConfigurationIds,
				isPid.toLong()
			)
			queries.getByName(name).executeAsOne().toModel()
		}
	}

	fun getByName(name: String) = queries.getByName(name).asFlow().map {
		it.executeAsOneOrNull()?.let { identity ->
			IdentityModel(
				identity.id,
				identity.name,
				Json.decodeFromString<Tokens>(identity.tokens),
				identity.emergency_tokens?.let { Json.decodeFromString<Tokens>(it) },
				identity.frost_blob,
				identity.oidc_settings,
				getIssuerForIdentity(identity.fk_issuer_url),
				identity.credential_configuration_ids,
				getCredentialsForIdentity(identity.id),
				identity.is_pid?.toBoolean() ?: false,
			)
		}
	}

	fun setFrostBlob(frostBlob: String, tokens: String, name: String) {
		queries.transaction {
			queries.setBackup(frostBlob, tokens, name)
		}
	}

	fun getFrostBlob(name: String): String? {
		val identity = queries.getByName(name).executeAsOneOrNull()
		return identity?.frost_blob
	}

	fun updateTokens(id: Long, tokens: Tokens) {
		val encodedTokens = json.encodeToString(tokens)
		queries.transaction {
			queries.setTokens(encodedTokens, id);
		}
	}

	fun remove(identity: IdentityEntity) {
		queries.transaction {
			queries.removeByName(identity.name)
		}
	}

	fun removeById(id: Long) {
		queries.transaction {
			queries.removeById(id)
		}
	}

	fun removeByName(name: String) {
		queries.transaction {
			queries.removeByName(name)
		}
	}

	private fun IdentityEntity.toModel(withIssuerData: Boolean = true) = IdentityModel(
		this.id,
		this.name,
		Json.decodeFromString(this.tokens),
		this.emergency_tokens?.let { Json.decodeFromString(it) },
		this.frost_blob,
		this.oidc_settings,
		if(withIssuerData) { getIssuerForIdentity(this.fk_issuer_url) } else {
			IssuerModel("", "", null)} ,
		this.credential_configuration_ids,
		getCredentialsForIdentity(this.id),
		this.is_pid?.toBoolean() ?: false,
	)

	private fun getIssuerForIdentity(url: String): IssuerModel {
		return issuerQueries.getByUrl(url).executeAsOne().toModel()
	}

	private fun getCredentialsForIdentity(identityId: Long): List<CredentialModel> {
		return credentialQueries.getByIdentity(identityId)
			.executeAsList()
			.mapNotNull { it.toModel { url -> getOcaBundleForCredential(url) } }
	}

	private fun getOcaBundleForCredential(ocaBundleUrl: String): OcaBundleModel? {
		return ocaBundleQueries.getByUrl(ocaBundleUrl).executeAsOneOrNull()?.toModel()
	}

}
