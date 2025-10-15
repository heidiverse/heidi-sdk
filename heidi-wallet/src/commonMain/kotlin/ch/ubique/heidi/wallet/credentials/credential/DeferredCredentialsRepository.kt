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
import ch.ubique.heidi.credentials.models.identity.DeferredIdentity
import ch.ubique.heidi.wallet.DeferredCredentialEntity
import ch.ubique.heidi.wallet.HeidiDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.map
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

class DeferredCredentialsRepository private constructor(db: HeidiDatabase)  {
	companion object {
		val koinModule = module {
			singleOf(::DeferredCredentialsRepository)
		}
	}

	private val queries = db.deferredCredentialQueries
	private val identities = db.identityQueries

	fun getAll()= queries.getAll().executeAsList().map {
		it.toIdentityModel()
	}
	fun getAllAsFlow() = queries.getAll().asFlow().mapToList(Dispatchers.IO).map {
		it.map { it.toIdentityModel() }
	}
	fun insert(identityName: String, transactionId: String, metadata: String, docType: String) = queries.transactionWithResult {
		queries.insert(transactionId, metadata, docType, identityName)
		queries.getForTransactionId(transactionId).executeAsOneOrNull()?.toIdentityModel()
	}
	fun useTransactionId(transactionId: String) = queries.useTransactionId(transactionId)
	fun getForTransactionId(transactionId: String) = queries.getForTransactionId(transactionId).executeAsOneOrNull()
	fun getIdentityForTransactionId(transactionId: String) = queries.transactionWithResult {
		val df = queries.getForTransactionId(transactionId).executeAsOneOrNull() ?: return@transactionWithResult null
		return@transactionWithResult  identities.getById(df.fk_identity_id).executeAsOneOrNull()
	}

	private fun DeferredCredentialEntity.toIdentityModel() = DeferredIdentity(
		this.id,
		this.transaction_id,
		this.metadata,
		this.doc_type,
		getIdentityForTransactionId(this.transaction_id)?.name ?: this.transaction_id ,
		this.used != 0L
	)
}
