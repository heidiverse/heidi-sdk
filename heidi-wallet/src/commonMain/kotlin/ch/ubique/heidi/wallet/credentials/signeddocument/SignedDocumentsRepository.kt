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

package ch.ubique.heidi.wallet.credentials.signeddocument

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToList
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.SignedDocumentEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

data class SignedDocumentModel(
	val id: Long,
	val fileName: String,
	val fileData: ByteArray,
	val transactionId: String,
	val signedDate: Long
)

@OptIn(ExperimentalTime::class)
class SignedDocumentsRepository private constructor(db: HeidiDatabase) {
	companion object {
		val koinModule = module {
			singleOf(::SignedDocumentsRepository)
		}
	}

	private val queries = db.signedDocumentQueries

	fun clear() = queries.clear()

	fun insertSignedDocument(
		fileName: String,
		fileData: ByteArray,
		transactionId: String,
	): SignedDocumentModel {
		val signedDate = Clock.System.now().toEpochMilliseconds()
		
		return queries.transactionWithResult {
			queries.insert(
				fileName,
				fileData,
				transactionId,
				signedDate
			)
			// Get the last inserted document
			queries.getAll().executeAsList().first().toModel()
		}
	}

	fun getAll(): List<SignedDocumentModel> {
		return queries.getAll()
			.executeAsList()
			.map { it.toModel() }
	}

	fun getAllAsFlow(): Flow<List<SignedDocumentModel>> {
		return queries.getAll()
			.asFlow()
			.mapToList(Dispatchers.IO)
			.map { entities -> entities.map { entity -> entity.toModel() } }
	}

	fun getById(id: Long): SignedDocumentModel? {
		return queries.getById(id).executeAsOneOrNull()?.toModel()
	}

	fun removeById(id: Long) {
		queries.transaction {
			queries.removeById(id)
		}
	}

	private fun SignedDocumentEntity.toModel() = SignedDocumentModel(
		id = this.id,
		fileName = this.file_name,
		fileData = this.file_data,
		transactionId = this.transaction_id,
		signedDate = this.signed_date
	)
}
