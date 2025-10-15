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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import org.koin.dsl.module
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

data class SignedDocumentUiModel(
	val id: Long,
	val fileName: String,
	val fileData: ByteArray,
	val transactionId: String,
	val signedDate: String
)

@OptIn(ExperimentalTime::class)
class SignedDocumentsController private constructor(
	private val signedDocumentsRepository: SignedDocumentsRepository,
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				SignedDocumentsController(
					signedDocumentsRepository = get(),
					scope = scope
				)
			}
		}
	}

	val allSignedDocuments: StateFlow<List<SignedDocumentUiModel>> = 
		signedDocumentsRepository.getAllAsFlow()
			.map { documents -> documents.map { it.toUiModel() } }
			.stateIn(
				scope = scope,
				started = SharingStarted.WhileSubscribed(5000),
				initialValue = emptyList()
			)

	fun getSignedDocumentById(id: Long): SignedDocumentUiModel? {
		return signedDocumentsRepository.getById(id)?.toUiModel()
	}

	fun removeSignedDocument(id: Long) {
		signedDocumentsRepository.removeById(id)
	}

	private fun SignedDocumentModel.toUiModel(): SignedDocumentUiModel {
		val instant = Instant.fromEpochMilliseconds(this.signedDate)
		val localDateTime = instant.toLocalDateTime(TimeZone.currentSystemDefault())
		val formattedDate = "${localDateTime.dayOfMonth.toString().padStart(2, '0')}.${localDateTime.monthNumber.toString().padStart(2, '0')}.${localDateTime.year}"
		
		return SignedDocumentUiModel(
			id = this.id,
			fileName = this.fileName,
			fileData = this.fileData,
			transactionId = this.transactionId,
			signedDate = formattedDate
		)
	}
}
