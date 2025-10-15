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

package ch.ubique.heidi.wallet.credentials.oca

import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.extensions.toModel
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class OcaRepository private constructor(db: HeidiDatabase) {
	companion object {
		val koinModule = module {
			singleOf(::OcaRepository)
		}
	}

	private val queries = db.ocaBundleQueries

	fun clear() = queries.clear()

	fun getAllEntities() = queries.getAll().executeAsList()

	fun fullInsert(
		url: String,
		content: String,
		updatedAt: Long,
	) = queries.fullInsert(
		url,
		content,
		updatedAt,
	)

	fun getForUrl(url: String) = queries.getByUrl(url).executeAsOneOrNull()?.toModel()

	fun getAll() = queries.getAll().executeAsList().map { it.toModel() }

	fun insertOrUpdateOca(url: String, json: String) {
		if (queries.exists(url).executeAsOne()) {
			queries.update(json, Clock.System.now().toEpochMilliseconds(), url)
		} else {
			queries.insert(url, json, Clock.System.now().toEpochMilliseconds())
		}
	}
}
