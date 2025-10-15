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

package ch.ubique.heidi.wallet.keyvalue

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToOneOrNull
import ch.ubique.heidi.wallet.HeidiDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.map
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class KeyValueRepository private constructor(db: HeidiDatabase) {
	companion object {
		val koinModule = module {
			singleOf(::KeyValueRepository)
		}
	}

	private val queries = db.keyValueQueries

	fun clear() = queries.clear()

	fun getAllEntities() = queries.getAll().executeAsList()

	fun fullInsert(
		key: String,
		value: String?,
		updatedAt: Long,
	) = queries.fullInsert(key, value, updatedAt)

	fun getForFlow(key: KeyValueEntry) = queries.getByKey(key.toString()).asFlow().mapToOneOrNull(Dispatchers.IO).map { it?.value_ }

	fun getFor(key: KeyValueEntry) = queries.getByKey(key.toString()).executeAsOneOrNull()?.value_

	fun setFor(key: KeyValueEntry, value: String?) =
		queries.setValueForKey(key.toString(), value, Clock.System.now().toEpochMilliseconds())

}
