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

package ch.ubique.heidi.wallet.database

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import ch.ubique.heidi.wallet.HeidiDatabase
import co.touchlab.sqliter.DatabaseFileContext
import co.touchlab.sqliter.JournalMode
import co.touchlab.sqliter.SynchronousFlag
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSURL
import platform.Foundation.NSURLIsExcludedFromBackupKey

internal class IosSqliteDriverFactory : SqliteDriverFactory {

	@OptIn(ExperimentalForeignApi::class)
	override fun createDriver(): SqlDriver {
		val fileName = SqliteDriverFactory.DATABASE_NAME
		val driver = NativeSqliteDriver(
			HeidiDatabase.Schema,
			fileName,
			onConfiguration = { config ->
				config.copy(
					journalMode = JournalMode.WAL,
					extendedConfig = config.extendedConfig.copy(
						foreignKeyConstraints = true,
						synchronousFlag = SynchronousFlag.NORMAL,
					)
				)
			},
			callbacks = SqliteDriverFactory.migrations,
		)

		val path = DatabaseFileContext.databasePath(fileName, null)

		val url = NSURL(fileURLWithPath = path)
		url.setResourceValue(true, NSURLIsExcludedFromBackupKey, null);

		return driver
	}
}
