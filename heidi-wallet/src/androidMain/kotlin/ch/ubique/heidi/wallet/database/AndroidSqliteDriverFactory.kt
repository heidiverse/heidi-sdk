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

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.android.AndroidSqliteDriver
import ch.ubique.heidi.wallet.HeidiDatabase

internal class AndroidSqliteDriverFactory(private val context: Context) : SqliteDriverFactory {

	override fun createDriver(): SqlDriver = AndroidSqliteDriver(
		schema = HeidiDatabase.Schema,
		context = context,
		name = SqliteDriverFactory.DATABASE_NAME,
		callback = object : AndroidSqliteDriver.Callback(
			schema = HeidiDatabase.Schema,
			callbacks = SqliteDriverFactory.migrations,
		) {
			override fun onConfigure(db: SupportSQLiteDatabase) {
				super.onConfigure(db)
				db.setForeignKeyConstraintsEnabled(true)
				db.enableWriteAheadLogging()
				db.execSQL("PRAGMA synchronous = NORMAL")
			}
		},
		windowSizeBytes = 10 * 1024 * 1024
	)
}
