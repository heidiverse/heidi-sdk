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

package ch.ubique.heidi.wallet.database.migrations

import app.cash.sqldelight.Query
import app.cash.sqldelight.db.AfterVersion
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial

/**
 * This migration renames the class discriminator field for the serialized [KeyMaterial] sealed class in the credential entity.
 * This is required because the [KeyMaterial] file was moved from the heidi-wallet module to the heidi-credentials module.
 * By default, KotlinX Serialization uses the fully qualified class name as the class discriminator, which is different after a package move.
 *
 * Note: Do NOT run migrations in a transaction, since the NativeSqliteDriver runs them in a transaction anyway and causes the migration to fail.
 * See: https://github.com/sqldelight/sqldelight/issues/3812 and https://sqldelight.github.io/sqldelight/2.0.2/multiplatform_sqlite/migrations/
 */
internal val V1To2RenameKeyMaterialClassDiscriminator = AfterVersion(1) { driver ->
	val readQuery = """
		SELECT id, metadata FROM credentialEntity
	""".trimIndent()

	data class Credential(val id: Long, val metadata: String)

	val credentials = Query(0, driver, readQuery) { cursor ->
		val id = requireNotNull(cursor.getLong(0))
		val metadata = requireNotNull(cursor.getString(1))
		Credential(id, metadata)
	}.executeAsList()

	val credentialsWithRenamedKeyMaterial = credentials.map { credential ->
		credential.copy(
			metadata = credential.metadata.replace("ch.ubique.heidi.wallet.credentials.metadata.KeyMaterial", "KeyMaterial")
		)
	}

	credentialsWithRenamedKeyMaterial.forEach { credential ->
		val updateQuery = """
			UPDATE credentialEntity
			SET metadata = ?
			WHERE id = ?
		""".trimIndent()
		driver.execute(null, updateQuery, 2) {
			bindString(0, credential.metadata)
			bindLong(1, credential.id)
		}
	}
}

