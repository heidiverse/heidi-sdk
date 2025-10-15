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

package ch.ubique.heidi.util.json

import ch.ubique.heidi.dcql.*
import kotlin.test.Test
import kotlin.test.assertEquals

class TestDcqlFromAttributes {

	@Test
	fun testGenerateDcqlSdJwt() {
		val att1 = Attribute(id = 0, name = "given_name", type = AttributeType.STRING, displayName = mapOf("en-US" to "something"))
		val att2 = Attribute(id = 0, name = "family_name", type = AttributeType.STRING, displayName = mapOf("en-US" to "something"))
		val input1: List<Attribute> = listOf(att1, att2)

		val query = parseDcqlQuery(
			"""
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
		)

		val result = sdJwtDcqlClaimsFromAttributes(input1)
		val claims = query.credentials?.get(0)?.claims

		assertEquals(result, claims);
	}


	@Test
	fun testGenerateDcqlMDoc() {
		val att1 = Attribute(id = 0, name = "given_name", type = AttributeType.STRING, displayName = mapOf("en-US" to "something"))
		val att2 = Attribute(id = 0, name = "family_name", type = AttributeType.STRING, displayName = mapOf("en-US" to "something"))
		val input1: List<Attribute> = listOf(att1, att2)

		val query = parseDcqlQuery(
			"""
            {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [
                            {"path": ["org.iso.18013.5.1", "given_name"]},
                            {"path": ["org.iso.18013.5.1", "family_name"]}
                        ]
                    }
                ]
            }
            """.trimIndent()
		)

		val result = mDocDcqlClaimsFromAttributes(input1)
		val claims = query.credentials?.get(0)?.claims

		assertEquals(result, claims);
	}




}
