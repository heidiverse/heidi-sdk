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

package ch.ubique.heidi.dcql

import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_dcql_rust.ClaimsQuery
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.Meta

// Test
fun DcqlQuery.isSubset(superset: DcqlQuery) : Boolean {
    val allowedCredentials = mutableListOf<CredentialQuery>()
    // we don't ask for any credentials?
    if(this.credentials == null) {
        return true
    }
    for(c in this.credentials) {
        val isAllowed = superset.credentials?.any {
            val sameCredentialTypes = it.format == c.format
            if(c.claims == null) {
                //verify if we contain all elements?
                return sameCredentialTypes && it.claims == null
            }

            sameCredentialTypes && (c.claims.all { askedClaim ->
				it.claims?.any { attestedClaim ->
					attestedClaim.path == askedClaim.path
				} != false
            })
        } ?: return false
        if(isAllowed) {
            allowedCredentials.add(c)
        }
    }

    //TODO:  check for credential sets
    return allowedCredentials.isNotEmpty() && allowedCredentials.size == this.credentials.size
}
fun DcqlQuery.disallowedClaims(superset: DcqlQuery) : List<ClaimsQuery> {
    val disallowedClaims = mutableListOf<ClaimsQuery>()
    // we don't ask for any credentials?
    if(this.credentials == null) {
        return emptyList()
    }
    for(c in this.credentials) {
        superset.credentials?.any {
            if(it.format != c.format) {
                return@any false
            }
//            if(it.meta?.similar(c.meta) == false) {
//                return@any false
//            }
            if(c.claims == null) {
                //verify if we contain all elementa?
                return emptyList()
            }
            val cs = c.claims.toMutableList()
            cs.removeAll { askedClaims ->
                it.claims?.any {
                    it.path == askedClaims.path
                } ?: false
            }
            disallowedClaims.addAll(cs)
        } ?: return c.claims ?: emptyList()
    }
    return disallowedClaims
}

fun Meta.similar(other: Meta?) : Boolean {
    if(other == null) {
        return false
    }
    return when(this) {
        is Meta.IsoMdoc -> when(other) {
            is Meta.IsoMdoc -> this.doctypeValue == other.doctypeValue
            else -> false
        }
        is Meta.SdjwtVc -> when(other) {
            is Meta.SdjwtVc -> this.vctValues.containsAll(other.vctValues)
            else -> false
        }
        is Meta.W3c -> when(other) {
            is Meta.W3c -> this.credentialTypes.containsAll(other.credentialTypes)
            else -> false
        }
    }
}


fun ClaimsQuery.pathString() : String {
    return this.path.joinToString(separator = ".") {
        when(it) {
            is PointerPart.Index -> "${it.v1}"
            is PointerPart.Null ->  "null"
            is PointerPart.String -> it.v1
        }
    }
}

fun claimsQueryToPathString(claimsQuery: ClaimsQuery) : String {
    return claimsQuery.pathString()
}
