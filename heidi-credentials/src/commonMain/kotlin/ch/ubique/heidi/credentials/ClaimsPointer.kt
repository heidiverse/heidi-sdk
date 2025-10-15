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

package ch.ubique.heidi.credentials

import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.getAll
import ch.ubique.heidi.util.extensions.isArrayLike
import ch.ubique.heidi.util.extensions.isObject
import uniffi.heidi_util_rust.Value
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_credentials_rust.QueryException
import uniffi.heidi_credentials_rust.Selector

class ClaimsPointer(val path: List<PointerPart>) : Selector {
    fun fromDepth(depth: Int) : ClaimsPointer {
        return ClaimsPointer(path.slice(depth-1..<path.size))
    }
    fun toDepth(depth: Int) : ClaimsPointer {
        return ClaimsPointer(path.slice(0..<depth))
    }
    fun key() : PointerPart {
        return path.last()
    }
    fun depth() : Int {
        return this.path.size
    }
    fun isSubPath(path: ClaimsPointer) : Boolean {
        val currentPath = this.path.toMutableList()
        if (currentPath.isEmpty() && path.path.firstOrNull() != null) {
            return false
        }
        for(p in path.path) {
            val cp = currentPath.removeFirstOrNull()
            // path is longer than this, hence it is a subpath (as we did not early return before)
            if(cp == null) {
                return true
            }
            when(cp) {
                // Index only is equal if both are index and the index is the same
                is PointerPart.Index  if(p is PointerPart.Index && cp.v1 == p.v1) -> { continue  }
                // Null is only valid on arrays, which means path can only be a subpath if it is an index or null
                // which also means it CANNOT be PointerPart.String
                is PointerPart.Null if(p is PointerPart.Null || p is PointerPart.Index ) -> { continue }
                is PointerPart.String if(p is PointerPart.String && p.v1 == cp.v1) ->  { continue }
                else -> {
                    return false
                }
            }
        }
        return this.path.size == path.path.size
    }
    override fun select(v: Value): List<Value> {
        var currentlySelected = mutableListOf<Value>(v)
        for(part in path) {
            when(part) {
                is PointerPart.String if currentlySelected.all { it.isObject() } -> {
                    currentlySelected = currentlySelected.map { it.get(part) }.filter { it !is Value.Null}.toMutableList()
                }
                is PointerPart.Index if currentlySelected.all { it.isArrayLike() } -> {
                    currentlySelected = currentlySelected.map { it.get(part) }.filter { it !is Value.Null}.toMutableList()
                }
                is PointerPart.Null if currentlySelected.all { it.isArrayLike() } -> {
                    currentlySelected = currentlySelected.flatMap { it.getAll() }.filter { it !is Value.Null}.toMutableList()
                }
                else -> throw QueryException.InvalidType()
            }
        }
        return currentlySelected
    }

    override fun resolvePtr(v: Value): List<List<PointerPart>> {
        var currentPointers = mutableListOf<MutableList<PointerPart>>(mutableListOf())
        var thePointer = mutableListOf<PointerPart>()
        for (part in path) {
            if (part is PointerPart.Null) {
                val element = ClaimsPointer(thePointer).select(v)
                if (element.size > 1 || element.isEmpty()) {
                    return emptyList()
                }
                if(!element[0].isArrayLike()) {
                    return emptyList()
                }
                val elementSize = element[0].getAll().size
                val newPointers = mutableListOf<MutableList<PointerPart>>()
                for (ptrs in currentPointers) {
                    for(i in 0..<elementSize) {
                        val p = ptrs.toMutableList()
                        p.add(PointerPart.Index(i.toULong()))
                        newPointers.add(p)
                    }
                }
                currentPointers = newPointers
            } else {
                for(ptr in currentPointers) {
                    ptr.add(part)
                }
            }
            thePointer.add(part)
        }
        return currentPointers
    }

    override fun equals(other: Any?): Boolean {
        if(other !is ClaimsPointer) {
            return false
        }
        return this.path == other.path
    }
}

operator fun Value.get(part: PointerPart): Value {
    return when (part) {
        is PointerPart.Index -> this[part.v1.toInt()]
        is PointerPart.Null -> Value.Null
        is PointerPart.String -> this[part.v1]
    }
}
operator fun Value.get(selector: Selector): List<Value> {
    return selector.select(this)
}

fun List<PointerPart>.asSelector(): Selector {
    return ClaimsPointer(this)
}
fun String.asSelector(): Selector {
    return ClaimsPointer(listOf(PointerPart.String(this)))
}
fun Int.asSelector(): Selector {
    return ClaimsPointer(listOf(PointerPart.Index(this.toULong())))
}

fun ClaimsPointer.toPointer() : List<PointerPart> {
    return this.path
}

fun List<Any?>.toClaimsPointer() : ClaimsPointer? {
    var elements = mutableListOf<PointerPart>()
    for (e in this) {
        when (e) {
            null ->  {
                elements.add(PointerPart.Null(false))
                continue
            }
            is String -> {
                elements.add(PointerPart.String(e))
                continue
            }
            is Int -> {
                elements.add(PointerPart.Index(e.toULong()))
                continue
            }
            is PointerPart -> {
                elements.add(e)
                continue
            }
            else -> {
                return null
            }
        }
    }
    return ClaimsPointer(elements)
}
