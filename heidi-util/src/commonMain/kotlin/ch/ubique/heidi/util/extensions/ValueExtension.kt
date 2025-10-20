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

package ch.ubique.heidi.util.extensions

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.double
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull

import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.MapEntry
import uniffi.heidi_util_rust.OrderedMap
import uniffi.heidi_util_rust.Value.Tag
import uniffi.heidi_util_rust.decodeCbor

fun Value.isObject() = this is Value.Object || this is Value.OrderedObject
fun Value.isArray() = this is Value.Array
fun Value.isBytes() = this is Value.Bytes
fun Value.isArrayLike() = this.isArray() || this.isArray()
fun Value.isTag() = this is Value.Tag
fun Value.isString() = this is Value.String
fun Value.isNumber() = this is Value.Number
fun Value.isBoolean() = this is Value.Boolean

val json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

inline fun <reified T> T.toValue() : Value {
    return json.decodeFromJsonElement(json.encodeToJsonElement(this))
}

inline fun <reified T> Value.transform() : T? {
    return try {
        json.decodeFromJsonElement(json.encodeToJsonElement(this))
    } catch (ex: Exception) {
        null
    }
}

inline fun <reified T> Value.safeTransform() : T? {
    return try {
        json.decodeFromString(this.toCanonicalJson())
    } catch (ex: Exception) {
        null
    }
}
fun Value.printableString() : String {
    return when(this) {
        is Value.Array -> this.v1.map { it.printableString() }.joinToString { "," }
        is Value.Boolean -> this.v1.toString()
        is Value.Bytes -> this.v1.map { it.toString() }.joinToString { "," }
        Value.Null -> return "null"
        is Value.Number -> return this.v1.toString()
        is Value.Object -> {
            var str = ""
            for((key, obj) in this.v1) {
                str += "$key => ${obj.printableString()}\n"
            }
            return str
        }
        is Value.OrderedObject -> {
            var str = ""
            for((key, obj) in this.v1.entries) {
                str += "$key => ${obj.printableString()}\n"
            }
            return str
        }
        is Value.String -> return this.v1
        is Tag -> return "${this.value.firstOrNull()?.printableString()}"
    }
}

fun Value.asObject() : Map<String, Value>? {
    return when (this) {
        is Value.Object -> this.v1
        is Value.OrderedObject if this.v1.entries.all { it.key.isString() } -> {
            this.toStringMap()
        }
        else -> null
    }
}
fun Value.asOrderedObject() : OrderedMap? {
    return when(this) {
        is Value.OrderedObject -> this.v1
        else -> null
    }
}
fun Value.toStringMap(): Map<String, Value>? {
    if(this !is Value.OrderedObject) {
        return null
    }
    val map = mutableMapOf<String, Value>()
    for(entry in this.v1.entries) {
        if (!entry.key.isString()) {
            return null
        }
        map.put(entry.key.asString()!!, entry.value)
    }
    return map
}

fun Value.asBoolean() : Boolean? {
    return when (this) {
        is Value.Boolean -> this.v1
        else -> null
    }
}

fun Value.asArray() : List<Value>? {
    return when (this) {
        is Value.Array -> this.v1
        else -> null
    }
}
fun Value.asBytes() : ByteArray? {
    return when (this) {
        is Value.Bytes -> this.v1
        else -> null
    }
}
fun Value.asTag() : Tag? {
    return when (this) {
        is Value.Tag -> this
        else -> null
    }
}
fun Value.asString() : String? {
    return when (this) {
        is Value.String -> this.v1
        else -> null
    }
}
fun Value.asDouble() : Double? {
    return when (this) {
        is Value.Number if this.v1 is JsonNumber.Float -> this.v1.v1
        else -> null
    }
}
fun Value.asLong() : Long? {
    return when (this) {
        is Value.Number if this.v1 is JsonNumber.Integer -> this.v1.v1
        else -> null
    }
}

operator fun Value.get(index: Int) : Value {
    return when (this) {
        is Value.Array -> {
            if (index > this.v1.count()) {
                return Value.Null
            }
            this.v1[index]
        }
        is Value.Bytes -> {
            if (index > this.v1.count()) {
                return Value.Null
            }
            Value.Number(JsonNumber.Integer(this.v1[index].toLong()))
        }
        else -> Value.Null
    }
}
operator fun Value.get(key: String) : Value {
    return when (this) {
        is Value.Object -> {
            this.v1[key] ?: Value.Null
        }
        is Value.OrderedObject -> {
            this.v1[key] ?: Value.Null
        }
        else -> Value.Null
    }
}
fun Value.getAll() : List<Value> {
    return when (this) {
        is Value.Array -> { this.v1.toList() }
        is Value.Bytes -> {
            this.v1.map { Value.Number(JsonNumber.Integer(it.toLong())) }
        }
        else -> emptyList()
    }
}

operator fun OrderedMap.get(v: Value): Value? {
    return this.entries.firstOrNull { it.key.isSame(v)}?.value
}
operator fun OrderedMap.get(v: String): Value? {
    return this.entries.firstOrNull { it.key.asString() == v}?.value
}

fun JsonNumber.isSame(other: JsonNumber) : Boolean {
    return when(this) {
        is JsonNumber.Float if other is JsonNumber.Float-> return this.v1 == other.v1
        is JsonNumber.Integer if other is JsonNumber.Integer -> return this.v1 == other.v1
        else -> return false
    }
}

fun Value.isSame(other: Value) : Boolean {
    return when( this) {
        is Value.Array if other is Value.Array && this.v1.size == other.v1.size -> {
            for (i in 0..<this.v1.size) {
                if (!this.v1[i].isSame(other.v1[i])) {
                    return false
                }
            }
            return true
        }
        is Value.Boolean if other is Value.Boolean -> return this.v1 == other.v1
        is Value.Bytes if other is Value.Bytes -> return this.v1.contentEquals(other.v1)
        is Value.Null if other is Value.Null -> return true
        is Value.Number if other is Value.Number -> this.v1.isSame(other.v1)
        is Value.Object if other is Value.Object && this.v1.size == other.v1.size -> {
            val thisEntries = this.v1.entries.toList()
            val otherEntries = other.v1.entries.toList()
            for (i in 0..<this.v1.size) {
                val thisEntry = thisEntries[i]
                val otherEntry = otherEntries[i]
                if(thisEntry.key != otherEntry.key || !thisEntry.value.isSame(otherEntry.value)) {
                    return false
                }
            }
            return true
        }
        is Value.OrderedObject if other is Value.OrderedObject && this.v1.entries.size == other.v1.entries.size -> {
            for (i in 0..<this.v1.entries.size) {
                val thisEntry = this.v1.entries[i]
                val otherEntry = other.v1.entries[i]
                if(thisEntry.key != otherEntry.key || !thisEntry.value.isSame(otherEntry.value)) {
                    return false
                }
            }
            return true
        }
        is Value.String if other is Value.String -> return this.v1 == other.v1
        is Tag if other is Tag && this.value.size == 1 && other.value.size == 1 -> return this.tag == other.tag && this.value[0].isSame(other.value[0])
        else -> return false
    }
}

fun ByteArray.toValue() : Value {
    return decodeCbor(this)
}
fun Value.toValue() : Value {
    return when(this) {
        is Value.Bytes -> this.v1.toValue()
        else -> Value.Null
    }
}

fun Any?.toCbor() : Value {
    when(this) {
        null -> return Value.Null
        is Pair<Any?, Any?> -> {
            val tagNumber = when(this.first) {
                is Int -> (this.first as? Int)?.toULong()
                is Long -> (this. first as? Long)?.toULong()
                is ULong -> (this.first as? ULong)
                else -> null
            }
            if(tagNumber == null) {
                return Value.Null
            }
            val taggedValue = this.second.toCbor()
            return Value.Tag(tagNumber, listOf(taggedValue))
        }
        is ByteArray -> return Value.Bytes(this)
        is List<Any?> -> {
            var elements = mutableListOf<Value>()
            for(e in this) {
                elements.add(e.toCbor())
            }
            return Value.Array(elements)
        }
        is Boolean -> {
            return Value.Boolean(this)
        }
        is String -> {
            return Value.String(this)
        }
        is Value -> return this
        is Int -> return Value.Number(JsonNumber.Integer(this.toLong()))
        is Long ->  return Value.Number(JsonNumber.Integer(this))
        is Double ->  return Value.Number(JsonNumber.Float(this))
        is Float ->  return Value.Number(JsonNumber.Float(this.toDouble()))
        is Map<*, *>  -> {
            val elements = mutableListOf<MapEntry>()
            for(entry in this.entries) {
                val key = entry.key.toCbor()
                val value = entry.value.toCbor()
                val entry = MapEntry(key, value)
                elements.add(entry)
            }
            return Value.OrderedObject(OrderedMap(elements))
        }
        else -> return Value.Null
    }
}

fun Value.toCanonicalJson(): String = when (this) {
    is Value.Array -> this.v1.joinToString(separator = ",", prefix = "[", postfix = "]") { it.toCanonicalJson() }
    is Value.Boolean -> if (this.v1) "true" else "false"
    is Value.Bytes -> throw Exception("Cannot convert Bytes to canonical Json")
    Value.Null -> "null"
    is Value.Number -> when (this.v1) {
        is JsonNumber.Integer -> this.v1.v1.toString()
        is JsonNumber.Float -> this.v1.v1.toString()
    }
    is Value.Object -> this.v1.entries
        .sortedBy { it.key }
        .joinToString(separator = ",", prefix = "{", postfix = "}") { "\"${it.key}\":${it.value.toCanonicalJson()}"}
    is Value.OrderedObject -> throw Exception("Cannot convert OrderedObject to canonical Json")
    is Value.String -> "\"${this.v1}\""
    is Tag -> throw Exception("Cannot convert Tag to canonical Json")
}

// NOTE: This function is preferred over directly deserializing into Value
//       class when the Json contains "null" elements. Null elements cannot
//       be handled properly by the built in deserializer.
fun Value.Companion.fromJsonElement(json: JsonElement): Value = when (json) {
    is JsonNull -> Value.Null
    is JsonPrimitive -> when {
        json.isString -> Value.String(json.content)
        json.booleanOrNull != null -> Value.Boolean(json.boolean)
        json.longOrNull != null -> Value.Number(JsonNumber.Integer(json.long))
        json.doubleOrNull != null -> Value.Number(JsonNumber.Float(json.double))
        else -> error("Unknown primitive type: $json")
    }
    is JsonArray -> Value.Array(json.map { fromJsonElement(it) })
    is JsonObject -> Value.Object(json.mapValues { (_, v) -> fromJsonElement(v) })
}
