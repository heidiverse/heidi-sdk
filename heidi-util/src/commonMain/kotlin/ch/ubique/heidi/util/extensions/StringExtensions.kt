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

import kotlin.math.roundToLong

fun String.toArgb(default: Long = 0xFFFFFFFF): Long {
	return when {
		this.startsWith("#") -> {
			val hex = this.substring(1)
			when (hex.length) {
				3 -> {
					val alpha = 0xFFL shl 24
					val red = hex[0].toString().repeat(2).toLong(16) shl 16
					val green = hex[1].toString().repeat(2).toLong(16) shl 8
					val blue = hex[2].toString().repeat(2).toLong(16)
					alpha or red or green or blue
				}
				4 -> {
					val alpha = hex[0].toString().repeat(2).toLong(16) shl 24
					val red = hex[1].toString().repeat(2).toLong(16) shl 16
					val green = hex[2].toString().repeat(2).toLong(16) shl 8
					val blue = hex[3].toString().repeat(2).toLong(16)
					alpha or red or green or blue
				}
				6 -> {
					val alpha = 0xFFL shl 24
					val red = hex.substring(0, 2).toLong(16) shl 16
					val green = hex.substring(2, 4).toLong(16) shl 8
					val blue = hex.substring(4, 6).toLong(16)
					alpha or red or green or blue
				}
				8 -> {
					val alpha = hex.substring(0, 2).toLong(16) shl 24
					val red = hex.substring(2, 4).toLong(16) shl 16
					val green = hex.substring(4, 6).toLong(16) shl 8
					val blue = hex.substring(6, 8).toLong(16)
					alpha or red or green or blue
				}
				else -> default
			}
		}
		this.startsWith("rgba") -> {
			val rgba = this.removePrefix("rgba").trim('(', ')').split(",").map { it.trim() }
			val alpha = (rgba[3].toDouble() * 255).roundToLong() shl 24
			val red = rgba[0].toLong() shl 16
			val green = rgba[1].toLong() shl 8
			val blue = rgba[2].toLong()
			alpha or red or green or blue
		}
		this.startsWith("argb") -> {
			val argb = this.removePrefix("argb").trim('(', ')').split(",").map { it.trim() }
			val alpha = (argb[0].toDouble() * 255).roundToLong() shl 24
			val red = argb[1].toLong() shl 16
			val green = argb[2].toLong() shl 8
			val blue = argb[3].toLong()
			alpha or red or green or blue
		}
		this.startsWith("rgb") -> {
			val rgb = this.removePrefix("rgb").trim('(', ')').split(",").map { it.trim().toInt() }
			val alpha = 0xFFL shl 24
			val red = rgb[0].toLong() shl 16
			val green = rgb[1].toLong() shl 8
			val blue = rgb[2].toLong()
			alpha or red or green or blue
		}
		else -> default
	}
}
