/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.sample.wallet.feature.scanner

import android.Manifest
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import com.google.accompanist.permissions.shouldShowRationale


@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun CameraPermissionHandler(
	onPermissionInSettingsChange: () -> Unit
) {
	var alreadyRequestedPermission by rememberSaveable { mutableStateOf(false) }
	val cameraPermissionState = rememberPermissionState(Manifest.permission.CAMERA) {
		alreadyRequestedPermission = true
	}

	if (cameraPermissionState.status.isGranted) {
		return
	}

	if (!alreadyRequestedPermission && !cameraPermissionState.status.shouldShowRationale) {
		LaunchedEffect(Unit) {
			cameraPermissionState.launchPermissionRequest()
		}
	} else if (cameraPermissionState.status.shouldShowRationale) {
		CameraPermissionRationalContent(
			onPermissionInSettingsChange = onPermissionInSettingsChange
		)
	} else {
		CameraPermissionRationalContent(
			onPermissionInSettingsChange = onPermissionInSettingsChange
		)
	}
}

@Composable
private fun CameraPermissionRationalContent(
	onPermissionInSettingsChange: () -> Unit
) {
	Surface(
		color = Color.White,
		modifier = Modifier.fillMaxSize()
	) {
		Column(
			verticalArrangement = Arrangement.Center,
			horizontalAlignment = Alignment.CenterHorizontally,
			modifier = Modifier
				.fillMaxWidth()
				.padding(horizontal = 48.dp),
		) {
			Text(
				modifier = Modifier.padding(vertical = 4.dp),
				text = "No Camera Access",
				textAlign = TextAlign.Center,
			)

			Text(
				modifier = Modifier.padding(bottom = 24.dp),
				textAlign = TextAlign.Center,
				text = "No Camera Access Text",
			)
			Button(
				onClick = onPermissionInSettingsChange,
			) {
				Text("Grant")
			}
		}
	}
}
