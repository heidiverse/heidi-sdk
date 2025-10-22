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
package ch.ubique.heidi.sample.verifier.feature.bluetooth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.verifier.ProximityVerifierState
import ch.ubique.heidi.sample.verifier.feature.network.ProofTemplate
import ch.ubique.heidi.sample.verifier.feature.scanner.QrScannerScreen
import ch.ubique.heidi.sample.verifier.feature.scanner.QrScannerScreenCallbacks
import ch.ubique.heidi.sample.verifier.feature.scanner.QrScannerViewModel

@Composable
fun BluetoothScreen(
	state: State<ProximityVerifierState>,
	log: State<List<String>>,
	proofTemplate: State<ProofTemplate>,
	onProofTemplateChanged: (ProofTemplate) -> Unit,
	onStartServer: (role: TransportProtocol.Role) -> Unit,
	onStartClient: (role: TransportProtocol.Role) -> Unit,
	qrScannerViewModel: QrScannerViewModel,
	scannerCallbacks: QrScannerScreenCallbacks,
	sendMessage: (String) -> Unit,
	onStopClicked: () -> Unit,
) {
	Scaffold { innerPadding ->
		Column(
			modifier = Modifier
				.padding(innerPadding)
				.padding(horizontal = 16.dp, vertical = 12.dp)
		) {
			val bluetoothState = state.value
			var expanded by remember { mutableStateOf(false) }

			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.spacedBy(8.dp),
				verticalAlignment = Alignment.CenterVertically,
			) {
				Text("Proof Template:", modifier = Modifier.weight(1f))
				Box {
					Button(
						onClick = { expanded = true },
						contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
					) {
						Text(
							when (proofTemplate.value) {
								ProofTemplate.IDENTITY_CARD_CHECK -> "ID Check"
								ProofTemplate.AGE_OVER_16 -> "Age 16+"
								ProofTemplate.AGE_OVER_18 -> "Age 18+"
								ProofTemplate.AGE_OVER_65 -> "Age 65+"
							},
							maxLines = 1
						)
					}
					DropdownMenu(
						expanded = expanded,
						onDismissRequest = { expanded = false }
					) {
						DropdownMenuItem(
							text = { Text("Identity Card Check (First Name)") },
							onClick = {
								onProofTemplateChanged(ProofTemplate.IDENTITY_CARD_CHECK)
								expanded = false
							}
						)
						DropdownMenuItem(
							text = { Text("Age Over 16") },
							onClick = {
								onProofTemplateChanged(ProofTemplate.AGE_OVER_16)
								expanded = false
							}
						)
						DropdownMenuItem(
							text = { Text("Age Over 18") },
							onClick = {
								onProofTemplateChanged(ProofTemplate.AGE_OVER_18)
								expanded = false
							}
						)
						DropdownMenuItem(
							text = { Text("Age Over 65") },
							onClick = {
								onProofTemplateChanged(ProofTemplate.AGE_OVER_65)
								expanded = false
							}
						)
					}
				}
			}

			Text("State: $bluetoothState")

			QrScannerScreen(
				qrScannerViewModel,
				scannerCallbacks,
			)

			if (bluetoothState is BluetoothState.Connected) {
				Row(
					verticalAlignment = Alignment.CenterVertically,
					horizontalArrangement = Arrangement.spacedBy(4.dp),
				) {
					var text by remember { mutableStateOf("") }
					OutlinedTextField(
						value = text,
						onValueChange = { text = it },
						modifier = Modifier.weight(1f),
						placeholder = { Text("Message") },
						maxLines = 1,
					)

					Button(
						onClick = {
							sendMessage.invoke(text)
							text = ""
						},
					) {
						Text("Send")
					}
				}
			}

			Spacer(Modifier.height(8.dp))

			log.value.takeIf { it.isNotEmpty() }?.let {
				Column(
					modifier = Modifier
						.fillMaxWidth()
						.verticalScroll(rememberScrollState())
				) {
					it.forEach { message ->
						Text(message)
					}
				}
			}
		}
	}
}
