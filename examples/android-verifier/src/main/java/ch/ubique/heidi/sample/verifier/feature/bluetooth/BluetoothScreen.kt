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

@Composable
fun BluetoothScreen(
	state: State<BluetoothState>,
	log: State<List<String>>,
	onStartServer: (role: TransportProtocol.Role) -> Unit,
	onStartClient: (role: TransportProtocol.Role) -> Unit,
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

			var role by remember { mutableStateOf(TransportProtocol.Role.WALLET) }
			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.spacedBy(4.dp),
				verticalAlignment = Alignment.CenterVertically,
			) {
				Row(verticalAlignment = Alignment.CenterVertically) {
					RadioButton(
						selected = role == TransportProtocol.Role.WALLET,
						onClick = { role = TransportProtocol.Role.WALLET },
					)
					Text("Act as wallet")
				}
				Row(verticalAlignment = Alignment.CenterVertically) {
					RadioButton(
						selected = role == TransportProtocol.Role.VERIFIER,
						onClick = { role = TransportProtocol.Role.VERIFIER },
					)
					Text("Act as verifier")
				}
			}

			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.spacedBy(4.dp),
				verticalAlignment = Alignment.CenterVertically,
			) {
				Button(
					onClick = { onStartServer.invoke(role) },
					modifier = Modifier.weight(1f),
					enabled = bluetoothState is BluetoothState.Idle,
					contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
				) {
					Text("Peripheral Server Mode", maxLines = 1)
				}
				Button(
					onClick = { onStartClient.invoke(role) },
					modifier = Modifier.weight(1f),
					enabled = bluetoothState is BluetoothState.Idle,
					contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
				) {
					Text("Central Client Mode", maxLines = 1)
				}
			}

			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.SpaceAround,
				verticalAlignment = Alignment.CenterVertically,
			) {
				Button(
					onClick = onStopClicked,
					modifier = Modifier.fillMaxWidth(0.5f),
					enabled = bluetoothState !is BluetoothState.Idle,
					contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
				) {
					Text("Stop", maxLines = 1)
				}
			}

			Spacer(Modifier.height(8.dp))

			Text("State: $bluetoothState")

			Spacer(Modifier.height(8.dp))

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
