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

import CoreBluetooth
import SwiftUI
import heidi_proximity

class ProximityVerifierWrapper: ObservableObject {

    private(set) var verifier: ProximityVerifier!

    @Published
    private(set) var status: ProximityVerifierState = ProximityVerifierStateInitial()

    init() {
        verifier = ProximityVerifier.companion.create(protocol: .openid4Vp, verifierName: "iOS", requester: self)

        let ui = "a3472373-ce0a-4d39-9eb2-7d32b606d550"
        let uuid = CBUUID(string: ui)
        print("ui: \(uuid.uuidString)")

        let service = CBMutableService(type: uuid, primary: true)
        service.characteristics = []
    }

    @MainActor
    func activate() async {
        for await status in verifier.verifierState {
            self.status = status
        }
    }

}

extension ProximityVerifierWrapper: DocumentRequester {
    func __createDocumentRequest() async throws -> any DocumentRequest {
        // TODO BM implement
        return DocumentRequestOpenId4Vp(parJwt: "!!")
    }
}
