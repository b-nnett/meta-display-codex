import AVFoundation
import CryptoKit
import Foundation
import MWDATDisplay
import XCTest
@testable import CodexRayBan

final class CodexRemoteAPICatalogTests: XCTestCase {
  @MainActor
  func testAuthViewModelStartsWithEmptySessionDuringTests() {
    let viewModel = CodexAuthViewModel()

    XCTAssertTrue(CodexRuntimeEnvironment.isRunningTests)
    XCTAssertFalse(viewModel.session.isSignedIn)
    XCTAssertFalse(viewModel.session.isRemoteEnrolled)
    XCTAssertNil(viewModel.session.normalAccessToken)
    XCTAssertNil(viewModel.session.remoteControlToken)
  }

  @MainActor
  func testRemoteTokenRefreshReportsFailureWhenSessionIsIncomplete() async {
    let viewModel = CodexAuthViewModel(loadSavedSession: false)

    let refreshed = await viewModel.refreshRemoteToken()

    XCTAssertFalse(refreshed)
    XCTAssertNotNil(viewModel.errorMessage)
    XCTAssertFalse(viewModel.session.remoteTokenIsFresh)
  }

  func testPKCERequestUsesBase64URLVerifierStateAndS256Challenge() throws {
    let request = try CodexPKCE.makeRequest(kind: .normal, config: .desktopNormal())
    let components = try XCTUnwrap(URLComponents(url: request.authorizationURL, resolvingAgainstBaseURL: false))
    let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
      item.value.map { (item.name, $0) }
    })

    XCTAssertEqual(request.codeVerifier.count, 43)
    XCTAssertFalse(request.codeVerifier.contains("+"))
    XCTAssertFalse(request.codeVerifier.contains("/"))
    XCTAssertFalse(request.codeVerifier.contains("="))
    XCTAssertEqual(request.state.count, 43)
    XCTAssertEqual(query["code_challenge_method"], "S256")
    XCTAssertEqual(query["state"], request.state)
    XCTAssertNotEqual(query["code_challenge"], request.codeVerifier)
  }

  func testDeviceKeyMetadataMatchesBackingProtectionClass() throws {
    let signingKey = CodexDeviceSigningKey.software(P256.Signing.PrivateKey())
    let key = CodexDeviceKey(
      keyID: "test-key",
      signingKey: signingKey,
      publicKeySPKIDERBase64: Data(signingKey.publicKeyX963Representation).base64EncodedString()
    )

    let signature = try key.signature(for: Data("payload".utf8))
    let identity = CodexDeviceProofBuilder.deviceIdentity(for: key)

    XCTAssertFalse(signature.derRepresentation.isEmpty)
    XCTAssertEqual(identity.protectionClass, CodexDeviceKeyProtectionClass.extractableKeychain)
  }

  func testNewStoredSoftwareDeviceKeyKeepsAccurateProtectionClass() throws {
    let signingKey = CodexDeviceSigningKey.software(P256.Signing.PrivateKey())
    let storedData = try CodexDeviceKeyStore.storedRepresentation(for: signingKey)
    let storedKey = try CodexDeviceKeyStore.storedSigningKey(from: storedData)

    guard case .software = storedKey.signingKey else {
      XCTFail("Expected software key")
      return
    }
    XCTAssertEqual(storedKey.protectionClassOverride, CodexDeviceKeyProtectionClass.extractableKeychain)

    let key = CodexDeviceKey(
      keyID: "stored-software",
      signingKey: storedKey.signingKey,
      publicKeySPKIDERBase64: Data(storedKey.signingKey.publicKeyX963Representation).base64EncodedString(),
      protectionClassOverride: storedKey.protectionClassOverride
    )

    let identity = CodexDeviceProofBuilder.deviceIdentity(for: key)
    XCTAssertEqual(identity.protectionClass, CodexDeviceKeyProtectionClass.extractableKeychain)
  }

  func testLegacyRawSoftwareDeviceKeyKeepsEnrolledProtectionClass() throws {
    let legacyKey = P256.Signing.PrivateKey()
    let storedKey = try CodexDeviceKeyStore.storedSigningKey(from: legacyKey.rawRepresentation)

    guard case .software = storedKey.signingKey else {
      XCTFail("Expected legacy raw key to load as software")
      return
    }
    XCTAssertEqual(storedKey.protectionClassOverride, CodexDeviceKeyProtectionClass.nonextractable)

    let key = CodexDeviceKey(
      keyID: "legacy-software",
      signingKey: storedKey.signingKey,
      publicKeySPKIDERBase64: Data(storedKey.signingKey.publicKeyX963Representation).base64EncodedString(),
      protectionClassOverride: storedKey.protectionClassOverride
    )

    let identity = CodexDeviceProofBuilder.deviceIdentity(for: key)
    XCTAssertEqual(identity.protectionClass, CodexDeviceKeyProtectionClass.nonextractable)
  }

  func testOpenChatDisplayActionSwitchesGlassesToPet() {
    XCTAssertTrue(CodexDisplayAppAction.openChat(chatID: "chat-1").switchesGlassesToPetAfterHandling)
    XCTAssertFalse(CodexDisplayAppAction.openProject(projectID: "project-1").switchesGlassesToPetAfterHandling)
    XCTAssertFalse(CodexDisplayAppAction.setMode(.work).switchesGlassesToPetAfterHandling)
  }

  func testCapabilityCatalogCoversProductionSurface() {
    let expectedIDs: Set<String> = [
      "desktopOAuthSignIn",
      "remoteEnrollStart",
      "remoteEnrollFinish",
      "remoteTokenRefresh",
      "listRemoteHosts",
      "readRemoteHost",
      "connectRemoteWebSocket",
      "initializeAppServer",
      "readAccount",
      "readRateLimits",
      "readConfig",
      "listModels",
      "listProjects",
      "listChats",
      "paginateChats",
      "searchChats",
      "loadChat",
      "paginateChatTurns",
      "listLoadedChats",
      "newChat",
      "resumeChat",
      "sendTextMessage",
      "sendImageMessage",
      "steerActiveTurn",
      "interruptTurn",
      "archiveChat",
      "unarchiveChat",
      "renameChat",
      "pinChat",
      "setChatGoal",
      "clearChatGoal",
      "forkChat",
      "compactChat",
      "rollbackChat",
      "viewFile",
      "listDirectory",
      "readFileMetadata",
      "searchFiles",
      "observeStreamingText",
      "observeToolDetails",
      "observeTodoUpdates",
      "observeFileChanges",
      "handleCommandApprovalRequest",
      "handleFileChangeApprovalRequest",
      "handlePermissionRequest",
      "handleToolCallRequest",
      "handleUserInputRequest",
      "handleAuthTokenRefreshRequest",
      "handleMcpElicitationRequest",
      "approveGuardianAction",
      "runShellCommand",
      "displayOnGlasses",
      "displayPetOnGlasses",
      "transcribeGlassesMic",
    ]

    let actualIDs = Set(CodexRemoteAPICatalog.capabilities.map(\.id))
    XCTAssertEqual(actualIDs, expectedIDs)
    XCTAssertEqual(CodexRemoteAPICatalog.capabilities.count, actualIDs.count, "Capability IDs must be unique.")
  }

  func testValidatedCapabilitiesReferenceKnownTransportShapes() {
    let endpointIDs = Set(CodexRemoteAPICatalog.restEndpoints.map(\.id))

    for capability in CodexRemoteAPICatalog.capabilities {
      switch capability.transport {
      case .rest:
        XCTAssertNotNil(capability.restEndpointID, capability.id)
        XCTAssertTrue(endpointIDs.contains(capability.restEndpointID ?? ""), capability.id)

      case .webSocket:
        XCTAssertEqual(CodexRemoteAPICatalog.webSocketEndpointPath, "/codex/remote/control/client")
        XCTAssertEqual(
          CodexRemoteAPICatalog.webSocketHeaders,
          ["x-codex-client-session-token", "x-codex-client-id", "x-codex-protocol-version"]
        )

      case .appServerRPC, .derived:
        guard let method = capability.rpcMethod else {
          continue
        }
        if capability.validationStatus == .schemaMissing {
          XCTAssertFalse(CodexRemoteAPICatalog.observedAppServerMethods.contains(method), capability.id)
        } else if capability.validationStatus != .planned {
          XCTAssertTrue(CodexRemoteAPICatalog.observedAppServerMethods.contains(method), capability.id)
        }

      case .serverNotification:
        XCTAssertFalse(capability.notificationNames.isEmpty, capability.id)
        for name in capability.notificationNames {
          XCTAssertTrue(CodexRemoteAPICatalog.observedServerNotifications.contains(name), "\(capability.id): \(name)")
        }

      case .serverRequest:
        XCTAssertFalse(capability.notificationNames.isEmpty, capability.id)
        for name in capability.notificationNames {
          XCTAssertTrue(CodexRemoteAPICatalog.observedServerRequests.contains(name), "\(capability.id): \(name)")
        }

      case .oauth:
        XCTAssertFalse(capability.requiredParams.isEmpty, capability.id)
      }
    }
  }

  func testRESTEndpointCatalogMatchesDesktopRoutes() throws {
    let byID = Dictionary(uniqueKeysWithValues: CodexRemoteAPICatalog.restEndpoints.map { ($0.id, $0) })

    let listHosts = try XCTUnwrap(byID["listRemoteHosts"])
    XCTAssertEqual(listHosts.method, "GET")
    XCTAssertEqual(listHosts.path, "/codex/remote/control/environments?limit=50")
    XCTAssertTrue(listHosts.requiresNormalAccessToken)
    XCTAssertTrue(listHosts.requiresAccountID)

    let enrollFinish = try XCTUnwrap(byID["enrollFinish"])
    XCTAssertEqual(enrollFinish.method, "POST")
    XCTAssertEqual(enrollFinish.path, "/codex/remote/control/client/enroll/finish")
    XCTAssertEqual(enrollFinish.bodyKeys, ["client_id", "step_up_token", "device_identity", "device_key_proof"])

    let refreshFinish = try XCTUnwrap(byID["refreshFinish"])
    XCTAssertEqual(refreshFinish.method, "POST")
    XCTAssertEqual(refreshFinish.path, "/codex/remote/control/client/refresh/finish")
    XCTAssertEqual(refreshFinish.bodyKeys, ["client_id", "device_key_proof"])
  }

  func testKnownAppServerMethodsHaveSafetyClassification() {
    for method in CodexRemoteAPICatalog.observedAppServerMethods {
      let safety = CodexAppServerMethodClassifier.safety(for: method)
      switch method {
      case "fs/readFile", "fs/readDirectory", "fs/getMetadata":
        XCTAssertEqual(safety, .filesystemRead, method)
      case "fs/writeFile", "fs/createDirectory", "fs/remove", "fs/copy":
        XCTAssertEqual(safety, .filesystemMutation, method)
      case "command/exec", "command/exec/write", "command/exec/terminate", "command/exec/resize", "thread/shellCommand":
        XCTAssertEqual(safety, .commandExecution, method)
      case "mcpServer/tool/call", "plugin/install", "plugin/uninstall", "config/value/write", "config/batchWrite":
        XCTAssertEqual(safety, .pluginOrMCPMutation, method)
      case "account/logout", "account/login/start", "account/login/cancel", "feedback/upload":
        XCTAssertEqual(safety, .accountMutation, method)
      default:
        XCTAssertFalse(safety.rawValue.isEmpty, method)
      }
    }
  }

  func testRPCRequestBuildersUseExpectedMethodsAndParams() throws {
    try assertRequest(
      CodexAppServerRequestBuilder.initialize(id: "1"),
      method: "initialize",
      requiredParams: ["clientInfo", "capabilities"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.listThreads(id: "2", limit: 50, cursor: "cursor-1", cwd: "/Users/example/Documents/meta-display-codex"),
      method: "thread/list",
      requiredParams: ["limit", "archived", "sortKey", "sortDirection", "useStateDbOnly", "cursor", "cwd"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readThread(id: "3", threadID: "thread-1"),
      method: "thread/read",
      requiredParams: ["threadId", "includeTurns"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.listThreadTurns(
        id: "3b",
        threadID: "thread-1",
        limit: 20,
        cursor: CodexThreadTurnsCursor(turnID: "turn-1", includeAnchor: false)
      ),
      method: "thread/turns/list",
      requiredParams: ["threadId", "limit", "cursor"]
    )
    try assertTurnCursor(CodexAppServerRequestBuilder.listThreadTurns(
      id: "3c",
      threadID: "thread-1",
      limit: 20,
      cursor: CodexThreadTurnsCursor(turnID: "turn-1", includeAnchor: false)
    ))
    try assertRequest(
      CodexAppServerRequestBuilder.loadedThreads(id: "4"),
      method: "thread/loaded/list",
      requiredParams: []
    )
    let startThreadRequest = CodexAppServerRequestBuilder.startThread(
      id: "5",
      cwd: "/Users/example/Documents/meta-display-codex",
      model: "gpt-5-codex"
    )
    try assertRequest(
      startThreadRequest,
      method: "thread/start",
      requiredParams: ["threadSource", "sessionStartSource", "cwd", "model"]
    )
    let startThreadParams = try XCTUnwrap(startThreadRequest.objectValue?["params"]?.objectValue)
    XCTAssertEqual(startThreadParams["threadSource"]?.stringValue, "user")
    XCTAssertEqual(startThreadParams["sessionStartSource"]?.stringValue, "startup")
    try assertRequest(
      CodexAppServerRequestBuilder.startTurn(
        id: "6",
        threadID: "thread-1",
        text: "Hello",
        localImagePaths: ["/tmp/image.png"]
      ),
      method: "turn/start",
      requiredParams: ["threadId", "input"]
    )
    try assertImageInput(CodexAppServerRequestBuilder.startTurn(
      id: "7",
      threadID: "thread-1",
      text: "Read this screenshot",
      localImagePaths: ["/tmp/image.png"]
    ))
    try assertRequest(
      CodexAppServerRequestBuilder.steerTurn(id: "8", threadID: "thread-1", expectedTurnID: "turn-1", text: "Continue"),
      method: "turn/steer",
      requiredParams: ["threadId", "expectedTurnId", "input"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.interruptTurn(id: "9", threadID: "thread-1", turnID: "turn-1"),
      method: "turn/interrupt",
      requiredParams: ["threadId", "turnId"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.archiveThread(id: "9a", threadID: "thread-1"),
      method: "thread/archive",
      requiredParams: ["threadId"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.unarchiveThread(id: "9b", threadID: "thread-1"),
      method: "thread/unarchive",
      requiredParams: ["threadId"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readFile(id: "10", path: "/Users/example/file.swift"),
      method: "fs/readFile",
      requiredParams: ["path"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readDirectory(id: "11", path: "/Users/example/Documents"),
      method: "fs/readDirectory",
      requiredParams: ["path"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readFileMetadata(id: "12", path: "/Users/example/file.swift"),
      method: "fs/getMetadata",
      requiredParams: ["path"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.listModels(id: "13"),
      method: "model/list",
      requiredParams: ["limit", "includeHidden"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readAccount(id: "14"),
      method: "account/read",
      requiredParams: ["refreshToken"]
    )
    try assertRequest(
      CodexAppServerRequestBuilder.readConfig(id: "15", cwd: "/Users/example/Documents/meta-display-codex"),
      method: "config/read",
      requiredParams: ["cwd", "includeLayers"]
    )
  }

  func testThreadTurnsCursorRoundTripsEscapedIDsAndDefaultsIncludeAnchor() throws {
    let cursor = CodexThreadTurnsCursor(turnID: #"turn-"quoted"\path"#, includeAnchor: true)
    let rawValue = cursor.rawValue

    XCTAssertNotNil(rawValue.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) })
    XCTAssertEqual(CodexThreadTurnsCursor(rawValue: rawValue), cursor)
    XCTAssertEqual(
      CodexThreadTurnsCursor(rawValue: #"{"turnId":"turn-legacy"}"#),
      CodexThreadTurnsCursor(turnID: "turn-legacy", includeAnchor: false)
    )
    XCTAssertNil(CodexThreadTurnsCursor(rawValue: #"{"turnId":"unterminated}"#))
    XCTAssertNil(CodexThreadTurnsCursor(rawValue: #"{"includeAnchor":true}"#))
  }

  func testObservedEnvironmentListResponseDecodes() throws {
    let sample = Data(
      """
      {
        "items": [
          {
            "env_id": "env_e_6a06e6e50a84832e8599c90373d3d131",
            "kind": "single",
            "display_name": "Example Mac",
            "host_name": "example-host.local",
            "name": "Example Mac",
            "online": true,
            "busy": false,
            "os": "Mac OS",
            "os_version": "26.3.1",
            "arch": "arm64",
            "app_server_version": "0.136.0-alpha.2",
            "installation_id": "e57aeace-8d73-4746-b93b-99415facb92c",
            "client_type": "CODEX_DESKTOP_APP",
            "originator": "Codex Desktop",
            "terminal": "unknown",
            "client_name": "Codex Desktop",
            "client_version": "26.601.21317",
            "last_seen_at": "2026-06-04T16:43:11.609791Z"
          }
        ],
        "cursor": null
      }
      """.utf8
    )

    let decoded = try JSONDecoder().decode(CodexEnvironmentsResponse.self, from: sample)
    XCTAssertEqual(decoded.items.count, 1)
    XCTAssertEqual(decoded.items[0].envID, "env_e_6a06e6e50a84832e8599c90373d3d131")
    XCTAssertEqual(decoded.items[0].displayName, "Example Mac")
    XCTAssertEqual(decoded.items[0].hostName, "example-host.local")
    XCTAssertTrue(decoded.items[0].online)
    XCTAssertEqual(decoded.items[0].clientName, "Codex Desktop")
    XCTAssertEqual(decoded.items[0].clientVersion, "26.601.21317")
  }

  func testTranscriptionMultipartBodyUsesExpectedAudioShape() throws {
    let body = CodexTranscriptionClient.multipartBody(
      boundary: "Boundary-Test",
      fields: [
        "model": "gpt-4o-mini-transcribe",
        "response_format": "json",
      ],
      fileField: "file",
      fileName: "voice.m4a",
      mimeType: "audio/m4a",
      fileData: Data("audio-bytes".utf8)
    )

    let text = try XCTUnwrap(String(data: body, encoding: .utf8))
    XCTAssertTrue(text.contains("name=\"model\""))
    XCTAssertTrue(text.contains("gpt-4o-mini-transcribe"))
    XCTAssertTrue(text.contains("name=\"response_format\""))
    XCTAssertTrue(text.contains("json"))
    XCTAssertTrue(text.contains("name=\"file\"; filename=\"voice.m4a\""))
    XCTAssertTrue(text.contains("Content-Type: audio/m4a"))
    XCTAssertTrue(text.contains("audio-bytes"))
    XCTAssertTrue(text.hasSuffix("--Boundary-Test--\r\n"))
  }

  func testAudioMeterNormalizationRespondsToPeakPower() {
    let silence = CodexTranscriptionViewModel.normalizedAudioPower(averagePower: -90, peakPower: -90)
    let speaking = CodexTranscriptionViewModel.normalizedAudioPower(averagePower: -32, peakPower: -18)
    let transient = CodexTranscriptionViewModel.normalizedAudioPower(averagePower: -48, peakPower: -10)

    XCTAssertEqual(silence, 0, accuracy: 0.001)
    XCTAssertGreaterThan(speaking, 0.45)
    XCTAssertGreaterThan(transient, speaking * 0.8)
    XCTAssertLessThanOrEqual(transient, 1)
  }

  func testPetVideoRendererProducesPlayableMP4() async throws {
    let videoURL = try CodexPetVideoRenderer.renderVideo(for: .pet(id: "fireball"), state: .idle)
    defer { try? FileManager.default.removeItem(at: videoURL) }

    let attributes = try FileManager.default.attributesOfItem(atPath: videoURL.path)
    let fileSize = try XCTUnwrap(attributes[.size] as? NSNumber)
    XCTAssertGreaterThan(fileSize.intValue, 1_000)

    let asset = AVURLAsset(url: videoURL)
    let videoTracks = try await asset.loadTracks(withMediaType: .video)
    XCTAssertFalse(videoTracks.isEmpty)
  }

  func testPetFrameImageRendererProducesDataURI() throws {
    let uri = try CodexPetFrameImageRenderer.dataURI(for: .pet(id: "fireball"), state: .running, frameIndex: 2)
    XCTAssertTrue(uri.hasPrefix("data:image/png;base64,"))

    let encoded = String(uri.dropFirst("data:image/png;base64,".count))
    let data = try XCTUnwrap(Data(base64Encoded: encoded))
    XCTAssertGreaterThan(data.count, 1_000)
    XCTAssertLessThan(data.count, 20_000)
  }

  func testFileEditPreviewCompactsLargeDiffs() throws {
    let diff = """
    --- a/file.swift
    +++ b/file.swift
    @@ -1,6 +1,7 @@
    -old 1
    -old 2
    -old 3
    +new 1
    +new 2
    +new 3
    +new 4
    """
    let file = CodexFilePreview(id: "file-1", path: "/tmp/file.swift", detail: diff, diff: diff)
    let preview = try XCTUnwrap(file.editPreview)

    XCTAssertEqual(preview.addedLineCount, 4)
    XCTAssertEqual(preview.removedLineCount, 3)
    XCTAssertTrue(preview.shouldShowCountsOnly)
    XCTAssertEqual(preview.previewLines.count, 5)
  }

  func testFileChangeNormalizerPreservesFullDiff() throws {
    let diff = """
    --- a/View.swift
    +++ b/View.swift
    @@ -1 +1 @@
    -Text("Old")
    +Text("New")
    """
    let messages = CodexChatNormalizer.messages(fromItems: [
      .object([
        "id": .string("change-1"),
        "type": .string("fileChange"),
        "status": .string("completed"),
        "changes": .array([
          .object([
            "path": .string("/Users/example/View.swift"),
            "diff": .string(diff),
          ]),
        ]),
      ]),
    ])

    let message = try XCTUnwrap(messages.first)
    guard case .fileGroup(let group) = try XCTUnwrap(message.parts.first) else {
      XCTFail("Expected grouped file preview")
      return
    }
    let file = try XCTUnwrap(group.files.first)
    XCTAssertEqual(file.path, "/Users/example/View.swift")
    XCTAssertEqual(file.diff, diff)
    XCTAssertEqual(file.editPreview?.addedLineCount, 1)
    XCTAssertEqual(file.editPreview?.removedLineCount, 1)
    XCTAssertFalse(file.editPreview?.shouldShowCountsOnly ?? true)
    XCTAssertEqual(group.addedLineCount, 1)
    XCTAssertEqual(group.removedLineCount, 1)
  }

  func testDisplayAppStateExportsCodexWorkspaceSurface() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let projectPath = "/Users/example/Documents/meta-display-codex"
    let diff = """
    --- a/CodexHomeView.swift
    +++ b/CodexHomeView.swift
    @@ -1,2 +1,3 @@
    -old line
    +new line
    +another line
    """
    let state = CodexDisplayAppState.make(
      chats: [
        CodexChatPreview(
          id: "chat-project",
          title: "Build display app",
          projectName: "meta-display-codex",
          projectPath: projectPath,
          summary: "Display app work",
          isPinned: true,
          isUnread: true,
          isActive: true,
          updatedAt: referenceDate.addingTimeInterval(-90)
        ),
        CodexChatPreview(
          id: "chat-loose",
          title: "Loose chat",
          projectName: "Projectless",
          projectPath: nil,
          summary: "No project",
          isPinned: false,
          isUnread: false,
          isActive: false,
          updatedAt: referenceDate.addingTimeInterval(-7_200)
        ),
      ],
      projects: [
        CodexProjectPreview(
          id: projectPath,
          name: "meta-display-codex",
          path: projectPath,
          chatCount: 1
        ),
      ],
      activeChat: CodexChatDetail(
        id: "chat-project",
        title: "Build display app",
        projectName: "meta-display-codex",
        projectPath: projectPath,
        messages: [
          CodexChatMessage(
            id: "assistant-1",
            role: .assistant,
            parts: [
              .text(id: "text-1", "Implemented the display state bridge."),
              .reasoning(id: "reasoning-1", "Map native state to the display contract."),
              .tool(CodexToolRun(id: "tool-1", name: "test", status: "completed", detail: "10 tests passed")),
              .fileGroup(CodexFileChangeGroup(
                id: "files-1",
                status: "changed",
                files: [
                  CodexFilePreview(
                    id: "file-1",
                    path: "\(projectPath)/CodexHomeView.swift",
                    detail: diff,
                    diff: diff
                  ),
                ]
              )),
              .todos(id: "todos-1", [
                CodexTodoItem(id: "todo-1", title: "Export state", status: "completed"),
                CodexTodoItem(id: "todo-2", title: "Render state", status: "pending"),
              ]),
            ]
          ),
        ],
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: "turn-1",
        isStreaming: true
      ),
      selectedPet: .pet(id: "fireball"),
      petState: .running,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      mode: "work",
      draft: "hello",
      transcriptPreview: "transcribed text",
      referenceDate: referenceDate
    )

    XCTAssertEqual(state.schemaVersion, 1)
    XCTAssertEqual(state.host.id, "env-1")
    XCTAssertEqual(state.host.name, "Example Mac")
    XCTAssertTrue(state.host.connected)
    XCTAssertEqual(state.screen, "home")
    XCTAssertFalse(state.isTranscribing)
    XCTAssertEqual(state.selectedProjectId, projectPath)
    XCTAssertEqual(state.selectedChatId, "chat-project")
    XCTAssertTrue(state.composerExpanded)
    XCTAssertEqual(state.draft, "hello")
    XCTAssertEqual(state.transcriptPreview, "transcribed text")
    XCTAssertEqual(state.pet.id, "fireball")
    XCTAssertEqual(state.pet.state, "running")
    XCTAssertEqual(state.pet.bubble, "Implemented the display state bridge.")
    XCTAssertEqual(state.pet.imageURI, "https://example.com/codex-pets/fireball-idle.gif")

    let project = try XCTUnwrap(state.projects.first)
    XCTAssertEqual(project.id, projectPath)
    XCTAssertEqual(project.chats, ["chat-project"])
    XCTAssertTrue(project.unread)
    XCTAssertTrue(project.active)

    let projectChat = try XCTUnwrap(state.chats.first { $0.id == "chat-project" })
    XCTAssertEqual(projectChat.projectId, projectPath)
    XCTAssertEqual(projectChat.updated, "1m")
    XCTAssertTrue(projectChat.pinned)
    XCTAssertTrue(projectChat.unread)
    XCTAssertTrue(projectChat.active)

    let looseChat = try XCTUnwrap(state.chats.first { $0.id == "chat-loose" })
    XCTAssertNil(looseChat.projectId)
    XCTAssertEqual(looseChat.updated, "2h")

    let message = try XCTUnwrap(state.messagesByChat["chat-project"]?.first)
    XCTAssertEqual(message.role, "assistant")
    XCTAssertEqual(message.parts.map(\.type), ["text", "reasoning", "tool", "fileGroup", "todo"])
    XCTAssertEqual(message.parts[0].text, "Implemented the display state bridge.")
    XCTAssertEqual(message.parts[1].text, "Map native state to the display contract.")
    XCTAssertEqual(message.parts[2].name, "test")

    let file = try XCTUnwrap(message.parts[3].files?.first)
    XCTAssertEqual(file.path, "\(projectPath)/CodexHomeView.swift")
    XCTAssertEqual(file.added, 2)
    XCTAssertEqual(file.removed, 1)
    XCTAssertEqual(file.diff, diff)

    let todos = try XCTUnwrap(message.parts[4].items)
    XCTAssertEqual(todos.count, 2)
    XCTAssertTrue(todos[0].done)
    XCTAssertFalse(todos[1].done)

    let encoded = try JSONEncoder().encode(state)
    let decoded = try JSONDecoder().decode(CodexDisplayAppState.self, from: encoded)
    XCTAssertEqual(decoded, state)
  }

  @MainActor
  func testWorkspaceProjectDerivationIncludesSingletonCwdGroupsAndSortsByRecentActivity() {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let recentProject = "/Users/example/Documents/recent-project"
    let olderProject = "/Users/example/Documents/older-project"
    let staleProject = "/Users/example/Documents/removed-project"

    let projects = CodexWorkspaceViewModel.projects(from: [
      chatPreview(
        id: "older-1",
        title: "Older project one",
        projectPath: olderProject,
        updatedAt: referenceDate.addingTimeInterval(-900)
      ),
      chatPreview(
        id: "older-2",
        title: "Older project two",
        projectPath: olderProject,
        updatedAt: referenceDate.addingTimeInterval(-800)
      ),
      chatPreview(
        id: "recent-1",
        title: "Recent project one",
        projectPath: recentProject,
        updatedAt: referenceDate.addingTimeInterval(-90)
      ),
      chatPreview(
        id: "recent-2",
        title: "Recent project two",
        projectPath: recentProject,
        updatedAt: referenceDate.addingTimeInterval(-120)
      ),
      chatPreview(
        id: "stale-singleton",
        title: "Stale one-off",
        projectPath: staleProject,
        updatedAt: referenceDate.addingTimeInterval(-30)
      ),
      chatPreview(
        id: "loose",
        title: "Loose chat",
        projectPath: nil,
        updatedAt: referenceDate
      ),
    ])

    XCTAssertEqual(projects.map(\.id), [staleProject, recentProject, olderProject])
    XCTAssertEqual(projects.map(\.chatCount), [1, 2, 2])
  }

  func testDisplayAppStateKeepsUnknownCwdChatsInRecentChats() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let projectPath = "/Users/example/Documents/meta-display-codex"
    let stalePath = "/Users/example/Documents/removed-project"
    let chats = [
      chatPreview(
        id: "project-1",
        title: "Project chat one",
        projectPath: projectPath,
        updatedAt: referenceDate.addingTimeInterval(-300)
      ),
      chatPreview(
        id: "project-2",
        title: "Project chat two",
        projectPath: projectPath,
        updatedAt: referenceDate.addingTimeInterval(-200)
      ),
      chatPreview(
        id: "stale-singleton",
        title: "Stale one-off",
        projectPath: stalePath,
        updatedAt: referenceDate.addingTimeInterval(-100)
      ),
      chatPreview(
        id: "loose",
        title: "Loose chat",
        projectPath: nil,
        updatedAt: referenceDate.addingTimeInterval(-50)
      ),
    ]

    var state = CodexDisplayAppState.make(
      chats: chats,
      projects: [
        CodexProjectPreview(
          id: projectPath,
          name: "meta-display-codex",
          path: projectPath,
          chatCount: 2
        ),
      ],
      activeChat: nil,
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )
    state.screen = "home"

    XCTAssertEqual(state.projects.map(\.id), [projectPath])
    XCTAssertEqual(state.projects.first?.chats, ["project-1", "project-2"])
    XCTAssertNil(state.selectedProjectId)

    let staleChat = try XCTUnwrap(state.chats.first { $0.id == "stale-singleton" })
    XCTAssertNil(staleChat.projectId)
    XCTAssertEqual(staleChat.projectName, "No project")

    let looseChat = try XCTUnwrap(state.chats.first { $0.id == "loose" })
    XCTAssertNil(looseChat.projectId)

    let text = visibleText(in: CodexDisplayAppGlasses.app(state: state) { _ in })
    XCTAssertTrue(text.contains("Stale one-off"))
    XCTAssertTrue(text.contains("Loose chat"))
  }

  func testDisplayAppActionEnvelopeDecodesWebPayloads() throws {
    let sendPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "sendMessage",
        "payload": {
          "chatId": "chat-1",
          "projectId": "/Users/example/project",
          "text": "Summarize this"
        }
      }
      """.utf8
    )
    let sendEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: sendPayload)
    XCTAssertEqual(sendEnvelope.type, "codex:action")
    XCTAssertEqual(sendEnvelope.action, .sendMessage(
      chatID: "chat-1",
      projectID: "/Users/example/project",
      text: "Summarize this"
    ))

    let modePayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setMode",
        "payload": {
          "mode": "pet"
        }
      }
      """.utf8
    )
    let modeEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: modePayload)
    XCTAssertEqual(modeEnvelope.action, .setMode(.pet))

    let uiPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setShowAllChats",
        "payload": {
          "showAllChats": true
        }
      }
      """.utf8
    )
    let uiEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: uiPayload)
    XCTAssertEqual(uiEnvelope.action, .setShowAllChats(true))

    let pinnedPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setShowAllPinnedChats",
        "payload": {
          "showAllPinnedChats": true
        }
      }
      """.utf8
    )
    let pinnedEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: pinnedPayload)
    XCTAssertEqual(pinnedEnvelope.action, .setShowAllPinnedChats(true))

    let projectsPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setShowAllProjects",
        "payload": {
          "showAllProjects": true
        }
      }
      """.utf8
    )
    let projectsEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: projectsPayload)
    XCTAssertEqual(projectsEnvelope.action, .setShowAllProjects(true))

    let projectChatsPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setShowAllProjectChats",
        "payload": {
          "showAllProjectChats": true
        }
      }
      """.utf8
    )
    let projectChatsEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: projectChatsPayload)
    XCTAssertEqual(projectChatsEnvelope.action, .setShowAllProjectChats(true))

    let messagesPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setShowAllMessages",
        "payload": {
          "showAllMessages": true
        }
      }
      """.utf8
    )
    let messagesEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: messagesPayload)
    XCTAssertEqual(messagesEnvelope.action, .setShowAllMessages(true))

    let petBubblePayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setPetBubbleExpanded",
        "payload": {
          "petBubbleExpanded": true
        }
      }
      """.utf8
    )
    let petBubbleEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: petBubblePayload)
    XCTAssertEqual(petBubbleEnvelope.action, .setPetBubbleExpanded(true))

    let modelPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setModel",
        "payload": {
          "modelId": "gpt-5-codex"
        }
      }
      """.utf8
    )
    let modelEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: modelPayload)
    XCTAssertEqual(modelEnvelope.action, .setModel(modelID: "gpt-5-codex"))

    let screenPayload = Data(
      """
      {
        "type": "codex:action",
        "action": "setScreen",
        "payload": {
          "screen": "chat"
        }
      }
      """.utf8
    )
    let screenEnvelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: screenPayload)
    XCTAssertEqual(screenEnvelope.action, .setScreen(.chat))

    let encoded = try JSONEncoder().encode(CodexDisplayAppActionEnvelope(
      action: .openFile(path: "/Users/example/project/file.swift")
    ))
    let roundTripped = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: encoded)
    XCTAssertEqual(roundTripped, CodexDisplayAppActionEnvelope(
      action: .openFile(path: "/Users/example/project/file.swift")
    ))
  }

  func testDisplayAppHTMLResourceIsBundled() throws {
    let url = try XCTUnwrap(Bundle.main.url(forResource: "codex-display-app", withExtension: "html"))
    let html = try String(contentsOf: url, encoding: .utf8)
    XCTAssertTrue(html.contains("CodexDisplayApp"))
    XCTAssertTrue(html.contains("codex:action"))
    XCTAssertTrue(html.contains("codex:set-state"))
    XCTAssertTrue(html.contains("data-action=\"toggle-projects\""))
    XCTAssertTrue(html.contains("data-action=\"toggle-project-chats\""))
    XCTAssertTrue(html.contains("setShowAllProjects"))
    XCTAssertTrue(html.contains("setShowAllProjectChats"))
    XCTAssertTrue(html.contains("setPetBubbleExpanded"))
    XCTAssertTrue(html.contains("data-action=\"toggle-pet-bubble\""))
    XCTAssertTrue(html.contains("--pet-size: 142px"))
  }

  @MainActor
  func testDisplayAppBridgeRoutesLocalActionsIntoWorkspaceState() async throws {
    let suiteName = "codex-display-bridge-tests-\(UUID().uuidString)"
    let userDefaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
    userDefaults.removePersistentDomain(forName: suiteName)
    let workspace = CodexWorkspaceViewModel(userDefaults: userDefaults)
    let bridge = CodexDisplayAppBridge()
    let projectPath = "/Users/example/Documents/meta-display-codex"
    let chat = CodexChatPreview(
      id: "chat-bridge",
      title: "Bridge chat",
      projectName: "meta-display-codex",
      projectPath: projectPath,
      summary: "Bridge work",
      isPinned: false,
      isUnread: true,
      isActive: false,
      updatedAt: Date(timeIntervalSince1970: 1_780_600_000)
    )
    workspace.chats = [chat]
    workspace.projects = [
      CodexProjectPreview(
        id: projectPath,
        name: "meta-display-codex",
        path: projectPath,
        chatCount: 1
      ),
    ]
    workspace.models = [
      CodexModelOption(id: "gpt-5.5", displayName: "GPT-5.5", detail: "Default", isDefault: true),
      CodexModelOption(id: "gpt-5-codex", displayName: "GPT-5 Codex", detail: "Code", isDefault: false),
    ]
    let openedFileDiff = """
      --- a/CodexHomeView.swift
      +++ b/CodexHomeView.swift
      -old title
      +new title
      +new detail
      """

    try await bridge.handle(.openProject(projectID: projectPath), workspace: workspace)
    XCTAssertEqual(bridge.selectedProjectID, projectPath)
    XCTAssertNil(bridge.selectedChatID)
    XCTAssertEqual(bridge.mode, .work)
    XCTAssertEqual(bridge.screen, .project)

    try await bridge.handle(.openChat(chatID: chat.id), workspace: workspace)
    XCTAssertEqual(bridge.selectedChatID, chat.id)
    XCTAssertEqual(bridge.screen, .chat)
    XCTAssertEqual(workspace.activeChat?.id, chat.id)
    XCTAssertEqual(workspace.activeChat?.title, "Bridge chat")
    workspace.activeChat?.messages = [
      CodexChatMessage(
        id: "file-message",
        role: .assistant,
        parts: [
          .fileGroup(CodexFileChangeGroup(
            id: "file-group",
            status: "changed",
            files: [
              CodexFilePreview(
                id: "file-bridge",
                path: "\(projectPath)/CodexHomeView.swift",
                detail: "Updated CodexHomeView.swift",
                diff: openedFileDiff
              ),
            ]
          )),
        ]
      ),
    ]

    try await bridge.handle(.startTranscription(chatID: chat.id), workspace: workspace) { receivedChatID in
      XCTAssertEqual(receivedChatID, chat.id)
      return CodexDisplayAppTranscriptionResult(text: "", isRecording: true)
    }
    XCTAssertEqual(bridge.transcriptPreview, "")
    XCTAssertTrue(bridge.composerExpanded)
    XCTAssertEqual(workspace.petState, .recording)

    try await bridge.handle(.startTranscription(chatID: chat.id), workspace: workspace) { receivedChatID in
      XCTAssertEqual(receivedChatID, chat.id)
      return CodexDisplayAppTranscriptionResult(text: "dictated bridge text", isRecording: false)
    }
    XCTAssertEqual(bridge.transcriptPreview, "dictated bridge text")
    XCTAssertTrue(bridge.composerExpanded)
    XCTAssertEqual(workspace.petState, .idle)

    try await bridge.handle(.acceptTranscript(text: bridge.transcriptPreview), workspace: workspace)
    XCTAssertEqual(bridge.draft, "dictated bridge text")
    XCTAssertEqual(bridge.transcriptPreview, "")

    try await bridge.handle(.updateDraft(text: "edited draft"), workspace: workspace)
    XCTAssertEqual(bridge.draft, "edited draft")
    XCTAssertTrue(bridge.composerExpanded)

    try await bridge.handle(.setComposerExpanded(false), workspace: workspace)
    XCTAssertTrue(bridge.composerExpanded)

    try await bridge.handle(.setShowAllPinnedChats(true), workspace: workspace)
    XCTAssertTrue(bridge.showAllPinnedChats)

    try await bridge.handle(.setShowAllChats(true), workspace: workspace)
    XCTAssertTrue(bridge.showAllChats)

    try await bridge.handle(.setShowAllProjects(true), workspace: workspace)
    XCTAssertTrue(bridge.showAllProjects)

    try await bridge.handle(.setShowAllProjectChats(true), workspace: workspace)
    XCTAssertTrue(bridge.showAllProjectChats)

    try await bridge.handle(.setShowAllMessages(true), workspace: workspace)
    XCTAssertTrue(bridge.showAllMessages)

    try await bridge.handle(.setPetBubbleExpanded(true), workspace: workspace)
    XCTAssertTrue(bridge.petBubbleExpanded)

    try await bridge.handle(.setModel(modelID: "gpt-5-codex"), workspace: workspace)
    XCTAssertEqual(bridge.selectedModelID, "gpt-5-codex")

    try await bridge.handle(.togglePinned(chatID: chat.id), workspace: workspace)
    XCTAssertTrue(workspace.chats.first?.isPinned ?? false)

    try await bridge.handle(.openFile(path: "CodexHomeView.swift"), workspace: workspace)
    XCTAssertEqual(bridge.selectedFilePath, "\(projectPath)/CodexHomeView.swift")
    XCTAssertEqual(bridge.screen, .file)
    XCTAssertEqual(bridge.lastOpenedFileDetail, "Updated CodexHomeView.swift")
    XCTAssertEqual(bridge.lastOpenedFileDiff, openedFileDiff)
    XCTAssertEqual(bridge.lastOpenedFileAdded, 2)
    XCTAssertEqual(bridge.lastOpenedFileRemoved, 1)

    do {
      try await bridge.handle(.sendMessage(chatID: chat.id, projectID: projectPath, text: bridge.draft), workspace: workspace)
      XCTFail("Expected disconnected send to throw")
    } catch {
      XCTAssertEqual(error.localizedDescription, CodexAppServerError.notConnected.localizedDescription)
    }
    XCTAssertEqual(bridge.draft, "")
    XCTAssertEqual(bridge.transcriptPreview, "")
    XCTAssertFalse(bridge.composerExpanded)
    XCTAssertEqual(workspace.activeChat?.messages.last?.role, .user)
    guard case .text(_, let sentText) = try XCTUnwrap(workspace.activeChat?.messages.last?.parts.first) else {
      XCTFail("Expected sent text message")
      return
    }
    XCTAssertEqual(sentText, "edited draft")
    if case .failed = workspace.activeChat?.messages.last?.deliveryState {
      XCTAssertTrue(true)
    } else {
      XCTFail("Expected failed optimistic send state")
    }
    XCTAssertEqual(workspace.petState, .failed)
    XCTAssertFalse(workspace.activeChat?.isStreaming ?? true)

    try await bridge.handle(.setMode(.pet), workspace: workspace)
    XCTAssertEqual(bridge.mode, .pet)
    XCTAssertEqual(bridge.screen, .pet)
    let state = bridge.state(from: workspace, hostID: "env-bridge", hostName: "Example Mac")
    XCTAssertEqual(state.mode, "pet")
    XCTAssertEqual(state.screen, "pet")
    XCTAssertTrue(state.showAllPinnedChats)
    XCTAssertTrue(state.showAllChats)
    XCTAssertTrue(state.showAllProjects)
    XCTAssertTrue(state.showAllProjectChats)
    XCTAssertTrue(state.showAllMessages)
    XCTAssertFalse(state.petBubbleExpanded)
    XCTAssertEqual(state.selectedProjectId, projectPath)
    XCTAssertEqual(state.selectedChatId, chat.id)
    XCTAssertEqual(state.selectedModelId, "gpt-5-codex")
    XCTAssertFalse(state.chats.first { $0.id == chat.id }?.active ?? true)
    XCTAssertEqual(state.selectedFile?.path, "\(projectPath)/CodexHomeView.swift")
    XCTAssertEqual(state.selectedFile?.detail, "Updated CodexHomeView.swift")
    XCTAssertEqual(state.selectedFile?.diff, openedFileDiff)
    XCTAssertEqual(state.selectedFile?.added, 2)
    XCTAssertEqual(state.selectedFile?.removed, 1)
    XCTAssertEqual(state.host.name, "Example Mac")
  }

  func testDisplayAppGlassesRendererBuildsPrimaryScreens() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    var state = CodexDisplayAppState.make(
      chats: [
        CodexChatPreview(
          id: "chat-1",
          title: "Renderer chat",
          projectName: "meta-display-codex",
          projectPath: "/Users/example/Documents/meta-display-codex",
          summary: "Renderer smoke",
          isPinned: true,
          isUnread: true,
          isActive: true,
          updatedAt: referenceDate
        ),
      ],
      projects: [
        CodexProjectPreview(
          id: "/Users/example/Documents/meta-display-codex",
          name: "meta-display-codex",
          path: "/Users/example/Documents/meta-display-codex",
          chatCount: 1
        ),
      ],
      models: [
        CodexModelOption(id: "gpt-5.5", displayName: "GPT-5.5", detail: "Default", isDefault: true),
        CodexModelOption(id: "gpt-5-codex", displayName: "GPT-5 Codex", detail: "Code", isDefault: false),
        CodexModelOption(id: "gpt-5-low", displayName: "GPT-5 Low", detail: "Low", isDefault: false),
        CodexModelOption(id: "gpt-5-high", displayName: "GPT-5 High", detail: "High", isDefault: false),
        CodexModelOption(id: "gpt-5-extra", displayName: "GPT-5 Extra High", detail: "Extra High", isDefault: false),
      ],
      activeChat: CodexChatDetail(
        id: "chat-1",
        title: "Renderer chat",
        projectName: "meta-display-codex",
        projectPath: "/Users/example/Documents/meta-display-codex",
        messages: [
          CodexChatMessage(id: "m1", role: .assistant, parts: [
            .text(id: "t1", "Renderer response"),
            .file(CodexFilePreview(id: "f1", path: "/Users/example/file.swift", detail: "Swift file")),
          ]),
        ],
        nextTurnCursor: CodexThreadTurnsCursor(turnID: "turn-older", includeAnchor: false),
        backwardsTurnCursor: nil,
        activeTurnID: "turn-1",
        isStreaming: true
      ),
      selectedPet: .pet(id: "fireball"),
      petState: .running,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )

    let actions = LockedActions()
    for screen in ["home", "project", "chat", "chatActions", "file", "modelPicker", "pet"] {
      state.screen = screen
      state.selectedFile = CodexDisplayAppViewedFile(
        path: "/Users/example/file.swift",
        content: "let value = 1",
        detail: "Swift file"
      )
      let view = CodexDisplayAppGlasses.app(state: state) { action in
        actions.append(action)
      }
      XCTAssertFalse(view.children.isEmpty, screen)
    }
  }

  func testDisplayAppGlassesPetScreenOnlyShowsBubbleText() throws {
    var state = CodexDisplayAppState.make(
      chats: [],
      projects: [],
      activeChat: nil,
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1"
    )
    state.screen = "pet"
    state.mode = "pet"
    XCTAssertEqual(state.pet.bubble, "")
    state.pet.bubble = """
    **Ready.** I finished the markdown renderer and kept the file links tappable.
    Review the latest app build on the phone.
    Then send it back to the glasses for the pet pass.
    """

    let actions = LockedActions()
    let view = CodexDisplayAppGlasses.app(state: state) { action in
      actions.append(action)
    }
    let collapsedText = visibleText(in: view).filter { !$0.isEmpty }.joined(separator: "\n")
    XCTAssertTrue(collapsedText.contains("Ready. I finished the markdown renderer"))
    XCTAssertFalse(collapsedText.contains("Review the latest app build on the phone."))
    XCTAssertTrue(collapsedText.contains("More"))
    XCTAssertFalse(collapsedText.contains("Then send it back to the glasses for the pet pass."))
    let image = try XCTUnwrap(images(in: view).first)
    XCTAssertEqual(image.uri, "https://example.com/codex-pets/fireball-idle.gif")
    XCTAssertEqual(image.sizePreset, .fill)
    try XCTUnwrap(try XCTUnwrap(buttons(in: view).first { $0.label == "More" }).onClick)()
    try XCTUnwrap(try XCTUnwrap(buttons(in: view).first { $0.iconName == .x }).onClick)()
    XCTAssertEqual(actions.values(), [.setPetBubbleExpanded(true), .setMode(.work)])

    state.petBubbleExpanded = true
    let expandedText = visibleText(in: CodexDisplayAppGlasses.app(state: state) { _ in })
      .filter { !$0.isEmpty }
      .joined(separator: "\n")
    XCTAssertTrue(expandedText.contains("Less"))
    XCTAssertTrue(expandedText.contains("Then send it back to the glasses for the pet pass."))
  }

  func testDisplayAppGlassesFilePreviewFormatsDiffs() throws {
    let smallDiff = """
    --- a/App.swift
    +++ b/App.swift
    -Text("Old")
    +Text("New")
    """
    var state = CodexDisplayAppState.make(
      chats: [],
      projects: [],
      activeChat: nil,
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1"
    )
    state.screen = "file"
    state.selectedFile = CodexDisplayAppViewedFile(
      path: "/Users/example/project/App.swift",
      content: nil,
      detail: "Swift file",
      diff: smallDiff,
      added: 1,
      removed: 1
    )

    let smallView = CodexDisplayAppGlasses.app(state: state) { _ in }
    let smallText = visibleText(in: smallView)
    XCTAssertTrue(smallText.contains("+1 -1"))
    XCTAssertTrue(smallText.contains("+ Text(\"New\")"))
    XCTAssertTrue(smallText.contains("- Text(\"Old\")"))

    state.selectedFile = CodexDisplayAppViewedFile(
      path: "/Users/example/project/App.swift",
      content: nil,
      detail: "Swift file",
      diff: smallDiff,
      added: 4,
      removed: 3
    )

    let largeText = visibleText(in: CodexDisplayAppGlasses.app(state: state) { _ in })
    XCTAssertTrue(largeText.contains("+4 -3"))
    XCTAssertTrue(largeText.contains("7 lines edited"))
    XCTAssertFalse(largeText.contains("+ Text(\"New\")"))
  }

  func testDisplayAppGlassesHomeCanExpandPinnedChats() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let chats = (1...4).map { index in
      CodexChatPreview(
        id: "pinned-\(index)",
        title: "Pinned \(index)",
        projectName: "No project",
        projectPath: nil,
        summary: "Pinned chat \(index)",
        isPinned: true,
        isUnread: false,
        isActive: false,
        updatedAt: referenceDate.addingTimeInterval(Double(-index))
      )
    }
    var state = CodexDisplayAppState.make(
      chats: chats,
      projects: [],
      activeChat: nil,
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )
    state.screen = "home"

    let actions = LockedActions()
    let collapsedView = CodexDisplayAppGlasses.app(state: state) { action in
      actions.append(action)
    }
    let collapsedText = visibleText(in: collapsedView)
    XCTAssertTrue(collapsedText.contains("Pinned 1"))
    XCTAssertTrue(collapsedText.contains("Pinned 2"))
    XCTAssertTrue(collapsedText.contains("Pinned 3"))
    XCTAssertFalse(collapsedText.contains("Pinned 4"))
    XCTAssertTrue(collapsedText.contains("Show all pinned"))

    try XCTUnwrap(buttons(in: collapsedView).first { $0.label == "Show all pinned" }?.onClick)()
    XCTAssertEqual(actions.values(), [.setShowAllPinnedChats(true)])

    state.showAllPinnedChats = true
    let expandedText = visibleText(in: CodexDisplayAppGlasses.app(state: state) { _ in })
    XCTAssertTrue(expandedText.contains("Pinned 4"))
    XCTAssertTrue(expandedText.contains("Show fewer pinned"))
  }

  func testDisplayAppGlassesHomeNavigationUsesButtonActions() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let projectPath = "/Users/example/Documents/meta-display-codex"
    var state = CodexDisplayAppState.make(
      chats: [
        CodexChatPreview(
          id: "project-chat",
          title: "Project chat",
          projectName: "meta-display-codex",
          projectPath: projectPath,
          summary: "Project chat",
          isPinned: false,
          isUnread: false,
          isActive: false,
          updatedAt: referenceDate.addingTimeInterval(-60)
        ),
        CodexChatPreview(
          id: "loose-chat",
          title: "Loose chat",
          projectName: "No project",
          projectPath: nil,
          summary: "Loose chat",
          isPinned: false,
          isUnread: false,
          isActive: false,
          updatedAt: referenceDate
        ),
      ],
      projects: [
        CodexProjectPreview(
          id: projectPath,
          name: "meta-display-codex",
          path: projectPath,
          chatCount: 1
        ),
      ],
      activeChat: nil,
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )
    state.screen = "home"

    let actions = LockedActions()
    let view = CodexDisplayAppGlasses.app(state: state) { action in
      actions.append(action)
    }
    let text = visibleText(in: view)
    XCTAssertFalse(text.contains(projectPath))
    XCTAssertFalse(text.contains("Active"))
    XCTAssertFalse(text.contains("Unread"))
    XCTAssertFalse(text.contains("New chat"))
    XCTAssertFalse(text.contains("Open"))
    XCTAssertTrue(images(in: view).contains { $0.uri.hasPrefix("data:image/svg+xml") })

    let actionButtons = buttons(in: view)
    try XCTUnwrap(try XCTUnwrap(actionButtons.first { $0.label == "New" && $0.iconName == .plus }).onClick)()
    let openButtons = actionButtons.filter { $0.label.isEmpty && $0.iconName == .caretRight }
    XCTAssertEqual(openButtons.count, 2)
    let rowTaps = tappableRows(in: view).filter { $0.onClick != nil }
    try XCTUnwrap(try XCTUnwrap(rowTaps.first { $0.text.contains("meta-display-codex") }).onClick)()
    try XCTUnwrap(try XCTUnwrap(rowTaps.first { $0.text.contains("Loose chat") }).onClick)()

    XCTAssertEqual(actions.values(), [
      .newChat(projectID: nil),
      .openProject(projectID: projectPath),
      .openChat(chatID: "loose-chat"),
    ])
  }

  func testDisplayAppGlassesChatDefaultsToLatestMessages() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let messages = (1...7).map { index in
      CodexChatMessage(id: "m\(index)", role: index % 2 == 0 ? .assistant : .user, parts: [
        .text(id: "t\(index)", "Message \(index)"),
      ])
    }
    var state = CodexDisplayAppState.make(
      chats: [
        CodexChatPreview(
          id: "chat-1",
          title: "Bottom anchored chat",
          projectName: "No project",
          projectPath: nil,
          summary: "Message 7",
          isPinned: false,
          isUnread: false,
          isActive: false,
          updatedAt: referenceDate
        ),
      ],
      projects: [],
      activeChat: CodexChatDetail(
        id: "chat-1",
        title: "Bottom anchored chat",
        projectName: "No project",
        projectPath: nil,
        messages: messages,
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: nil,
        isStreaming: false
      ),
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )
    state.screen = "chat"

    let actions = LockedActions()
    let view = CodexDisplayAppGlasses.app(state: state) { action in
      actions.append(action)
    }
    let text = visibleText(in: view)
    XCTAssertFalse(text.contains("Message 1"))
    XCTAssertFalse(text.contains("Message 2"))
    XCTAssertFalse(text.contains("Message 3"))
    XCTAssertTrue(text.contains("3 previous messages"))
    XCTAssertTrue(text.contains("Message 4"))
    XCTAssertTrue(text.contains("Message 5"))
    XCTAssertTrue(text.contains("Message 6"))
    XCTAssertTrue(text.contains("Message 7"))
    let message7Index = try XCTUnwrap(text.firstIndex(of: "Message 7"))
    let message6Index = try XCTUnwrap(text.firstIndex(of: "Message 6"))
    let message5Index = try XCTUnwrap(text.firstIndex(of: "Message 5"))
    let message4Index = try XCTUnwrap(text.firstIndex(of: "Message 4"))
    let previousIndex = try XCTUnwrap(text.firstIndex(of: "3 previous messages"))
    XCTAssertLessThan(message7Index, message6Index)
    XCTAssertLessThan(message6Index, message5Index)
    XCTAssertLessThan(message5Index, message4Index)
    XCTAssertLessThan(message4Index, previousIndex)

    try XCTUnwrap(try XCTUnwrap(buttons(in: view).first { $0.label == "3 previous messages" }).onClick)()
    XCTAssertEqual(actions.values(), [.setShowAllMessages(true)])

    state.showAllMessages = true
    let expandedText = visibleText(in: CodexDisplayAppGlasses.app(state: state) { _ in })
    XCTAssertTrue(expandedText.contains("Message 1"))
    XCTAssertTrue(expandedText.contains("Message 7"))
    XCTAssertLessThan(
      try XCTUnwrap(expandedText.firstIndex(of: "Message 7")),
      try XCTUnwrap(expandedText.firstIndex(of: "Message 1"))
    )
  }

  func testDisplayAppGlassesChatScreenExposesActionsAndOverflow() throws {
    let referenceDate = Date(timeIntervalSince1970: 1_780_600_000)
    let files = (1...5).map { index in
      CodexFilePreview(
        id: "file-\(index)",
        path: "/Users/example/project/file-\(index).swift",
        detail: "Swift file \(index)",
        diff: """
        --- a/file-\(index).swift
        +++ b/file-\(index).swift
        -old
        +new
        """
      )
    }
    let todos = (1...5).map { index in
      CodexTodoItem(id: "todo-\(index)", title: "Task \(index)", status: index == 1 ? "completed" : "pending")
    }
    var state = CodexDisplayAppState.make(
      chats: [
        CodexChatPreview(
          id: "chat-1",
          title: "Renderer chat",
          projectName: "No project",
          projectPath: nil,
          summary: "Renderer smoke",
          isPinned: false,
          isUnread: false,
          isActive: false,
          updatedAt: referenceDate
        ),
      ],
      projects: [],
      models: [
        CodexModelOption(id: "gpt-5.5", displayName: "GPT-5.5", detail: "Default", isDefault: true),
        CodexModelOption(id: "gpt-5-codex", displayName: "GPT-5 Codex", detail: "Code", isDefault: false),
      ],
      activeChat: CodexChatDetail(
        id: "chat-1",
        title: "Renderer chat",
        projectName: "No project",
        projectPath: nil,
        messages: [
          CodexChatMessage(id: "m0", role: .user, parts: [
            .text(id: "t0", "Earlier loaded message"),
          ]),
          CodexChatMessage(id: "m1", role: .assistant, parts: [
            .text(id: "t1", """
            ## Renderer response

            - **Fixed** markdown in src/App.swift:42
            - Linked [report](codex-file:/Users/example/project/report.md)

            ```swift
            let value = 1
            ```
            """),
            .fileGroup(CodexFileChangeGroup(id: "files", status: "changed", files: files)),
            .todos(id: "todos", todos),
            .tool(CodexToolRun(id: "tool", name: "build", status: "completed", detail: "Built")),
            .reasoning(id: "reasoning", "Hidden overflow"),
          ]),
        ],
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: nil,
        isStreaming: false
      ),
      selectedPet: .pet(id: "fireball"),
      petState: .idle,
      connectionState: .ready("Example Mac"),
      hostID: "env-1",
      referenceDate: referenceDate
    )
    state.screen = "chat"

    let actions = LockedActions()
    let view = CodexDisplayAppGlasses.app(state: state) { action in
      actions.append(action)
    }
    let text = visibleText(in: view)
    let joinedText = text.joined(separator: "\n")
    XCTAssertTrue(text.contains("More"))
    XCTAssertTrue(text.contains("Pet"))
    XCTAssertFalse(text.contains("No project"))
    XCTAssertFalse(text.contains("Example Mac"))
    XCTAssertFalse(text.contains("Pin"))
    XCTAssertFalse(text.contains("Archive"))
    XCTAssertFalse(text.contains("New"))
    XCTAssertTrue(text.contains("+1 more files"))
    XCTAssertTrue(text.contains("+1 more"))
    XCTAssertTrue(text.contains("+1 more items"))
    XCTAssertTrue(text.contains("Earlier loaded message"))
    XCTAssertTrue(text.contains("Renderer response"))
    XCTAssertTrue(text.contains("- Fixed markdown in src/App.swift:42"))
    XCTAssertTrue(text.contains("let value = 1"))
    XCTAssertFalse(joinedText.contains("## Renderer response"))
    XCTAssertFalse(joinedText.contains("**Fixed**"))
    XCTAssertTrue(text.contains("src/App.swift:42"))
    XCTAssertTrue(text.contains("report"))
    XCTAssertTrue(text.contains("Dictate"))
    XCTAssertFalse(joinedText.contains("Streaming..."))
    XCTAssertFalse(text.contains("GPT-5.5"))
    XCTAssertFalse(text.contains("5.5 - Default"))
    let chatButtons = buttons(in: view)
    let moreButton = try XCTUnwrap(chatButtons.first { $0.label == "More" })
    let petButton = try XCTUnwrap(chatButtons.first { $0.label == "Pet" })
    let dictateButton = try XCTUnwrap(chatButtons.first { $0.label == "Dictate" && $0.iconName == .speechBubble })
    XCTAssertNil(chatButtons.first { $0.iconName == .slidersHorizontal })
    let swiftFileButton = try XCTUnwrap(chatButtons.first { $0.label.contains("src/App.swift") })
    let reportButton = try XCTUnwrap(chatButtons.first { $0.label == "report" })

    try XCTUnwrap(moreButton.onClick)()
    try XCTUnwrap(petButton.onClick)()
    try XCTUnwrap(dictateButton.onClick)()
    try XCTUnwrap(swiftFileButton.onClick)()
    try XCTUnwrap(reportButton.onClick)()
    XCTAssertTrue(tappableRows(in: view).allSatisfy { $0.onClick == nil })

    XCTAssertEqual(actions.values(), [
      .setScreen(.chatActions),
      .setMode(.pet),
      .startTranscription(chatID: "chat-1"),
      .openFile(path: "src/App.swift"),
      .openFile(path: "/Users/example/project/report.md"),
    ])

    let originalMessages = state.messagesByChat["chat-1"]
    state.pet.state = CodexPetVisualState.thinking.rawValue
    state.messagesByChat["chat-1"] = []
    let thinkingView = CodexDisplayAppGlasses.app(state: state) { _ in }
    XCTAssertTrue(visibleText(in: thinkingView).contains("Thinking..."))
    state.pet.state = CodexPetVisualState.idle.rawValue
    state.messagesByChat["chat-1"] = originalMessages

    state.screen = "chatActions"
    let menuActions = LockedActions()
    let menuView = CodexDisplayAppGlasses.app(state: state) { action in
      menuActions.append(action)
    }
    XCTAssertTrue(visibleText(in: menuView).contains("GPT-5.5"))
    let menuButtons = buttons(in: menuView)
    try XCTUnwrap(try XCTUnwrap(menuButtons.first { $0.label == "Model" }).onClick)()
    try XCTUnwrap(try XCTUnwrap(menuButtons.first { $0.label == "Pin" }).onClick)()
    try XCTUnwrap(try XCTUnwrap(menuButtons.first { $0.label == "Archive" }).onClick)()
    XCTAssertEqual(menuActions.values(), [
      .setScreen(.modelPicker),
      .togglePinned(chatID: "chat-1"),
      .setScreen(.chat),
      .archiveChat(chatID: "chat-1"),
    ])

    state.screen = "chat"
    state.pet.state = CodexPetVisualState.recording.rawValue
    state.audioLevel = 0.8
    let recordingView = CodexDisplayAppGlasses.app(state: state) { _ in }
    assertFullHeightTopAligned(recordingView)
    XCTAssertTrue(visibleText(in: recordingView).contains("Finished"))
    XCTAssertEqual(buttons(in: recordingView).first?.iconName, .checkmark)

    state.pet.state = CodexPetVisualState.idle.rawValue
    state.isTranscribing = true
    let transcribingView = CodexDisplayAppGlasses.app(state: state) { _ in }
    assertFullHeightTopAligned(transcribingView)
    XCTAssertTrue(visibleText(in: transcribingView).contains("Transcribing"))
    XCTAssertTrue(buttons(in: transcribingView).isEmpty)

    state.isTranscribing = false
    state.transcriptPreview = "Send this transcript"
    let transcriptView = CodexDisplayAppGlasses.app(state: state) { _ in }
    assertFullHeightTopAligned(transcriptView)
    XCTAssertTrue(visibleText(in: transcriptView).contains("Send"))
    XCTAssertEqual(buttons(in: transcriptView).first?.iconName, .paperAirplane)

    state.transcriptPreview = ""
    state.messagesByChat["chat-1"] = []
    let emptyChatView = CodexDisplayAppGlasses.app(state: state) { _ in }
    assertFullHeightTopAligned(emptyChatView)
    XCTAssertTrue(visibleText(in: emptyChatView).contains("Ask Codex to start this chat"))
  }

  private func assertRequest(
    _ value: CodexJSONValue,
    method expectedMethod: String,
    requiredParams: [String],
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let object = try XCTUnwrap(value.objectValue, file: file, line: line)
    XCTAssertEqual(object["jsonrpc"]?.stringValue, "2.0", file: file, line: line)
    XCTAssertEqual(object["method"]?.stringValue, expectedMethod, file: file, line: line)
    XCTAssertTrue(CodexRemoteAPICatalog.observedAppServerMethods.contains(expectedMethod), file: file, line: line)

    let params = try XCTUnwrap(object["params"]?.objectValue, file: file, line: line)
    for param in requiredParams {
      XCTAssertNotNil(params[param], "\(expectedMethod) missing \(param)", file: file, line: line)
    }
  }

  private func chatPreview(
    id: String,
    title: String,
    projectPath: String?,
    updatedAt: Date,
    isPinned: Bool = false,
    isUnread: Bool = false,
    isActive: Bool = false
  ) -> CodexChatPreview {
    CodexChatPreview(
      id: id,
      title: title,
      projectName: projectPath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "No project",
      projectPath: projectPath,
      summary: title,
      isPinned: isPinned,
      isUnread: isUnread,
      isActive: isActive,
      updatedAt: updatedAt
    )
  }

  private func assertTurnCursor(
    _ value: CodexJSONValue,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let params = try XCTUnwrap(value.objectValue?["params"]?.objectValue, file: file, line: line)
    XCTAssertEqual(
      params["cursor"]?.stringValue.flatMap(CodexThreadTurnsCursor.init(rawValue:)),
      CodexThreadTurnsCursor(turnID: "turn-1", includeAnchor: false),
      file: file,
      line: line
    )
  }

  private func assertImageInput(
    _ value: CodexJSONValue,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let params = try XCTUnwrap(value.objectValue?["params"]?.objectValue, file: file, line: line)
    let input = try XCTUnwrap(params["input"], file: file, line: line)
    guard case .array(let items) = input else {
      XCTFail("turn/start input must be an array", file: file, line: line)
      return
    }

    XCTAssertEqual(items.count, 2, file: file, line: line)
    XCTAssertEqual(items[0].objectValue?["type"]?.stringValue, "text", file: file, line: line)
    XCTAssertEqual(items[1].objectValue?["type"]?.stringValue, "localImage", file: file, line: line)
    XCTAssertEqual(items[1].objectValue?["path"]?.stringValue, "/tmp/image.png", file: file, line: line)
    XCTAssertEqual(items[1].objectValue?["detail"]?.stringValue, "auto", file: file, line: line)
  }

  private func visibleText(in component: any ViewComponent) -> [String] {
    if let text = component as? Text {
      return [text.content]
    }
    if let button = component as? Button {
      return [button.label]
    }
    if let flexBox = component as? FlexBox {
      return flexBox.children.flatMap { visibleText(in: $0) }
    }
    return []
  }

  private func buttons(in component: any ViewComponent) -> [Button] {
    if let button = component as? Button {
      return [button]
    }
    if let flexBox = component as? FlexBox {
      return flexBox.children.flatMap { buttons(in: $0) }
    }
    return []
  }

  private func images(in component: any ViewComponent) -> [Image] {
    if let image = component as? Image {
      return [image]
    }
    if let flexBox = component as? FlexBox {
      return flexBox.children.flatMap { images(in: $0) }
    }
    return []
  }

  private func tappableRows(in component: any ViewComponent) -> [(text: String, onClick: (() -> Void)?)] {
    if let flexBox = component as? FlexBox {
      let text = visibleText(in: flexBox).joined(separator: " ")
      return [(text, flexBox.onClick)] + flexBox.children.flatMap { tappableRows(in: $0) }
    }
    return []
  }

  private func assertFullHeightTopAligned(
    _ component: FlexBox,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(component.alignment, .start, file: file, line: line)
    XCTAssertEqual(component.crossAlignment, .stretch, file: file, line: line)
    XCTAssertEqual(component.flexGrow, 1, file: file, line: line)
    XCTAssertEqual(component.alignSelf, .stretch, file: file, line: line)

    let reserveText = visibleText(in: component).filter { $0 == "\u{00A0}" }
    XCTAssertTrue(reserveText.isEmpty, "Root layout should not rely on invisible measurement text.", file: file, line: line)
  }
}

private final class LockedActions: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [CodexDisplayAppAction] = []

  func append(_ action: CodexDisplayAppAction) {
    lock.lock()
    storage.append(action)
    lock.unlock()
  }

  func values() -> [CodexDisplayAppAction] {
    lock.lock()
    defer { lock.unlock() }
    return storage
  }
}
