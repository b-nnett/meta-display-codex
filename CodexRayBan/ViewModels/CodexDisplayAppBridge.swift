import Foundation

enum CodexDisplayAppMode: String, Codable, Equatable, Sendable {
  case work
  case pet
}

enum CodexDisplayAppScreen: String, Codable, Equatable, Sendable {
  case home
  case project
  case chat
  case chatActions
  case file
  case modelPicker
  case pet
}

struct CodexDisplayAppActionEnvelope: Codable, Equatable, Sendable {
  var type: String
  var action: CodexDisplayAppAction

  init(type: String = "codex:action", action: CodexDisplayAppAction) {
    self.type = type
    self.action = action
  }

  enum CodingKeys: String, CodingKey {
    case type
    case action
    case payload
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.type = try container.decode(String.self, forKey: .type)
    let name = try container.decode(String.self, forKey: .action)
    let payload = try container.decodeIfPresent(CodexDisplayAppActionPayload.self, forKey: .payload) ?? .empty
    self.action = try CodexDisplayAppAction(name: name, payload: payload)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    try container.encode(action.name, forKey: .action)
    try container.encode(action.payload, forKey: .payload)
  }
}

enum CodexDisplayAppAction: Equatable, Sendable {
  case openProject(projectID: String)
  case openChat(chatID: String)
  case openFile(path: String)
  case sendMessage(chatID: String?, projectID: String?, text: String)
  case startTranscription(chatID: String?)
  case acceptTranscript(text: String)
  case discardTranscript
  case newChat(projectID: String?)
  case setMode(CodexDisplayAppMode)
  case updateDraft(text: String)
  case setComposerExpanded(Bool)
  case setShowAllPinnedChats(Bool)
  case setShowAllChats(Bool)
  case setShowAllProjects(Bool)
  case setShowAllProjectChats(Bool)
  case setShowAllMessages(Bool)
  case setPetBubbleExpanded(Bool)
  case loadOlderTurns
  case interruptTurn
  case togglePinned(chatID: String)
  case archiveChat(chatID: String)
  case setModel(modelID: String)
  case setScreen(CodexDisplayAppScreen)

  var name: String {
    switch self {
    case .openProject:
      return "openProject"
    case .openChat:
      return "openChat"
    case .openFile:
      return "openFile"
    case .sendMessage:
      return "sendMessage"
    case .startTranscription:
      return "startTranscription"
    case .acceptTranscript:
      return "acceptTranscript"
    case .discardTranscript:
      return "discardTranscript"
    case .newChat:
      return "newChat"
    case .setMode:
      return "setMode"
    case .updateDraft:
      return "updateDraft"
    case .setComposerExpanded:
      return "setComposerExpanded"
    case .setShowAllPinnedChats:
      return "setShowAllPinnedChats"
    case .setShowAllChats:
      return "setShowAllChats"
    case .setShowAllProjects:
      return "setShowAllProjects"
    case .setShowAllProjectChats:
      return "setShowAllProjectChats"
    case .setShowAllMessages:
      return "setShowAllMessages"
    case .setPetBubbleExpanded:
      return "setPetBubbleExpanded"
    case .loadOlderTurns:
      return "loadOlderTurns"
    case .interruptTurn:
      return "interruptTurn"
    case .togglePinned:
      return "togglePinned"
    case .archiveChat:
      return "archiveChat"
    case .setModel:
      return "setModel"
    case .setScreen:
      return "setScreen"
    }
  }

  var payload: CodexDisplayAppActionPayload {
    switch self {
    case .openProject(let projectID):
      return CodexDisplayAppActionPayload(projectId: projectID)
    case .openChat(let chatID):
      return CodexDisplayAppActionPayload(chatId: chatID)
    case .openFile(let path):
      return CodexDisplayAppActionPayload(path: path)
    case .sendMessage(let chatID, let projectID, let text):
      return CodexDisplayAppActionPayload(chatId: chatID, projectId: projectID, text: text)
    case .startTranscription(let chatID):
      return CodexDisplayAppActionPayload(chatId: chatID)
    case .acceptTranscript(let text):
      return CodexDisplayAppActionPayload(text: text)
    case .discardTranscript:
      return .empty
    case .newChat(let projectID):
      return CodexDisplayAppActionPayload(projectId: projectID)
    case .setMode(let mode):
      return CodexDisplayAppActionPayload(mode: mode.rawValue)
    case .updateDraft(let text):
      return CodexDisplayAppActionPayload(text: text)
    case .setComposerExpanded(let expanded):
      return CodexDisplayAppActionPayload(expanded: expanded)
    case .setShowAllPinnedChats(let showAllPinnedChats):
      return CodexDisplayAppActionPayload(showAllPinnedChats: showAllPinnedChats)
    case .setShowAllChats(let showAllChats):
      return CodexDisplayAppActionPayload(showAllChats: showAllChats)
    case .setShowAllProjects(let showAllProjects):
      return CodexDisplayAppActionPayload(showAllProjects: showAllProjects)
    case .setShowAllProjectChats(let showAllProjectChats):
      return CodexDisplayAppActionPayload(showAllProjectChats: showAllProjectChats)
    case .setShowAllMessages(let showAllMessages):
      return CodexDisplayAppActionPayload(showAllMessages: showAllMessages)
    case .setPetBubbleExpanded(let expanded):
      return CodexDisplayAppActionPayload(petBubbleExpanded: expanded)
    case .loadOlderTurns, .interruptTurn:
      return .empty
    case .togglePinned(let chatID), .archiveChat(let chatID):
      return CodexDisplayAppActionPayload(chatId: chatID)
    case .setModel(let modelID):
      return CodexDisplayAppActionPayload(modelId: modelID)
    case .setScreen(let screen):
      return CodexDisplayAppActionPayload(screen: screen.rawValue)
    }
  }

  init(name: String, payload: CodexDisplayAppActionPayload) throws {
    switch name {
    case "openProject":
      self = .openProject(projectID: try payload.required(\.projectId, "projectId"))
    case "openChat":
      self = .openChat(chatID: try payload.required(\.chatId, "chatId"))
    case "openFile":
      self = .openFile(path: try payload.required(\.path, "path"))
    case "sendMessage":
      self = .sendMessage(
        chatID: payload.chatId,
        projectID: payload.projectId,
        text: try payload.required(\.text, "text")
      )
    case "startTranscription":
      self = .startTranscription(chatID: payload.chatId)
    case "acceptTranscript":
      self = .acceptTranscript(text: try payload.required(\.text, "text"))
    case "discardTranscript":
      self = .discardTranscript
    case "newChat":
      self = .newChat(projectID: payload.projectId)
    case "setMode":
      let rawMode = try payload.required(\.mode, "mode")
      guard let mode = CodexDisplayAppMode(rawValue: rawMode) else {
        throw CodexDisplayAppActionError.invalidPayload("Unknown mode \(rawMode)")
      }
      self = .setMode(mode)
    case "updateDraft":
      self = .updateDraft(text: payload.text ?? "")
    case "setComposerExpanded":
      guard let expanded = payload.expanded else {
        throw CodexDisplayAppActionError.missingPayloadValue("expanded")
      }
      self = .setComposerExpanded(expanded)
    case "setShowAllPinnedChats":
      guard let showAllPinnedChats = payload.showAllPinnedChats else {
        throw CodexDisplayAppActionError.missingPayloadValue("showAllPinnedChats")
      }
      self = .setShowAllPinnedChats(showAllPinnedChats)
    case "setShowAllChats":
      guard let showAllChats = payload.showAllChats else {
        throw CodexDisplayAppActionError.missingPayloadValue("showAllChats")
      }
      self = .setShowAllChats(showAllChats)
    case "setShowAllProjects":
      guard let showAllProjects = payload.showAllProjects else {
        throw CodexDisplayAppActionError.missingPayloadValue("showAllProjects")
      }
      self = .setShowAllProjects(showAllProjects)
    case "setShowAllProjectChats":
      guard let showAllProjectChats = payload.showAllProjectChats else {
        throw CodexDisplayAppActionError.missingPayloadValue("showAllProjectChats")
      }
      self = .setShowAllProjectChats(showAllProjectChats)
    case "setShowAllMessages":
      guard let showAllMessages = payload.showAllMessages else {
        throw CodexDisplayAppActionError.missingPayloadValue("showAllMessages")
      }
      self = .setShowAllMessages(showAllMessages)
    case "setPetBubbleExpanded":
      guard let expanded = payload.petBubbleExpanded else {
        throw CodexDisplayAppActionError.missingPayloadValue("petBubbleExpanded")
      }
      self = .setPetBubbleExpanded(expanded)
    case "loadOlderTurns":
      self = .loadOlderTurns
    case "interruptTurn":
      self = .interruptTurn
    case "togglePinned":
      self = .togglePinned(chatID: try payload.required(\.chatId, "chatId"))
    case "archiveChat":
      self = .archiveChat(chatID: try payload.required(\.chatId, "chatId"))
    case "setModel":
      self = .setModel(modelID: try payload.required(\.modelId, "modelId"))
    case "setScreen":
      let rawScreen = try payload.required(\.screen, "screen")
      guard let screen = CodexDisplayAppScreen(rawValue: rawScreen) else {
        throw CodexDisplayAppActionError.invalidPayload("Unknown screen \(rawScreen)")
      }
      self = .setScreen(screen)
    default:
      throw CodexDisplayAppActionError.unknownAction(name)
    }
  }
}

extension CodexDisplayAppAction {
  var diagnosticsSummary: String {
    switch self {
    case .openProject(let projectID):
      "openProject project=\(short(projectID))"
    case .openChat(let chatID):
      "openChat chat=\(short(chatID))"
    case .openFile(let path):
      "openFile path=\(short(path))"
    case .sendMessage(let chatID, let projectID, let text):
      "sendMessage chat=\(short(chatID)) project=\(short(projectID)) chars=\(text.count)"
    case .startTranscription(let chatID):
      "startTranscription chat=\(short(chatID))"
    case .acceptTranscript(let text):
      "acceptTranscript chars=\(text.count)"
    case .discardTranscript:
      "discardTranscript"
    case .newChat(let projectID):
      "newChat project=\(short(projectID))"
    case .setMode(let mode):
      "setMode mode=\(mode.rawValue)"
    case .updateDraft(let text):
      "updateDraft chars=\(text.count)"
    case .setComposerExpanded(let expanded):
      "setComposerExpanded expanded=\(expanded)"
    case .setShowAllPinnedChats(let showAll):
      "setShowAllPinnedChats showAll=\(showAll)"
    case .setShowAllChats(let showAll):
      "setShowAllChats showAll=\(showAll)"
    case .setShowAllProjects(let showAll):
      "setShowAllProjects showAll=\(showAll)"
    case .setShowAllProjectChats(let showAll):
      "setShowAllProjectChats showAll=\(showAll)"
    case .setShowAllMessages(let showAll):
      "setShowAllMessages showAll=\(showAll)"
    case .setPetBubbleExpanded(let expanded):
      "setPetBubbleExpanded expanded=\(expanded)"
    case .loadOlderTurns:
      "loadOlderTurns"
    case .interruptTurn:
      "interruptTurn"
    case .togglePinned(let chatID):
      "togglePinned chat=\(short(chatID))"
    case .archiveChat(let chatID):
      "archiveChat chat=\(short(chatID))"
    case .setModel(let modelID):
      "setModel model=\(short(modelID))"
    case .setScreen(let screen):
      "setScreen screen=\(screen.rawValue)"
    }
  }

  private func short(_ value: String?) -> String {
    guard let value, !value.isEmpty else {
      return "missing"
    }
    if value.count <= 18 {
      return value
    }
    return "\(value.prefix(10))...\(value.suffix(6))"
  }
}

struct CodexDisplayAppActionPayload: Codable, Equatable, Sendable {
  static let empty = CodexDisplayAppActionPayload()

  var chatId: String?
  var projectId: String?
  var path: String?
  var text: String?
  var mode: String?
  var modelId: String?
  var expanded: Bool?
  var showAllPinnedChats: Bool?
  var showAllChats: Bool?
  var showAllProjects: Bool?
  var showAllProjectChats: Bool?
  var showAllMessages: Bool?
  var petBubbleExpanded: Bool?
  var screen: String?

  init(
    chatId: String? = nil,
    projectId: String? = nil,
    path: String? = nil,
    text: String? = nil,
    mode: String? = nil,
    modelId: String? = nil,
    expanded: Bool? = nil,
    showAllPinnedChats: Bool? = nil,
    showAllChats: Bool? = nil,
    showAllProjects: Bool? = nil,
    showAllProjectChats: Bool? = nil,
    showAllMessages: Bool? = nil,
    petBubbleExpanded: Bool? = nil,
    screen: String? = nil
  ) {
    self.chatId = chatId
    self.projectId = projectId
    self.path = path
    self.text = text
    self.mode = mode
    self.modelId = modelId
    self.expanded = expanded
    self.showAllPinnedChats = showAllPinnedChats
    self.showAllChats = showAllChats
    self.showAllProjects = showAllProjects
    self.showAllProjectChats = showAllProjectChats
    self.showAllMessages = showAllMessages
    self.petBubbleExpanded = petBubbleExpanded
    self.screen = screen
  }

  func required(_ keyPath: KeyPath<CodexDisplayAppActionPayload, String?>, _ name: String) throws -> String {
    guard let value = self[keyPath: keyPath]?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
      throw CodexDisplayAppActionError.missingPayloadValue(name)
    }
    return value
  }
}

struct CodexDisplayAppTranscriptionResult: Equatable, Sendable {
  var text: String
  var isRecording: Bool
}

enum CodexDisplayAppActionError: LocalizedError, Equatable, Sendable {
  case unknownAction(String)
  case missingPayloadValue(String)
  case invalidPayload(String)
  case invalidEnvelopeType(String)

  var errorDescription: String? {
    switch self {
    case .unknownAction(let action):
      return "Unknown display action: \(action)"
    case .missingPayloadValue(let key):
      return "Display action is missing payload value: \(key)"
    case .invalidPayload(let message):
      return "Invalid display action payload: \(message)"
    case .invalidEnvelopeType(let type):
      return "Invalid display action envelope type: \(type)"
    }
  }
}

@MainActor
final class CodexDisplayAppBridge {
  var mode: CodexDisplayAppMode = .work
  var screen: CodexDisplayAppScreen = .home
  var selectedProjectID: String?
  var selectedChatID: String?
  var draft = ""
  var transcriptPreview = ""
  var showAllPinnedChats = false
  var showAllChats = false
  var showAllProjects = false
  var showAllProjectChats = false
  var showAllMessages = false
  var petBubbleExpanded = false
  var composerExpanded = false
  var isTranscribing = false
  var selectedModelID: String?
  var isComposingNewChat = false
  var selectedFilePath: String?
  var lastOpenedFileContent: String?
  var lastOpenedFileDetail: String?
  var lastOpenedFileDiff: String?
  var lastOpenedFileAdded = 0
  var lastOpenedFileRemoved = 0

  func state(
    from workspace: CodexWorkspaceViewModel,
    hostID: String? = nil,
    hostName: String? = nil,
    referenceDate: Date = .now
  ) -> CodexDisplayAppState {
    var state = workspace.displayAppState(
      hostID: hostID,
      hostName: hostName,
      screen: screen.rawValue,
      mode: mode.rawValue,
      draft: draft,
      transcriptPreview: transcriptPreview,
      showAllPinnedChats: showAllPinnedChats,
      showAllChats: showAllChats,
      showAllProjects: showAllProjects,
      showAllProjectChats: showAllProjectChats,
      showAllMessages: showAllMessages,
      petBubbleExpanded: petBubbleExpanded,
      composerExpanded: composerExpanded,
      isTranscribing: isTranscribing,
      referenceDate: referenceDate
    )
    state.selectedProjectId = selectedProjectID ?? state.selectedProjectId
    if isComposingNewChat {
      state.selectedChatId = nil
    } else if let selectedChatID, state.chats.contains(where: { $0.id == selectedChatID }) {
      state.selectedChatId = selectedChatID
    }
    state.selectedModelId = selectedModelID ?? state.selectedModelId
    if let selectedFilePath {
      state.selectedFile = CodexDisplayAppViewedFile(
        path: selectedFilePath,
        content: lastOpenedFileContent,
        detail: lastOpenedFileDetail,
        diff: lastOpenedFileDiff,
        added: lastOpenedFileAdded,
        removed: lastOpenedFileRemoved
      )
    }
    return state
  }

  func handle(
    envelopeData: Data,
    workspace: CodexWorkspaceViewModel,
    transcribe: ((String?) async throws -> CodexDisplayAppTranscriptionResult)? = nil
  ) async throws {
    let envelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: envelopeData)
    guard envelope.type == "codex:action" else {
      throw CodexDisplayAppActionError.invalidEnvelopeType(envelope.type)
    }
    try await handle(envelope.action, workspace: workspace, transcribe: transcribe)
  }

  func handle(
    _ action: CodexDisplayAppAction,
    workspace: CodexWorkspaceViewModel,
    transcribe: ((String?) async throws -> CodexDisplayAppTranscriptionResult)? = nil
  ) async throws {
    log("action \(action.diagnosticsSummary) screen=\(screen.rawValue) mode=\(mode.rawValue)")
    switch action {
    case .openProject(let projectID):
      if selectedProjectID != projectID {
        showAllProjectChats = false
      }
      selectedProjectID = projectID
      selectedChatID = nil
      isComposingNewChat = false
      screen = .project
      mode = .work
      composerExpanded = false

    case .openChat(let chatID):
      if selectedChatID != chatID {
        showAllMessages = false
        petBubbleExpanded = false
      }
      selectedChatID = chatID
      isComposingNewChat = false
      screen = .chat
      mode = .work
      transcriptPreview = ""
      isTranscribing = false
      composerExpanded = false
      if let chat = workspace.chats.first(where: { $0.id == chatID }) {
        selectedProjectID = knownProjectID(for: chat.projectPath, workspace: workspace)
        if workspace.connectionState.isReady {
          await workspace.loadChat(chat)
        } else {
          workspace.activeChat = CodexChatDetail(
            id: chat.id,
            title: chat.title,
            projectName: chat.projectName,
            projectPath: chat.projectPath,
            messages: workspace.activeChat?.id == chat.id ? workspace.activeChat?.messages ?? [] : [],
            nextTurnCursor: nil,
            backwardsTurnCursor: nil,
            activeTurnID: nil,
            isStreaming: chat.isActive
          )
        }
      }

    case .openFile(let path):
      let resolvedPath = resolveFilePath(path, workspace: workspace)
      let metadata = filePreviewMetadata(rawPath: path, resolvedPath: resolvedPath, workspace: workspace)
      let editPreview = metadata?.editPreview
      selectedFilePath = resolvedPath
      lastOpenedFileContent = await workspace.readFile(path: resolvedPath) ?? metadata?.detail
      lastOpenedFileDetail = metadata?.detail
      lastOpenedFileDiff = metadata?.diff
      lastOpenedFileAdded = editPreview?.addedLineCount ?? 0
      lastOpenedFileRemoved = editPreview?.removedLineCount ?? 0
      screen = .file

    case .sendMessage(let chatID, let projectID, let text):
      let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmed.isEmpty else {
        return
      }
      let targetChatID = chatID ?? selectedChatID
      let targetProjectID = knownProjectID(for: projectID, workspace: workspace) ?? selectedProjectID
      selectedChatID = targetChatID
      selectedProjectID = targetProjectID
      isComposingNewChat = false
      screen = .chat
      draft = ""
      transcriptPreview = ""
      isTranscribing = false
      composerExpanded = false
      let acceptedThreadID = try await workspace.sendMessage(
        text: trimmed,
        threadID: targetChatID,
        cwd: targetProjectID,
        model: selectedModelID
      )
      if let acceptedThreadID {
        selectedChatID = acceptedThreadID
      }
      if let activeChat = workspace.activeChat {
        selectedChatID = activeChat.id
        selectedProjectID = knownProjectID(for: activeChat.projectPath, workspace: workspace) ?? selectedProjectID
        isComposingNewChat = false
        screen = .chat
        mode = .work
      }

    case .startTranscription(let chatID):
      selectedChatID = chatID ?? selectedChatID
      screen = .chat
      composerExpanded = true
      guard let transcribe else {
        log("transcription unavailable chat=\(short(selectedChatID))")
        return
      }
      defer {
        isTranscribing = false
      }
      log("transcription start chat=\(short(selectedChatID))")
      let result = try await transcribe(selectedChatID)
      let transcript = result.text.trimmingCharacters(in: .whitespacesAndNewlines)
      transcriptPreview = transcript
      composerExpanded = result.isRecording || !transcript.isEmpty || !draft.isEmpty
      log("transcription result chat=\(short(selectedChatID)) recording=\(result.isRecording) chars=\(transcript.count)")
      if result.isRecording {
        workspace.petState = .recording
      } else if workspace.activeChat?.isStreaming != true {
        workspace.petState = .idle
      }

    case .acceptTranscript(let text):
      let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
      if !trimmed.isEmpty {
        draft = draft.isEmpty ? trimmed : "\(draft) \(trimmed)"
      }
      transcriptPreview = ""
      isTranscribing = false
      composerExpanded = !draft.isEmpty
      if workspace.activeChat?.isStreaming != true {
        workspace.petState = .idle
      }

    case .discardTranscript:
      transcriptPreview = ""
      isTranscribing = false
      composerExpanded = !draft.isEmpty
      if workspace.activeChat?.isStreaming != true {
        workspace.petState = .idle
      }

    case .newChat(let projectID):
      selectedProjectID = knownProjectID(for: projectID, workspace: workspace)
      selectedChatID = nil
      isComposingNewChat = true
      screen = .chat
      draft = ""
      transcriptPreview = ""
      isTranscribing = false
      composerExpanded = true
      mode = .work
      workspace.activeChat = nil

    case .setMode(let nextMode):
      mode = nextMode
      if nextMode == .pet, workspace.petState == .idle {
        workspace.petState = .waving
      }
      if nextMode == .pet {
        petBubbleExpanded = false
      }
      screen = nextMode == .pet ? .pet : .home

    case .updateDraft(let text):
      draft = text
      composerExpanded = composerExpanded || !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !transcriptPreview.isEmpty

    case .setComposerExpanded(let expanded):
      composerExpanded = expanded || !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !transcriptPreview.isEmpty

    case .setShowAllPinnedChats(let showAll):
      showAllPinnedChats = showAll

    case .setShowAllChats(let showAll):
      showAllChats = showAll

    case .setShowAllProjects(let showAll):
      showAllProjects = showAll

    case .setShowAllProjectChats(let showAll):
      showAllProjectChats = showAll

    case .setShowAllMessages(let showAll):
      showAllMessages = showAll

    case .setPetBubbleExpanded(let expanded):
      petBubbleExpanded = expanded

    case .loadOlderTurns:
      await workspace.loadOlderTurns()

    case .interruptTurn:
      await workspace.interruptActiveTurn()

    case .togglePinned(let chatID):
      if let chat = workspace.chats.first(where: { $0.id == chatID }) {
        workspace.togglePinned(chat)
      }

    case .archiveChat(let chatID):
      if let chat = workspace.chats.first(where: { $0.id == chatID }) {
        await workspace.archiveChat(chat)
        if selectedChatID == chatID {
          selectedChatID = nil
          screen = .home
          composerExpanded = false
        }
      }

    case .setModel(let modelID):
      selectedModelID = modelID

    case .setScreen(let nextScreen):
      screen = nextScreen
      mode = nextScreen == .pet ? .pet : .work
    }
  }

  private func log(_ message: String) {
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      NSLog("[Codex display bridge] %@", message)
    }
  }

  private func short(_ value: String?) -> String {
    guard let value, !value.isEmpty else {
      return "missing"
    }
    if value.count <= 18 {
      return value
    }
    return "\(value.prefix(10))...\(value.suffix(6))"
  }

  private func resolveFilePath(_ rawPath: String, workspace: CodexWorkspaceViewModel) -> String {
    let path = rawPath.removingPercentEncoding ?? rawPath
    if path.hasPrefix("/") || path.hasPrefix("~") {
      return path
    }

    let projectPath = selectedProjectID
      ?? workspace.activeChat?.projectPath
      ?? selectedChatID.flatMap { chatID in
        workspace.chats.first(where: { $0.id == chatID })?.projectPath
      }

    guard let projectPath, !projectPath.isEmpty else {
      return path
    }
    return URL(fileURLWithPath: projectPath).appendingPathComponent(path).path
  }

  private func knownProjectID(for projectPath: String?, workspace: CodexWorkspaceViewModel) -> String? {
    guard let projectPath = CodexWorkspaceViewModel.normalizedProjectPath(projectPath) else {
      return nil
    }

    let identifiers = Set(workspace.projects.flatMap { project in
      [CodexWorkspaceViewModel.normalizedProjectPath(project.id), CodexWorkspaceViewModel.normalizedProjectPath(project.path)]
        .compactMap(\.self)
    })
    return identifiers.contains(projectPath) ? projectPath : nil
  }

  private func filePreviewMetadata(
    rawPath: String,
    resolvedPath: String,
    workspace: CodexWorkspaceViewModel
  ) -> CodexFilePreview? {
    guard let activeChat = workspace.activeChat else {
      return nil
    }

    for message in activeChat.messages.reversed() {
      for part in message.parts.reversed() {
        switch part {
        case .file(let file):
          if fileMatches(file.path, rawPath: rawPath, resolvedPath: resolvedPath, workspace: workspace) {
            return file
          }
        case .fileGroup(let group):
          if let file = group.files.reversed().first(where: {
            fileMatches($0.path, rawPath: rawPath, resolvedPath: resolvedPath, workspace: workspace)
          }) {
            return file
          }
        case .text, .reasoning, .tool, .todos:
          continue
        }
      }
    }

    return nil
  }

  private func fileMatches(
    _ filePath: String,
    rawPath: String,
    resolvedPath: String,
    workspace: CodexWorkspaceViewModel
  ) -> Bool {
    let decodedFilePath = filePath.removingPercentEncoding ?? filePath
    let decodedRawPath = rawPath.removingPercentEncoding ?? rawPath
    let resolvedFilePath = resolveFilePath(decodedFilePath, workspace: workspace)

    return decodedFilePath == decodedRawPath
      || decodedFilePath == resolvedPath
      || resolvedFilePath == resolvedPath
      || decodedFilePath.hasSuffix("/\(decodedRawPath)")
      || resolvedPath.hasSuffix("/\(decodedFilePath)")
  }
}
