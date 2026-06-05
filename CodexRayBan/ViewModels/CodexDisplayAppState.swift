import Foundation

struct CodexDisplayAppState: Codable, Equatable, Sendable {
  var schemaVersion = 1
  var host: CodexDisplayAppHost
  var screen: String
  var mode: String
  var selectedProjectId: String?
  var selectedChatId: String?
  var showAllPinnedChats: Bool
  var showAllChats: Bool
  var showAllProjects: Bool
  var showAllProjectChats: Bool
  var showAllMessages: Bool
  var petBubbleExpanded: Bool
  var composerExpanded: Bool
  var isTranscribing: Bool
  var audioLevel: Double?
  var draft: String
  var transcriptPreview: String
  var hasOlderMessages: Bool
  var models: [CodexDisplayAppModel]
  var selectedModelId: String?
  var selectedFile: CodexDisplayAppViewedFile?
  var pet: CodexDisplayAppPet
  var projects: [CodexDisplayAppProject]
  var chats: [CodexDisplayAppChat]
  var messagesByChat: [String: [CodexDisplayAppMessage]]

  static func make(
    chats: [CodexChatPreview],
    projects: [CodexProjectPreview],
    models: [CodexModelOption] = [],
    activeChat: CodexChatDetail?,
    selectedPet: CodexPet,
    petState: CodexPetVisualState,
    connectionState: CodexChatTransportState,
    hostID: String? = nil,
    hostName: String? = nil,
    screen: String = "home",
    mode: String = "work",
    draft: String = "",
    transcriptPreview: String = "",
    showAllPinnedChats: Bool = false,
    showAllChats: Bool = false,
    showAllProjects: Bool = false,
    showAllProjectChats: Bool = false,
    showAllMessages: Bool = false,
    petBubbleExpanded: Bool = false,
    composerExpanded: Bool = false,
    isTranscribing: Bool = false,
    audioLevel: Double = 0,
    referenceDate: Date = .now
  ) -> CodexDisplayAppState {
    let exportedProjects = Self.projects(from: projects, chats: chats)
    let projectIdentifiers = Self.projectIdentifiers(in: exportedProjects)
    let exportedChats = chats.map { chat in
      var displayChat = CodexDisplayAppChat(chat: chat, referenceDate: referenceDate, projectIdentifiers: projectIdentifiers)
      if chat.id == activeChat?.id {
        displayChat.active = activeChat?.isStreaming ?? displayChat.active
      }
      return displayChat
    }
    let selectedProjectID = Self.knownProjectID(for: activeChat?.projectPath, in: projectIdentifiers)
    let selectedChatID = activeChat?.id ?? chats.first?.id
    let messagesByChat: [String: [CodexDisplayAppMessage]]
    if let activeChat {
      messagesByChat = [
        activeChat.id: activeChat.messages.map(CodexDisplayAppMessage.init(message:)),
      ]
    } else {
      messagesByChat = [:]
    }

    return CodexDisplayAppState(
      host: CodexDisplayAppHost(
        id: hostID,
        name: hostName?.nonEmptyDisplayText ?? connectionState.displayHostName ?? "No host",
        connected: connectionState.isReady
      ),
      screen: screen,
      mode: mode,
      selectedProjectId: selectedProjectID,
      selectedChatId: selectedChatID,
      showAllPinnedChats: showAllPinnedChats,
      showAllChats: showAllChats,
      showAllProjects: showAllProjects,
      showAllProjectChats: showAllProjectChats,
      showAllMessages: showAllMessages,
      petBubbleExpanded: petBubbleExpanded,
      composerExpanded: composerExpanded || petState == .recording || !draft.isEmpty || !transcriptPreview.isEmpty,
      isTranscribing: isTranscribing,
      audioLevel: min(max(audioLevel, 0), 1),
      draft: draft,
      transcriptPreview: transcriptPreview,
      hasOlderMessages: activeChat?.nextTurnCursor != nil,
      models: models.map(CodexDisplayAppModel.init(model:)),
      selectedModelId: models.first(where: \.isDefault)?.id ?? models.first?.id,
      selectedFile: nil,
      pet: CodexDisplayAppPet(
        id: selectedPet.id,
        name: selectedPet.displayName,
        state: petState.rawValue,
        bubble: Self.petBubbleText(from: activeChat),
        imageURI: selectedPet.hostedImageURL
      ),
      projects: exportedProjects,
      chats: exportedChats,
      messagesByChat: messagesByChat
    )
  }

  private static func projects(
    from projects: [CodexProjectPreview],
    chats: [CodexChatPreview]
  ) -> [CodexDisplayAppProject] {
    var exported: [(project: CodexDisplayAppProject, latest: Date)] = []

    for project in projects {
      let projectChats = chats.filter { $0.projectPath == project.id || $0.projectPath == project.path }
      guard !projectChats.isEmpty else {
        continue
      }

      exported.append((
        CodexDisplayAppProject(
          id: project.id,
          name: project.name,
          path: project.path,
          unread: projectChats.contains { $0.isUnread },
          active: projectChats.contains { $0.isActive },
          chats: projectChats.map(\.id)
        ),
        projectChats.map(\.updatedAt).max() ?? .distantPast
      ))
    }

    return exported.sorted { lhs, rhs in
      if lhs.project.active != rhs.project.active {
        return lhs.project.active
      }
      if lhs.project.unread != rhs.project.unread {
        return lhs.project.unread
      }
      if lhs.latest != rhs.latest {
        return lhs.latest > rhs.latest
      }
      return lhs.project.name.localizedCaseInsensitiveCompare(rhs.project.name) == .orderedAscending
    }.map(\.project)
  }

  private static func projectIdentifiers(in projects: [CodexDisplayAppProject]) -> Set<String> {
    Set(projects.flatMap { project in
      [project.id.nonEmptyDisplayText, project.path?.nonEmptyDisplayText].compactMap(\.self)
    })
  }

  private static func knownProjectID(for projectPath: String?, in projectIdentifiers: Set<String>) -> String? {
    guard let projectPath = projectPath?.nonEmptyDisplayText, projectIdentifiers.contains(projectPath) else {
      return nil
    }
    return projectPath
  }

  private static func petBubbleText(from activeChat: CodexChatDetail?) -> String {
    guard let activeChat else {
      return ""
    }

    if let text = latestAssistantText(in: activeChat)?.nonEmptyDisplayText {
      return text
    }

    return activeChat.title.nonEmptyDisplayText ?? ""
  }

  private static func latestAssistantText(in activeChat: CodexChatDetail) -> String? {
    for message in activeChat.messages.reversed() where message.role == .assistant {
      for part in message.parts.reversed() {
        if case .text(_, let text) = part, let text = text.nonEmptyDisplayText {
          return text
        }
      }

      for part in message.parts.reversed() {
        switch part {
        case .reasoning(_, let text):
          if let text = text.nonEmptyDisplayText {
            return text
          }
        case .tool(let tool):
          if let detail = tool.detail.nonEmptyDisplayText {
            return detail
          }
        case .todos(_, let items):
          if let todo = items.first(where: { !$0.isDone })?.title.nonEmptyDisplayText {
            return todo
          }
        case .text, .fileGroup, .file:
          continue
        }
      }
    }
    return nil
  }
}

struct CodexDisplayAppHost: Codable, Equatable, Sendable {
  var id: String?
  var name: String
  var connected: Bool
}

struct CodexDisplayAppPet: Codable, Equatable, Sendable {
  var id: String
  var name: String
  var state: String
  var bubble: String
  var imageURI: String? = nil
}

struct CodexDisplayAppModel: Codable, Equatable, Sendable {
  var id: String
  var name: String
  var detail: String
  var isDefault: Bool

  init(model: CodexModelOption) {
    self.id = model.id
    self.name = model.displayName
    self.detail = model.detail
    self.isDefault = model.isDefault
  }
}

struct CodexDisplayAppViewedFile: Codable, Equatable, Sendable {
  var path: String
  var title: String
  var content: String?
  var detail: String?
  var diff: String?
  var added: Int
  var removed: Int
  var supported: Bool

  init(path: String, content: String?, detail: String? = nil, diff: String? = nil, added: Int = 0, removed: Int = 0) {
    self.path = path
    self.title = URL(fileURLWithPath: path).lastPathComponent.nonEmptyDisplayText ?? path
    self.content = content
    self.detail = detail
    self.diff = diff
    self.added = added
    self.removed = removed
    self.supported = Self.isPreviewSupported(path: path)
  }

  private static func isPreviewSupported(path: String) -> Bool {
    let supportedExtensions: Set<String> = [
      "css", "go", "html", "js", "json", "jsx", "md", "mjs", "py", "rb", "rs",
      "sh", "swift", "toml", "ts", "tsx", "txt", "xml", "yaml", "yml",
    ]
    return supportedExtensions.contains(URL(fileURLWithPath: path).pathExtension.lowercased())
  }
}

struct CodexDisplayAppProject: Codable, Equatable, Sendable {
  var id: String
  var name: String
  var path: String?
  var unread: Bool
  var active: Bool
  var chats: [String]
}

struct CodexDisplayAppChat: Codable, Equatable, Sendable {
  var id: String
  var title: String
  var projectId: String?
  var projectName: String
  var updated: String
  var unread: Bool
  var active: Bool
  var pinned: Bool

  init(chat: CodexChatPreview, referenceDate: Date, projectIdentifiers: Set<String>) {
    self.id = chat.id
    self.title = chat.title
    let projectID = Self.knownProjectID(for: chat.projectPath, in: projectIdentifiers)
    self.projectId = projectID
    self.projectName = projectID == nil ? "No project" : chat.projectName
    self.updated = Self.relativeTimestamp(for: chat.updatedAt, referenceDate: referenceDate)
    self.unread = chat.isUnread
    self.active = chat.isActive
    self.pinned = chat.isPinned
  }

  private static func knownProjectID(for projectPath: String?, in projectIdentifiers: Set<String>) -> String? {
    guard let projectPath = projectPath?.nonEmptyDisplayText, projectIdentifiers.contains(projectPath) else {
      return nil
    }
    return projectPath
  }

  private static func relativeTimestamp(for date: Date, referenceDate: Date) -> String {
    let seconds = max(0, Int(referenceDate.timeIntervalSince(date)))
    if seconds < 60 {
      return "now"
    }

    let minutes = seconds / 60
    if minutes < 60 {
      return "\(minutes)m"
    }

    let hours = minutes / 60
    if hours < 24 {
      return "\(hours)h"
    }

    let days = hours / 24
    return "\(days)d"
  }
}

struct CodexDisplayAppMessage: Codable, Equatable, Sendable {
  var id: String
  var role: String
  var parts: [CodexDisplayAppMessagePart]
  var streaming: Bool?

  init(message: CodexChatMessage) {
    self.id = message.id
    self.role = message.role.displayRole
    self.parts = message.parts.map(CodexDisplayAppMessagePart.init(part:))
    self.streaming = nil
  }
}

struct CodexDisplayAppMessagePart: Codable, Equatable, Sendable {
  var type: String
  var text: String?
  var name: String?
  var status: String?
  var detail: String?
  var path: String?
  var diff: String?
  var added: Int?
  var removed: Int?
  var files: [CodexDisplayAppFile]?
  var items: [CodexDisplayAppTodo]?

  init(part: CodexMessagePart) {
    switch part {
    case .text(_, let text):
      self.init(type: "text", text: text)
    case .reasoning(_, let text):
      self.init(type: "reasoning", text: text)
    case .tool(let tool):
      self.init(
        type: "tool",
        name: tool.name,
        status: tool.status,
        detail: tool.detail
      )
    case .file(let file):
      self.init(
        type: "file",
        detail: file.detail,
        path: file.path,
        diff: file.diff,
        added: file.editPreview?.addedLineCount,
        removed: file.editPreview?.removedLineCount
      )
    case .fileGroup(let group):
      self.init(
        type: "fileGroup",
        status: group.status,
        files: group.files.map(CodexDisplayAppFile.init(file:))
      )
    case .todos(_, let items):
      self.init(
        type: "todo",
        items: items.map(CodexDisplayAppTodo.init(item:))
      )
    }
  }

  private init(
    type: String,
    text: String? = nil,
    name: String? = nil,
    status: String? = nil,
    detail: String? = nil,
    path: String? = nil,
    diff: String? = nil,
    added: Int? = nil,
    removed: Int? = nil,
    files: [CodexDisplayAppFile]? = nil,
    items: [CodexDisplayAppTodo]? = nil
  ) {
    self.type = type
    self.text = text
    self.name = name
    self.status = status
    self.detail = detail
    self.path = path
    self.diff = diff
    self.added = added
    self.removed = removed
    self.files = files
    self.items = items
  }
}

struct CodexDisplayAppFile: Codable, Equatable, Sendable {
  var path: String
  var detail: String
  var diff: String?
  var added: Int
  var removed: Int

  init(file: CodexFilePreview) {
    self.path = file.path
    self.detail = file.detail
    self.diff = file.diff
    self.added = file.editPreview?.addedLineCount ?? 0
    self.removed = file.editPreview?.removedLineCount ?? 0
  }
}

struct CodexDisplayAppTodo: Codable, Equatable, Sendable {
  var title: String
  var status: String
  var done: Bool

  init(item: CodexTodoItem) {
    self.title = item.title
    self.status = item.status
    self.done = item.isDone
  }
}

@MainActor
extension CodexWorkspaceViewModel {
  func displayAppState(
    hostID: String? = nil,
    hostName: String? = nil,
    screen: String = "home",
    mode: String = "work",
    draft: String = "",
    transcriptPreview: String = "",
    showAllPinnedChats: Bool = false,
    showAllChats: Bool = false,
    showAllProjects: Bool = false,
    showAllProjectChats: Bool = false,
    showAllMessages: Bool = false,
    petBubbleExpanded: Bool = false,
    composerExpanded: Bool = false,
    isTranscribing: Bool = false,
    audioLevel: Double = 0,
    referenceDate: Date = .now
  ) -> CodexDisplayAppState {
    CodexDisplayAppState.make(
      chats: chats,
      projects: projects,
      models: models,
      activeChat: activeChat,
      selectedPet: selectedPet,
      petState: petState,
      connectionState: connectionState,
      hostID: hostID,
      hostName: hostName,
      screen: screen,
      mode: mode,
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
      audioLevel: audioLevel,
      referenceDate: referenceDate
    )
  }
}

private extension CodexChatMessage.Role {
  var displayRole: String {
    switch self {
    case .user:
      return "user"
    case .assistant:
      return "assistant"
    case .system:
      return "system"
    }
  }
}

private extension CodexChatTransportState {
  var displayHostName: String? {
    switch self {
    case .connecting(let host), .ready(let host):
      return host.nonEmptyDisplayText
    case .disconnected, .failed:
      return nil
    }
  }
}

private extension String {
  var nonEmptyDisplayText: String? {
    let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
  }
}
