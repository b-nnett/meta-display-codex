import CryptoKit
import Foundation
import Observation

struct CodexChatPreview: Identifiable, Hashable {
  let id: String
  var title: String
  var projectName: String
  var projectPath: String?
  var summary: String
  var isPinned: Bool
  var isUnread: Bool
  var isActive: Bool
  var updatedAt: Date
}

struct CodexProjectPreview: Identifiable, Hashable {
  let id: String
  var name: String
  var path: String?
  var chatCount: Int
}

struct CodexModelOption: Identifiable, Hashable {
  var id: String
  var displayName: String
  var detail: String
  var isDefault: Bool
}

struct CodexChatDetail: Identifiable, Hashable {
  var id: String
  var title: String
  var projectName: String
  var projectPath: String?
  var messages: [CodexChatMessage]
  var nextTurnCursor: CodexThreadTurnsCursor?
  var backwardsTurnCursor: CodexThreadTurnsCursor?
  var activeTurnID: String?
  var isStreaming: Bool
}

struct CodexChatMessage: Identifiable, Hashable {
  enum Role: Hashable {
    case user
    case assistant
    case system
  }

  enum DeliveryState: Hashable {
    case sent
    case sending
    case failed(String)
  }

  var id: String
  var role: Role
  var parts: [CodexMessagePart]
  var createdAt: Date = .now
  var deliveryState: DeliveryState = .sent
}

enum CodexMessagePart: Identifiable, Hashable {
  case text(id: String, String)
  case reasoning(id: String, String)
  case tool(CodexToolRun)
  case file(CodexFilePreview)
  case fileGroup(CodexFileChangeGroup)
  case todos(id: String, [CodexTodoItem])

  var id: String {
    switch self {
    case .text(let id, _), .reasoning(let id, _), .todos(let id, _):
      id
    case .tool(let tool):
      tool.id
    case .file(let file):
      file.id
    case .fileGroup(let group):
      group.id
    }
  }
}

struct CodexToolRun: Identifiable, Hashable {
  var id: String
  var name: String
  var status: String
  var detail: String
}

struct CodexFilePreview: Identifiable, Hashable {
  var id: String
  var path: String
  var detail: String
  var diff: String? = nil
}

struct CodexFileChangeGroup: Identifiable, Hashable {
  var id: String
  var status: String
  var files: [CodexFilePreview]

  var addedLineCount: Int {
    files.reduce(0) { $0 + ($1.editPreview?.addedLineCount ?? 0) }
  }

  var removedLineCount: Int {
    files.reduce(0) { $0 + ($1.editPreview?.removedLineCount ?? 0) }
  }
}

struct CodexFileEditPreview: Hashable {
  var addedLineCount: Int
  var removedLineCount: Int
  var previewLines: [CodexFileEditPreviewLine]

  var editedLineCount: Int {
    addedLineCount + removedLineCount
  }

  var shouldShowCountsOnly: Bool {
    editedLineCount > 5
  }
}

struct CodexFileEditPreviewLine: Identifiable, Hashable {
  enum Kind: Hashable {
    case added
    case removed

    var prefix: String {
      switch self {
      case .added:
        "+"
      case .removed:
        "-"
      }
    }
  }

  var id: Int
  var kind: Kind
  var text: String
}

extension CodexFilePreview {
  var editPreview: CodexFileEditPreview? {
    guard let diff, !diff.isEmpty else {
      return nil
    }

    var addedLineCount = 0
    var removedLineCount = 0
    var previewLines: [CodexFileEditPreviewLine] = []

    for line in diff.split(whereSeparator: \.isNewline).map(String.init) {
      if line.hasPrefix("+++") || line.hasPrefix("---") {
        continue
      }

      if line.hasPrefix("+") {
        addedLineCount += 1
        if previewLines.count < 5 {
          previewLines.append(CodexFileEditPreviewLine(
            id: previewLines.count,
            kind: .added,
            text: String(line.dropFirst()).trimmingCharacters(in: .whitespaces)
          ))
        }
      } else if line.hasPrefix("-") {
        removedLineCount += 1
        if previewLines.count < 5 {
          previewLines.append(CodexFileEditPreviewLine(
            id: previewLines.count,
            kind: .removed,
            text: String(line.dropFirst()).trimmingCharacters(in: .whitespaces)
          ))
        }
      }
    }

    guard addedLineCount + removedLineCount > 0 else {
      return nil
    }

    return CodexFileEditPreview(
      addedLineCount: addedLineCount,
      removedLineCount: removedLineCount,
      previewLines: previewLines
    )
  }
}

struct CodexTodoItem: Identifiable, Hashable {
  var id: String
  var title: String
  var status: String

  var isDone: Bool {
    status == "completed" || status == "done"
  }
}

private extension CodexMessagePart {
  var plainText: String {
    switch self {
    case .text(_, let text), .reasoning(_, let text):
      return text
    case .todos(_, let items):
      return items.map(\.title).joined(separator: "\n")
    case .tool(let tool):
      return tool.detail
    case .file(let file):
      return file.detail
    case .fileGroup(let group):
      return group.files.map(\.detail).joined(separator: "\n")
    }
  }
}

struct CodexAppServerEvent: Sendable {
  var id: String?
  var method: String
  var params: CodexJSONValue
}

enum CodexChatTransportState: Equatable {
  case disconnected
  case connecting(String)
  case ready(String)
  case failed(String)

  var isReady: Bool {
    if case .ready = self {
      return true
    }
    return false
  }

  var emptyStateText: String {
    switch self {
    case .disconnected:
      return "Chat transport not connected"
    case .connecting(let host):
      return "Connecting to \(host)"
    case .ready:
      return "No chats yet"
    case .failed:
      return "Chat transport failed"
    }
  }
}

@Observable
@MainActor
final class CodexWorkspaceViewModel {
  var chats: [CodexChatPreview] = []
  var projects: [CodexProjectPreview] = []
  var models: [CodexModelOption] = []
  var activeChat: CodexChatDetail?
  var selectedPet: CodexPet = .pet(id: UserDefaults.standard.string(forKey: "codex.selected.pet.id")) {
    didSet {
      UserDefaults.standard.set(selectedPet.id, forKey: "codex.selected.pet.id")
    }
  }
  var petState: CodexPetVisualState = .idle
  var connectionState: CodexChatTransportState = .disconnected
  var errorMessage: String?
  var isLoading = false
  var isLoadingChat = false

  @ObservationIgnored private let deviceKeyStore: CodexDeviceKeyStore
  @ObservationIgnored private let userDefaults: UserDefaults
  @ObservationIgnored private var pinnedChatIDs: Set<String>
  @ObservationIgnored private var readTimestampsByChatID: [String: TimeInterval]
  @ObservationIgnored private var connection: CodexRemoteAppServerConnection?
  @ObservationIgnored private var connectionKey: String?

  init(deviceKeyStore: CodexDeviceKeyStore = CodexDeviceKeyStore(), userDefaults: UserDefaults = .standard) {
    self.deviceKeyStore = deviceKeyStore
    self.userDefaults = userDefaults
    self.pinnedChatIDs = Self.loadPinnedChatIDs(from: userDefaults)
    self.readTimestampsByChatID = Self.loadReadTimestamps(from: userDefaults)
  }

  func refresh(
    session: CodexAuthSession,
    environments: [CodexEnvironment],
    preferredEnvironmentID: String? = nil,
    authTokenProvider: (@Sendable () async throws -> CodexAppServerAuthTokens)? = nil
  ) async {
    guard session.remoteTokenIsFresh else {
      disconnect()
      return
    }

    guard let environment = selectedEnvironment(from: environments, preferredEnvironmentID: preferredEnvironmentID) else {
      connectionState = .disconnected
      chats = []
      errorMessage = nil
      return
    }

    guard
      let clientID = session.remoteClientID,
      let remoteToken = session.remoteControlToken,
      !clientID.isEmpty,
      !remoteToken.isEmpty
    else {
      disconnect()
      return
    }

    isLoading = true
    errorMessage = nil
    connectionState = .connecting(environment.displayName)
    defer { isLoading = false }

    do {
      let key = try deviceKeyStore.loadOrCreate(existingKeyID: session.deviceKeyID)
      let nextConnectionKey = [
        environment.envID,
        clientID,
        key.keyID,
      ].joined(separator: ":")

      if connection == nil || connectionKey != nextConnectionKey {
        await connection?.close()
        connection = CodexRemoteAppServerConnection(
          environmentID: environment.envID,
          clientID: clientID,
          accountID: session.accountID,
          remoteControlToken: remoteToken,
          tokenExpiresAt: session.remoteControlExpiresAt,
          deviceKey: key,
          eventHandler: { [weak self] event in
            await self?.handle(event)
          },
          authTokenProvider: authTokenProvider,
          disconnectionHandler: { [weak self] error in
            await self?.handleConnectionFailure(error)
          }
        )
        connectionKey = nextConnectionKey
      } else {
        await connection?.updateHandlers(
          eventHandler: { [weak self] event in
            await self?.handle(event)
          },
          authTokenProvider: authTokenProvider,
          disconnectionHandler: { [weak self] error in
            await self?.handleConnectionFailure(error)
          }
        )
        await connection?.updateRemoteControlToken(remoteToken, expiresAt: session.remoteControlExpiresAt)
      }

      guard let connection else {
        throw CodexAppServerError.notConnected
      }

      try await connection.connectIfNeeded()
      let page = try await connection.listThreads(limit: 50)
      let threads = page.data
      chats = threads.map(preview)
      projects = Self.projects(from: chats)
      models = (try? await connection.listModels()) ?? models
      connectionState = .ready(environment.displayName)
    } catch {
      chats = []
      projects = []
      errorMessage = error.localizedDescription
      connectionState = .failed(error.localizedDescription)
    }
  }

  func loadChat(_ chat: CodexChatPreview) async {
    guard let connection else {
      errorMessage = CodexAppServerError.notConnected.localizedDescription
      return
    }

    isLoadingChat = true
    errorMessage = nil
    defer { isLoadingChat = false }

    do {
      let detail = try await connection.readThread(threadID: chat.id)
      activeChat = detail.withFallback(preview: chat)
      markRead(chat)
      petState = detail.isStreaming ? .thinking : .idle
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  func loadOlderTurns() async {
    guard
      let connection,
      let detail = activeChat,
      let cursor = detail.nextTurnCursor
    else {
      return
    }

    isLoadingChat = true
    defer { isLoadingChat = false }

    do {
      let page = try await connection.listThreadTurns(threadID: detail.id, limit: 20, cursor: cursor)
      let older = CodexChatNormalizer.messages(fromTurns: page.turns)
      activeChat?.messages.insert(contentsOf: older, at: 0)
      activeChat?.nextTurnCursor = page.nextCursor
      activeChat?.backwardsTurnCursor = page.backwardsCursor
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  @discardableResult
  func startChat(cwd: String?, model: String?) async throws -> CodexChatPreview {
    guard let connection else {
      throw CodexAppServerError.notConnected
    }
    let thread = try await connection.startThread(cwd: cwd, model: model)
    let preview = preview(from: thread)
    markRead(preview)
    upsert(chat: preview)
    projects = Self.projects(from: chats)
    activeChat = CodexChatDetail(
      id: preview.id,
      title: preview.title,
      projectName: preview.projectName,
      projectPath: preview.projectPath,
      messages: [],
      nextTurnCursor: nil,
      backwardsTurnCursor: nil,
      activeTurnID: nil,
      isStreaming: false
    )
    return preview
  }

  func archiveChat(_ chat: CodexChatPreview) async {
    guard let connection else {
      errorMessage = CodexAppServerError.notConnected.localizedDescription
      return
    }

    let previousChats = chats
    let previousProjects = projects
    chats.removeAll { $0.id == chat.id }
    projects = Self.projects(from: chats)
    if activeChat?.id == chat.id {
      activeChat = nil
      petState = .idle
    }

    do {
      try await connection.archiveThread(threadID: chat.id)
      pinnedChatIDs.remove(chat.id)
      persistPinnedChatIDs()
    } catch {
      chats = previousChats
      projects = previousProjects
      errorMessage = error.localizedDescription
    }
  }

  func togglePinned(_ chat: CodexChatPreview) {
    if pinnedChatIDs.contains(chat.id) {
      pinnedChatIDs.remove(chat.id)
    } else {
      pinnedChatIDs.insert(chat.id)
    }
    persistPinnedChatIDs()

    let isPinned = pinnedChatIDs.contains(chat.id)
    updateChat(id: chat.id) { preview in
      preview.isPinned = isPinned
    }
  }

  @discardableResult
  func sendMessage(text: String, threadID: String?, cwd: String? = nil, model: String? = nil) async throws -> String? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      return nil
    }

    let optimisticThreadID = threadID ?? activeChat?.id ?? "local-thread-\(UUID().uuidString)"
    prepareOptimisticSend(text: trimmed, threadID: optimisticThreadID, cwd: cwd)
    log("send optimistic thread=\(short(optimisticThreadID)) existing=\(threadID != nil) cwd=\(short(cwd)) model=\(short(model)) chars=\(trimmed.count)")

    return try await performRemoteSendMessage(
      text: trimmed,
      optimisticThreadID: optimisticThreadID,
      existingThreadID: threadID,
      cwd: cwd,
      model: model
    )
  }

  private func performRemoteSendMessage(
    text: String,
    optimisticThreadID: String,
    existingThreadID: String?,
    cwd: String?,
    model: String?
  ) async throws -> String {
    do {
      guard let connection else {
        throw CodexAppServerError.notConnected
      }

      let targetThreadID: String
      if let threadID = existingThreadID {
        targetThreadID = threadID
      } else {
        log("send create thread start pending=\(short(optimisticThreadID)) cwd=\(short(cwd)) model=\(short(model))")
        let thread = try await connection.startThread(cwd: cwd, model: model)
        let preview = preview(from: thread)
        replaceOptimisticThread(optimisticThreadID, with: preview)
        targetThreadID = preview.id
        log("send create thread success pending=\(short(optimisticThreadID)) thread=\(short(targetThreadID))")
      }

      ensureActiveChat(threadID: targetThreadID)
      petState = .thinking
      activeChat?.isStreaming = true
      log("send turn start thread=\(short(targetThreadID)) chars=\(text.count)")
      _ = try await connection.startTurn(threadID: targetThreadID, text: text)
      markOptimisticMessages(threadID: targetThreadID, state: .sent)
      log("send turn accepted thread=\(short(targetThreadID))")
      return targetThreadID
    } catch {
      errorMessage = error.localizedDescription
      petState = .failed
      activeChat?.isStreaming = false
      updateChat(id: activeChat?.id ?? existingThreadID ?? optimisticThreadID) { preview in
        preview.isActive = false
      }
      markOptimisticMessages(
        threadID: activeChat?.id ?? existingThreadID ?? optimisticThreadID,
        state: .failed(error.localizedDescription)
      )
      log("send failed pending=\(short(optimisticThreadID)) existing=\(short(existingThreadID)) error=\(error.localizedDescription)")
      throw error
    }
  }

  func interruptActiveTurn() async {
    guard
      let connection,
      let threadID = activeChat?.id,
      let turnID = activeChat?.activeTurnID
    else {
      return
    }

    do {
      try await connection.interruptTurn(threadID: threadID, turnID: turnID)
      activeChat?.isStreaming = false
      petState = .idle
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  func readFile(path: String) async -> String? {
    guard let connection else {
      errorMessage = CodexAppServerError.notConnected.localizedDescription
      return nil
    }

    do {
      return try await connection.readFile(path: path)
    } catch {
      errorMessage = error.localizedDescription
      return nil
    }
  }

  func performCatalogRPC(method: String, params: CodexJSONValue) async throws -> CodexJSONValue {
    guard let connection else {
      throw CodexAppServerError.notConnected
    }
    return try await connection.call(method: method, params: params)
  }

  private func handle(_ event: CodexAppServerEvent) async {
    guard let params = event.params.objectValue else {
      log("event ignored method=\(event.method) reason=params-not-object")
      return
    }
    let threadID = eventString(params, keys: ["threadId", "thread_id", "threadID"])
    log("event method=\(event.method) thread=\(short(threadID)) active=\(short(activeChat?.id))")

    if event.method == "thread/archived", let threadID {
      chats.removeAll { $0.id == threadID }
      projects = Self.projects(from: chats)
      return
    }

    guard threadID == nil || threadID == activeChat?.id else {
      applyBackgroundEvent(event, threadID: threadID, params: params)
      return
    }

    switch event.method {
    case "turn/started":
      let turnObject = params["turn"]?.objectValue
      activeChat?.activeTurnID = turnObject.flatMap { eventString($0, keys: ["id", "turnId", "turn_id"]) }
        ?? eventString(params, keys: ["turnId", "turn_id"])
      activeChat?.isStreaming = true
      petState = .thinking
    case "turn/completed":
      activeChat?.activeTurnID = nil
      activeChat?.isStreaming = false
      petState = .review
      if let turn = params["turn"] {
        merge(turn: turn)
      }
    case "item/started", "item/completed":
      if let item = params["item"] {
        merge(item: item)
      }
      petState = event.method == "item/completed" ? .review : .running
    case "item/agentMessage/delta":
      appendDelta(
        id: eventString(params, keys: ["itemId", "item_id"]) ?? UUID().uuidString,
        text: params["delta"]?.stringValue ?? "",
        role: .assistant,
        part: .text
      )
      petState = .running
    case "item/reasoning/textDelta", "item/reasoning/summaryTextDelta", "item/plan/delta":
      appendDelta(
        id: eventString(params, keys: ["itemId", "item_id"]) ?? UUID().uuidString,
        text: params["delta"]?.stringValue ?? "",
        role: .assistant,
        part: event.method == "item/plan/delta" ? .plan : .reasoning
      )
      petState = .thinking
    case "turn/plan/updated":
      mergePlan(params)
      petState = .thinking
    case "turn/diff/updated":
      if let diff = params["diff"]?.stringValue, !diff.isEmpty {
        merge(item: .object([
          "id": .string("diff-\(params["turnId"]?.stringValue ?? UUID().uuidString)"),
          "type": .string("fileChange"),
          "status": .string("inProgress"),
          "changes": .array([.object(["path": .string("Working diff"), "diff": .string(diff)])]),
        ]))
      }
    case "error", "warning", "guardianWarning", "serverRequest/resolved":
      if let text = params["message"]?.stringValue ?? params["title"]?.stringValue {
        appendSystemMessage(text: text, threadID: activeChat?.id)
      }
      if event.method == "error" {
        petState = .failed
      }
    default:
      break
    }
  }

  private func applyBackgroundEvent(_ event: CodexAppServerEvent, threadID: String?, params: [String: CodexJSONValue]) {
    guard let threadID else {
      return
    }

    let previewText = params["delta"]?.stringValue
      ?? params["message"]?.stringValue
      ?? params["title"]?.stringValue
    let isActiveEvent = [
      "turn/started",
      "item/started",
      "item/agentMessage/delta",
      "item/reasoning/textDelta",
      "item/reasoning/summaryTextDelta",
      "item/plan/delta",
      "turn/plan/updated",
      "turn/diff/updated",
    ].contains(event.method)
    let isCompletedEvent = event.method == "turn/completed" || event.method == "item/completed"

    updateChat(id: threadID) { preview in
      if isActiveEvent {
        preview.isActive = true
      } else if isCompletedEvent || event.method == "error" {
        preview.isActive = false
      }
      preview.isUnread = true
      preview.updatedAt = .now
      if let previewText = previewText?.nonEmptyPreviewTitle {
        preview.summary = previewText
      }
    }
    log("event applied to background thread method=\(event.method) thread=\(short(threadID))")
  }

  private func eventString(_ object: [String: CodexJSONValue], keys: [String]) -> String? {
    for key in keys {
      if let value = object[key]?.stringValue, !value.isEmpty {
        return value
      }
    }
    return nil
  }

  private func selectedEnvironment(from environments: [CodexEnvironment], preferredEnvironmentID: String?) -> CodexEnvironment? {
    let onlineEnvironments = environments.filter(\.online)
    if let preferredEnvironmentID, let preferred = onlineEnvironments.first(where: { $0.envID == preferredEnvironmentID }) {
      return preferred
    }
    return onlineEnvironments.first
  }

  func disconnect() {
    let connection = connection
    self.connection = nil
    connectionKey = nil
    chats = []
    projects = []
    activeChat = nil
    errorMessage = nil
    connectionState = .disconnected
    petState = .idle
    Task {
      await connection?.close()
    }
  }

  private func handleConnectionFailure(_ error: Error) {
    errorMessage = error.localizedDescription
    connectionState = .failed(error.localizedDescription)
    activeChat?.isStreaming = false
    petState = .failed
  }

  static func projects(from chats: [CodexChatPreview]) -> [CodexProjectPreview] {
    Dictionary(grouping: chats.compactMap { chat -> (path: String, chat: CodexChatPreview)? in
      guard let path = normalizedProjectPath(chat.projectPath) else {
        return nil
      }
      return (path, chat)
    }, by: \.path)
      .map { path, entries -> (project: CodexProjectPreview, latest: Date) in
        let chats = entries.map(\.chat)
        let projectName = URL(fileURLWithPath: path).lastPathComponent.nonEmptyPreviewTitle ?? chats.first?.projectName ?? path
        return (
          CodexProjectPreview(id: path, name: projectName, path: path, chatCount: chats.count),
          chats.map(\.updatedAt).max() ?? .distantPast
        )
      }
      .sorted { lhs, rhs in
        if lhs.latest != rhs.latest {
          return lhs.latest > rhs.latest
        }
        return lhs.project.name.localizedCaseInsensitiveCompare(rhs.project.name) == .orderedAscending
      }
      .map(\.project)
  }

  static func normalizedProjectPath(_ rawPath: String?) -> String? {
    guard let rawPath else {
      return nil
    }

    let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed != ".", trimmed != "/" else {
      return nil
    }
    return trimmed
  }

  private func upsert(chat: CodexChatPreview) {
    chats.removeAll { $0.id == chat.id }
    chats.insert(chat, at: 0)
  }

  private func updateChat(id: String, update: (inout CodexChatPreview) -> Void) {
    guard let index = chats.firstIndex(where: { $0.id == id }) else {
      return
    }
    update(&chats[index])
    projects = Self.projects(from: chats)
  }

  private func markRead(_ chat: CodexChatPreview) {
    readTimestampsByChatID[chat.id] = max(Date().timeIntervalSince1970, chat.updatedAt.timeIntervalSince1970)
    persistReadTimestamps()
    updateChat(id: chat.id) { preview in
      preview.isUnread = false
    }
  }

  private func preview(from thread: CodexThreadSummary) -> CodexChatPreview {
    CodexChatPreview(
      thread: thread,
      isPinned: pinnedChatIDs.contains(thread.id),
      isUnread: isUnread(thread)
    )
  }

  private func isUnread(_ thread: CodexThreadSummary) -> Bool {
    if let explicitUnread = thread.explicitUnreadState {
      return explicitUnread
    }
    guard let readAt = readTimestampsByChatID[thread.id] else {
      return false
    }
    return thread.updatedAtDate.timeIntervalSince1970 > readAt
  }

  private static let pinnedChatIDsKey = "codex.chat.pinned.ids.v1"
  private static let readTimestampsKey = "codex.chat.read.timestamps.v1"

  private static func loadPinnedChatIDs(from userDefaults: UserDefaults) -> Set<String> {
    Set(userDefaults.stringArray(forKey: pinnedChatIDsKey) ?? [])
  }

  private static func loadReadTimestamps(from userDefaults: UserDefaults) -> [String: TimeInterval] {
    let raw = userDefaults.dictionary(forKey: readTimestampsKey) ?? [:]
    return raw.reduce(into: [:]) { result, entry in
      if let timestamp = entry.value as? TimeInterval {
        result[entry.key] = timestamp
      } else if let number = entry.value as? NSNumber {
        result[entry.key] = number.doubleValue
      }
    }
  }

  private func persistPinnedChatIDs() {
    userDefaults.set(Array(pinnedChatIDs).sorted(), forKey: Self.pinnedChatIDsKey)
  }

  private func persistReadTimestamps() {
    userDefaults.set(readTimestampsByChatID, forKey: Self.readTimestampsKey)
  }

  private func prepareOptimisticSend(text: String, threadID: String, cwd: String?) {
    let title = text.nonEmptyPreviewTitle ?? "New chat"
    if !chats.contains(where: { $0.id == threadID }) {
      let projectName = cwd.map { URL(fileURLWithPath: $0).lastPathComponent }.flatMap(\.nonEmptyPreviewTitle) ?? "No project"
      upsert(chat: CodexChatPreview(
        id: threadID,
        title: title,
        projectName: projectName,
        projectPath: cwd,
        summary: title,
        isPinned: false,
        isUnread: false,
        isActive: true,
        updatedAt: .now
      ))
      projects = Self.projects(from: chats)
    } else {
      updateChat(id: threadID) { preview in
        preview.summary = title
        preview.isActive = true
        preview.updatedAt = .now
      }
    }

    ensureActiveChat(threadID: threadID)
    if activeChat == nil {
      activeChat = CodexChatDetail(
        id: threadID,
        title: title,
        projectName: cwd.map { URL(fileURLWithPath: $0).lastPathComponent }.flatMap(\.nonEmptyPreviewTitle) ?? "No project",
        projectPath: cwd,
        messages: [],
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: nil,
        isStreaming: false
      )
    }
    appendUserMessage(text: text, threadID: threadID)
    petState = .thinking
    activeChat?.isStreaming = true
  }

  private func replaceOptimisticThread(_ optimisticThreadID: String, with preview: CodexChatPreview) {
    chats.removeAll { $0.id == optimisticThreadID || $0.id == preview.id }
    chats.insert(preview, at: 0)
    markRead(preview)

    if activeChat?.id == optimisticThreadID {
      activeChat?.id = preview.id
      activeChat?.title = preview.title
      activeChat?.projectName = preview.projectName
      activeChat?.projectPath = preview.projectPath
    } else if activeChat?.id == nil {
      activeChat = CodexChatDetail(
        id: preview.id,
        title: preview.title,
        projectName: preview.projectName,
        projectPath: preview.projectPath,
        messages: [],
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: nil,
        isStreaming: true
      )
    }

    projects = Self.projects(from: chats)
  }

  private func appendUserMessage(text: String, threadID: String) {
    ensureActiveChat(threadID: threadID)
    activeChat?.messages.append(
      CodexChatMessage(
        id: "local-user-\(UUID().uuidString)",
        role: .user,
        parts: [.text(id: "local-user-text-\(UUID().uuidString)", text)],
        deliveryState: .sending
      )
    )
  }

  private func markOptimisticMessages(threadID: String, state: CodexChatMessage.DeliveryState) {
    guard activeChat?.id == threadID, let indices = activeChat?.messages.indices else {
      return
    }
    for index in indices {
      guard activeChat?.messages[index].id.hasPrefix("local-user-") == true else {
        continue
      }
      if activeChat?.messages[index].deliveryState == .sending {
        activeChat?.messages[index].deliveryState = state
      }
    }
  }

  private func appendSystemMessage(text: String, threadID: String?) {
    guard let threadID else {
      return
    }
    ensureActiveChat(threadID: threadID)
    activeChat?.messages.append(
      CodexChatMessage(
        id: "system-\(UUID().uuidString)",
        role: .system,
        parts: [.text(id: "system-text-\(UUID().uuidString)", text)]
      )
    )
  }

  private enum StreamingPartKind {
    case text
    case reasoning
    case plan
  }

  private func appendDelta(id: String, text: String, role: CodexChatMessage.Role, part: StreamingPartKind) {
    guard !text.isEmpty else {
      return
    }
    ensureActiveChat(threadID: activeChat?.id)

    let messageID = "stream-\(id)"
    if let messageIndex = activeChat?.messages.firstIndex(where: { $0.id == messageID }) {
      appendText(text, toPartWithID: id, messageIndex: messageIndex, kind: part)
    } else {
      activeChat?.messages.append(
        CodexChatMessage(
          id: messageID,
          role: role,
          parts: [makeStreamingPart(id: id, text: text, kind: part)]
        )
      )
    }
  }

  private func appendText(_ text: String, toPartWithID id: String, messageIndex: Int, kind: StreamingPartKind) {
    guard var message = activeChat?.messages[messageIndex] else {
      return
    }
    if let partIndex = message.parts.firstIndex(where: { $0.id == id }) {
      switch message.parts[partIndex] {
      case .text(let partID, let existing):
        message.parts[partIndex] = .text(id: partID, existing + text)
      case .reasoning(let partID, let existing):
        message.parts[partIndex] = .reasoning(id: partID, existing + text)
      case .todos:
        let existing = message.parts[partIndex].plainText
        message.parts[partIndex] = .todos(id: id, CodexChatNormalizer.todos(from: existing + text))
      default:
        break
      }
    } else {
      message.parts.append(makeStreamingPart(id: id, text: text, kind: kind))
    }
    activeChat?.messages[messageIndex] = message
  }

  private func makeStreamingPart(id: String, text: String, kind: StreamingPartKind) -> CodexMessagePart {
    switch kind {
    case .text:
      .text(id: id, text)
    case .reasoning:
      .reasoning(id: id, text)
    case .plan:
      .todos(id: id, CodexChatNormalizer.todos(from: text))
    }
  }

  private func ensureActiveChat(threadID: String?) {
    guard let threadID else {
      return
    }
    if activeChat?.id == threadID {
      return
    }
    if let chat = chats.first(where: { $0.id == threadID }) {
      activeChat = CodexChatDetail(
        id: chat.id,
        title: chat.title,
        projectName: chat.projectName,
        projectPath: chat.projectPath,
        messages: [],
        nextTurnCursor: nil,
        backwardsTurnCursor: nil,
        activeTurnID: nil,
        isStreaming: false
      )
    }
  }

  private func log(_ message: String) {
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      NSLog("[Codex workspace] %@", message)
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

  private func merge(turn: CodexJSONValue) {
    guard let object = turn.objectValue, let items = object["items"]?.arrayValue else {
      return
    }
    for item in items {
      merge(item: item)
    }
  }

  private func merge(item: CodexJSONValue) {
    let messages = CodexChatNormalizer.messages(fromItems: [item])
    for message in messages {
      if let index = activeChat?.messages.firstIndex(where: { $0.id == message.id || $0.id == "stream-\(message.id)" }) {
        activeChat?.messages[index] = message
      } else if let index = activeChat?.messages.firstIndex(where: { $0.isOptimisticDuplicate(of: message) }) {
        activeChat?.messages[index] = message
      } else {
        activeChat?.messages.append(message)
      }
    }
  }

  private func mergePlan(_ params: [String: CodexJSONValue]) {
    guard let plan = params["plan"]?.arrayValue else {
      return
    }
    let items = plan.enumerated().map { index, value -> CodexTodoItem in
      let object = value.objectValue ?? [:]
      return CodexTodoItem(
        id: object["id"]?.stringValue ?? "plan-\(index)",
        title: object["step"]?.stringValue ?? object["text"]?.stringValue ?? value.description,
        status: object["status"]?.stringValue ?? "pending"
      )
    }
    let partID = "plan-\(params["turnId"]?.stringValue ?? "active")"
    let message = CodexChatMessage(
      id: partID,
      role: .assistant,
      parts: [.todos(id: partID, items)]
    )
    activeChat?.messages.removeAll { $0.id == partID }
    activeChat?.messages.append(message)
  }
}

private extension CodexChatPreview {
  init(thread: CodexThreadSummary, isPinned: Bool, isUnread: Bool) {
    let projectPath = thread.cwd?.isEmpty == false ? thread.cwd : nil
    let resolvedProjectName = projectPath.map { URL(fileURLWithPath: $0).lastPathComponent }
    let projectName = resolvedProjectName?.isEmpty == false ? resolvedProjectName! : "Projectless"
    let fallbackTitle = thread.preview?.trimmingCharacters(in: .whitespacesAndNewlines)
      .nonEmptyPreviewTitle ?? "Untitled chat"

    self.id = thread.id
    self.title = thread.name?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmptyPreviewTitle ?? fallbackTitle
    self.projectName = projectName
    self.projectPath = projectPath
    self.summary = thread.preview?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmptyPreviewTitle ?? "No preview"
    self.isPinned = isPinned
    self.isUnread = isUnread
    self.isActive = thread.isActive
    self.updatedAt = thread.updatedAtDate
  }
}

private extension CodexThreadSummary {
  var isActive: Bool {
    guard let rawStatus = status?.codexStatusString else {
      return false
    }

    let normalized = rawStatus
      .replacingOccurrences(of: "_", with: "-")
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()

    return [
      "active",
      "in-progress",
      "pending",
      "queued",
      "running",
      "thinking",
      "working",
    ].contains(normalized)
  }
}

private extension String {
  var nonEmptyPreviewTitle: String? {
    let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      return nil
    }
    return String(trimmed.prefix(120))
  }
}

private extension CodexChatDetail {
  func withFallback(preview: CodexChatPreview) -> CodexChatDetail {
    CodexChatDetail(
      id: id,
      title: title.nonEmptyPreviewTitle ?? preview.title,
      projectName: projectName.nonEmptyPreviewTitle ?? preview.projectName,
      projectPath: projectPath ?? preview.projectPath,
      messages: messages,
      nextTurnCursor: nextTurnCursor,
      backwardsTurnCursor: backwardsTurnCursor,
      activeTurnID: activeTurnID,
      isStreaming: isStreaming
    )
  }
}

private extension CodexChatMessage {
  var plainText: String {
    parts.map(\.plainText)
      .joined(separator: "\n")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  func isOptimisticDuplicate(of remoteMessage: CodexChatMessage) -> Bool {
    role == .user
      && remoteMessage.role == .user
      && id.hasPrefix("local-user-")
      && plainText == remoteMessage.plainText
  }
}

struct CodexThreadPage {
  var data: [CodexThreadSummary]
  var nextCursor: String?
  var backwardsCursor: String?
}

struct CodexThreadTurnsPage {
  var turns: [CodexJSONValue]
  var nextCursor: CodexThreadTurnsCursor?
  var backwardsCursor: CodexThreadTurnsCursor?
}

enum CodexChatNormalizer {
  static func detail(fromThreadReadResponse response: CodexJSONValue) throws -> CodexChatDetail {
    let thread = try threadValue(fromRPCResponse: response)
    guard let object = thread.objectValue else {
      throw CodexAppServerError.invalidWebSocketMessage("thread/read returned no thread")
    }

    let id = object["id"]?.stringValue ?? UUID().uuidString
    let cwd = object["cwd"]?.stringValue
    let projectName = cwd.map { URL(fileURLWithPath: $0).lastPathComponent }.flatMap(\.nonEmptyPreviewTitle) ?? "Projectless"
    let turns = object["turns"]?.arrayValue ?? []
    let status = object["status"]?.stringValue ?? ""
    let activeTurn = turns.last?.objectValue?["id"]?.stringValue
    return CodexChatDetail(
      id: id,
      title: object["name"]?.stringValue?.nonEmptyPreviewTitle
        ?? object["preview"]?.stringValue?.nonEmptyPreviewTitle
        ?? "Untitled chat",
      projectName: projectName,
      projectPath: cwd,
      messages: messages(fromTurns: turns),
      nextTurnCursor: nil,
      backwardsTurnCursor: nil,
      activeTurnID: status == "running" ? activeTurn : nil,
      isStreaming: status == "running"
    )
  }

  static func turnsPage(fromResponse response: CodexJSONValue) throws -> CodexThreadTurnsPage {
    let result = response.objectValue?["result"]?.objectValue ?? [:]
    let next = result["nextCursor"]?.stringValue.flatMap(CodexThreadTurnsCursor.init(rawValue:))
    let backwards = result["backwardsCursor"]?.stringValue.flatMap(CodexThreadTurnsCursor.init(rawValue:))
    return CodexThreadTurnsPage(
      turns: result["data"]?.arrayValue ?? [],
      nextCursor: next,
      backwardsCursor: backwards
    )
  }

  static func threadValue(fromRPCResponse response: CodexJSONValue) throws -> CodexJSONValue {
    guard let thread = response.objectValue?["result"]?.objectValue?["thread"] else {
      throw CodexAppServerError.invalidWebSocketMessage("response returned no thread")
    }
    return thread
  }

  static func fileText(fromResponse response: CodexJSONValue) throws -> String {
    let result = response.objectValue?["result"]?.objectValue ?? [:]
    if let text = result["content"]?.stringValue ?? result["text"]?.stringValue {
      return text
    }
    if let data = result["data"]?.stringValue {
      return data
    }
    return response.description
  }

  static func models(fromResponse response: CodexJSONValue) throws -> [CodexModelOption] {
    let data = response.objectValue?["result"]?.objectValue?["data"]?.arrayValue ?? []
    return data.compactMap { value in
      guard let object = value.objectValue else {
        return nil
      }
      let id = object["id"]?.stringValue ?? object["model"]?.stringValue ?? ""
      guard !id.isEmpty else {
        return nil
      }
      return CodexModelOption(
        id: id,
        displayName: object["displayName"]?.stringValue ?? object["model"]?.stringValue ?? id,
        detail: object["description"]?.stringValue ?? "",
        isDefault: object["isDefault"]?.boolValue ?? false
      )
    }
  }

  static func messages(fromTurns turns: [CodexJSONValue]) -> [CodexChatMessage] {
    turns.flatMap { turn -> [CodexChatMessage] in
      let items = turn.objectValue?["items"]?.arrayValue ?? []
      return messages(fromItems: items)
    }
  }

  static func messages(fromItems items: [CodexJSONValue]) -> [CodexChatMessage] {
    items.compactMap(message(fromItem:))
  }

  static func todos(from text: String) -> [CodexTodoItem] {
    text.split(separator: "\n").enumerated().compactMap { index, line in
      let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmed.isEmpty else {
        return nil
      }
      let done = trimmed.hasPrefix("- [x]") || trimmed.hasPrefix("[x]")
      let pending = trimmed
        .replacingOccurrences(of: "- [x]", with: "")
        .replacingOccurrences(of: "- [ ]", with: "")
        .replacingOccurrences(of: "[x]", with: "")
        .replacingOccurrences(of: "[ ]", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return CodexTodoItem(
        id: "todo-\(index)-\(pending)",
        title: pending,
        status: done ? "completed" : "pending"
      )
    }
  }

  private static func message(fromItem item: CodexJSONValue) -> CodexChatMessage? {
    guard let object = item.objectValue else {
      return nil
    }
    let type = object["type"]?.stringValue ?? "item"
    let id = object["id"]?.stringValue ?? "\(type)-\(UUID().uuidString)"

    switch type {
    case "userMessage":
      let text = userText(from: object["content"]?.arrayValue ?? [])
      guard !text.isEmpty else {
        return nil
      }
      return CodexChatMessage(id: id, role: .user, parts: [.text(id: "\(id)-text", text)])

    case "agentMessage":
      let text = object["text"]?.stringValue ?? ""
      guard !text.isEmpty else {
        return nil
      }
      return CodexChatMessage(id: id, role: .assistant, parts: [.text(id: "\(id)-text", text)])

    case "reasoning":
      let content = stringArray(object["summary"]) + stringArray(object["content"])
      let text = content.joined(separator: "\n")
      guard !text.isEmpty else {
        return nil
      }
      return CodexChatMessage(id: id, role: .assistant, parts: [.reasoning(id: "\(id)-reasoning", text)])

    case "plan":
      let text = object["text"]?.stringValue ?? ""
      return CodexChatMessage(id: id, role: .assistant, parts: [.todos(id: "\(id)-todos", todos(from: text))])

    case "commandExecution":
      let command = object["command"]?.stringValue ?? "Command"
      let output = object["aggregatedOutput"]?.stringValue ?? ""
      let status = object["status"]?.stringValue ?? "running"
      return CodexChatMessage(
        id: id,
        role: .assistant,
        parts: [
          .tool(CodexToolRun(id: id, name: command, status: status, detail: output.nonEmptyPreviewTitle ?? command)),
        ]
      )

    case "fileChange":
      let status = object["status"]?.stringValue ?? "changed"
      let files = (object["changes"]?.arrayValue ?? []).enumerated().map { index, value in
        let change = value.objectValue ?? [:]
        let diff = change["diff"]?.stringValue
        return CodexFilePreview(
          id: "\(id)-file-\(index)",
          path: change["path"]?.stringValue ?? change["file"]?.stringValue ?? "File change",
          detail: diff?.nonEmptyPreviewTitle ?? status,
          diff: diff
        )
      }
      guard !files.isEmpty else {
        return nil
      }
      let group = CodexFileChangeGroup(id: id, status: status, files: files)
      return CodexChatMessage(id: id, role: .assistant, parts: [.fileGroup(group)])

    case "mcpToolCall", "dynamicToolCall", "collabAgentToolCall":
      let tool = object["tool"]?.stringValue ?? type
      let status = object["status"]?.stringValue ?? "running"
      return CodexChatMessage(
        id: id,
        role: .assistant,
        parts: [
          .tool(CodexToolRun(id: id, name: tool, status: status, detail: item.description)),
        ]
      )

    case "webSearch":
      let query = object["query"]?.stringValue ?? "Web search"
      return CodexChatMessage(
        id: id,
        role: .assistant,
        parts: [
          .tool(CodexToolRun(id: id, name: "Web search", status: "completed", detail: query)),
        ]
      )

    case "imageView":
      let path = object["path"]?.stringValue ?? "Image"
      return CodexChatMessage(id: id, role: .assistant, parts: [.file(CodexFilePreview(id: id, path: path, detail: "Image"))])

    default:
      return nil
    }
  }

  private static func userText(from content: [CodexJSONValue]) -> String {
    content.compactMap { value -> String? in
      guard let object = value.objectValue else {
        return value.stringValue
      }
      if let text = object["text"]?.stringValue {
        return text
      }
      if let path = object["path"]?.stringValue {
        return "[Image] \(path)"
      }
      if let url = object["url"]?.stringValue {
        return "[Image] \(url)"
      }
      return nil
    }
    .joined(separator: "\n")
    .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private static func stringArray(_ value: CodexJSONValue?) -> [String] {
    value?.arrayValue?.compactMap(\.stringValue) ?? []
  }
}

enum CodexAppServerError: LocalizedError {
  case notConnected
  case missingWebSocketChallenge
  case invalidWebSocketMessage(String)
  case rpcError(String)
  case rpcTimeout(String)

  var errorDescription: String? {
    switch self {
    case .notConnected:
      return "Codex chat transport is not connected."
    case .missingWebSocketChallenge:
      return "Codex websocket did not provide a device-key challenge."
    case .invalidWebSocketMessage(let message):
      return "Invalid Codex websocket message: \(message)"
    case .rpcError(let message):
      return message
    case .rpcTimeout(let method):
      return "Codex request timed out: \(method)"
    }
  }
}

actor CodexRemoteAppServerConnection {
  private let environmentID: String
  private let clientID: String
  private let accountID: String?
  private let deviceKey: CodexDeviceKey
  private var eventHandler: (@Sendable (CodexAppServerEvent) async -> Void)?
  private var authTokenProvider: (@Sendable () async throws -> CodexAppServerAuthTokens)?
  private var remoteControlToken: String
  private var tokenExpiresAt: Date?
  private var webSocketTask: URLSessionWebSocketTask?
  private var receiveTask: Task<Void, Never>?
  private var initialized = false
  private var isConnecting = false
  private var connectWaiters: [CheckedContinuation<Void, Error>] = []
  private var streamID = UUID().uuidString
  private var nextSeqID = 1
  private var nextRequestID = 1
  private var pendingResponses: [String: CheckedContinuation<CodexJSONValue, Error>] = [:]
  private var pendingMethodsByID: [String: String] = [:]
  private var pendingRequestIDs: [String] = []
  private var serverSeqID: Int?
  private var chunkAssembler = CodexRemoteChunkAssembler()
  private var reconnectAfter: Date?
  private let requestTimeoutNanoseconds: UInt64
  private var disconnectionHandler: (@Sendable (Error) async -> Void)?

  init(
    environmentID: String,
    clientID: String,
    accountID: String?,
    remoteControlToken: String,
    tokenExpiresAt: Date?,
    deviceKey: CodexDeviceKey,
    eventHandler: (@Sendable (CodexAppServerEvent) async -> Void)? = nil,
    authTokenProvider: (@Sendable () async throws -> CodexAppServerAuthTokens)? = nil,
    disconnectionHandler: (@Sendable (Error) async -> Void)? = nil,
    requestTimeoutNanoseconds: UInt64 = 30_000_000_000
  ) {
    self.environmentID = environmentID
    self.clientID = clientID
    self.accountID = accountID
    self.remoteControlToken = remoteControlToken
    self.tokenExpiresAt = tokenExpiresAt
    self.deviceKey = deviceKey
    self.eventHandler = eventHandler
    self.authTokenProvider = authTokenProvider
    self.disconnectionHandler = disconnectionHandler
    self.requestTimeoutNanoseconds = requestTimeoutNanoseconds
  }

  func updateRemoteControlToken(_ token: String, expiresAt: Date?) {
    remoteControlToken = token
    tokenExpiresAt = expiresAt
  }

  func updateHandlers(
    eventHandler: (@Sendable (CodexAppServerEvent) async -> Void)?,
    authTokenProvider: (@Sendable () async throws -> CodexAppServerAuthTokens)?,
    disconnectionHandler: (@Sendable (Error) async -> Void)?
  ) {
    self.eventHandler = eventHandler
    self.authTokenProvider = authTokenProvider
    self.disconnectionHandler = disconnectionHandler
  }

  func connectIfNeeded() async throws {
    if webSocketTask != nil, initialized {
      return
    }
    if isConnecting {
      log("connect wait existing env=\(short(environmentID))")
      try await withCheckedThrowingContinuation { continuation in
        connectWaiters.append(continuation)
      }
      return
    }

    isConnecting = true
    defer {
      isConnecting = false
    }
    if let reconnectAfter, reconnectAfter > Date() {
      let delay = reconnectAfter.timeIntervalSinceNow
      log("connect backoff delay=\(String(format: "%.2f", delay))s env=\(short(environmentID))")
      try await Task.sleep(nanoseconds: UInt64(max(0, delay) * 1_000_000_000))
    }
    reconnectAfter = nil
    log("connect start env=\(short(environmentID)) client=\(short(clientID)) tokenExpires=\(expiryText(tokenExpiresAt))")
    do {
      try await openWebSocket()
      try await initializeAppServer()
      log("connect ready env=\(short(environmentID))")
      let waiters = connectWaiters
      connectWaiters = []
      for waiter in waiters {
        waiter.resume()
      }
    } catch {
      let waiters = connectWaiters
      connectWaiters = []
      for waiter in waiters {
        waiter.resume(throwing: error)
      }
      throw error
    }
  }

  func listThreads(limit: Int, cursor: String? = nil, cwd: String? = nil, searchTerm: String? = nil) async throws -> CodexThreadPage {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.listThreads(
        id: $0,
        limit: limit,
        cursor: cursor,
        cwd: cwd,
        searchTerm: searchTerm
      )
    }
    let rpcResponse = try CodexJSONCodec.decode(CodexRPCResponse<CodexThreadListResult>.self, from: response)
    return CodexThreadPage(
      data: rpcResponse.result.data,
      nextCursor: rpcResponse.result.nextCursor,
      backwardsCursor: rpcResponse.result.backwardsCursor
    )
  }

  func readThread(threadID: String) async throws -> CodexChatDetail {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readThread(id: $0, threadID: threadID, includeTurns: true)
    }
    return try CodexChatNormalizer.detail(fromThreadReadResponse: response)
  }

  func listThreadTurns(threadID: String, limit: Int, cursor: CodexThreadTurnsCursor?) async throws -> CodexThreadTurnsPage {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.listThreadTurns(id: $0, threadID: threadID, limit: limit, cursor: cursor)
    }
    return try CodexChatNormalizer.turnsPage(fromResponse: response)
  }

  func startThread(cwd: String?, model: String?) async throws -> CodexThreadSummary {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.startThread(id: $0, cwd: cwd, model: model)
    }
    let thread = try CodexChatNormalizer.threadValue(fromRPCResponse: response)
    return try CodexJSONCodec.decode(CodexThreadSummary.self, from: thread)
  }

  func startTurn(threadID: String, text: String, localImagePaths: [String] = []) async throws -> CodexJSONValue {
    try await connectIfNeeded()
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.startTurn(
        id: $0,
        threadID: threadID,
        text: text,
        localImagePaths: localImagePaths
      )
    }
  }

  func steerTurn(threadID: String, expectedTurnID: String, text: String) async throws {
    try await connectIfNeeded()
    _ = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.steerTurn(id: $0, threadID: threadID, expectedTurnID: expectedTurnID, text: text)
    }
  }

  func interruptTurn(threadID: String, turnID: String) async throws {
    try await connectIfNeeded()
    _ = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.interruptTurn(id: $0, threadID: threadID, turnID: turnID)
    }
  }

  func archiveThread(threadID: String) async throws {
    try await connectIfNeeded()
    _ = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.archiveThread(id: $0, threadID: threadID)
    }
  }

  func readFile(path: String) async throws -> String {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readFile(id: $0, path: path)
    }
    return try CodexChatNormalizer.fileText(fromResponse: response)
  }

  func readDirectory(path: String) async throws -> CodexJSONValue {
    try await connectIfNeeded()
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readDirectory(id: $0, path: path)
    }
  }

  func readFileMetadata(path: String) async throws -> CodexJSONValue {
    try await connectIfNeeded()
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readFileMetadata(id: $0, path: path)
    }
  }

  func listModels() async throws -> [CodexModelOption] {
    try await connectIfNeeded()
    let response = try await sendBuiltRequest {
      CodexAppServerRequestBuilder.listModels(id: $0)
    }
    return try CodexChatNormalizer.models(fromResponse: response)
  }

  func readAccount() async throws -> CodexJSONValue {
    try await connectIfNeeded()
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readAccount(id: $0)
    }
  }

  func readConfig(cwd: String?) async throws -> CodexJSONValue {
    try await connectIfNeeded()
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.readConfig(id: $0, cwd: cwd)
    }
  }

  func call(method: String, params: CodexJSONValue) async throws -> CodexJSONValue {
    try await connectIfNeeded()
    guard CodexRemoteAPICatalog.observedAppServerMethods.contains(method) else {
      throw CodexAppServerError.invalidWebSocketMessage("unknown app-server method \(method)")
    }
    return try await sendBuiltRequest {
      CodexAppServerRequestBuilder.request(id: $0, method: method, params: params)
    }
  }

  func close() {
    if webSocketTask != nil || !pendingResponses.isEmpty {
      log("close pending=\(pendingResponses.count)")
    }
    receiveTask?.cancel()
    receiveTask = nil
    webSocketTask?.cancel(with: .goingAway, reason: nil)
    webSocketTask = nil
    initialized = false
    pendingResponses.values.forEach { $0.resume(throwing: CodexAppServerError.notConnected) }
    pendingResponses = [:]
    pendingMethodsByID = [:]
    pendingRequestIDs = []
  }

  private func openWebSocket() async throws {
    close()

    var request = URLRequest(url: CodexRemoteConstants.webSocketURL)
    request.setValue("Bearer \(remoteControlToken)", forHTTPHeaderField: "x-codex-client-session-token")
    request.setValue(clientID, forHTTPHeaderField: "x-codex-client-id")
    request.setValue("3", forHTTPHeaderField: "x-codex-protocol-version")
    request.setValue(CodexRemoteConstants.originator, forHTTPHeaderField: "originator")
    request.setValue(CodexRemoteConstants.userAgent, forHTTPHeaderField: "User-Agent")

    let appServerAuthTokens: CodexAppServerAuthTokens?
    if let authTokenProvider {
      do {
        appServerAuthTokens = try await authTokenProvider()
      } catch {
        log("websocket normal auth header failed error=\(error.localizedDescription)")
        throw error
      }
    } else {
      appServerAuthTokens = nil
    }

    if let appServerAuthTokens {
      request.setValue("Bearer \(appServerAuthTokens.accessToken)", forHTTPHeaderField: "Authorization")
      request.setValue(appServerAuthTokens.chatgptAccountID, forHTTPHeaderField: "ChatGPT-Account-Id")
    } else if let accountID, !accountID.isEmpty {
      request.setValue(accountID, forHTTPHeaderField: "ChatGPT-Account-Id")
    }
    log("websocket open url=\(request.url?.absoluteString ?? "missing") headers=[authorization,account,client,protocol,originator,userAgent,session]")

    let task = URLSession.shared.webSocketTask(with: request)
    webSocketTask = task
    task.resume()

    let firstMessage: URLSessionWebSocketTask.Message?
    do {
      firstMessage = try await receiveMessage(timeoutNanoseconds: 10_000_000_000)
    } catch {
      log("websocket handshake failed error=\(error.localizedDescription)")
      throw CodexAppServerError.rpcError("Codex websocket handshake failed: \(error.localizedDescription)")
    }

    guard let firstMessage else {
      log("websocket handshake timed out waiting for challenge")
      throw CodexAppServerError.missingWebSocketChallenge
    }

    if let challenge = try? decodeWebSocketChallenge(from: firstMessage) {
      try validate(challenge: challenge)
      log("websocket challenge received session=\(short(challenge.sessionID)) scopes=\(challenge.scopes.joined(separator: ","))")
      let proof = try CodexDeviceProofBuilder.websocketProof(for: challenge, key: deviceKey)
      try await sendRaw(.object([
        "type": .string("device_key_proof"),
        "keyId": .string(proof.keyID),
        "signatureDerBase64": .string(proof.signatureDERBase64),
        "signedPayloadBase64": .string(proof.signedPayloadBase64),
        "algorithm": .string(proof.algorithm),
      ]))
      log("websocket challenge proof sent key=\(short(proof.keyID))")
    } else {
      log("websocket first frame was app-server envelope")
      try await handle(message: firstMessage)
    }

    receiveTask = Task { [weak self] in
      await self?.receiveLoop()
    }
  }

  private func initializeAppServer() async throws {
    guard !initialized else {
      return
    }

    streamID = UUID().uuidString
    nextSeqID = 1
    serverSeqID = nil
    pendingRequestIDs = []
    pendingMethodsByID = [:]
    chunkAssembler = CodexRemoteChunkAssembler()

    log("rpc initialize start stream=\(short(streamID))")
    _ = try await sendRequest(
      method: "initialize",
      params: .object([
        "clientInfo": .object([
          "name": .string("Codex Ray-Ban"),
          "version": .string("0.1"),
        ]),
        "capabilities": .object([
          "experimentalApi": .bool(true),
        ]),
      ])
    )
    try await sendNotification(method: "initialized", params: .object([:]))
    initialized = true
    log("rpc initialize complete stream=\(short(streamID))")
  }

  private func sendRequest(method: String, params: CodexJSONValue) async throws -> CodexJSONValue {
    let id = String(nextRequestID)
    nextRequestID += 1

    let message: CodexJSONValue = .object([
      "jsonrpc": .string("2.0"),
      "id": .string(id),
      "method": .string(method),
      "params": params,
    ])

    return try await sendRequestMessage(id: id, method: method, message: message)
  }

  private func sendBuiltRequest(_ build: (String) -> CodexJSONValue) async throws -> CodexJSONValue {
    let id = String(nextRequestID)
    nextRequestID += 1
    let message = build(id)
    let method = requestMethod(from: message) ?? "<unknown>"

    return try await sendRequestMessage(id: id, method: method, message: message)
  }

  private func sendRequestMessage(id: String, method: String, message: CodexJSONValue) async throws -> CodexJSONValue {
    try await withCheckedThrowingContinuation { continuation in
      pendingResponses[id] = continuation
      pendingMethodsByID[id] = method
      pendingRequestIDs.append(id)

      Task {
        do {
          try await self.sendClientMessage(message)
        } catch {
          self.failPendingResponse(id, error: error)
        }
      }

      Task {
        try? await Task.sleep(nanoseconds: requestTimeoutNanoseconds)
        self.failPendingResponse(id, error: CodexAppServerError.rpcTimeout(method))
      }
    }
  }

  private func sendNotification(method: String, params: CodexJSONValue) async throws {
    try await sendClientMessage(
      .object([
        "jsonrpc": .string("2.0"),
        "method": .string(method),
        "params": params,
      ])
    )
  }

  private func sendClientMessage(_ message: CodexJSONValue) async throws {
    let method = requestMethod(from: message) ?? notificationMethod(from: message) ?? "<response>"
    let id = message.objectValue?["id"]?.idString ?? "-"
    let envelope = CodexRemoteOutboundEnvelope(
      type: "client_message",
      clientID: clientID,
      seqID: takeNextSeqID(),
      streamID: streamID,
      envID: environmentID,
      skipHistory: false,
      state: nil,
      message: message
    )
    log("send seq=\(envelope.seqID) id=\(id) method=\(method) stream=\(short(streamID))")
    try await sendRaw(try CodexJSONCodec.value(from: envelope))
  }

  private func sendRaw(_ value: CodexJSONValue) async throws {
    guard let webSocketTask else {
      throw CodexAppServerError.notConnected
    }
    let data = try CodexJSONCodec.data(from: value)
    guard let text = String(data: data, encoding: .utf8) else {
      throw CodexAppServerError.invalidWebSocketMessage("unable to encode message")
    }
    try await webSocketTask.send(.string(text))
  }

  private func receiveLoop() async {
    while !Task.isCancelled {
      do {
        guard let webSocketTask else {
          return
        }
        let message = try await webSocketTask.receive()
        try await handle(message: message)
      } catch {
        failAllPending(error)
        return
      }
    }
  }

  private func receiveMessage(timeoutNanoseconds: UInt64) async throws -> URLSessionWebSocketTask.Message? {
    guard let webSocketTask else {
      throw CodexAppServerError.notConnected
    }

    return try await withThrowingTaskGroup(of: URLSessionWebSocketTask.Message?.self) { group in
      group.addTask {
        try await webSocketTask.receive()
      }
      group.addTask {
        try await Task.sleep(nanoseconds: timeoutNanoseconds)
        return nil
      }

      let first = try await group.next() ?? nil
      group.cancelAll()
      return first
    }
  }

  private func handle(message: URLSessionWebSocketTask.Message) async throws {
    let data: Data
    switch message {
    case .string(let string):
      data = Data(string.utf8)
    case .data(let value):
      data = value
    @unknown default:
      throw CodexAppServerError.invalidWebSocketMessage("unsupported websocket frame")
    }

    let envelope = try JSONDecoder().decode(CodexRemoteInboundEnvelope.self, from: data)

    switch envelope.type {
    case "ack":
      log("recv ack seq=\(envelope.seqID.map(String.init) ?? "-")")
      return
    case "server_message", "server_message_chunk":
      guard let complete = try chunkAssembler.observe(envelope) else {
        log("recv chunk env=\(short(envelope.envID)) stream=\(short(envelope.streamID)) seq=\(envelope.seqID.map(String.init) ?? "-") segment=\(envelope.segmentID.map(String.init) ?? "?")/\(envelope.segmentCount.map(String.init) ?? "?")")
        return
      }
      try await handleServerMessage(complete)
    case "pong":
      log("recv pong")
      return
    case "device_key_challenge":
      let challenge = try JSONDecoder().decode(CodexWebSocketDeviceKeyChallenge.self, from: data)
      try validate(challenge: challenge)
      log("websocket challenge received during loop session=\(short(challenge.sessionID))")
      let proof = try CodexDeviceProofBuilder.websocketProof(for: challenge, key: deviceKey)
      try await sendRaw(.object([
        "type": .string("device_key_proof"),
        "keyId": .string(proof.keyID),
        "signatureDerBase64": .string(proof.signatureDERBase64),
        "signedPayloadBase64": .string(proof.signedPayloadBase64),
        "algorithm": .string(proof.algorithm),
      ]))
      log("websocket challenge proof sent during loop key=\(short(proof.keyID))")
    default:
      log("recv unsupported envelope type=\(envelope.type)")
      throw CodexAppServerError.invalidWebSocketMessage(envelope.type)
    }
  }

  private func handleServerMessage(_ envelope: CodexRemoteInboundEnvelope) async throws {
    guard envelope.clientID == clientID else {
      log("recv ignored client mismatch expected=\(short(clientID)) actual=\(short(envelope.clientID))")
      return
    }
    guard envelope.envID == environmentID, envelope.streamID == streamID else {
      log("recv ignored foreign envelope env=\(short(envelope.envID)) stream=\(short(envelope.streamID)) currentEnv=\(short(environmentID)) currentStream=\(short(streamID))")
      return
    }
    if let seqID = envelope.seqID {
      if let serverSeqID, seqID > serverSeqID + 1 {
        log("recv server sequence gap previous=\(serverSeqID) next=\(seqID)")
      }
      if serverSeqID == nil || seqID > serverSeqID ?? 0 {
        serverSeqID = seqID
      }
    }
    guard let message = envelope.message else {
      return
    }

    let object = message.objectValue ?? [:]

    if let method = object["method"]?.stringValue, let id = object["id"]?.idString {
      log("recv server request id=\(id) method=\(method)")
      try await handleServerRequest(id: id, method: method, params: object["params"] ?? .object([:]))
      return
    }

    if let method = object["method"]?.stringValue {
      log("recv notification method=\(method)")
      await eventHandler?(
        CodexAppServerEvent(
          id: object["id"]?.idString,
          method: method,
          params: object["params"] ?? .object([:])
        )
      )
      return
    }

    if let id = object["id"]?.idString {
      pendingRequestIDs.removeAll { $0 == id }
      let method = pendingMethodsByID.removeValue(forKey: id) ?? "<unknown>"
      if let continuation = pendingResponses.removeValue(forKey: id) {
        if let error = object["error"] {
          log("recv error id=\(id) method=\(method) error=\(trim(error.description))")
          continuation.resume(throwing: CodexAppServerError.rpcError("RPC \(method) failed: \(trim(error.description))"))
        } else {
          log("recv result id=\(id) method=\(method)")
          continuation.resume(returning: message)
        }
      }
      return
    }

    if object["type"]?.stringValue == "error" {
      guard let id = pendingRequestIDs.first else {
        return
      }
      pendingRequestIDs.removeFirst()
      let method = pendingMethodsByID.removeValue(forKey: id) ?? "<unknown>"
      log("recv transport error assignedTo=\(method) id=\(id) error=\(trim(message.description))")
      pendingResponses.removeValue(forKey: id)?.resume(
        throwing: CodexAppServerError.rpcError("RPC \(method) failed: \(trim(message.description))")
      )
    }
  }

  private func handleServerRequest(id: String, method: String, params: CodexJSONValue) async throws {
    await eventHandler?(
      CodexAppServerEvent(
        id: id,
        method: method,
        params: params
      )
    )

    do {
      let result: CodexJSONValue
      switch method {
      case "account/chatgptAuthTokens/refresh":
        guard let authTokenProvider else {
          throw CodexAppServerError.invalidWebSocketMessage("missing app-server auth token provider")
        }
        log("server request token refresh start id=\(id)")
        let tokens = try await authTokenProvider()
        result = .object([
          "accessToken": .string(tokens.accessToken),
          "chatgptAccountId": .string(tokens.chatgptAccountID),
          "chatgptPlanType": tokens.chatgptPlanType.map(CodexJSONValue.string) ?? .null,
        ])
      default:
        throw CodexAppServerError.invalidWebSocketMessage("unsupported server request \(method)")
      }

      log("server request result id=\(id) method=\(method)")
      try await sendClientMessage(
        .object([
          "jsonrpc": .string("2.0"),
          "id": .string(id),
          "result": result,
        ])
      )
    } catch {
      log("server request failed id=\(id) method=\(method) error=\(error.localizedDescription)")
      try await sendClientMessage(
        .object([
          "jsonrpc": .string("2.0"),
          "id": .string(id),
          "error": .object([
            "code": .int(-32000),
            "message": .string(error.localizedDescription),
          ]),
        ])
      )
    }
  }

  private func failPendingResponse(_ id: String, error: Error) {
    pendingRequestIDs.removeAll { $0 == id }
    guard let continuation = pendingResponses.removeValue(forKey: id) else {
      pendingMethodsByID.removeValue(forKey: id)
      return
    }
    let method = pendingMethodsByID.removeValue(forKey: id) ?? "<unknown>"
    log("pending failed id=\(id) method=\(method) error=\(error.localizedDescription)")
    continuation.resume(throwing: error)
  }

  private func failAllPending(_ error: Error) {
    log("connection failed pending=\(pendingResponses.count) error=\(error.localizedDescription)")
    pendingResponses.values.forEach { $0.resume(throwing: error) }
    pendingResponses = [:]
    pendingMethodsByID = [:]
    pendingRequestIDs = []
    webSocketTask = nil
    initialized = false
    reconnectAfter = Date().addingTimeInterval(1)
    if let disconnectionHandler {
      Task {
        await disconnectionHandler(error)
      }
    }
  }

  private func takeNextSeqID() -> Int {
    let value = nextSeqID
    nextSeqID += 1
    return value
  }

  private func decodeWebSocketChallenge(from message: URLSessionWebSocketTask.Message) throws -> CodexWebSocketDeviceKeyChallenge {
    let data: Data
    switch message {
    case .string(let string):
      data = Data(string.utf8)
    case .data(let value):
      data = value
    @unknown default:
      throw CodexAppServerError.invalidWebSocketMessage("unsupported websocket frame")
    }
    return try JSONDecoder().decode(CodexWebSocketDeviceKeyChallenge.self, from: data)
  }

  private func validate(challenge: CodexWebSocketDeviceKeyChallenge) throws {
    guard challenge.audience == "remote_control_client_websocket" else {
      throw CodexAppServerError.invalidWebSocketMessage("invalid challenge audience")
    }
    guard challenge.clientID == clientID else {
      throw CodexAppServerError.invalidWebSocketMessage("challenge client id mismatch")
    }
    guard challenge.targetOrigin == "https://chatgpt.com" else {
      throw CodexAppServerError.invalidWebSocketMessage("challenge target origin mismatch")
    }
    guard challenge.targetPath == "/backend-api/codex/remote/control/client" else {
      throw CodexAppServerError.invalidWebSocketMessage("challenge target path mismatch")
    }
    let tokenHash = Data(SHA256.hash(data: Data(remoteControlToken.utf8))).base64URLEncodedString()
    guard challenge.tokenSha256Base64url == tokenHash else {
      throw CodexAppServerError.invalidWebSocketMessage("challenge token hash mismatch")
    }
  }

  private func requestMethod(from message: CodexJSONValue) -> String? {
    message.objectValue?["method"]?.stringValue
  }

  private func notificationMethod(from message: CodexJSONValue) -> String? {
    guard message.objectValue?["id"] == nil else {
      return nil
    }
    return message.objectValue?["method"]?.stringValue
  }

  private func log(_ message: String) {
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      NSLog("[Codex app-server] %@", message)
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

  private func expiryText(_ date: Date?) -> String {
    guard let date else {
      return "missing"
    }
    let seconds = Int(date.timeIntervalSinceNow)
    return "\(seconds)s"
  }

  private func trim(_ text: String, limit: Int = 600) -> String {
    let normalized = text.replacingOccurrences(of: "\n", with: " ")
    if normalized.count <= limit {
      return normalized
    }
    return "\(normalized.prefix(limit))..."
  }
}

private struct CodexRemoteOutboundEnvelope: Encodable {
  let type: String
  let clientID: String
  let seqID: Int
  let streamID: String
  let envID: String
  let skipHistory: Bool?
  let state: String?
  let message: CodexJSONValue?

  enum CodingKeys: String, CodingKey {
    case type
    case clientID = "client_id"
    case seqID = "seq_id"
    case streamID = "stream_id"
    case envID = "env_id"
    case skipHistory = "skip_history"
    case state
    case message
  }
}

private struct CodexRemoteInboundEnvelope: Decodable {
  let type: String
  let clientID: String
  let seqID: Int?
  let streamID: String?
  let cursor: String?
  let envID: String?
  let status: String?
  let skipHistory: Bool?
  let segmentID: Int?
  let segmentCount: Int?
  let messageSizeBytes: Int?
  let messageChunkBase64: String?
  let message: CodexJSONValue?

  enum CodingKeys: String, CodingKey {
    case type
    case clientID = "client_id"
    case seqID = "seq_id"
    case streamID = "stream_id"
    case cursor
    case envID = "env_id"
    case status
    case skipHistory = "skip_history"
    case segmentID = "segment_id"
    case segmentCount = "segment_count"
    case messageSizeBytes = "message_size_bytes"
    case messageChunkBase64 = "message_chunk_base64"
    case message
  }
}

private struct CodexRemoteChunkAssembler {
  private struct Assembly {
    var envelope: CodexRemoteInboundEnvelope
    var chunks: [String?]
    var expectedBytes: Int
  }

  private var assemblies: [String: Assembly] = [:]

  mutating func observe(_ envelope: CodexRemoteInboundEnvelope) throws -> CodexRemoteInboundEnvelope? {
    guard envelope.type == "server_message_chunk" else {
      return envelope
    }
    guard
      let envID = envelope.envID,
      let streamID = envelope.streamID,
      let seqID = envelope.seqID,
      let segmentID = envelope.segmentID,
      let segmentCount = envelope.segmentCount,
      let messageSizeBytes = envelope.messageSizeBytes,
      let chunk = envelope.messageChunkBase64,
      segmentCount > 1,
      segmentID >= 0,
      segmentID < segmentCount
    else {
      throw CodexAppServerError.invalidWebSocketMessage("invalid chunk metadata")
    }

    let key = "\(envID):\(streamID):\(seqID)"
    var assembly = assemblies[key] ?? Assembly(
      envelope: envelope,
      chunks: Array(repeating: nil, count: segmentCount),
      expectedBytes: messageSizeBytes
    )
    guard assembly.chunks.count == segmentCount, assembly.expectedBytes == messageSizeBytes else {
      assemblies[key] = nil
      throw CodexAppServerError.invalidWebSocketMessage("chunk metadata mismatch")
    }

    assembly.chunks[segmentID] = chunk
    assemblies[key] = assembly

    guard assembly.chunks.allSatisfy({ $0 != nil }) else {
      return nil
    }

    let data = Data(
      assembly.chunks
        .compactMap { $0 }
        .compactMap { Data(base64Encoded: $0) }
        .joined()
    )
    guard data.count == messageSizeBytes else {
      assemblies[key] = nil
      throw CodexAppServerError.invalidWebSocketMessage("chunk size mismatch")
    }
    let message = try JSONDecoder().decode(CodexJSONValue.self, from: data)
    assemblies[key] = nil

    return CodexRemoteInboundEnvelope(
      type: "server_message",
      clientID: envelope.clientID,
      seqID: seqID,
      streamID: streamID,
      cursor: envelope.cursor,
      envID: envID,
      status: envelope.status,
      skipHistory: envelope.skipHistory,
      segmentID: nil,
      segmentCount: nil,
      messageSizeBytes: nil,
      messageChunkBase64: nil,
      message: message
    )
  }
}

private struct CodexWebSocketDeviceKeyChallenge: Decodable {
  let type: String
  let nonce: String
  let purpose: String
  let audience: String
  let sessionID: String
  let targetOrigin: String
  let targetPath: String
  let accountUserID: String
  let clientID: String
  let tokenSha256Base64url: String
  let tokenExpiresAt: Int
  let scopes: [String]

  enum CodingKeys: String, CodingKey {
    case type
    case nonce
    case purpose
    case audience
    case sessionID = "sessionId"
    case targetOrigin
    case targetPath
    case accountUserID = "accountUserId"
    case clientID = "clientId"
    case tokenSha256Base64url
    case tokenExpiresAt
    case scopes
  }
}

private struct CodexWebSocketDeviceKeyProof {
  let keyID: String
  let signatureDERBase64: String
  let signedPayloadBase64: String
  let algorithm = "ecdsa_p256_sha256"
}

private extension CodexDeviceProofBuilder {
  static func websocketProof(
    for challenge: CodexWebSocketDeviceKeyChallenge,
    key: CodexDeviceKey
  ) throws -> CodexWebSocketDeviceKeyProof {
    let payload = OrderedJSON.object([
      ("accountUserId", .string(challenge.accountUserID)),
      ("audience", .string(challenge.audience)),
      ("clientId", .string(challenge.clientID)),
      ("nonce", .string(challenge.nonce)),
      ("scopes", .array(challenge.scopes.map { .string($0) })),
      ("sessionId", .string(challenge.sessionID)),
      ("targetOrigin", .string(challenge.targetOrigin)),
      ("targetPath", .string(challenge.targetPath)),
      ("tokenExpiresAt", .int(challenge.tokenExpiresAt)),
      ("tokenSha256Base64url", .string(challenge.tokenSha256Base64url)),
      ("type", .string("remoteControlClientConnection")),
    ])

    let signedPayload = OrderedJSON.object([
      ("domain", .string(CodexRemoteConstants.deviceKeyDomain)),
      ("payload", payload),
    ]).render()

    let signedPayloadData = Data(signedPayload.utf8)
    let signature = try key.signature(for: signedPayloadData)

    return CodexWebSocketDeviceKeyProof(
      keyID: key.keyID,
      signatureDERBase64: signature.derRepresentation.base64EncodedString(),
      signedPayloadBase64: signedPayloadData.base64EncodedString()
    )
  }
}

struct CodexThreadSummary: Decodable {
  let id: String
  let preview: String?
  let cwd: String?
  let name: String?
  let status: CodexJSONValue?
  let unread: CodexJSONValue?
  let hasUnread: CodexJSONValue?
  let unreadCount: CodexJSONValue?
  let metadata: CodexJSONValue?
  let userMetadata: CodexJSONValue?
  let createdAt: TimeInterval?
  let updatedAt: TimeInterval?

  var updatedAtDate: Date {
    Date(timeIntervalSince1970: updatedAt ?? createdAt ?? 0)
  }

  var explicitUnreadState: Bool? {
    unread?.truthyBool
      ?? hasUnread?.truthyBool
      ?? unreadCount?.positiveNumberBool
      ?? metadata?.objectValue?.explicitUnreadState
      ?? userMetadata?.objectValue?.explicitUnreadState
  }
}

private extension Dictionary where Key == String, Value == CodexJSONValue {
  var explicitUnreadState: Bool? {
    self["unread"]?.truthyBool
      ?? self["hasUnread"]?.truthyBool
      ?? self["has_unread"]?.truthyBool
      ?? self["unreadCount"]?.positiveNumberBool
      ?? self["unread_count"]?.positiveNumberBool
  }
}

private struct CodexThreadListResult: Decodable {
  let data: [CodexThreadSummary]
  let nextCursor: String?
  let backwardsCursor: String?
}

private struct CodexRPCResponse<Result: Decodable>: Decodable {
  let id: String?
  let result: Result
}

enum CodexJSONValue: Codable, Equatable, Sendable, CustomStringConvertible {
  case string(String)
  case int(Int)
  case double(Double)
  case bool(Bool)
  case object([String: CodexJSONValue])
  case array([CodexJSONValue])
  case null

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(Int.self) {
      self = .int(value)
    } else if let value = try? container.decode(Double.self) {
      self = .double(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([String: CodexJSONValue].self) {
      self = .object(value)
    } else if let value = try? container.decode([CodexJSONValue].self) {
      self = .array(value)
    } else {
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .string(let value):
      try container.encode(value)
    case .int(let value):
      try container.encode(value)
    case .double(let value):
      try container.encode(value)
    case .bool(let value):
      try container.encode(value)
    case .object(let value):
      try container.encode(value)
    case .array(let value):
      try container.encode(value)
    case .null:
      try container.encodeNil()
    }
  }

  var objectValue: [String: CodexJSONValue]? {
    if case .object(let value) = self {
      return value
    }
    return nil
  }

  var arrayValue: [CodexJSONValue]? {
    if case .array(let value) = self {
      return value
    }
    return nil
  }

  var stringValue: String? {
    if case .string(let value) = self {
      return value
    }
    return nil
  }

  var boolValue: Bool? {
    if case .bool(let value) = self {
      return value
    }
    return nil
  }

  var idString: String? {
    switch self {
    case .string(let value):
      return value
    case .int(let value):
      return String(value)
    case .double(let value) where value.rounded() == value:
      return String(Int(value))
    default:
      return nil
    }
  }

  var description: String {
    guard let data = try? CodexJSONCodec.data(from: self) else {
      return "<json>"
    }
    return String(data: data, encoding: .utf8) ?? "<json>"
  }
}

private extension CodexJSONValue {
  var truthyBool: Bool? {
    switch self {
    case .bool(let value):
      return value
    case .int(let value):
      return value > 0
    case .double(let value):
      return value > 0
    case .string(let value):
      let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      if ["true", "yes", "1", "unread"].contains(normalized) {
        return true
      }
      if ["false", "no", "0", "read"].contains(normalized) {
        return false
      }
      return nil
    case .object, .array, .null:
      return nil
    }
  }

  var positiveNumberBool: Bool? {
    switch self {
    case .int(let value):
      return value > 0
    case .double(let value):
      return value > 0
    case .string(let value):
      return Double(value.trimmingCharacters(in: .whitespacesAndNewlines)).map { $0 > 0 }
    case .bool(let value):
      return value
    case .object, .array, .null:
      return nil
    }
  }

  var codexStatusString: String? {
    switch self {
    case .string(let status):
      return status
    case .bool(let isActive):
      return isActive ? "running" : nil
    case .object(let object):
      return object["status"]?.stringValue
        ?? object["state"]?.stringValue
        ?? object["type"]?.stringValue
    case .int, .double, .array, .null:
      return nil
    }
  }
}

enum CodexJSONCodec {
  static func data(from value: CodexJSONValue) throws -> Data {
    try JSONEncoder().encode(value)
  }

  static func value<T: Encodable>(from encodable: T) throws -> CodexJSONValue {
    let data = try JSONEncoder().encode(encodable)
    return try JSONDecoder().decode(CodexJSONValue.self, from: data)
  }

  static func decode<T: Decodable>(_ type: T.Type, from value: CodexJSONValue) throws -> T {
    let data = try data(from: value)
    return try JSONDecoder().decode(T.self, from: data)
  }
}

private extension CodexRemoteConstants {
  static let webSocketURL = URL(string: "wss://chatgpt.com/backend-api/codex/remote/control/client")!
}
