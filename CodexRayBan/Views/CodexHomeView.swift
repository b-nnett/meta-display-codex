import MWDATCore
import SwiftUI

private enum CodexHomeSection: String, CaseIterable, Identifiable {
  case pinnedChats
  case recentChats
  case projects

  var id: String { rawValue }

  var title: String {
    switch self {
    case .pinnedChats:
      "Pinned Chats"
    case .projects:
      "Projects"
    case .recentChats:
      "Recent Chats"
    }
  }
}

private func codexNormalizedProjectIdentifier(_ rawValue: String?) -> String? {
  guard let rawValue else {
    return nil
  }

  let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
  guard !trimmed.isEmpty, trimmed != ".", trimmed != "/" else {
    return nil
  }
  return trimmed
}

private func codexProjectIdentifiers(from projects: [CodexProjectPreview]) -> Set<String> {
  var identifiers = Set<String>()
  for project in projects {
    if let id = codexNormalizedProjectIdentifier(project.id) {
      identifiers.insert(id)
    }
    if let path = codexNormalizedProjectIdentifier(project.path) {
      identifiers.insert(path)
    }
  }
  return identifiers
}

private func codexChatBelongsToKnownProject(_ chat: CodexChatPreview, projects: [CodexProjectPreview]) -> Bool {
  guard let projectPath = codexNormalizedProjectIdentifier(chat.projectPath) else {
    return false
  }
  return codexProjectIdentifiers(from: projects).contains(projectPath)
}

struct CodexHomeView: View {
  var displayViewModel: DisplayViewModel
  var authViewModel: CodexAuthViewModel
  var workspaceViewModel: CodexWorkspaceViewModel
  var transcriptionViewModel: CodexTranscriptionViewModel
  var showChatOnGlasses: @MainActor () async -> Void
  var showPetOnGlasses: @MainActor () async -> Void

  @AppStorage("codex.home.section.order") private var sectionOrderRaw = defaultSectionOrder
  @AppStorage("codex.selected.remote.host.id") private var selectedRemoteHostID = ""
  @State private var showsRemoteHostSwitcher = false
  @State private var showsNewThread = false
  @State private var deviceSnapshotChat: CodexChatPreview?
  @State private var didScheduleDeviceSnapshot = false
  @State private var showsAllRecentChats = false

  private static let defaultSections: [CodexHomeSection] = [.pinnedChats, .recentChats, .projects]
  private static let legacyDefaultSections: [CodexHomeSection] = [.pinnedChats, .projects, .recentChats]
  private static let recentChatLimit = 5
  private static let defaultSectionOrder = defaultSections
    .map(\.rawValue)
    .joined(separator: ",")
  private static let legacyDefaultSectionOrder = legacyDefaultSections
    .map(\.rawValue)
    .joined(separator: ",")

  var body: some View {
    @Bindable var authViewModel = authViewModel

    List {
      ForEach(visibleSections) { section in
        sectionContent(section)
      }
      .onMove(perform: moveSections)

      if authViewModel.isBusy || displayViewModel.isSending || workspaceViewModel.isLoading {
        Section {
          HStack(spacing: 12) {
            ProgressView()
            Text(progressText)
          }
        }
      }

      if let errorMessage = authViewModel.errorMessage {
        Section("Codex Error") {
          Text(errorMessage)
            .foregroundStyle(.red)
          Button("Clear") {
            authViewModel.clearError()
          }
        }
      }

    }
    .navigationTitle("Codex")
    .navigationBarTitleDisplayMode(.large)
    .toolbar {
      ToolbarItem(placement: .topBarLeading) {
        remoteHostToolbarItem
      }

      ToolbarItem(placement: .topBarTrailing) {
        Button {
          createChat()
        } label: {
          Image(systemName: "square.and.pencil")
        }
        .disabled(!canCreateChat)
        .accessibilityLabel("New chat")
      }
    }
    .refreshable {
      await refreshWorkspace()
    }
    .navigationDestination(isPresented: $showsNewThread) {
      CodexChatView(
        chat: nil,
        hostName: remoteHostName,
        authViewModel: authViewModel,
        displayViewModel: displayViewModel,
        workspaceViewModel: workspaceViewModel,
        transcriptionViewModel: transcriptionViewModel,
        showChatOnGlasses: showChatOnGlasses,
        showPetOnGlasses: showPetOnGlasses
      )
    }
    .navigationDestination(item: $deviceSnapshotChat) { chat in
      CodexChatView(
        chat: chat,
        hostName: remoteHostName,
        authViewModel: authViewModel,
        displayViewModel: displayViewModel,
        workspaceViewModel: workspaceViewModel,
        transcriptionViewModel: transcriptionViewModel,
        showChatOnGlasses: showChatOnGlasses,
        showPetOnGlasses: showPetOnGlasses
      )
    }
    .task(id: workspaceRefreshKey) {
      await refreshWorkspace()
    }
    .sheet(item: $authViewModel.activeOAuthRequest) { request in
      CodexOAuthSessionPresenter(
        request: request,
        onCallback: { url, request in
          Task {
            await authViewModel.handleOAuthCallback(url, request: request)
          }
        },
        onCancel: { request in
          if authViewModel.activeOAuthRequest?.id == request.id {
            authViewModel.activeOAuthRequest = nil
          }
        },
        onError: { message in
          authViewModel.activeOAuthRequest = nil
          authViewModel.errorMessage = message
        }
      )
    }
    .sheet(isPresented: $showsRemoteHostSwitcher) {
      RemoteHostSwitcherSheet(
        hosts: authViewModel.environments,
        selectedHostID: $selectedRemoteHostID,
        connectionState: workspaceViewModel.connectionState
      )
    }
    .alert("Chat transport error", isPresented: chatTransportErrorIsPresented) {
      Button("OK") {
        workspaceViewModel.errorMessage = nil
      }
    } message: {
      Text(workspaceViewModel.errorMessage ?? "Codex could not load chats.")
    }
  }

  private var orderedSections: [CodexHomeSection] {
    let rawOrder = sectionOrderRaw == Self.legacyDefaultSectionOrder ? Self.defaultSectionOrder : sectionOrderRaw
    let saved = rawOrder
      .split(separator: ",")
      .compactMap { CodexHomeSection(rawValue: String($0)) }
    let missing = Self.defaultSections.filter { !saved.contains($0) }
    let sections = saved + missing
    return sections.isEmpty ? Self.defaultSections : sections
  }

  private var visibleSections: [CodexHomeSection] {
    orderedSections.filter { section in
      switch section {
      case .pinnedChats:
        return !pinnedChats.isEmpty
      case .projects, .recentChats:
        return true
      }
    }
  }

  private var pinnedChats: [CodexChatPreview] {
    workspaceViewModel.chats.filter(\.isPinned)
      .sorted { $0.updatedAt > $1.updatedAt }
  }

  private var recentChats: [CodexChatPreview] {
    workspaceViewModel.chats
      .filter { !codexChatBelongsToKnownProject($0, projects: workspaceViewModel.projects) && !$0.isPinned }
      .sorted { $0.updatedAt > $1.updatedAt }
  }

  private var visibleRecentChats: [CodexChatPreview] {
    if showsAllRecentChats {
      return recentChats
    }
    return Array(recentChats.prefix(Self.recentChatLimit))
  }

  private var hasMoreRecentChats: Bool {
    recentChats.count > Self.recentChatLimit
  }

  private var projects: [CodexProjectPreview] {
    workspaceViewModel.projects.filter { !chats(for: $0).isEmpty }
  }

  private var selectedRemoteHost: CodexEnvironment? {
    if let match = authViewModel.environments.first(where: { $0.envID == selectedRemoteHostID }) {
      return match
    }
    return authViewModel.environments.first(where: \.online) ?? authViewModel.environments.first
  }

  private var remoteHostName: String {
    selectedRemoteHost?.displayName ?? "No host"
  }

  private var selectedRemoteHostStatus: RemoteHostConnectionStatus {
    guard selectedRemoteHost != nil else {
      return .disconnected
    }

    switch workspaceViewModel.connectionState {
    case .ready:
      return .connected
    case .connecting:
      return .connecting
    case .disconnected, .failed:
      return .disconnected
    }
  }

  private var isChatTransportConnected: Bool {
    workspaceViewModel.connectionState.isReady
  }

  private var canCreateChat: Bool {
    isChatTransportConnected
  }

  private var progressText: String {
    if authViewModel.isBusy {
      return "Working on Codex"
    }
    if workspaceViewModel.isLoading {
      return "Loading chats"
    }
    return "Sending to glasses"
  }

  private var workspaceRefreshKey: String {
    [
      authViewModel.session.isSignedIn ? "signed-in" : "signed-out",
      authViewModel.session.remoteClientID ?? "no-client",
      selectedRemoteHostID.isEmpty ? "auto-host" : selectedRemoteHostID,
    ].joined(separator: ":")
  }

  private var projectsEmptyTitle: String {
    if !authViewModel.session.remoteTokenIsFresh {
      return "Codex not connected"
    }
    if !workspaceViewModel.connectionState.isReady {
      return workspaceViewModel.connectionState.emptyStateText
    }
    return "No projects"
  }

  private var chatsEmptyTitle: String {
    if !authViewModel.session.remoteTokenIsFresh {
      return "Codex not connected"
    }
    if !workspaceViewModel.connectionState.isReady {
      return workspaceViewModel.connectionState.emptyStateText
    }
    if !projects.isEmpty {
      return "No non-project chats"
    }
    return workspaceViewModel.connectionState.emptyStateText
  }

  private var chatTransportErrorIsPresented: Binding<Bool> {
    Binding {
      workspaceViewModel.errorMessage != nil
    } set: { isPresented in
      if !isPresented {
        workspaceViewModel.errorMessage = nil
      }
    }
  }

  @ViewBuilder
  private var remoteHostToolbarItem: some View {
    Button {
      showsRemoteHostSwitcher = true
    } label: {
      RemoteHostStatusLabel(name: remoteHostName, status: selectedRemoteHostStatus)
    }
    .accessibilityLabel("Remote host \(remoteHostName)")
  }

  @ViewBuilder
  private func sectionContent(_ section: CodexHomeSection) -> some View {
    switch section {
    case .pinnedChats:
      Section(section.title) {
        if pinnedChats.isEmpty {
          emptyRow("No pinned chats")
        } else {
          ForEach(pinnedChats) { chat in
            chatRow(chat)
          }
        }
      }

    case .projects:
      Section(section.title) {
        if projects.isEmpty {
          emptyRow(projectsEmptyTitle)
        } else {
          ForEach(projects) { project in
            projectDisclosure(project)
          }
        }
      }

    case .recentChats:
      Section(section.title) {
        if recentChats.isEmpty {
          emptyRow(chatsEmptyTitle)
        } else {
          ForEach(visibleRecentChats) { chat in
            chatRow(chat)
          }

          if hasMoreRecentChats {
            Button {
              withAnimation(.snappy(duration: 0.2)) {
                showsAllRecentChats.toggle()
              }
            } label: {
              Label(showsAllRecentChats ? "Show less" : "Show more", systemImage: showsAllRecentChats ? "chevron.up" : "chevron.down")
            }
          }
        }
      }
    }
  }

  private func chatRow(_ chat: CodexChatPreview) -> some View {
    NavigationLink {
      CodexChatView(
        chat: chat,
        hostName: remoteHostName,
        authViewModel: authViewModel,
        displayViewModel: displayViewModel,
        workspaceViewModel: workspaceViewModel,
        transcriptionViewModel: transcriptionViewModel,
        showChatOnGlasses: showChatOnGlasses,
        showPetOnGlasses: showPetOnGlasses
      )
    } label: {
      HStack(spacing: 12) {
        Text(chat.title)
          .font(.body)
          .lineLimit(1)
          .truncationMode(.tail)

        Spacer(minLength: 8)

        if chat.isUnread {
          Circle()
            .fill(Color.blue)
            .frame(width: 8, height: 8)
            .accessibilityLabel("Unread")
        }

        if chatIsActive(chat) {
          ProgressView()
            .controlSize(.small)
            .accessibilityLabel("Active chat")
        }
      }
    }
    .swipeActions(edge: .leading, allowsFullSwipe: false) {
      Button {
        workspaceViewModel.togglePinned(chat)
      } label: {
        Label(chat.isPinned ? "Unpin" : "Pin", systemImage: chat.isPinned ? "pin.slash" : "pin")
      }
      .tint(.orange)
    }
    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
      Button(role: .destructive) {
        Task {
          await workspaceViewModel.archiveChat(chat)
        }
      } label: {
        Label("Archive", systemImage: "archivebox")
      }
      .disabled(!isChatTransportConnected)
    }
  }

  private func chatIsActive(_ chat: CodexChatPreview) -> Bool {
    if chat.isActive {
      return true
    }
    return workspaceViewModel.activeChat?.id == chat.id && workspaceViewModel.activeChat?.isStreaming == true
  }

  private func projectDisclosure(_ project: CodexProjectPreview) -> some View {
    let chats = chats(for: project)

    return DisclosureGroup {
      if chats.isEmpty {
        emptyRow("No chats")
      } else {
        ForEach(chats) { chat in
          chatRow(chat)
            .padding(.leading, 4)
        }
      }
    } label: {
      HStack(spacing: 12) {
        Image(systemName: "folder")
          .foregroundStyle(.blue)
          .frame(width: 24)

        VStack(alignment: .leading, spacing: 3) {
          Text(project.name)
          Text("\(chats.count) chat\(chats.count == 1 ? "" : "s")")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
    }
  }

  private func chats(for project: CodexProjectPreview) -> [CodexChatPreview] {
    workspaceViewModel.chats
      .filter { chat in
        guard !chat.isPinned else {
          return false
        }
        guard let chatProjectPath = codexNormalizedProjectIdentifier(chat.projectPath) else {
          return false
        }
        return chatProjectPath == project.id || chatProjectPath == codexNormalizedProjectIdentifier(project.path)
      }
      .sorted { $0.updatedAt > $1.updatedAt }
  }

  private func emptyRow(_ title: String) -> some View {
    HStack(spacing: 12) {
      Image(systemName: "tray")
        .foregroundStyle(.secondary)
        .frame(width: 24)
      Text(title)
        .foregroundStyle(.secondary)
    }
  }

  private func moveSections(from source: IndexSet, to destination: Int) {
    var sections = orderedSections
    sections.move(fromOffsets: source, toOffset: destination)
    sectionOrderRaw = sections.map(\.rawValue).joined(separator: ",")
  }

  private func createChat() {
    showsNewThread = true
  }

  private func refreshWorkspace() async {
    if authViewModel.session.isRemoteEnrolled && !authViewModel.session.remoteTokenIsFresh {
      await authViewModel.refreshRemoteToken()
    }

    if authViewModel.session.isSignedIn {
      await authViewModel.refreshHosts()
    }

    await workspaceViewModel.refresh(
      session: authViewModel.session,
      environments: authViewModel.environments,
      preferredEnvironmentID: selectedRemoteHostID.isEmpty ? nil : selectedRemoteHostID,
      authTokenProvider: {
        try await authViewModel.appServerAuthTokens()
      }
    )
    scheduleDeviceSnapshotIfNeeded()
  }

  private func scheduleDeviceSnapshotIfNeeded() {
    #if DEBUG
    guard
      !didScheduleDeviceSnapshot,
      CodexDeviceSnapshotWriter.isHomeSnapshotRequested || CodexDeviceSnapshotWriter.isChatSnapshotRequested
    else {
      return
    }
    guard !workspaceViewModel.isLoading else {
      return
    }

    didScheduleDeviceSnapshot = true
    if CodexDeviceSnapshotWriter.isHomeSnapshotRequested {
      CodexDeviceSnapshotWriter.captureAfterDelay(filename: CodexDeviceSnapshotWriter.homeSnapshotFilename)
      return
    }

    if let chat = recentChats.first ?? workspaceViewModel.chats.sorted(by: { $0.updatedAt > $1.updatedAt }).first {
      deviceSnapshotChat = chat
    } else {
      showsNewThread = true
    }
    CodexDeviceSnapshotWriter.captureAfterDelay()
    #endif
  }
}

private enum RemoteHostConnectionStatus: Equatable {
  case connected
  case connecting
  case disconnected
}

private struct RemoteHostStatusLabel: View {
  var name: String
  var status: RemoteHostConnectionStatus

  var body: some View {
    HStack(spacing: 7) {
      RemoteHostStatusDot(status: status)
      Text(name)
        .font(.caption.weight(.semibold))
        .lineLimit(1)
        .layoutPriority(1)
    }
    .frame(height: 32)
    .fixedSize(horizontal: true, vertical: true)
  }
}

private struct RemoteHostStatusDot: View {
  var status: RemoteHostConnectionStatus
  @State private var isPulsing = false

  var body: some View {
    ZStack {
      if status == .connecting {
        Circle()
          .fill(Color.gray.opacity(0.24))
          .frame(width: 14, height: 14)
          .scaleEffect(isPulsing ? 1.0 : 0.55)
          .opacity(isPulsing ? 0.2 : 1.0)

        Circle()
          .fill(color)
          .frame(width: 8, height: 8)
      } else {
        Circle()
          .fill(color)
          .frame(width: 8, height: 8)
      }
    }
      .frame(width: 14, height: 14)
      .animation(status == .connecting ? .easeInOut(duration: 0.85).repeatForever(autoreverses: true) : nil, value: isPulsing)
      .onAppear {
        isPulsing = status == .connecting
      }
      .onChange(of: status) { _, status in
        isPulsing = status == .connecting
      }
  }

  private var color: Color {
    switch status {
    case .connected:
      .green
    case .connecting:
      .gray
    case .disconnected:
      .red
    }
  }
}

private struct RemoteHostSwitcherSheet: View {
  let hosts: [CodexEnvironment]
  @Binding var selectedHostID: String
  var connectionState: CodexChatTransportState
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      List {
        if hosts.isEmpty {
          Text("No remote hosts found")
            .foregroundStyle(.secondary)
        } else {
          ForEach(hosts) { host in
            Button {
              selectedHostID = host.envID
              dismiss()
            } label: {
              HStack(spacing: 12) {
                RemoteHostStatusDot(status: status(for: host))
                VStack(alignment: .leading, spacing: 2) {
                  Text(host.displayName)
                  Text(hostDetail(host))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
                if selectedHostID == host.envID {
                  Image(systemName: "checkmark")
                    .foregroundStyle(.blue)
                }
              }
            }
            .buttonStyle(.plain)
          }
        }
      }
      .navigationTitle("Remote Host")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Done") {
            dismiss()
          }
        }
      }
    }
  }

  private func status(for host: CodexEnvironment) -> RemoteHostConnectionStatus {
    if selectedHostID == host.envID {
      switch connectionState {
      case .ready:
        return .connected
      case .connecting:
        return .connecting
      case .disconnected, .failed:
        break
      }
    }

    return host.online ? .connected : .disconnected
  }

  private func hostDetail(_ host: CodexEnvironment) -> String {
    if let clientName = host.clientName, !clientName.isEmpty {
      return clientName
    }
    if let os = host.os, !os.isEmpty {
      return os
    }
    return host.online ? "Online" : "Offline"
  }
}

private struct CodexChatView: View {
  private static let bottomAnchorID = "codex-chat-bottom"

  let chat: CodexChatPreview?
  var hostName: String
  var authViewModel: CodexAuthViewModel
  var displayViewModel: DisplayViewModel
  var workspaceViewModel: CodexWorkspaceViewModel
  var transcriptionViewModel: CodexTranscriptionViewModel
  var showChatOnGlasses: @MainActor () async -> Void
  var showPetOnGlasses: @MainActor () async -> Void

  @State private var draft = ""
  @State private var selectedProjectID = ""
  @State private var selectedModelID = ""
  @State private var intelligence = "High"
  @State private var speed = "Fast"
  @State private var selectedFile: CodexViewedFile?
  @State private var voiceAlertMessage: String?
  @State private var bottomScrollRequest = 0
  @FocusState private var composerFocused: Bool

  private var isNewThread: Bool { chat == nil }
  private var activeChat: CodexChatDetail? { workspaceViewModel.activeChat }
  private var messages: [CodexChatMessage] { activeChat?.messages ?? [] }
  private var isTransportConnected: Bool { workspaceViewModel.connectionState.isReady }
  private var isStreaming: Bool {
    activeChat?.isStreaming ?? (workspaceViewModel.petState == .running || workspaceViewModel.petState == .thinking)
  }

  private var chatScrollKey: String {
    [
      activeChat?.id ?? chat?.id ?? "new",
      workspaceViewModel.isLoadingChat ? "loading" : "ready",
      "\(messages.count)",
      isStreaming ? "streaming" : "idle",
      messages.suffix(4).map(messageScrollSignature).joined(separator: "|"),
    ].joined(separator: ":")
  }

  var body: some View {
    ZStack {
      Color(.systemBackground).ignoresSafeArea()

      if workspaceViewModel.isLoadingChat {
        topAlignedChatSubview {
          loadingMessages
        }
      } else if messages.isEmpty {
        topAlignedChatSubview {
          newThreadPrompt
        }
      } else {
        ScrollViewReader { proxy in
          GeometryReader { geometry in
            ScrollView {
              LazyVStack(alignment: .leading, spacing: 14) {
                ForEach(messages) { message in
                  messageView(message)
                    .id(message.id)
                }

                Color.clear
                  .frame(height: 1)
                  .id(Self.bottomAnchorID)
              }
              .frame(minHeight: geometry.size.height, alignment: .top)
              .padding(.horizontal, 22)
              .padding(.top, 14)
              .padding(.bottom, 22)
            }
            .defaultScrollAnchor(.bottom)
            .scrollDismissesKeyboard(.interactively)
            .simultaneousGesture(TapGesture().onEnded {
              composerFocused = false
            })
            .onAppear {
              scrollToBottom(proxy, animated: false)
            }
            .task(id: chatScrollKey) {
              await scrollToBottomAfterLayout(proxy, animated: false)
            }
            .onChange(of: bottomScrollRequest) { _, _ in
              scrollToBottom(proxy, animated: false)
            }
          }
        }
      }
    }
    .navigationTitle(headerTitle)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar(.hidden, for: .tabBar)
    .toolbar {
      ToolbarItemGroup(placement: .topBarTrailing) {
        Button {
          workspaceViewModel.activeChat = nil
          draft = ""
          composerFocused = true
        } label: {
          Image(systemName: "square.and.pencil")
        }
        .accessibilityLabel("New thread")

        Menu {
          Button {
            Task { await showPetOnGlasses() }
          } label: {
            Label("Show pet on glasses", systemImage: "eyeglasses")
          }

          Button(role: .destructive) {
            Task { await workspaceViewModel.interruptActiveTurn() }
          } label: {
            Label("Stop response", systemImage: "stop.fill")
          }
          .disabled(!isStreaming)
        } label: {
          Image(systemName: "ellipsis")
        }
        .accessibilityLabel("More")
      }
    }
    .safeAreaInset(edge: .bottom) {
      VStack(spacing: 8) {
        if isStreaming {
          thinkingRow
            .padding(.horizontal, 20)
        }
        composer
      }
    }
    .task(id: chat?.id ?? "new") {
      selectedProjectID = defaultProjectID
      selectedModelID = defaultModelID
      if let chat {
        await workspaceViewModel.loadChat(chat)
      } else {
        workspaceViewModel.activeChat = nil
        composerFocused = true
      }
      bottomScrollRequest &+= 1
      await showChatOnGlasses()
    }
    .sheet(item: $selectedFile) { file in
      CodexFilePreviewSheet(file: file)
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
    }
    .alert("Voice input", isPresented: voiceAlertIsPresented) {
      Button("OK") {
        voiceAlertMessage = nil
      }
    } message: {
      Text(voiceAlertMessage ?? "Voice input is unavailable.")
    }
    .alert("Glasses display", isPresented: displayErrorIsPresented) {
      Button("OK") {
        displayViewModel.errorMessage = nil
      }
    } message: {
      Text(displayViewModel.errorMessage ?? "The glasses did not accept that display update.")
    }
  }

  private var headerTitle: String {
    activeChat?.title ?? chat?.title ?? "New thread"
  }

  private var headerSubtitle: String {
    if let activeChat {
      return "\(displayProjectName(path: activeChat.projectPath, fallback: activeChat.projectName)) • \(hostName)"
    }
    if let chat {
      return "\(displayProjectName(path: chat.projectPath, fallback: chat.projectName)) • \(hostName)"
    }
    return ""
  }

  private var loadingMessages: some View {
    VStack(spacing: 14) {
      ProgressView()
        .controlSize(.large)
      Text("Loading messages...")
        .font(.headline)
        .foregroundStyle(.secondary)
    }
  }

  @ViewBuilder
  private func topAlignedChatSubview<Content: View>(@ViewBuilder content: () -> Content) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      content()
        .frame(maxWidth: .infinity, alignment: .top)
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 22)
    .padding(.top, 14)
    .padding(.bottom, 22)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .contentShape(Rectangle())
    .onTapGesture {
      composerFocused = false
    }
  }

  private var newThreadPrompt: some View {
    VStack(spacing: 12) {
      if isNewThread {
        Text("What should we work on?")
          .font(.largeTitle.weight(.regular))
          .multilineTextAlignment(.center)
      } else {
        Text("No messages yet")
          .font(.title2.weight(.semibold))
      }

      Menu {
        projectMenuItems
      } label: {
        HStack(spacing: 8) {
          Image(systemName: "folder")
          Text(selectedProjectName)
          Image(systemName: "chevron.up.chevron.down")
            .font(.caption.weight(.semibold))
        }
        .font(.title2.weight(.regular))
        .foregroundStyle(.secondary)
      }
      .disabled(workspaceViewModel.projects.isEmpty)

      if !isNewThread {
        Text("Use the composer below to continue this thread.")
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }
    }
    .frame(maxWidth: .infinity)
  }

  private var thinkingRow: some View {
    HStack(spacing: 10) {
      Text(workspaceViewModel.petState == .thinking ? "Codex is thinking" : "Codex is working")
        .font(.subheadline.weight(.medium))
        .foregroundStyle(.secondary)
      Spacer(minLength: 8)
      TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { context in
        Image(systemName: "arrow.triangle.2.circlepath")
          .font(.subheadline.weight(.semibold))
          .rotationEffect(.degrees(thinkingRotationAngle(at: context.date)))
      }
      .frame(width: 18, height: 18)
    }
    .padding(.horizontal, 14)
    .frame(height: 42)
    .background(.ultraThinMaterial, in: Capsule())
    .overlay {
      Capsule()
        .stroke(Color.white.opacity(0.7), lineWidth: 1)
    }
    .shadow(color: .black.opacity(0.08), radius: 18, y: 8)
  }

  private var composer: some View {
    Group {
      if composerIsExpanded {
        expandedComposer
      } else {
        collapsedComposer
      }
    }
    .animation(.snappy(duration: 0.2), value: composerIsExpanded)
  }

  private var composerIsExpanded: Bool {
    composerFocused
      || !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || transcriptionViewModel.isRecording
      || transcriptionViewModel.isTranscribing
      || !isTransportConnected
  }

  private var collapsedComposer: some View {
    HStack(spacing: 16) {
      Button {} label: {
        Image(systemName: "plus")
          .font(.title2.weight(.regular))
      }
      .disabled(true)
      .accessibilityLabel("Add")

      Text("Ask Codex")
        .font(.body)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture {
          composerFocused = true
        }

      Button {
        toggleDictation()
      } label: {
        Image(systemName: "mic")
          .font(.title2.weight(.semibold))
      }
      .disabled(transcriptionViewModel.isTranscribing)
      .accessibilityLabel("Dictate")
    }
    .foregroundStyle(.black)
    .padding(.horizontal, 20)
    .frame(height: 64)
    .background(.ultraThinMaterial, in: Capsule())
    .overlay {
      Capsule()
        .stroke(Color.white.opacity(0.75), lineWidth: 1)
    }
    .shadow(color: .black.opacity(0.12), radius: 24, y: 10)
    .padding(.horizontal, 20)
    .padding(.bottom, 10)
  }

  private var expandedComposer: some View {
    VStack(spacing: 6) {
      VStack(alignment: .leading, spacing: 12) {
        TextField("Ask Codex", text: $draft, axis: .vertical)
          .font(.body)
          .lineLimit(1...5)
          .focused($composerFocused)
          .disabled(!isTransportConnected)

        HStack(spacing: 18) {
          Button {} label: {
            Image(systemName: "plus")
              .font(.title2.weight(.regular))
          }
          .disabled(true)
          .accessibilityLabel("Add")

          Spacer()

          modelSettingsMenu

          Button {
            toggleDictation()
          } label: {
            Image(systemName: transcriptionViewModel.isRecording ? "stop.circle.fill" : "mic")
              .font(.title2.weight(.semibold))
              .foregroundStyle(transcriptionViewModel.isRecording ? .red : .black)
          }
          .disabled(transcriptionViewModel.isTranscribing)
          .accessibilityLabel("Dictate")

          if isStreaming {
            Button {
              Task { await workspaceViewModel.interruptActiveTurn() }
            } label: {
              Image(systemName: "stop.fill")
                .font(.headline.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(Color.black, in: Circle())
            }
            .accessibilityLabel("Stop")
          } else {
            Button {
              sendDraft()
            } label: {
              Image(systemName: "arrow.up")
                .font(.headline.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(canSend ? Color.black : Color.black.opacity(0.12), in: Circle())
            }
            .disabled(!canSend)
            .accessibilityLabel("Send")
          }
        }
        .foregroundStyle(.black)
      }
      .padding(.horizontal, 18)
      .padding(.vertical, 16)
      .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 28, style: .continuous))
      .overlay {
        RoundedRectangle(cornerRadius: 28, style: .continuous)
          .stroke(Color.white.opacity(0.75), lineWidth: 1)
      }
      .shadow(color: .black.opacity(0.08), radius: 30, y: 12)

      if !isTransportConnected {
        Text("Codex is disconnected")
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.horizontal, 18)
      }

      if let voiceStatusText {
        Text(voiceStatusText)
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.horizontal, 18)
      }
    }
    .padding(.horizontal, 20)
    .padding(.bottom, 10)
  }

  private var modelSettingsMenu: some View {
    Menu {
      Section("Intelligence") {
        ForEach(["Low", "Medium", "High", "Extra High"], id: \.self) { option in
          Button {
            intelligence = option
          } label: {
            if intelligence == option {
              Label(option, systemImage: "checkmark")
            } else {
              Text(option)
            }
          }
        }
      }

      Section("Model") {
        ForEach(workspaceViewModel.models) { model in
          Button {
            selectedModelID = model.id
          } label: {
            if selectedModelID == model.id {
              Label(model.displayName, systemImage: "checkmark")
            } else {
              Text(model.displayName)
            }
          }
        }
      }

      Section("Speed") {
        ForEach(["Standard", "Fast"], id: \.self) { option in
          Button {
            speed = option
          } label: {
            if speed == option {
              Label(option, systemImage: "checkmark")
            } else {
              Text(option)
            }
          }
        }
      }

      Section("Pet") {
        ForEach(CodexPet.builtIns) { pet in
          Button {
            workspaceViewModel.selectedPet = pet
          } label: {
            if workspaceViewModel.selectedPet == pet {
              Label(pet.displayName, systemImage: "checkmark")
            } else {
              Text(pet.displayName)
            }
          }
        }
      }
    } label: {
      HStack(spacing: 6) {
        Image(systemName: "bolt.fill")
        Text(selectedModelShortName)
      }
      .font(.subheadline.weight(.semibold))
    }
    .accessibilityLabel("Model and thinking")
  }

  @ViewBuilder
  private var projectMenuItems: some View {
    Button {
      selectedProjectID = ""
    } label: {
      Label("No project", systemImage: selectedProjectID.isEmpty ? "checkmark" : "bubble.left")
    }

    if !workspaceViewModel.projects.isEmpty {
      Divider()
    }

    ForEach(workspaceViewModel.projects) { project in
      Button {
        selectedProjectID = project.id
      } label: {
        Label(project.name, systemImage: selectedProjectID == project.id ? "checkmark" : "folder")
      }
    }
  }

  private var canSend: Bool {
    isTransportConnected && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }

  private var voiceAlertIsPresented: Binding<Bool> {
    Binding {
      voiceAlertMessage != nil
    } set: { isPresented in
      if !isPresented {
        voiceAlertMessage = nil
      }
    }
  }

  private var displayErrorIsPresented: Binding<Bool> {
    Binding {
      displayViewModel.errorMessage != nil
    } set: { isPresented in
      if !isPresented {
        displayViewModel.errorMessage = nil
      }
    }
  }

  private var voiceStatusText: String? {
    if transcriptionViewModel.isRecording {
      return "Listening with \(transcriptionViewModel.activeInputName)"
    }
    if transcriptionViewModel.isTranscribing {
      return "Transcribing voice"
    }
    return nil
  }

  private var defaultProjectID: String {
    if let chat, let projectPath = knownProjectID(for: chat.projectPath) {
      return projectPath
    }
    if let activeChat, let projectPath = knownProjectID(for: activeChat.projectPath) {
      return projectPath
    }
    return ""
  }

  private var defaultModelID: String {
    workspaceViewModel.models.first(where: \.isDefault)?.id ?? workspaceViewModel.models.first?.id ?? "gpt-5.5"
  }

  private var selectedProject: CodexProjectPreview? {
    workspaceViewModel.projects.first { $0.id == selectedProjectID }
  }

  private var selectedProjectName: String {
    if let selectedProject {
      return selectedProject.name
    }
    if let chat {
      return displayProjectName(path: chat.projectPath, fallback: chat.projectName)
    }
    if let activeChat {
      return displayProjectName(path: activeChat.projectPath, fallback: activeChat.projectName)
    }
    return "No project"
  }

  private var selectedProjectPath: String? {
    selectedProject?.path
  }

  private var knownProjectIdentifiers: Set<String> {
    codexProjectIdentifiers(from: workspaceViewModel.projects)
  }

  private func knownProjectID(for projectPath: String?) -> String? {
    guard let projectPath = codexNormalizedProjectIdentifier(projectPath), knownProjectIdentifiers.contains(projectPath) else {
      return nil
    }
    return projectPath
  }

  private func displayProjectName(path: String?, fallback: String) -> String {
    knownProjectID(for: path) == nil ? "No project" : fallback
  }

  private var selectedModelShortName: String {
    let model = workspaceViewModel.models.first { $0.id == selectedModelID }
    let name = model?.displayName ?? selectedModelID
    return name
      .replacingOccurrences(of: "GPT-", with: "")
      .replacingOccurrences(of: "Codex", with: "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func scrollToBottom(_ proxy: ScrollViewProxy, animated: Bool) {
    Task { @MainActor in
      await scrollToBottomAfterLayout(proxy, animated: animated)
    }
  }

  @MainActor
  private func scrollToBottomAfterLayout(_ proxy: ScrollViewProxy, animated: Bool) async {
    await Task.yield()
    performScrollToBottom(proxy, animated: animated)
    try? await Task.sleep(nanoseconds: 120_000_000)
    performScrollToBottom(proxy, animated: false)
    try? await Task.sleep(nanoseconds: 260_000_000)
    performScrollToBottom(proxy, animated: false)
  }

  private func performScrollToBottom(_ proxy: ScrollViewProxy, animated: Bool) {
    if animated {
      withAnimation(.snappy(duration: 0.25)) {
        proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
      }
    } else {
      proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
    }
  }

  private func messageScrollSignature(_ message: CodexChatMessage) -> String {
    [
      message.id,
      "\(message.deliveryState)",
      message.parts.map(partScrollSignature).joined(separator: ","),
    ].joined(separator: "=")
  }

  private func partScrollSignature(_ part: CodexMessagePart) -> String {
    switch part {
    case .text(let id, let text), .reasoning(let id, let text):
      return "\(id):\(text.count)"
    case .tool(let tool):
      return "\(tool.id):\(tool.status):\(tool.detail.count)"
    case .fileGroup(let group):
      return "\(group.id):\(group.files.count)"
    case .file(let file):
      return "\(file.id):\(file.detail.count):\(file.diff?.count ?? 0)"
    case .todos(let id, let items):
      return "\(id):\(items.map { "\($0.id)-\($0.isDone)" }.joined(separator: ","))"
    }
  }

  private func thinkingRotationAngle(at date: Date) -> Double {
    let duration = 1.05
    let progress = date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: duration) / duration
    return progress * 360
  }

  private func messageView(_ message: CodexChatMessage) -> some View {
    VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 8) {
      ForEach(message.parts) { part in
        partView(part, role: message.role)
      }
      deliveryStateView(message.deliveryState)
    }
    .frame(maxWidth: .infinity, alignment: message.role == .user ? .trailing : .leading)
  }

  @ViewBuilder
  private func deliveryStateView(_ state: CodexChatMessage.DeliveryState) -> some View {
    switch state {
    case .sent:
      EmptyView()
    case .sending:
      HStack(spacing: 6) {
        ProgressView()
          .controlSize(.mini)
        Text("Sending")
      }
      .font(.caption2)
      .foregroundStyle(.secondary)
    case .failed:
      Label("Send failed", systemImage: "exclamationmark.circle.fill")
        .font(.caption2.weight(.semibold))
        .foregroundStyle(.red)
    }
  }

  @ViewBuilder
  private func partView(_ part: CodexMessagePart, role: CodexChatMessage.Role) -> some View {
    switch part {
    case .text(_, let text):
      CodexMarkdownText(markdown: text) { path in
        openLinkedFile(path)
      }
        .font(.callout)
        .foregroundStyle(.primary)
        .padding(.horizontal, role == .user ? 12 : 0)
        .padding(.vertical, role == .user ? 8 : 1)
        .background(role == .user ? Color(.systemGray6) : Color.clear, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .frame(maxWidth: role == .user ? 320 : .infinity, alignment: role == .user ? .trailing : .leading)

    case .reasoning(_, let text):
      DisclosureGroup {
        CodexMarkdownText(markdown: text)
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      } label: {
        Text("Thinking")
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      .padding(.vertical, 4)

    case .tool(let tool):
      DisclosureGroup {
        Text(tool.detail)
          .font(.system(.caption, design: .monospaced))
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      } label: {
        Label(tool.name, systemImage: tool.status == "completed" ? "checkmark.circle" : "hammer")
          .font(.subheadline.weight(.semibold))
      }
      .padding(12)
      .background(Color(.systemGray6), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

    case .fileGroup(let group):
      CodexFileChangeCard(group: group) { file in
        Task { await openFile(file) }
      }

    case .file(let file):
      Button {
        Task { await openFile(file) }
      } label: {
        filePreview(file)
      }
      .buttonStyle(.plain)

    case .todos(_, let items):
      VStack(alignment: .leading, spacing: 9) {
        ForEach(items) { item in
          HStack(alignment: .top, spacing: 9) {
            Image(systemName: item.isDone ? "checkmark.circle.fill" : "circle")
              .foregroundStyle(item.isDone ? .green : .secondary)
            Text(item.title)
              .strikethrough(item.isDone)
              .foregroundStyle(item.isDone ? .secondary : .primary)
          }
          .font(.subheadline)
        }
      }
      .padding(12)
      .background(Color(.systemGray6), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
  }

  private func filePreview(_ file: CodexFilePreview) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(spacing: 7) {
        Image(systemName: "doc.text")
          .font(.caption2)
          .foregroundStyle(.secondary)
        Text(file.path)
          .font(.caption2.weight(.semibold))
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }

      if let editPreview = file.editPreview {
        fileEditPreview(editPreview)
      } else {
        Text(file.detail)
          .font(.caption2)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(12)
    .background(Color(.systemGray6), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
  }

  private func openLinkedFile(_ rawPath: String) {
    let resolvedPath = resolveLinkedFilePath(rawPath)
    Task {
      await openFile(CodexFilePreview(
        id: "linked-\(resolvedPath)",
        path: resolvedPath,
        detail: "Linked file"
      ))
    }
  }

  private func resolveLinkedFilePath(_ rawPath: String) -> String {
    let path = rawPath.removingPercentEncoding ?? rawPath
    if path.hasPrefix("/") || path.hasPrefix("~") {
      return path
    }
    if let projectPath = selectedProjectPath ?? chat?.projectPath ?? activeChat?.projectPath {
      return URL(fileURLWithPath: projectPath).appendingPathComponent(path).path
    }
    return path
  }

  @ViewBuilder
  private func fileEditPreview(_ editPreview: CodexFileEditPreview) -> some View {
    if editPreview.shouldShowCountsOnly {
      HStack(spacing: 10) {
        if editPreview.addedLineCount > 0 {
          Text("+\(editPreview.addedLineCount)")
            .foregroundStyle(.green)
        }

        if editPreview.removedLineCount > 0 {
          Text("-\(editPreview.removedLineCount)")
            .foregroundStyle(.red)
        }

        Text("lines edited")
          .foregroundStyle(.secondary)
      }
      .font(.caption.weight(.semibold).monospacedDigit())
    } else {
      VStack(alignment: .leading, spacing: 3) {
        ForEach(editPreview.previewLines) { line in
          HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(line.kind.prefix)
              .foregroundStyle(line.kind == .added ? .green : .red)
              .frame(width: 10, alignment: .leading)

            Text(line.text.isEmpty ? " " : line.text)
              .foregroundStyle(.primary)
              .lineLimit(1)
              .truncationMode(.tail)
          }
          .font(.system(.caption2, design: .monospaced))
        }
      }
    }
  }

  private func sendDraft() {
    let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
    guard canSend else {
      return
    }
    draft = ""
    composerFocused = false
    Task {
      do {
        try await workspaceViewModel.sendMessage(
          text: text,
          threadID: chat?.id ?? activeChat?.id,
          cwd: selectedProjectPath,
          model: selectedModelID.isEmpty ? nil : selectedModelID
        )
      } catch {
        workspaceViewModel.errorMessage = error.localizedDescription
      }
      await MainActor.run {
        bottomScrollRequest &+= 1
      }
      await refreshChatOnGlasses()
    }
  }

  private func toggleDictation() {
    Task {
      do {
        if transcriptionViewModel.isRecording {
          let authTokens = try? await authViewModel.appServerAuthTokens()
          let transcript = try await transcriptionViewModel.stopAndTranscribe(codexAuthTokens: authTokens)
          appendTranscript(transcript)
          if activeChat?.isStreaming != true {
            workspaceViewModel.petState = .idle
          }
        } else {
          try await transcriptionViewModel.startRecording()
          workspaceViewModel.petState = .recording
        }
        await refreshChatOnGlasses()
      } catch {
        if activeChat?.isStreaming != true {
          workspaceViewModel.petState = .idle
        }
        transcriptionViewModel.cancelRecording()
        voiceAlertMessage = error.localizedDescription
      }
    }
  }

  private func appendTranscript(_ transcript: String) {
    let text = transcript.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !text.isEmpty else {
      return
    }

    if draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      draft = text
    } else {
      draft += " \(text)"
    }
    composerFocused = true
  }

  private func openFile(_ file: CodexFilePreview) async {
    let content = await workspaceViewModel.readFile(path: file.path) ?? file.detail
    selectedFile = CodexViewedFile(path: file.path, content: content, detail: file.detail, diff: file.diff)
  }

  private func refreshChatOnGlasses() async {
    await showChatOnGlasses()
  }
}

private struct CodexViewedFile: Identifiable {
  var id: String { path }
  var path: String
  var content: String
  var detail: String
  var diff: String?

  var title: String {
    URL(fileURLWithPath: path).lastPathComponent
  }

  var subtitle: String {
    path
  }

  var previewText: String {
    diff ?? content
  }

  var isPreviewSupported: Bool {
    if diff != nil {
      return true
    }
    let supportedExtensions: Set<String> = [
      "c", "cc", "cpp", "css", "go", "h", "hpp", "html", "js", "json", "jsx",
      "m", "md", "mm", "py", "rb", "rs", "sh", "swift", "toml", "ts", "tsx",
      "txt", "xml", "yaml", "yml",
    ]
    let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
    return ext.isEmpty || supportedExtensions.contains(ext)
  }
}

private struct CodexFilePreviewSheet: View {
  var file: CodexViewedFile
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      VStack(alignment: .leading, spacing: 0) {
        VStack(alignment: .leading, spacing: 6) {
          Text(file.title)
            .font(.headline)
            .lineLimit(1)
            .truncationMode(.middle)

          Text(file.subtitle)
            .font(.caption2)
            .foregroundStyle(.secondary)
            .lineLimit(2)
            .truncationMode(.middle)
        }
        .padding(.horizontal, 18)
        .padding(.top, 12)
        .padding(.bottom, 10)

        Divider()

        if file.isPreviewSupported {
          ScrollView {
            Text(file.previewText)
              .font(.system(.footnote, design: .monospaced))
              .frame(maxWidth: .infinity, alignment: .leading)
              .textSelection(.enabled)
              .padding(18)
          }
        } else {
          ContentUnavailableView(
            "Preview unavailable",
            systemImage: "doc",
            description: Text(file.detail)
          )
          .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .navigationTitle("File")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) {
          Button("Done") {
            dismiss()
          }
        }
      }
    }
  }
}

private struct CodexFileChangeCard: View {
  var group: CodexFileChangeGroup
  var openFile: (CodexFilePreview) -> Void

  @State private var isExpanded = true

  var body: some View {
    VStack(spacing: 0) {
      Button {
        withAnimation(.snappy(duration: 0.18)) {
          isExpanded.toggle()
        }
      } label: {
        HStack(spacing: 12) {
          Text("\(group.files.count) \(group.files.count == 1 ? "file" : "files") changed")
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.primary)

          diffCounts(added: group.addedLineCount, removed: group.removedLineCount)

          Spacer()

          Image(systemName: "chevron.down")
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(isExpanded ? 0 : -90))
        }
        .padding(.horizontal, 16)
        .frame(height: 54)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)

      if isExpanded {
        Divider()

        ForEach(Array(group.files.enumerated()), id: \.element.id) { index, file in
          Button {
            openFile(file)
          } label: {
            HStack(spacing: 12) {
              Text(displayPath(file.path))
                .font(.subheadline)
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.middle)

              Spacer(minLength: 10)

              diffCounts(
                added: file.editPreview?.addedLineCount ?? 0,
                removed: file.editPreview?.removedLineCount ?? 0
              )
            }
            .padding(.horizontal, 16)
            .frame(height: 48)
            .contentShape(Rectangle())
          }
          .buttonStyle(.plain)

          if index < group.files.count - 1 {
            Divider()
          }
        }
      }
    }
    .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    .overlay {
      RoundedRectangle(cornerRadius: 18, style: .continuous)
        .stroke(Color(.separator).opacity(0.35), lineWidth: 1)
    }
    .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
  }

  private func diffCounts(added: Int, removed: Int) -> some View {
    HStack(spacing: 4) {
      Text("+\(added)")
        .foregroundStyle(.green)
      Text("-\(removed)")
        .foregroundStyle(.red)
    }
    .font(.subheadline.weight(.semibold).monospacedDigit())
    .fixedSize()
  }

  private func displayPath(_ path: String) -> String {
    if path.count <= 42 {
      return path
    }
    return "..." + String(path.suffix(39))
  }
}

private struct CodexMarkdownText: View {
  let markdown: String
  var openFile: ((String) -> Void)? = nil

  var body: some View {
    if let attributed = attributedMarkdown {
      Text(attributed)
        .environment(\.openURL, OpenURLAction { url in
          if let filePath = filePath(from: url), let openFile {
            openFile(filePath)
            return .handled
          }
          return .systemAction
        })
    } else {
      Text(markdown)
    }
  }

  private var attributedMarkdown: AttributedString? {
    let normalized = markdown.replacingOccurrences(of: "\r\n", with: "\n")
    if let full = try? AttributedString(
      markdown: normalized,
      options: AttributedString.MarkdownParsingOptions(interpretedSyntax: .full)
    ) {
      return full
    }

    return try? AttributedString(
      markdown: normalized,
      options: AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
    )
  }

  private func filePath(from url: URL) -> String? {
    if url.isFileURL {
      return url.path
    }

    let scheme = url.scheme?.lowercased()
    if scheme == "sandbox" || scheme == "codex-file" {
      return url.path.removingPercentEncoding
    }
    if scheme == nil || scheme == "" {
      return url.path.isEmpty ? url.absoluteString : url.path
    }
    if scheme == "http" || scheme == "https" || scheme == "mailto" {
      return nil
    }

    let raw = url.absoluteString.removingPercentEncoding ?? url.absoluteString
    guard raw.contains("/") || raw.contains(".") else {
      return nil
    }
    return raw
  }
}

private struct CodexPetSpriteView: View {
  let pet: CodexPet
  let state: CodexPetVisualState
  var isAnimationEnabled = true

  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  @State private var frameIndex = 0

  private let columns: CGFloat = 8
  private let rows: CGFloat = 9
  private let frameAspect: CGFloat = 192.0 / 208.0

  private var animation: CodexPetAnimation {
    CodexPetAnimation.animation(for: state)
  }

  private var activeFrame: CodexPetFrame {
    let frames = animation.frames
    guard !frames.isEmpty else {
      return CodexPetFrame(row: 0, column: 0, duration: 1)
    }
    return frames[min(frameIndex, frames.count - 1)]
  }

  var body: some View {
    GeometryReader { proxy in
      let width = min(proxy.size.width, proxy.size.height * frameAspect)
      let height = width / frameAspect
      let frame = activeFrame

      Image(pet.imageName)
        .resizable()
        .interpolation(.none)
        .antialiased(false)
        .frame(width: width * columns, height: height * rows, alignment: .topLeading)
        .offset(x: -width * CGFloat(frame.column), y: -height * CGFloat(frame.row))
        .frame(width: width, height: height, alignment: .topLeading)
        .clipped()
        .position(x: proxy.size.width / 2, y: proxy.size.height / 2)
    }
    .aspectRatio(frameAspect, contentMode: .fit)
    .accessibilityLabel(pet.displayName)
    .task(id: "\(pet.id)-\(state.rawValue)-\(isAnimationEnabled)-\(reduceMotion)") {
      await animate()
    }
  }

  private func animate() async {
    let animation = animation
    let shouldAnimate = isAnimationEnabled && !reduceMotion
    let frames = shouldAnimate ? animation.frames : Array(animation.frames.prefix(1))
    guard frames.count > 1 else {
      await MainActor.run { frameIndex = 0 }
      return
    }

    var index = 0
    await MainActor.run { frameIndex = 0 }

    while !Task.isCancelled {
      let frame = frames[min(index, frames.count - 1)]
      try? await Task.sleep(nanoseconds: UInt64(max(frame.duration, 0.01) * 1_000_000_000))
      if Task.isCancelled {
        return
      }

      let next = index + 1
      if next >= frames.count, let loopStartIndex = animation.loopStartIndex, loopStartIndex < frames.count {
        index = loopStartIndex
      } else if next >= frames.count {
        return
      } else {
        index = next
      }

      await MainActor.run {
        frameIndex = index
      }
    }
  }
}
