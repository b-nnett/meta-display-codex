import Foundation
import MWDATDisplay

enum CodexDisplayAppGlasses {
  private static let initialVisibleChatMessageLimit = 4

  static func app(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    switch CodexDisplayAppScreen(rawValue: state.screen) ?? .home {
    case .home:
      return home(state: state, onAction: onAction)
    case .project:
      return project(state: state, onAction: onAction)
    case .chat:
      return chat(state: state, onAction: onAction)
    case .chatActions:
      return chatActionsScreen(state: state, onAction: onAction)
    case .file:
      return filePreview(state: state, onAction: onAction)
    case .modelPicker:
      return modelPicker(state: state, onAction: onAction)
    case .pet:
      return pet(state: state, onAction: onAction)
    }
  }

  private static func home(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let pinnedChats = state.chats.filter(\.pinned)
    let visiblePinnedChats = state.showAllPinnedChats ? pinnedChats : Array(pinnedChats.prefix(3))
    let recentChats = state.chats.filter { $0.projectId == nil && !$0.pinned }
    let visibleRecentChats = state.showAllChats ? recentChats : Array(recentChats.prefix(5))
    let visibleProjects = state.showAllProjects ? state.projects : Array(state.projects.prefix(5))

    return root {
      header(title: "Codex", subtitle: state.host.name) {
        onAction(.newChat(projectID: nil))
      } petAction: {
        onAction(.setMode(.pet))
      }

      if !pinnedChats.isEmpty {
        sectionTitle("Pinned")
        for chat in visiblePinnedChats {
          chatRow(chat) {
            onAction(.openChat(chatID: chat.id))
          }
        }
        if pinnedChats.count > 3 {
          Button(
            label: state.showAllPinnedChats ? "Show fewer pinned" : "Show all pinned",
            style: .secondary,
            iconName: state.showAllPinnedChats ? .caretUp : .caretDown
          ) {
            onAction(.setShowAllPinnedChats(!state.showAllPinnedChats))
          }
        }
      }

      sectionTitle("Projects")
      if state.projects.isEmpty {
        empty("No projects")
      } else {
        for project in visibleProjects {
          projectRow(project) {
            onAction(.openProject(projectID: project.id))
          }
        }
        if state.projects.count > 5 {
          Button(
            label: state.showAllProjects ? "Show fewer projects" : "Show all projects",
            style: .secondary,
            iconName: state.showAllProjects ? .caretUp : .caretDown
          ) {
            onAction(.setShowAllProjects(!state.showAllProjects))
          }
        }
      }

      sectionTitle("Recent chats")
      if visibleRecentChats.isEmpty {
        empty("No recent chats")
      } else {
        for chat in visibleRecentChats {
          chatRow(chat) {
            onAction(.openChat(chatID: chat.id))
          }
        }
        if recentChats.count > 5 {
          Button(
            label: state.showAllChats ? "Show less" : "Show more",
            style: .secondary,
            iconName: state.showAllChats ? .caretUp : .caretDown
          ) {
            onAction(.setShowAllChats(!state.showAllChats))
          }
        }
      }
    }
  }

  private static func project(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let project = selectedProject(state)
    let chats = state.chats.filter { chat in
      guard let project else { return false }
      return project.chats.contains(chat.id)
    }
    let visibleChats = state.showAllProjectChats ? chats : Array(chats.prefix(7))

    return root {
      backHeader(
        title: project?.name ?? "Project",
        subtitle: project.map { "\($0.chats.count) chats" } ?? ""
      ) {
        onAction(.setScreen(.home))
      } trailing: {
        onAction(.newChat(projectID: project?.id))
      } petAction: {
        onAction(.setMode(.pet))
      }

      if chats.isEmpty {
        empty("No chats in this project")
      } else {
        for chat in visibleChats {
          chatRow(chat) {
            onAction(.openChat(chatID: chat.id))
          }
        }
        if chats.count > 7 {
          Button(
            label: state.showAllProjectChats ? "Show fewer chats" : "Show all chats",
            style: .secondary,
            iconName: state.showAllProjectChats ? .caretUp : .caretDown
          ) {
            onAction(.setShowAllProjectChats(!state.showAllProjectChats))
          }
        }
      }
    }
  }

  private static func chat(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let selectedChat = currentChat(state)
    let messages = selectedChat.flatMap { state.messagesByChat[$0.id] } ?? []
    let visibleMessages = bottomVisibleMessages(messages, showAll: state.showAllMessages)
    let renderedMessages = Array(visibleMessages.reversed())
    let hiddenLoadedMessageCount = max(messages.count - visibleMessages.count, 0)
    let isFailed = state.pet.state == CodexPetVisualState.failed.rawValue
    let hasAssistantText = hasAssistantText(in: visibleMessages)
    let isActive = selectedChat?.active == true || messages.contains { $0.streaming == true }
    let shouldShowThinking = state.pet.state == CodexPetVisualState.thinking.rawValue || (isActive && !hasAssistantText)
    let transcript = state.transcriptPreview.trimmingCharacters(in: .whitespacesAndNewlines)
    let isRecording = state.pet.state == CodexPetVisualState.recording.rawValue

    if state.isTranscribing {
      return transcriptionScreen(state: state)
    }

    if isRecording {
      return recordingScreen(state: state, chat: selectedChat, onAction: onAction)
    }

    if !transcript.isEmpty {
      return transcriptPreviewScreen(state: state, chat: selectedChat, transcript: transcript, onAction: onAction)
    }

    let subtitle: String
    if let selectedChat, selectedChat.projectId != nil {
      subtitle = selectedChat.projectName
    } else {
      subtitle = ""
    }

    return root {
      chatHeader(
        title: selectedChat?.title ?? "New chat",
        subtitle: subtitle
      ) {
        if selectedChat?.projectId != nil {
          onAction(.setScreen(.project))
        } else {
          onAction(.setScreen(.home))
        }
      } moreAction: {
        onAction(.setScreen(.chatActions))
      } dictateAction: {
        onAction(.startTranscription(chatID: selectedChat?.id))
      } petAction: {
        onAction(.setMode(.pet))
      }

      if isFailed {
        chatFailureRow()
      } else if shouldShowThinking {
        thinkingActivityRow()
      }

      if !state.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        composer(state: state, chat: selectedChat, onAction: onAction)
      }

      if visibleMessages.isEmpty {
        empty("Ask Codex to start this chat")
      } else {
        for message in renderedMessages {
          messageCard(message, onAction: onAction)
        }

        if hiddenLoadedMessageCount > 0 {
          Button(
            label: "\(hiddenLoadedMessageCount) previous messages",
            style: .secondary,
            iconName: .caretUp
          ) {
            onAction(.setShowAllMessages(true))
          }
        } else if state.hasOlderMessages {
          Button(label: "Previous messages", style: .secondary, iconName: .caretUp) {
            onAction(.loadOlderTurns)
          }
        }
      }
    }
  }

  private static func chatActionsScreen(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let selectedChat = currentChat(state)
    let selectedModel = selectedModel(state)

    return root {
      simpleBackHeader(title: "Chat menu", subtitle: selectedChat?.title ?? "") {
        onAction(.setScreen(.chat))
      }

      Button(label: "Model", style: .secondary, iconName: .slidersHorizontal) {
        onAction(.setScreen(.modelPicker))
      }
      if let selectedModel {
        Text(modelControlLabel(selectedModel), style: .meta, color: .secondary)
      }

      if let selectedChat {
        Button(
          label: selectedChat.pinned ? "Unpin" : "Pin",
          style: .secondary,
          iconName: selectedChat.pinned ? .x : .star
        ) {
          onAction(.togglePinned(chatID: selectedChat.id))
          onAction(.setScreen(.chat))
        }
        Button(label: "Archive", style: .outline, iconName: .containerWithLid) {
          onAction(.archiveChat(chatID: selectedChat.id))
        }
      } else {
        empty("No chat selected")
      }
    }
  }

  private static func modelPicker(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let selectedModel = selectedModel(state)

    return root {
      simpleBackHeader(title: "Model", subtitle: selectedModel?.name ?? "") {
        onAction(.setScreen(.chat))
      }

      if state.models.isEmpty {
        empty("No models loaded")
      } else {
        for model in state.models {
          modelOptionRow(
            model: model,
            selected: model.id == selectedModel?.id
          ) {
            onAction(.setModel(modelID: model.id))
            onAction(.setScreen(.chat))
          }
        }
      }
    }
  }

  private static func recordingScreen(
    state: CodexDisplayAppState,
    chat: CodexDisplayAppChat?,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    root {
      Text("Dictating", style: .heading)
      waveform(level: state.audioLevel ?? 0)
        .alignSelf(.center)
      FlexBox(direction: .row, spacing: 8, alignment: .center, crossAlignment: .center) {
        Button(label: "Finished", style: .primary, iconName: .checkmark) {
          onAction(.startTranscription(chatID: chat?.id ?? state.selectedChatId))
        }
      }
      .alignSelf(.center)
    }
  }

  private static func transcriptionScreen(state _: CodexDisplayAppState) -> FlexBox {
    root {
      Text("Transcribing", style: .heading)
      waveform(level: 0.35)
        .alignSelf(.center)
    }
  }

  private static func transcriptPreviewScreen(
    state: CodexDisplayAppState,
    chat: CodexDisplayAppChat?,
    transcript: String,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    root {
      Text("Transcript", style: .heading)
      Text(cleaned(transcript), style: .body)
      Button(label: "Send", style: .primary, iconName: .paperAirplane) {
        onAction(.sendMessage(
          chatID: chat?.id ?? state.selectedChatId,
          projectID: chat?.projectId ?? state.selectedProjectId,
          text: transcript
        ))
      }
    }
  }

  private static func filePreview(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let file = state.selectedFile
    let preview = file?.diff ?? file?.content ?? file?.detail ?? "No preview available."
    let added = file?.added ?? 0
    let removed = file?.removed ?? 0
    let editedCount = added + removed
    let diffLines = file?.diff.map(diffPreviewLines) ?? []
    let path = file?.path ?? ""

    return root {
      backHeader(title: file?.title ?? "File", subtitle: shortPath(path)) {
        onAction(.setScreen(.chat))
      } trailing: {
        onAction(.setScreen(.chat))
      } petAction: {
        onAction(.setMode(.pet))
      }

      FlexBox(direction: .column, spacing: 8) {
        Text(file?.title ?? "File", style: .heading)
        if !path.isEmpty {
          Text(shortPath(path), style: .meta, color: .secondary)
        }
        if editedCount > 0 {
          Text("+\(added) -\(removed)", style: .body)
        }
        if editedCount > 5 {
          Text("\(editedCount) lines edited", style: .body)
        } else if !diffLines.isEmpty {
          for line in diffLines.prefix(5) {
            Text("\(line.prefix) \(line.text)", style: .body)
          }
        } else {
          Text(clamp(preview, maxLength: 420), style: .body)
        }
      }
      .padding(16)
      .background(.card)
    }
  }

  private static func pet(
    state: CodexDisplayAppState,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    FlexBox(
      direction: .column,
      spacing: 8,
      alignment: .center,
      crossAlignment: .center,
      padding: EdgeInsets(top: 12, bottom: 16, leading: 16, trailing: 16)
    ) {
      FlexBox(direction: .row, spacing: 0, alignment: .end, crossAlignment: .center) {
        Button(label: "", style: .secondary, iconName: .x) {
          onAction(.setMode(.work))
        }
      }

      spacer()

      let bubble = petBubbleDisplay(state.pet.bubble, expanded: state.petBubbleExpanded)
      if !bubble.text.isEmpty {
        FlexBox(direction: .column, spacing: 0, alignment: .center, crossAlignment: .center) {
          Text(bubble.text, style: .body)
          if bubble.isExpandable {
            Button(
              label: state.petBubbleExpanded ? "Less" : "More",
              style: .secondary,
              iconName: state.petBubbleExpanded ? .caretUp : .caretDown
            ) {
              onAction(.setPetBubbleExpanded(!state.petBubbleExpanded))
            }
          }
        }
        .padding(14)
        .background(.card)
      }

      FlexBox(direction: .column, spacing: 0, alignment: .center, crossAlignment: .center) {
        if let imageURI = state.pet.imageURI {
          Image(uri: imageURI, sizePreset: .fill, cornerRadius: .none)
        } else {
          Icon(name: .smileyCircle)
        }
      }
      .padding(EdgeInsets(top: 0, bottom: 0, leading: 132, trailing: 132))

      spacer()
    }
  }

  private static func composer(
    state: CodexDisplayAppState,
    chat: CodexDisplayAppChat?,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let draft = state.draft.trimmingCharacters(in: .whitespacesAndNewlines)

    return FlexBox(direction: .column, spacing: 10) {
      if !draft.isEmpty {
        Text(cleaned(draft), style: .body)
      }

      if !draft.isEmpty {
        FlexBox(direction: .row, spacing: 8, alignment: .end, crossAlignment: .center) {
          controlButton(label: "Send", style: .primary, iconName: .paperAirplane) {
            onAction(.sendMessage(
              chatID: chat?.id,
              projectID: chat?.projectId ?? state.selectedProjectId,
              text: draft
            ))
          }
        }
      }
    }
    .padding(10)
    .background(.card)
  }

  private static func messageCard(
    _ message: CodexDisplayAppMessage,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 8) {
      for part in message.parts.prefix(4) {
        partView(part, onAction: onAction)
      }
      if message.parts.count > 4 {
        Text("+\(message.parts.count - 4) more items", style: .meta, color: .secondary)
      }
    }
    .padding(14)
    .background(message.role == "user" ? .card : .none)
  }

  private static func partView(
    _ part: CodexDisplayAppMessagePart,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    switch part.type {
    case "fileGroup":
      return fileGroup(part, onAction: onAction)
    case "file":
      let path = part.path ?? "File"
      return fileRow(title: shortPath(path), detail: part.detail, added: part.added ?? 0, removed: part.removed ?? 0) {
        onAction(.openFile(path: path))
      }
    case "tool":
      return FlexBox(direction: .column, spacing: 4) {
        Text(part.name ?? "Tool", style: .body)
        Text(part.status ?? "", style: .meta, color: .secondary)
        Text(cleaned(part.detail ?? ""), style: .meta, color: .secondary)
      }
      .padding(10)
      .background(.card)
    case "todo":
      return FlexBox(direction: .column, spacing: 6) {
        Text("To-do", style: .meta, color: .secondary)
        for item in (part.items ?? []).prefix(4) {
          Text("\(item.done ? "[x]" : "[ ]") \(item.title)", style: .body)
        }
        if (part.items ?? []).count > 4 {
          Text("+\((part.items ?? []).count - 4) more", style: .meta, color: .secondary)
        }
      }
      .padding(10)
      .background(.card)
    case "reasoning":
      return FlexBox(direction: .column, spacing: 4) {
        Text("Thinking", style: .meta, color: .secondary)
        Text(cleaned(part.text ?? ""), style: .body, color: .secondary)
      }
    case "text":
      return textPart(part.text ?? "", onAction: onAction)
    default:
      return textPart(part.text ?? "", onAction: onAction)
    }
  }

  private static func textPart(
    _ text: String,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let links = fileLinks(in: text)

    return FlexBox(direction: .column, spacing: 7) {
      for line in markdownLines(text) {
        markdownLineView(line)
      }
      if !links.isEmpty {
        for link in links.prefix(3) {
          linkedFileRow(link) {
            onAction(.openFile(path: link.path))
          }
        }
        if links.count > 3 {
          Text("+\(links.count - 3) more linked files", style: .meta, color: .secondary)
        }
      }
    }
  }

  private static func fileGroup(
    _ part: CodexDisplayAppMessagePart,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    let files = part.files ?? []
    let added = files.reduce(0) { $0 + $1.added }
    let removed = files.reduce(0) { $0 + $1.removed }

    return FlexBox(direction: .column, spacing: 8) {
      Text("\(files.count) files changed  +\(added) -\(removed)", style: .body)
      for file in files.prefix(4) {
        fileRow(title: shortPath(file.path), detail: file.detail, added: file.added, removed: file.removed) {
          onAction(.openFile(path: file.path))
        }
      }
      if files.count > 4 {
        Text("+\(files.count - 4) more files", style: .meta, color: .secondary)
      }
    }
    .padding(12)
    .background(.card)
  }

  private static func chatActions(
    _ chat: CodexDisplayAppChat,
    onAction: @escaping @Sendable (CodexDisplayAppAction) -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 8, wrap: true) {
      Button(
        label: chat.pinned ? "Unpin" : "Pin",
        style: .secondary,
        iconName: chat.pinned ? .x : .star
      ) {
        onAction(.togglePinned(chatID: chat.id))
      }
      Button(label: "Archive", style: .outline, iconName: .containerWithLid) {
        onAction(.archiveChat(chatID: chat.id))
      }
    }
    .padding(10)
    .background(.card)
  }

  private static func chatFailureRow() -> FlexBox {
    FlexBox(direction: .row, spacing: 8, alignment: .start, crossAlignment: .center) {
      Icon(name: .x)
      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text("Send failed", style: .body)
        Text("Check logs", style: .meta, color: .secondary)
      }
      .flexGrow(1)
    }
    .padding(10)
    .background(.card)
  }

  private static func thinkingActivityRow() -> FlexBox {
    FlexBox(direction: .row, spacing: 8, alignment: .start, crossAlignment: .center) {
      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text("Thinking...", style: .body)
      }
      .flexGrow(1)
      Icon(name: .twoArrowsClockwise)
    }
    .padding(10)
    .background(.card)
  }

  private static func controlButton(
    label: String,
    style: ButtonStyle,
    iconName: IconName,
    onTap: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 8, alignment: .start, crossAlignment: .center) {
      Text(label, style: .body)
      Button(label: "", style: style, iconName: iconName, onClick: onTap)
    }
    .padding(10)
    .background(.card)
  }

  private static func modelOptionRow(
    model: CodexDisplayAppModel,
    selected: Bool,
    onTap: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .start, crossAlignment: .center) {
      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text(model.name, style: .body)
      }
      .flexGrow(1)
      Button(
        label: "",
        style: selected ? .primary : .secondary,
        iconName: selected ? .checkmark : .caretRight,
        onClick: onTap
      )
    }
    .padding(12)
    .background(.card)
  }

  private static func fileRow(
    title: String,
    detail: String?,
    added: Int,
    removed: Int,
    onTap: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 6) {
      Button(label: title, style: .secondary, iconName: .twoSquaresStackedRightDown, onClick: onTap)
      FlexBox(direction: .row, spacing: 8, alignment: .center, crossAlignment: .center) {
        if let detail, !detail.isEmpty {
          Text(clamp(detail, maxLength: 80), style: .meta, color: .secondary)
        } else {
          Text("Changed", style: .meta, color: .secondary)
        }
        Text("+\(added) -\(removed)", style: .meta, color: .secondary)
      }
    }
    .padding(10)
    .background(.card)
  }

  private static func linkedFileRow(
    _ link: FileLink,
    onTap: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 6) {
      Button(label: link.label, style: .secondary, iconName: .twoSquaresStackedRightDown, onClick: onTap)
      Text(shortPath(link.path), style: .meta, color: .secondary)
    }
    .padding(10)
    .background(.card)
  }

  private static func projectRow(_ project: CodexDisplayAppProject, onTap: @escaping @Sendable () -> Void) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .start, crossAlignment: .center) {
      Image(uri: folderIconURI, sizePreset: .icon, cornerRadius: .none)
      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text(project.name, style: .body)
      }
      .flexGrow(1)
      if project.active {
        Icon(name: .twoArrowsClockwise)
      }
      Button(label: "", style: .secondary, iconName: .caretRight, onClick: onTap)
    }
    .padding(12)
    .background(.card)
    .onTap(onTap)
  }

  private static func chatRow(_ chat: CodexDisplayAppChat, onTap: @escaping @Sendable () -> Void) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .start, crossAlignment: .center) {
      if chat.active {
        Icon(name: .twoArrowsClockwise)
      } else if chat.unread {
        Icon(name: .bell)
      }
      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text(chat.title, style: .body)
      }
      .flexGrow(1)
      Button(label: "", style: .secondary, iconName: .caretRight, onClick: onTap)
    }
    .padding(12)
    .background(.card)
    .onTap(onTap)
  }

  private static func header(
    title: String,
    subtitle: String,
    newAction: @escaping @Sendable () -> Void,
    petAction: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .center, crossAlignment: .center) {
      FlexBox(direction: .column, spacing: 2) {
        Text(title, style: .heading)
        if !subtitle.isEmpty {
          Text(subtitle, style: .meta, color: .secondary)
        }
      }
      .flexGrow(1)
      Button(label: "New", style: .secondary, iconName: .plus, onClick: newAction)
      Button(label: "Pet", style: .secondary, iconName: .smileyCircle, onClick: petAction)
    }
  }

  private static func backHeader(
    title: String,
    subtitle: String,
    back: @escaping @Sendable () -> Void,
    trailing: @escaping @Sendable () -> Void,
    petAction: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .center, crossAlignment: .center) {
      Button(label: "Back", style: .secondary, iconName: .arrowLeft, onClick: back)
      FlexBox(direction: .column, spacing: 2) {
        Text(title, style: .heading)
        if !subtitle.isEmpty {
          Text(subtitle, style: .meta, color: .secondary)
        }
      }
      .flexGrow(1)
      Button(label: "New", style: .secondary, iconName: .plus, onClick: trailing)
      Button(label: "Pet", style: .secondary, iconName: .smileyCircle, onClick: petAction)
    }
  }

  private static func chatHeader(
    title: String,
    subtitle: String,
    back: @escaping @Sendable () -> Void,
    moreAction: @escaping @Sendable () -> Void,
    dictateAction: @escaping @Sendable () -> Void,
    petAction: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 8) {
      FlexBox(direction: .row, spacing: 10, alignment: .end, crossAlignment: .center) {
        Button(label: "Back", style: .secondary, iconName: .arrowLeft, onClick: back)
        Button(label: "More", style: .secondary, iconName: .threeDotsHorizontal, onClick: moreAction)
        Button(label: "Dictate", style: .primary, iconName: .speechBubble, onClick: dictateAction)
        Button(label: "Pet", style: .secondary, iconName: .smileyCircle, onClick: petAction)
      }

      FlexBox(direction: .column, spacing: 2, alignment: .start, crossAlignment: .start) {
        Text(title, style: .heading)
        if !subtitle.isEmpty {
          Text(subtitle, style: .meta, color: .secondary)
        }
      }
    }
  }

  private static func simpleBackHeader(
    title: String,
    subtitle: String,
    back: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .row, spacing: 10, alignment: .center, crossAlignment: .center) {
      Button(label: "Back", style: .secondary, iconName: .arrowLeft, onClick: back)
      FlexBox(direction: .column, spacing: 2) {
        Text(title, style: .heading)
        if !subtitle.isEmpty {
          Text(subtitle, style: .meta, color: .secondary)
        }
      }
      .flexGrow(1)
    }
  }

  private static func waveform(level: Double) -> FlexBox {
    let clampedLevel = min(max(level, 0), 1)
    let profile = [0.42, 0.68, 0.92, 0.58, 1.0, 0.74, 0.46, 0.84, 0.54]

    return FlexBox(direction: .row, spacing: 5, alignment: .center, crossAlignment: .center) {
      for index in profile.indices {
        let scaled = max(0.08, min(1, clampedLevel * profile[index] * 1.16))
        let height = max(1, min(5, Int((scaled * 5).rounded(.up))))
        Text(
          String(repeating: "|", count: height),
          style: height >= 4 ? .heading : .body,
          color: height >= 2 ? .primary : .secondary
        )
      }
    }
  }

  private static func root(@ComponentBuilder content: () -> [any ViewComponent]) -> FlexBox {
    let components = content()
    return FlexBox(
      direction: .column,
      spacing: 12,
      alignment: .start,
      crossAlignment: .stretch,
      padding: EdgeInsets(all: 16)
    ) {
      for component in components {
        component
      }
    }
    .flexGrow(1)
    .alignSelf(.stretch)
  }

  private static func spacer() -> FlexBox {
    FlexBox(direction: .column, spacing: 0) {}
      .flexGrow(1)
      .flexShrink(1)
  }

  private static func sectionTitle(_ title: String) -> Text {
    Text(title, style: .meta, color: .secondary)
  }

  private static func empty(_ title: String) -> FlexBox {
    FlexBox(direction: .column, spacing: 4, alignment: .start, crossAlignment: .stretch) {
      Text(title, style: .body, color: .secondary)
    }
    .padding(12)
    .background(.card)
    .alignSelf(.stretch)
  }

  private static func selectedProject(_ state: CodexDisplayAppState) -> CodexDisplayAppProject? {
    state.projects.first { $0.id == state.selectedProjectId } ?? state.projects.first
  }

  private static func currentChat(_ state: CodexDisplayAppState) -> CodexDisplayAppChat? {
    guard let selectedChatId = state.selectedChatId else { return nil }
    return state.chats.first { $0.id == selectedChatId }
  }

  private static func selectedModel(_ state: CodexDisplayAppState) -> CodexDisplayAppModel? {
    if let selectedModelId = state.selectedModelId,
       let model = state.models.first(where: { $0.id == selectedModelId }) {
      return model
    }
    return state.models.first(where: \.isDefault) ?? state.models.first
  }

  private static func visibleModels(_ state: CodexDisplayAppState) -> [CodexDisplayAppModel] {
    var models = Array(state.models.prefix(4))
    if let selectedModel = selectedModel(state), !models.contains(where: { $0.id == selectedModel.id }) {
      models.append(selectedModel)
    }
    return models
  }

  private static func bottomVisibleMessages(
    _ messages: [CodexDisplayAppMessage],
    showAll: Bool
  ) -> [CodexDisplayAppMessage] {
    guard !showAll, messages.count > initialVisibleChatMessageLimit else {
      return messages
    }
    return Array(messages.suffix(initialVisibleChatMessageLimit))
  }

  private static func nextModel(_ state: CodexDisplayAppState) -> CodexDisplayAppModel? {
    guard state.models.count > 1 else { return nil }
    let selectedID = selectedModel(state)?.id
    let currentIndex = state.models.firstIndex { $0.id == selectedID } ?? 0
    return state.models[(currentIndex + 1) % state.models.count]
  }

  private struct FileLink: Hashable {
    var label: String
    var path: String
  }

  private struct DiffPreviewLine: Hashable {
    var prefix: String
    var text: String
  }

  private enum MarkdownDisplayLine: Hashable {
    case heading(String)
    case body(String)
    case code(String)
  }

  private struct PetBubbleDisplay: Hashable {
    var text: String
    var isExpandable: Bool
  }

  private static let folderIconURI = "data:image/svg+xml,%3Csvg%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27currentColor%27%20stroke-width%3D%272.1%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%3E%3Cpath%20d%3D%27M3%207.5A2.5%202.5%200%200%201%205.5%205H9l2%202h8.5A2.5%202.5%200%200%201%2022%209.5v8A2.5%202.5%200%200%201%2019.5%2020h-15A2.5%202.5%200%200%201%202%2017.5v-10Z%27%2F%3E%3C%2Fsvg%3E"

  private static func markdownLineView(_ line: MarkdownDisplayLine) -> Text {
    switch line {
    case .heading(let text):
      return Text(text, style: .heading)
    case .body(let text):
      return Text(text, style: .body)
    case .code(let text):
      return Text(text, style: .meta, color: .secondary)
    }
  }

  private static func markdownLines(_ text: String) -> [MarkdownDisplayLine] {
    let lines = cleaned(text).components(separatedBy: .newlines)
    var rendered: [MarkdownDisplayLine] = []
    var isInCodeFence = false
    var sawBlank = false

    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line.hasPrefix("```") {
        isInCodeFence.toggle()
        sawBlank = false
        continue
      }

      if isInCodeFence {
        if !line.isEmpty {
          rendered.append(.code(rawLine))
        }
        sawBlank = false
        continue
      }

      guard !line.isEmpty else {
        sawBlank = !rendered.isEmpty
        continue
      }

      if let heading = markdownHeading(from: line) {
        if sawBlank, !rendered.isEmpty {
          rendered.append(.body(""))
        }
        rendered.append(.heading(heading))
      } else {
        if sawBlank, !rendered.isEmpty {
          rendered.append(.body(""))
        }
        rendered.append(.body(markdownBodyLine(from: line)))
      }
      sawBlank = false
    }

    return rendered.isEmpty ? [.body(cleaned(text))] : rendered
  }

  private static func markdownHeading(from line: String) -> String? {
    guard let match = line.range(
      of: #"^#{1,6}\s+(.+)$"#,
      options: .regularExpression
    ) else {
      return nil
    }
    let matched = String(line[match])
    let title = matched.replacingOccurrences(
      of: #"^#{1,6}\s+"#,
      with: "",
      options: .regularExpression
    )
    return inlineMarkdownText(title)
  }

  private static func markdownBodyLine(from line: String) -> String {
    var rendered = line
    if rendered.hasPrefix(">") {
      rendered = rendered.replacingOccurrences(
        of: #"^>\s*"#,
        with: "> ",
        options: .regularExpression
      )
    }
    return inlineMarkdownText(rendered)
  }

  private static func inlineMarkdownText(_ text: String) -> String {
    var rendered = text
    rendered = regexReplace(rendered, pattern: #"!\[([^\]]*)\]\([^)]+\)"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"\[([^\]]+)\]\([^)]+\)"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"`([^`]+)`"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"\*\*([^*\n]+)\*\*"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"__([^_\n]+)__"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"~~([^~\n]+)~~"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"(?<!\*)\*([^*\n]+)\*(?!\*)"#, template: "$1")
    rendered = regexReplace(rendered, pattern: #"\\([*_`~\[\]()#>-])"#, template: "$1")
    return rendered.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private static func regexReplace(_ text: String, pattern: String, template: String) -> String {
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
      return text
    }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    return regex.stringByReplacingMatches(in: text, range: range, withTemplate: template)
  }

  private static func petBubbleDisplay(_ text: String, expanded: Bool) -> PetBubbleDisplay {
    let lines = cleaned(text)
      .components(separatedBy: .newlines)
      .map(inlineMarkdownText)
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
    let fullText = lines.joined(separator: "\n")
    guard !fullText.isEmpty else {
      return PetBubbleDisplay(text: "", isExpandable: false)
    }

    let maxCollapsedCharacters = 44
    let needsLineCollapse = lines.count > 2
    let needsCharacterCollapse = fullText.count > maxCollapsedCharacters
    let isExpandable = needsLineCollapse || needsCharacterCollapse
    guard !expanded, isExpandable else {
      return PetBubbleDisplay(text: fullText, isExpandable: isExpandable)
    }

    let singleLinePreview = lines.joined(separator: " ")
    let prefix = singleLinePreview.prefix(maxCollapsedCharacters - 1)
    return PetBubbleDisplay(text: "\(prefix)...", isExpandable: true)
  }

  private static func diffPreviewLines(_ diff: String) -> [DiffPreviewLine] {
    var lines: [DiffPreviewLine] = []
    for rawLine in diff.split(whereSeparator: \.isNewline).map(String.init) {
      if rawLine.hasPrefix("+++") || rawLine.hasPrefix("---") {
        continue
      }
      if rawLine.hasPrefix("+") {
        lines.append(DiffPreviewLine(
          prefix: "+",
          text: String(rawLine.dropFirst()).trimmingCharacters(in: .whitespaces)
        ))
      } else if rawLine.hasPrefix("-") {
        lines.append(DiffPreviewLine(
          prefix: "-",
          text: String(rawLine.dropFirst()).trimmingCharacters(in: .whitespaces)
        ))
      }
    }
    return lines
  }

  private static func fileLinks(in text: String) -> [FileLink] {
    let pattern = #"\[([^\]]+)\]\(([^)]+)\)|`([^`]+)`|((?:\.{1,2}/|/|~/)?[A-Za-z0-9_.~/-]+\.(?:swift|mjs|js|ts|tsx|jsx|md|sh|py|json|yaml|yml|txt|html|css|rb|rs|go|toml|xml)(?::\d+)?)"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
      return []
    }

    let textRange = NSRange(text.startIndex..<text.endIndex, in: text)
    var links: [FileLink] = []
    var seen = Set<String>()

    for match in regex.matches(in: text, range: textRange) {
      if let labelRange = Range(match.range(at: 1), in: text),
         let pathRange = Range(match.range(at: 2), in: text) {
        let rawLabel = String(text[labelRange])
        let rawPath = String(text[pathRange])
        if let link = fileLink(label: rawLabel, path: rawPath), seen.insert(link.path).inserted {
          links.append(link)
        }
      } else if let pathRange = Range(match.range(at: 4), in: text) {
        let rawPath = String(text[pathRange])
        if let link = fileLink(label: rawPath, path: rawPath), seen.insert(link.path).inserted {
          links.append(link)
        }
      }
    }

    return links
  }

  private static func fileLink(label: String, path rawPath: String) -> FileLink? {
    let decodedPath = rawPath.removingPercentEncoding ?? rawPath
    let decodedLabel = label.removingPercentEncoding ?? label
    guard !decodedPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      return nil
    }

    if let url = URL(string: decodedPath), let scheme = url.scheme?.lowercased(), !scheme.isEmpty {
      if scheme == "http" || scheme == "https" || scheme == "mailto" {
        return nil
      }
      if scheme == "file" || scheme == "sandbox" || scheme == "codex-file" {
        let path = url.path.removingPercentEncoding ?? url.path
        return FileLink(label: nonEmpty(decodedLabel) ?? shortPath(path), path: stripLineSuffix(path))
      }
    }

    let cleanPath = stripLineSuffix(decodedPath)
    guard cleanPath.contains("/") || cleanPath.contains(".") else {
      return nil
    }
    return FileLink(label: nonEmpty(decodedLabel) ?? shortPath(cleanPath), path: cleanPath)
  }

  private static func stripLineSuffix(_ path: String) -> String {
    path.replacingOccurrences(of: #":\d+$"#, with: "", options: .regularExpression)
  }

  private static func nonEmpty(_ text: String) -> String? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
  }

  private static func shortPath(_ path: String) -> String {
    guard path.count > 34 else { return path }
    return "..." + path.suffix(31)
  }

  private static func shortModelName(_ name: String) -> String {
    let shortened = name
      .replacingOccurrences(of: "GPT-", with: "")
      .replacingOccurrences(of: "Codex", with: "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    return shortened.isEmpty ? name : shortened
  }

  private static func modelControlLabel(_ model: CodexDisplayAppModel?) -> String {
    nonEmpty(model?.name ?? "") ?? "Model"
  }

  private static func hasAssistantText(in messages: [CodexDisplayAppMessage]) -> Bool {
    messages.contains { message in
      message.role == "assistant" && message.parts.contains { part in
        part.type == "text" && !(part.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      }
    }
  }

  private static func thinkingLevelName(_ model: CodexDisplayAppModel?) -> String {
    let detail = model?.detail.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !detail.isEmpty {
      return shortThinkingLevel(detail)
    }

    let id = (model?.id ?? model?.name ?? "").lowercased()
    if id.contains("extra") {
      return "Extra"
    }
    if id.contains("high") {
      return "High"
    }
    if id.contains("medium") {
      return "Medium"
    }
    if id.contains("low") {
      return "Low"
    }
    return "Auto"
  }

  private static func shortThinkingLevel(_ detail: String) -> String {
    let normalized = detail
      .replacingOccurrences(of: "thinking", with: "", options: .caseInsensitive)
      .replacingOccurrences(of: "reasoning", with: "", options: .caseInsensitive)
      .trimmingCharacters(in: CharacterSet(charactersIn: " -:").union(.whitespacesAndNewlines))
    return normalized.isEmpty ? "Auto" : normalized
  }

  private static func clamp(_ text: String, maxLength: Int) -> String {
    let cleanedText = cleaned(text)
    guard cleanedText.count > maxLength else { return cleanedText }
    return String(cleanedText.prefix(maxLength - 1)) + "..."
  }

  private static func cleaned(_ text: String) -> String {
    text
      .replacingOccurrences(of: "\r\n", with: "\n")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
