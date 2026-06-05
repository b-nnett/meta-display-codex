import Foundation

enum CodexRemoteTransport: String, CaseIterable {
  case oauth
  case rest
  case webSocket
  case appServerRPC
  case serverNotification
  case serverRequest
  case derived
}

enum CodexRemoteSafety: String, CaseIterable {
  case readOnly
  case auth
  case sessionMutation
  case filesystemRead
  case filesystemMutation
  case commandExecution
  case pluginOrMCPMutation
  case accountMutation
  case localDisplay
  case audioCapture
}

enum CodexRemoteValidationStatus: String, CaseIterable {
  case validated
  case implemented
  case planned
  case schemaMissing
}

struct CodexRemoteRESTEndpoint: Identifiable, Equatable {
  var id: String
  var method: String
  var path: String
  var requiresNormalAccessToken: Bool
  var requiresAccountID: Bool
  var bodyKeys: [String]
}

struct CodexRemoteCapability: Identifiable, Equatable {
  var id: String
  var title: String
  var transport: CodexRemoteTransport
  var safety: CodexRemoteSafety
  var validationStatus: CodexRemoteValidationStatus
  var restEndpointID: String? = nil
  var rpcMethod: String? = nil
  var notificationNames: [String] = []
  var requiredParams: [String] = []
  var notes: String
}

enum CodexRemoteAPICatalog {
  static let restEndpoints: [CodexRemoteRESTEndpoint] = [
    CodexRemoteRESTEndpoint(
      id: "listRemoteHosts",
      method: "GET",
      path: "/codex/remote/control/environments?limit=50",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: []
    ),
    CodexRemoteRESTEndpoint(
      id: "readRemoteHost",
      method: "GET",
      path: "/codex/remote/control/environments/{env_id}",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: []
    ),
    CodexRemoteRESTEndpoint(
      id: "enrollStart",
      method: "POST",
      path: "/codex/remote/control/client/enroll/start",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: []
    ),
    CodexRemoteRESTEndpoint(
      id: "enrollFinish",
      method: "POST",
      path: "/codex/remote/control/client/enroll/finish",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: ["client_id", "step_up_token", "device_identity", "device_key_proof"]
    ),
    CodexRemoteRESTEndpoint(
      id: "refreshStart",
      method: "POST",
      path: "/codex/remote/control/client/refresh/start",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: ["client_id"]
    ),
    CodexRemoteRESTEndpoint(
      id: "refreshFinish",
      method: "POST",
      path: "/codex/remote/control/client/refresh/finish",
      requiresNormalAccessToken: true,
      requiresAccountID: true,
      bodyKeys: ["client_id", "device_key_proof"]
    ),
  ]

  static let webSocketEndpointPath = "/codex/remote/control/client"
  static let webSocketHeaders = [
    "x-codex-client-session-token",
    "x-codex-client-id",
    "x-codex-protocol-version",
  ]

  static let capabilities: [CodexRemoteCapability] = [
    CodexRemoteCapability(
      id: "desktopOAuthSignIn",
      title: "Authenticate with OpenAI",
      transport: .oauth,
      safety: .auth,
      validationStatus: .implemented,
      requiredParams: ["client_id", "redirect_uri", "scope", "code_challenge", "state"],
      notes: "Custom persistent webview recreates the desktop OAuth flow and captures the localhost callback."
    ),
    CodexRemoteCapability(
      id: "remoteEnrollStart",
      title: "Start remote-control enrollment",
      transport: .rest,
      safety: .auth,
      validationStatus: .implemented,
      restEndpointID: "enrollStart",
      notes: "Creates the server challenge used by the device-key proof."
    ),
    CodexRemoteCapability(
      id: "remoteEnrollFinish",
      title: "Finish remote-control enrollment",
      transport: .rest,
      safety: .auth,
      validationStatus: .implemented,
      restEndpointID: "enrollFinish",
      requiredParams: ["client_id", "step_up_token", "device_identity", "device_key_proof"],
      notes: "Stores client id, remote-control token, token expiry, and device-key id."
    ),
    CodexRemoteCapability(
      id: "remoteTokenRefresh",
      title: "Refresh remote-control token",
      transport: .rest,
      safety: .auth,
      validationStatus: .implemented,
      restEndpointID: "refreshFinish",
      requiredParams: ["client_id", "device_key_proof"],
      notes: "Uses refresh start/finish with the stored device key before websocket token expiry."
    ),
    CodexRemoteCapability(
      id: "listRemoteHosts",
      title: "List Codex Desktop hosts",
      transport: .rest,
      safety: .readOnly,
      validationStatus: .implemented,
      restEndpointID: "listRemoteHosts",
      notes: "Returns remote environments such as Example Mac."
    ),
    CodexRemoteCapability(
      id: "readRemoteHost",
      title: "Read one Codex Desktop host",
      transport: .rest,
      safety: .readOnly,
      validationStatus: .validated,
      restEndpointID: "readRemoteHost",
      requiredParams: ["env_id"],
      notes: "Useful for host details and stale selected-host recovery."
    ),
    CodexRemoteCapability(
      id: "connectRemoteWebSocket",
      title: "Connect remote websocket",
      transport: .webSocket,
      safety: .sessionMutation,
      validationStatus: .implemented,
      requiredParams: webSocketHeaders,
      notes: "Completes the device-key websocket proof, then relays app-server JSON-RPC."
    ),
    CodexRemoteCapability(
      id: "initializeAppServer",
      title: "Initialize app-server session",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .implemented,
      rpcMethod: "initialize",
      requiredParams: ["clientInfo", "capabilities"],
      notes: "Must be followed by the initialized notification."
    ),
    CodexRemoteCapability(
      id: "readAccount",
      title: "Read account",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "account/read",
      notes: "Settings and diagnostics only."
    ),
    CodexRemoteCapability(
      id: "readRateLimits",
      title: "Read rate limits",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "account/rateLimits/read",
      notes: "Optional quota display in Settings."
    ),
    CodexRemoteCapability(
      id: "readConfig",
      title: "Read Codex config",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "config/read",
      notes: "Read effective model/sandbox/project config."
    ),
    CodexRemoteCapability(
      id: "listModels",
      title: "List models",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "model/list",
      notes: "Needed for model picker and current model display."
    ),
    CodexRemoteCapability(
      id: "listProjects",
      title: "List projects",
      transport: .derived,
      safety: .readOnly,
      validationStatus: .implemented,
      rpcMethod: "thread/list",
      notes: "Projects are inferred from stable cwd groups in thread/list; there is no remote REST projects route."
    ),
    CodexRemoteCapability(
      id: "listChats",
      title: "List chats",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .implemented,
      rpcMethod: "thread/list",
      requiredParams: ["limit", "archived", "sortKey", "sortDirection", "useStateDbOnly"],
      notes: "Primary recent-chat feed."
    ),
    CodexRemoteCapability(
      id: "paginateChats",
      title: "Paginate chats",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "thread/list",
      requiredParams: ["cursor", "limit"],
      notes: "Uses nextCursor/backwardsCursor from thread/list responses."
    ),
    CodexRemoteCapability(
      id: "searchChats",
      title: "Search chats",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "thread/list",
      requiredParams: ["searchTerm"],
      notes: "Server-side title/preview search."
    ),
    CodexRemoteCapability(
      id: "loadChat",
      title: "Load chat",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "thread/read",
      requiredParams: ["threadId", "includeTurns"],
      notes: "Reads a thread and, with includeTurns, its rollout items."
    ),
    CodexRemoteCapability(
      id: "paginateChatTurns",
      title: "Paginate chat turns",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "thread/turns/list",
      requiredParams: ["threadId", "cursor", "limit"],
      notes: "Live-probed against Codex Desktop 26.601.21317. The generated ClientRequest schema omits this method, but app-server accepts it and returns data, nextCursor, and backwardsCursor. Cursors are opaque strings containing JSON with turnId/includeAnchor."
    ),
    CodexRemoteCapability(
      id: "listLoadedChats",
      title: "List loaded chats",
      transport: .appServerRPC,
      safety: .readOnly,
      validationStatus: .validated,
      rpcMethod: "thread/loaded/list",
      notes: "Lets the app distinguish resident/in-memory chats from historical chats."
    ),
    CodexRemoteCapability(
      id: "newChat",
      title: "Create new chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/start",
      notes: "Creates the thread shell before the first turn."
    ),
    CodexRemoteCapability(
      id: "resumeChat",
      title: "Resume chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/resume",
      requiredParams: ["threadId"],
      notes: "Loads a previous chat into the app-server."
    ),
    CodexRemoteCapability(
      id: "sendTextMessage",
      title: "Send text message",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "turn/start",
      requiredParams: ["threadId", "input"],
      notes: "Starts a new user turn with a text input part."
    ),
    CodexRemoteCapability(
      id: "sendImageMessage",
      title: "Send image message",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "turn/start",
      requiredParams: ["threadId", "input"],
      notes: "Uses image URL or localImage user input parts; no separate upload route is exposed by the generated schema."
    ),
    CodexRemoteCapability(
      id: "steerActiveTurn",
      title: "Steer active turn",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "turn/steer",
      requiredParams: ["threadId", "expectedTurnId", "input"],
      notes: "Adds input to the active turn when the server still accepts same-turn steering."
    ),
    CodexRemoteCapability(
      id: "interruptTurn",
      title: "Interrupt turn",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "turn/interrupt",
      requiredParams: ["threadId", "turnId"],
      notes: "Stop generation from the mobile UI/glasses."
    ),
    CodexRemoteCapability(
      id: "archiveChat",
      title: "Archive chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/archive",
      requiredParams: ["threadId"],
      notes: "Hide a chat from normal lists."
    ),
    CodexRemoteCapability(
      id: "unarchiveChat",
      title: "Unarchive chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/unarchive",
      requiredParams: ["threadId"],
      notes: "Restore an archived chat."
    ),
    CodexRemoteCapability(
      id: "renameChat",
      title: "Rename chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/name/set",
      requiredParams: ["threadId", "name"],
      notes: "Persist a user-visible chat name."
    ),
    CodexRemoteCapability(
      id: "pinChat",
      title: "Pin chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .planned,
      rpcMethod: "thread/metadata/update",
      requiredParams: ["threadId"],
      notes: "The method exists, but the exact metadata key for pinned state still needs desktop verification."
    ),
    CodexRemoteCapability(
      id: "setChatGoal",
      title: "Set chat goal",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/goal/set",
      requiredParams: ["threadId", "objective"],
      notes: "Needed for goal/todo state once exposed in the mobile chat view."
    ),
    CodexRemoteCapability(
      id: "clearChatGoal",
      title: "Clear chat goal",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/goal/clear",
      requiredParams: ["threadId"],
      notes: "Clears active goal state."
    ),
    CodexRemoteCapability(
      id: "forkChat",
      title: "Fork chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/fork",
      requiredParams: ["threadId"],
      notes: "Optional later workflow for branching chats from the phone."
    ),
    CodexRemoteCapability(
      id: "compactChat",
      title: "Compact chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/compact/start",
      requiredParams: ["threadId"],
      notes: "Manual compaction control."
    ),
    CodexRemoteCapability(
      id: "rollbackChat",
      title: "Rollback chat",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/rollback",
      requiredParams: ["threadId", "numTurns"],
      notes: "Optional edit/undo workflow."
    ),
    CodexRemoteCapability(
      id: "viewFile",
      title: "View file",
      transport: .appServerRPC,
      safety: .filesystemRead,
      validationStatus: .validated,
      rpcMethod: "fs/readFile",
      requiredParams: ["path"],
      notes: "Returns base64 file contents for inline file viewing."
    ),
    CodexRemoteCapability(
      id: "listDirectory",
      title: "List directory",
      transport: .appServerRPC,
      safety: .filesystemRead,
      validationStatus: .validated,
      rpcMethod: "fs/readDirectory",
      requiredParams: ["path"],
      notes: "Browse project folders from chat references."
    ),
    CodexRemoteCapability(
      id: "readFileMetadata",
      title: "Read file metadata",
      transport: .appServerRPC,
      safety: .filesystemRead,
      validationStatus: .validated,
      rpcMethod: "fs/getMetadata",
      requiredParams: ["path"],
      notes: "Size/type/existence checks before previewing."
    ),
    CodexRemoteCapability(
      id: "searchFiles",
      title: "Search files",
      transport: .appServerRPC,
      safety: .filesystemRead,
      validationStatus: .validated,
      rpcMethod: "fuzzyFileSearch",
      requiredParams: ["query"],
      notes: "Used by composer file mentions and file picker search."
    ),
    CodexRemoteCapability(
      id: "observeStreamingText",
      title: "Render streaming text",
      transport: .serverNotification,
      safety: .readOnly,
      validationStatus: .validated,
      notificationNames: ["item/agentMessage/delta", "item/reasoning/textDelta", "item/reasoning/summaryTextDelta"],
      notes: "Render assistant text and reasoning deltas as they arrive."
    ),
    CodexRemoteCapability(
      id: "observeToolDetails",
      title: "Render tool details",
      transport: .serverNotification,
      safety: .readOnly,
      validationStatus: .validated,
      notificationNames: ["item/started", "item/completed", "item/mcpToolCall/progress", "item/commandExecution/outputDelta"],
      notes: "Display tool calls, command progress, and completion details inline."
    ),
    CodexRemoteCapability(
      id: "observeTodoUpdates",
      title: "Render inline todo list",
      transport: .serverNotification,
      safety: .readOnly,
      validationStatus: .validated,
      notificationNames: ["turn/plan/updated", "item/plan/delta"],
      notes: "Turn plan notifications become the inline to-do list."
    ),
    CodexRemoteCapability(
      id: "observeFileChanges",
      title: "Render file changes",
      transport: .serverNotification,
      safety: .readOnly,
      validationStatus: .validated,
      notificationNames: ["turn/diff/updated", "item/fileChange/patchUpdated", "item/fileChange/outputDelta"],
      notes: "Drives file diff previews and changed-file summaries."
    ),
    CodexRemoteCapability(
      id: "handleCommandApprovalRequest",
      title: "Handle command approval request",
      transport: .serverRequest,
      safety: .commandExecution,
      validationStatus: .validated,
      notificationNames: ["item/commandExecution/requestApproval"],
      notes: "Required when a turn asks the user to approve or deny a command."
    ),
    CodexRemoteCapability(
      id: "handleFileChangeApprovalRequest",
      title: "Handle file-change approval request",
      transport: .serverRequest,
      safety: .filesystemMutation,
      validationStatus: .validated,
      notificationNames: ["item/fileChange/requestApproval"],
      notes: "Required when a turn asks the user to approve or deny a patch."
    ),
    CodexRemoteCapability(
      id: "handlePermissionRequest",
      title: "Handle permission request",
      transport: .serverRequest,
      safety: .sessionMutation,
      validationStatus: .validated,
      notificationNames: ["item/permissions/requestApproval"],
      notes: "Required for sandbox, network, and other permission prompts."
    ),
    CodexRemoteCapability(
      id: "handleToolCallRequest",
      title: "Handle tool call request",
      transport: .serverRequest,
      safety: .pluginOrMCPMutation,
      validationStatus: .validated,
      notificationNames: ["item/tool/call"],
      notes: "Required if the app-server delegates a callable tool request back to the client."
    ),
    CodexRemoteCapability(
      id: "handleUserInputRequest",
      title: "Handle structured user input request",
      transport: .serverRequest,
      safety: .sessionMutation,
      validationStatus: .validated,
      notificationNames: ["item/tool/requestUserInput"],
      notes: "Required for request_user_input style prompts."
    ),
    CodexRemoteCapability(
      id: "handleAuthTokenRefreshRequest",
      title: "Handle auth-token refresh request",
      transport: .serverRequest,
      safety: .auth,
      validationStatus: .validated,
      notificationNames: ["account/chatgptAuthTokens/refresh"],
      notes: "Required if the app-server asks the mobile client to refresh account auth tokens."
    ),
    CodexRemoteCapability(
      id: "handleMcpElicitationRequest",
      title: "Handle MCP elicitation request",
      transport: .serverRequest,
      safety: .pluginOrMCPMutation,
      validationStatus: .validated,
      notificationNames: ["mcpServer/elicitation/request"],
      notes: "Required for MCP servers that ask the user for structured input."
    ),
    CodexRemoteCapability(
      id: "approveGuardianAction",
      title: "Approve guarded action",
      transport: .appServerRPC,
      safety: .sessionMutation,
      validationStatus: .validated,
      rpcMethod: "thread/approveGuardianDeniedAction",
      requiredParams: ["threadId", "event"],
      notes: "Must stay behind an explicit confirmation UI."
    ),
    CodexRemoteCapability(
      id: "runShellCommand",
      title: "Run shell command",
      transport: .appServerRPC,
      safety: .commandExecution,
      validationStatus: .validated,
      rpcMethod: "thread/shellCommand",
      requiredParams: ["threadId"],
      notes: "Powerful; should not be exposed on glasses without confirmation."
    ),
    CodexRemoteCapability(
      id: "displayOnGlasses",
      title: "Send UI to glasses",
      transport: .derived,
      safety: .localDisplay,
      validationStatus: .implemented,
      notes: "Uses Meta DAT display session, not Codex remote-control transport."
    ),
    CodexRemoteCapability(
      id: "displayPetOnGlasses",
      title: "Show pet state on glasses",
      transport: .derived,
      safety: .localDisplay,
      validationStatus: .implemented,
      notificationNames: [
        "turn/started",
        "turn/completed",
        "item/started",
        "item/completed",
        "item/agentMessage/delta",
        "item/reasoning/textDelta",
        "serverRequest/resolved",
      ],
      notes: "Maps Codex Desktop/watch companion states into idle, thinking, running, review, failed, and recording pet states. The iPhone app includes the eight watch companion spritesheets for preview/selection; the glasses path currently sends a DAT pet state card while animated sprite delivery waits on a stable asset URI path."
    ),
    CodexRemoteCapability(
      id: "transcribeGlassesMic",
      title: "Transcribe voice input",
      transport: .derived,
      safety: .audioCapture,
      validationStatus: .implemented,
      requiredParams: ["file", "model"],
      notes: "Uses the OpenAI audio transcription endpoint with gpt-4o-mini-transcribe by default. The installed DAT SDK exposes microphone permission, but no public Swift audio stream API; recording currently uses the iOS audio input route and prefers external Bluetooth microphones when available."
    ),
  ]

  static let observedAppServerMethods: Set<String> = [
    "account/login/cancel",
    "account/login/start",
    "account/logout",
    "account/rateLimits/read",
    "account/read",
    "account/sendAddCreditsNudgeEmail",
    "app/list",
    "command/exec",
    "command/exec/resize",
    "command/exec/terminate",
    "command/exec/write",
    "config/batchWrite",
    "config/mcpServer/reload",
    "config/read",
    "config/value/write",
    "configRequirements/read",
    "experimentalFeature/enablement/set",
    "experimentalFeature/list",
    "externalAgentConfig/detect",
    "externalAgentConfig/import",
    "feedback/upload",
    "fs/copy",
    "fs/createDirectory",
    "fs/getMetadata",
    "fs/readDirectory",
    "fs/readFile",
    "fs/remove",
    "fs/unwatch",
    "fs/watch",
    "fs/writeFile",
    "fuzzyFileSearch",
    "hooks/list",
    "initialize",
    "marketplace/add",
    "marketplace/remove",
    "marketplace/upgrade",
    "mcpServer/oauth/login",
    "mcpServer/resource/read",
    "mcpServer/tool/call",
    "mcpServerStatus/list",
    "model/list",
    "modelProvider/capabilities/read",
    "permissionProfile/list",
    "plugin/install",
    "plugin/installed",
    "plugin/list",
    "plugin/read",
    "plugin/share/checkout",
    "plugin/share/delete",
    "plugin/share/list",
    "plugin/share/save",
    "plugin/share/updateTargets",
    "plugin/skill/read",
    "plugin/uninstall",
    "review/start",
    "skills/config/write",
    "skills/extraRoots/set",
    "skills/list",
    "thread/approveGuardianDeniedAction",
    "thread/archive",
    "thread/compact/start",
    "thread/fork",
    "thread/goal/clear",
    "thread/goal/get",
    "thread/goal/set",
    "thread/inject_items",
    "thread/list",
    "thread/loaded/list",
    "thread/metadata/update",
    "thread/name/set",
    "thread/read",
    "thread/resume",
    "thread/rollback",
    "thread/shellCommand",
    "thread/start",
    "thread/turns/list",
    "thread/unarchive",
    "thread/unsubscribe",
    "turn/interrupt",
    "turn/start",
    "turn/steer",
    "windowsSandbox/readiness",
    "windowsSandbox/setupStart",
  ]

  static let observedServerNotifications: Set<String> = [
    "account/login/completed",
    "account/rateLimits/updated",
    "account/updated",
    "app/list/updated",
    "command/exec/outputDelta",
    "externalAgentConfig/import/completed",
    "fs/changed",
    "fuzzyFileSearch/sessionCompleted",
    "fuzzyFileSearch/sessionUpdated",
    "hook/completed",
    "hook/started",
    "item/agentMessage/delta",
    "item/autoApprovalReview/completed",
    "item/autoApprovalReview/started",
    "item/commandExecution/outputDelta",
    "item/commandExecution/terminalInteraction",
    "item/completed",
    "item/fileChange/outputDelta",
    "item/fileChange/patchUpdated",
    "item/mcpToolCall/progress",
    "item/plan/delta",
    "item/reasoning/summaryPartAdded",
    "item/reasoning/summaryTextDelta",
    "item/reasoning/textDelta",
    "item/started",
    "mcpServer/oauthLogin/completed",
    "mcpServer/startupStatus/updated",
    "model/rerouted",
    "model/verification",
    "process/exited",
    "process/outputDelta",
    "remoteControl/status/changed",
    "serverRequest/resolved",
    "skills/changed",
    "thread/archived",
    "thread/closed",
    "thread/compacted",
    "thread/goal/cleared",
    "thread/goal/updated",
    "thread/name/updated",
    "thread/realtime/closed",
    "thread/realtime/error",
    "thread/realtime/itemAdded",
    "thread/realtime/outputAudio/delta",
    "thread/realtime/sdp",
    "thread/realtime/started",
    "thread/realtime/transcript/delta",
    "thread/realtime/transcript/done",
    "thread/settings/updated",
    "thread/started",
    "thread/status/changed",
    "thread/tokenUsage/updated",
    "thread/unarchived",
    "turn/completed",
    "turn/diff/updated",
    "turn/plan/updated",
    "turn/started",
    "warning",
    "guardianWarning",
    "deprecationNotice",
    "configWarning",
    "windows/worldWritableWarning",
    "windowsSandbox/setupCompleted",
  ]

  static let observedServerRequests: Set<String> = [
    "account/chatgptAuthTokens/refresh",
    "attestation/generate",
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval",
    "item/tool/call",
    "item/tool/requestUserInput",
    "mcpServer/elicitation/request",
    "applyPatchApproval",
    "execCommandApproval",
  ]

  static let liveOnlyAppServerMethods: Set<String> = [
    "thread/turns/list",
  ]
}

enum CodexAppServerMethodClassifier {
  static func safety(for method: String) -> CodexRemoteSafety {
    if readOnlyMethods.contains(method) {
      return .readOnly
    }
    if filesystemReadMethods.contains(method) {
      return .filesystemRead
    }
    if filesystemMutationMethods.contains(method) {
      return .filesystemMutation
    }
    if commandExecutionMethods.contains(method) {
      return .commandExecution
    }
    if pluginOrMCPMutationMethods.contains(method) {
      return .pluginOrMCPMutation
    }
    if accountMutationMethods.contains(method) {
      return .accountMutation
    }
    return .sessionMutation
  }

  private static let readOnlyMethods: Set<String> = [
    "account/read",
    "account/rateLimits/read",
    "app/list",
    "config/read",
    "configRequirements/read",
    "experimentalFeature/list",
    "externalAgentConfig/detect",
    "fuzzyFileSearch",
    "hooks/list",
    "initialize",
    "mcpServer/resource/read",
    "mcpServerStatus/list",
    "model/list",
    "modelProvider/capabilities/read",
    "permissionProfile/list",
    "plugin/installed",
    "plugin/list",
    "plugin/read",
    "plugin/share/list",
    "plugin/skill/read",
    "skills/list",
    "thread/goal/get",
    "thread/list",
    "thread/loaded/list",
    "thread/read",
    "windowsSandbox/readiness",
  ]

  private static let filesystemReadMethods: Set<String> = [
    "fs/getMetadata",
    "fs/readDirectory",
    "fs/readFile",
    "fs/watch",
    "fs/unwatch",
  ]

  private static let filesystemMutationMethods: Set<String> = [
    "fs/copy",
    "fs/createDirectory",
    "fs/remove",
    "fs/writeFile",
  ]

  private static let commandExecutionMethods: Set<String> = [
    "command/exec",
    "command/exec/resize",
    "command/exec/terminate",
    "command/exec/write",
    "thread/shellCommand",
  ]

  private static let pluginOrMCPMutationMethods: Set<String> = [
    "config/batchWrite",
    "config/mcpServer/reload",
    "config/value/write",
    "experimentalFeature/enablement/set",
    "externalAgentConfig/import",
    "marketplace/add",
    "marketplace/remove",
    "marketplace/upgrade",
    "mcpServer/oauth/login",
    "mcpServer/tool/call",
    "plugin/install",
    "plugin/share/checkout",
    "plugin/share/delete",
    "plugin/share/save",
    "plugin/share/updateTargets",
    "plugin/uninstall",
    "skills/config/write",
    "skills/extraRoots/set",
    "windowsSandbox/setupStart",
  ]

  private static let accountMutationMethods: Set<String> = [
    "account/login/cancel",
    "account/login/start",
    "account/logout",
    "account/sendAddCreditsNudgeEmail",
    "feedback/upload",
  ]
}

enum CodexAppServerRequestBuilder {
  static func request(id: String, method: String, params: CodexJSONValue) -> CodexJSONValue {
    .object([
      "jsonrpc": .string("2.0"),
      "id": .string(id),
      "method": .string(method),
      "params": params,
    ])
  }

  static func notification(method: String, params: CodexJSONValue) -> CodexJSONValue {
    .object([
      "jsonrpc": .string("2.0"),
      "method": .string(method),
      "params": params,
    ])
  }

  static func initialize(id: String) -> CodexJSONValue {
    request(
      id: id,
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
  }

  static func initializedNotification() -> CodexJSONValue {
    notification(method: "initialized", params: .object([:]))
  }

  static func listThreads(id: String, limit: Int, cursor: String? = nil, cwd: String? = nil, searchTerm: String? = nil) -> CodexJSONValue {
    var params: [String: CodexJSONValue] = [
      "limit": .int(limit),
      "archived": .bool(false),
      "sortKey": .string("updated_at"),
      "sortDirection": .string("desc"),
      "useStateDbOnly": .bool(false),
    ]
    params["cursor"] = cursor.map(CodexJSONValue.string) ?? .null
    if let cwd {
      params["cwd"] = .string(cwd)
    }
    if let searchTerm {
      params["searchTerm"] = .string(searchTerm)
    }
    return request(id: id, method: "thread/list", params: .object(params))
  }

  static func readThread(id: String, threadID: String, includeTurns: Bool = true) -> CodexJSONValue {
    request(
      id: id,
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        "includeTurns": .bool(includeTurns),
      ])
    )
  }

  static func listThreadTurns(id: String, threadID: String, limit: Int, cursor: CodexThreadTurnsCursor? = nil) -> CodexJSONValue {
    request(
      id: id,
      method: "thread/turns/list",
      params: .object([
        "threadId": .string(threadID),
        "limit": .int(limit),
        "cursor": cursor.map { .string($0.rawValue) } ?? .null,
      ])
    )
  }

  static func loadedThreads(id: String) -> CodexJSONValue {
    request(id: id, method: "thread/loaded/list", params: .object([:]))
  }

  static func startThread(id: String, cwd: String? = nil, model: String? = nil) -> CodexJSONValue {
    var params: [String: CodexJSONValue] = [
      "threadSource": .string("user"),
      "sessionStartSource": .string("startup"),
    ]
    if let cwd {
      params["cwd"] = .string(cwd)
    }
    if let model {
      params["model"] = .string(model)
    }
    return request(id: id, method: "thread/start", params: .object(params))
  }

  static func startTurn(id: String, threadID: String, text: String, localImagePaths: [String] = []) -> CodexJSONValue {
    let textInput: CodexJSONValue = .object([
      "type": .string("text"),
      "text": .string(text),
    ])
    let images = localImagePaths.map { path in
      CodexJSONValue.object([
        "type": .string("localImage"),
        "path": .string(path),
        "detail": .string("auto"),
      ])
    }
    return request(
      id: id,
      method: "turn/start",
      params: .object([
        "threadId": .string(threadID),
        "input": .array([textInput] + images),
      ])
    )
  }

  static func steerTurn(id: String, threadID: String, expectedTurnID: String, text: String) -> CodexJSONValue {
    request(
      id: id,
      method: "turn/steer",
      params: .object([
        "threadId": .string(threadID),
        "expectedTurnId": .string(expectedTurnID),
        "input": .array([
          .object([
            "type": .string("text"),
            "text": .string(text),
          ]),
        ]),
      ])
    )
  }

  static func interruptTurn(id: String, threadID: String, turnID: String) -> CodexJSONValue {
    request(
      id: id,
      method: "turn/interrupt",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
      ])
    )
  }

  static func archiveThread(id: String, threadID: String) -> CodexJSONValue {
    request(id: id, method: "thread/archive", params: .object(["threadId": .string(threadID)]))
  }

  static func unarchiveThread(id: String, threadID: String) -> CodexJSONValue {
    request(id: id, method: "thread/unarchive", params: .object(["threadId": .string(threadID)]))
  }

  static func readFile(id: String, path: String) -> CodexJSONValue {
    request(id: id, method: "fs/readFile", params: .object(["path": .string(path)]))
  }

  static func readDirectory(id: String, path: String) -> CodexJSONValue {
    request(id: id, method: "fs/readDirectory", params: .object(["path": .string(path)]))
  }

  static func readFileMetadata(id: String, path: String) -> CodexJSONValue {
    request(id: id, method: "fs/getMetadata", params: .object(["path": .string(path)]))
  }

  static func listModels(id: String, limit: Int = 50) -> CodexJSONValue {
    request(id: id, method: "model/list", params: .object(["limit": .int(limit), "includeHidden": .bool(false)]))
  }

  static func readAccount(id: String) -> CodexJSONValue {
    request(id: id, method: "account/read", params: .object(["refreshToken": .bool(false)]))
  }

  static func readConfig(id: String, cwd: String? = nil) -> CodexJSONValue {
    var params: [String: CodexJSONValue] = ["includeLayers": .bool(true)]
    params["cwd"] = cwd.map(CodexJSONValue.string) ?? .null
    return request(id: id, method: "config/read", params: .object(params))
  }
}

struct CodexThreadTurnsCursor: Equatable, Hashable {
  var turnID: String
  var includeAnchor: Bool

  private struct Payload: Codable {
    var turnId: String
    var includeAnchor: Bool

    enum CodingKeys: String, CodingKey {
      case turnId
      case includeAnchor
    }

    init(turnId: String, includeAnchor: Bool) {
      self.turnId = turnId
      self.includeAnchor = includeAnchor
    }

    init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      self.turnId = try container.decode(String.self, forKey: .turnId)
      self.includeAnchor = try container.decodeIfPresent(Bool.self, forKey: .includeAnchor) ?? false
    }
  }

  init(turnID: String, includeAnchor: Bool) {
    self.turnID = turnID
    self.includeAnchor = includeAnchor
  }

  init?(rawValue: String) {
    guard
      let data = rawValue.data(using: .utf8),
      let payload = try? JSONDecoder().decode(Payload.self, from: data)
    else {
      return nil
    }
    self.turnID = payload.turnId
    self.includeAnchor = payload.includeAnchor
  }

  var rawValue: String {
    let payload = Payload(turnId: turnID, includeAnchor: includeAnchor)
    let data = (try? JSONEncoder().encode(payload)) ?? Data()
    return String(data: data, encoding: .utf8) ?? ""
  }
}
