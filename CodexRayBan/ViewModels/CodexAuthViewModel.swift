import Foundation
import Observation

struct CodexAuthDebugRow: Identifiable {
  let title: String
  let value: String

  var id: String { title }
}

struct CodexAuthLogEntry: Identifiable {
  let id = UUID()
  let timestamp: Date
  let message: String

  var displayText: String {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss"
    return "\(formatter.string(from: timestamp))  \(message)"
  }
}

struct CodexAppServerAuthTokens: Sendable {
  let accessToken: String
  let chatgptAccountID: String
  let chatgptPlanType: String?
}

@Observable
@MainActor
class CodexAuthViewModel {
  var session: CodexAuthSession
  var environments: [CodexEnvironment] = []
  var isBusy = false
  var errorMessage: String?
  var activeOAuthRequest: CodexOAuthRequest?
  var showsTokenImport = false
  var lastAuthEvent = "Idle"
  var authLogEntries: [CodexAuthLogEntry] = []

  @ObservationIgnored private let secureStore: CodexSecureStore
  @ObservationIgnored private let deviceKeyStore: CodexDeviceKeyStore
  @ObservationIgnored private let oauthService: CodexOAuthService
  @ObservationIgnored private let remoteClient: CodexRemoteClient
  @ObservationIgnored private var activeOAuthConfig: CodexOAuthConfig?
  @ObservationIgnored private var isRefreshingRemoteToken = false
  @ObservationIgnored private var remoteTokenRefreshWaiters: [CheckedContinuation<Bool, Never>] = []

  init(
    secureStore: CodexSecureStore = CodexSecureStore(),
    deviceKeyStore: CodexDeviceKeyStore = CodexDeviceKeyStore(),
    oauthService: CodexOAuthService = CodexOAuthService(),
    remoteClient: CodexRemoteClient = CodexRemoteClient(),
    loadSavedSession: Bool = !CodexRuntimeEnvironment.isRunningTests
  ) {
    self.secureStore = secureStore
    self.deviceKeyStore = deviceKeyStore
    self.oauthService = oauthService
    self.remoteClient = remoteClient
    self.session = loadSavedSession ? secureStore.loadSession() : CodexAuthSession()
    log("Loaded saved session: signedIn=\(session.isSignedIn), remoteEnrolled=\(session.isRemoteEnrolled), account=\(shortened(session.accountID)), remoteClient=\(shortened(session.remoteClientID))")
  }

  var accountStatusText: String {
    session.isSignedIn ? "Signed in" : "Not signed in"
  }

  var enrollmentStatusText: String {
    if session.remoteTokenIsFresh {
      return "Ready"
    }
    if session.isRemoteEnrolled {
      return "Refresh needed"
    }
    return "Not enrolled"
  }

  var hostStatusText: String {
    if environments.isEmpty {
      return "No hosts loaded"
    }
    let onlineCount = environments.filter(\.online).count
    return "\(onlineCount) online / \(environments.count) total"
  }

  var glassesStatusTitle: String {
    if !session.isSignedIn {
      return "Codex sign-in needed"
    }
    if !session.isRemoteEnrolled {
      return "Codex enrollment needed"
    }
    return "Codex ready"
  }

  var glassesStatusDetail: String {
    [
      "Account: \(accountStatusText)",
      "Remote: \(enrollmentStatusText)",
      "Hosts: \(hostStatusText)",
    ].joined(separator: "\n")
  }

  var debugRows: [CodexAuthDebugRow] {
    [
      CodexAuthDebugRow(title: "Last event", value: lastAuthEvent),
      CodexAuthDebugRow(title: "Account id", value: shortened(session.accountID)),
      CodexAuthDebugRow(title: "Account user", value: shortened(session.accountUserID)),
      CodexAuthDebugRow(title: "Access token", value: session.normalAccessToken?.isEmpty == false ? "stored" : "missing"),
      CodexAuthDebugRow(title: "Access expiry", value: dateText(session.normalExpiresAt)),
      CodexAuthDebugRow(title: "Remote client", value: shortened(session.remoteClientID)),
      CodexAuthDebugRow(title: "Remote user", value: shortened(session.remoteAccountUserID)),
      CodexAuthDebugRow(title: "Remote token", value: session.remoteControlToken?.isEmpty == false ? "stored" : "missing"),
      CodexAuthDebugRow(title: "Remote expiry", value: dateText(session.remoteControlExpiresAt)),
    ]
  }

  var authLogText: String {
    authLogEntries.map(\.displayText).joined(separator: "\n")
  }

  func startNormalSignIn() {
    do {
      let config = CodexOAuthConfig.desktopNormal()
      log("Normal sign-in start: \(configSummary(config))")
      activeOAuthConfig = config
      activeOAuthRequest = try CodexPKCE.makeRequest(kind: .normal, config: config)
      log("Normal sign-in URL ready: \(urlSummary(activeOAuthRequest?.authorizationURL))")
    } catch {
      showError(error)
    }
  }

  func startRemoteEnrollment() {
    do {
      _ = try requireNormalToken()
      let config = CodexOAuthConfig.desktopStepUp(accountID: session.accountID)
      log("Remote enrollment OAuth start: account=\(shortened(session.accountID)), user=\(shortened(session.accountUserID)), \(configSummary(config))")
      activeOAuthConfig = config
      activeOAuthRequest = try CodexPKCE.makeRequest(kind: .stepUp, config: config)
      log("Remote enrollment URL ready: \(urlSummary(activeOAuthRequest?.authorizationURL))")
    } catch {
      showError(error)
    }
  }

  func handleOAuthCallback(_ url: URL, request: CodexOAuthRequest) async {
    guard let config = activeOAuthConfig else {
      log("OAuth callback arrived without active config: \(urlSummary(url))")
      showError(CodexOAuthError.invalidAuthorizationURL)
      return
    }

    activeOAuthRequest = nil
    isBusy = true
    defer { isBusy = false }

    do {
      log("OAuth callback received: kind=\(request.kind.rawValue), \(urlSummary(url))")
      let code = try CodexPKCE.code(from: url, expectedState: request.state)
      log("OAuth callback validated: kind=\(request.kind.rawValue), codeLength=\(code.count)")
      log("OAuth exchange start: tokenURL=\(config.tokenURL.host() ?? "unknown"), redirect=\(request.redirectURI), scope=\(config.scope)")
      let tokenResponse = try await oauthService.exchangeAuthorizationCode(
        code,
        request: request,
        config: config
      )
      log("OAuth exchange success: \(tokenSummary(tokenResponse))")

      switch request.kind {
      case .normal:
        try storeNormalToken(tokenResponse)
        await refreshHosts()
      case .stepUp:
        log("Step-up token received, starting remote enrollment finish")
        try await completeEnrollment(stepUpToken: tokenResponse.accessToken)
        await refreshHosts()
      }
    } catch {
      showError(error)
    }
  }

  func importAccessToken(_ token: String) {
    do {
      let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmed.isEmpty else { throw CodexRemoteError.missingNormalToken }
      var next = session
      next.normalAccessToken = trimmed
      next.normalRefreshToken = nil
      next.normalExpiresAt = CodexJWT.expiresAt(from: trimmed)
      next.accountID = CodexJWT.accountID(from: trimmed)
      next.accountUserID = CodexJWT.accountUserID(from: trimmed)
      next.updatedAt = .now
      session = next
      try secureStore.saveSession(next)
      log("Imported token: account=\(shortened(session.accountID)), user=\(shortened(session.accountUserID)), expires=\(dateText(session.normalExpiresAt))")
      showsTokenImport = false
    } catch {
      showError(error)
    }
  }

  func refreshHosts() async {
    do {
      let accessToken = try requireNormalToken()
      let accountID = try requireAccountID()
      log("Host list start: account=\(shortened(accountID)), token=stored")
      isBusy = true
      defer { isBusy = false }
      environments = try await remoteClient.listEnvironments(
        accessToken: accessToken,
        accountID: accountID
      )
      let onlineCount = environments.filter(\.online).count
      log("Host list success: total=\(environments.count), online=\(onlineCount), names=\(environments.map(\.displayName).joined(separator: ", "))")
    } catch {
      showError(error)
    }
  }

  @discardableResult
  func refreshRemoteToken() async -> Bool {
    if isRefreshingRemoteToken {
      log("Remote token refresh wait existing request")
      return await withCheckedContinuation { continuation in
        remoteTokenRefreshWaiters.append(continuation)
      }
    }

    isRefreshingRemoteToken = true
    var succeeded = false
    defer {
      isRefreshingRemoteToken = false
      let waiters = remoteTokenRefreshWaiters
      remoteTokenRefreshWaiters = []
      for waiter in waiters {
        waiter.resume(returning: succeeded)
      }
    }

    do {
      let accessToken = try requireNormalToken()
      let accountID = try requireAccountID()
      guard let clientID = session.remoteClientID, !clientID.isEmpty else {
        throw CodexRemoteError.missingRemoteClientID
      }
      log("Remote token refresh start: account=\(shortened(accountID)), client=\(shortened(clientID))")
      let challenge = try await remoteClient.refreshStart(
        accessToken: accessToken,
        accountID: accountID,
        clientID: clientID
      )
      log("Refresh challenge received: \(challengeSummary(challenge))")
      let key = try deviceKeyStore.loadOrCreate(existingKeyID: session.deviceKeyID)
      log("Device key loaded for refresh: keyID=\(shortened(key.keyID)), publicKeyBytes=\(key.publicKeySPKIDERBase64.count)")
      let proof = try CodexDeviceProofBuilder.proof(for: challenge, key: key)
      log("Refresh proof built: keyID=\(shortened(proof.keyID)), signedPayloadBytes=\(proof.signedPayloadBase64.count)")
      let token = try await remoteClient.refreshFinish(
        accessToken: accessToken,
        accountID: accountID,
        request: CodexRefreshFinishRequest(clientID: clientID, deviceKeyProof: proof)
      )
      log("Refresh finish response: \(remoteTokenSummary(token))")
      try remoteClient.validateRemoteToken(
        token,
        clientID: clientID,
        accountUserID: challenge.accountUserID
      )
      try storeRemoteToken(token, deviceKeyID: key.keyID)
      succeeded = true
    } catch {
      showError(error)
    }
    return succeeded
  }

  func appServerAuthTokens() async throws -> CodexAppServerAuthTokens {
    try await refreshNormalTokenIfNeeded()
    let accessToken = try requireNormalToken()
    let accountID = try requireAccountID()
    log("App-server auth token supplied: account=\(shortened(accountID)), token=stored")
    return CodexAppServerAuthTokens(
      accessToken: accessToken,
      chatgptAccountID: accountID,
      chatgptPlanType: nil
    )
  }

  func signOut() {
    do {
      try deviceKeyStore.delete(keyID: session.deviceKeyID)
      try secureStore.clearSession()
      session = CodexAuthSession()
      environments = []
      activeOAuthRequest = nil
      activeOAuthConfig = nil
      errorMessage = nil
      log("Signed out and cleared Codex auth session")
    } catch {
      showError(error)
    }
  }

  func clearError() {
    errorMessage = nil
    log("Cleared visible auth error")
  }

  func clearAuthLog() {
    authLogEntries = []
    log("Cleared auth log")
  }

  private func completeEnrollment(stepUpToken: String) async throws {
    let accessToken = try requireNormalToken()
    let accountID = try requireAccountID()
    log("Enroll start request: account=\(shortened(accountID)), stepUpToken=stored")
    let start = try await remoteClient.enrollStart(accessToken: accessToken, accountID: accountID)
    log("Enroll start response: client=\(shortened(start.clientID)), user=\(shortened(start.accountUserID)), \(challengeSummary(start.deviceKeyChallenge))")
    let key = try deviceKeyStore.loadOrCreate(existingKeyID: session.deviceKeyID)
    log("Device key loaded for enroll: keyID=\(shortened(key.keyID)), publicKeyChars=\(key.publicKeySPKIDERBase64.count)")
    let identity = CodexDeviceProofBuilder.deviceIdentity(for: key)
    log("Device identity built: keyID=\(shortened(identity.keyID)), algorithm=\(identity.algorithm), protection=\(identity.protectionClass)")
    let proof = try CodexDeviceProofBuilder.proof(for: start.deviceKeyChallenge, key: key)
    log("Enrollment proof built: keyID=\(shortened(proof.keyID)), signedPayloadChars=\(proof.signedPayloadBase64.count), signatureChars=\(proof.signatureDERBase64.count)")
    log("Enroll finish request: client=\(shortened(start.clientID)), target=\(start.deviceKeyChallenge.targetPath)")
    let response = try await remoteClient.enrollFinish(
      accessToken: accessToken,
      accountID: accountID,
      request: CodexEnrollFinishRequest(
        clientID: start.clientID,
        stepUpToken: stepUpToken,
        deviceIdentity: identity,
        deviceKeyProof: proof
      )
    )
    log("Enroll finish response: \(remoteTokenSummary(response))")
    try remoteClient.validateRemoteToken(
      response,
      clientID: start.clientID,
      accountUserID: start.accountUserID
    )
    log("Enroll finish validation passed")
    try storeRemoteToken(response, deviceKeyID: key.keyID)
  }

  private func refreshNormalTokenIfNeeded() async throws {
    if let expiresAt = session.normalExpiresAt, expiresAt > Date().addingTimeInterval(300) {
      return
    }

    guard let refreshToken = session.normalRefreshToken, !refreshToken.isEmpty else {
      log("Normal token refresh skipped: refresh token missing")
      if let expiresAt = session.normalExpiresAt, expiresAt <= Date() {
        throw CodexOAuthError.tokenExchangeFailed(401, "OpenAI sign-in expired. Sign in again.")
      }
      return
    }

    log("Normal token refresh start")
    let response = try await oauthService.refreshAccessToken(refreshToken)
    var next = session
    next.normalAccessToken = response.accessToken
    next.normalRefreshToken = response.refreshToken ?? refreshToken
    if let expiresIn = response.expiresIn {
      next.normalExpiresAt = Date().addingTimeInterval(TimeInterval(expiresIn))
    } else {
      next.normalExpiresAt = CodexJWT.expiresAt(from: response.accessToken)
    }
    next.accountID = CodexJWT.accountID(from: response.accessToken) ?? next.accountID
    next.accountUserID = CodexJWT.accountUserID(from: response.accessToken) ?? next.accountUserID
    next.updatedAt = .now
    session = next
    try secureStore.saveSession(next)
    log("Normal token refresh stored: account=\(shortened(session.accountID)), expires=\(dateText(session.normalExpiresAt))")
  }

  private func storeNormalToken(_ response: CodexOAuthTokenResponse) throws {
    var next = session
    next.normalAccessToken = response.accessToken
    next.normalRefreshToken = response.refreshToken
    if let expiresIn = response.expiresIn {
      next.normalExpiresAt = Date().addingTimeInterval(TimeInterval(expiresIn))
    } else {
      next.normalExpiresAt = CodexJWT.expiresAt(from: response.accessToken)
    }
    next.accountID = CodexJWT.accountID(from: response.accessToken)
    next.accountUserID = CodexJWT.accountUserID(from: response.accessToken)
    next.updatedAt = .now
    session = next
    try secureStore.saveSession(next)
    log("Stored normal token: account=\(shortened(session.accountID)), user=\(shortened(session.accountUserID)), expires=\(dateText(session.normalExpiresAt)), refresh=\(response.refreshToken == nil ? "missing" : "stored")")
  }

  private func storeRemoteToken(_ response: CodexRemoteTokenResponse, deviceKeyID: String) throws {
    var next = session
    next.remoteClientID = response.clientID
    next.remoteAccountUserID = response.accountUserID
    next.remoteControlToken = response.remoteControlToken
    next.remoteControlExpiresAt = response.expiresAt
    next.deviceKeyID = deviceKeyID
    next.updatedAt = .now
    session = next
    try secureStore.saveSession(next)
    log("Stored remote token: client=\(shortened(session.remoteClientID)), user=\(shortened(session.remoteAccountUserID)), expires=\(dateText(session.remoteControlExpiresAt)), keyID=\(shortened(deviceKeyID))")
  }

  private func requireNormalToken() throws -> String {
    guard let token = session.normalAccessToken, !token.isEmpty else {
      throw CodexRemoteError.missingNormalToken
    }
    return token
  }

  private func requireAccountID() throws -> String {
    guard let accountID = session.accountID, !accountID.isEmpty else {
      throw CodexRemoteError.missingAccountID
    }
    return accountID
  }

  private func showError(_ error: Error) {
    let message = error.localizedDescription
    errorMessage = message
    log("ERROR: \(message)")
  }

  private func shortened(_ value: String?) -> String {
    guard let value, !value.isEmpty else {
      return "missing"
    }
    if value.count <= 18 {
      return value
    }
    return "\(value.prefix(10))...\(value.suffix(6))"
  }

  private func dateText(_ date: Date?) -> String {
    guard let date else {
      return "missing"
    }
    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .short
    return formatter.localizedString(for: date, relativeTo: .now)
  }

  private func log(_ message: String) {
    lastAuthEvent = message
    authLogEntries.append(CodexAuthLogEntry(timestamp: .now, message: message))
    if authLogEntries.count > 120 {
      authLogEntries.removeFirst(authLogEntries.count - 120)
    }
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      print("Codex auth log: \(message)")
    }
  }

  private func configSummary(_ config: CodexOAuthConfig) -> String {
    let extras = config.extraParameters.map(\.0).joined(separator: ",")
    return "client=\(config.clientID), scope=\(config.scope), redirect=\(config.redirectURI), extras=[\(extras)]"
  }

  private func urlSummary(_ url: URL?) -> String {
    guard let url else {
      return "url=missing"
    }
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    let queryNames = components?.queryItems?.map(\.name).joined(separator: ",") ?? ""
    return "url=\(url.scheme ?? "?")://\(url.host() ?? "?")\(url.path), query=[\(queryNames)]"
  }

  private func tokenSummary(_ response: CodexOAuthTokenResponse) -> String {
    let accountID = CodexJWT.accountID(from: response.accessToken)
    let userID = CodexJWT.accountUserID(from: response.accessToken)
    let expiresAt = response.expiresIn.map { "in \($0)s" } ?? dateText(CodexJWT.expiresAt(from: response.accessToken))
    return "type=\(response.tokenType ?? "missing"), scope=\(response.scope ?? "missing"), expires=\(expiresAt), refresh=\(response.refreshToken == nil ? "missing" : "stored"), account=\(shortened(accountID)), user=\(shortened(userID))"
  }

  private func challengeSummary(_ challenge: CodexDeviceKeyChallenge) -> String {
    "challenge=\(shortened(challenge.challengeID)), client=\(shortened(challenge.clientID)), user=\(shortened(challenge.accountUserID)), purpose=\(challenge.purpose), audience=\(challenge.audience), target=\(challenge.targetPath), identityHash=\(challenge.deviceIdentityHash == nil ? "missing" : "present"), expiresAt=\(challenge.challengeExpiresAt)"
  }

  private func remoteTokenSummary(_ response: CodexRemoteTokenResponse) -> String {
    "client=\(shortened(response.clientID)), user=\(shortened(response.accountUserID)), token=\(response.remoteControlToken.isEmpty ? "missing" : "stored"), expires=\(dateText(response.expiresAt)), scopes=[\(response.scopes.joined(separator: ","))]"
  }
}
