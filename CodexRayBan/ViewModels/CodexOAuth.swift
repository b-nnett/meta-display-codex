import CryptoKit
import Foundation
import Security

enum CodexOAuthKind: String, Sendable {
  case normal
  case stepUp
}

struct CodexOAuthRequest: Identifiable, Sendable {
  let id = UUID()
  let kind: CodexOAuthKind
  let authorizationURL: URL
  let codeVerifier: String
  let state: String
  let redirectURI: String
}

struct CodexOAuthTokenResponse: Decodable {
  let accessToken: String
  let refreshToken: String?
  let expiresIn: Int?
  let scope: String?
  let tokenType: String?

  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
    case expiresIn = "expires_in"
    case scope
    case tokenType = "token_type"
  }
}

struct CodexOAuthConfig {
  let clientID: String
  let authorizationURL: URL
  let tokenURL: URL
  let redirectURI: String
  let scope: String
  let audience: String?
  let extraParameters: [(String, String)]

  static func desktopNormal() -> CodexOAuthConfig {
    CodexOAuthConfig(
      clientID: CodexOAuthConstants.desktopClientID,
      authorizationURL: CodexOAuthConstants.authorizeURL,
      tokenURL: CodexOAuthConstants.tokenURL,
      redirectURI: CodexOAuthConstants.redirectURI,
      scope: "openid profile email offline_access",
      audience: nil,
      extraParameters: [
        ("originator", CodexRemoteConstants.originator),
        ("codex_cli_simplified_flow", "true"),
      ]
    )
  }

  static func desktopStepUp(accountID: String?) -> CodexOAuthConfig {
    var extras: [(String, String)] = [
      ("originator", CodexRemoteConstants.originator),
      ("reauth", "remote_control"),
      ("max_age", "0"),
      ("codex_cli_simplified_flow", "true"),
    ]

    if let accountID, !accountID.isEmpty {
      extras.append(("allowed_workspace_id", accountID))
      extras.append(("current_workspace_id", accountID))
    }

    return CodexOAuthConfig(
      clientID: CodexOAuthConstants.desktopClientID,
      authorizationURL: CodexOAuthConstants.authorizeURL,
      tokenURL: CodexOAuthConstants.tokenURL,
      redirectURI: CodexOAuthConstants.redirectURI,
      scope: "codex.remote_control.enroll",
      audience: nil,
      extraParameters: extras
    )
  }
}

enum CodexOAuthConstants {
  static var desktopClientID: String {
    guard let value = Bundle.main.object(forInfoDictionaryKey: "CodexOAuthClientID") as? String else {
      return ""
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.hasPrefix("$(") ? "" : trimmed
  }

  static let redirectURI = "http://localhost:1455/auth/callback"
  static let callbackScheme = "http"
  static let callbackHost = "localhost"
  static let callbackPath = "/auth/callback"
  static let webViewUserAgent =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1"
  static let authorizeURL = URL(string: "https://auth.openai.com/oauth/authorize")!
  static let tokenURL = URL(string: "https://auth.openai.com/oauth/token")!
}

enum CodexOAuthError: LocalizedError {
  case invalidAuthorizationURL
  case stateMismatch
  case missingAuthorizationCode
  case authorizationFailed(String)
  case tokenExchangeFailed(Int, String)
  case randomGenerationFailed(OSStatus)

  var errorDescription: String? {
    switch self {
    case .invalidAuthorizationURL:
      "Invalid authorization URL."
    case .stateMismatch:
      "OAuth state did not match."
    case .missingAuthorizationCode:
      "OAuth callback did not include an authorization code."
    case .authorizationFailed(let message):
      message
    case .tokenExchangeFailed(let status, let message):
      "Token exchange failed with HTTP \(status): \(message)"
    case .randomGenerationFailed(let status):
      "Secure random generation failed: \(status)"
    }
  }
}

enum CodexPKCE {
  static func makeRequest(kind: CodexOAuthKind, config: CodexOAuthConfig) throws -> CodexOAuthRequest {
    let codeVerifier = try randomBase64URL(byteCount: 32)
    let state = try randomBase64URL(byteCount: 32)
    let challenge = codeChallenge(for: codeVerifier)

    guard var components = URLComponents(url: config.authorizationURL, resolvingAgainstBaseURL: false) else {
      throw CodexOAuthError.invalidAuthorizationURL
    }

    var items: [URLQueryItem] = [
      URLQueryItem(name: "response_type", value: "code"),
      URLQueryItem(name: "client_id", value: config.clientID),
      URLQueryItem(name: "redirect_uri", value: config.redirectURI),
      URLQueryItem(name: "scope", value: config.scope),
      URLQueryItem(name: "code_challenge", value: challenge),
      URLQueryItem(name: "code_challenge_method", value: "S256"),
      URLQueryItem(name: "state", value: state),
    ]

    if let audience = config.audience {
      items.append(URLQueryItem(name: "audience", value: audience))
    }

    items.append(contentsOf: config.extraParameters.map { URLQueryItem(name: $0.0, value: $0.1) })
    components.queryItems = items

    guard let url = components.url else {
      throw CodexOAuthError.invalidAuthorizationURL
    }

    return CodexOAuthRequest(
      kind: kind,
      authorizationURL: url,
      codeVerifier: codeVerifier,
      state: state,
      redirectURI: config.redirectURI
    )
  }

  static func code(from callbackURL: URL, expectedState: String) throws -> String {
    guard
      let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)
    else {
      throw CodexOAuthError.invalidAuthorizationURL
    }

    if components.queryItems?.first(where: { $0.name == "state" })?.value != expectedState {
      throw CodexOAuthError.stateMismatch
    }

    if let error = components.queryItems?.first(where: { $0.name == "error" })?.value {
      let description = components.queryItems?.first(where: { $0.name == "error_description" })?.value
      throw CodexOAuthError.authorizationFailed(description ?? error)
    }

    guard let code = components.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty else {
      throw CodexOAuthError.missingAuthorizationCode
    }

    return code
  }

  private static func codeChallenge(for codeVerifier: String) -> String {
    let digest = SHA256.hash(data: Data(codeVerifier.utf8))
    return Data(digest).base64URLEncodedString()
  }

  private static func randomBase64URL(byteCount: Int) throws -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
      throw CodexOAuthError.randomGenerationFailed(status)
    }
    return Data(bytes).base64URLEncodedString()
  }
}

struct CodexOAuthService {
  func exchangeAuthorizationCode(
    _ code: String,
    request: CodexOAuthRequest,
    config: CodexOAuthConfig
  ) async throws -> CodexOAuthTokenResponse {
    var urlRequest = URLRequest(url: config.tokenURL)
    urlRequest.httpMethod = "POST"
    urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")

    var components = URLComponents()
    components.queryItems = [
      URLQueryItem(name: "grant_type", value: "authorization_code"),
      URLQueryItem(name: "code", value: code),
      URLQueryItem(name: "redirect_uri", value: request.redirectURI),
      URLQueryItem(name: "client_id", value: config.clientID),
      URLQueryItem(name: "code_verifier", value: request.codeVerifier),
    ]
    urlRequest.httpBody = components.percentEncodedQuery?.data(using: .utf8)

    let (data, response) = try await URLSession.shared.data(for: urlRequest)
    guard let httpResponse = response as? HTTPURLResponse else {
      throw CodexOAuthError.tokenExchangeFailed(-1, "Missing HTTP response")
    }

    guard (200..<300).contains(httpResponse.statusCode) else {
      let body = String(data: data, encoding: .utf8) ?? ""
      throw CodexOAuthError.tokenExchangeFailed(httpResponse.statusCode, body)
    }

    return try JSONDecoder().decode(CodexOAuthTokenResponse.self, from: data)
  }

  func refreshAccessToken(_ refreshToken: String) async throws -> CodexOAuthTokenResponse {
    var urlRequest = URLRequest(url: CodexOAuthConstants.tokenURL)
    urlRequest.httpMethod = "POST"
    urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")

    var components = URLComponents()
    components.queryItems = [
      URLQueryItem(name: "grant_type", value: "refresh_token"),
      URLQueryItem(name: "refresh_token", value: refreshToken),
      URLQueryItem(name: "client_id", value: CodexOAuthConstants.desktopClientID),
    ]
    urlRequest.httpBody = components.percentEncodedQuery?.data(using: .utf8)

    let (data, response) = try await URLSession.shared.data(for: urlRequest)
    guard let httpResponse = response as? HTTPURLResponse else {
      throw CodexOAuthError.tokenExchangeFailed(-1, "Missing HTTP response")
    }

    guard (200..<300).contains(httpResponse.statusCode) else {
      let body = String(data: data, encoding: .utf8) ?? ""
      throw CodexOAuthError.tokenExchangeFailed(httpResponse.statusCode, body)
    }

    return try JSONDecoder().decode(CodexOAuthTokenResponse.self, from: data)
  }
}
