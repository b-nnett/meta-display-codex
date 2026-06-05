import SwiftUI
import WebKit

struct CodexOAuthSessionPresenter: View {
  let request: CodexOAuthRequest
  let onCallback: (URL, CodexOAuthRequest) -> Void
  let onCancel: (CodexOAuthRequest) -> Void
  let onError: (String) -> Void

  var body: some View {
    NavigationStack {
      CodexOAuthWebView(
        request: request,
        onCallback: onCallback,
        onError: onError
      )
      .ignoresSafeArea(edges: .bottom)
      .navigationTitle(title)
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") {
            onCancel(request)
          }
        }
      }
    }
  }

  private var title: String {
    switch request.kind {
    case .normal:
      "OpenAI Sign In"
    case .stepUp:
      "Codex Enrollment"
    }
  }
}

struct CodexOAuthWebView: UIViewRepresentable {
  let request: CodexOAuthRequest
  let onCallback: (URL, CodexOAuthRequest) -> Void
  let onError: (String) -> Void

  func makeCoordinator() -> Coordinator {
    Coordinator(request: request, onCallback: onCallback, onError: onError)
  }

  func makeUIView(context: Context) -> WKWebView {
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .default()

    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = context.coordinator
    webView.customUserAgent = CodexOAuthConstants.webViewUserAgent
    webView.allowsBackForwardNavigationGestures = true
    context.coordinator.loadedRequestID = request.id
    webView.load(URLRequest(url: request.authorizationURL))
    return webView
  }

  func updateUIView(_ webView: WKWebView, context: Context) {
    context.coordinator.update(request: request, onCallback: onCallback, onError: onError)

    guard context.coordinator.loadedRequestID != request.id else {
      return
    }

    context.coordinator.loadedRequestID = request.id
    webView.load(URLRequest(url: request.authorizationURL))
  }

  final class Coordinator: NSObject, WKNavigationDelegate {
    var loadedRequestID: UUID?
    private var request: CodexOAuthRequest
    private var onCallback: (URL, CodexOAuthRequest) -> Void
    private var onError: (String) -> Void
    private var didFinishWithCallback = false

    init(
      request: CodexOAuthRequest,
      onCallback: @escaping (URL, CodexOAuthRequest) -> Void,
      onError: @escaping (String) -> Void
    ) {
      self.request = request
      self.onCallback = onCallback
      self.onError = onError
    }

    func update(
      request: CodexOAuthRequest,
      onCallback: @escaping (URL, CodexOAuthRequest) -> Void,
      onError: @escaping (String) -> Void
    ) {
      self.request = request
      self.onCallback = onCallback
      self.onError = onError
    }

    func webView(
      _ webView: WKWebView,
      decidePolicyFor navigationAction: WKNavigationAction,
      decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
      guard let url = navigationAction.request.url else {
        decisionHandler(.allow)
        return
      }

      if isCodexCallback(url) {
        didFinishWithCallback = true
        decisionHandler(.cancel)
        onCallback(url, request)
        return
      }

      decisionHandler(.allow)
    }

    func webView(
      _ webView: WKWebView,
      didFailProvisionalNavigation navigation: WKNavigation!,
      withError error: Error
    ) {
      guard !didFinishWithCallback else {
        return
      }

      onError(error.localizedDescription)
    }

    func webView(
      _ webView: WKWebView,
      didFail navigation: WKNavigation!,
      withError error: Error
    ) {
      guard !didFinishWithCallback else {
        return
      }

      onError(error.localizedDescription)
    }

    private func isCodexCallback(_ url: URL) -> Bool {
      url.scheme == CodexOAuthConstants.callbackScheme
        && url.host == CodexOAuthConstants.callbackHost
        && url.path == CodexOAuthConstants.callbackPath
    }
  }
}

struct TokenImportView: View {
  @Environment(\.dismiss) private var dismiss
  @State private var token = ""

  let onImport: (String) -> Void

  var body: some View {
    NavigationStack {
      Form {
        Section("Access Token") {
          SecureField("Paste token", text: $token)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        }
      }
      .navigationTitle("Import Token")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") {
            dismiss()
          }
        }
        ToolbarItem(placement: .confirmationAction) {
          Button("Import") {
            onImport(token)
            dismiss()
          }
          .disabled(token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
      }
    }
  }
}
