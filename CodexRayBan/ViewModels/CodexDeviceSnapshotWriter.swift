#if DEBUG
import UIKit

enum CodexDeviceSnapshotWriter {
  static let homeSnapshotArgument = "--codex-device-snapshot-home"
  static let homeSnapshotFilename = "codex-device-home-snapshot.png"
  static let chatSnapshotArgument = "--codex-device-snapshot-chat"
  static let chatSnapshotFilename = "codex-device-chat-snapshot.png"

  static var isHomeSnapshotRequested: Bool {
    ProcessInfo.processInfo.arguments.contains(homeSnapshotArgument)
  }

  static var isChatSnapshotRequested: Bool {
    ProcessInfo.processInfo.arguments.contains(chatSnapshotArgument)
  }

  @MainActor
  static func captureAfterDelay(filename: String = chatSnapshotFilename, delay: TimeInterval = 4.0) {
    Task { @MainActor in
      try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
      do {
        try capture(filename: filename)
        NSLog("[CodexRayBan] Device snapshot saved: \(filename)")
      } catch {
        NSLog("[CodexRayBan] Device snapshot failed: \(error.localizedDescription)")
      }
    }
  }

  @MainActor
  private static func capture(filename: String) throws {
    guard
      let scene = UIApplication.shared.connectedScenes
        .compactMap({ $0 as? UIWindowScene })
        .first(where: { $0.activationState == .foregroundActive }),
      let window = scene.windows.first(where: \.isKeyWindow) ?? scene.windows.first
    else {
      return
    }

    let renderer = UIGraphicsImageRenderer(bounds: window.bounds)
    let image = renderer.image { _ in
      window.drawHierarchy(in: window.bounds, afterScreenUpdates: true)
    }

    guard let data = image.pngData() else {
      return
    }

    let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    try data.write(to: documentsURL.appendingPathComponent(filename), options: .atomic)
  }
}
#endif
