import SwiftUI

@main
struct BandBridgeApp: App {
  @StateObject private var scanner = BluetoothScanner()

  var body: some Scene {
    WindowGroup {
      ContentView()
        .environmentObject(scanner)
        .frame(minWidth: 980, minHeight: 680)
        .task {
          scanner.startScanningIfPossible()
        }
    }
  }
}
