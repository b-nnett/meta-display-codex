import CoreBluetooth
import SwiftUI

struct ContentView: View {
  @EnvironmentObject private var scanner: BluetoothScanner
  @State private var psmText = ""
  @State private var identityBase64Text = ""
  @State private var identityFilePathText = ""
  @State private var authGatePathText = ""

  var body: some View {
    NavigationSplitView {
      VStack(alignment: .leading, spacing: 12) {
        header
        deviceList
      }
      .padding()
      .navigationSplitViewColumnWidth(min: 320, ideal: 360)
    } detail: {
      VStack(alignment: .leading, spacing: 16) {
        controlPanel
        servicePanel
        eventPanel
        logPanel
      }
      .padding()
    }
  }

  private var header: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("Codex Band Bridge")
        .font(.title2.weight(.semibold))
      Text(scanner.bluetoothStateDescription)
        .font(.callout)
        .foregroundStyle(scanner.isBluetoothReady ? Color.secondary : Color.red)

      HStack {
        Button {
          scanner.startScan()
        } label: {
          Label("Scan", systemImage: "dot.radiowaves.left.and.right")
        }
        .disabled(!scanner.isBluetoothReady || scanner.isScanning)

        Button {
          scanner.stopScan()
        } label: {
          Label("Stop", systemImage: "stop.fill")
        }
        .disabled(!scanner.isScanning)
      }
      .buttonStyle(.bordered)
    }
  }

  private var deviceList: some View {
    List(selection: $scanner.selectedPeripheralID) {
      ForEach(scanner.discoveredPeripherals) { item in
        VStack(alignment: .leading, spacing: 4) {
          HStack(spacing: 8) {
            Text(item.displayName)
              .font(.headline)
            if item.isCandidate {
              Text(item.isExactBand ? "Target band" : "Likely band")
                .font(.caption.weight(.medium))
                .foregroundStyle(.green)
            }
          }
          HStack {
            Text("RSSI \(item.rssi)")
            Text(item.id.uuidString.prefix(8))
          }
          .font(.caption)
          .foregroundStyle(.secondary)
        }
        .tag(item.id)
      }
    }
    .overlay {
      if scanner.discoveredPeripherals.isEmpty {
        ContentUnavailableView(
          scanner.isScanning ? "Scanning" : "No devices yet",
          systemImage: scanner.isScanning ? "dot.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash",
          description: Text(scanner.isScanning ? "Keep the band in pairing mode." : "Start scanning when the band is in pairing mode.")
        )
      }
    }
  }

  private var controlPanel: some View {
    GroupBox("Connection") {
      Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
        GridRow {
          Text("Selected")
            .foregroundStyle(.secondary)
          Text(scanner.selectedPeripheralName)
        }
        GridRow {
          Text("Status")
            .foregroundStyle(.secondary)
          Text(scanner.connectionDescription)
        }
        GridRow {
          Text("Secure Link")
            .foregroundStyle(.secondary)
          Text(scanner.secureLinkDescription)
        }
        GridRow {
          Text("AirShield")
            .foregroundStyle(.secondary)
          Text(scanner.airShieldValidationDescription)
        }
        GridRow {
          Text("Identity")
            .foregroundStyle(.secondary)
          Text(scanner.airShieldIdentityDescription)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Auth")
            .foregroundStyle(.secondary)
          Text(scanner.airShieldAuthCandidateDescription)
        }
        GridRow {
          Text("Auth Gate")
            .foregroundStyle(.secondary)
          Text(scanner.airShieldAuthGateDescription)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Reconnect")
            .foregroundStyle(.secondary)
          Text(scanner.reconnectDescription)
        }
        GridRow {
          Text("L2CAP")
            .foregroundStyle(.secondary)
          Text(scanner.isL2CAPOpen ? "Open" : "Closed")
        }
        GridRow {
          Text("Frames")
            .foregroundStyle(.secondary)
          Text("raw \(scanner.rawFrameCount) / decoded \(scanner.decodedFrameCount)")
        }
        GridRow {
          Text("Log")
            .foregroundStyle(.secondary)
          Text(scanner.logFilePath)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Events")
            .foregroundStyle(.secondary)
          Text(scanner.gestureEventFilePath)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Session")
            .foregroundStyle(.secondary)
          VStack(alignment: .leading, spacing: 3) {
            Text(scanner.sessionSummaryFilePath)
            Text(scanner.sessionEventFilePath)
          }
          .textSelection(.enabled)
          .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Direct Write Trigger")
            .foregroundStyle(.secondary)
          Text(scanner.directWriteTriggerFilePath)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Rescan Trigger")
            .foregroundStyle(.secondary)
          Text(scanner.rescanTriggerFilePath)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("Socket")
            .foregroundStyle(.secondary)
          Text(scanner.gestureSocketEndpoint)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("WebSocket")
            .foregroundStyle(.secondary)
          Text(scanner.gestureWebSocketEndpoint)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("HTTP")
            .foregroundStyle(.secondary)
          Text(scanner.gestureHTTPEndpoint)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
        GridRow {
          Text("LAN HTTP")
            .foregroundStyle(.secondary)
          Text(scanner.gestureLANHTTPEndpoint)
            .textSelection(.enabled)
            .font(.system(.caption, design: .monospaced))
        }
      }

      Divider()

      VStack(alignment: .leading, spacing: 8) {
        Toggle("Auto-connect target band", isOn: $scanner.autoConnectExactBand)
        Toggle("Auto-connect likely pairing band", isOn: $scanner.autoConnectLikelyPairingBand)
        Toggle("Auto-open detected L2CAP", isOn: $scanner.autoOpenDetectedL2CAP)
        Toggle("Dump raw frame hex", isOn: $scanner.dumpRawFrames)
        Toggle("Attempt DataX handshake", isOn: $scanner.attemptDataXHandshake)
      }
      .toggleStyle(.switch)

      Divider()

      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Picker("Identity slot", selection: $scanner.selectedIdentitySlot) {
            ForEach(AirShieldIdentitySlot.allCases) { slot in
              Text(slot.displayName).tag(slot)
            }
          }
          .pickerStyle(.menu)
          SecureField("Base64 private key from Android prefs", text: $identityBase64Text)
            .textFieldStyle(.roundedBorder)
            .frame(minWidth: 260)
          Button {
            scanner.importAirShieldIdentity(base64: identityBase64Text)
            identityBase64Text = ""
          } label: {
            Label("Import", systemImage: "key")
          }
          .disabled(identityBase64Text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
          Button {
            scanner.clearAirShieldIdentity()
            identityBase64Text = ""
            identityFilePathText = ""
          } label: {
            Label("Clear", systemImage: "trash")
          }
        }
        HStack {
          TextField("Base64 identity file path", text: $identityFilePathText)
            .textFieldStyle(.roundedBorder)
            .frame(minWidth: 360)
          Button {
            scanner.importAirShieldIdentity(pathText: identityFilePathText)
          } label: {
            Label("Load File", systemImage: "doc.badge.key")
          }
          .disabled(identityFilePathText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        HStack {
          TextField("EnableTrust gate JSON path", text: $authGatePathText)
            .textFieldStyle(.roundedBorder)
            .frame(minWidth: 360)
          Button {
            scanner.loadAirShieldAuthGate(pathText: authGatePathText)
          } label: {
            Label("Load Gate", systemImage: "checkmark.seal")
          }
          .disabled(authGatePathText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
      }

      Divider()

      HStack {
        Button {
          scanner.connectSelectedPeripheral()
        } label: {
          Label("Connect", systemImage: "link")
        }
        .disabled(scanner.selectedPeripheralID == nil)

        Button {
          scanner.connectStrongestLikelyBand()
        } label: {
          Label("Connect Likely", systemImage: "scope")
        }
        .disabled(!scanner.hasLikelyBandCandidate)

        Button {
          scanner.disconnect()
        } label: {
          Label("Disconnect", systemImage: "xmark.circle")
        }
        .disabled(scanner.connectedPeripheralID == nil)

        Button {
          scanner.rediscoverServices()
        } label: {
          Label("Discover", systemImage: "list.bullet.rectangle")
        }
        .disabled(scanner.connectedPeripheralID == nil)

        Spacer()

        TextField("PSM", text: $psmText)
          .textFieldStyle(.roundedBorder)
          .frame(width: 90)

        Button {
          scanner.openL2CAPChannel(psmText: psmText)
        } label: {
          Label("Open L2CAP", systemImage: "cable.connector")
        }
        .disabled(scanner.connectedPeripheralID == nil || psmText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

        Button {
          scanner.sendAirShieldHandshakeProbe()
        } label: {
          Label("Send Probe", systemImage: "lock.shield")
        }
        .disabled(!scanner.isL2CAPOpen)

        Button {
          scanner.sendAirShieldHandshakeProbeDirectWriteDiagnostic()
        } label: {
          Label("Direct Write", systemImage: "bolt.horizontal")
        }
        .disabled(!scanner.isL2CAPOpen)

        Button {
          scanner.sendAirShieldEnableTrustIfGated()
        } label: {
          Label("Send Auth", systemImage: "person.badge.key")
        }
        .disabled(!scanner.canSendAirShieldEnableTrust)

        Button {
          scanner.sendEncryptedEndLinkSetup()
        } label: {
          Label("End Setup", systemImage: "checkmark.shield")
        }
        .disabled(!scanner.canSendEncryptedEndLinkSetup)

        Button {
          scanner.sendEncryptedGestureEnable()
        } label: {
          Label("Enable Gestures", systemImage: "hand.tap")
        }
        .disabled(!scanner.canSendEncryptedGestureEnable)
      }
      .buttonStyle(.bordered)
    }
  }

  private var servicePanel: some View {
    GroupBox("Services") {
      if scanner.serviceRows.isEmpty {
        Text("Connect to a device to discover services and characteristics.")
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
      } else {
        ScrollView {
          LazyVStack(alignment: .leading, spacing: 8) {
            ForEach(scanner.serviceRows) { row in
              VStack(alignment: .leading, spacing: 4) {
                Text(row.title)
                  .font(.system(.body, design: .monospaced))
                Text(row.detail)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .textSelection(.enabled)
              }
              .frame(maxWidth: .infinity, alignment: .leading)
              .padding(8)
              .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
          }
        }
        .frame(minHeight: 170, maxHeight: 240)
      }
    }
  }

  private var eventPanel: some View {
    GroupBox("Gesture Events") {
      if scanner.gestureEntries.isEmpty {
        Text("No decoded gestures yet.")
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
      } else {
        ScrollView {
          LazyVStack(alignment: .leading, spacing: 6) {
            ForEach(scanner.gestureEntries) { event in
              Text(event.summary)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
          }
        }
        .frame(minHeight: 80, maxHeight: 140)
      }
    }
  }

  private var logPanel: some View {
    GroupBox("Live Log") {
      ScrollViewReader { proxy in
        ScrollView {
          LazyVStack(alignment: .leading, spacing: 6) {
            ForEach(scanner.logEntries) { entry in
              Text(entry.line)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(entry.level.color)
                .textSelection(.enabled)
                .id(entry.id)
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onChange(of: scanner.logEntries.count) { _, _ in
          if let last = scanner.logEntries.last {
            proxy.scrollTo(last.id, anchor: .bottom)
          }
        }
      }
    }
  }
}

private extension BluetoothLogLevel {
  var color: Color {
    switch self {
    case .info:
      .primary
    case .success:
      .green
    case .warning:
      .orange
    case .error:
      .red
    }
  }
}
