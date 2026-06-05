import Darwin
import Foundation
import CryptoKit

final class LocalEventServer {
  let port: UInt16

  private let queue = DispatchQueue(label: "CodexBandBridge.LocalEventServer")
  private var serverSocket: Int32 = -1
  private var clientSockets: Set<Int32> = []
  private var isRunning = false

  init(port: UInt16 = 49731) {
    self.port = port
    start()
  }

  deinit {
    stop()
  }

  var endpoint: String {
    "127.0.0.1:\(port)"
  }

  func broadcast(_ json: [String: Any]) {
    guard JSONSerialization.isValidJSONObject(json),
          var data = try? JSONSerialization.data(withJSONObject: json) else {
      return
    }
    data.append(0x0a)
    queue.async { [weak self] in
      self?.send(data)
    }
  }

  private func start() {
    queue.async { [weak self] in
      self?.openSocket()
    }
  }

  private func stop() {
    queue.sync {
      isRunning = false
      for client in clientSockets {
        close(client)
      }
      clientSockets.removeAll()
      if serverSocket >= 0 {
        close(serverSocket)
        serverSocket = -1
      }
    }
  }

  private func openSocket() {
    guard !isRunning else {
      return
    }

    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else {
      return
    }

    var reuse: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

    let bindResult = withUnsafePointer(to: &addr) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
        Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }

    guard bindResult == 0, listen(fd, 8) == 0 else {
      close(fd)
      return
    }

    serverSocket = fd
    isRunning = true
    DispatchQueue.global(qos: .utility).async { [weak self] in
      self?.acceptLoop(fd)
    }
  }

  private func acceptLoop(_ fd: Int32) {
    while true {
      var addr = sockaddr()
      var length = socklen_t(MemoryLayout<sockaddr>.size)
      let client = withUnsafeMutablePointer(to: &addr) { pointer in
        Darwin.accept(fd, pointer, &length)
      }
      if client < 0 {
        return
      }
      var noSigPipe: Int32 = 1
      setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
      queue.async { [weak self] in
        self?.clientSockets.insert(client)
      }
    }
  }

  private func send(_ data: Data) {
    guard !clientSockets.isEmpty else {
      return
    }

    var closed: [Int32] = []
    for client in clientSockets {
      if !Self.sendAll(data, to: client) {
        closed.append(client)
      }
    }

    for client in closed {
      clientSockets.remove(client)
      close(client)
    }
  }

  static func sendAll(_ data: Data, to socket: Int32) -> Bool {
    var offset = 0
    while offset < data.count {
      let sent = data.withUnsafeBytes { rawBuffer -> Int in
        guard let baseAddress = rawBuffer.baseAddress else {
          return -1
        }
        return Darwin.send(socket, baseAddress.advanced(by: offset), data.count - offset, 0)
      }
      if sent <= 0 {
        return false
      }
      offset += sent
    }
    return true
  }
}

final class LocalWebSocketEventServer {
  let port: UInt16

  private let queue = DispatchQueue(label: "CodexBandBridge.LocalWebSocketEventServer")
  private var serverSocket: Int32 = -1
  private var clientSockets: Set<Int32> = []
  private var isRunning = false

  init(port: UInt16 = 49732) {
    self.port = port
    start()
  }

  deinit {
    stop()
  }

  var endpoint: String {
    "ws://127.0.0.1:\(port)"
  }

  func broadcast(_ json: [String: Any]) {
    guard JSONSerialization.isValidJSONObject(json),
          let data = try? JSONSerialization.data(withJSONObject: json) else {
      return
    }
    guard let frame = Self.textFrame(payload: data) else {
      return
    }
    queue.async { [weak self] in
      self?.send(frame)
    }
  }

  private func start() {
    queue.async { [weak self] in
      self?.openSocket()
    }
  }

  private func stop() {
    queue.sync {
      isRunning = false
      for client in clientSockets {
        close(client)
      }
      clientSockets.removeAll()
      if serverSocket >= 0 {
        close(serverSocket)
        serverSocket = -1
      }
    }
  }

  private func openSocket() {
    guard !isRunning else {
      return
    }

    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else {
      return
    }

    var reuse: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

    let bindResult = withUnsafePointer(to: &addr) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
        Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }

    guard bindResult == 0, listen(fd, 8) == 0 else {
      close(fd)
      return
    }

    serverSocket = fd
    isRunning = true
    DispatchQueue.global(qos: .utility).async { [weak self] in
      self?.acceptLoop(fd)
    }
  }

  private func acceptLoop(_ fd: Int32) {
    while true {
      var addr = sockaddr()
      var length = socklen_t(MemoryLayout<sockaddr>.size)
      let client = withUnsafeMutablePointer(to: &addr) { pointer in
        Darwin.accept(fd, pointer, &length)
      }
      if client < 0 {
        return
      }
      var noSigPipe: Int32 = 1
      setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
      DispatchQueue.global(qos: .utility).async { [weak self] in
        self?.performHandshake(client)
      }
    }
  }

  private func performHandshake(_ client: Int32) {
    guard let request = Self.readHTTPRequest(from: client),
          let key = Self.webSocketKey(from: request),
          let response = Self.handshakeResponse(for: key).data(using: .utf8),
          LocalEventServer.sendAll(response, to: client) else {
      close(client)
      return
    }

    queue.async { [weak self] in
      guard let self, self.isRunning else {
        close(client)
        return
      }
      self.clientSockets.insert(client)
    }
  }

  private func send(_ frame: Data) {
    guard !clientSockets.isEmpty else {
      return
    }

    var closed: [Int32] = []
    for client in clientSockets {
      if !LocalEventServer.sendAll(frame, to: client) {
        closed.append(client)
      }
    }

    for client in closed {
      clientSockets.remove(client)
      close(client)
    }
  }

  private static func readHTTPRequest(from socket: Int32) -> String? {
    var buffer = [UInt8](repeating: 0, count: 1024)
    var data = Data()
    while data.count < 8192 {
      let count = Darwin.recv(socket, &buffer, buffer.count, 0)
      if count <= 0 {
        return nil
      }
      data.append(buffer, count: count)
      if data.range(of: Data([0x0d, 0x0a, 0x0d, 0x0a])) != nil {
        break
      }
    }
    return String(data: data, encoding: .utf8)
  }

  private static func webSocketKey(from request: String) -> String? {
    for line in request.components(separatedBy: "\r\n") {
      let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
      guard parts.count == 2 else {
        continue
      }
      if parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "sec-websocket-key" {
        return parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
      }
    }
    return nil
  }

  private static func handshakeResponse(for key: String) -> String {
    let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    let digest = Insecure.SHA1.hash(data: Data((key + magic).utf8))
    let accept = Data(digest).base64EncodedString()
    return [
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Accept: \(accept)",
      "",
      ""
    ].joined(separator: "\r\n")
  }

  private static func textFrame(payload: Data) -> Data? {
    var frame = Data()
    frame.append(0x81)
    if payload.count < 126 {
      frame.append(UInt8(payload.count))
    } else if payload.count <= UInt16.max {
      frame.append(126)
      frame.append(UInt8((payload.count >> 8) & 0xff))
      frame.append(UInt8(payload.count & 0xff))
    } else {
      frame.append(127)
      let length = UInt64(payload.count)
      for shift in stride(from: 56, through: 0, by: -8) {
        frame.append(UInt8((length >> UInt64(shift)) & 0xff))
      }
    }
    frame.append(payload)
    return frame
  }
}

final class LocalHTTPEventServer {
  let port: UInt16
  let historyLimit: Int
  let bindAddress: String
  let displayHost: String
  let allowWildcardCORS: Bool

  private let queue: DispatchQueue
  private var serverSocket: Int32 = -1
  private var events: [[String: Any]] = []
  private var isRunning = false

  init(
    port: UInt16 = 49733,
    historyLimit: Int = 100,
    bindAddress: String = "127.0.0.1",
    displayHost: String? = nil,
    allowWildcardCORS: Bool = true,
    autoStart: Bool = true
  ) {
    self.port = port
    self.historyLimit = historyLimit
    self.bindAddress = bindAddress
    self.displayHost = displayHost ?? bindAddress
    self.allowWildcardCORS = allowWildcardCORS
    self.queue = DispatchQueue(label: "CodexBandBridge.LocalHTTPEventServer.\(port)")
    if autoStart {
      start()
    }
  }

  deinit {
    stop()
  }

  var endpoint: String {
    "http://\(displayHost):\(port)"
  }

  func record(_ json: [String: Any]) {
    guard JSONSerialization.isValidJSONObject(json) else {
      return
    }
    queue.async { [weak self] in
      guard let self else {
        return
      }
      self.events.append(json)
      if self.events.count > self.historyLimit {
        self.events.removeFirst(self.events.count - self.historyLimit)
      }
    }
  }

  private func start() {
    queue.async { [weak self] in
      self?.openSocket()
    }
  }

  private func stop() {
    queue.sync {
      isRunning = false
      if serverSocket >= 0 {
        close(serverSocket)
        serverSocket = -1
      }
    }
  }

  private func openSocket() {
    guard !isRunning else {
      return
    }

    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else {
      return
    }

    var reuse: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr(bindAddress))

    let bindResult = withUnsafePointer(to: &addr) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
        Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }

    guard bindResult == 0, listen(fd, 8) == 0 else {
      close(fd)
      return
    }

    serverSocket = fd
    isRunning = true
    DispatchQueue.global(qos: .utility).async { [weak self] in
      self?.acceptLoop(fd)
    }
  }

  private func acceptLoop(_ fd: Int32) {
    while true {
      var addr = sockaddr()
      var length = socklen_t(MemoryLayout<sockaddr>.size)
      let client = withUnsafeMutablePointer(to: &addr) { pointer in
        Darwin.accept(fd, pointer, &length)
      }
      if client < 0 {
        return
      }
      var noSigPipe: Int32 = 1
      setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
      DispatchQueue.global(qos: .utility).async { [weak self] in
        self?.handleClient(client)
      }
    }
  }

  private func handleClient(_ client: Int32) {
    defer {
      close(client)
    }
    guard let request = Self.readHTTPRequest(from: client) else {
      return
    }
    let currentEvents = queue.sync { events }
    let response = Self.httpResponse(for: request, events: currentEvents, allowWildcardCORS: allowWildcardCORS)
    _ = LocalEventServer.sendAll(response, to: client)
  }

  static func httpResponse(for request: String, events: [[String: Any]], allowWildcardCORS: Bool = true) -> Data {
    if requestMethod(from: request) == "OPTIONS" {
      return httpResponse(status: "204 No Content", contentType: "text/plain; charset=utf-8", body: Data(), allowWildcardCORS: allowWildcardCORS)
    }

    switch requestPath(from: request) {
    case "/health":
      return jsonResponse([
        "ok": true,
        "schema": EventForwarder.payloadSchema,
        "event_count": events.count
      ], allowWildcardCORS: allowWildcardCORS)
    case "/schema":
      return jsonResponse(schemaJSON(), allowWildcardCORS: allowWildcardCORS)
    case "/latest":
      return jsonResponse(latestJSON(events: events), allowWildcardCORS: allowWildcardCORS)
    case "/events":
      return jsonResponse(eventsJSON(events: events), allowWildcardCORS: allowWildcardCORS)
    case "/events.ndjson":
      return httpResponse(
        status: "200 OK",
        contentType: "application/x-ndjson; charset=utf-8",
        body: ndjson(events: events),
        allowWildcardCORS: allowWildcardCORS
      )
    default:
      return jsonResponse([
        "ok": false,
        "error": "not_found",
        "paths": EventForwarder.httpPaths
      ], status: "404 Not Found", allowWildcardCORS: allowWildcardCORS)
    }
  }

  static func schemaJSON() -> [String: Any] {
    [
      "schema": EventForwarder.payloadSchema,
      "event_type": "gesture",
      "paths": EventForwarder.httpPaths,
      "methods": EventForwarder.httpMethods,
      "route": [
        "app_id": EventForwarder.routeAppID,
        "message_type": EventForwarder.routeMessageType,
      ],
      "normalized_actions": EventForwarder.standardActions,
      "live_validation_actions": EventForwarder.liveValidationActions,
      "required_fields": EventForwarder.requiredPayloadFields,
      "optional_fields": EventForwarder.optionalPayloadFields,
    ]
  }

  static func eventsJSON(events: [[String: Any]]) -> [String: Any] {
    [
      "schema": EventForwarder.payloadSchema,
      "event_count": events.count,
      "events": events
    ]
  }

  static func latestJSON(events: [[String: Any]]) -> [String: Any] {
    [
      "schema": EventForwarder.payloadSchema,
      "event_count": events.count,
      "latest": events.last ?? NSNull()
    ]
  }

  static func ndjson(events: [[String: Any]]) -> Data {
    var data = Data()
    for event in events {
      guard JSONSerialization.isValidJSONObject(event),
            var encoded = try? JSONSerialization.data(withJSONObject: event) else {
        continue
      }
      encoded.append(0x0a)
      data.append(encoded)
    }
    return data
  }

  static func preferredLANIPv4Address() -> String? {
    var interfaces: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&interfaces) == 0, let firstInterface = interfaces else {
      return nil
    }
    defer {
      freeifaddrs(interfaces)
    }

    var pointer: UnsafeMutablePointer<ifaddrs>? = firstInterface
    while let current = pointer {
      defer {
        pointer = current.pointee.ifa_next
      }
      guard let address = current.pointee.ifa_addr,
            address.pointee.sa_family == UInt8(AF_INET) else {
        continue
      }
      let flags = Int32(current.pointee.ifa_flags)
      guard (flags & IFF_UP) != 0,
            (flags & IFF_LOOPBACK) == 0 else {
        continue
      }

      var socketAddress = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
      var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
      guard inet_ntop(AF_INET, &socketAddress.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
        continue
      }
      let value = String(cString: buffer)
      if !value.isEmpty, value != "0.0.0.0" {
        return value
      }
    }
    return nil
  }

  private static func requestPath(from request: String) -> String {
    guard let firstLine = request.components(separatedBy: "\r\n").first else {
      return "/"
    }
    let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
    guard parts.count >= 2 else {
      return "/"
    }
    let rawPath = String(parts[1])
    return rawPath.components(separatedBy: "?").first ?? rawPath
  }

  private static func requestMethod(from request: String) -> String {
    guard let firstLine = request.components(separatedBy: "\r\n").first else {
      return "GET"
    }
    let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
    guard let method = parts.first else {
      return "GET"
    }
    return String(method).uppercased()
  }

  private static func readHTTPRequest(from socket: Int32) -> String? {
    var buffer = [UInt8](repeating: 0, count: 1024)
    var data = Data()
    while data.count < 8192 {
      let count = Darwin.recv(socket, &buffer, buffer.count, 0)
      if count <= 0 {
        return nil
      }
      data.append(buffer, count: count)
      if data.range(of: Data([0x0d, 0x0a, 0x0d, 0x0a])) != nil {
        break
      }
    }
    return String(data: data, encoding: .utf8)
  }

  private static func jsonResponse(_ object: [String: Any], status: String = "200 OK", allowWildcardCORS: Bool = true) -> Data {
    let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data([0x7b, 0x7d])
    return httpResponse(status: status, contentType: "application/json; charset=utf-8", body: body, allowWildcardCORS: allowWildcardCORS)
  }

  private static func httpResponse(status: String, contentType: String, body: Data, allowWildcardCORS: Bool = true) -> Data {
    var response = Data()
    var header = [
      "HTTP/1.1 \(status)",
      "Content-Type: \(contentType)",
      "Content-Length: \(body.count)",
      "Cache-Control: no-store",
    ]
    if allowWildcardCORS {
      header.append(contentsOf: [
      "Access-Control-Allow-Origin: *",
      "Access-Control-Allow-Methods: \(EventForwarder.httpMethods.joined(separator: ", "))",
      "Access-Control-Allow-Headers: Content-Type, Accept",
      "Access-Control-Max-Age: 600",
      "Vary: Origin",
      ])
    }
    header.append(contentsOf: [
      "Connection: close",
      "",
      ""
    ])
    let rawHeader = header.joined(separator: "\r\n")
    response.append(Data(rawHeader.utf8))
    response.append(body)
    return response
  }
}
