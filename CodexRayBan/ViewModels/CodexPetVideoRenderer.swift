import AVFoundation
import CoreGraphics
import UIKit

enum CodexPetVideoRendererError: LocalizedError {
  case missingSpritesheet(String)
  case missingCGImage(String)
  case invalidFrame
  case writerSetupFailed
  case pixelBufferFailed
  case appendFailed

  var errorDescription: String? {
    switch self {
    case .missingSpritesheet(let name):
      return "Missing pet spritesheet \(name)."
    case .missingCGImage(let name):
      return "Could not load pet spritesheet image \(name)."
    case .invalidFrame:
      return "Pet animation contains an invalid frame."
    case .writerSetupFailed:
      return "Could not prepare pet animation video."
    case .pixelBufferFailed:
      return "Could not render pet animation frame."
    case .appendFailed:
      return "Could not write pet animation frame."
    }
  }
}

enum CodexPetVideoRenderer {
  private static let columns = 8
  private static let rows = 9
  private static let outputSize = CGSize(width: 512, height: 512)

  static func renderVideo(for pet: CodexPet, state: CodexPetVisualState) throws -> URL {
    guard let image = UIImage(named: pet.imageName) else {
      throw CodexPetVideoRendererError.missingSpritesheet(pet.imageName)
    }
    guard let spritesheet = image.cgImage else {
      throw CodexPetVideoRendererError.missingCGImage(pet.imageName)
    }

    let outputURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-pet-\(pet.id)-\(state.rawValue)-\(UUID().uuidString)")
      .appendingPathExtension("mp4")
    try? FileManager.default.removeItem(at: outputURL)

    let writer = try AVAssetWriter(outputURL: outputURL, fileType: .mp4)
    let settings: [String: Any] = [
      AVVideoCodecKey: AVVideoCodecType.h264,
      AVVideoWidthKey: Int(outputSize.width),
      AVVideoHeightKey: Int(outputSize.height),
      AVVideoCompressionPropertiesKey: [
        AVVideoAverageBitRateKey: 700_000,
        AVVideoProfileLevelKey: AVVideoProfileLevelH264BaselineAutoLevel,
      ],
    ]
    let input = AVAssetWriterInput(mediaType: .video, outputSettings: settings)
    input.expectsMediaDataInRealTime = false

    let attributes: [String: Any] = [
      kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_32ARGB),
      kCVPixelBufferWidthKey as String: Int(outputSize.width),
      kCVPixelBufferHeightKey as String: Int(outputSize.height),
      kCVPixelBufferCGImageCompatibilityKey as String: true,
      kCVPixelBufferCGBitmapContextCompatibilityKey as String: true,
    ]
    let adaptor = AVAssetWriterInputPixelBufferAdaptor(
      assetWriterInput: input,
      sourcePixelBufferAttributes: attributes
    )

    guard writer.canAdd(input) else {
      throw CodexPetVideoRendererError.writerSetupFailed
    }
    writer.add(input)
    guard writer.startWriting() else {
      throw writer.error ?? CodexPetVideoRendererError.writerSetupFailed
    }
    writer.startSession(atSourceTime: .zero)

    var presentationTime = 0.0
    for frame in timeline(for: CodexPetAnimation.animation(for: state)) {
      while !input.isReadyForMoreMediaData {
        Thread.sleep(forTimeInterval: 0.01)
      }
      let pixelBuffer = try pixelBuffer(for: frame, in: spritesheet)
      let time = CMTime(seconds: presentationTime, preferredTimescale: 600)
      guard adaptor.append(pixelBuffer, withPresentationTime: time) else {
        throw writer.error ?? CodexPetVideoRendererError.appendFailed
      }
      presentationTime += frame.duration
    }

    input.markAsFinished()
    let semaphore = DispatchSemaphore(value: 0)
    writer.finishWriting {
      semaphore.signal()
    }
    semaphore.wait()

    if writer.status == .failed {
      throw writer.error ?? CodexPetVideoRendererError.writerSetupFailed
    }
    return outputURL
  }

  private static func timeline(for animation: CodexPetAnimation) -> [CodexPetFrame] {
    let frames = animation.frames
    guard !frames.isEmpty else {
      return [CodexPetFrame(row: 0, column: 0, duration: 1.0)]
    }

    var timeline: [CodexPetFrame] = []
    var elapsed = 0.0
    var index = 0
    let minimumDuration = 3.2
    let maximumFrames = 64

    while elapsed < minimumDuration && timeline.count < maximumFrames {
      let frame = frames[min(index, frames.count - 1)]
      timeline.append(frame)
      elapsed += max(frame.duration, 0.08)

      let next = index + 1
      if next >= frames.count, let loopStartIndex = animation.loopStartIndex, loopStartIndex < frames.count {
        index = loopStartIndex
      } else if next >= frames.count {
        index = 0
      } else {
        index = next
      }
    }

    return timeline
  }

  private static func pixelBuffer(for frame: CodexPetFrame, in spritesheet: CGImage) throws -> CVPixelBuffer {
    let frameWidth = spritesheet.width / columns
    let frameHeight = spritesheet.height / rows
    let cropRect = CGRect(
      x: CGFloat(frame.column * frameWidth),
      y: CGFloat(frame.row * frameHeight),
      width: CGFloat(frameWidth),
      height: CGFloat(frameHeight)
    )
    guard let cropped = spritesheet.cropping(to: cropRect) else {
      throw CodexPetVideoRendererError.invalidFrame
    }

    var pixelBuffer: CVPixelBuffer?
    let status = CVPixelBufferCreate(
      kCFAllocatorDefault,
      Int(outputSize.width),
      Int(outputSize.height),
      kCVPixelFormatType_32ARGB,
      nil,
      &pixelBuffer
    )
    guard status == kCVReturnSuccess, let pixelBuffer else {
      throw CodexPetVideoRendererError.pixelBufferFailed
    }

    CVPixelBufferLockBaseAddress(pixelBuffer, [])
    defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }

    guard
      let baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer),
      let context = CGContext(
        data: baseAddress,
        width: Int(outputSize.width),
        height: Int(outputSize.height),
        bitsPerComponent: 8,
        bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer),
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue
      )
    else {
      throw CodexPetVideoRendererError.pixelBufferFailed
    }

    context.setFillColor(UIColor.black.cgColor)
    context.fill(CGRect(origin: .zero, size: outputSize))
    context.interpolationQuality = .none

    let spriteAspect = CGFloat(cropped.width) / CGFloat(cropped.height)
    let drawHeight = outputSize.height * 0.74
    let drawWidth = drawHeight * spriteAspect
    let drawRect = CGRect(
      x: (outputSize.width - drawWidth) / 2,
      y: (outputSize.height - drawHeight) / 2,
      width: drawWidth,
      height: drawHeight
    )
    context.draw(cropped, in: drawRect)

    return pixelBuffer
  }
}

enum CodexPetFrameImageRendererError: LocalizedError {
  case missingSpritesheet(String)
  case missingCGImage(String)
  case invalidFrame
  case pngEncodingFailed

  var errorDescription: String? {
    switch self {
    case .missingSpritesheet(let name):
      return "Missing pet spritesheet \(name)."
    case .missingCGImage(let name):
      return "Could not load pet spritesheet image \(name)."
    case .invalidFrame:
      return "Pet animation contains an invalid frame."
    case .pngEncodingFailed:
      return "Could not encode pet animation frame."
    }
  }
}

enum CodexPetFrameImageRenderer {
  private static let columns = 8
  private static let rows = 9
  private static let outputSize = CGSize(width: 80, height: 87)

  static func dataURI(for pet: CodexPet, state: CodexPetVisualState, frameIndex: Int) throws -> String {
    let animation = CodexPetAnimation.animation(for: state)
    let frame = animation.frames.isEmpty
      ? CodexPetFrame(row: 0, column: 0, duration: 1)
      : animation.frames[frameIndex % animation.frames.count]
    return try dataURI(for: pet, frame: frame)
  }

  static func dataURI(for pet: CodexPet, frame: CodexPetFrame) throws -> String {
    let image = try image(for: pet, frame: frame)
    guard let data = image.pngData() else {
      throw CodexPetFrameImageRendererError.pngEncodingFailed
    }
    return "data:image/png;base64,\(data.base64EncodedString())"
  }

  static func image(for pet: CodexPet, frame: CodexPetFrame) throws -> UIImage {
    guard let image = UIImage(named: pet.imageName) else {
      throw CodexPetFrameImageRendererError.missingSpritesheet(pet.imageName)
    }
    guard let spritesheet = image.cgImage else {
      throw CodexPetFrameImageRendererError.missingCGImage(pet.imageName)
    }

    let frameWidth = spritesheet.width / columns
    let frameHeight = spritesheet.height / rows
    let cropRect = CGRect(
      x: CGFloat(frame.column * frameWidth),
      y: CGFloat(frame.row * frameHeight),
      width: CGFloat(frameWidth),
      height: CGFloat(frameHeight)
    )
    guard let cropped = spritesheet.cropping(to: cropRect) else {
      throw CodexPetFrameImageRendererError.invalidFrame
    }

    let format = UIGraphicsImageRendererFormat()
    format.opaque = false
    format.scale = 1

    return UIGraphicsImageRenderer(size: outputSize, format: format).image { context in
      context.cgContext.interpolationQuality = .none
      let sprite = UIImage(cgImage: cropped)
      let spriteAspect = CGFloat(cropped.width) / CGFloat(cropped.height)
      let drawHeight = outputSize.height * 0.96
      let drawWidth = drawHeight * spriteAspect
      let drawRect = CGRect(
        x: (outputSize.width - drawWidth) / 2,
        y: outputSize.height - drawHeight,
        width: drawWidth,
        height: drawHeight
      )
      sprite.draw(in: drawRect)
    }
  }
}
