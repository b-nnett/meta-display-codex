import MWDATDisplay

enum CodexDisplay {
  static func helloWorld(onDismiss: @escaping @Sendable () -> Void) -> FlexBox {
    FlexBox(direction: .column, spacing: 12) {
      FlexBox(direction: .column, spacing: 8) {
        Text("Codex", style: .meta, color: .secondary)
        Text("Hello, Ray-Ban Display", style: .heading)
        Text("DAT is connected and rendering from the iPhone app.", style: .body, color: .secondary)
      }
      .padding(24)
      .background(.card)

      FlexBox(direction: .row, spacing: 8, alignment: .center, crossAlignment: .center) {
        Button(label: "Done", style: .primary, iconName: .checkmark, onClick: onDismiss)
      }
    }
  }

  static func statusCard(
    title: String,
    detail: String,
    actionTitle: String,
    onAction: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 12) {
      FlexBox(direction: .column, spacing: 8) {
        Text("Codex", style: .meta, color: .secondary)
        Text(title, style: .heading)
        Text(detail, style: .body, color: .secondary)
      }
      .padding(24)
      .background(.card)

      FlexBox(direction: .row, spacing: 8, alignment: .center, crossAlignment: .center) {
        Button(label: actionTitle, style: .primary, iconName: .checkmark, onClick: onAction)
      }
    }
  }

  static func authRequired(onOpenApp: @escaping @Sendable () -> Void) -> FlexBox {
    statusCard(
      title: "Authentication needed",
      detail: "Open the iPhone app to complete Codex sign-in, then return to the glasses.",
      actionTitle: "Open app",
      onAction: onOpenApp
    )
  }

  static func ready(onDismiss: @escaping @Sendable () -> Void) -> FlexBox {
    statusCard(
      title: "Ready for Codex",
      detail: "The display channel is connected. Codex remote control can be added next.",
      actionTitle: "Done",
      onAction: onDismiss
    )
  }

  static func codexStatus(
    title: String,
    detail: String,
    onDismiss: @escaping @Sendable () -> Void
  ) -> FlexBox {
    statusCard(
      title: title,
      detail: detail,
      actionTitle: "Done",
      onAction: onDismiss
    )
  }

  static func petBubble(
    imageURI: String,
    message: String,
    onDismiss: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 10, alignment: .center, crossAlignment: .center) {
      Image(uri: imageURI, sizePreset: .icon, cornerRadius: .none)

      if !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        FlexBox(direction: .column, spacing: 0) {
          Text(message, style: .body)
        }
        .padding(14)
        .background(.card)
      }
    }
    .onTap(onDismiss)
  }

  static func petStatus(
    petName: String,
    state: String,
    message: String,
    onDismiss: @escaping @Sendable () -> Void
  ) -> FlexBox {
    FlexBox(direction: .column, spacing: 12, alignment: .center, crossAlignment: .center) {
      FlexBox(direction: .column, spacing: 8, alignment: .center, crossAlignment: .center) {
        Icon(name: .smileyCircle)
        Text(state, style: .meta, color: .secondary)
      }

      if !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        FlexBox(direction: .column, spacing: 0) {
          Text(message, style: .body)
        }
        .padding(14)
        .background(.card)
      } else {
        Text(petName, style: .body)
      }
    }
    .onTap(onDismiss)
  }

  static func confirmation(message: String) -> FlexBox {
    FlexBox(direction: .column, spacing: 10) {
      FlexBox(direction: .column, spacing: 8) {
        Text("Codex", style: .meta, color: .secondary)
        Text("Confirmed", style: .heading)
        Text(message, style: .body)
      }
      .padding(24)
      .background(.card)
    }
  }
}
