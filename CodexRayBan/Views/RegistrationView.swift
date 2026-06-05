/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

//
// RegistrationView.swift
//
// Handles deep link callbacks from the Meta AI app during DAT SDK registration
// and permission flows.
//

import MWDATCore
import SwiftUI

struct RegistrationView: View {
  var viewModel: WearablesViewModel

  var body: some View {
    EmptyView()
      .onOpenURL { url in
        guard
          let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          components.queryItems?.contains(where: { $0.name == "metaWearablesAction" }) == true
        else {
          return
        }
        Task {
          do {
            _ = try await Wearables.shared.handleUrl(url)
          } catch let error as RegistrationError {
            viewModel.showError(error.description)
          } catch {
            viewModel.showError("Unknown error: \(error.localizedDescription)")
          }
        }
      }
  }
}
