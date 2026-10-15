//===----------------------------------------------------------------------===//
//
// AboutView — Zipee's About window, and the only place the donation address
// appears in the app.
//
// The entry point is a single `Support Development` button in the toolbar's
// overflow menu, not a nag, a banner or a prompt on launch.
//
//===----------------------------------------------------------------------===//

import SwiftUI
import AppKit

struct AboutView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false
    @State private var qrImage: Image?
    @State private var addressIsValid = true

    var body: some View {
        VStack(spacing: 18) {
            header

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Label("Free and open-source", systemImage: "lock.open")
                    .font(.headline)
                Text(Donation.disclaimer)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(spacing: 10) {
                if let qrImage {
                    qrImage
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 190, height: 190)
                        .accessibilityLabel("QR code containing the Solana donation address")
                } else {
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [4]))
                        .frame(width: 190, height: 190)
                        .foregroundStyle(.secondary)
                        .overlay(Text("QR unavailable").font(.caption).foregroundStyle(.secondary))
                }

                Text("Solana address")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                // The address is shown verbatim in a selectable monospaced
                // block. Never truncated, never abbreviated, never a label.
                Text(Donation.solanaAddress)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: 380)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(Color(nsColor: .textBackgroundColor)))
                    .accessibilityLabel("Solana donation address")

                Button {
                    if DonationClipboard.copy(Donation.solanaAddress) {
                        copied = true
                    }
                } label: {
                    Label(copied ? "Copied" : "Copy Address",
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .disabled(!addressIsValid)
            }

            if !addressIsValid {
                // Deliberately loud. If the address ever fails validation the
                // app must not present it as payable.
                Label(
                    "The donation address failed validation and is not shown as payable.",
                    systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(width: 460)
        .task {
            // Validate before rendering. A failure means no payable QR.
            // `validate` returns a Result, it does not throw, so there is
            // nothing to catch here.
            if case .success = SolanaAddress.validate(Donation.solanaAddress) {
                addressIsValid = true
            } else {
                addressIsValid = false
            }
            guard addressIsValid,
                  let png = DonationQRCode.donationPNG(),
                  let nsImage = NSImage(data: png) else { return }
            qrImage = Image(nsImage: nsImage)
        }
    }

    private var header: some View {
        HStack(spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 64, height: 64)
            VStack(alignment: .leading, spacing: 2) {
                Text("Zipee")
                    .font(.title2.bold())
                Text("Version \(Bundle.main.appVersion)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Text("Archive utility · Apache-2.0")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

extension Bundle {
    /// Version from the bundle, with a safe fallback.
    var appVersion: String {
        let short = object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let build = object(forInfoDictionaryKey: "CFBundleVersion") as? String
        switch (short, build) {
        case let (s?, b?): return "\(s) (\(b))"
        case let (s?, nil): return s
        case let (nil, b?): return b
        default: return "unknown"
        }
    }
}