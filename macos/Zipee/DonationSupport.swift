//===----------------------------------------------------------------------===//
//
// DonationSupport — the optional, voluntary donation affordance.
//
// Design constraints, all deliberate:
//
// * **Display and copy only.** Zipee never connects to a wallet, never signs,
//   never requests a payment and never sends anything anywhere. The only
//   network entitlement the app holds is `network.client`, for update checks.
//
// * **Never a paywall.** No feature, tier or frequency is gated on this. Every
//   capability is available to every user regardless of what they do here.
//
// * **The address is a constant, never constructed.** It is written out in full
//   and checked at runtime by `SolanaAddress.validate`. A truncated or
//   mistyped address fails the build's test suite rather than quietly sending
//   money somewhere else.
//
// * **No seed phrase, ever.** This code neither requests, stores nor transmits
//   one, and there is no code path that could.
//
// * **No amount, no URI scheme.** A bare address decodes in every wallet
//   without the user having to trust a scheme, and cannot imply a payment is
//   expected. A Solana Pay URI is offered separately, still amount-free.
//
//===----------------------------------------------------------------------===//

import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

/// The public donation address.
///
/// This is the address supplied for Zipee. It is written out in full because a
/// donation address must never be assembled, truncated or transformed: a
/// one-character difference sends money somewhere unrecoverable.
public enum Donation {
    public static let solanaAddress = "2EJyURV4HhJNFas4V3cJtB1BqvMnDaPhqcxu5yiSkAxG"

    /// A Solana Pay URI with **no amount** and **no memo**.
    ///
    /// Offered as a secondary convenience because some wallets prefer it. It
    /// carries nothing that could be read as a required payment.
    public static var solanaPayURI: String { "solana:\(solanaAddress)" }

    /// The message shown wherever the address appears.
    public static let disclaimer = """
        Zipee is free and open-source. Donating is entirely optional, and \
        every feature stays available if you never donate. Donations support \
        maintenance, testing and future development.
        """
}

/// The base58 alphabet Solana uses for addresses.
enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    /// True when every character is in the base58 alphabet.
    ///
    /// Deliberately a *charset* check and nothing more.
    ///
    /// A full base58 decoder was written here and then removed: three
    /// hand-rolled attempts disagreed with a known-good reference, and the
    /// Swift layer cannot be unit-tested on the build host. Shipping a
    /// plausible-looking decoder that has never run would be worse than not
    /// having one — a wrong decoder does not fail loudly, it validates the
    /// wrong things.
    ///
    /// So validation here is charset plus length, which are obvious and
    /// verifiable by inspection. The authoritative check that the address
    /// decodes to exactly the expected 32 bytes is in the test suite and in
    /// CI, where a real base58 implementation is available to compare against.
    static func isValidCharset(_ text: String) -> Bool {
        !text.isEmpty && text.allSatisfy { alphabet.contains($0) }
    }
}

/// Validation for the donation address.
public enum SolanaAddress {
    /// A valid Solana public key is 32 bytes.
    public static let expectedByteCount = 32

    /// The character-count range that a 32-byte public key can occupy in
    /// base58. A 32-byte value needs 43 or 44 characters: 43 when the leading
    /// bytes are small, 44 otherwise. Solana addresses are always in this range.
    public static let validCharacterCounts = 43...44

    /// Validate that `address` could be a 32-byte Solana public key.
    ///
    /// Checks the base58 charset and the character count. It deliberately does
    /// **not** attempt an on-curve check: an address that is merely well-formed
    /// is still the address we must display, and refusing to show it would be
    /// worse than showing a key its owner can decide what to do with.
    public static func validate(_ address: String) -> Result<Void, AddressError> {
        guard !address.isEmpty else { return .failure(.empty) }
        guard Base58.isValidCharset(address) else { return .failure(.notBase58) }
        guard validCharacterCounts.contains(address.count) else {
            return .failure(.wrongLength(address.count))
        }
        return .success(())
    }

    public enum AddressError: Error, CustomStringConvertible {
        case empty
        case notBase58
        case wrongLength(Int)

        public var description: String {
            switch self {
            case .empty: "the address is empty"
            case .notBase58: "the address contains a character outside base58"
            case .wrongLength(let n):
                "the address is \(n) characters, expected \(validCharacterCounts.lowerBound)-\(validCharacterCounts.upperBound)"
            }
        }
    }
}

/// Renders the donation address as a QR code, locally.
///
/// `CIQRCodeGenerator` is a system filter: no network call, no third-party
/// code, nothing that could observe the address.
public enum DonationQRCode {
    /// Generate a PNG of the QR code for `payload`, or `nil` if it cannot.
    public static func png(for payload: String, scale: CGFloat = 10) -> Data? {
        let context = CIContext()
        let filter = CIFilter(name: "CIQRCodeGenerator")
        filter?.setValue(Data(payload.utf8), forKey: "inputMessage")
        filter?.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter?.outputImage else { return nil }

        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }

        let rep = NSBitmapImageRep(cgImage: cgImage)
        // CGImage exposes width and height, not size. Build the CGSize.
        rep.size = CGSize(width: cgImage.width, height: cgImage.height)
        return rep.representation(using: .png, properties: [:])
    }

    /// Generate the QR for the donation address specifically.
    public static func donationPNG() -> Data? {
        png(for: Donation.solanaAddress)
    }
}

/// Copy-to-pasteboard with user-visible confirmation.
public enum DonationClipboard {
    /// Copy text and return whether it worked.
    @discardableResult
    public static func copy(_ text: String) -> Bool {
        let pb = NSPasteboard.general
        pb.clearContents()
        return pb.setString(text, forType: .string)
    }
}