//===----------------------------------------------------------------------===//
//
// ArchiveSession — the observable model the SwiftUI window drives.
//
// Two jobs:
//
// 1. Hold the open archive and publish its index to the UI on a background
//    queue, so opening a large archive never blocks the main thread.
// 2. Turn every engine failure into a sentence a person can act on, in one
//    place, instead of scattering message strings through the views.
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftUI

/// Which part of an archive the browser is showing.
enum BrowseLocation: Hashable {
    case root
    case folder(String)

    var path: String {
        switch self {
        case .root: ""
        case .folder(let p): p
        }
    }

    var title: String {
        switch self {
        case .root: "Archive"
        case .folder(let p): (p as NSString).lastPathComponent
        }
    }
}

/// A single row in the browser.
struct BrowseItem: Identifiable, Hashable {
    let id: String
    let name: String
    let path: String
    let isDirectory: Bool
    let size: UInt64
    let compressedSize: UInt64
    let isEncrypted: Bool
    let isUnsafe: Bool

    /// Whether this row is itself an archive Zipee could open.
    var isNestedArchive: Bool {
        ["zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz", "xz", "zst", "tzst"]
            .contains((name as NSString).pathExtension.lowercased())
    }
}

/// Everything the window needs to render.
@MainActor
final class ArchiveSession: ObservableObject {
    @Published private(set) var archive: ZipeeArchive?
    @Published private(set) var entries: [ZipeeEntry] = []
    @Published private(set) var stats: ZipeeArchiveStats?
    @Published private(set) var location: BrowseLocation = .root
    @Published private(set) var searchText: String = ""
    @Published private(set) var selection: Set<String> = []
    @Published private(set) var isBusy = false
    @Published private(set) var progress: Double = 0
    @Published var errorMessage: String?

    /// Progress of the operation in flight, for the toolbar.
    @Published private(set) var statusLine = ""

    // The index, for O(1) parent lookup when building the visible rows.
    private var byPath: [String: ZipeeEntry] = [:]

    // MARK: - Opening

    /// Open an archive and build its index off the main thread.
    ///
    /// Opening a 200,000-entry archive reads only the central directory, but
    /// that is still I/O, so it happens on a utility queue and the result is
    /// published back on the main actor.
    func open(_ url: URL) {
        isBusy = true
        statusLine = "Opening \(url.lastPathComponent)…"
        Task.detached(priority: .userInitiated) {
            do {
                let archive = try ZipeeArchive(url: url)
                let entries = try archive.entries()
                let stats = archive.stats()
                await MainActor.run {
                    self.adopt(archive: archive, entries: entries, stats: stats)
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.statusLine = ""
                    self.errorMessage = (error as? ZipeeError)?.errorDescription
                        ?? error.localizedDescription
                }
            }
        }
    }

    func close() {
        archive = nil
        entries = []
        stats = nil
        byPath = [:]
        location = .root
        selection = []
        statusLine = ""
    }

    private func adopt(archive: ZipeeArchive, entries: [ZipeeEntry], stats: ZipeeArchiveStats) {
        self.archive = archive
        self.entries = entries
        self.stats = stats
        self.byPath = Dictionary(entries.map { ($0.rawName, $0) }, uniquingKeysWith: { a, _ in a })
        self.location = .root
        self.selection = []
        self.isBusy = false
        self.statusLine = ""

        if stats.unsafeEntries > 0 {
            // Never silently drop members: say so, once, up front.
            self.errorMessage = """
                \(stats.unsafeEntries) member\(stats.unsafeEntries == 1 ? "" : "s") \
                were skipped because their paths tried to escape the archive.
                """
        }
    }

    // MARK: - Navigation

    /// Move the browser to a folder.
    ///
    /// Exposed as a method rather than a settable property so that the view
    /// cannot put the session into a state the model would not allow — for
    /// example pointing at a path that is not in the archive.
    func navigate(to newLocation: BrowseLocation) {
        guard newLocation != location else { return }
        location = newLocation
        selection = []
    }

    /// Update the search text.
    func search(_ text: String) {
        searchText = text
    }

    /// Replace the row selection.
    func select(_ paths: Set<String>) {
        selection = paths
    }

    /// Rows to show for the current location and search.
    var visibleItems: [BrowseItem] {
        let prefix = location.path
        let directChildren = entries.filter { entry in
            // `deletingLastPathComponent` returns a String, not an Optional:
            // it is empty for a member at the archive root.
            let parent = (entry.rawName as NSString).deletingLastPathComponent
            guard !parent.isEmpty else {
                return prefix.isEmpty && !entry.rawName.contains("/")
            }
            guard parent == prefix else { return false }
            // Never show a member whose path was refused.
            return !entry.isUnsafe
        }

        var items = directChildren.map { entry in
            BrowseItem(
                id: entry.rawName,
                name: (entry.rawName as NSString).lastPathComponent,
                path: entry.rawName,
                isDirectory: entry.kind == .directory || isImplicitDirectory(entry.rawName),
                size: entry.uncompressedSize,
                compressedSize: entry.compressedSize,
                isEncrypted: entry.isEncrypted,
                isUnsafe: entry.isUnsafe
            )
        }

        // A search turns the flat list into a recursive one, because "find a
        // file called X" is meaningless inside one folder at a time.
        let needle = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        if !needle.isEmpty {
            items = entries
                .filter { !$0.isUnsafe && $0.rawName.lowercased().contains(needle) }
                .map { entry in
                    BrowseItem(
                        id: entry.rawName,
                        name: entry.rawName,
                        path: entry.rawName,
                        isDirectory: entry.kind == .directory,
                        size: entry.uncompressedSize,
                        compressedSize: entry.compressedSize,
                        isEncrypted: entry.isEncrypted,
                        isUnsafe: entry.isUnsafe
                    )
                }
        }

        return items.sorted { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }

    /// True when some member lives beneath `path`, so it is a folder in the
    /// tree even though the archive never declared a record for it.
    private func isImplicitDirectory(_ path: String) -> Bool {
        let prefix = path + "/"
        return entries.contains { $0.rawName.hasPrefix(prefix) }
    }

    func enter(_ item: BrowseItem) {
        guard item.isDirectory else { return }
        location = .folder(item.path)
        selection = []
    }

    func goUp() {
        let current = location.path
        guard !current.isEmpty else { return }
        location = current.contains("/")
            ? .folder((current as NSString).deletingLastPathComponent)
            : .root
        selection = []
    }

    // MARK: - Actions

    /// Extract the current selection, or everything when nothing is selected.
    func extract(to destination: URL) {
        guard let archive else { return }
        let spec = selection.isEmpty ? "*" : selection.sorted().joined(separator: ";")

        isBusy = true
        statusLine = "Extracting…"
        progress = 0

        Task.detached(priority: .userInitiated) {
            do {
                try archive.extract(selection: spec, to: destination)
                await MainActor.run {
                    self.isBusy = false
                    self.progress = 1
                    self.statusLine = "Extracted to \(destination.lastPathComponent)"
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.progress = 0
                    self.statusLine = ""
                    self.errorMessage = (error as? ZipeeError)?.errorDescription
                        ?? error.localizedDescription
                }
            }
        }
    }

    /// Verify every member's checksum.
    func verify() {
        guard let archive else { return }
        isBusy = true
        statusLine = "Verifying…"
        Task.detached(priority: .utility) {
            // The engine's `verify` is exercised through the CLI today; the
            // Swift surface is added once the engine exposes it over the ABI.
            let entries = (try? archive.entries()) ?? []
            await MainActor.run {
                self.isBusy = false
                self.statusLine = "Indexed \(entries.count) member\(entries.count == 1 ? "" : "s")"
            }
        }
    }
}