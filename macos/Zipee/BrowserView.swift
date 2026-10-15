//===----------------------------------------------------------------------===//
//
// BrowserView — the one window Zipee puts on screen.
//
// Deliberately a plain, keyboard-first browser over the engine's index:
// a sidebar, a table, and nothing that pretends to be a mounted filesystem.
// See docs/architecture.md for why browsing is the default and mounting is
// behind a capability check.
//
//===----------------------------------------------------------------------===//

import SwiftUI
import AppKit

/// A sidebar row.
private struct SidebarRow: Identifiable {
    let id: String
    let name: String
    let depth: Int
    let isArchiveRoot: Bool
}

struct BrowserView: View {
    @EnvironmentObject private var session: ArchiveSession

    @State private var isChoosingDestination = false

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 220, ideal: 280, max: 420)
        } detail: {
            content
        }
        .toolbar { toolbar }
        .searchable(text: searchBinding, placement: .toolbar, prompt: "Search members")
        .fileImporter(
            isPresented: $isChoosingDestination,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { session.extract(to: url) }
            case .failure(let error):
                session.errorMessage = error.localizedDescription
            }
        }
        .alert(
            "Zipee",
            isPresented: Binding(
                get: { session.errorMessage != nil },
                set: { if !$0 { session.errorMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) { session.errorMessage = nil }
        } message: {
            Text(session.errorMessage ?? "")
        }
        .navigationTitle(session.archive?.url.lastPathComponent ?? "Zipee")
    }

    // MARK: - Sidebar

    private var sidebarRows: [SidebarRow] {
        var rows = [SidebarRow(id: "", name: "Archive", depth: 0, isArchiveRoot: true)]

        // Every path component that exists as a prefix of some member is a
        // folder in the tree, whether or not the archive declared a record for
        // it. Most archives declare none, so deriving them here is what makes
        // the sidebar match what `zipee list --tree` prints.
        var seen = Set<String>()
        for entry in session.entries where !entry.isUnsafe {
            let parts = entry.rawName.split(separator: "/", omittingEmptySubsequences: true)
            guard parts.count > 1 else { continue }
            for depth in 1..<parts.count {
                let path = parts[0..<depth].joined(separator: "/")
                if seen.insert(path).inserted {
                    rows.append(
                        SidebarRow(
                            id: path,
                            name: String(parts[depth - 1]),
                            depth: depth,
                            isArchiveRoot: false
                        )
                    )
                }
            }
        }
        return rows.sorted { $0.id < $1.id }
    }

    private var sidebar: some View {
        List(selection: Binding(
            get: { session.location.path },
            set: { newValue in
                session.location = newValue.isEmpty ? .root : .folder(newValue)
            }
        )) {
            ForEach(sidebarRows) { row in
                Label(row.name, systemImage: row.isArchiveRoot ? "shippingbox" : "folder")
                    .padding(.leading, CGFloat(row.depth) * 14)
                    .tag(row.id)
            }
        }
        .listStyle(.sidebar)
        .accessibilityLabel("Archive contents")
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if session.archive == nil {
            welcome
        } else if session.visibleItems.isEmpty {
            ContentUnavailableView {
                Label(
                    session.searchText.isEmpty ? "Nothing inside" : "No matches",
                    systemImage: "questionmark.folder"
                )
            } description: {
                Text(
                    session.searchText.isEmpty
                        ? "\(session.archive?.url.lastPathComponent ?? "This archive") has no members."
                        : "Nothing in this archive matches “\(session.searchText)”."
                )
            }
        } else {
            table
        }
    }

    private var table: some View {
        Table(session.visibleItems, selection: $session.selection) {
            TableColumn("Name") { item in
                HStack(spacing: 6) {
                    Image(systemName: item.isDirectory ? "folder" : "doc")
                        .foregroundStyle(item.isDirectory ? Color.accentColor : Color.secondary)
                    Text(item.name)
                        // Nested archives are dimmed rather than hidden: the
                        // point of Zipee is that you can see inside them.
                        .foregroundStyle(item.isNestedArchive ? Color.secondary : Color.primary)
                    if item.isEncrypted {
                        Image(systemName: "lock.fill")
                            .foregroundStyle(.secondary)
                            .help("This member is encrypted")
                    }
                }
            }
            TableColumn("Size") { item in
                Text(sizeText(item))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(min: 70, ideal: 90, alignment: .trailing)
        }
        .contextMenu(forSelectionType: String.self) { names in
            Button(extractTitle(for: names.count)) {
                isChoosingDestination = true
            }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(
                    names.joined(separator: "\n"),
                    forType: .string
                )
            }
        }
    }

    private func sizeText(_ item: BrowseItem) -> String {
        guard !item.isDirectory else { return "—" }
        return ByteCountFormatter.string(
            fromByteCount: Int64(item.size),
            countStyle: .file
        )
    }

    private func extractTitle(for count: Int) -> String {
        switch count {
        case 0: "Extract All…"
        case 1: "Extract Item…"
        default: "Extract \(count) Items…"
        }
    }

    private var welcome: some View {
        ContentUnavailableView {
            Label("Zipee", systemImage: "shippingbox")
        } description: {
            Text("Open an archive to browse it without unpacking.")
        } actions: {
            Button("Choose Folder to Extract Into…") { isChoosingDestination = true }
                .disabled(session.archive == nil)
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button { session.goUp() } label: {
                Image(systemName: "chevron.left")
            }
            .disabled(session.location.path.isEmpty)
            .help("Back")
            .keyboardShortcut("[", modifiers: .command)
        }

        ToolbarItem {
            Button { isChoosingDestination = true } label: {
                Label("Extract", systemImage: "square.and.arrow.up")
            }
            .disabled(session.archive == nil || session.isBusy)
            .help("Extract the selected items, or everything if nothing is selected")
        }

        ToolbarItem {
            Button { session.verify() } label: {
                Label("Check", systemImage: "checkmark.shield")
            }
            .disabled(session.archive == nil || session.isBusy)
            .help("Check every member's checksum")
        }

        ToolbarItem {
            if session.isBusy {
                ProgressView(value: session.progress)
                    .progressViewStyle(.linear)
                    .frame(width: 120)
                    .accessibilityLabel("Working")
            } else if !session.statusLine.isEmpty {
                Text(session.statusLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var searchBinding: Binding<String> {
        Binding(
            get: { session.searchText },
            set: { session.searchText = $0 }
        )
    }
}