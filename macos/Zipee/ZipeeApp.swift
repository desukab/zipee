//===----------------------------------------------------------------------===//
//
// ZipeeApp — the application object.
//
// Zipee is a document-less agent: it has no Dock icon and no main window of its
// own by default, because its main entry point is Finder (open-with, Services,
// drag-and-drop). A window is shown when the user asks for one.
//
//===----------------------------------------------------------------------===//

import SwiftUI
import AppKit

@main
struct ZipeeApp: App {
    @StateObject private var session = ArchiveSession()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var isShowingAbout = false

    var body: some Scene {
        Window("Zipee", id: "main") {
            BrowserView()
                .environmentObject(session)
                .onOpenURL { url in
                    session.open(url)
                }
                // Opening an archive is the app's primary job, so handle drops
                // of any number of archives by taking the first and reporting
                // the rest rather than silently ignoring them.
                .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                    handleDrop(providers)
                }
                // The sheet hangs off the content view, not off the Window.
                // `sheet` is a View modifier; `WindowGroup` is a Scene, and
                // Scenes have no `sheet` member.
                .sheet(isPresented: $isShowingAbout) {
                    AboutView()
                }
        }
        .defaultSize(width: 1000, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Archive…") { presentOpenPanel() }
                    .keyboardShortcut("o", modifiers: .command)
            }
            CommandGroup(after: .newItem) {
                Divider()
                Button("Close Archive") { session.close() }
                    .keyboardShortcut("w", modifiers: .command)
                    .disabled(session.archive == nil)
            }
            // The donation entry point. One action, in the Help menu, where
            // someone who already values the app will look for it. Never a
            // launch prompt, never a nag, never tied to any feature.
            CommandGroup(replacing: .appInfo) {
                Button("About Zipee") { isShowingAbout = true }
            }
            CommandGroup(after: .appInfo) {
                Button("Support Development…") { isShowingAbout = true }
                    .help("Zipee is free and open-source. Donating is optional.")
            }
        }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url else { return }
            Task { @MainActor in
                session.open(url)
            }
        }
        return true
    }

    private func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose an archive to browse"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in session.open(url) }
        }
    }
}

/// Application-level behaviour that has no view: Finder integration and the
/// Services entry point.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Finder's Services menu calls this. `NSServices` in Info.plist routes
    /// the "Extract with Zipee" item here.
    @objc func extractArchives(
        _ sender: Any?,
        _ archive: NSURL,
        _ appName: NSString
    ) -> Bool {
        Task { @MainActor in
            // The session is owned by the scene; reach it through the app.
            guard let url = archive as URL? else { return }
            NotificationCenter.default.post(
                name: .zipeeExtractRequested,
                object: url
            )
        }
        return true
    }
}

extension Notification.Name {
    /// Posted when Finder asks Zipee to extract an archive.
    static let zipeeExtractRequested = Notification.Name("com.zipee.extractRequested")
}
