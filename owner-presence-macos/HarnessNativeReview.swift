import AppKit
import Foundation
import SystemConfiguration

// This is presented by the verified flat executable itself. It works when the
// exported challenge arrives on stdin; the deliberate confirmation is local.
enum HarnessNativeReview {
    static func text(_ challenge: HarnessLaunchChallenge, guest: GuestOwnerPermit? = nil) throws -> String {
        guard let purpose = PairedHarnessPurpose(rawValue: challenge.action) else { throw PresenceFailure.invalidChallenge }
        let details = try purpose.review(challenge.plan_canonical, planID: challenge.plan_id, digest: challenge.plan_digest)
        if let guest {
            return ["Disposable Tart guest: " + guest.guest_vm_name,
                    "VM MAC: " + guest.guest_vm_mac,
                    "Guest macOS build: " + guest.guest_build,
                    "Physical Machine SHA-256: " + machineFingerprint(guest.host_machine_key),
                    "Guest Machine SHA-256: " + machineFingerprint(guest.guest_machine_key),
                    "Tart wrapper SHA-256: " + guest.tart_wrapper_sha256,
                    "Tart app SHA-256: " + guest.tart_app_sha256,
                    "HQ SHA-256: " + machineFingerprint(challenge.hq_key),
                    "Expires (Unix seconds): " + String(challenge.expires_at), details].joined(separator: "\n")
        }
        return ["Machine SHA-256: " + machineFingerprint(challenge.machine_key),
                "HQ SHA-256: " + machineFingerprint(challenge.hq_key),
                "Expires (Unix seconds): " + String(challenge.expires_at), details].joined(separator: "\n")
    }

    @MainActor static func confirm(_ challenge: HarnessLaunchChallenge, guest: GuestOwnerPermit? = nil) throws {
        let display = try text(challenge, guest: guest)
        try challenge.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        try guest?.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        var uid: uid_t = 0, gid: gid_t = 0
        guard SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil, uid == getuid() else { throw PresenceFailure.incomplete }
        let app = NSApplication.shared
        guard app.setActivationPolicy(.accessory) else { throw PresenceFailure.incomplete }
        let alert = NSAlert()
        guard let purpose = PairedHarnessPurpose(rawValue: challenge.action) else { throw PresenceFailure.invalidChallenge }
        alert.messageText = guest == nil ? purpose.confirmationPrompt : "Approve disposable Tart guest operation?"
        alert.informativeText = "Review the exact plan below before continuing to owner authentication."
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 600, height: 330))
        scroll.hasVerticalScroller = true
        let view = NSTextView(frame: scroll.contentView.bounds)
        view.isVerticallyResizable = true
        view.isHorizontallyResizable = false
        view.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        view.isEditable = false
        view.isSelectable = true
        view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        view.autoresizingMask = [.width]
        view.textContainer?.widthTracksTextView = true
        view.string = display
        scroll.documentView = view
        alert.accessoryView = scroll
        let cancel = alert.addButton(withTitle: "Cancel")
        cancel.keyEquivalent = "\r"
        let proceed = alert.addButton(withTitle: "Continue to owner authentication")
        proceed.keyEquivalent = ""
        let remaining = TimeInterval(challenge.expires_at) - Date().timeIntervalSince1970
        guard remaining > 0 else { throw PresenceFailure.expired }
        let deadline = Timer(timeInterval: remaining, repeats: false) { _ in NSApp.abortModal() }
        RunLoop.main.add(deadline, forMode: .modalPanel)
        defer { deadline.invalidate() }
        app.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertSecondButtonReturn else { throw PresenceFailure.declined }
        try challenge.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        try guest?.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    }
}
