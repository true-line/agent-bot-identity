import CryptoKit
import Darwin
import Foundation

@main
struct HarnessOwnerBoundaryTests {
    static func main() throws {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: scratch, withIntermediateDirectories: false)
        defer { try? fm.removeItem(at: scratch) }
        let fd = open(scratch.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        precondition(fd >= 0)
        let root = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        // The actual descriptor walk runs only under this private fixture.
        // Permission and directory-service checks are tested separately; no
        // real Machine pin, owner key, local consent dialog or signer is used.
        func read() throws -> Data {
            try HarnessMachinePin.publishedKey(root: root) { _, _, _, _ in }
        }
        func empty(_ path: String) throws -> URL {
            let dir = scratch.appendingPathComponent(path)
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir.appendingPathComponent("daemon.pub")
        }
        let bytes = Data(0..<32)
        precondition((try? read()) == nil)
        let first = try empty("opt/homebrew/var/agent-machine")
        precondition((try? read()) == nil)
        try bytes.write(to: first)
        let trusted = try read()
        precondition(trusted == bytes)
        try HarnessMachinePin.verify(bytes.map { String(format: "%02x", $0) }.joined(), published: trusted)
        precondition((try? HarnessMachinePin.verify(String(repeating: "ff", count: 32), published: trusted)) == nil)
        let second = try empty("usr/local/var/agent-machine")
        precondition((try? read()) == nil)
        try bytes.write(to: second)
        precondition((try? read()) == nil)
        try fm.removeItem(at: first.deletingLastPathComponent())
        let alternate = try read()
        precondition(alternate == bytes)
        try fm.removeItem(at: second)
        try fm.createSymbolicLink(at: second, withDestinationURL: scratch)
        precondition((try? read()) == nil)
        try fm.removeItem(at: second)
        try Data(repeating: 0, count: 33).write(to: second)
        precondition((try? read()) == nil)

        var s = stat()
        s.st_uid = 550; s.st_gid = 80; s.st_nlink = 1; s.st_size = 32
        func allows(_ type: HarnessMachinePin.Component, _ mode: mode_t, writable: Bool = false) -> Bool {
            s.st_mode = mode
            return HarnessMachinePin.allowed(s, type, owner: 550, caller: 551, callerCanWrite: writable)
        }
        precondition(allows(.prefix, S_IFDIR | 0o775))
        precondition(!allows(.prefix, S_IFDIR | 0o775, writable: true))
        s.st_gid = 20
        precondition(!allows(.variable, S_IFDIR | 0o775))
        precondition(allows(.channel, S_IFDIR | 0o755))
        precondition(!allows(.channel, S_IFDIR | 0o775))
        precondition(allows(.key, S_IFREG | 0o644))
        precondition(!allows(.key, S_IFREG | 0o664))
        s.st_nlink = 2; precondition(!allows(.key, S_IFREG | 0o644))
        s.st_nlink = 1; s.st_uid = 551; precondition(!allows(.key, S_IFREG | 0o644))
        s.st_uid = 0; precondition(allows(.systemDirectory, S_IFDIR | 0o755))

        let fixtures = URL(fileURLWithPath: CommandLine.arguments[1])
        for action in ["install", "retire"] {
            let canonical = try String(contentsOf: fixtures.appendingPathComponent("harness-launch-" + action + ".json"), encoding: .utf8)
            let digest = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
            let c = HarnessLaunchChallenge(action: "harness-launch-" + action, machine_key: String(repeating:"01", count:32),
                hq_key: String(repeating:"02", count:32), owner_key: "", plan_id: "plan-20261120T122100Z-dcef",
                plan_digest: digest, nonce: "", plan_canonical: canonical, expires_at: 1120)
            let text = try HarnessNativeReview.text(c)
            for exact in ["argv[0]", "argv[1] \"--stdio\"", "SHA-256: " + digest,
                          "/private/etc/sudoers.d/agent-bot-hq-harness-launch", "root:wheel 0440", "NOSETENV:", "harness-egress.sb"] {
                precondition(text.contains(exact))
            }
            if action == "retire" { precondition(text.contains("Installed plan SHA-256: ")) }
        }
        let initial = try String(contentsOf: fixtures.appendingPathComponent("harness-launch-install.json"), encoding: .utf8)
        let unusual = initial.replacingOccurrences(of: "--stdio", with: "a b\u{202e}c")
        let exact = SHA256.hash(data: Data(unusual.utf8)).map { String(format: "%02x", $0) }.joined()
        let rendered = try renderHarnessReview(unusual, planID: "plan-20261120T122100Z-dcef", digest: exact, action: .install)
        precondition(rendered.contains(#"argv[1] "a b\u202ec""#) && !rendered.contains("\u{202e}"))
        print("Verified installed channel discovery, pin metadata and both native review texts.")
    }
}
