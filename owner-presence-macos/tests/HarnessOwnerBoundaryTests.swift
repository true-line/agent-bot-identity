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
        func checkAccounts(_ source: String) throws -> String {
            let digest = SHA256.hash(data: Data(source.utf8)).map { String(format: "%02x", $0) }.joined()
            return try reviewHarnessAccounts(source, planID: "plan-20261120T122100Z-dcef", digest: digest)
        }
        let accounts = try String(contentsOf: fixtures.appendingPathComponent("harness-account-provision-accounts.json"), encoding: .utf8)
        let withBroker = try String(contentsOf: fixtures.appendingPathComponent("harness-account-provision-accounts-and-broker.json"), encoding: .utf8)
        let plainReview = try checkAccounts(accounts)
        precondition(plainReview.contains("Broker directories: none"))
        let directoryReview = try checkAccounts(withBroker)
        for field in ["none account _agent-bot-hq  UID 320  private group _agent-bot-hq  GID 320",
                      "none account _lead  UID 322  private group _lead  GID 322",
                      "create account _spec  UID 323  private group _spec  GID 323",
                      "Home /var/agent-bot-harness-_spec  mode 0700", "/usr/bin/false",
                      "create directory /Library/Application Support/ai.true-line.agent-bot-hq/ipc  root:wheel 0755",
                      "/ipc/_lead  _agent-bot-hq:_lead 2750", "/ipc/_spec  _agent-bot-hq:_spec 2750"] {
            precondition(directoryReview.contains(field))
        }
        let repair = accounts.replacingOccurrences(of: #""target":"_lead","action":"none""#, with: #""target":"_lead","action":"repair""#)
            .replacingOccurrences(of: "exists; home /var/agent-bot-harness-_lead;", with: "exists; home /var/agent-bot-harness-_lead has mode 0750 and is set to 0700;")
        let unchanged = accounts.replacingOccurrences(of: #""action":"create""#, with: #""action":"none""#)
            .replacingOccurrences(of: "home /var/agent-bot-harness-_spec, shell /usr/bin/false, private group, no password, no other groups",
                                  with: "exists; home /var/agent-bot-harness-_spec; its password is checked at apply")
        let unchangedReview = try checkAccounts(unchanged)
        precondition(unchangedReview.contains("none account _spec"))
        let repaired = try checkAccounts(repair)
        precondition(repaired.contains("repair account _lead") && repaired.contains("0750 and is set to 0700"))
        for (old, new) in [
            (#""purpose":"harness-account-provision""#, #""purpose":"harness-launch-install""#),
            (#""uid":323,"gid":323"#, #""uid":322,"gid":322"#),
            (#""gid":323"#, #""gid":324"#),
            (#""uid":323,"gid":323"#, #""uid":500,"gid":500"#),
            (#""target":"_agent-bot-hq","action":"none""#, #""target":"_agent-bot-hq","action":"create""#),
            (#""kind":"account""#, #""kind":"service""#),
            (#""kind":"directory""#, #""kind":"file""#),
            (#""group":"_spec""#, #""group":"wheel""#),
            ("home /var/agent-bot-harness-_spec", "home /var/agent-bot-hq"),
            ("-hq/ipc/_spec", "-hq/ipc/_other"),
            (#""mode":"0700""#, #""mode":"0755""#),
            (#""mode":"2750""#, #""mode":"0777""#),
            (#""action":"create""#, #""action":"remove""#),
            (#""group":"wheel""#, #""group":"wheel","content":"extra""#),
            (#""version":3"#, #""version":3,"version":3"#)
        ] {
            let changed = withBroker.replacingOccurrences(of: old, with: new)
            precondition(changed != withBroker && (try? checkAccounts(changed)) == nil)
        }
        let initial = try String(contentsOf: fixtures.appendingPathComponent("harness-launch-install.json"), encoding: .utf8)
        let unusual = initial.replacingOccurrences(of: "--stdio", with: "a b\u{202e}c")
        let exact = SHA256.hash(data: Data(unusual.utf8)).map { String(format: "%02x", $0) }.joined()
        let rendered = try renderHarnessReview(unusual, planID: "plan-20261120T122100Z-dcef", digest: exact, action: .install)
        precondition(rendered.contains(#"argv[1] "a b\u202ec""#) && !rendered.contains("\u{202e}"))
        print("Verified installed channel discovery, pin metadata, launch-rule and account review texts.")
    }
}
