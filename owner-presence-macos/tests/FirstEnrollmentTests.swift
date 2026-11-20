import Darwin
import Foundation

@main struct FirstEnrollmentTests {
    enum Failure: Error { case expectation }
    static func refuses(_ wanted: FirstEnrollmentError, _ operation: () throws -> Void) throws {
        do { try operation(); throw Failure.expectation }
        catch let error as FirstEnrollmentError where error == wanted { return }
    }

    static func main() throws {
        if CommandLine.arguments.count == 3, let account = UUID(uuidString: CommandLine.arguments[2]) {
            let fd = open(CommandLine.arguments[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.expectation }
            do {
                try OwnerFirstEnrollment.consume(at: FileHandle(fileDescriptor: fd, closeOnDealloc: true),
                    authority: getuid(), owner: getuid(), account: account, clock: { 1400 })
            } catch FirstEnrollmentError.spent { exit(2) }
              catch FirstEnrollmentError.denied { exit(2) }
            return
        }
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("owner-enrollment-" + UUID().uuidString)
        try fm.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: base) }
        let fd = open(base.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.expectation }
        let root = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        let id = UUID(), uid = getuid()
        var now: Int64 = 1000
        var checks = 0
        func issue(_ retry: Bool, _ principal: UUID = id) throws {
            try OwnerFirstEnrollment.issue(at: root, authority: uid, owner: uid, account: principal,
                                            retry: retry, now: now) { checks += 1 }
        }
        func use(_ principal: UUID = id) throws {
            try OwnerFirstEnrollment.consume(at: root, authority: uid, owner: uid, account: principal, clock: { now })
        }
        try refuses(.missing) { try use() }
        try refuses(.missing) { try issue(true) }
        try issue(false)
        let current = base.appendingPathComponent("current")
        let original = try String(contentsOf: current, encoding: .utf8)
        func replaceRecord(_ content: String) throws {
            try Data(content.utf8).write(to: current, options: .atomic)
            guard chmod(current.path, 0o444) == 0 else { throw Failure.expectation }
        }
        for bad in ["-9223372036854775808", "18446744073709551615", "01300", "N/A"] {
            try replaceRecord(original.replacingOccurrences(of: "\n1300\n", with: "\n" + bad + "\n"))
            try refuses(.denied) { try use() }
        }
        try replaceRecord(original.replacingOccurrences(of: "\n1300\n", with: "\n9223372036854775807\n"))
        try refuses(.spent) { try use() }
        try replaceRecord(original)
        try refuses(.reserved) { try issue(false) }
        try refuses(.active) { try issue(true) }
        try refuses(.denied) { try use(UUID()) }
        try refuses(.denied) { try issue(true, UUID()) }
        try use()
        try refuses(.spent) { try use() }
        try refuses(.history) {
            try OwnerFirstEnrollment.issue(at: root, authority: uid, owner: uid, account: id,
                                            retry: true, now: now) { throw FirstEnrollmentError.history }
        }
        try refuses(.spent) { try use() }
        now += 5
        try issue(true)
        now += 300
        try refuses(.spent) { try use() }
        try issue(true)
        try use()
        guard checks == 7 else { throw Failure.expectation }
        now = 1400
        try issue(true)
        let competing = try (0..<4).map { _ -> Process in
            let process = Process()
            process.executableURL = Bundle.main.executableURL
            process.arguments = [base.path, id.uuidString]
            try process.run()
            return process
        }
        for process in competing { process.waitUntilExit() }
        let outcomes = competing.map(\.terminationStatus).sorted()
        guard outcomes == [0, 2, 2, 2] else { throw Failure.expectation }

        // Exercise the real Machine filename inventory without opening any key or receipt.
        let stateURL = base.appendingPathComponent("machine")
        let peers = stateURL.appendingPathComponent("peers")
        try fm.createDirectory(at: peers, withIntermediateDirectories: true)
        let stateFD = open(stateURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard stateFD >= 0 else { throw Failure.expectation }
        let state = FileHandle(fileDescriptor: stateFD, closeOnDealloc: true)
        for leaf in ["daemon.pub", "peers/terminal.pub"] {
            try Data().write(to: stateURL.appendingPathComponent(leaf))
        }
        try OwnerFirstEnrollment.checkMachineState(state)
        for leaf in ["owner-pair.json", "agent-daemon.uid", "peers/agent-daemon.pub", "peers/agent-daemon.next",
                     "peers/agent-daemon.confirm", "peers/agent-daemon.revoked", "peer.pub", "peers/unrecognized"] {
            let item = stateURL.appendingPathComponent(leaf)
            try Data().write(to: item)
            try refuses(.history) { try OwnerFirstEnrollment.checkMachineState(state) }
            try fm.removeItem(at: item)
        }
        try fm.removeItem(at: peers)
        try Data().write(to: stateURL.appendingPathComponent("peer.pub"))
        try OwnerFirstEnrollment.checkMachineState(state)
        let ledger = base.appendingPathComponent("receipts")
        try fm.createDirectory(at: ledger, withIntermediateDirectories: false)
        func checkReceipts() throws {
            let fd = open(ledger.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.expectation }
            try OwnerFirstEnrollment.checkReceipts(FileHandle(fileDescriptor: fd, closeOnDealloc: true))
        }
        try checkReceipts()
        try Data().write(to: ledger.appendingPathComponent("plan-example.json"))
        try refuses(.history) { try checkReceipts() }
        print("Passed first-enrollment issue, use, admin retry, account, expiry and Machine history checks.")
    }
}
