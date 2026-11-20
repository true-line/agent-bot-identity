import CryptoKit
import Darwin
import Foundation
import Security

private enum TestError: Error { case fail }

private func check(_ condition: Bool) throws {
    guard condition else { throw TestError.fail }
}

private func refused(_ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw TestError.fail
}

private func syntheticACLs() throws {
    let policy = try OwnerItemAccess()
    let correct = try policy.make()
    try policy.verify(correct)
    let entries = try policy.entries(correct)
    guard let entry = entries.first(where: {
        (SecACLCopyAuthorizations($0) as? [String])?.contains(kSecACLAuthorizationDecrypt as String) == true
    }) else { throw TestError.fail }
    // All-application access and a list with two trusted entries both refuse.
    let label = "Synthetic owner reference" as CFString
    try check(SecACLSetContents(entry, nil, label, []) == errSecSuccess)
    try refused { try policy.verify(correct) }
    try check(SecACLSetContents(entry, [policy.app, policy.app] as CFArray, label, []) == errSecSuccess)
    try refused { try policy.verify(correct) }
    var other: SecTrustedApplication?
    try check(SecTrustedApplicationCreateFromPath("/usr/bin/true", &other) == errSecSuccess)
    try check(SecACLSetContents(entry, [other!] as CFArray, label, []) == errSecSuccess)
    try refused { try policy.verify(correct) }
}

private func codeContinuity(_ directory: URL) throws {
    let program = URL(fileURLWithPath: "/usr/bin/true")
    let old = directory.appendingPathComponent("old")
    let updated = directory.appendingPathComponent("updated")
    try FileManager.default.copyItem(at: program, to: old)
    try FileManager.default.copyItem(at: program, to: updated)
    func trusted(_ path: String) throws -> SecTrustedApplication {
        var app: SecTrustedApplication?
        try check(SecTrustedApplicationCreateFromPath(path, &app) == errSecSuccess)
        guard let app else { throw TestError.fail }
        return app
    }
    let original = try trusted(old.path)
    try FileManager.default.removeItem(at: old)
    let retained = try OwnerItemAccess.codeIdentity(of: original)
    try check(try retained == OwnerItemAccess.codeIdentity(of: trusted(updated.path)))
    try check(try retained != OwnerItemAccess.codeIdentity(of: trusted("/usr/bin/false")))
}

private func creationOrdering(_ dir: String) throws {
    var events: [String] = []
    var present = false
    func attempt() throws {
        try withFreshOwnerSlot(directory: dir, exists: { events.append("inspect"); return present },
                               authorizeFresh: { events.append("grant") }) {
            try refused {
                try withFreshOwnerSlot(directory: dir, exists: { events.append("other inspect"); return false },
                                       authorizeFresh: { events.append("other grant") }) {
                    events.append("other creation")
                }
            }
            events.append("create")
            present = true
        }
    }
    try attempt()
    try check(events == ["inspect", "grant", "create"])
    try refused { try attempt() }
    try check(events == ["inspect", "grant", "create", "inspect"])
    try refused {
        try withFreshOwnerSlot(directory: dir, exists: { false }, authorizeFresh: { throw TestError.fail }) {
            events.append("unauthorized creation")
        }
    }
    try refused {
        try withFreshOwnerSlot(directory: dir, exists: { throw TestError.fail },
                               authorizeFresh: { events.append("uncertain grant") }) {
            events.append("uncertain creation")
        }
    }
    try check(events.count == 4)
}

private func hostedFileKeychain(_ dir: URL) throws {
    let env = ProcessInfo.processInfo.environment
    guard env["GITHUB_ACTIONS"] == "true", env["OWNER_PERMIT_RUNNER"] == "github-hosted",
          getuid() == geteuid(), getuid() != 0 else { throw TestError.fail }
    let path = dir.appendingPathComponent("synthetic.keychain-db").path
    var db: SecKeychain?
    try check(SecKeychainSetUserInteractionAllowed(false) == errSecSuccess)
    try check("fixture".withCString { SecKeychainCreate(path, 7, $0, false, nil, &db) } == errSecSuccess)
    guard let db else { throw TestError.fail }
    defer { SecKeychainDelete(db) }
    let store = try FreshOwnerStore.fixture(db, directory: dir.path)
    // The public P-256 generator and a fake reference do not require an enclave.
    let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
              "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    let point = Data(stride(from: 0, to: hex.count, by: 2).map {
        let i = hex.index(hex.startIndex, offsetBy: $0)
        return UInt8(hex[i..<hex.index(i, offsetBy: 2)], radix: 16)!
    })
    try check(try store.fixtureItem() == nil)
    try store.insertFixture(point: point, reference: Data([1]))
    let stored = try store.fixtureItem()
    try check(stored != nil)
    try refused { try store.insertFixture(point: point, reference: Data([2])) }
    var grants = 0
    try refused { _ = try store.initializePublicKey { grants += 1 } }
    try check(grants == 0)
    // Inspect actual stored rights. An unsigned hosted binary lacks a release Team ID
    // for Apple's additional partition entry. No positive signed-release claim.
    var actual: SecAccess?
    try check(SecKeychainItemCopyAccess(stored!, &actual) == errSecSuccess)
    guard let actual else { throw TestError.fail }
    let policy = try OwnerItemAccess()
    var countedDecrypt = 0
    for entry in try policy.entries(actual) {
        if (SecACLCopyAuthorizations(entry) as? [String])?.contains(kSecACLAuthorizationDecrypt as String) == true {
            var apps: CFArray?, label: CFString?, flags: SecKeychainPromptSelector = []
            try check(SecACLCopyContents(entry, &apps, &label, &flags) == errSecSuccess)
            try check(apps.map(CFArrayGetCount) == 1)
            countedDecrypt += 1
        }
    }
    try check(countedDecrypt == 1)
    // Inspect the same stored item that won the initial insert, including
    // its original bytes after the duplicate insert and duplicate init.
    var size: UInt32 = 0, data: UnsafeMutableRawPointer?
    try check(SecKeychainItemCopyContent(stored!, nil, nil, &size, &data) == errSecSuccess)
    defer { SecKeychainItemFreeContent(nil, data) }
    guard size == 66, let data else { throw TestError.fail }
    try check(Data(bytes: data, count: Int(size)) == point + Data([1]))
}

@main struct FreshOwnerStoreTests {
    static func main() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        try syntheticACLs()
        try codeContinuity(dir)
        try creationOrdering(dir.path)
        if CommandLine.arguments.dropFirst() == ["--disposable-keychain"] { try hostedFileKeychain(dir) }
        else { try check(CommandLine.arguments.count == 1) }
        print("Fresh owner store checks passed")
    }
}
