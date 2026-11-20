import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

enum FreshOwnerFailure: Error, LocalizedError {
    case missing, exists, unavailable, untrusted

    var errorDescription: String? {
        switch self {
        case .missing: return "The fresh Machine owner key has not been initialized."
        case .exists: return "A Machine owner key record already exists. Use the existing public key."
        case .unavailable: return "The owner's login Keychain or Secure Enclave is unavailable."
        case .untrusted: return "The Machine owner key record failed its custody checks."
        }
    }
}

// The retained result is the original ACL code requirement, including when a
// legitimate update changed the executable bytes. A displayed pathname alone
// does not identify which code macOS granted access to.
@_silgen_name("keyd_copy_trusted_identity")
private func copyOwnerCodeIdentity(_ app: SecTrustedApplication) -> Unmanaged<CFData>?

private func requireOwnerStatus(_ status: OSStatus) throws {
    guard status == errSecSuccess else { throw FreshOwnerFailure.unavailable }
}

struct OwnerItemAccess {
    let app: SecTrustedApplication
    let identity: Data
    let team: String?
    private let name = "Machine owner key reference" as CFString
    private let extraRights = [kSecACLAuthorizationDelete, kSecACLAuthorizationKeychainItemDelete,
                               kSecACLAuthorizationKeychainItemModify, kSecACLAuthorizationChangeOwner,
                               kSecACLAuthorizationChangeACL]

    static func codeIdentity(of app: SecTrustedApplication) throws -> Data {
        guard let id = copyOwnerCodeIdentity(app)?.takeRetainedValue() else {
            throw FreshOwnerFailure.untrusted
        }
        return id as Data
    }

    init() throws {
        var app: SecTrustedApplication?
        try requireOwnerStatus(SecTrustedApplicationCreateFromPath(nil, &app))
        guard let app else { throw FreshOwnerFailure.untrusted }
        self.app = app
        identity = try Self.codeIdentity(of: app)
        var code: SecCode?
        var info: CFDictionary?
        try requireOwnerStatus(SecCodeCopySelf([], &code))
        guard let code else { throw FreshOwnerFailure.untrusted }
        var staticCode: SecStaticCode?
        try requireOwnerStatus(SecCodeCopyStaticCode(code, [], &staticCode))
        guard let staticCode else { throw FreshOwnerFailure.untrusted }
        try requireOwnerStatus(SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info))
        team = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    func entries(_ access: SecAccess) throws -> [SecACL] {
        var list: CFArray?
        try requireOwnerStatus(SecAccessCopyACLList(access, &list))
        guard let list, CFArrayGetCount(list) > 0 else { throw FreshOwnerFailure.untrusted }
        return list as! [SecACL]
    }

    func make() throws -> SecAccess {
        let apps = [app] as CFArray
        var access: SecAccess?
        try requireOwnerStatus(SecAccessCreate(name, apps, &access))
        guard let access else { throw FreshOwnerFailure.untrusted }
        for entry in try entries(access) {
            try requireOwnerStatus(SecACLSetContents(entry, apps, name, []))
        }
        var extra: SecACL?
        try requireOwnerStatus(SecACLCreateWithSimpleContents(access, apps, name, [], &extra))
        guard let extra else { throw FreshOwnerFailure.untrusted }
        try requireOwnerStatus(SecACLUpdateAuthorizations(extra, extraRights as CFArray))
        return access
    }

    private func matchesTeam(_ description: CFString?) -> Bool {
        guard let team, let description else { return false }
        let text = description as String
        let hex = Array(text.utf8)
        guard !hex.isEmpty, hex.count <= 8192, hex.count.isMultiple(of: 2) else { return false }
        var data = Data()
        for i in stride(from: 0, to: hex.count, by: 2) {
            guard let n = UInt8(String(decoding: hex[i...i+1], as: UTF8.self), radix: 16) else { return false }
            data.append(n)
        }
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        return (plist as? [String: Any])?["Partitions"] as? [String] == ["teamid:" + team]
    }

    func verify(_ access: SecAccess) throws {
        var covered = Set<String>()
        for entry in try entries(access) {
            guard let names = SecACLCopyAuthorizations(entry) as? [String], !names.isEmpty else {
                throw FreshOwnerFailure.untrusted
            }
            var apps: CFArray?, desc: CFString?, prompt: SecKeychainPromptSelector = []
            try requireOwnerStatus(SecACLCopyContents(entry, &apps, &desc, &prompt))
            if let apps {
                let list = apps as! [SecTrustedApplication]
                guard list.count == 1, try Self.codeIdentity(of: list[0]) == identity else {
                    throw FreshOwnerFailure.untrusted
                }
                covered.formUnion(names)
            } else {
                guard names == [kSecACLAuthorizationIntegrity as String] ||
                    (names == [kSecACLAuthorizationPartitionID as String] && matchesTeam(desc))
                else { throw FreshOwnerFailure.untrusted }
            }
        }
        let required = extraRights.map { $0 as String } + [kSecACLAuthorizationDecrypt as String]
        guard covered.isSuperset(of: required) else { throw FreshOwnerFailure.untrusted }
    }
}

private struct FreshOwnerRecord {
    let point: Data
    let reference: Data

    init(point: Data, reference: Data) throws {
        guard point.count == 65, point.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: point)) != nil,
              (1...8192).contains(reference.count) else { throw FreshOwnerFailure.untrusted }
        self.point = point
        self.reference = reference
    }

    init(bytes: Data) throws {
        guard bytes.count > 65 else { throw FreshOwnerFailure.untrusted }
        try self.init(point: Data(bytes.prefix(65)), reference: Data(bytes.dropFirst(65)))
    }
}

// All three callbacks are required. Observing a missing item never authorizes
// enrollment. The separate first-enrollment grant is consumed by authorizeFresh.
func withFreshOwnerSlot<T>(directory: String, exists: () throws -> Bool,
                           authorizeFresh: () throws -> Void, create: () throws -> T) throws -> T {
    // Serialize first enrollment without adding a file to the owner's home.
    // SecItemAdd independently refuses a duplicate in the selected Keychain.
    let fd = Darwin.open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw FreshOwnerFailure.unavailable }
    defer { Darwin.close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0, st.st_uid == getuid(), st.st_mode & 0o022 == 0,
          flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw FreshOwnerFailure.unavailable }
    guard try !exists() else { throw FreshOwnerFailure.exists }
    try authorizeFresh()
    return try create()
}

struct FreshOwnerStore {
    private typealias Key = SecureEnclave.P256.Signing.PrivateKey
    private let keychain: SecKeychain
    private let directory: String
    private let access: OwnerItemAccess
    private let verifyExecutable: () throws -> Void
    private let item: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "ai.true-line.agent-bot-owner-presence.fresh",
        kSecAttrAccount: "owner-pairing-p256-v1",
    ]

    static func open(verifyExecutable: @escaping () throws -> Void) throws -> Self {
        try verifyExecutable()
        guard getuid() != 0, getuid() == geteuid(), let user = getpwuid(getuid()) else {
            throw FreshOwnerFailure.unavailable
        }
        let home = String(cString: user.pointee.pw_dir)
        guard home.hasPrefix("/") else { throw FreshOwnerFailure.unavailable }
        let path = URL(fileURLWithPath: home).appendingPathComponent("Library/Keychains/login.keychain-db")
        var st = stat()
        guard path.resolvingSymlinksInPath().path == path.path,
              lstat(path.path, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1,
              st.st_uid == getuid(), st.st_mode & 0o077 == 0 else { throw FreshOwnerFailure.unavailable }
        // This affects only this one-shot CLI process. Keychain reads must
        // never open an OS authorization dialog; exact approval uses LAContext.
        try requireOwnerStatus(SecKeychainSetUserInteractionAllowed(false))
        var db: SecKeychain?
        try requireOwnerStatus(SecKeychainOpen(path.path, &db))
        guard let db else { throw FreshOwnerFailure.unavailable }
        var flags: SecKeychainStatus = 0
        try requireOwnerStatus(SecKeychainGetStatus(db, &flags))
        guard flags & UInt32(kSecUnlockStateStatus) != 0 else { throw FreshOwnerFailure.unavailable }
        let access = try OwnerItemAccess()
        guard access.team != nil else { throw FreshOwnerFailure.untrusted }
        return Self(keychain: db, directory: path.deletingLastPathComponent().path, access: access, verifyExecutable: verifyExecutable)
    }

    private func find() throws -> SecKeychainItem? {
        var query = item
        query[kSecMatchSearchList] = [keychain]
        query[kSecReturnRef] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try requireOwnerStatus(status)
        guard let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else {
            throw FreshOwnerFailure.untrusted
        }
        return (result as! SecKeychainItem)
    }

    private func read() throws -> FreshOwnerRecord {
        try verifyExecutable()
        guard let found = try find() else { throw FreshOwnerFailure.missing }
        var storedAccess: SecAccess?
        try requireOwnerStatus(SecKeychainItemCopyAccess(found, &storedAccess))
        guard let storedAccess else { throw FreshOwnerFailure.untrusted }
        try access.verify(storedAccess)
        var size: UInt32 = 0, value: UnsafeMutableRawPointer?
        try requireOwnerStatus(SecKeychainItemCopyContent(found, nil, nil, &size, &value))
        defer { SecKeychainItemFreeContent(nil, value) }
        guard (66...8257).contains(size), let value else { throw FreshOwnerFailure.untrusted }
        return try FreshOwnerRecord(bytes: Data(bytes: value, count: Int(size)))
    }

    private func insert(_ record: FreshOwnerRecord) throws {
        var add = item
        add[kSecUseKeychain] = keychain
        add[kSecValueData] = record.point + record.reference
        add[kSecAttrAccess] = try access.make()
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status != errSecDuplicateItem else { throw FreshOwnerFailure.exists }
        try requireOwnerStatus(status)
    }

    private func existing() throws -> FreshOwnerRecord {
        let record = try read()
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let key = try Key(dataRepresentation: record.reference, authenticationContext: context)
        guard key.publicKey.x963Representation == record.point else { throw FreshOwnerFailure.untrusted }
        return record
    }

    func existingPublicKey() throws -> Data { try existing().point }

    func initializePublicKey(authorizeFresh: () throws -> Void) throws -> Data {
        try verifyExecutable()
        return try withFreshOwnerSlot(directory: directory, exists: { try find() != nil },
                                      authorizeFresh: authorizeFresh) {
            try createAndReopen()
        }
    }

    private func createAndReopen() throws -> Data {
        guard let policy = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .userPresence], nil) else { throw FreshOwnerFailure.unavailable }
        let context = LAContext()
        defer { context.invalidate() }
        context.interactionNotAllowed = true
        let key = try Key(compactRepresentable: true, accessControl: policy, authenticationContext: context)
        let point = key.publicKey.x963Representation
        try verifyExecutable()
        try insert(FreshOwnerRecord(point: point, reference: key.dataRepresentation))
        guard try existingPublicKey() == point else { throw FreshOwnerFailure.untrusted }
        return point
    }

    func approve(_ request: OwnerRequest) async throws -> [String: String] {
        try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        let record = try existing()
        let proof = try await approveOwnerRequest(request, existingReference: record.reference)
        try verifyExecutable()
        let retained = try read()
        guard retained.point == record.point, retained.reference == record.reference,
              proof["public_key"] == record.point.base64EncodedString() else { throw FreshOwnerFailure.untrusted }
        return proof
    }
}

#if FRESH_OWNER_STORE_TESTS
// This fixture can persist only synthetic records in a caller-supplied file
// Keychain. Production builds have no path or custody injection interface.
extension FreshOwnerStore {
    static func fixture(_ db: SecKeychain, directory: String) throws -> Self {
        Self(keychain: db, directory: directory, access: try OwnerItemAccess(), verifyExecutable: {})
    }

    func insertFixture(point: Data, reference: Data) throws {
        try insert(FreshOwnerRecord(point: point, reference: reference))
    }

    func fixtureItem() throws -> SecKeychainItem? { try find() }

}
#endif
