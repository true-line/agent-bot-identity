import Darwin
import Foundation
import OpenDirectory

enum FirstEnrollmentError: String, Error, CustomStringConvertible {
    case denied = "First owner enrollment could not verify the local account or protected setup records."
    case history = "Prior or ambiguous Machine/HQ enrollment evidence exists. Preserve the existing owner identity."
    case missing = "Ask the administrator to authorize first enrollment for this daily account."
    case reserved = "A first-enrollment grant was already issued. Only an explicit administrator retry can renew it."
    case active = "The current first-enrollment grant is still available to the selected daily account."
    case spent = "The first-enrollment grant was used or expired. An administrator must check enrollment history before an explicit retry."
    var description: String { rawValue }
}

private struct EnrollmentAccount {
    let uid: uid_t
    let id: UUID
    let directoryRecord: ODRecord
    let home: String
    init(_ uid: uid_t) throws {
        // Local Directory Services supplies the account incarnation and registered home.
        // A UID, environment HOME, or a synthesized UID-derived UUID cannot identify it alone.
        let node = try ODNode(session: .default(), type: UInt32(kODNodeTypeLocalNodes))
        let keys = [kODAttributeTypeUniqueID, kODAttributeTypeGUID, kODAttributeTypeNFSHomeDirectory]
        let query = try ODQuery(node: node, forRecordTypes: kODRecordTypeUsers, attribute: keys[0],
                                matchType: UInt32(kODMatchEqualTo), queryValues: String(uid),
                                returnAttributes: keys, maximumResults: 2)
        let records = try query.resultsAllowingPartial(false) as? [ODRecord]
        guard uid >= 501, let records, records.count == 1 else { throw FirstEnrollmentError.denied }
        let record = records[0]
        directoryRecord = record
        func value(_ key: String) throws -> String {
            guard let values = try record.values(forAttribute: key) as? [String], values.count == 1
            else { throw FirstEnrollmentError.denied }
            return values[0]
        }
        guard try value(keys[0]) == String(uid), let uuid = UUID(uuidString: try value(keys[1]))
        else { throw FirstEnrollmentError.denied }
        home = try value(keys[2])
        guard home.hasPrefix("/"), home != "/", home == (home as NSString).standardizingPath
        else { throw FirstEnrollmentError.denied }
        self.uid = uid
        id = uuid
    }
}

enum OwnerFirstEnrollment {
    private static let location = ["private", "var", "db", "agent-bot-owner-enrollment"]
    private static let lifetime: Int64 = 300
    private static let directoryFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
    private static let readFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK

    private static func handle(_ fd: Int32) throws -> FileHandle {
        guard fd >= 0 else { throw FirstEnrollmentError.denied }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    private static func checked(_ fd: Int32, owner: uid_t, type: mode_t, mode: mode_t? = nil) throws -> stat {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_uid == owner, s.st_mode & S_IFMT == type,
              s.st_mode & 0o6022 == 0, mode.map({ s.st_mode & 0o7777 == $0 }) ?? true,
              type != S_IFREG || s.st_nlink == 1 else { throw FirstEnrollmentError.denied }
        if let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL
            else { throw FirstEnrollmentError.denied }
        } else if errno != ENOENT { throw FirstEnrollmentError.denied }
        return s
    }

    // This root-owned directory is only created by the authorized administrator command.
    private static func openRoot(create: Bool) throws -> FileHandle {
        var parent = try handle(open("/", directoryFlags))
        for part in location {
            _ = try checked(parent.fileDescriptor, owner: 0, type: S_IFDIR)
            var created = false
            if create && part == location.last {
                created = mkdirat(parent.fileDescriptor, part, 0o755) == 0
                guard created || errno == EEXIST else { throw FirstEnrollmentError.denied }
            }
            let fd = openat(parent.fileDescriptor, part, directoryFlags)
            if fd < 0 && errno == ENOENT && !create { throw FirstEnrollmentError.missing }
            let child = try handle(fd)
            if created {
                guard fchmod(fd, 0o755) == 0, fsync(parent.fileDescriptor) == 0 else { throw FirstEnrollmentError.denied }
            }
            parent = child
        }
        _ = try checked(parent.fileDescriptor, owner: 0, type: S_IFDIR, mode: 0o755)
        return parent
    }

    // Distinguish an absent component from unreadable state or an indirect directory.
    private static func directory(_ parent: FileHandle, _ name: String) throws -> FileHandle? {
        let fd = openat(parent.fileDescriptor, name, directoryFlags)
        if fd < 0 && errno == ENOENT { return nil }
        return try handle(fd)
    }

    static func checkMachineState(_ state: FileHandle) throws {
        func requireAbsent(_ dir: FileHandle, _ name: String) throws {
            var s = stat()
            if fstatat(dir.fileDescriptor, name, &s, AT_SYMLINK_NOFOLLOW) == 0 { throw FirstEnrollmentError.history }
            guard errno == ENOENT else { throw FirstEnrollmentError.denied }
        }
        try requireAbsent(state, "owner-pair.json")
        try requireAbsent(state, "agent-daemon.uid")
        let suffixes = ["pub", "next", "confirm", "revoked"]
        let peers = try directory(state, "peers")
        for suffix in suffixes {
            var old = stat()
            if fstatat(state.fileDescriptor, "peer." + suffix, &old, AT_SYMLINK_NOFOLLOW) == 0 {
                // Machine migrates these terminal records only when peers/ is absent.
                guard peers == nil, old.st_mode & S_IFMT == S_IFREG else { throw FirstEnrollmentError.history }
            } else if errno != ENOENT { throw FirstEnrollmentError.denied }
        }
        if let peers {
            let terminal = Set(suffixes.map { "terminal." + $0 })
            try forEachEntry(peers) { name in
                var leaf = stat()
                guard terminal.contains(name),
                      fstatat(peers.fileDescriptor, name, &leaf, AT_SYMLINK_NOFOLLOW) == 0,
                      leaf.st_mode & S_IFMT == S_IFREG else { throw FirstEnrollmentError.history }
            }
        }
    }

    private static func inspectHistory(_ owner: EnrollmentAccount) throws {
        let root = try handle(open("/", directoryFlags))
        func descend(_ parent: FileHandle, _ path: String) throws -> FileHandle? {
            var current = parent
            for name in path.split(separator: "/") {
                guard let next = try directory(current, String(name)) else { return nil }
                current = next
            }
            return current
        }
        var homes = [owner.home: owner.uid]
        #if arch(arm64)
        let nativePrefix = "opt/homebrew"
        #else
        let nativePrefix = "usr/local"
        #endif
        for name in ["opt/homebrew", "usr/local"] {
            guard let prefix = try descend(root, name) else {
                if name == nativePrefix { throw FirstEnrollmentError.denied }
                continue
            }
            let shared = try descend(prefix, "var/agent-machine")
            if let shared { try checkMachineState(shared) }
            if name != nativePrefix && shared == nil {
                // An unused /usr/local is common on Apple Silicon. An installed second
                // Homebrew prefix must still have an identifiable, inspectable owner.
                guard let bin = try descend(prefix, "bin") else { continue }
                var brew = stat()
                if fstatat(bin.fileDescriptor, "brew", &brew, AT_SYMLINK_NOFOLLOW) != 0 {
                    guard errno == ENOENT else { throw FirstEnrollmentError.denied }
                    continue
                }
            }
            var s = stat()
            guard fstat(prefix.fileDescriptor, &s) == 0 else { throw FirstEnrollmentError.denied }
            let admin = try EnrollmentAccount(s.st_uid)
            let node = try ODNode(session: .default(), type: UInt32(kODNodeTypeLocalNodes))
            let group = try node.record(withRecordType: kODRecordTypeGroups, name: "admin", attributes: nil)
            try group.isMemberRecord(admin.directoryRecord)
            if let registeredUID = homes[admin.home], registeredUID != admin.uid { throw FirstEnrollmentError.denied }
            homes[admin.home] = admin.uid
        }
        for (home, uid) in homes {
            guard let registered = try descend(root, home) else { throw FirstEnrollmentError.denied }
            var s = stat()
            guard fstat(registered.fileDescriptor, &s) == 0, s.st_uid == uid, s.st_mode & 0o022 == 0
            else { throw FirstEnrollmentError.denied }
            guard let config = try directory(registered, ".config") else { continue }
            guard fstat(config.fileDescriptor, &s) == 0, s.st_uid == uid, s.st_mode & 0o022 == 0
            else { throw FirstEnrollmentError.denied }
            if let state = try directory(config, "agent-machine") {
                guard fstat(state.fileDescriptor, &s) == 0, s.st_uid == uid, s.st_mode & 0o077 == 0
                else { throw FirstEnrollmentError.denied }
                try checkMachineState(state)
            }
        }
        if let receipts = try descend(root, "private/var/db/managed-machine/members/receipts") {
            try checkReceipts(receipts)
        }
    }

    static func checkReceipts(_ receipts: FileHandle) throws {
        try forEachEntry(receipts) { _ in throw FirstEnrollmentError.history }
    }

    private static func forEachEntry(_ directory: FileHandle, _ check: (String) throws -> Void) throws {
        let fd = openat(directory.fileDescriptor, ".", directoryFlags)
        guard fd >= 0 else { throw FirstEnrollmentError.denied }
        guard let stream = fdopendir(fd) else { close(fd); throw FirstEnrollmentError.denied }
        defer { closedir(stream) }
        errno = 0
        while let item = readdir(stream) {
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: item.pointee.d_name)) { String(cString: $0) }
            }
            if name != "." && name != ".." { try check(name) }
            errno = 0
        }
        guard errno == 0 else { throw FirstEnrollmentError.denied }
    }

    private struct Grant: Equatable {
        let uid: uid_t
        let account: UUID
        let slot: UUID
        let expiry: Int64
        var bytes: Data { Data("first-enrollment-v1\n\(uid)\n\(account.uuidString)\n\(slot.uuidString)\n\(expiry)\n".utf8) }
        var directory: String { "grant-" + slot.uuidString }
        init(uid: uid_t, account: UUID, now: Int64) {
            self.uid = uid; self.account = account; slot = UUID(); expiry = now + lifetime
        }
        init(_ data: Data) throws {
            let fields = String(decoding: data, as: UTF8.self).split(separator: "\n")
            guard fields.count == 5, let uid = uid_t(fields[1]), let account = UUID(uuidString: String(fields[2])),
                  let slot = UUID(uuidString: String(fields[3])), let expiry = Int64(fields[4]), expiry >= lifetime
            else { throw FirstEnrollmentError.denied }
            self.uid = uid; self.account = account; self.slot = slot; self.expiry = expiry
            guard bytes == data else { throw FirstEnrollmentError.denied }
        }
        func valid(at now: Int64) -> Bool { now < expiry && expiry - lifetime <= now }
    }

    private static func record(_ parent: FileHandle, _ name: String, owner: uid_t) throws -> (FileHandle, Grant)? {
        let fd = openat(parent.fileDescriptor, name, readFlags)
        if fd < 0 && errno == ENOENT { return nil }
        let file = try handle(fd)
        let s = try checked(fd, owner: owner, type: S_IFREG, mode: 0o444)
        guard (1...200).contains(s.st_size), let bytes = try file.read(upToCount: 201), bytes.count == s.st_size
        else { throw FirstEnrollmentError.denied }
        return (file, try Grant(bytes))
    }

    private static func write(_ grant: Grant, at parent: FileHandle, name: String) throws {
        let file = try handle(openat(parent.fileDescriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600))
        try file.write(contentsOf: grant.bytes)
        guard fchmod(file.fileDescriptor, 0o444) == 0, fsync(file.fileDescriptor) == 0
        else { throw FirstEnrollmentError.denied }
    }

    static func authorize(ownerUID: uid_t) throws { try setup(ownerUID: ownerUID, retry: false) }
    static func retry(ownerUID: uid_t) throws { try setup(ownerUID: ownerUID, retry: true) }
    private static func setup(ownerUID: uid_t, retry: Bool) throws {
        guard getuid() == 0, geteuid() == 0 else { throw FirstEnrollmentError.denied }
        let account = try EnrollmentAccount(ownerUID)
        try issue(at: openRoot(create: true), authority: 0, owner: ownerUID, account: account.id,
                  retry: retry, now: Int64(time(nil))) { try inspectHistory(account) }
    }

    // The fixed production entry points supply the authority, registered account and clock.
    // These descriptor-based routines also exercise the exact file transaction in private fixtures.
    static func issue(at root: FileHandle, authority: uid_t, owner: uid_t, account: UUID,
                      retry: Bool, now: Int64, checkHistory: () throws -> Void) throws {
        let admin = try handle(openat(root.fileDescriptor, "issue.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600))
        _ = try checked(admin.fileDescriptor, owner: authority, type: S_IFREG, mode: 0o600)
        guard flock(admin.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw FirstEnrollmentError.denied }
        defer { flock(admin.fileDescriptor, LOCK_UN) }
        try checkHistory()
        let previous = try record(root, "current", owner: authority)?.1
        if let previous {
            guard retry else { throw FirstEnrollmentError.reserved }
            guard previous.uid == owner && previous.account == account else { throw FirstEnrollmentError.denied }
            if previous.valid(at: now) {
                guard let slot = try directory(root, previous.directory) else { throw FirstEnrollmentError.denied }
                if try record(slot, "permit", owner: authority) != nil { throw FirstEnrollmentError.active }
            }
        } else if retry { throw FirstEnrollmentError.missing }

        let grant = Grant(uid: owner, account: account, now: now)
        guard mkdirat(root.fileDescriptor, grant.directory, 0o700) == 0,
              let slot = try directory(root, grant.directory) else { throw FirstEnrollmentError.denied }
        // Only the issuing authority can reach this new directory until the permit is complete.
        guard fchmod(slot.fileDescriptor, 0o700) == 0 else { throw FirstEnrollmentError.denied }
        try write(grant, at: slot, name: "permit")
        guard fchown(slot.fileDescriptor, owner, gid_t.max) == 0, fsync(slot.fileDescriptor) == 0
        else { throw FirstEnrollmentError.denied }
        let temporary = "reservation-" + grant.slot.uuidString
        try write(grant, at: root, name: temporary)
        guard renameat(root.fileDescriptor, temporary, root.fileDescriptor, "current") == 0,
              fsync(root.fileDescriptor) == 0 else { throw FirstEnrollmentError.denied }
    }

    static func registeredID(for uid: uid_t) throws -> UUID { try EnrollmentAccount(uid).id }

    static func consume() throws {
        let uid = getuid()
        guard uid != 0, uid == geteuid() else { throw FirstEnrollmentError.denied }
        try consume(at: openRoot(create: false), authority: 0, owner: uid, account: registeredID(for: uid),
                    clock: { Int64(time(nil)) })
    }

    static func consume(at root: FileHandle, authority: uid_t, owner: uid_t, account: UUID,
                        clock: () -> Int64) throws {
        guard let grant = try record(root, "current", owner: authority)?.1 else { throw FirstEnrollmentError.missing }
        guard grant.uid == owner && grant.account == account else { throw FirstEnrollmentError.denied }
        guard grant.valid(at: clock()), let slot = try directory(root, grant.directory)
        else { throw FirstEnrollmentError.spent }
        _ = try checked(slot.fileDescriptor, owner: owner, type: S_IFDIR, mode: 0o700)
        guard let (file, issued) = try record(slot, "permit", owner: authority) else { throw FirstEnrollmentError.spent }
        let fd = file.fileDescriptor
        guard grant == issued, flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw FirstEnrollmentError.denied }
        defer { flock(file.fileDescriptor, LOCK_UN) }
        _ = try checked(fd, owner: authority, type: S_IFREG, mode: 0o444)
        var after = stat()
        guard unlinkat(slot.fileDescriptor, "permit", 0) == 0, fstat(fd, &after) == 0, after.st_nlink == 0,
              fsync(slot.fileDescriptor) == 0, grant.valid(at: clock()),
              try record(root, "current", owner: authority)?.1 == grant else { throw FirstEnrollmentError.spent }
    }
}
