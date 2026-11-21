import CryptoKit
import Darwin
import Foundation
import OpenDirectory

// Machine publishes its raw Ed25519 key beside the shared socket. Only the
// two installed Homebrew locations are eligible; neither a transfer nor the
// invoking account can choose the trusted directory.
enum HarnessMachinePin {
    enum Failure: Error {
        case unavailable, prefixWriteGroup, varWriteGroup

        var diagnostic: String? {
            let location: String
            switch self {
            case .unavailable: return nil
            case .prefixWriteGroup: location = "prefix"
            case .varWriteGroup: location = "var directory"
            }
            return "Machine owner approval unavailable. The group-writable Homebrew \(location) must belong to the admin group. Ask the Homebrew administrator to review its group or write permissions."
        }
    }
    private static let flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    private static func file(_ fd: Int32) throws -> FileHandle {
        guard fd >= 0 else { throw Failure.unavailable }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }
    static func installedPublicKey() throws -> Data {
        guard getuid() != 0, getuid() == geteuid() else { throw Failure.unavailable }
        let root = try file(open("/", flags | O_DIRECTORY))
        return try publishedKey(root: root, check: checkComponent)
    }

    static func fingerprint(_ published: Data) -> String {
        SHA256.hash(data: published).map { String(format: "%02x", $0) }.joined()
    }

    static func verify(_ hex: String) throws {
        try verify(hex, published: installedPublicKey())
    }

    static func verify(_ hex: String, published: Data) throws {
        guard published.count == 32, hex == published.map({ String(format: "%02x", $0) }).joined()
        else { throw Failure.unavailable }
    }

    enum Component { case systemDirectory, prefix, variable, channel, key }
    typealias Check = (FileHandle, stat, Component, uid_t) throws -> Void

    static func publishedKey(root: FileHandle, check: Check) throws -> Data {
        var published: Data?
        for prefix in [["opt", "homebrew"], ["usr", "local"]] {
            var chain = [root]
            let names = prefix + ["var", "agent-machine"]
            for name in names {
                let fd = openat(chain.last!.fileDescriptor, name, flags | O_DIRECTORY)
                if fd < 0 && errno == ENOENT { break }
                chain.append(try file(fd))
            }
            if chain.count != names.count + 1 { continue }
            var metadata = try chain.map { h -> stat in
                var s = stat()
                guard fstat(h.fileDescriptor, &s) == 0 else { throw Failure.unavailable }
                return s
            }
            let types: [Component] = [.systemDirectory, .systemDirectory, .prefix, .variable, .channel]
            let owner = metadata[2].st_uid
            for i in chain.indices { try check(chain[i], metadata[i], types[i], owner) }
            let parent = chain.last!.fileDescriptor
            var link = stat()
            guard published == nil, fstatat(parent, "daemon.pub", &link, AT_SYMLINK_NOFOLLOW) == 0,
                  link.st_mode & S_IFMT == S_IFREG else { throw Failure.unavailable }
            let leaf = try file(openat(parent, "daemon.pub", flags))
            var keyStat = stat()
            guard fstat(leaf.fileDescriptor, &keyStat) == 0, keyStat.st_ino == link.st_ino,
                  keyStat.st_dev == link.st_dev else { throw Failure.unavailable }
            try check(leaf, keyStat, .key, owner)
            metadata.append(keyStat)
            guard keyStat.st_size == 32,
                  let bytes = try leaf.read(upToCount: 33), bytes.count == 32 else { throw Failure.unavailable }
            for (i, name) in (names + ["daemon.pub"]).enumerated() {
                var linked = stat()
                guard fstatat(chain[i].fileDescriptor, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
                      linked.st_dev == metadata[i+1].st_dev, linked.st_ino == metadata[i+1].st_ino else { throw Failure.unavailable }
            }
            published = bytes
        }
        guard let published else { throw Failure.unavailable }
        return published
    }

    static func checkMetadata(_ s: stat, _ type: Component, owner: uid_t, caller: uid_t, callerCanWrite: Bool) throws {
        guard owner >= 501, owner != caller, !callerCanWrite,
              s.st_mode & S_IFMT == (type == .key ? S_IFREG : S_IFDIR),
              s.st_mode & 0o7002 == 0 else { throw Failure.unavailable }
        let valid: Bool
        switch type {
        case .systemDirectory: valid = s.st_uid == 0 && s.st_mode & 0o020 == 0
        case .prefix, .variable:
            guard s.st_uid == owner else { throw Failure.unavailable }
            if s.st_mode & 0o020 != 0 && s.st_gid != 80 {
                throw type == .prefix ? Failure.prefixWriteGroup : Failure.varWriteGroup
            }
            return
        case .channel: valid = s.st_uid == owner && s.st_mode & 0o7777 == 0o755
        case .key: valid = s.st_uid == owner && s.st_mode & 0o7777 == 0o644 && s.st_nlink == 1 && s.st_size == 32
        }
        guard valid else { throw Failure.unavailable }
    }

    private static func checkComponent(_ handle: FileHandle, _ s: stat, _ type: Component, _ owner: uid_t) throws {
        // The leaf mode allows only its verified owner to write. For directories
        // check the caller's actual access, including supplementary groups.
        let fd = handle.fileDescriptor
        var writable = false
        if type != .key {
            writable = faccessat(fd, ".", W_OK, 0) == 0
            guard writable || errno == EACCES || errno == EROFS || errno == EPERM else { throw Failure.unavailable }
        }
        try checkMetadata(s, type, owner: owner, caller: getuid(), callerCanWrite: writable)
        if type == .prefix {
            let node = try ODNode(session: .default(), type: UInt32(kODNodeTypeLocalNodes))
            let attribute = kODAttributeTypeUniqueID
            let query = try ODQuery(node: node, forRecordTypes: kODRecordTypeUsers, attribute: attribute,
                                    matchType: UInt32(kODMatchEqualTo), queryValues: String(owner),
                                    returnAttributes: [attribute], maximumResults: 2)
            guard let records = try query.resultsAllowingPartial(false) as? [ODRecord], records.count == 1 else { throw Failure.unavailable }
            let admin = try node.record(withRecordType: kODRecordTypeGroups, name: "admin", attributes: nil)
            try admin.isMemberRecord(records[0])
        }
        if let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            var cursor = ACL_FIRST_ENTRY
            while acl_get_entry(acl, cursor.rawValue, &entry) == 0 {
                var tag = ACL_UNDEFINED_TAG
                guard acl_get_tag_type(entry, &tag) == 0 && tag == ACL_EXTENDED_DENY else { throw Failure.unavailable }
                cursor = ACL_NEXT_ENTRY
            }
            guard errno == EINVAL else { throw Failure.unavailable }
        } else if errno != ENOENT { throw Failure.unavailable }
    }
}
