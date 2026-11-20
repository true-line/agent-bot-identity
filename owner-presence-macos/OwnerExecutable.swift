import CryptoKit
import Darwin
import Foundation
import Security

enum OwnerExecutableError: Error { case unverified }

enum OwnerExecutable {
    static let identifier = "ai.true-line.agent-bot-owner-presence"
    static let directory = "/Library/PrivilegedHelperTools"
    static let path = directory + "/" + identifier

    // The installer pins the organization's exact Developer ID team outside
    // the daily account. A source checkout, HOME or PATH cannot supply it.
    static func verify(administrator: Bool = false) throws {
        guard (getuid() == 0) == administrator, getuid() == geteuid() else { throw OwnerExecutableError.unverified }
        let running = try runningAtInstallPath()
        var directoryFD = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY)
        guard directoryFD >= 0 else { throw OwnerExecutableError.unverified }
        defer { close(directoryFD) }
        try protectedMetadata(directoryFD, directory: true)
        for part in ["Library", "PrivilegedHelperTools"] {
            let fd = openat(directoryFD, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
            guard fd >= 0 else { throw OwnerExecutableError.unverified }
            close(directoryFD)
            directoryFD = fd
            try protectedMetadata(fd, directory: true)
        }
        func openFile(_ name: String, mode: mode_t) throws -> FileHandle {
            let fd = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard fd >= 0 else { throw OwnerExecutableError.unverified }
            let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try protectedMetadata(fd, directory: false, mode: mode)
            return file
        }
        let executable = try openFile(identifier, mode: 0o555)
        let pin = try openFile(identifier + ".publisher", mode: 0o444)
        var meta = stat()
        guard fstat(pin.fileDescriptor, &meta) == 0, meta.st_size == 76,
              let data = try pin.read(upToCount: 77), data.count == 76,
              data[10] == 10, data.last == 10 else { throw OwnerExecutableError.unverified }
        let team = data.prefix(10)
        let expected = data.dropFirst(11).dropLast()
        guard team.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              expected.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              fstat(executable.fileDescriptor, &meta) == 0, (1...32*1024*1024).contains(meta.st_size)
        else { throw OwnerExecutableError.unverified }
        var hash = SHA256()
        var total = 0
        while let part = try executable.read(upToCount: 64 * 1024), !part.isEmpty {
            total += part.count
            guard total <= meta.st_size else { throw OwnerExecutableError.unverified }
            hash.update(data: part)
        }
        let actual = hash.finalize().map { String(format: "%02x", $0) }.joined()
        guard total == meta.st_size, actual == String(decoding: expected, as: UTF8.self)
        else { throw OwnerExecutableError.unverified }
        try verifyCode(running, team: String(decoding: team, as: UTF8.self))
        var linked = stat()
        guard fstatat(directoryFD, identifier, &linked, AT_SYMLINK_NOFOLLOW) == 0,
              linked.st_dev == meta.st_dev, linked.st_ino == meta.st_ino
        else { throw OwnerExecutableError.unverified }
    }

    static func protectedMetadata(_ fd: Int32, directory: Bool, mode: mode_t? = nil) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == 0, info.st_gid == 0,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o6022 == 0, directory || info.st_nlink == 1,
              mode.map({ info.st_mode & 0o7777 == $0 }) ?? true
        else { throw OwnerExecutableError.unverified }
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            guard errno == ENOENT else { throw OwnerExecutableError.unverified }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL
        else { throw OwnerExecutableError.unverified }
    }

    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw OwnerExecutableError.unverified }
    }

    private static func runningAtInstallPath() throws -> SecCode {
        var running: SecCode?
        try check(SecCodeCopySelf([], &running))
        guard let running else { throw OwnerExecutableError.unverified }
        var processCode: SecStaticCode?
        try check(SecCodeCopyStaticCode(running, [], &processCode))
        guard let processCode else { throw OwnerExecutableError.unverified }
        var url: CFURL?
        try check(SecCodeCopyPath(processCode, [], &url))
        guard let url, (url as URL).path == path else { throw OwnerExecutableError.unverified }
        return running
    }

    private static func verifyCode(_ running: SecCode, team: String) throws {
        func requirement(_ text: String) throws -> SecRequirement {
            var r: SecRequirement?
            try check(SecRequirementCreateWithString(text as CFString, [], &r))
            guard let r else { throw OwnerExecutableError.unverified }
            return r
        }
        let req = try requirement("anchor apple generic and identifier \"\(identifier)\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(team)\"")
        try check(SecCodeCheckValidity(running, [], req))
        var disk: SecStaticCode?
        try check(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &disk))
        guard let disk else { throw OwnerExecutableError.unverified }
        try check(SecStaticCodeCheckValidity(disk, SecCSFlags(rawValue: kSecCSStrictValidate), req))
        var info: CFDictionary?
        try check(SecCodeCopySigningInformation(disk, [], &info))
        guard let hash = (info as NSDictionary?)?[kSecCodeInfoUnique] as? Data, hash.count == 20
        else { throw OwnerExecutableError.unverified }
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        try check(SecCodeCheckValidity(running, [], try requirement("cdhash H\"" + hex + "\"")))
    }
}
