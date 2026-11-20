import Darwin
import Foundation

// Compiled only by the hosted scratch fixture. The installed CLI has no path,
// clock or account-record overrides. No login Keychain or signing is used here.
@main struct FirstEnrollmentAccountTests {
    enum Failure: Error { case expectation }

    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 4, let target = uid_t(args[3]), target >= 501,
              args[2].hasPrefix("/private/tmp/owner-enrollment-ci."), !args[2].dropFirst(13).contains("/")
        else { throw Failure.expectation }
        let fd = open(args[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        var authority = stat()
        guard fd >= 0, fstat(fd, &authority) == 0, authority.st_uid == 0,
              authority.st_mode & 0o777 == 0o755 else { throw Failure.expectation }
        let fixture = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        let account = try OwnerFirstEnrollment.registeredID(for: target)
        let now = { Int64(time(nil)) }
        switch args[1] {
        case "issue", "retry":
            guard getuid() == 0, geteuid() == 0 else { throw Failure.expectation }
            try OwnerFirstEnrollment.issue(at: fixture, authority: 0, owner: target, account: account,
                                           retry: args[1] == "retry", now: now()) {
                try OwnerFirstEnrollment.checkMachineState(fixture)
            }
        case "use", "used":
            guard getuid() == target, geteuid() == target else { throw Failure.expectation }
            do {
                try OwnerFirstEnrollment.consume(at: fixture, authority: 0, owner: target, account: account, clock: now)
                guard args[1] == "use" else { throw Failure.expectation }
            } catch FirstEnrollmentError.spent {
                guard args[1] == "used" else { throw Failure.expectation }
            }
        default:
            throw Failure.expectation
        }
    }
}
