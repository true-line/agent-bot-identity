import Darwin
import Foundation

@main
enum OwnerPresenceMain {
    static func readRequest(firstHQ: Bool) throws -> OwnerRequest {
        let limit = firstHQ ? FirstHQChallenge.maximumBytes : PairingChallenge.maximumBytes
        var bytes = Data()
        while let part = try FileHandle.standardInput.read(upToCount: limit + 1 - bytes.count), !part.isEmpty {
            bytes.append(part)
            guard bytes.count <= limit else { throw PresenceFailure.invalidChallenge }
        }
        let now = Int64(Date().timeIntervalSince1970)
        do {
            return firstHQ ? .firstHQ(try FirstHQChallenge.parse(bytes, now: now))
                           : .pairing(try PairingChallenge.parse(bytes, now: now))
        } catch let refusal as PresenceFailure {
            throw refusal
        } catch {
            throw PresenceFailure.invalidChallenge
        }
    }

    static func run(_ args: [String]) async throws {
        if args.first == "authorize-first-enrollment" || args.first == "retry-first-enrollment" {
            guard args.count == 3, args[2] == "--no-prior-enrollment",
                  let uid = uid_t(args[1]), uid > 0, String(uid) == args[1]
            else { throw PresenceFailure.invalidChallenge }
            try OwnerExecutable.verify(administrator: true)
            if args[0] == "retry-first-enrollment" {
                try OwnerFirstEnrollment.retry(ownerUID: uid)
            } else {
                try OwnerFirstEnrollment.authorize(ownerUID: uid)
            }
            return
        }
        guard args.count == 1, ["init-owner-key", "owner-public-key", "approve-pairing", "approve-first-hq"].contains(args[0])
        else { throw PresenceFailure.invalidChallenge }
        let request: OwnerRequest?
        switch args[0] {
        case "approve-pairing": request = try readRequest(firstHQ: false)
        case "approve-first-hq": request = try readRequest(firstHQ: true)
        default: request = nil
        }
        let verify = { try OwnerExecutable.verify() }
        let store = try FreshOwnerStore.open(verifyExecutable: verify)
        let result: [String: String]
        switch args[0] {
        case "init-owner-key":
            result = ["public_key": try store.initializePublicKey(authorizeFresh: OwnerFirstEnrollment.consume).base64EncodedString()]
        case "owner-public-key":
            result = ["public_key": try store.existingPublicKey().base64EncodedString()]
        default:
            guard let request else { throw PresenceFailure.invalidChallenge }
            result = try await store.approve(request)
            try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        }
        try verify()
        var data = try JSONSerialization.data(withJSONObject: result)
        data.append(0x0a)
        try FileHandle.standardOutput.write(contentsOf: data)
    }

    static func main() async {
        do { try await run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            // Native errors may include account, Keychain or signing metadata.
            // Expose only our own fixed, public diagnostics.
            let message = (error as? PresenceFailure)?.errorDescription
                ?? (error as? FreshOwnerFailure)?.errorDescription
                ?? (error as? FirstEnrollmentError)?.description
                ?? "Machine owner operation unavailable."
            FileHandle.standardError.write(Data((message + "\n").utf8))
            // EX_UNAVAILABLE distinguishes an unusable provider or credential
            // from a rejected challenge or an owner's decision.
            exit(error is PresenceFailure ? 1 : EX_UNAVAILABLE)
        }
    }
}
