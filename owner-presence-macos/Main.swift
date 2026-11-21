import Darwin
import Foundation

@main
enum OwnerPresenceMain {
    static func readInput(limit: Int) throws -> Data {
        var bytes = Data()
        while let part = try FileHandle.standardInput.read(upToCount: limit + 1 - bytes.count), !part.isEmpty {
            bytes.append(part)
            guard bytes.count <= limit else { throw PresenceFailure.invalidChallenge }
        }
        return bytes
    }

    static func readRequest(_ command: String) throws -> OwnerRequest {
        let limit: Int
        switch command {
        case "approve-pairing": limit = PairingChallenge.maximumBytes
        case "approve-first-hq": limit = FirstHQChallenge.maximumBytes
        case "approve-harness-launch-install", "approve-harness-launch-retire", "approve-harness-account-provision", "approve-hq-service-recovery": limit = HarnessLaunchChallenge.maximumBytes
        default: throw PresenceFailure.invalidChallenge
        }
        let bytes = try readInput(limit: limit)
        let now = Int64(Date().timeIntervalSince1970)
        do {
            switch command {
            case "approve-pairing": return .pairing(try PairingChallenge.parse(bytes, now: now))
            case "approve-first-hq": return .firstHQ(try FirstHQChallenge.parse(bytes, now: now))
            case "approve-harness-launch-install": return .harnessLaunch(try HarnessLaunchChallenge.parse(bytes, action: .install, now: now))
            case "approve-harness-launch-retire": return .harnessLaunch(try HarnessLaunchChallenge.parse(bytes, action: .retire, now: now))
            case "approve-hq-service-recovery": return .harnessLaunch(try HarnessLaunchChallenge.parse(bytes, action: .serviceRecovery, now: now))
            case "approve-harness-account-provision": return .harnessLaunch(try HarnessLaunchChallenge.parse(bytes, action: .provision, now: now))
            default: throw PresenceFailure.invalidChallenge
            }
        } catch let refusal as PresenceFailure {
            throw refusal
        } catch {
            throw PresenceFailure.invalidChallenge
        }
    }

    static func run(_ args: [String]) async throws {
        if args == ["check-machine-pin"] {
            try OwnerExecutable.verify()
            let key = try HarnessMachinePin.installedPublicKey()
            let fingerprint = HarnessMachinePin.fingerprint(key)
            try FileHandle.standardOutput.write(contentsOf: Data((fingerprint + "\n").utf8))
            return
        }
        if args.first == "preview-harness-launch" {
            guard args.count == 4, let action = HarnessLaunchAction(rawValue: args[1]) else { throw PresenceFailure.invalidChallenge }
            let data = try readInput(limit: 32 * 1024)
            guard let plan = String(data: data, encoding: .utf8), Data(plan.utf8) == data else { throw PresenceFailure.invalidChallenge }
            let preview: String
            do { preview = try renderHarnessReview(plan, planID: args[2], digest: args[3], action: action) }
            catch { throw PresenceFailure.invalidChallenge }
            try FileHandle.standardOutput.write(contentsOf: Data((preview + "\n").utf8))
            return
        }
        if args.first == "preview-harness-qualification" {
            guard args.count == 3 else { throw PresenceFailure.invalidChallenge }
            let data = try readInput(limit: maximumQualificationPlanBytes)
            let preview: String
            do { preview = try reviewHarnessQualification(data, planID: args[1], digest: args[2]) }
            catch { throw PresenceFailure.invalidChallenge }
            try FileHandle.standardOutput.write(contentsOf: Data((preview + "\n").utf8))
            return
        }
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
        guard args.count == 1 else { throw PresenceFailure.invalidChallenge }
        let request: OwnerRequest?
        switch args[0] {
        case "init-owner-key", "owner-public-key": request = nil
        default: request = try readRequest(args[0])
        }
        let verify = { try OwnerExecutable.verify() }
        if case .harnessLaunch(let challenge) = request {
            try verify()
            try HarnessMachinePin.verify(challenge.machine_key)
        }
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

    @MainActor static func main() {
        runOwnerCommand { await commandStatus() }
    }

    private static func commandStatus() async -> Int32 {
        do {
            try await run(Array(CommandLine.arguments.dropFirst()))
            return EXIT_SUCCESS
        } catch {
            // Native errors may include account, Keychain or signing metadata.
            // Expose only our own fixed, public diagnostics.
            let message = (error as? PresenceFailure)?.errorDescription
                ?? (error as? FreshOwnerFailure)?.errorDescription
                ?? (error as? FirstEnrollmentError)?.description
                ?? (error as? HarnessMachinePin.Failure)?.diagnostic
                ?? "Machine owner operation unavailable."
            FileHandle.standardError.write(Data((message + "\n").utf8))
            // EX_UNAVAILABLE distinguishes an unusable provider or credential
            // from a rejected challenge or an owner's decision.
            return error is PresenceFailure ? 1 : EX_UNAVAILABLE
        }
    }
}
