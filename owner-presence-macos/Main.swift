import CryptoKit
import Darwin
import Foundation

@main
struct OwnerPresenceMain {
    static func main() async {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            guard args == ["public-key"] || args == ["approve-pairing"] || args == ["approve-first-hq"] || args == ["approve-hq-service-recovery"] else {
                throw PresenceFailure.invalidChallenge
            }
            let store = try OwnerKey(group: verifiedAccessGroup())
            guard SecureEnclave.isAvailable else { throw PresenceFailure.unavailable }
            let output: [String: String]
            if args == ["public-key"] {
                output = ["public_key": try store.publicKey().base64EncodedString()]
            } else {
                let limit = args == ["approve-pairing"] ? PairingChallenge.maximumBytes : FirstHQChallenge.maximumBytes
                var bytes = Data()
                while let part = try FileHandle.standardInput.read(upToCount: limit + 1 - bytes.count),
                      !part.isEmpty {
                    bytes.append(part)
                    guard bytes.count <= limit else { throw PresenceFailure.invalidChallenge }
                }
                let now = Int64(Date().timeIntervalSince1970)
                let challenge: OwnerRequest
                switch args[0] {
                case "approve-pairing": challenge = .pairing(try PairingChallenge.parse(bytes, now: now))
                case "approve-first-hq": challenge = .firstHQ(try FirstHQChallenge.parse(bytes, now: now))
                case "approve-hq-service-recovery": challenge = .serviceRecovery(try HQServiceRecoveryChallenge.parse(bytes, now: now))
                default: throw PresenceFailure.invalidChallenge
                }
                output = try await store.approve(challenge)
            }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: output))
        } catch {
            FileHandle.standardError.write(Data("Owner approval: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
