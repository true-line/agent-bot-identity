import CryptoKit
import Darwin
import Foundation

@main
struct OwnerPresenceMain {
    static func main() async {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            guard args == ["public-key"] || args == ["approve-pairing"] || args == ["approve-first-hq"] else {
                throw PresenceFailure.invalidChallenge
            }
            let store = try OwnerKey(group: verifiedAccessGroup())
            guard SecureEnclave.isAvailable else { throw PresenceFailure.unavailable }
            let output: [String: String]
            if args == ["public-key"] {
                output = ["public_key": try store.publicKey().base64EncodedString()]
            } else {
                let firstHQ = args == ["approve-first-hq"]
                let limit = firstHQ ? FirstHQChallenge.maximumBytes : PairingChallenge.maximumBytes
                var bytes = Data()
                while let part = try FileHandle.standardInput.read(upToCount: limit + 1 - bytes.count),
                      !part.isEmpty {
                    bytes.append(part)
                    guard bytes.count <= limit else { throw PresenceFailure.invalidChallenge }
                }
                let now = Int64(Date().timeIntervalSince1970)
                let challenge: OwnerRequest = firstHQ
                    ? .firstHQ(try FirstHQChallenge.parse(bytes, now: now))
                    : .pairing(try PairingChallenge.parse(bytes, now: now))
                output = try await store.approve(challenge)
            }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: output))
        } catch {
            FileHandle.standardError.write(Data("Owner approval: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
