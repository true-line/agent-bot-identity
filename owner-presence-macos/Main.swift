import CryptoKit
import Darwin
import Foundation

@main
struct OwnerPresenceMain {
    static func main() async {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            guard args == ["public-key"] || args == ["approve-pairing"] else {
                throw PresenceFailure.invalidChallenge
            }
            let store = try OwnerKey(group: verifiedAccessGroup())
            guard SecureEnclave.isAvailable else { throw PresenceFailure.unavailable }
            let output: [String: String]
            if args == ["public-key"] {
                output = ["public_key": try store.publicKey().base64EncodedString()]
            } else {
                var bytes = Data()
                while let part = try FileHandle.standardInput.read(upToCount: PairingChallenge.maximumBytes + 1 - bytes.count),
                      !part.isEmpty {
                    bytes.append(part)
                    guard bytes.count <= PairingChallenge.maximumBytes else { throw PresenceFailure.invalidChallenge }
                }
                let challenge = try PairingChallenge.parse(bytes, now: Int64(Date().timeIntervalSince1970))
                output = try await store.approve(challenge)
            }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: output))
        } catch {
            FileHandle.standardError.write(Data("Owner approval: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
