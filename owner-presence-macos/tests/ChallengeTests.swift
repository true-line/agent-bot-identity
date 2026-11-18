import CryptoKit
import Foundation

@main
struct ChallengeTests {
    static func main() throws {
        let machine = String(repeating: "ab", count: 32)
        let hq = String(repeating: "12", count: 32)
        let nonce = String(repeating: "f0", count: 32)
        let fields: [String: Any] = ["action": "machine-pair", "machine_key": machine,
            "hq_key": hq, "nonce": nonce, "expires_at": 1120]
        func parse(_ fields: [String: Any], now: Int64 = 1000) throws -> PairingChallenge {
            try PairingChallenge.parse(JSONSerialization.data(withJSONObject: fields), now: now)
        }
        let challenge = try parse(fields)
        precondition(challenge.signedBytes == Data("agent-bot-machine-owner/v1\nmachine-pair\n\(machine)\n\(hq)\n\(nonce)\n1120\n".utf8))
        // Node's independent P-256 vector is also verified by Machine's Go enrollment test.
        let publicPoint = Data(base64Encoded: "BDjokZqqPh39fjipw1EC8xKwi2eosj6MFX94A/HdkRdd2T+vOg0UHeB+zx+8J+4aaQx1Xc/Eyc9n5sv8v4DkpXs=")!
        let der = Data(base64Encoded: "MEUCIQCgF9p55vCHM/OCmK8eNuA+0qKayEt2UTewnTV/xmoq3AIgRWwv4nM/Ae+pfNtz2shgRQtSGnt1liS+tHmIJYMJPn0=")!
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicPoint)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
        precondition(publicKey.isValidSignature(signature, for: challenge.signedBytes))
        let machineHash = SHA256.hash(data: Data(repeating: 0xab, count: 32)).map { String(format: "%02x", $0) }.joined()
        let hqHash = SHA256.hash(data: Data(repeating: 0x12, count: 32)).map { String(format: "%02x", $0) }.joined()
        precondition(challenge.approvalReason.contains(machineHash) && challenge.approvalReason.contains(hqHash))
        let invalidValues: [(String, Any)] = [
            ("action", "machine-unpair"), ("machine_key", machine.uppercased()), ("hq_key", "AA"),
            ("nonce", nonce + "\n"), ("expires_at", 1000), ("expires_at", 1121), ("expires_at", true),
            ("unsigned_text", "different action")
        ]
        for (key, value) in invalidValues {
            var invalid = fields
            invalid[key] = value
            precondition((try? parse(invalid)) == nil)
        }
        var missing = fields
        missing.removeValue(forKey: "machine_key")
        precondition((try? parse(missing)) == nil)
        precondition((try? challenge.checkExpiry(now: 1120)) == nil)
    }
}
