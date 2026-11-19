import CryptoKit
import Foundation

@main
struct ChallengeTests {
    static func main() throws {
        let transfer = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let firstHQ = try FirstHQChallenge.parse(transfer, now: 1000)
        let expected = ["agent-bot-machine-owner/v1", "first-hq-provision", String(repeating: "ab", count: 32),
            "plan-20261119T020000Z-abcd", "2d82ea20059ea1188eeab2ec889bcf4133779f346cfc3881c0663bfd483a710c",
            String(repeating: "f0", count: 32), "1120", ""].joined(separator: "\n")
        precondition(firstHQ.signedBytes == Data(expected.utf8))
        precondition(firstHQ.approvalReason.contains(firstHQ.plan_digest))
        precondition((try? PairingChallenge.parse(transfer, now: 1000)) == nil)
        precondition((try? FirstHQChallenge.parse(transfer, now: 1120)) == nil)
        var envelope = try JSONSerialization.jsonObject(with: transfer) as! [String: Any]
        func parseFirst(_ text: String) throws -> FirstHQChallenge {
            envelope["plan_canonical"] = text
            envelope["plan_digest"] = SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
            return try FirstHQChallenge.parse(JSONSerialization.data(withJSONObject: envelope), now: 1000)
        }
        let original = firstHQ.plan_canonical
        for text in [original + " ", original.replacingOccurrences(of: #""members":[]"#, with: #""members":null"#),
                     original.replacingOccurrences(of: #""version":3"#, with: #""version":3,"version":3"#),
                     original.replacingOccurrences(of: #""action":"create""#, with: #""action":"repair""#)] {
            precondition((try? parseFirst(text)) == nil)
        }
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
        try checkServiceRecovery(firstHQ: firstHQ, publicPoint: publicPoint)
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

    static func checkServiceRecovery(firstHQ: FirstHQChallenge, publicPoint: Data) throws {
        let accountOnly = firstHQ.plan_canonical.replacingOccurrences(of: #""action":"create""#, with: #""action":"none""#)
        let service = #"{"kind":"service","target":"ai.true-line.agent-bot-hq","action":"write","owner":"qa-owner","content":"<plist>\n</plist>","detail":"install QA service"}"#
        let plan = String(accountOnly.dropLast(3)) + "," + service + "]}\n"
        let machine = firstHQ.machine_key, hq = String(repeating: "12", count: 32)
        let owner = publicPoint.base64EncodedString()
        func envelope(_ text: String) -> [String: Any] {
            ["action": "hq-service-recovery", "machine_key": machine, "hq_key": hq, "owner_key": owner,
             "plan_id": firstHQ.plan_id, "plan_digest": SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined(),
             "nonce": firstHQ.nonce, "expires_at": 1120, "plan_canonical": text]
        }
        func parse(_ fields: [String: Any]) throws -> HQServiceRecoveryChallenge {
            try HQServiceRecoveryChallenge.parse(JSONSerialization.data(withJSONObject: fields), now: 1000)
        }
        let fields = envelope(plan)
        let c = try parse(fields)
        let request = OwnerRequest.serviceRecovery(c)
        let expected = ["agent-bot-machine-owner/v1", "hq-service-recovery", machine, hq, owner, c.plan_id, c.plan_digest, c.nonce, "1120", ""]
        precondition(request.signedBytes == Data(expected.joined(separator: "\n").utf8))
        // Independently computed with Node from the same public fixture.
        precondition(c.plan_digest == "083753c8fb803effa153dc8c8829e45ac44ebe31e220cf0afef81fbacdc86014")
        let transcriptHash = SHA256.hash(data: request.signedBytes).map { String(format: "%02x", $0) }.joined()
        precondition(transcriptHash == "c473ea0b8d960a149330ea932925aecaeb5ff712511e53035ac3c34567b77ada")
        for value in [machineFingerprint(machine), machineFingerprint(hq), c.plan_id, c.plan_digest] {
            precondition(request.approvalReason.contains(value))
        }
        try request.checkOwnerKey(publicPoint)
        precondition((try? request.checkOwnerKey(Data(repeating: 0, count: 65))) == nil)
        precondition((try? request.checkExpiry(now: 1120)) == nil)
        _ = try parse(envelope(plan.replacingOccurrences(of: #""action":"write""#, with: #""action":"create""#)))
        for text in [firstHQ.plan_canonical, accountOnly,
                     plan.replacingOccurrences(of: #""action":"none""#, with: #""action":"create""#),
                     plan.replacingOccurrences(of: #""action":"write""#, with: #""action":"remove""#),
                     plan.replacingOccurrences(of: #""members":[]"#, with: #""members":null"#),
                     plan.replacingOccurrences(of: #""members":[]"#, with: #""members":["harness"]"#),
                     plan.replacingOccurrences(of: "ai.true-line.agent-bot-hq", with: "other.service"),
                     plan.replacingOccurrences(of: #""mode":"0700""#, with: #""mode":"0755""#),
                     plan.replacingOccurrences(of: #""version":3"#, with: #""version":3,"version":3"#),
                     plan + " "] {
            precondition((try? parse(envelope(text))) == nil)
        }
        for (key, value) in [("action", "first-hq-provision"), ("machine_key", machine.uppercased()),
                             ("hq_key", ""), ("owner_key", owner + "="),
                             ("owner_key", (Data([4]) + Data(repeating: 0, count: 64)).base64EncodedString()),
                             ("plan_digest", firstHQ.plan_digest), ("unknown", "field")] {
            var invalid = fields
            invalid[key] = value
            precondition((try? parse(invalid)) == nil)
        }
        let raw = try JSONSerialization.data(withJSONObject: fields)
        precondition((try? FirstHQChallenge.parse(raw, now: 1000)) == nil)
        precondition((try? PairingChallenge.parse(raw, now: 1000)) == nil)
        let duplicate = Data(#"{"action":"hq-service-recovery","#.utf8) + raw.dropFirst()
        precondition((try? HQServiceRecoveryChallenge.parse(duplicate, now: 1000)) == nil)
    }
}
