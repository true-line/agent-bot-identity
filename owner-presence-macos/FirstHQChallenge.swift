import CryptoKit
import Foundation

// Each owner operation constructs its own purpose-bound signed bytes.
enum OwnerRequest {
    case pairing(PairingChallenge)
    case firstHQ(FirstHQChallenge)
    case serviceRecovery(HQServiceRecoveryChallenge)

    var signedBytes: Data {
        switch self {
        case .pairing(let challenge): return challenge.signedBytes
        case .firstHQ(let challenge): return challenge.signedBytes
        case .serviceRecovery(let challenge): return challenge.signedBytes
        }
    }

    var approvalReason: String {
        switch self {
        case .pairing(let challenge): return challenge.approvalReason
        case .firstHQ(let challenge): return challenge.approvalReason
        case .serviceRecovery(let challenge): return challenge.approvalReason
        }
    }

    func checkOwnerKey(_ publicPoint: Data) throws {
        if case .serviceRecovery(let challenge) = self,
           publicPoint.base64EncodedString() != challenge.owner_key { throw PresenceFailure.invalidKey }
    }

    func checkExpiry(now: Int64) throws {
        switch self {
        case .pairing(let challenge): try challenge.checkExpiry(now: now)
        case .firstHQ(let challenge): try challenge.checkExpiry(now: now)
        case .serviceRecovery(let challenge): try challenge.checkExpiry(now: now)
        }
    }
}

struct FirstHQChallenge: Decodable {
    let action, machine_key, plan_id, plan_digest, nonce, plan_canonical: String
    let expires_at: Int64
    static let maximumBytes = 64 * 1024

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        let fields: Set<String> = ["action", "machine_key", "plan_id", "plan_digest", "nonce", "expires_at", "plan_canonical"]
        guard bytes.count <= maximumBytes,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(json.keys) == fields else { throw PresenceFailure.invalidChallenge }
        let c = try JSONDecoder().decode(Self.self, from: bytes)
        guard c.action == "first-hq-provision",
              [c.machine_key, c.plan_digest, c.nonce].allSatisfy(isLowerHex32), validMembersPlanID(c.plan_id)
        else { throw PresenceFailure.invalidChallenge }
        try c.checkExpiry(now: now)
        try checkHQPlan(c.plan_canonical, digest: c.plan_digest, purpose: .firstProvision)
        return c
    }

    func checkExpiry(now: Int64) throws {
        try checkPlanExpiry(expires_at, now: now)
    }

    var signedBytes: Data {
        Data("agent-bot-machine-owner/v1\nfirst-hq-provision\n\(machine_key)\n\(plan_id)\n\(plan_digest)\n\(nonce)\n\(expires_at)\n".utf8)
    }

    var approvalReason: String {
        "Provision the first HQ account?\nMachine SHA-256: \(machineFingerprint(machine_key))\nPlan: \(plan_id)\nPlan SHA-256: \(plan_digest)"
    }
}


private enum HQPlanPurpose { case firstProvision, serviceRecovery }

private func checkHQPlan(_ canonicalText: String, digest: String, purpose: HQPlanPurpose) throws {
    let bytes = Data(canonicalText.utf8)
    guard bytes.count <= 48 * 1024, SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest,
          let plan = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          let steps = plan["steps"] as? [[String: String]], (purpose == .firstProvision ? (1...2).contains(steps.count) : steps.count == 2) else { throw PresenceFailure.invalidChallenge }
    let hq = "_agent-bot-hq"
    let account = steps[0]
    guard account["kind"] == "hq-account", account["target"] == hq, account["action"] == (purpose == .firstProvision ? "create" : "none"),
          account["group"] == hq, account["mode"] == "0700" else { throw PresenceFailure.invalidChallenge }
    func canonicalStep(_ step: [String: String], fields: [String]) throws -> String {
        guard Set(step.keys) == Set(fields) else { throw PresenceFailure.invalidChallenge }
        let parts = try fields.map { key -> String in
            guard let value = step[key], !value.isEmpty, value.utf8.allSatisfy({ (32...126).contains($0) || $0 == 9 || $0 == 10 })
            else { throw PresenceFailure.invalidChallenge }
            let encoded = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes])
            return "\"\(key)\":" + String(decoding: encoded, as: UTF8.self)
        }
        return "{" + parts.joined(separator: ",") + "}"
    }
    var parts = [try canonicalStep(account, fields: ["kind", "target", "action", "group", "mode", "detail"])]
    if steps.count == 2 {
        let service = steps[1]
        guard service["kind"] == "service", service["target"] == "ai.true-line.agent-bot-hq",
              ["create", "write"].contains(service["action"]) else { throw PresenceFailure.invalidChallenge }
        parts.append(try canonicalStep(service, fields: ["kind", "target", "action", "owner", "content", "detail"]))
    }
    // Byte equality also rejects duplicate keys, unknown fields, alternate
    // serialization, omitted members and any other plan header.
    let canonical = #"{"version":3,"hq_account":"_agent-bot-hq","dir":"none","members":[],"steps":["# + parts.joined(separator: ",") + "]}\n"
    guard Data(canonical.utf8) == bytes else { throw PresenceFailure.invalidChallenge }
}

struct HQServiceRecoveryChallenge: Decodable {
    let action, machine_key, hq_key, owner_key, plan_id, plan_digest, nonce, plan_canonical: String
    let expires_at: Int64
    static let maximumBytes = FirstHQChallenge.maximumBytes

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        let fields: Set<String> = ["action", "machine_key", "hq_key", "owner_key", "plan_id",
                                   "plan_digest", "nonce", "expires_at", "plan_canonical"]
        guard bytes.count <= maximumBytes,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(json.keys) == fields, memberCount(bytes) == fields.count
        else { throw PresenceFailure.invalidChallenge }
        let c = try JSONDecoder().decode(Self.self, from: bytes)
        guard c.action == "hq-service-recovery",
              [c.machine_key, c.hq_key, c.plan_digest, c.nonce].allSatisfy(isLowerHex32),
              validMembersPlanID(c.plan_id),
              let point = Data(base64Encoded: c.owner_key), point.count == 65, point.first == 4,
              point.base64EncodedString() == c.owner_key,
              (try? P256.Signing.PublicKey(x963Representation: point)) != nil
        else { throw PresenceFailure.invalidChallenge }
        try c.checkExpiry(now: now)
        try checkHQPlan(c.plan_canonical, digest: c.plan_digest, purpose: .serviceRecovery)
        return c
    }

    // Foundation collapses repeated JSON keys. Every value in this validated
    // envelope is scalar, so each colon outside a string denotes one member.
    private static func memberCount(_ bytes: Data) -> Int {
        var quoted = false, escaped = false, count = 0
        for c in bytes {
            if escaped { escaped = false }
            else if quoted && c == 92 { escaped = true }
            else if c == 34 { quoted.toggle() }
            else if !quoted && c == 58 { count += 1 }
        }
        return count
    }

    func checkExpiry(now: Int64) throws { try checkPlanExpiry(expires_at, now: now) }

    var signedBytes: Data {
        Data(["agent-bot-machine-owner/v1", action, machine_key, hq_key, owner_key, plan_id,
              plan_digest, nonce, String(expires_at), ""].joined(separator: "\n").utf8)
    }

    var approvalReason: String {
        "Recover the paired HQ service?\nMachine SHA-256: \(machineFingerprint(machine_key))\nHQ SHA-256: \(machineFingerprint(hq_key))\nPlan: \(plan_id)\nPlan SHA-256: \(plan_digest)"
    }
}

private func isLowerHex32(_ text: String) -> Bool {
    text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

private func validMembersPlanID(_ id: String) -> Bool {
    id.utf8.count == 26 && id.range(of: #"^plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$"#, options: .regularExpression) != nil
}

private func checkPlanExpiry(_ expires: Int64, now: Int64) throws {
    guard now >= 0, expires > now, expires - now <= 120 else { throw PresenceFailure.expired }
}
