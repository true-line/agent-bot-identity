import CryptoKit
import Foundation

// Each admitted owner operation constructs its own purpose-bound signed bytes.
enum OwnerRequest {
    case pairing(PairingChallenge)
    case firstHQ(FirstHQChallenge)
    case harnessLaunch(HarnessLaunchChallenge)
    case guestHarness(GuestHarnessReview)

    var signedBytes: Data {
        switch self {
        case .pairing(let challenge): return challenge.signedBytes
        case .firstHQ(let challenge): return challenge.signedBytes
        case .harnessLaunch(let challenge): return challenge.signedBytes
        case .guestHarness(let review): return review.challenge.signedBytes
        }
    }

    var approvalReason: String {
        switch self {
        case .pairing(let challenge): return challenge.approvalReason
        case .firstHQ(let challenge): return challenge.approvalReason
        case .harnessLaunch(let c):
            let operation = PairedHarnessPurpose(rawValue: c.action)?.confirmationPrompt ?? "Review the signed harness plan?"
            return "\(operation)\nMachine SHA-256: \(machineFingerprint(c.machine_key))\nPlan: \(c.plan_id)\nPlan SHA-256: \(c.plan_digest)"
        case .guestHarness(let review):
            let c = review.challenge
            let p = review.permit
            let operation = PairedHarnessPurpose(rawValue: c.action)?.confirmationPrompt ?? "Review the guest plan?"
            return "\(operation)\nPhysical Machine SHA-256: \(machineFingerprint(p.host_machine_key))\nGuest Machine SHA-256: \(machineFingerprint(c.machine_key))\nVM: \(p.guest_vm_name)\nPlan: \(c.plan_id)\nPlan SHA-256: \(c.plan_digest)"
        }
    }

    func checkExpiry(now: Int64) throws {
        switch self {
        case .pairing(let challenge): try challenge.checkExpiry(now: now)
        case .firstHQ(let challenge): try challenge.checkExpiry(now: now)
        case .harnessLaunch(let challenge): try challenge.checkExpiry(now: now)
        case .guestHarness(let review): try review.checkExpiry(now: now)
        }
    }

    func verifyMachinePin() throws {
        switch self {
        case .harnessLaunch(let challenge): try HarnessMachinePin.verify(challenge.machine_key)
        case .guestHarness(let review): try HarnessMachinePin.verify(review.permit.host_machine_key)
        default: break
        }
    }
}

struct FirstHQChallenge: Decodable {
    let action, machine_key, plan_id, plan_digest, nonce, plan_canonical: String
    let expires_at: Int64
    private enum ServiceAction: String { case create, write }
    private var serviceAction: ServiceAction?
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case action, machine_key, plan_id, plan_digest, nonce, plan_canonical, expires_at
    }
    static let maximumBytes = 64 * 1024

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        let fields = Set(CodingKeys.allCases.map(\.stringValue))
        guard bytes.count <= maximumBytes,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(json.keys) == fields else { throw PresenceFailure.invalidChallenge }
        var c = try JSONDecoder().decode(Self.self, from: bytes)
        guard c.action == "first-hq-provision",
              [c.machine_key, c.plan_digest, c.nonce].allSatisfy({ $0.utf8.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }),
              c.plan_id.utf8.count == 26, c.plan_id.range(of: #"^plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$"#, options: .regularExpression) != nil
        else { throw PresenceFailure.invalidChallenge }
        try c.checkExpiry(now: now)
        c.serviceAction = try c.checkPlan()
        return c
    }

    func checkExpiry(now: Int64) throws {
        guard now >= 0, expires_at > now, expires_at - now <= 120 else { throw PresenceFailure.expired }
    }

    private func checkPlan() throws -> ServiceAction? {
        let bytes = Data(plan_canonical.utf8)
        guard bytes.count <= 48 * 1024, SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == plan_digest,
              let plan = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let steps = plan["steps"] as? [[String: String]], (1...2).contains(steps.count) else { throw PresenceFailure.invalidChallenge }
        let hq = "_agent-bot-hq"
        let account = steps[0]
        guard account["kind"] == "hq-account", account["target"] == hq, account["action"] == "create",
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
        var serviceAction: ServiceAction?
        if steps.count == 2 {
            let service = steps[1]
            guard service["kind"] == "service", service["target"] == "ai.true-line.agent-bot-hq",
                  let action = service["action"].flatMap(ServiceAction.init(rawValue:)) else { throw PresenceFailure.invalidChallenge }
            serviceAction = action
            parts.append(try canonicalStep(service, fields: ["kind", "target", "action", "owner", "content", "detail"]))
        }
        // Byte equality also rejects duplicate keys, unknown fields, alternate
        // serialization, omitted members and any non-bootstrap header.
        let canonical = #"{"version":3,"hq_account":"_agent-bot-hq","dir":"none","members":[],"steps":["# + parts.joined(separator: ",") + "]}\n"
        guard Data(canonical.utf8) == bytes else { throw PresenceFailure.invalidChallenge }
        return serviceAction
    }

    var signedBytes: Data {
        Data("agent-bot-machine-owner/v1\nfirst-hq-provision\n\(machine_key)\n\(plan_id)\n\(plan_digest)\n\(nonce)\n\(expires_at)\n".utf8)
    }

    var approvalReason: String {
        let prompt: String
        switch serviceAction {
        case .create: prompt = "Create the first HQ account and install the HQ LaunchDaemon?"
        case .write: prompt = "Create the first HQ account and update the HQ LaunchDaemon?"
        case nil: prompt = "Provision the first HQ account?"
        }
        return "\(prompt)\nMachine SHA-256: \(machineFingerprint(machine_key))\nPlan: \(plan_id)\nPlan SHA-256: \(plan_digest)"
    }
}
