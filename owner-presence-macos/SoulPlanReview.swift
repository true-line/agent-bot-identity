import CryptoKit
import Foundation

// Machine signs the exact canonical plan, not a rendered approximation. Show
// every byte of the reviewed plan for the two launch installs, whose nested
// component inventories are intentionally too large for a shortened summary.
func reviewSoulPlan(_ source: String, planID: String, digest: String, purpose: PairedHarnessPurpose) throws -> String {
    let invalid = PresenceFailure.invalidChallenge
    let bytes = Data(source.utf8)
    guard bytes.count <= 64 * 1024, source.hasSuffix("\n"),
          matchesHarnessField(planID, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"),
          SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest,
          let plan = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          let version = plan["version"] as? Int, version == 3,
          let hq = plan["hq_account"] as? String, hq == "_agent-bot-hq",
          let dir = plan["dir"] as? String,
          let namedPurpose = plan["purpose"] as? String, namedPurpose == purpose.rawValue,
          let members = plan["members"] as? [String], !members.isEmpty,
          members == Array(Set(members)).sorted(),
          let steps = plan["steps"] as? [[String: Any]], !steps.isEmpty
    else { throw invalid }

    let role: String
    let payload: String
    switch purpose {
    case .soulRunner, .soulBridge:
        role = purpose == .soulRunner ? "runner" : "bridge"
        payload = purpose == .soulRunner ? "soul_runners" : "soul_bridges"
        guard dir == "none",
              Set(plan.keys) == ["version", "hq_account", "dir", "members", "steps", "purpose", payload],
              let roles = plan[payload] as? [[String: Any]], roles.count == members.count,
              roles.allSatisfy({ entry in
                  guard Set(entry.keys) == ["soul_id", "installation_id", "account"],
                        let soul = entry["soul_id"] as? String,
                        let installation = entry["installation_id"] as? String,
                        let account = entry["account"] as? String,
                        matchesHarnessField(soul, "agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
                        matchesHarnessField(installation, "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                  else { return false }
                  let domain = purpose == .soulRunner ? installation : "agent-bot-soul-bridge/v1\0" + installation
                  let suffix = SHA256.hash(data: Data(domain.utf8)).prefix(10).map { String(format: "%02x", $0) }.joined()
                  return account == (purpose == .soulRunner ? "_abm-sr-" : "_abm-br-") + suffix
              }),
              Set(roles.compactMap({ $0["account"] as? String })) == Set(members),
              steps.count == members.count + 1 + (purpose == .soulBridge ? 4 + 4 * members.count : 0),
              steps[0]["kind"] as? String == "hq-account",
              steps[0]["target"] as? String == hq,
              steps[0]["action"] as? String == "none"
        else { throw invalid }
        for (name, step) in zip(members, steps.dropFirst()) {
            guard step["kind"] as? String == "account", step["target"] as? String == name,
                  ["create", "none", "repair"].contains(step["action"] as? String ?? ""),
                  step["group"] as? String == name, step["mode"] as? String == "0700",
                  let uid = step["uid"] as? Int, let gid = step["gid"] as? Int,
                  (300...399).contains(uid), uid == gid,
                  (step["detail"] as? String)?.contains("/var/agent-bot-soul-\(role)-\(name)") == true
            else { throw invalid }
        }
        if purpose == .soulBridge {
            let base = "/Library/Application Support/ai.true-line.agent-bot-hq"
            for step in steps.dropFirst(members.count + 1) {
                guard step["kind"] as? String == "directory",
                      let target = step["target"] as? String,
                      target.hasPrefix(base + "/"),
                      ["create", "none"].contains(step["action"] as? String ?? ""),
                      (step["owner"] as? String)?.isEmpty == false,
                      (step["group"] as? String)?.isEmpty == false,
                      ["0755", "2750"].contains(step["mode"] as? String ?? "")
                else { throw invalid }
            }
        }
    case .soulProtected, .soulCooperative:
        payload = purpose == .soulProtected ? "soul_protected_launch" : "soul_cooperative_launch"
        role = "launch"
        guard dir == "none",
              Set(plan.keys) == ["version", "hq_account", "dir", "members", "steps", "purpose", payload],
              let policy = plan[payload] as? [String: Any], steps.count == 1,
              steps[0]["kind"] as? String == (purpose == .soulProtected ? "soul-protected-launch" : "soul-cooperative-launch"),
              steps[0]["action"] as? String == "write",
              let installation = steps[0]["target"] as? String,
              matchesHarnessField(installation, "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
        else { throw invalid }
        if purpose == .soulProtected {
            guard let installed = policy["policy"] as? [String: Any],
                  let binding = installed["binding"] as? [String: Any],
                  binding["installation_id"] as? String == installation,
                  let runner = installed["runner"] as? [String: Any],
                  let bridge = installed["bridge"] as? [String: Any],
                  Set([runner["account"] as? String, bridge["account"] as? String].compactMap { $0 }) == Set(members)
            else { throw invalid }
        } else {
            guard policy["purpose"] as? String == purpose.rawValue,
                  policy["profile_in_force"] as? String == "managed-cooperative",
                  let runner = policy["runner"] as? [String: Any],
                  runner["installation_id"] as? String == installation,
                  runner["account"] as? String == members.first,
                  members.count == 1
            else { throw invalid }
        }
    default: throw invalid
    }
    return ["Approve Machine \(role) operation", "Purpose: " + namedPurpose,
            "Plan: " + planID, "Plan SHA-256: " + digest,
            "Exact Machine plan (complete JSON):", source].joined(separator: "\n")
}
