import CryptoKit
import Foundation

private struct HarnessAccountPlan: Decodable {
    let version: Int, hq_account, dir, purpose: String
    let members: [String], steps: [Step]

    struct Step: Decodable {
        let kind, target, action, group, mode: String
        let owner, detail: String?
        let uid, gid: Int?

        func canonical() throws -> String {
            var fields = try [("kind", quote(kind)), ("target", quote(target)), ("action", quote(action))]
            if let owner { fields.append(("owner", try quote(owner))) }
            fields += try [("group", quote(group)), ("mode", quote(mode))]
            if let detail { fields.append(("detail", try quote(detail))) }
            if let uid { fields.append(("uid", String(uid))) }
            if let gid { fields.append(("gid", String(gid))) }
            return object(fields)
        }
    }
}

// Verify and display only the plan for provisioned operating-system identities.
// Rebuilding Machine's exact bytes rejects extra steps, fields and duplicate keys.
func reviewHarnessAccounts(_ source: String, planID: String, digest: String) throws -> String {
    let invalid = PresenceFailure.invalidChallenge
    let hq = "_agent-bot-hq"
    let broker = "/Library/Application Support/ai.true-line.agent-bot-hq/ipc"
    let bytes = Data(source.utf8)
    guard bytes.count <= 32768, matchesHarnessField(planID, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"),
          SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest else { throw invalid }
    let p = try JSONDecoder().decode(HarnessAccountPlan.self, from: bytes)
    guard p.version == 3, p.purpose == "harness-account-provision", p.hq_account == hq,
          p.dir == "none" || p.dir == broker, (1...99).contains(p.members.count),
          p.members == Array(Set(p.members)).sorted(),
          p.members.allSatisfy({ matchesHarnessField($0, "[a-z_][a-z0-9_-]{0,31}") && ![hq, "admin", "root"].contains($0) })
    else { throw invalid }

    let roles = [hq] + p.members
    guard p.steps.count == roles.count * (p.dir == broker ? 2 : 1) else { throw invalid }
    var identities = Set<Int>()
    var lines = ["Provision harness accounts", "Plan: " + planID, "Plan SHA-256: " + digest]
    for (name, step) in zip(roles, p.steps) {
        guard step.kind == (name == hq ? "hq-account" : "account"), step.target == name, step.owner == nil,
              step.group == name, step.mode == "0700", let uid = step.uid, step.gid == uid,
              (300...399).contains(uid), identities.insert(uid).inserted, let detail = step.detail
        else { throw invalid }
        let home = name == hq ? "/var/agent-bot-hq" : "/var/agent-bot-harness-" + name
        if name == hq {
            guard step.action == "none", detail == "exists; dedicated; home " + home + "; its password is checked at apply" else { throw invalid }
        } else {
            switch step.action {
            case "create":
                guard detail == "home " + home + ", shell /usr/bin/false, private group, no password, no other groups" else { throw invalid }
            case "none":
                guard detail == "exists; home " + home + "; its password is checked at apply" else { throw invalid }
            case "repair":
                let prefix = "exists; home " + home + " has mode "
                let suffix = " and is set to 0700; its password is checked at apply"
                guard detail.hasPrefix(prefix), detail.hasSuffix(suffix) else { throw invalid }
                let old = String(detail.dropFirst(prefix.count).dropLast(suffix.count))
                guard matchesHarnessField(old, "[0-7]{4}"), old != "0700", detail == prefix + old + suffix else { throw invalid }
            default: throw invalid
            }
        }
        lines += ["\(step.action) account \(name)  UID \(uid)  private group \(name)  GID \(uid)",
                  "Home \(home)  mode 0700", detail]
    }
    for (index, step) in p.steps.dropFirst(roles.count).enumerated() {
        let owner = index == 0 ? "root" : hq
        let group = index == 0 ? "wheel" : p.members[index - 1]
        let path = index == 0 ? broker : broker + "/" + group
        let mode = index == 0 ? "0755" : "2750"
        guard step.kind == "directory", step.target == path, ["create", "none"].contains(step.action),
              step.owner == owner, step.group == group, step.mode == mode,
              step.detail == nil, step.uid == nil, step.gid == nil else { throw invalid }
        lines.append("\(step.action) directory \(path)  \(owner):\(group) \(mode)")
    }

    let canonical = try object([("version", "3"), ("hq_account", quote(hq)), ("dir", quote(p.dir)),
        ("members", array(p.members.map(quote))), ("steps", array(p.steps.map { try $0.canonical() })),
        ("purpose", quote(p.purpose))]) + "\n"
    guard Data(canonical.utf8) == bytes else { throw invalid }
    if p.dir == "none" { lines.append("Broker directories: none") }
    return lines.joined(separator: "\n")
}
