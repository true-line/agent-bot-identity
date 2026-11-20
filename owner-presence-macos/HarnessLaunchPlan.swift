import CryptoKit
import Foundation

enum HarnessLaunchAction: String { case install, retire }

private struct HarnessPlan: Decodable {
    let version: Int, hq_account: String, dir: String, members: [String], steps: [FileStep]
    struct FileStep: Decodable { let kind, target, action, owner, group, mode, content: String }
}

private struct Grant: Decodable {
    let schema, action: String
    let hq_uid: Int
    let launcher, sandbox: File
    let adapters: [Adapter]
    let installed_plan_id, installed_plan_digest: String
    struct File: Decodable { let path, sha256: String }
    struct Adapter: Decodable {
        let adapter_id, account: String, uid: Int, executable, sha256: String, args: [String]
    }
}

// Go writes fields in declaration order and one final LF. Rebuild using that
// schema, so duplicate/extra fields or alternate numeric encodings cannot
// disappear inside Foundation's decoder and still produce an approval.
private func quote(_ value: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    return String(decoding: data, as: UTF8.self)
        .replacingOccurrences(of: "\u{2028}", with: "\\u2028").replacingOccurrences(of: "\u{2029}", with: "\\u2029")
}
private func array(_ elements: [String]) -> String { "[" + elements.joined(separator: ",") + "]" }
private func object(_ fields: [(String,String)]) -> String {
    "{" + fields.map { "\"" + $0.0 + "\":" + $0.1 }.joined(separator: ",") + "}"
}
func matchesHarnessField(_ text: String, _ pattern: String) -> Bool {
    text.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil
}

func checkHarnessPlan(_ text: String, planID: String, digest: String, action: HarnessLaunchAction) throws {
    let invalid = PresenceFailure.invalidChallenge
    let base = "/Library/Application Support/ai.true-line.agent-bot-hq"
    let data = Data(text.utf8)
    guard data.count <= 32 * 1024, matchesHarnessField(planID, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"),
          SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == digest else { throw invalid }
    let p = try JSONDecoder().decode(HarnessPlan.self, from: data)
    guard p.version == 3, p.hq_account == "_agent-bot-hq", p.dir == base + "/ipc", p.steps.count == 2 else { throw invalid }
    let install = action == .install
    let policy = p.steps[0], rule = p.steps[1]
    guard policy.target == base + "/harness-launch-policy.json", policy.mode == "0644",
          rule.target == "/private/etc/sudoers.d/agent-bot-hq-harness-launch", rule.mode == "0440" else { throw invalid }
    for s in p.steps {
        guard s.kind == "file", s.action == (install ? "create" : "remove"),
              s.owner == "root", s.group == "wheel" else { throw invalid }
    }
    func renderPlan(fileAction: String, policyContent: String) throws -> String {
        let steps = try p.steps.enumerated().map { (index, s) -> String in
            try object([("kind",quote(s.kind)), ("target",quote(s.target)), ("action",quote(fileAction)),
                        ("owner",quote(s.owner)), ("group",quote(s.group)), ("mode",quote(s.mode)),
                        ("content",quote(index == 0 ? policyContent : s.content))])
        }
        return try object([("version","3"), ("hq_account",quote(p.hq_account)), ("dir",quote(p.dir)),
                           ("members",array(p.members.map(quote))), ("steps",array(steps))]) + "\n"
    }
    let rebuilt = try renderPlan(fileAction: policy.action, policyContent: policy.content)
    guard Data(rebuilt.utf8) == data else { throw invalid }
    let bytes = Data(policy.content.utf8)
    let g = try JSONDecoder().decode(Grant.self, from: bytes)
    guard g.schema == "agent-bot-harness-launch/v1", g.action == action.rawValue,
          (300...399).contains(g.hq_uid), (1...16).contains(g.adapters.count) else { throw invalid }
    if install {
        guard g.installed_plan_id.isEmpty, g.installed_plan_digest.isEmpty else { throw invalid }
    } else {
        guard matchesHarnessField(g.installed_plan_id, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"), g.installed_plan_id != planID,
              matchesHarnessField(g.installed_plan_digest, "[0-9a-f]{64}") else { throw invalid }
    }
    func file(_ f: Grant.File, _ name: String) throws -> String {
        guard f.path == base + "/" + name, matchesHarnessField(f.sha256, "[0-9a-f]{64}") else { throw invalid }
        return try object([("path", quote(f.path)), ("sha256", quote(f.sha256))])
    }
    var previous = "", accounts: [String: Int] = [:]
    let adapters = try g.adapters.map { a -> String in
        guard matchesHarnessField(a.adapter_id, "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"), previous < a.adapter_id,
              matchesHarnessField(a.account, "[a-z_][a-z0-9_-]{0,31}"), !["root","admin","_agent-bot-hq"].contains(a.account),
              (300...399).contains(a.uid), a.uid != g.hq_uid, accounts[a.account].map({ $0 == a.uid }) ?? true,
              matchesHarnessField(a.executable, "/[A-Za-z0-9._+ /-]+"), a.executable.utf8.count <= 1024,
              a.executable.dropFirst().split(separator:"/", omittingEmptySubsequences:false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              matchesHarnessField(a.sha256, "[0-9a-f]{64}"), a.args.count <= 32,
              a.args.allSatisfy({ $0.utf8.count <= 1024 && $0.unicodeScalars.allSatisfy({ $0.properties.generalCategory != .control }) })
        else { throw invalid }
        previous = a.adapter_id
        accounts[a.account] = a.uid
        return try object([("adapter_id",quote(a.adapter_id)), ("account",quote(a.account)), ("uid",String(a.uid)),
                           ("executable",quote(a.executable)), ("sha256",quote(a.sha256)), ("args",array(a.args.map(quote)))])
    }
    let names = accounts.keys.sorted()
    guard names == p.members, Set(accounts.values).count == accounts.count else { throw invalid }
    func renderGrant(action: HarnessLaunchAction, previousID: String, previousDigest: String) throws -> String {
        try object([("schema",quote(g.schema)), ("action",quote(action.rawValue)), ("hq_uid",String(g.hq_uid)),
                    ("launcher",file(g.launcher,"harness-launch")), ("sandbox",file(g.sandbox,"harness-egress.sb")),
                    ("adapters",array(adapters)), ("installed_plan_id",quote(previousID)),
                    ("installed_plan_digest",quote(previousDigest))]) + "\n"
    }
    let grant = try renderGrant(action: action, previousID: g.installed_plan_id, previousDigest: g.installed_plan_digest)
    let launcher = g.launcher.path.replacingOccurrences(of:" ",with:"\\ ")
    let lines = names.map { "_agent-bot-hq ALL = (\($0)) NOPASSWD: NOSETENV: sha256:\(g.launcher.sha256) \(launcher) harness-run" }
    let sudoers = (["# Managed by managed-machine harness launch v1."] + lines + [""]).joined(separator:"\n")
    guard Data(grant.utf8) == bytes, Data(rule.content.utf8) == Data(sudoers.utf8) else { throw invalid }
    if !install {
        let originalGrant = try renderGrant(action: .install, previousID: "", previousDigest: "")
        let originalPlan = try renderPlan(fileAction: "create", policyContent: originalGrant)
        let originalDigest = SHA256.hash(data: Data(originalPlan.utf8)).map { String(format: "%02x", $0) }.joined()
        guard originalDigest == g.installed_plan_digest else { throw invalid }
    }
}

// Keep argv boundaries, whitespace, combining characters and bidi controls
// visible on the native review surface. The full canonical plan is included.
func renderHarnessReview(_ source: String, planID: String, digest: String, action: HarnessLaunchAction) throws -> String {
    try checkHarnessPlan(source, planID: planID, digest: digest, action: action)
    func visible(_ text: String) -> String {
        text.utf16.map { unit in
            if unit == 10 { return "\n" }
            if (32...126).contains(unit) { return String(UnicodeScalar(unit)!) }
            return String(format: "\\u%04x", unit)
        }.joined()
    }
    let plan = try JSONDecoder().decode(HarnessPlan.self, from: Data(source.utf8))
    let grant = try JSONDecoder().decode(Grant.self, from: Data(plan.steps[0].content.utf8))
    var lines = ["Harness launch plan preview: " + action.rawValue, "Plan: " + planID, "Plan SHA-256: " + digest,
        "Dedicated HQ UID: \(grant.hq_uid)",
        "Launcher: \(grant.launcher.path)  SHA-256: \(grant.launcher.sha256)",
        "Sandbox: \(grant.sandbox.path)  SHA-256: \(grant.sandbox.sha256)"]
    if grant.action == "retire" {
        lines += ["Installed plan: " + grant.installed_plan_id, "Installed plan SHA-256: " + grant.installed_plan_digest]
    }
    for adapter in grant.adapters {
        lines += ["Adapter: \(adapter.adapter_id)  Account: \(adapter.account)  UID: \(adapter.uid)",
            "Executable SHA-256: " + adapter.sha256]
        for (i, arg) in ([adapter.executable] + adapter.args).enumerated() {
            lines.append("argv[\(i)] " + visible(try quote(arg)))
        }
    }
    for step in plan.steps {
        lines.append("\(step.action) \(step.target)  \(step.owner):\(step.group) \(step.mode)")
    }
    lines += ["Sudoers rule", plan.steps[1].content, "Full canonical plan (non-ASCII shown as Unicode escapes)", visible(source)]
    return lines.joined(separator: "\n")
}
