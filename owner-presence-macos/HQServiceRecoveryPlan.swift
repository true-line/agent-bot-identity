import CryptoKit
import Foundation

private struct RecoveryRecord: Decodable {
    struct Release: Decodable { let archive, release_dir, artifact_sha256, node, node_sha256: String }
    struct Directory: Decodable { let path, action, owner, group, mode: String }
    let service: Release, plist: String, owner_uid: UInt32, runtime_directory: Directory?
}

// Accept exactly the two effects in Machine's stopped-service recovery plan.
// Round-trip both JSON layers so decoders cannot hide duplicate or unknown fields.
func reviewHQServiceRecovery(_ source: String, planID: String, digest: String) throws -> String {
    let invalid = PresenceFailure.invalidChallenge
    let bytes = Data(source.utf8)
    let hq = "_agent-bot-hq", label = "ai.true-line.agent-bot-hq"
    let runtime = "/Library/Application Support/" + label
    guard bytes.count <= 48 * 1024, matchesHarnessField(planID, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"),
          SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest,
          let plan = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          let steps = plan["steps"] as? [[String: String]], steps.count == 2 else { throw invalid }
    let step = steps[1]
    guard let action = step["action"], ["create", "write"].contains(action),
          let owner = step["owner"], matchesHarnessField(owner, "[a-z_][a-z0-9_-]{0,31}"), owner != "root", owner != hq,
          let content = step["content"] else { throw invalid }
    let record = try JSONDecoder().decode(RecoveryRecord.self, from: Data(content.utf8))
    let release = record.service
    func cleanPath(_ s: String) -> Bool {
        matchesHarnessField(s, "/[a-zA-Z0-9._/+:-]+") && s.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
    guard record.owner_uid > 0, [release.release_dir, release.node, release.archive].allSatisfy(cleanPath),
          release.release_dir.hasSuffix("/hq"),
          [release.artifact_sha256, release.node_sha256].allSatisfy({ matchesHarnessField($0, "[0-9a-f]{64}") }) else { throw invalid }

    func strings(_ pairs: [(String, String)]) throws -> String {
        try object(pairs.map { ($0.0, try quote($0.1)) })
    }
    let detail = "install the approved LaunchDaemon and verify status as its owner"
    var serviceDetail = detail
    var directoryLine: String?
    let releaseJSON = try strings([("archive", release.archive), ("release_dir", release.release_dir),
                                   ("artifact_sha256", release.artifact_sha256), ("node", release.node), ("node_sha256", release.node_sha256)])
    // The nested record is json.Marshal, including HTML escaping; Plan.Canonical deliberately disables it.
    let plistJSON = try quote(record.plist).replacingOccurrences(of: "<", with: "\\u003c")
        .replacingOccurrences(of: ">", with: "\\u003e").replacingOccurrences(of: "&", with: "\\u0026")
    var fields = [("service", releaseJSON), ("plist", plistJSON), ("owner_uid", String(record.owner_uid))]
    if let dir = record.runtime_directory {
        guard dir.path == runtime, dir.owner == "root", dir.group == "wheel", dir.mode == "0755",
              dir.action == "none" || (dir.action == "create" && action == "create") else { throw invalid }
        let verb = dir.action == "create" ? "create" : "verify"
        directoryLine = "\(verb) \(runtime) as root:wheel 0755"
        serviceDetail = "\(verb) \(runtime) as root:wheel 0755, " + detail
        fields.append(("runtime_directory", try strings([("path", runtime), ("action", dir.action), ("owner", "root"), ("group", "wheel"), ("mode", "0755")])))
    }
    let account = try strings([("kind", "hq-account"), ("target", hq), ("action", "none"), ("group", hq), ("mode", "0700"),
                               ("detail", "exists; dedicated; home /var/agent-bot-hq; its password is checked at apply")])
    let service = try strings([("kind", "service"), ("target", label), ("action", action), ("owner", owner),
                               ("content", object(fields)), ("detail", serviceDetail)])
    let expected = #"{"version":3,"hq_account":"_agent-bot-hq","dir":"none","members":[],"steps":["# + account + "," + service + "]}\n"
    guard bytes == Data(expected.utf8) else { throw invalid }

    // Match Machine's fixed launchd program, service account, peer and endpoint.
    // Byte equality also excludes misleading XML comments, duplicate keys or entities in the review.
    let socket = record.runtime_directory == nil ? "/private/var/agent-bot-hq-control.sock" : runtime + "/owner-control.sock"
    let plist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!-- Managed by managed-machine members. -->
    <!-- archive \(release.artifact_sha256) node \(release.node_sha256) owner UID \(record.owner_uid) -->
    <plist version="1.0"><dict>
    <key>Label</key><string>\(label)</string>
    <key>UserName</key><string>\(hq)</string>
    <key>GroupName</key><string>\(hq)</string>
    <key>Umask</key><integer>63</integer>
    <key>ProgramArguments</key><array>
    <string>/usr/bin/ruby</string><string>--disable-gems</string><string>\(release.release_dir)/helpers/darwin-owner.rb</string><string>launch</string>
    <string>\(release.node)</string><string>\(release.release_dir)/hq/main.mjs</string><string>run</string><string>--home</string><string>/var/agent-bot-hq/.agent-bot-hq</string>
    <string>--owner-account</string><string>\(owner)</string></array>
    <key>Sockets</key><dict><key>owner-control</key><dict>
    <key>SockPathName</key><string>\(socket)</string><key>SockPathMode</key><integer>438</integer>
    <key>SockType</key><string>stream</string></dict></dict>
    </dict></plist>

    """
    guard record.plist.utf8.elementsEqual(plist.utf8) else { throw invalid }
    var lines = ["Plan: " + planID, "Plan SHA-256: " + digest, "Keep dedicated account: " + hq,
                 "Service: " + action + " " + label, "Owner: \(owner) (UID \(record.owner_uid))",
                 "Release: " + release.release_dir, "Archive: " + release.archive, "Archive SHA-256: " + release.artifact_sha256,
                 "Node: " + release.node, "Node SHA-256: " + release.node_sha256]
    if let directoryLine { lines.append("Runtime directory: " + directoryLine) }
    lines.append("LaunchDaemon plist\n" + plist)
    return lines.joined(separator: "\n")
}
