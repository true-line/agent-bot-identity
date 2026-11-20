import CryptoKit
import Foundation

// Decode exactly one successful, Machine-signed response line from HQ's export.
// JSONSerialization and JSONDecoder handle the JSON grammar. The scanner only
// locates the original body octets and counts fields before Foundation can fold
// duplicate keys. Both allowed objects otherwise contain scalar values only.
struct HarnessLaunchChallenge: Decodable {
    let action, machine_key, hq_key, owner_key, plan_id, plan_digest, nonce, plan_canonical: String
    let expires_at: Int64
    static let maximumBytes = 64 * 1024 + 1 // one optional terminating newline

    private struct Frame: Decodable {
        let ok: Bool
        let state, nonce, request_nonce, signature: String
        let timestamp: Int64
        let body: HarnessLaunchChallenge
    }

    static func parse(_ input: Data, action: HarnessLaunchAction, now: Int64) throws -> Self {
        let invalid = PresenceFailure.invalidChallenge
        guard input.count <= maximumBytes else { throw invalid }
        let line = input.last == 10 ? Data(input.dropLast()) : input
        guard !line.isEmpty, line.count < maximumBytes, !line.contains(where: { $0 < 32 && $0 != 9 }),
              let utf8 = String(data: line, encoding: .utf8), Data(utf8.utf8) == line,
              let object = try JSONSerialization.jsonObject(with: line) as? [String: Any],
              Set(object.keys) == ["ok","state","body","timestamp","nonce","request_nonce","signature"],
              let body = object["body"] as? [String: Any],
              Set(body.keys) == ["action","machine_key","hq_key","owner_key","plan_id","plan_digest","nonce","expires_at","plan_canonical"]
        else { throw invalid }
        let rawBody = try signedBody(line)
        let f = try JSONDecoder().decode(Frame.self, from: line)
        let c = f.body
        guard f.ok, f.state == "challenged", c.action == "harness-launch-" + action.rawValue,
              [c.machine_key,c.hq_key,c.plan_digest,c.nonce].allSatisfy({ matchesHarnessField($0, "[0-9a-f]{64}") }),
              c.machine_key != c.hq_key,
              [f.nonce,f.request_nonce].allSatisfy({ matchesHarnessField($0, "[A-Za-z0-9_-]{1,128}") }),
              let point = Data(base64Encoded: c.owner_key), point.count == 65, point.first == 4,
              point.base64EncodedString() == c.owner_key, (try? P256.Signing.PublicKey(x963Representation: point)) != nil,
              let sig = Data(base64Encoded: f.signature), sig.count == 64, sig.base64EncodedString() == f.signature,
              f.timestamp >= 0, f.timestamp < c.expires_at, c.expires_at - f.timestamp <= 120
        else { throw invalid }
        try c.checkExpiry(now: now)
        let signed = ["true","","","challenged",rawBody,String(f.timestamp),f.nonce,f.request_nonce].joined(separator: "\n")
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: machineKeyBytes(c.machine_key))
        guard key.isValidSignature(sig, for: Data(signed.utf8)) else { throw invalid }
        try checkHarnessPlan(c.plan_canonical, planID: c.plan_id, digest: c.plan_digest, action: action)
        return c
    }

    private static func signedBody(_ line: Data) throws -> String {
        var quoted = false, escaped = false, depth = 0, frameFields = 0, bodyFields = 0
        var start: Data.Index?
        var range: Range<Data.Index>?
        for i in line.indices {
            let b = line[i]
            if escaped { escaped = false; continue }
            if quoted {
                if b == 92 { escaped = true }
                if b == 34 { quoted = false }
                continue
            }
            switch b {
            case 34: quoted = true
            case 123:
                depth += 1
                if depth == 2 {
                    guard start == nil else { throw PresenceFailure.invalidChallenge }
                    start = i
                }
                guard depth <= 2 else { throw PresenceFailure.invalidChallenge }
            case 125:
                if depth == 2, let start { range = start..<line.index(after: i) }
                depth -= 1
            case 58:
                if depth == 1 { frameFields += 1 }
                if depth == 2 { bodyFields += 1 }
            case 91, 93: throw PresenceFailure.invalidChallenge
            default: break
            }
        }
        guard frameFields == 7, bodyFields == 9, let range,
              let body = String(data: line[range], encoding: .utf8),
              Data(body.utf8) == line[range] else { throw PresenceFailure.invalidChallenge }
        return body
    }

    func checkExpiry(now: Int64) throws {
        guard now >= 0, expires_at > now, expires_at - now <= 120 else { throw PresenceFailure.expired }
    }

    var signedBytes: Data {
        Data(["agent-bot-machine-owner/v1", action, machine_key, hq_key, owner_key,
              plan_id, plan_digest, nonce, String(expires_at), ""].joined(separator: "\n").utf8)
    }

    func checkOwnerKey(_ key: Data) throws {
        guard key.base64EncodedString() == owner_key else { throw PresenceFailure.invalidChallenge }
    }
}
