import CryptoKit
import Foundation

enum PresenceFailure: Error, LocalizedError {
    case invalidChallenge, expired, declined, incomplete

    var errorDescription: String? {
        switch self {
        case .invalidChallenge: return "Invalid Machine owner challenge."
        case .declined: return "Owner approval was declined."
        case .incomplete: return "Owner authentication did not complete."
        case .expired: return "Machine owner challenge expired."
        }
    }
}

struct PairingChallenge {
    static let maximumBytes = PairingFields.maximumBytes
    private let fields: PairingFields

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        Self(fields: try PairingFields.parse(bytes, now: now))
    }

    func checkExpiry(now: Int64) throws { try fields.checkExpiry(now: now) }
    var signedBytes: Data { fields.signedBytes }

    var approvalReason: String {
        guard let uid = fields.hq_uid else { return fields.approvalReason }
        return "HQ will run in ordinary account UID \(uid).\n\(fields.approvalReason)"
    }
}

private struct PairingFields: Decodable {
    let action: String
    let machine_key: String
    let hq_uid: Int?
    let hq_key: String
    let nonce: String
    let expires_at: Int64

    static let maximumBytes = 2048

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        let fields: Set<String> = ["action", "machine_key", "hq_key", "nonce", "expires_at"]
        guard bytes.count <= maximumBytes,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let action = json["action"] as? String else { throw PresenceFailure.invalidChallenge }
        switch action {
        case "machine-pair":
            guard Set(json.keys) == fields else { throw PresenceFailure.invalidChallenge }
        case "machine-pair-ordinary":
            guard Set(json.keys) == fields.union(["hq_uid"]) else { throw PresenceFailure.invalidChallenge }
        default:
            throw PresenceFailure.invalidChallenge
        }
        let challenge = try JSONDecoder().decode(Self.self, from: bytes)
        guard (action == "machine-pair" || (challenge.hq_uid.map { (501...Int(Int32.max)).contains($0) } == true)),
              [challenge.machine_key, challenge.hq_key, challenge.nonce].allSatisfy({ text in
                  text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
              }) else { throw PresenceFailure.invalidChallenge }
        try challenge.checkExpiry(now: now)
        return challenge
    }

    func checkExpiry(now: Int64) throws {
        guard now >= 0, expires_at > now, expires_at - now <= 120 else { throw PresenceFailure.expired }
    }

    var signedBytes: Data {
        var fields = ["agent-bot-machine-owner/v1", action, machine_key, hq_key]
        if let uid = hq_uid { fields.append(String(uid)) }
        fields.append(contentsOf: [nonce, String(expires_at), ""])
        return Data(fields.joined(separator: "\n").utf8)
    }

    var approvalReason: String {
        "Pair HQ with Machine?\nMachine SHA-256: \(machineFingerprint(machine_key))\nHQ SHA-256: \(machineFingerprint(hq_key))"
    }
}

func machineKeyBytes(_ hex: String) -> Data {
    // The parser has already validated the 32 lowercase-hex octets.
    let octets = Array(hex.utf8)
    func value(_ c: UInt8) -> UInt8 { c <= 57 ? c - 48 : c - 87 }
    let bytes = stride(from: 0, to: octets.count, by: 2).map {
        (value(octets[$0]) << 4) | value(octets[$0 + 1])
    }
    return Data(bytes)
}

func machineFingerprint(_ hex: String) -> String {
    SHA256.hash(data: machineKeyBytes(hex)).map { String(format: "%02x", $0) }.joined()
}
