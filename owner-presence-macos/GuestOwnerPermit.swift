import CryptoKit
import Foundation

// The disposable-guest path is separate from ordinary same-host approvals.
// Its host signature is checked under the installed physical Machine pin;
// the guest challenge remains independently signed by the guest Machine.
struct GuestOwnerPermit: Decodable {
    let version: Int
    let host_machine_key, guest_machine_key, guest_vm_name, guest_vm_mac, guest_build: String
    let tart_wrapper_sha256, tart_app_sha256: String
    let action, hq_key, owner_key, plan_id, plan_digest, challenge_sha256, challenge_nonce: String
    let issued_at, expires_at: Int64
    let permit_nonce, signature: String

    private static let fields: Set<String> = [
        "version", "host_machine_key", "guest_machine_key", "guest_vm_name", "guest_vm_mac",
        "guest_build", "tart_wrapper_sha256", "tart_app_sha256", "action", "hq_key",
        "owner_key", "plan_id", "plan_digest", "challenge_sha256", "challenge_nonce",
        "issued_at", "expires_at", "permit_nonce", "signature"
    ]
    static let maximumBytes = HarnessLaunchChallenge.maximumBytes + 4096

    private static func exactScalarObject(_ data: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == fields else { throw PresenceFailure.invalidChallenge }
        // JSONSerialization folds duplicate keys. Count the top-level colons
        // before decoding; the permit has scalar fields and no nested objects.
        var quoted = false, escaped = false, depth = 0, count = 0
        for byte in data {
            if escaped { escaped = false; continue }
            if quoted {
                if byte == 92 { escaped = true }
                if byte == 34 { quoted = false }
                continue
            }
            switch byte {
            case 34: quoted = true
            case 123: depth += 1
            case 125: depth -= 1
            case 58 where depth == 1: count += 1
            case 91, 93: throw PresenceFailure.invalidChallenge
            default: break
            }
            guard depth >= 0 && depth <= 1 else { throw PresenceFailure.invalidChallenge }
        }
        guard !quoted, depth == 0, count == fields.count else { throw PresenceFailure.invalidChallenge }
    }

    static func parse(_ input: Data, now: Int64,
                      verifyHost: (String) throws -> Void = HarnessMachinePin.verify) throws -> GuestHarnessReview {
        let invalid = PresenceFailure.invalidChallenge
        guard input.count <= maximumBytes,
              let split = input.firstIndex(of: 10) else { throw invalid }
        let challengeLine = Data(input[..<split])
        var permitLine = Data(input[input.index(after: split)...])
        if permitLine.last == 10 { permitLine.removeLast() }
        guard !challengeLine.isEmpty, challengeLine.count < HarnessLaunchChallenge.maximumBytes,
              !permitLine.isEmpty, permitLine.count <= 4096,
              !permitLine.contains(10), !permitLine.contains(13) else { throw invalid }
        try exactScalarObject(permitLine)
        let permit = try JSONDecoder().decode(Self.self, from: permitLine)
        guard permit.version == 1,
              let purpose = PairedHarnessPurpose(rawValue: permit.action),
              [.install, .retire, .provision, .qualification, .soulRunner, .soulBridge,
               .soulProtected, .soulProtectedRetire, .soulCooperative].contains(purpose),
              [permit.host_machine_key, permit.guest_machine_key, permit.tart_wrapper_sha256,
               permit.tart_app_sha256, permit.hq_key, permit.plan_digest, permit.challenge_sha256,
               permit.challenge_nonce, permit.permit_nonce].allSatisfy({
                   matchesHarnessField($0, "[0-9a-f]{64}")
               }),
              matchesHarnessField(permit.guest_vm_name, "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
              matchesHarnessField(permit.guest_vm_mac, "[0-9a-f]{2}(:[0-9a-f]{2}){5}"),
              matchesHarnessField(permit.guest_build, "[0-9]{2}[A-Z][0-9]{1,5}"),
              permit.issued_at >= 0, permit.issued_at <= now + 30,
              permit.expires_at > now, permit.expires_at <= now + 120,
              permit.issued_at < permit.expires_at,
              permit.expires_at - permit.issued_at <= 120
        else { throw invalid }
        let challenge = try HarnessLaunchChallenge.parse(challengeLine, action: purpose, now: now)
        let digest = SHA256.hash(data: challengeLine).map { String(format: "%02x", $0) }.joined()
        guard permit.guest_machine_key == challenge.machine_key,
              permit.action == challenge.action, permit.hq_key == challenge.hq_key,
              permit.owner_key == challenge.owner_key, permit.plan_id == challenge.plan_id,
              permit.plan_digest == challenge.plan_digest, permit.challenge_nonce == challenge.nonce,
              permit.challenge_sha256 == digest, permit.expires_at == challenge.expires_at,
              let sig = Data(base64Encoded: permit.signature), sig.count == 64,
              sig.base64EncodedString() == permit.signature else { throw invalid }
        try verifyHost(permit.host_machine_key)
        let host = try Curve25519.Signing.PublicKey(rawRepresentation: machineKeyBytes(permit.host_machine_key))
        guard host.isValidSignature(sig, for: permit.signedBytes) else { throw invalid }
        return GuestHarnessReview(challenge: challenge, permit: permit)
    }

    var signedBytes: Data {
        Data(["agent-bot-machine-owner/guest-permit/v1", String(version), host_machine_key,
              guest_machine_key, guest_vm_name, guest_vm_mac, guest_build,
              tart_wrapper_sha256, tart_app_sha256, action, hq_key, owner_key, plan_id,
              plan_digest, challenge_sha256, challenge_nonce, String(issued_at),
              String(expires_at), permit_nonce, ""].joined(separator: "\n").utf8)
    }

    func checkExpiry(now: Int64) throws {
        guard now >= 0, expires_at > now, expires_at - now <= 120 else {
            throw PresenceFailure.expired
        }
    }
}

struct GuestHarnessReview {
    let challenge: HarnessLaunchChallenge
    let permit: GuestOwnerPermit

    func checkExpiry(now: Int64) throws {
        try challenge.checkExpiry(now: now)
        try permit.checkExpiry(now: now)
    }
}
