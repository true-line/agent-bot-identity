import CryptoKit
import Foundation

@main
struct GuestOwnerPermitTests {
    static func main() throws {
        let fixture = URL(fileURLWithPath: CommandLine.arguments[1])
        let plan = try String(contentsOf: fixture, encoding: .utf8)
        let planDigest = SHA256.hash(data: Data(plan.utf8)).map { String(format: "%02x", $0) }.joined()
        let host = Curve25519.Signing.PrivateKey()
        let guest = Curve25519.Signing.PrivateKey()
        let owner = P256.Signing.PrivateKey()
        let hostHex = host.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let guestHex = guest.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let ownerKey = owner.publicKey.x963Representation.base64EncodedString()
        let planID = "plan-20261120T122100Z-dcef"
        let nonce = String(repeating: "ab", count: 32)
        let hq = String(repeating: "02", count: 32)
        let body: [String: Any] = [
            "action": "harness-account-provision", "machine_key": guestHex, "hq_key": hq,
            "owner_key": ownerKey, "plan_id": planID, "plan_digest": planDigest,
            "nonce": nonce, "expires_at": 1090, "plan_canonical": plan
        ]
        let bodyData = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
        let bodyString = String(decoding: bodyData, as: UTF8.self)
        let responseSigned = ["true", "", "", "challenged", bodyString, "1000",
                              "response-nonce", "request-nonce"].joined(separator: "\n")
        let responseSignature = try guest.signature(for: Data(responseSigned.utf8)).base64EncodedString()
        let frame = #"{"ok":true,"state":"challenged","body":\#(bodyString),"timestamp":1000,"nonce":"response-nonce","request_nonce":"request-nonce","signature":"\#(responseSignature)"}"#
        let frameData = Data(frame.utf8)
        let frameDigest = SHA256.hash(data: frameData).map { String(format: "%02x", $0) }.joined()
        var permit: [String: Any] = [
            "version": 1, "host_machine_key": hostHex, "guest_machine_key": guestHex,
            "guest_vm_name": "synthetic-guest", "guest_vm_mac": "02:00:00:00:00:01",
            "guest_build": "25G83", "tart_wrapper_sha256": String(repeating: "1", count: 64),
            "tart_app_sha256": String(repeating: "2", count: 64),
            "action": "harness-account-provision", "hq_key": hq, "owner_key": ownerKey,
            "plan_id": planID, "plan_digest": planDigest, "challenge_sha256": frameDigest,
            "challenge_nonce": nonce, "issued_at": 1000, "expires_at": 1090,
            "permit_nonce": String(repeating: "3", count: 64)
        ]
        let signed = ["agent-bot-machine-owner/guest-permit/v1", "1", hostHex, guestHex,
                      "synthetic-guest", "02:00:00:00:00:01", "25G83",
                      String(repeating: "1", count: 64), String(repeating: "2", count: 64),
                      "harness-account-provision", hq, ownerKey, planID, planDigest,
                      frameDigest, nonce, "1000", "1090", String(repeating: "3", count: 64), ""
        ].joined(separator: "\n")
        permit["signature"] = try host.signature(for: Data(signed.utf8)).base64EncodedString()
        func envelope(_ values: [String: Any], frame: String = frame) throws -> Data {
            let encoded = try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
            return Data(frame.utf8) + Data([10]) + encoded + Data([10])
        }
        func verifyHost(_ key: String) throws {
            guard key == hostHex else { throw PresenceFailure.invalidChallenge }
        }
        let reviewed = try GuestOwnerPermit.parse(envelope(permit), now: 1000, verifyHost: verifyHost)
        precondition(reviewed.challenge.machine_key == guestHex)
        precondition(reviewed.permit.signedBytes == Data(signed.utf8))
        let text = try HarnessNativeReview.text(reviewed.challenge, guest: reviewed.permit)
        precondition(text.contains("Physical Machine SHA-256: " + machineFingerprint(hostHex)))
        precondition(text.contains("Guest Machine SHA-256: " + machineFingerprint(guestHex)))
        precondition((try? GuestOwnerPermit.parse(envelope(permit), now: 1090, verifyHost: verifyHost)) == nil)
        var changed = permit
        changed["guest_vm_mac"] = "02:00:00:00:00:02"
        precondition((try? GuestOwnerPermit.parse(envelope(changed), now: 1000, verifyHost: verifyHost)) == nil)
        changed = permit
        changed["plan_digest"] = String(repeating: "0", count: 64)
        precondition((try? GuestOwnerPermit.parse(envelope(changed), now: 1000, verifyHost: verifyHost)) == nil)
        precondition((try? GuestOwnerPermit.parse(envelope(permit), now: 1000, verifyHost: { _ in
            throw PresenceFailure.invalidChallenge
        })) == nil)
        let duplicate = String(decoding: try envelope(permit), as: UTF8.self)
            .replacingOccurrences(of: #""version":1"#, with: #""version":1,"version":1"#)
        precondition((try? GuestOwnerPermit.parse(Data(duplicate.utf8), now: 1000, verifyHost: verifyHost)) == nil)
        let forgedFrame = frame.replacingOccurrences(of: responseSignature,
                                                     with: String(repeating: "A", count: responseSignature.count))
        precondition((try? GuestOwnerPermit.parse(envelope(permit, frame: forgedFrame),
                                                  now: 1000, verifyHost: verifyHost)) == nil)
        let runner = "_abm-sr-bbbbbbbbbbbbbbbbbbbb"
        let bridge = "_abm-br-aaaaaaaaaaaaaaaaaaaa"
        let retirement: [String: Any] = [
            "version": 3, "hq_account": "_agent-bot-hq", "dir": "none",
            "members": [bridge, runner], "purpose": "soul-protected-launch-retire",
            "steps": [[
                "kind": "soul-protected-launch", "target": "inst_fixture",
                "action": "remove",
                "detail": "disable exact per-Soul authority and sudo rule after both role UIDs are idle; retain claims, snapshots and receipts"
            ]],
            "soul_protected_retire": [
                "schema": "agent-bot-machine/soul-protected-launch-retire/v1",
                "installed_plan_id": "plan-20260101T000000Z-abcd",
                "installed_plan_digest": String(repeating: "a", count: 64),
                "installed_plan": [
                    "purpose": "soul-protected-launch-install",
                    "soul_protected_launch": ["policy": [
                        "binding": ["installation_id": "inst_fixture"],
                        "runner": ["account": runner], "bridge": ["account": bridge]
                    ]]
                ]
            ]
        ]
        let retireBytes = try JSONSerialization.data(withJSONObject: retirement, options: [.sortedKeys])
        let retireSource = String(decoding: retireBytes, as: UTF8.self) + "\n"
        let retireDigest = SHA256.hash(data: Data(retireSource.utf8))
            .map { String(format: "%02x", $0) }.joined()
        let retireReview = try PairedHarnessPurpose.soulProtectedRetire.review(
            retireSource, planID: planID, digest: retireDigest)
        precondition(retireReview.contains("retain claims, snapshots and receipts"))
        let unsafeRetire = retireSource.replacingOccurrences(of: "retain claims, snapshots and receipts",
                                                              with: "delete all claims")
        let unsafeDigest = SHA256.hash(data: Data(unsafeRetire.utf8))
            .map { String(format: "%02x", $0) }.joined()
        precondition((try? PairedHarnessPurpose.soulProtectedRetire.review(
            unsafeRetire, planID: planID, digest: unsafeDigest)) == nil)
        precondition(GuestOwnerPermit.permits(.serviceUpgrade))
        precondition(!GuestOwnerPermit.permits(.serviceRecovery))
        let upgradePlan = try String(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]), encoding: .utf8)
        let upgradeDigest = SHA256.hash(data: Data(upgradePlan.utf8))
            .map { String(format: "%02x", $0) }.joined()
        var upgradeBody = body
        upgradeBody["action"] = "hq-service-upgrade"
        upgradeBody["plan_canonical"] = upgradePlan
        upgradeBody["plan_digest"] = upgradeDigest
        let upgradeBodyData = try JSONSerialization.data(withJSONObject: upgradeBody,
                                                          options: [.sortedKeys, .withoutEscapingSlashes])
        let upgradeBodyString = String(decoding: upgradeBodyData, as: UTF8.self)
        let upgradeResponseSigned = ["true", "", "", "challenged", upgradeBodyString, "1000",
                                     "response-nonce", "request-nonce"].joined(separator: "\n")
        let upgradeResponseSignature = try guest.signature(for: Data(upgradeResponseSigned.utf8))
            .base64EncodedString()
        let upgradeFrame = #"{"ok":true,"state":"challenged","body":\#(upgradeBodyString),"timestamp":1000,"nonce":"response-nonce","request_nonce":"request-nonce","signature":"\#(upgradeResponseSignature)"}"#
        let upgradeFrameDigest = SHA256.hash(data: Data(upgradeFrame.utf8))
            .map { String(format: "%02x", $0) }.joined()
        var upgradePermit = permit
        upgradePermit["action"] = "hq-service-upgrade"
        upgradePermit["plan_digest"] = upgradeDigest
        upgradePermit["challenge_sha256"] = upgradeFrameDigest
        let upgradePermitSigned = ["agent-bot-machine-owner/guest-permit/v1", "1", hostHex, guestHex,
                                   "synthetic-guest", "02:00:00:00:00:01", "25G83",
                                   String(repeating: "1", count: 64), String(repeating: "2", count: 64),
                                   "hq-service-upgrade", hq, ownerKey, planID, upgradeDigest,
                                   upgradeFrameDigest, nonce, "1000", "1090",
                                   String(repeating: "3", count: 64), ""].joined(separator: "\n")
        upgradePermit["signature"] = try host.signature(for: Data(upgradePermitSigned.utf8))
            .base64EncodedString()
        let upgradeReview = try GuestOwnerPermit.parse(envelope(upgradePermit, frame: upgradeFrame),
                                                       now: 1000, verifyHost: verifyHost)
        precondition(upgradeReview.challenge.action == "hq-service-upgrade")
        print("Verified guest permit host pin, signatures, plan binding, review text and expiry.")
    }
}
