import CryptoKit
import Foundation

@main
struct HarnessExportTests {
    static func main() throws {
        let fixtures = URL(fileURLWithPath: CommandLine.arguments[1])
        let machine = Curve25519.Signing.PrivateKey()
        let owner = P256.Signing.PrivateKey()
        let machineHex = machine.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        let ownerPin = owner.publicKey.x963Representation.base64EncodedString()
        let now = Int64(Date().timeIntervalSince1970)
        let planID = "plan-20261120T122100Z-dcef"
        func checkService(_ src: String) throws -> String {
            let digest = SHA256.hash(data: Data(src.utf8)).map { String(format: "%02x", $0) }.joined()
            return try reviewHQServiceRecovery(src, planID: planID, digest: digest)
        }
        for (file, socket) in [("hq-service-recovery", "/Library/Application Support/ai.true-line.agent-bot-hq/owner-control.sock"),
                               ("hq-service-recovery-v1", "/private/var/agent-bot-hq-control.sock")] {
            let source = try String(contentsOf: fixtures.appendingPathComponent(file + ".json"), encoding: .utf8)
            let text = try checkService(source)
            for effect in ["Keep dedicated account: _agent-bot-hq", "Service: create ai.true-line.agent-bot-hq",
                           "Owner: operator (UID 501)", "Archive: /private/tmp/hq-recovery-fixture/hq.tar",
                           "Node: /private/tmp/hq-recovery-fixture/node", "LaunchDaemon plist\n<?xml", socket] {
                precondition(text.contains(effect))
            }
            let write = source.replacingOccurrences(of: #""action":"create","owner":"operator""#, with: #""action":"write","owner":"operator""#)
            if file == "hq-service-recovery" {
                precondition((try? checkService(write)) == nil) // An existing job cannot create its missing directory.
            }
            let existing = write.replacingOccurrences(of: #"\"action\":\"create\""#, with: #"\"action\":\"none\""#)
                .replacingOccurrences(of: #""detail":"create /Library"#, with: #""detail":"verify /Library"#)
            let existingText = try checkService(existing)
            precondition(existingText.contains("Service: write ai.true-line.agent-bot-hq"))
            // U+212A is canonically equivalent to ASCII K in Swift String equality.
            // Both paths look alike in a review but their executable path bytes differ.
            let ascii = source.replacingOccurrences(of: "hq-recovery-fixture", with: "K-hq-recovery-fixture")
            _ = try checkService(ascii)
            let changedPath = ascii.replacingOccurrences(of: "K-hq-recovery-fixture/hq/helpers", with: "\u{212A}-hq-recovery-fixture/hq/helpers")
            precondition(ascii == changedPath && !ascii.utf8.elementsEqual(changedPath.utf8))
            precondition((try? checkService(changedPath)) == nil)
            for (old, new) in [(#""action":"none""#, #""action":"create""#),
                               (#""kind":"service""#, #""kind":"account""#),
                               (#""members":[]"#, #""members":["member"]"#),
                               (#""owner":"operator""#, #""owner":"root""#),
                               (#""version":3"#, #""version":3,"version":3"#),
                               ("hq-recovery-fixture/hq.tar", "hq-recovery-fixture/../hq.tar"),
                               ("helpers/darwin-owner.rb", "helpers/other.rb"),
                               ("owner-control.sock", "different.sock"),
                               (#"\"owner_uid\":501"#, #"\"owner_uid\":0"#)] {
                let changed = source.replacingOccurrences(of: old, with: new)
                if old == "owner-control.sock" && file.hasSuffix("-v1") { continue }
                precondition(changed != source && (try? checkService(changed)) == nil)
            }
        }
        for action in PairedHarnessPurpose.allCases {
            let name = action.rawValue
            let file = action == .provision ? "harness-account-provision-accounts-and-broker" : name
            let fixtureCanonical = try String(contentsOf: fixtures.appendingPathComponent(file + ".json"), encoding: .utf8)
            let canonical = action == .qualification ? fixtureCanonical.replacingOccurrences(
                of: "Review only: declared host identity, fixed conformance gates, pinned runner and test provider, disposable member state; no install or launch authorization.",
                with: "Owner approval permits one qualification run with the listed runner, test provider and disposable member state. It grants no installation or ordinary HQ access."
            ) : fixtureCanonical
            let digest = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
            let body: [String:Any] = ["action":name,"machine_key":machineHex,"hq_key":String(repeating:"45", count:32),
                "owner_key":ownerPin,"plan_id":planID,"plan_digest":digest,"nonce":String(repeating:"12",count:32),
                "expires_at":now+120,"plan_canonical":canonical]
            func signedFrame(_ body: [String: Any]) throws -> String {
                let encodedBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
                // Signed interior whitespace is deliberate. Reserializing a decoded
                // body would silently change the Ed25519 message.
                let exactBody = "{ " + String(decoding: encodedBody.dropFirst(), as: UTF8.self)
                let wire = ["true","","","challenged",exactBody,String(now),"machine-request","hq-request"].joined(separator:"\n")
                let signature = try machine.signature(for: Data(wire.utf8)).base64EncodedString()
                return #"{"ok":true,"state":"challenged","body":"# + exactBody + #","timestamp":"# + String(now)
                    + #","nonce":"machine-request","request_nonce":"hq-request","signature":""# + signature + #""}"#
            }
            let frame = try signedFrame(body)
            let request = try HarnessLaunchChallenge.parse(Data((frame+"\n").utf8), action: action, now: now)
            try HarnessMachinePin.verify(request.machine_key, published: machine.publicKey.rawRepresentation)
            try request.checkOwnerKey(owner.publicKey.x963Representation)
            if action == .qualification {
                let displayed = try action.review(request.plan_canonical, planID: request.plan_id, digest: request.plan_digest)
                precondition(displayed.hasPrefix("Harness qualification run approval\n"))
                for expected in ["Independent runner:", "Test provider configuration:", "Member state: disposable",
                                 "One use: yes", "T03: managed-protected", "T21: managed-cooperative",
                                 "Owner approval permits one qualification run"] {
                    precondition(displayed.contains(expected))
                }
            }
            precondition((try? request.checkOwnerKey(Data(repeating: 0, count:65))) == nil)
            let expected = ["agent-bot-machine-owner/v1",name,machineHex,String(repeating:"45",count:32),
                ownerPin,planID,digest,String(repeating:"12",count:32),String(now+120),""].joined(separator:"\n")
            precondition(request.signedBytes == Data(expected.utf8))
            let softwareProof = try owner.signature(for: request.signedBytes)
            precondition(owner.publicKey.isValidSignature(softwareProof, for: Data(expected.utf8)))
            for other in PairedHarnessPurpose.allCases where other != action {
                precondition((try? HarnessLaunchChallenge.parse(Data(frame.utf8), action: other, now: now)) == nil)
            }
            precondition((try? HarnessLaunchChallenge.parse(Data(frame.utf8), action: action, now: now+120)) == nil)
            for invalid in [frame + "\n{}", frame + "\r\n", frame.replacingOccurrences(of: "{ ", with: "{"),
                frame.replacingOccurrences(of: #""ok":true"#, with: #""ok":true,"ok":true"#),
                frame.replacingOccurrences(of: #""machine_key":"#, with: #""machine_key":"","machine_key":"#),
                frame.replacingOccurrences(of: "hq-request", with: "other-request")] {
                precondition((try? HarnessLaunchChallenge.parse(Data(invalid.utf8), action:action, now:now)) == nil)
            }
            // Exercise the packaged command's real dispatch. This fixture
            // executable lives outside the verified installation, so provenance
            // must refuse before any installed pin, Keychain or UI access.
            func checkCLI(_ frame: String, status: Int32, message: String) throws {
                let process = Process(), input = Pipe(), output = Pipe(), errors = Pipe()
                process.executableURL = URL(fileURLWithPath: CommandLine.arguments[2])
                process.arguments = ["approve-" + name]
                process.standardInput = input; process.standardOutput = output; process.standardError = errors
                try process.run()
                try input.fileHandleForWriting.write(contentsOf: Data((frame+"\n").utf8))
                try input.fileHandleForWriting.close()
                process.waitUntilExit()
                precondition(process.terminationStatus == status && output.fileHandleForReading.readDataToEndOfFile().isEmpty)
                precondition(String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) == message + "\n")
            }
            try checkCLI(frame, status: 69, message: "Machine owner operation unavailable.")
            if action == .qualification {
                precondition(canonical != fixtureCanonical)
                let oldBytes = Data(fixtureCanonical.utf8)
                let oldDigest = SHA256.hash(data: oldBytes).map { String(format: "%02x", $0) }.joined()
                let preview = try reviewHarnessQualification(oldBytes, planID: planID, digest: oldDigest)
                precondition(preview.hasPrefix("Harness qualification plan preview\n"))
                var old = body
                old["plan_canonical"] = fixtureCanonical
                old["plan_digest"] = oldDigest
                let oldFrame = try signedFrame(old)
                precondition((try? HarnessLaunchChallenge.parse(Data(oldFrame.utf8), action: .qualification, now: now)) == nil)
                try checkCLI(oldFrame, status: 1, message: "Invalid Machine owner challenge.")
            }

        }
        print("All paired Machine export purposes passed native validation and uninstalled-provider refusal.")
    }
}
