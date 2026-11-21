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
        for action in PairedHarnessPurpose.allCases {
            let name = action.rawValue
            let file = action == .provision ? "harness-account-provision-accounts-and-broker" : name
            let canonical = try String(contentsOf: fixtures.appendingPathComponent(file + ".json"), encoding: .utf8)
            let digest = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
            let planID = "plan-20261120T122100Z-dcef"
            let body: [String:Any] = ["action":name,"machine_key":machineHex,"hq_key":String(repeating:"45", count:32),
                "owner_key":ownerPin,"plan_id":planID,"plan_digest":digest,"nonce":String(repeating:"12",count:32),
                "expires_at":now+120,"plan_canonical":canonical]
            let encodedBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
            // Signed interior whitespace is deliberate. Reserializing a decoded
            // body would silently change the Ed25519 message.
            let exactBody = "{ " + String(decoding: encodedBody.dropFirst(), as: UTF8.self)
            let wire = ["true","","","challenged",exactBody,String(now),"machine-request","hq-request"].joined(separator:"\n")
            let signature = try machine.signature(for: Data(wire.utf8)).base64EncodedString()
            let frame = #"{"ok":true,"state":"challenged","body":"# + exactBody + #","timestamp":"# + String(now)
                + #","nonce":"machine-request","request_nonce":"hq-request","signature":""# + signature + #""}"#
            let request = try HarnessLaunchChallenge.parse(Data((frame+"\n").utf8), action: action, now: now)
            try HarnessMachinePin.verify(request.machine_key, published: machine.publicKey.rawRepresentation)
            try request.checkOwnerKey(owner.publicKey.x963Representation)
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
            let process = Process(), input = Pipe(), output = Pipe(), errors = Pipe()
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[2])
            process.arguments = ["approve-" + name]
            process.standardInput = input; process.standardOutput = output; process.standardError = errors
            try process.run()
            try input.fileHandleForWriting.write(contentsOf: Data((frame+"\n").utf8))
            try input.fileHandleForWriting.close()
            process.waitUntilExit()
            precondition(process.terminationStatus == 69 && output.fileHandleForReading.readDataToEndOfFile().isEmpty)
            precondition(String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) == "Machine owner operation unavailable.\n")
        }
        print("All three signed HQ export purposes passed native validation and uninstalled-provider refusal.")
    }
}
