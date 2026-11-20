import CryptoKit
import Foundation

// Reference bytes from Darwin Machine Plan.Canonical with disposable accounts
// and digests. The retirement reference differs in only its reviewed action
// and the original install receipt. Check both independent Machine digests.
@main struct HarnessLaunchPlanTests {
    static func main() throws {
        let source = try String(contentsOfFile: CommandLine.arguments[1], encoding:.utf8)
        let installDigest = "0b8ecd3ce5241a20da07502c396b36d65e60cf8e6c3312733ca31d84df9f0d09"
        let retireDigest = "e790b19de136ebf7f843c27c3520515738ed3cff36ad08fc02179a827edf1f19"
        let prior = "plan-20261120T120000Z-abcd"
        let current = "plan-20261120T121212Z-dcef"
        let retireURL = URL(fileURLWithPath: CommandLine.arguments[1]).deletingLastPathComponent()
            .appendingPathComponent("harness-launch-retire.json")
        let retire = try String(contentsOf: retireURL, encoding: .utf8)
        func hash(_ text: String) -> String {
            SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        try checkHarnessPlan(source, planID:prior, digest:installDigest, action:.install)
        try checkHarnessPlan(retire, planID:current, digest:retireDigest, action:.retire)
        precondition((try? checkHarnessPlan(source, planID:prior, digest:installDigest, action:.retire)) == nil)
        precondition((try? checkHarnessPlan(retire, planID:prior, digest:retireDigest, action:.retire)) == nil)
        // A valid digest over the transferred retirement cannot substitute
        // for the original installation's digest over this very same mapping.
        for changed in [
            retire.replacingOccurrences(of: installDigest, with: String(repeating: "e", count: 64)),
            retire.replacingOccurrences(of: "--stdio", with: "--changed")
        ] {
            precondition(changed != retire)
            precondition((try? checkHarnessPlan(changed, planID: current, digest: hash(changed), action: .retire)) == nil)
        }

        // Keep each fixed argv within the per-argument limit. Only the total
        // canonical UTF-8 length changes at Machine's 32 KiB boundary.
        func paddedInstall(_ size: Int) -> String {
            let delimiter = #"\",\""#
            let template = source.replacingOccurrences(of: "--stdio", with: Array(repeating: "", count: 32).joined(separator: delimiter))
            var remaining = size - template.utf8.count
            let args = (0..<32).map { _ -> String in
                let n = min(1024, remaining)
                remaining -= n
                return String(repeating: "x", count: n)
            }
            precondition(remaining == 0)
            let text = source.replacingOccurrences(of: "--stdio", with: args.joined(separator: delimiter))
            precondition(text.utf8.count == size)
            return text
        }
        let atLimit = paddedInstall(32768)
        try checkHarnessPlan(atLimit, planID: prior, digest: hash(atLimit), action: .install)
        let overLimit = paddedInstall(32769)
        precondition((try? checkHarnessPlan(overLimit, planID: prior, digest: hash(overLimit), action: .install)) == nil)
        for (original, changed) in [("0644","0664"), ("0440","0644"), ("NOSETENV","SETENV"),
                                    ("harness-egress.sb","other.sb"), ("harness-run","other-run"),
                                    (#""kind":"file""#, #""kind":"file","kind":"file""#)] {
            let modified = source.replacingOccurrences(of:original, with:changed)
            precondition(modified != source)
            let digest = hash(modified)
            precondition((try? checkHarnessPlan(modified, planID:prior, digest:digest, action:.install)) == nil)
        }
    }
}
