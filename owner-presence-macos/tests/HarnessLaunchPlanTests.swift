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
        let retire = source.replacingOccurrences(of: #""action":"create""#, with: #""action":"remove""#)
            .replacingOccurrences(of: #"\"action\":\"install\""#, with: #"\"action\":\"retire\""#)
            .replacingOccurrences(of: #"\"installed_plan_id\":\"\""#, with: "\\\"installed_plan_id\\\":\\\"" + prior + "\\\"")
            .replacingOccurrences(of: #"\"installed_plan_digest\":\"\""#, with: "\\\"installed_plan_digest\\\":\\\"" + installDigest + "\\\"")
        try checkHarnessPlan(source, planID:prior, digest:installDigest, action:.install)
        try checkHarnessPlan(retire, planID:current, digest:retireDigest, action:.retire)
        precondition((try? checkHarnessPlan(source, planID:prior, digest:installDigest, action:.retire)) == nil)
        precondition((try? checkHarnessPlan(retire, planID:prior, digest:retireDigest, action:.retire)) == nil)
        for (original, changed) in [("0644","0664"), ("0440","0644"), ("NOSETENV","SETENV"),
                                    ("harness-egress.sb","other.sb"), ("harness-run","other-run"),
                                    (#""kind":"file""#, #""kind":"file","kind":"file""#)] {
            let modified = source.replacingOccurrences(of:original, with:changed)
            precondition(modified != source)
            let digest = SHA256.hash(data:Data(modified.utf8)).map { String(format:"%02x",$0) }.joined()
            precondition((try? checkHarnessPlan(modified, planID:prior, digest:digest, action:.install)) == nil)
        }
    }
}
