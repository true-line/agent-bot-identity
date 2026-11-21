import CoreFoundation
import Foundation

@main enum OwnerCommandLifecycleTests {
    @MainActor static func main() {
        runOwnerCommand {
            // Emulate the outer run loop stopping while an owner operation is
            // waiting for a callback. There is no signer, key, or UI in this test.
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                DispatchQueue.main.async {
                    CFRunLoopStop(CFRunLoopGetMain())
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                        continuation.resume()
                    }
                }
            }
            if CommandLine.arguments.dropFirst().first == "refuse" { return 17 }
            do {
                try FileHandle.standardOutput.write(contentsOf: Data("completed\n".utf8))
                return 0
            } catch { return 1 }
        }
    }
}
