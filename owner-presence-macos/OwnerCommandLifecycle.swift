import CoreFoundation
import Darwin
import Foundation

// A nested AppKit loop can stop the main loop while the command is suspended.
// Only the completed command decides when the process exits and with which status.
@MainActor func runOwnerCommand(_ operation: @escaping @MainActor () async -> Int32) -> Never {
    // Keep the loop asleep while the command is waiting for its next callback.
    RunLoop.main.add(Port(), forMode: .default)
    Task { @MainActor in exit(await operation()) }
    while true { CFRunLoopRun() }
}
