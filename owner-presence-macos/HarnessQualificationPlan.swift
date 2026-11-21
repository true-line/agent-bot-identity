import CryptoKit
import Foundation

private struct QualificationPlan: Decodable {
    struct Step: Decodable { let kind, target, action, content, detail: String }
    let version: Int
    let hq_account, dir: String
    let members: [String]
    let steps: [Step]
    let purpose: String
}

private struct QualificationRun: Decodable {
    struct Gate: Decodable, Equatable {
        let id, profile: String

        func canonical() throws -> String {
            try object([("id", qualificationQuote(id)), ("profile", qualificationQuote(profile))])
        }
    }

    let request_sha256: String
    let request: QualificationRequest
    let member_state: String
    let one_use: Bool
    let gates: [Gate]

    static let requiredGates = ["T01", "T02", "T03"].map {
        Gate(id: $0, profile: "managed-protected")
    } + [Gate(id: "T21", profile: "managed-cooperative")]

    func canonical() throws -> String {
        try object([
            ("request_sha256", qualificationQuote(request_sha256)),
            ("request", request.canonical()),
            ("member_state", qualificationQuote(member_state)),
            ("one_use", one_use ? "true" : "false"),
            ("gates", array(gates.map { try $0.canonical() })),
        ])
    }
}

// The embedded request is rendered by Go json.Marshal, which escapes HTML.
// The outer plan uses the existing Machine canonical encoder with HTML escaping disabled.
private func qualificationQuote(_ text: String) throws -> String {
    try quote(text).replacingOccurrences(of: "&", with: "\\u0026")
        .replacingOccurrences(of: "<", with: "\\u003c")
        .replacingOccurrences(of: ">", with: "\\u003e")
}

private func isDigest(_ text: String) -> Bool { matchesHarnessField(text, "[0-9a-f]{64}") }

private func containsASCIIControl(_ text: String) -> Bool {
    text.utf8.contains { $0 < 0x20 || $0 == 0x7f }
}

private func cleanAbsolutePath(_ path: String) -> Bool {
    path == "/" || (path.first == "/" && !containsASCIIControl(path) && path.dropFirst()
        .split(separator: "/", omittingEmptySubsequences: false)
        .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." })
}

private struct QualificationFile: Decodable {
    let path, sha256: String
    var missing: Bool { path.isEmpty && sha256.isEmpty }
    var valid: Bool { cleanAbsolutePath(path) && isDigest(sha256) }

    func canonical() throws -> String {
        try object([("path", qualificationQuote(path)), ("sha256", qualificationQuote(sha256))])
    }

    func summary(_ label: String) throws -> String {
        try label + ": " + visibleHarnessText(quote(path)) + "  SHA-256: " + sha256
    }
}

private struct QualificationRequest: Decodable {
    struct Binary: Decodable {
        let version, binary_path, binary_sha256: String
        let name, id: String?
        var file: QualificationFile { QualificationFile(path: binary_path, sha256: binary_sha256) }

        func canonical(key: String, value: String) throws -> String {
            try object([(key, qualificationQuote(value)), ("version", qualificationQuote(version)),
                        ("binary_path", qualificationQuote(binary_path)), ("binary_sha256", qualificationQuote(binary_sha256))])
        }
    }

    struct Launch: Decodable {
        let executable, executable_sha256: String
        let argv: [String]
        let code_inputs: [QualificationFile]
        let code_inputs_manifest, driver: QualificationFile
        var file: QualificationFile { QualificationFile(path: executable, sha256: executable_sha256) }

        func canonical() throws -> String {
            try object([
                ("executable", qualificationQuote(executable)), ("executable_sha256", qualificationQuote(executable_sha256)),
                ("argv", array(argv.map(qualificationQuote))),
                ("code_inputs", array(code_inputs.map { try $0.canonical() })),
                ("code_inputs_manifest", code_inputs_manifest.canonical()), ("driver", driver.canonical()),
            ])
        }
    }

    struct Adapter: Decodable {
        let id, version, package_path, package_sha256: String
        let launch: Launch
        let harness: Binary
        var package: QualificationFile { QualificationFile(path: package_path, sha256: package_sha256) }

        func canonical() throws -> String {
            guard let name = harness.name else { throw PresenceFailure.invalidChallenge }
            return try object([
                ("id", qualificationQuote(id)), ("version", qualificationQuote(version)),
                ("package_path", qualificationQuote(package_path)), ("package_sha256", qualificationQuote(package_sha256)),
                ("launch", launch.canonical()), ("harness", harness.canonical(key: "name", value: name)),
            ])
        }
    }

    struct Target: Decodable {
        let account: String
        let uid: Int

        func canonical() throws -> String {
            try object([("account", qualificationQuote(account)), ("uid", String(uid))])
        }
    }

    struct Host: Decodable {
        let id, model, os, os_version, os_build, architecture, enforcement_policy_sha256: String

        func canonical() throws -> String {
            try object([
                ("id", qualificationQuote(id)), ("model", qualificationQuote(model)), ("os", qualificationQuote(os)),
                ("os_version", qualificationQuote(os_version)), ("os_build", qualificationQuote(os_build)),
                ("architecture", qualificationQuote(architecture)), ("enforcement_policy_sha256", qualificationQuote(enforcement_policy_sha256)),
            ])
        }
    }

    struct Provider: Decodable {
        let id, configuration_path, configuration_sha256: String
        var file: QualificationFile { QualificationFile(path: configuration_path, sha256: configuration_sha256) }

        func canonical() throws -> String {
            try object([("id", qualificationQuote(id)), ("configuration_path", qualificationQuote(configuration_path)),
                        ("configuration_sha256", qualificationQuote(configuration_sha256))])
        }
    }

    let schema_version: Int
    let adapter: Adapter
    let target: Target
    let host: Host
    let definition_revision, suite_revision: String
    let runner: Binary
    let test_provider: Provider

    func canonical() throws -> String {
        guard let runnerID = runner.id else { throw PresenceFailure.invalidChallenge }
        return try object([
            ("schema_version", String(schema_version)), ("adapter", adapter.canonical()), ("target", target.canonical()),
            ("host", host.canonical()), ("definition_revision", qualificationQuote(definition_revision)),
            ("suite_revision", qualificationQuote(suite_revision)), ("runner", runner.canonical(key: "id", value: runnerID)),
            ("test_provider", test_provider.canonical()),
        ])
    }

    func checkedIdentities() throws -> (harness: String, runner: String) {
        let launch = adapter.launch
        guard let harnessName = adapter.harness.name, let runnerID = runner.id,
              schema_version == 1, (300...399).contains(target.uid),
              host.os == "darwin", host.architecture == "arm64", isDigest(host.enforcement_policy_sha256),
              [definition_revision, suite_revision].allSatisfy({ matchesHarnessField($0, "[0-9a-f]{40}") }),
              [adapter.id, adapter.version, harnessName, adapter.harness.version, target.account, host.id, host.model,
               host.os_version, host.os_build, runnerID, runner.version, test_provider.id].allSatisfy({
                   !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !containsASCIIControl($0) && $0.utf8.count <= 256
               }),
              [adapter.package, launch.file, adapter.harness.file, runner.file, test_provider.file].allSatisfy(\.valid),
              launch.argv.count <= 128, launch.argv.allSatisfy({ !containsASCIIControl($0) && $0.utf8.count <= 4096 }),
              launch.code_inputs.count <= 2048, launch.code_inputs.allSatisfy(\.valid),
              Set(launch.code_inputs.map { Data($0.path.utf8) }).count == launch.code_inputs.count,
              launch.code_inputs.isEmpty ? launch.code_inputs_manifest.valid : launch.code_inputs_manifest.missing,
              launch.driver.missing || launch.driver.valid
        else { throw PresenceFailure.invalidChallenge }
        return (harnessName, runnerID)
    }
}

let maximumQualificationPlanBytes = 28 * 1024

func reviewHarnessQualification(_ data: Data, planID: String, digest: String) throws -> String {
    let invalid = PresenceFailure.invalidChallenge
    guard data.count <= maximumQualificationPlanBytes, matchesHarnessField(planID, "plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}"),
          SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == digest
    else { throw invalid }
    let p = try JSONDecoder().decode(QualificationPlan.self, from: data)
    let detail = "Review only: declared host identity, fixed conformance gates, pinned runner and test provider, disposable member state; no install or launch authorization."
    guard p.version == 3, p.hq_account == "_agent-bot-hq", p.dir == "/Library/Application Support/ai.true-line.agent-bot-hq/ipc",
          p.members.isEmpty, p.steps.count == 1, p.purpose == "harness-qualification-run",
          let step = p.steps.first, step.kind == "qualification-run", step.action == "none", step.detail == detail
    else { throw invalid }
    let run = try JSONDecoder().decode(QualificationRun.self, from: Data(step.content.utf8))
    let r = run.request, launch = r.adapter.launch
    guard step.target.utf8.elementsEqual(r.adapter.id.utf8), isDigest(run.request_sha256),
          run.member_state == "disposable", run.one_use, run.gates == QualificationRun.requiredGates,
          Data(try run.canonical().utf8) == Data(step.content.utf8)
    else { throw invalid }
    let names = try r.checkedIdentities()
    let canonicalStep = try object([
        ("kind", quote(step.kind)), ("target", quote(step.target)), ("action", quote(step.action)),
        ("content", quote(step.content)), ("detail", quote(step.detail)),
    ])
    let canonical = try object([
        ("version", "3"), ("hq_account", quote(p.hq_account)), ("dir", quote(p.dir)), ("members", "[]"),
        ("steps", array([canonicalStep])), ("purpose", quote(p.purpose)),
    ]) + "\n"
    guard Data(canonical.utf8) == data else { throw invalid }

    func display(_ text: String) throws -> String { try visibleHarnessText(quote(text)) }
    var lines = try [
        "Harness qualification plan preview",
        "Plan: " + planID, "Plan SHA-256: " + digest, "Original request SHA-256: " + run.request_sha256,
        "Candidate adapter: " + display(r.adapter.id) + "  Version: " + display(r.adapter.version),
        r.adapter.package.summary("Package"),
        "Harness: " + display(names.harness) + "  Version: " + display(r.adapter.harness.version),
        r.adapter.harness.file.summary("Native binary"), launch.file.summary("Launch executable"),
        "Target account: " + display(r.target.account) + "  UID: " + String(r.target.uid),
        "Declared host: " + display(r.host.id) + "  Model: " + display(r.host.model),
        "Host OS: darwin  Version: " + display(r.host.os_version) + "  Build: " + display(r.host.os_build) + "  Architecture: arm64",
        "Enforcement policy SHA-256: " + r.host.enforcement_policy_sha256,
        "Definition revision: " + r.definition_revision, "Suite revision: " + r.suite_revision,
        "Independent runner: " + display(names.runner) + "  Version: " + display(r.runner.version),
        r.runner.file.summary("Runner binary"),
        "Test provider: " + display(r.test_provider.id),
        r.test_provider.file.summary("Test provider configuration"),
        "Member state: disposable", "One use: yes", detail,
    ]
    for (i, arg) in ([launch.executable] + launch.argv).enumerated() {
        lines.append(try "argv[\(i)] " + display(arg))
    }
    lines += try launch.code_inputs.map { try $0.summary("Fixed code input") }
    if !launch.code_inputs_manifest.missing { lines.append(try launch.code_inputs_manifest.summary("Code input manifest")) }
    if !launch.driver.missing { lines.append(try launch.driver.summary("Driver")) }
    lines += run.gates.map { "\($0.id): \($0.profile)" }
    lines += ["Full canonical plan (non-ASCII shown as Unicode escapes)", visibleHarnessText(canonical)]
    return lines.joined(separator: "\n")
}
