"""Read-only tests for the flat qualification-plan preview."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

provider, fixture = sys.argv[1:]
plan_id = "plan-20261121T181029Z-7aaf"
digest = "bcb92029dfefdc36c87eb6d48b0d851216206b68c659e940fc659c992767889a"
raw = Path(fixture).read_bytes()
assert sha256(raw).hexdigest() == digest
plan = json.loads(raw)
run = json.loads(plan["steps"][0]["content"])


def preview(source, supplied_digest, command="preview-harness-qualification"):
    return subprocess.run([provider, command, plan_id, supplied_digest], input=source,
                          capture_output=True, timeout=10)


def refuses(source, supplied_digest=None):
    result = preview(source, supplied_digest or sha256(source).hexdigest())
    assert (result.returncode, result.stdout, result.stderr) == (
        1, b"", b"Invalid Machine owner challenge.\n")


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("\u2028", r"\u2028").replace("\u2029", r"\u2029")


def packed(body, **outer_fields):
    changed = deepcopy(plan)
    changed.update(outer_fields)
    changed["steps"][0]["content"] = encode(body).replace("&",r"\u0026").replace("<",r"\u003c").replace(">",r"\u003e")
    return (encode(changed) + "\n").encode()


result = preview(raw, digest)
assert result.returncode == 0 and result.stderr == b""
for field in (
    digest.encode(), run["request_sha256"].encode(), b'Candidate adapter: "fixture-adapter"',
    b'Target account: "_abh-ci-proof-a"  UID: 310', b'Declared host: "fixture-virtual-host"',
    b'Independent runner: "fixture-runner"', b'Test provider: "fixture-provider"',
    b'Native binary: "/usr/bin/true"', b'Driver:', b'Fixed code input:', b'One use: yes',
    b'T01: managed-protected', b'T02: managed-protected', b'T03: managed-protected', b'T21: managed-cooperative',
):
    assert field in result.stdout
assert b"argv[1]" not in result.stdout
refuses(raw, "0" * 64)
refuses(raw[:-1])
refuses(b"x" * (28 * 1024 + 1))
refuses(packed(run, purpose="harness-launch-install"))
refuses(raw.replace(b'"version":3', b'"version":3,"version":3', 1))

changed = deepcopy(run)
changed["request"]["test_provider"]["configuration_sha256"] = "f" * 64
refuses(packed(changed), digest)
changed = deepcopy(run)
changed["gates"][-1]["profile"] = "managed-protected"
refuses(packed(changed))
refuses(packed({**run, "one_use": False}))
refuses(packed({**run, "command": "/usr/bin/true"}))

changed = deepcopy(run)
launch = changed["request"]["adapter"]["launch"]
launch["code_inputs_manifest"] = launch["code_inputs"][0]
refuses(packed(changed))
launch["code_inputs"] = []
launch["driver"] = {"path": "", "sha256": ""}
launch["argv"] = ["--flag", "<first>&second", "a\u202eb"]
encoded = packed(changed)
result = preview(encoded, sha256(encoded).hexdigest())
assert result.returncode == 0 and result.stderr == b""
assert b"Code input manifest:" in result.stdout and b"Driver:" not in result.stdout
assert b'argv[2] "<first>&second"' in result.stdout and rb'argv[3] "a\u202eb"' in result.stdout

# The preview purpose cannot select an owner approval command.
refusal = preview(raw, digest, "approve-harness-qualification")
assert (refusal.returncode, refusal.stdout, refusal.stderr) == (
    1, b"", b"Invalid Machine owner challenge.\n")
print("Qualification plan preview and binding checks passed.")
