#!/bin/sh
# Build the installed entry point and check its public refusal contract without
# touching an owner store, installing a helper or prompting for presence.
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
/usr/bin/xcrun --sdk macosx swiftc -target "$(uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
    "$src/OwnerCommandLifecycle.swift" "$src/tests/OwnerCommandLifecycleTests.swift" -o "$dir/lifecycle"
"$dir/lifecycle" > "$dir/completion"
test "$(cat "$dir/completion")" = completed
status=0
"$dir/lifecycle" refuse > "$dir/completion" || status=$?
test "$status" -eq 17
test ! -s "$dir/completion"

sh "$src/build.sh" "$dir/provider"
/usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
    "$src/PairingChallenge.swift" "$src/HarnessLaunchPlan.swift" "$src/HarnessAccountPlan.swift" "$src/HQServiceRecoveryPlan.swift" "$src/SoulPlanReview.swift" "$src/HarnessQualificationPlan.swift" "$src/HarnessLaunchChallenge.swift" "$src/HarnessMachinePin.swift" \
    "$src/tests/HarnessExportTests.swift" -o "$dir/export-tests"
"$dir/export-tests" "$src/../tests/fixtures" "$dir/provider"
refused() {
    reason=$1
    shift
    status=0
    "$dir/provider" "$@" > "$dir/stdout" 2> "$dir/stderr" || status=$?
    expected=1
    if [ "$reason" = "$unavailable" ]; then expected=69; fi
    test "$status" = "$expected"
    test ! -s "$dir/stdout"
    test "$(cat "$dir/stderr")" = "$reason"
}
invalid='Invalid Machine owner challenge.'
unavailable='Machine owner operation unavailable.'
# These are exact Machine-produced plan bytes and their independently recorded digests.
fixtures="$src/../tests/fixtures"
install_id=plan-20261120T120000Z-abcd
retire_id=plan-20261120T121212Z-dcef
install_digest=0b8ecd3ce5241a20da07502c396b36d65e60cf8e6c3312733ca31d84df9f0d09
retire_digest=e790b19de136ebf7f843c27c3520515738ed3cff36ad08fc02179a827edf1f19
"$dir/provider" preview-harness-launch install "$install_id" "$install_digest" < "$fixtures/harness-launch-install.json" > "$dir/preview"
grep -F -q 'argv[1] "--stdio"' "$dir/preview"
grep -F -q 'root:wheel 0440' "$dir/preview"
grep -F -q 'NOSETENV:' "$dir/preview"
"$dir/provider" preview-harness-launch retire "$retire_id" "$retire_digest" < "$fixtures/harness-launch-retire.json" > "$dir/preview"
grep -F -q "Installed plan: $install_id" "$dir/preview"
grep -F -q "Installed plan SHA-256: $install_digest" "$dir/preview"
refused "$invalid" preview-harness-launch retire "$retire_id" "$install_digest" < "$fixtures/harness-launch-retire.json"
refused "$invalid" preview-harness-launch install "$retire_id" "$retire_digest" < "$fixtures/harness-launch-retire.json"
{ printf '\357\273\277'; cat "$fixtures/harness-launch-install.json"; } |
  refused "$invalid" preview-harness-launch install "$install_id" "$install_digest"
dd if=/dev/zero bs=32769 count=1 2>/dev/null | refused "$invalid" preview-harness-launch install "$install_id" "$install_digest"
/usr/bin/python3 -IB "$src/tests/qualification-preview.py" "$dir/provider" "$fixtures/harness-qualification-run.json"
refused "$invalid" approve-harness-launch-install < "$fixtures/harness-launch-install.json"
refused "$invalid" approve-harness-launch-retire < "$fixtures/harness-launch-retire.json"
refused "$invalid" sign < /dev/null
refused "$invalid" approve-pairing raw < /dev/null
refused "$invalid" approve-first-hq < /dev/null
refused "$invalid" authorize-first-enrollment 0 --no-prior-enrollment < /dev/null
refused "$invalid" retry-first-enrollment 501 < /dev/null
dd if=/dev/zero bs=2049 count=1 2>/dev/null | refused "$invalid" approve-pairing
refused "$unavailable" init-owner-key < /dev/null
refused "$unavailable" owner-public-key < /dev/null
refused "$unavailable" check-machine-pin < /dev/null
refused "$invalid" check-machine-pin extra < /dev/null
refused "$unavailable" authorize-first-enrollment 501 --no-prior-enrollment < /dev/null
if sh "$src/build.sh" "$dir/provider" 2>/dev/null; then exit 1; fi
/usr/bin/ruby --disable-gems - "$src/install.rb" "$dir" <<'RUBY'
require File.realpath(ARGV[0])
# The installer must request Apple's ticket on a cold Mac, while keeping the
# exact publisher, identifier and notarization requirement on the same bytes.
class << OwnerHelperInstall
  attr_accessor :verification_result
  def system(tool, *args, **io)
    expected = ["--verify", "--strict", "--all-architectures", "--check-notarization"]
    raise unless tool == "/usr/bin/codesign" && args.take(4) == expected && args.length == 6
    requirement, path = args.last(2)
    raise unless requirement.start_with?("-R=anchor apple generic and identifier \"ai.true-line.agent-bot-owner-presence\"")
    raise unless requirement.include?('certificate leaf[subject.OU] = "ABCDE12345"') && requirement.end_with?(" and notarized")
    raise unless path == "staged-binary" && io == {out: File::NULL, err: File::NULL}
    verification_result
  end
end
OwnerHelperInstall.verification_result = true
OwnerHelperInstall.verify_release("staged-binary", "ABCDE12345")
OwnerHelperInstall.verification_result = false
begin
  OwnerHelperInstall.verify_release("staged-binary", "ABCDE12345")
  abort "Unverified release was accepted"
rescue OwnerHelperInstall::ReleaseVerificationError
end
src = File.join(ARGV[1], "install-source")
dst = File.join(ARGV[1], "install-destination")
File.binwrite(src, "verified fixture")
OwnerHelperInstall.publish(src, dst, 0o555)
raise unless !File.exist?(src) && File.stat(dst).nlink == 1
File.binwrite(src, "different fixture")
begin
  OwnerHelperInstall.publish(src, dst, 0o555)
  abort "Existing unrelated file was accepted"
rescue RuntimeError
  raise unless File.binread(dst) == "verified fixture" && File.binread(src) == "different fixture"
end
RUBY
echo 'Flat owner CLI and installer refusal checks passed.'
