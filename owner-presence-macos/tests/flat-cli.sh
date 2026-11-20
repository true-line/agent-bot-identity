#!/bin/sh
# Build the installed entry point and check its public refusal contract without
# touching an owner store, installing a helper or prompting for presence.
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
sh "$src/build.sh" "$dir/provider"
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
refused "$invalid" sign < /dev/null
refused "$invalid" approve-pairing raw < /dev/null
refused "$invalid" approve-first-hq < /dev/null
refused "$invalid" authorize-first-enrollment 0 --no-prior-enrollment < /dev/null
refused "$invalid" retry-first-enrollment 501 < /dev/null
dd if=/dev/zero bs=2049 count=1 2>/dev/null | refused "$invalid" approve-pairing
refused "$unavailable" init-owner-key < /dev/null
refused "$unavailable" owner-public-key < /dev/null
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
