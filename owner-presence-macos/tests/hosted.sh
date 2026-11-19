#!/bin/sh
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
"$src/build.sh" "$dir/build"
app="$dir/build/AgentBotOwnerPresence.app"
/usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
    "$src/PairingChallenge.swift" "$src/FirstHQChallenge.swift" "$src/tests/ChallengeTests.swift" -o "$dir/challenge-tests"
"$dir/challenge-tests" "$src/../tests/fixtures/first-hq-challenge.json"
/usr/bin/codesign --force --sign - "$app"
if "$app/Contents/MacOS/agent-bot-owner-presence" public-key >"$dir/public" 2>"$dir/error"; then
    echo 'ad hoc bundle unexpectedly enrolled an owner key' >&2
    exit 1
fi
test ! -s "$dir/public"
/usr/bin/grep -Fq 'A provisioned Developer ID owner approval application is required' "$dir/error"
