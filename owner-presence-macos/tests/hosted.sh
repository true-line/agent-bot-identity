#!/bin/sh
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
/usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
    "$src/PairingChallenge.swift" "$src/FirstHQChallenge.swift" "$src/OwnerKey.swift" "$src/tests/ChallengeTests.swift" -o "$dir/challenge-tests"
"$dir/challenge-tests" "$src/../tests/fixtures/first-hq-challenge.json"
