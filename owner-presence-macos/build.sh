#!/bin/sh
# Compile an unsigned application into a new output directory for verification
# or the separate, protected Developer ID signing and notarization process.
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: build.sh NEW_OUTPUT_DIRECTORY" >&2
    exit 2
fi
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$1"
contents="$1/AgentBotOwnerPresence.app/Contents"
mkdir -p "$contents/MacOS"
cp "$src/Info.plist" "$contents/Info.plist"
/usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library -O \
    "$src/PairingChallenge.swift" "$src/OwnerKey.swift" "$src/Main.swift" \
    -o "$contents/MacOS/agent-bot-owner-presence"
