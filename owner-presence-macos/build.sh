#!/bin/sh
# Produce one flat Mach-O. The protected release process signs the resulting bytes.
set -eu
if [ "$#" -ne 1 ] || [ "$(uname -s)" != Darwin ] || [ -e "$1" ] || [ -L "$1" ]; then
    echo "usage: build.sh NEW_OUTPUT_FILE" >&2
    exit 2
fi
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
out=$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
build=$(mktemp -d "$(dirname -- "$out")/.owner-build.XXXXXXXX")
trap 'rm -rf "$build"' EXIT
target=$(/usr/bin/uname -m)-apple-macosx15.0
/usr/bin/xcrun --sdk macosx clang -target "$target" -Wno-deprecated-declarations -c \
    "$src/TrustedApplication.c" -o "$build/trusted.o"
/usr/bin/xcrun --sdk macosx swiftc -O -target "$target" -swift-version 5 -parse-as-library \
    -module-name AgentBotOwnerPresence \
    "$src/PairingChallenge.swift" "$src/FirstHQChallenge.swift" "$src/HarnessLaunchPlan.swift" "$src/HarnessAccountPlan.swift" "$src/HQServiceRecoveryPlan.swift" "$src/SoulPlanReview.swift" "$src/HarnessLaunchChallenge.swift" "$src/HarnessMachinePin.swift" "$src/HarnessNativeReview.swift" "$src/OwnerKey.swift" \
    "$src/FreshOwnerStore.swift" "$src/OwnerFirstEnrollment.swift" "$src/OwnerExecutable.swift" "$src/Main.swift" "$build/trusted.o" \
    "$src/OwnerCommandLifecycle.swift" "$src/HarnessQualificationPlan.swift" -o "$build/ai.true-line.agent-bot-owner-presence"
ln "$build/ai.true-line.agent-bot-owner-presence" "$out"
