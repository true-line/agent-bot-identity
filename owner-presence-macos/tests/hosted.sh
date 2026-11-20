#!/bin/sh
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
/usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
    "$src/PairingChallenge.swift" "$src/FirstHQChallenge.swift" "$src/OwnerKey.swift" "$src/tests/ChallengeTests.swift" -o "$dir/challenge-tests"
"$dir/challenge-tests" "$src/../tests/fixtures/first-hq-challenge.json"

target="$(/usr/bin/uname -m)-apple-macosx15.0"
/usr/bin/xcrun --sdk macosx clang -target "$target" -Wno-deprecated-declarations -c "$src/TrustedApplication.c" -o "$dir/trusted.o"
/usr/bin/xcrun --sdk macosx swiftc -target "$target" -swift-version 5 -parse-as-library -D FRESH_OWNER_STORE_TESTS \
    "$src/PairingChallenge.swift" "$src/FirstHQChallenge.swift" "$src/OwnerKey.swift" \
    "$src/FreshOwnerStore.swift" "$src/tests/FreshOwnerStoreTests.swift" "$dir/trusted.o" -o "$dir/store-tests"
"$dir/store-tests"
/usr/bin/xcrun --sdk macosx swiftc -target "$target" -swift-version 5 -parse-as-library \
    "$src/OwnerFirstEnrollment.swift" "$src/tests/FirstEnrollmentTests.swift" -o "$dir/enrollment-tests"
"$dir/enrollment-tests"
sh "$src/tests/flat-cli.sh"

if [ "$#" -gt 0 ]; then
    test "$#" -eq 1
    test "$1" = --hosted-first-enrollment
    test "${GITHUB_ACTIONS:-}" = true
    test "${OWNER_PERMIT_RUNNER:-}" = github-hosted
    test "${RUNNER_OS:-}" = macOS
    "$dir/store-tests" --disposable-keychain
    uid=$(/usr/bin/id -u)
    test "$uid" -ge 501
    /usr/bin/xcrun --sdk macosx swiftc -target "$(/usr/bin/uname -m)-apple-macosx15.0" -swift-version 5 -parse-as-library \
        "$src/OwnerFirstEnrollment.swift" "$src/tests/FirstEnrollmentAccountTests.swift" -o "$dir/permit-account-tests"
    # mktemp creates the scratch directory as root. Only its grant subdirectory ever
    # belongs to the runner account. All privileged fixture commands run from its protected copy.
    fixture=$(/usr/bin/sudo -n /usr/bin/mktemp -d /private/tmp/owner-enrollment-ci.XXXXXXXX)
    trap '/usr/bin/sudo -n /bin/rm -rf "$fixture"; /bin/rm -rf "$dir"' EXIT
    /usr/bin/sudo -n /usr/bin/install -o root -g wheel -m 0555 "$dir/permit-account-tests" "$fixture/check"
    /usr/bin/sudo -n /bin/chmod 0755 "$fixture"
    /usr/bin/sudo -n "$fixture/check" issue "$fixture" "$uid"
    "$fixture/check" use "$fixture" "$uid"
    "$fixture/check" used "$fixture" "$uid"
    /usr/bin/sudo -n "$fixture/check" retry "$fixture" "$uid"
    "$fixture/check" use "$fixture" "$uid"
    echo "Verified root issuance, registered daily UID consumption, one use and explicit admin retry."
fi
