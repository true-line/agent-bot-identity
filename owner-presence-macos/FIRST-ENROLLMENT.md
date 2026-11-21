# First owner enrollment on macOS

Use this procedure only for a first owner enrollment on a Mac with a known installation history. An existing Machine owner pin, historical HQ enrollment or owner key from an earlier provider requires continuity with that owner. Keep an existing pairing in service. The procedure requires a qualified, independently verified release of the flat owner executable installed at `/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence`.

On first installation, the installer may need to contact Apple for the executable’s notarization ticket. It verifies the approved Developer ID and notarization before publishing the helper.

1. The administrator confirms that this Machine and the selected daily account have never had a Machine owner pairing or HQ enrollment, including custom prefixes, archived state and previous installations. The administrator identifies the selected daily account's numeric UID from its local account record. Run the following command using that UID. The declaration has local effect and expires after five minutes.

   ```sh
   sudo /Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence authorize-first-enrollment UID --no-prior-enrollment
   ```

2. The selected owner signs in to the daily account and runs the following command in that session. It creates the fresh protected owner key and returns its public key. Keep the registration and Machine pairing under administrator control throughout this window. Public-key lookup and approval operations cannot create a key.

   ```sh
   /Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence init-owner-key
   ```

3. The Homebrew prefix owner independently verifies the public key with the owner and pins it from the prefix owner's macOS admin account. Machine still requires its usual challenge and a fresh owner decision to pair HQ.

   ```sh
   managed-machine daemon pair --pin-owner BASE64
   ```

For the browser-based first-HQ plan review, load the organization's approved Developer ID team into the daily account's `settings.keydTeamId` before running `agent-bot machine review-first-hq FILE`. The review verifies the signed helper and the administrator's installation separately.

If a grant expires or initialization stops after consuming the grant, the administrator checks the same enrollment history again. When the host remains unused, the administrator may run `retry-first-enrollment UID --no-prior-enrollment` at the same installed path with `sudo`. It issues a new one-use grant only for the originally selected local account, including its directory-service UUID. An unexpired, unused grant remains available to its owner. An existing authority record or ambiguous history requires operator investigation.

The administrator's command checks the native Homebrew prefix owner, a second installed standard prefix, registered account homes, Machine's HQ UID and peer records, and the protected members receipt directory. Ordinary terminal pairing and the published Machine public key can exist before the first HQ owner pin. The command checks record names and metadata without reading credential contents. The administrator must account for archives, erased state and any custom installation personally. A grant records the observed state at issuance. Machine independently checks current pairing state when the administrator pins the public key.

## Remove the owner CLI

From an administrator-controlled copy of the reviewed installer, supply the publisher team and SHA-256 of the installed signed release.

```sh
sudo /usr/bin/ruby --disable-gems owner-presence-macos/install.rb --uninstall APPROVED_TEAM APPROVED_SHA256
```

Removal checks the executable and its publisher record before deleting either file. The command can be repeated after an interruption. The owner’s Keychain item, first-enrollment history and Machine pin remain available for continuity. Removing the helper does not authorize a fresh enrollment.

## Preview a harness launch plan

The flat helper can display the two file changes and exact adapter arguments in a
saved install or retirement plan. On the paired HQ, obtain the plan ID, SHA-256
and canonical JSON from `machine members-plans get PLAN_ID --socket PATH`.
Use the ID and digest from that verified lookup. Keep the canonical text’s
terminating newline. For example, with the HQ output in `lookup.json`:

```sh
plan_id=$(jq -er '.plan_id' lookup.json)
plan_sha256=$(jq -er '.plan_digest' lookup.json)
jq -jr '.plan_canonical' lookup.json |
  /Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence \
    preview-harness-launch install "$plan_id" "$plan_sha256"
```

Use `retire` to display the original installation ID and digest as well.
The preview checks plan contents against the supplied digest. Authentication
of the lookup occurs on HQ. Preview requires no owner key and issues no proof.

## Preview a single-use qualification plan

Take the plan ID, SHA-256 and exact `plan` string from the Machine
`members plan --harness-qualification` output. Keep the plan's terminating
newline. With the canonical bytes in `plan.json` and the ID and digest from
the same Machine response:

```sh
/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence \
  preview-harness-qualification "$plan_id" "$plan_sha256" < plan.json
```

The preview checks the plan bytes against the supplied digest and displays the
candidate, selected native binary, fixed arguments and code inputs, declared
host, role, fixed runner and test provider, and gate assignments. It shows the
SHA-256 of the original planner request for comparison against that request.
The preview opens no owner key or dialog and produces no proof. A physical
qualification run still requires its own exact owner approval.

## Check the installed Machine public key

From the daily account, the installed owner CLI can check the Homebrew channel
before a timed review. This optional command prints the SHA-256 fingerprint of
the raw Machine public key. The administrator can compare it with the
`fingerprint` from `managed-machine daemon verify-identity`.

```sh
/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence check-machine-pin
```

The check reads only public installation data. The owner Keychain stays closed.
Approval still checks the key against the signed challenge. If the command reports
a group-writable Homebrew prefix or `var` directory, the Homebrew administrator
can inspect its group and write permissions. Group-writable parents must belong
to the `admin` group.

## Approve a paired harness launch rule

On a Mac enrolled with this flat helper, the dedicated HQ exports one
Machine-signed challenge with `machine harness-launch-install export PLAN_ID
--socket SOCKET` or the corresponding `harness-launch-retire` command.
Transfer the complete exported line to the daily owner. In that account's
local desktop session, run the matching command:

```sh
umask 077
/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence \
  approve-harness-launch-install < challenge.json > owner-proof.json
```

For retirement, use `approve-harness-launch-retire`. The helper verifies the
Machine signature against the public key in the administrator-controlled Homebrew
channel and checks the existing owner key. In its native review, inspect the full
arguments, accounts, file changes and digests. Continue to owner authentication
only for the displayed plan. Cancellation, expiry or an unavailable credential
requires a fresh transfer. Return the proof from a successful run to the paired
HQ's `approve --challenge-file challenge.json --proof-file owner-proof.json --socket SOCKET`
command for the same action. Machine consumes the challenge once. Approval and
root application are separate operations. A historical owner key held by a
different provider requires the existing key-continuity procedure.


## Approve harness accounts on a paired Mac

The dedicated HQ exports the saved Machine plan with `machine harness-account-provision export PLAN_ID --socket SOCKET`. Transfer the complete signed line to the daily owner. In the local desktop session, use the existing enrolled owner key:

```sh
umask 077
/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence \
  approve-harness-account-provision < challenge.json > owner-proof.json
```

Review each harness account, its numeric UID, private group and GID, its home and mode, and any broker directories. Check whether Machine will create an account, repair its home mode, or verify an existing role. After confirmation and fresh owner authentication, return the proof via the dedicated HQ's `machine harness-account-provision approve --challenge-file challenge.json --proof-file owner-proof.json --socket SOCKET`. The administrator separately applies the approved plan. Installing or retiring a launch rule requires a separate approval.

## Review a stopped HQ service repair

The paired HQ exports the saved plan with `machine hq-service-recovery export PLAN_ID --socket SOCKET`.
Transfer the complete signed response to the enrolled owner's desktop session. Use a fresh output file for each challenge.

```sh
umask 077
/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence \
  approve-hq-service-recovery < challenge.json > owner-proof.json
```

The review shows the existing dedicated HQ account, the service action, the owner and UID, the archive and Node paths and digests, any runtime directory change and the complete LaunchDaemon configuration. After reviewing those effects and authenticating, return the successful proof through the paired HQ's `machine hq-service-recovery approve --challenge-file challenge.json --proof-file owner-proof.json --socket SOCKET`. Machine checks the current pairing and the stopped service before accepting the proof. The administrator applies the approved plan separately.
