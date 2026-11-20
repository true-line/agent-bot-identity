# First owner enrollment on macOS

Use this procedure only for a first owner enrollment on a Mac with a known installation history. An existing Machine owner pin, historical HQ enrollment or owner key from an earlier provider requires continuity with that owner. Keep an existing pairing in service. The procedure requires a qualified, independently verified release of the flat owner executable installed at `/Library/PrivilegedHelperTools/ai.true-line.agent-bot-owner-presence`.

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
