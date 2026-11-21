# Existing macOS pilot owner

Use this tool from a private source checkout on a Mac whose administrator already pinned the owner key from the pilot app. It uses the same owner gate, first-HQ review page and macOS consent prompt as the earlier pilot. The regular Identity commands use the provider supplied by that Identity release.

From the daily owner account, specify the previously confirmed public key file. It contains the original uncompressed P-256 public key in base64. Compare the file with the original enrollment record if its provenance is uncertain. The pairing challenge and first-HQ transfer do not contain this owner pin.

```sh
node tools/private-pilot/machine-owner.mjs --owner-pin-file original-owner.pub approve-pairing < challenge.json > proof.json
node tools/private-pilot/machine-owner.mjs --owner-pin-file original-owner.pub review-first-hq challenge.json
```

When the daily account also owns the standard Homebrew prefix, omit `--owner-pin-file` to read the existing owner field from that account’s private Machine pairing record. If the separate daily account has lost its confirmed public copy, the Machine administrator can hand it the public owner field again. Keep the private pairing record in the administrator account.

A missing or unverifiable pilot provider, a signed proof from a different owner, or an expired challenge stops the operation. Recover the existing provider and confirmed public pin before retrying. This tool requests proofs only. The Machine administrator still verifies and consumes each proof.
