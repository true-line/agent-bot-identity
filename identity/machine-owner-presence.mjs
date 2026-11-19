// Machine trusts an independently pinned Secure Enclave owner key. The
// general Identity/keyd presence protocol cannot produce Machine owner proofs.
function unavailable() {
  return Object.assign(new Error('This Identity version has no authorized Machine owner-presence provider. Continue using any existing pairing. New approvals must wait for a compatible provider.'), {
    code: 'machine-owner-provider-unavailable',
  });
}

export function machineOwnerPresence(command, { platform = process.platform, terminalInput = process.stdin.isTTY } = {}) {
  if (platform !== 'darwin') throw new Error('Machine owner approval requires macOS');
  if (command !== 'owner-public-key' && command !== 'approve-pairing') throw new Error('unknown Machine owner operation');
  if (command === 'approve-pairing' && terminalInput) throw new Error('provide the Machine pairing challenge JSON on standard input');
  throw unavailable();
}

export async function approveFirstHQ(_challenge, { platform = process.platform } = {}) {
  if (platform !== 'darwin') throw new Error('Machine owner approval requires macOS');
  throw unavailable();
}
