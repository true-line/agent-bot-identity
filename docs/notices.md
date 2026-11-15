# Notices: GitHub App events from the agent-bot server

In server mode (`AGENT_BOT_SERVER` set and this machine enrolled with
`agent-bot server enroll`), GitHub App webhooks are received by the agent-bot
server (`<server>/apps/webhook/<app slug>`) instead of the gh-app-hook Worker,
and sessions read them with a lease-based **take / ack** contract that replaces
`take_inbox`.

## CLI

```bash
agent-bot notices take --count 5 --type discussion        # lease up to 5, oldest first
agent-bot notices take --type pr,review --kind review_requested --repo true-line/agent-bot
agent-bot notices peek --type comment                     # look without leasing
agent-bot notices ack <lease> [<lease>...]                # done: delete them
agent-bot notices release <lease>                         # not mine: hand back now
```

`--json` prints the server response. `--harness` picks the harness when the
device holds several; by default the device's only harness is used.

## MCP tools (agent-bot mcp, requires bind)

`take_notices`, `peek_notices`, `ack_notices`, `release_notices`. `tools/list`
advertises only the meta-tools — `search_tools`, `describe_tool`, `call_tool`
(reads) and `call_write_tool` (writes) — but the notice names still work when
called directly. The App (and so
the server harness) comes from the bound soul's record, never from the caller;
filters come from the caller.

## Semantics

- **Filters**: `type` = discussion, issue, pr, review, comment (plurals ok). A
  notice carries its subject *and* its activity, so `type=discussion` includes
  discussion comments and `type=comment` matches comments anywhere. `kind` =
  `mention`, `review_requested` or `<event>.<action>`. `repo` = `owner/name`.
  `since` = RFC3339 or unix time. Lists are comma-separated (OR); filters AND.
- **count** 1..50 (default 10). **lease_seconds** 10..3600 (default 300).
- Each taken notice has `id` (the GitHub delivery id), `lease`, `attempts` and
  `lease_expires_at`; the response has `remaining` (matching, still visible) and
  `next_lease_expiry`.
- Un-acked notices become visible again when the lease expires. Acking with a
  lease that has expired or been re-taken is reported as `stale` and does not
  delete the notice. Notices are kept 7 days.

## take_inbox (deprecated)

`take_inbox` still works. In server mode it is a shim: it takes one notice for
the bound worktree's repository, acks it immediately and returns it as
`{ event }` (at-most-once). Without server mode it still pulls from the
gh-app-hook Worker. New code should use `take_notices` + `ack_notices`.


## HQ compatibility adapter preparation

[Accepted PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
defines the future HQ-backed handoff. `identity/hq-inbox-client.mjs` prepares
only its member-side adapter; the installed CLI and MCP paths above are
unchanged. It is not a new daemon or remote queue implementation.

An integration host must supply an already-bound `request(kind, payload)`, a
`currentRuntime()` returning only `{installation_epoch, lease_generation}`,
shared `validateQuery`/`validateResult` callbacks returning SDK error arrays,
and the SDK `canonicalBytes`. The callbacks must use the supported verified
contract release; missing validation refuses construction. `takeInbox()`
takes no arguments or queue selectors. It sends `notices.consume-one` once,
validates the response before legacy mapping, and propagates refusals or an
unknown transport outcome without reconnecting, replaying or calling Harbor.
The injected request implementation must likewise never automatically replay
a destructive call. Shared payload/compatibility rules live in
[soul-contracts](https://github.com/true-line/soul-contracts/blob/main/schemas/hq/v1/notices.md).

The shared authenticated member-query transport, its no-replay policy, the
actual release/pin and MCP wiring remain prerequisites tracked in
[#1441](https://github.com/true-line/agent-bot-identity/issues/1441). The adapter
has no credential, binding-proof, runtime-discovery or scope policy code.
Existing standalone clients must not compete with a migrated queue; the
owner's service custody gate and dedicated device key enforce that boundary.
No standalone flag or SDK injection activates production custody. Overall
alias parity remains open in [HQ #13](https://github.com/true-line/agent-bot-hq/issues/13).
