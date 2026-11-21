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


## Existing MCP command with an HQ member context

[Accepted PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
defines the HQ-backed handoff. The existing `agent-bot mcp` command selects
that inbox backend when the Soul supplies its member socket/token environment.
The public SDK authenticates the existing member token and binds its broker
connection; identity neither copies that protocol nor grants scope. No new
CLI flag, ACP server-slot launcher or direct upstream client is involved.

Only `take_inbox` changes backend. MCP discovery and other tool names remain
available; explicitly invoked unmigrated tools retain their legacy client.
The legacy client is lazy: an HQ inbox call never constructs it or attempts a
legacy worktree bind. A partial member environment refuses the inbox call;
HQ refusal, missing scope or unavailable dependencies never trigger fallback.
Outside a member context the existing standalone behavior remains separate.
It must not compete with a migrated queue; the service custody gate and
dedicated device key retain that boundary.

The leaf adapter accepts the public SDK `queries` capability. It builds and
validates its query synchronously inside the SDK's captured freshness attempt,
with `replay: "never"`. `takeInbox()` accepts no selectors. It checks the full
reply's shared schema, correlation, operation, capability and canonical byte
limits before producing the legacy event or `{event:null}`. The shared
[compatibility table](https://github.com/true-line/soul-contracts/blob/main/schemas/hq/v1/notices.md)
remains the payload's home. EOF, stream failure and process shutdown close the
SDK owner; no credential, binding or raw socket capability is returned to MCP.
A lost consume reply has an unknown outcome: do not blindly retry it.

### Dependency and acceptance status

The shipped `identity/hq-member-contracts.json` pins the genuine
[soul-contracts v0.5.0 release](https://github.com/true-line/soul-contracts/releases/tag/v0.5.0)
at `b96239cc47571237f7064ddbcbd0edec8e365c6b`, with the manifest digest and
154-file scope. Before opening a socket, the runtime requires an offline
directory whose bytes and modes reproduce that exact manifest.
`AGENT_BOT_SOUL_CONTRACTS` locates the directory; it cannot change the required
release or digest. Missing or altered data refuses before SDK/legacy effects.
There is no runtime network fetch or alternate schema override. The declaration
lives beside runtime code because packaging omits `governance/`.

The SDK modules are vendored byte-for-byte from the full source commit in
`identity/vendor/agent-bot-sdk/source.json`, with per-file hashes and LICENSE.
The signal-capable SDK source is merged PR #139 commit
`42d6f5110019f4b7d835e139875b89a75230afe1`. Component protocol tests use actual
SDK sockets with fixture peers. The installed test runs the real Soul runtime
and comms mailbox with HQ at that SDK commit. It injects the notice consumer,
the released v0.5.0 schemas, a fixture signer and a simulated upstream.

Required positive validation is a separate, never-skipped gate:

```sh
node --test tests/integration/hq-inbox-release-gate.test.mjs
```

This test provisions the exact public release as offline data, verifies its
manifest, packages and installs the candidate, then invokes its existing MCP
command through configured MCP discovery and calls with inherited real Soul
member inputs. It verifies one legacy handoff then empty, rejects a forged
repository, records the local consume tombstone, and makes no query uplink calls.
The protocol fixture adapter requires no LLM credentials. It does not provision
ACP server slots or prove every harness forwards member inputs. Deployments
must configure the genuine offline dependency and verify their command and
per-harness inheritance; a directory pinned to an older release refuses.

[Identity #1445](https://github.com/true-line/agent-bot-identity/pull/1445) delivered the
installed client. The [post-merge CI gate](https://github.com/true-line/agent-bot-identity/actions/runs/43808904199/job/133105989689)
passed on the [merged source](https://github.com/true-line/agent-bot-identity/blob/843b4433f397d5a3cc746fdc6f9110b6687d9444/tests/integration/hq-inbox-release-gate.test.mjs).
[HQ #141](https://github.com/true-line/agent-bot-hq/pull/141) verified default-host
registration. The [HQ #13 closeout](https://github.com/true-line/agent-bot-hq/issues/13#issuecomment-6927251608)
records provisioning, member-input inheritance and exclusive service custody for
the declared single-harness Linux cloud pilot.
