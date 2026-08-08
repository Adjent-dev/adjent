# adjent

Evidence for what autonomous software does.

```sh
adjent check  <url>            check an MCP server against the 2026-07-28 auth spec
adjent record --upstream <url> record agent traffic into a signed, append-only log
adjent verify <log>            verify that a recorded log has not been altered
adjent keygen                  create an Ed25519 signing key
adjent checkpoint <log>        sign a statement of how long the log is now
```

---

## check

Check whether an MCP server conforms to the 2026-07-28 authorization specification.

That revision made two requirements mandatory. Servers must publish
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected resource metadata, and clients must send
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators so that a token issued for one
server cannot be replayed against another. Most servers deployed before that date satisfy neither
requirement, and there has been no straightforward way to determine which side of the line a given
server falls on.

```
adjent  https://api.githubcopilot.com/mcp/
MCP authorization spec 2026-07-28

  PASS  HTTPS transport (MUST)
  PASS  Protected resource metadata (RFC 9728) (MUST)
  PASS  Canonical resource identifier (SHOULD)
  PASS  401 challenge points to metadata (SHOULD)
  PASS  Authorization server metadata (MUST)
  PASS  PKCE S256 supported (MUST)
  WARN  Dynamic client registration (SHOULD)
  SKIP  Resource indicators enforced (MUST)

  6 passed  0 failed  1 warnings  1 not checked  0 unknown
  Conformant. No MUST-level failures.
```

## Install

```sh
go install github.com/adjent-dev/adjent@latest
```

You can also build from source. adjent has no third-party dependencies and uses only the Go
standard library.

```sh
git clone https://github.com/adjent-dev/adjent
cd adjent && go build -o adjent .
```

## Usage

```sh
adjent check https://your-server.example.com/mcp
adjent check --json https://your-server.example.com/mcp
adjent check --timeout 30s https://slow-server.example.com/mcp
```

Exit codes are `0` for a conformant server, `1` when a MUST-level requirement is unmet, `2` for a
usage error, and `3` when the run was inconclusive because a required check could not be completed.
Warnings and checks that are out of scope by design never fail the build.

The distinction between `1` and `3` matters in CI. A server that is unreachable has not been shown to
be non-conformant, and reporting it as such would be a false accusation caused by a network problem.
adjent reports no verdict in that case rather than an incorrect one.

### Continuous integration

```yaml
- name: MCP authorization conformance
  run: |
    go install github.com/adjent-dev/adjent@latest
    adjent check --json ${{ env.MCP_SERVER_URL }}
```

## Scope and limitations

adjent reads only what a server publishes about itself. It fetches well-known metadata documents and
makes one ordinary unauthenticated request, which is the same request any MCP client makes before it
holds a token. It sends no crafted tokens, attempts no bypass, and tests nothing for exploitability.

Use it against servers you operate, or servers you have written permission to test.

This restriction is deliberate. It is also the reason one check reports `SKIP` instead of a verdict.

| Question | Answerable by reading published metadata |
|---|---|
| Does the server publish RFC 9728 metadata? | Yes. The document is public by design. |
| Does it advertise PKCE S256? | Yes. Authorization server metadata is public. |
| Does it enforce resource indicators? | No. Establishing this requires requesting a token with a mismatched `resource` value and observing whether it is rejected, which is an authorization test rather than a metadata read. |

A tool that guessed at the third question would be reporting a result it does not have. A tool that
probed for it without permission would be conducting an unauthorized security test. adjent states
what it does not know.

If you discover a genuine vulnerability on infrastructure you do not own, follow coordinated
disclosure. Notify the maintainer, allow 90 days, and publish afterwards.

## Checks performed

| ID | Check | Level | Reference |
|---|---|---|---|
| `TLS` | Served over HTTPS, with localhost exempt | MUST | MCP Authorization |
| `PRM` | Publishes protected resource metadata containing `resource` and `authorization_servers` | MUST | RFC 9728 §3 |
| `PRM-RESOURCE` | Declared canonical resource matches the host that clients call | SHOULD | RFC 9728 §3.1 |
| `WWW-AUTH` | 401 response advertises `resource_metadata` | SHOULD | RFC 9728 §5.1 |
| `AS-METADATA` | Advertised authorization server publishes discoverable metadata | MUST | RFC 8414 |
| `PKCE` | Authorization server supports the S256 challenge method | MUST | OAuth 2.1, RFC 7636 |
| `DCR` | Dynamic client registration is available | SHOULD | RFC 7591 |
| `RFC8707` | Resource indicators are enforced | MUST | RFC 8707, not verifiable passively |

Both the path-aware and root forms of each well-known location are attempted. Authorization server
metadata is looked up under RFC 8414 and under OpenID Connect discovery, because servers in
production use either convention.

---

## record

`adjent record` sits between your agent and an MCP server, forwards everything, and writes an entry
to an append-only chain for every call.

```sh
adjent keygen
adjent record --upstream https://server.example.com/mcp --key adjent.key --verbose
```

Then point your agent at `http://127.0.0.1:8722` instead of the server. Nothing else changes.

```
  tools/call read_file         200     75B  6ms
  tools/call list_dir          200     75B  5ms
  tools/call send_payment      200     75B  4ms
```

It records in the path rather than alongside it, on purpose. A recorder the acting system can bypass
captures only the actions that system chose to disclose, which is not evidence of anything.

Failed calls are recorded too. A recorder that writes only on success produces a log that flatters
the operator, and the actions an audit cares about are usually the ones that went wrong.

### Signing

Sign the log, or it is not evidence.

A hash chain alone detects someone editing a single line. It does not detect
someone reading the file, changing an entry, and recomputing every hash after
it, which produces a chain that verifies perfectly and says whatever they want.
Write access to the file is the only capability that attack requires.

Signing each entry raises the bar from write access to key compromise. `adjent
verify` reports which of the two guarantees it actually established, and says
so plainly when a log is unsigned or when signatures were present but no key was
supplied to check them.

What signing still does not stop: the holder of the private key can rewrite
history, and entries can be deleted from the end. Both need the head published
where the operator cannot reach it, which is the Verify stage of the roadmap and
does not exist yet.

### What is stored

By default, metadata only: the method, the tool name, the status, the size, and a SHA-256
commitment to the request and response bodies. The bodies themselves are not kept, because agent
traffic routinely carries credentials and personal data that a record keeper should not hold. The
commitment still lets anyone holding the original bodies prove they match what was recorded.

Pass `--retain-bodies` to store them, if you are recording into infrastructure you control and you
need the contents. Storage is capped at 4 MiB per body; the commitment is not, and an entry whose
stored bodies are a prefix is marked `partial` so a verifier does not try to recompute from them.

### The proxy never alters traffic

The commitment always covers exactly the bytes that were relayed. Responses are hashed as they
stream past rather than buffered, so size imposes no limit on what is committed to.

Requests above 32 MiB are refused with a 413 and recorded as never having reached the server. That is
the honest failure: forwarding a shortened request would corrupt the traffic, and forwarding it whole
while recording a prefix would produce evidence of an action that did not occur.

## verify

```sh
adjent verify adjent.log
```

```
  entries   3
  head      ecadee34ab1129f5be3b947b0bcf159fc66a27c41eea2363d4843757487e40c7

  Intact. Every entry links to the one before it.
```

Every entry commits to the hash of the entry before it, so altering or removing anything in the
middle breaks every link that follows. Verification reports the exact sequence number where the
chain first fails. Editing an entry and recomputing its own hash does not help, because the next
entry still commits to the original value.

Exit code is `0` for an intact log and `1` for an altered one.

## checkpoint

Signing a log does not reveal entries deleted from the end. The file carries no independent claim
about how long it should be, so a shorter chain verifies just as well as the original.

A checkpoint is that missing claim: a signed statement that at a given moment the log held a given
number of entries ending in a given hash.

```sh
adjent checkpoint --key checkpoint.key --origin prod-agent-1 run.log
adjent verify --pubkey adjent.pub \
              --checkpoint adjent.checkpoint \
              --checkpoint-pubkey checkpoint.pub \
              --origin prod-agent-1 run.log
```

Delete two entries from the end of a signed log and verification alone still passes:

```
  Intact. Every entry links to the one before it.
  Signed by key 4378aab5e0ffb97c and every signature validates.
```

With the checkpoint, it does not:

```
  Checkpoint mismatch.
  checkpoint records 5 entries but the log holds 3, so 2 entries were
  removed from the end
```

### Use a separate key for checkpoints

For the entries it covers, a verified checkpoint shows that none has been removed or rewritten.
Whether that holds against someone holding the **entry** signing key depends on which key signed the
checkpoint, and the difference is the whole point.

**Separate key.** An attacker with the entry key can rebuild the chain but cannot produce a
checkpoint that matches it. The guarantee survives compromise of the entry key. This is the only
property in the system that does.

**Same key.** That attacker can mint a replacement checkpoint agreeing with their rewritten chain,
and verification will accept it. The guarantee then rests on your having obtained the checkpoint
through a channel they cannot influence, which is an assumption the tool cannot see.

`adjent verify` reports which of the two it established and never conflates them. Keep the checkpoint
key somewhere the recorder is not, ideally with the party relying on the records.

### This depends entirely on where you keep it

A checkpoint stored beside the log it describes protects nothing. Whoever rewrites one rewrites the
other.

Checkpoints have to reach somewhere you cannot reach: a counterparty, an auditor, a customer, an
append-only log run by someone else. `adjent checkpoint` prints this every time it runs, because a
checkpoint kept locally is the failure mode most likely to feel like security.

Publishing them automatically is the next stage of work and does not exist yet. Entries appended
after the most recent checkpoint carry only the signature guarantee until a later one covers them.

## What none of this proves

`adjent checkpoint` refuses to sign a log that fails verification, so a checkpoint never attests to a
broken chain.

Beyond a distributed checkpoint's range, the two structural limits remain, and `adjent verify` states
them in its own output rather than implying a guarantee it cannot make. Three tests exist to fail
loudly if these properties change without the documentation changing with them:
`TestTruncationIsNotDetected`, `TestFullChainRebuildIsDetected`, and
`TestGuaranteeUnchangedWhenCheckpointUnverified`.

---

## Background

An MCP server sits between an AI agent and systems that matter, including repositories, databases,
and payment infrastructure. When its authorization is misconfigured, the visible symptom is rarely
that the agent stops working. The actual consequence is that a token intended for one server can be
presented to another, and that no record exists afterwards to establish what took place.

adjent addresses the first half of that problem. The second half, establishing what an agent
actually did in a form that a third party can verify, is the subject of ongoing work in this project.

## Licence

Apache-2.0
