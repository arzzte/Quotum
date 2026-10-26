# Local hook collectors

A hook replaces one native subscription collector with a local executable you control.
It can measure several accounts of that provider on the same device. Quotum still owns
identity pseudonyms, per-account scheduling, duty, participation policy, delivery and
retries. No extra hub token, virtual device, service or ingest implementation is needed.
The existing `quotum connect` connection is used. Hooks do not change client discovery,
activity tracking or which subscription a native client is signed in to.

## Configure

```toml
[providers.claude.hook]
path = "/absolute/path/to/usage-hook"
args = []
```

Or point `path` at an interpreter and put the script path in `args`:

```toml
[providers.claude.hook]
path = "/absolute/path/to/python3"
args = ["-I", "/absolute/path/to/usage-hook.py"]
```

Only the existing client-measured providers (`claude`, `codex`, `antigravity`) are
supported. The hook replaces measurement, not the provider's client `path` setting.
`enabled = false` and `--only` apply as usual; the provider's `interval` is still its
minimum interval with a hub. Restart the agent after changing the configuration.
`quotum --only claude --json` runs discovery and measures the returned accounts once.
`quotum run --only claude` follows the hub's schedule.

The executable path must be absolute. There is no shell, tilde expansion or command
string parsing. Arguments are passed literally (at most 32, each at most 4096 bytes,
without NUL). Batch files (`.cmd`, `.bat`) are refused; on Windows use an executable or
an interpreter explicitly. The hook runs in Quotum's neutral work directory at low
priority, with the normal client environment (no `QUOTUM_*` variables). Standard error
is discarded. Each invocation has a 60-second deadline and a 256 KiB stdout limit,
including output without newlines; both EOF and successful exit are required. Stop,
timeout or completion tears down the process tree using the native client runner.

## Contract v1

Each invocation reads one JSON request from stdin until EOF, prints exactly one JSON
reply to stdout, and exits. Do not print progress, credentials, paths, full provider
responses or diagnostics on stdout. Version 1 rejects unknown fields. The account
list has at most 16 entries, the existing check-in limit; each entry's `provider` must
match the configured provider. Duplicate identities, including those differing only
by the native pseudonym's normalization, are invalid.

### Discovery

Request:

```json
{"version":1,"action":"discover"}
```

Reply:

```json
{"version":1,"accounts":[
  {"provider":"claude","identity":{"email":"user@example.com","organization":"Example"}},
  {"provider":"claude","identity":{"email":"second@example.com","organization":"Example"}}
]}
```

Discovery lists identities only: no windows, plan or errors. It must do no provider
work and make no model requests. The agent checks participation before even discovery.
Discovery is repeated on the configured provider interval (120 seconds by default),
so accounts can appear and disappear without restarting the agent. Unchanged accounts
keep their existing schedules. An empty list is valid. A failed discovery suspends
check-ins and measurements for that roster and retries with bounded backoff, retaining
per-account schedules until discovery succeeds. Only confirmed removals discard state.

### Measurement

Before measuring, Quotum checks in for the complete discovered roster. The hub selects
which accounts are due on this device. Only those identities are passed to the hook:

```json
{"version":1,"action":"measure","accounts":[
  {"email":"user@example.com","organization":"Example"}
]}
```

Reply:

```json
{"version":1,"accounts":[{
  "provider":"claude",
  "identity":{"email":"user@example.com","organization":"Example"},
  "plan":"max",
  "windows":[
    {"id":"session","kind":"session","minutes":300,"usedPercent":12.5,"resetsAt":"2026-10-26T23:00:00Z"},
    {"id":"weekly","kind":"weekly","minutes":10080,"usedPercent":37,"resetsAt":"2026-11-01T23:00:00Z"},
    {"id":"weekly:sonnet","kind":"weekly","minutes":10080,"label":"Sonnet","usedPercent":8}
  ]
}]}
```

Measure **only** the requested identities. Do not return another account, even if a
credential changed during collection: that invalidates the reply. Return one entry
per requested identity; an omitted entry becomes an error for that account. Order
does not matter. One account's failure need not discard another's good measurement:

```json
{"version":1,"accounts":[{
  "provider":"claude",
  "identity":{"email":"user@example.com","organization":"Example"},
  "error":"not_logged_in"
}]}
```

Errors are `not_installed`, `not_logged_in`, `unsupported`, `timeout`, `invalid_output`
or `failed`; they exclude `windows` and `plan`. Do not include a free-text error body.
A nonzero exit, deadline, excess output or invalid JSON is a measurement error for all
requested accounts, never a crash. The agent emits fixed diagnostics, never raw output,
arguments, provider errors or parser messages.

A success has 1–32 unique windows. `kind` is `session`, `weekly` or `other`, independent
of the id. `usedPercent` is finite and between 0 and 100; `minutes`, when present, is
positive; `resetsAt`, when present, is RFC 3339 with a timezone. Unknown reset times
are omitted or null. Plan, ids and labels are nonempty, control-free text of at most
120 characters; ids must remain unique after trimming. Plan is optional: omit it when
not reported rather than guessing. The contract initially covers percentage windows,
not balances or free resets. Quotum supplies the observation time after the command
returns, freshness from the account's schedule, and `via = "local-hook/v1"`.

### Provider identities

| Provider | `identity` | Handling |
|---|---|---|
| Claude | `{"email":"user@example.com","organization":"Example"}` | The exact email and organization reported by Claude Code; organization is required, but can be empty. |
| Codex | `{"accountId":"provider-account-id"}` | The same stable account id returned by the native app-server. |
| Antigravity | `{"accountName":"work"}` | The owner's subscription name, as with native `providers.antigravity.account`; no supplier pseudonym is invented. |

Do not mix the identity fields of different providers. Identity fields are bounded to
120 characters without controls; only organization can be empty. For Claude and Codex,
Quotum calls the same pseudonym function as the native adapter. The script must not
hash identities or construct ingest packets. The same raw identity gives the same
subscription on any device, whether measured natively or by a hook. Raw Claude and
Codex supplier identities remain in memory and the hook's stdin/stdout, not the spool,
logs or hub. Antigravity's user-chosen `accountName` is sent to the hub in check-ins
and snapshots and can enter the spool, just as with native collection. Its identity
uses the trimmed, lowercased name; case-only changes do not create another account.
A hook's pooled accounts never become evidence of a native client's current login.

## Trust and failure boundaries

Opting in executes **your code with your user's permissions**. This is not a sandbox,
a signed-plugin system or a way to run untrusted scripts. Protect the executable,
script, interpreter and their parent directories from other writers. Prefer an isolated
interpreter mode, keep credentials out of arguments and choose absolute script paths.
A time/output cap protects Quotum, not the rest of your machine from a malicious hook.
The inherited non-Quotum environment may contain your own secrets; your script controls
its own credential access and network use. Quotum never opens provider credential
files, refreshes tokens, calls provider endpoints or makes model requests. Your hook
must also avoid model requests. Secret storage and provider access belong to your
script, outside Quotum's product and contract.

In the background, accounts retain independent hub duty, commands, epochs, freshness,
failure backoff and offline fallback through the existing scheduler and paired sink.
Discovery does not create a hub subscription; only ordinary check-ins and accepted
measurements do. Provider-only discovery failures remain private device diagnostics.
No hub, database or ingest-protocol change is required.

[Русская версия](hook-collectors.ru.md)
