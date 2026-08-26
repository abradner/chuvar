# Operations

Runbook for operating a Chuvar deployment. Scope is deliberately narrow: this
covers procedures that are **security-sensitive**, **destructive**, or
**specific to Chuvar's own invariants**.

Anything that's standard use of an underlying tool is linked, not restated —
those projects document their own tools better than we can, and a copy here
just goes stale:

- Applying/rolling back migrations — [golang-migrate](https://github.com/golang-migrate/migrate/blob/master/README.md)
  (`cmd/migrate` is the only thing that applies them; `apiserver` and `mcpserver`
  verify the schema and refuse to start if it is behind — see AGENTS.md §3.6)
- Running `psql`, dumps, restores — [PostgreSQL client docs](https://www.postgresql.org/docs/current/app-psql.html)
- Container lifecycle — [Docker Compose CLI](https://docs.docker.com/reference/cli/docker/compose/)

---

## Least-privilege database roles

Four roles, so no service holds authority it does not use:

| Role | Used by | Can | Cannot |
|---|---|---|---|
| owner (`chuvar`) | `cmd/migrate` only | everything, including DDL | — |
| `chuvar_app` | `apiserver` | all DML; read `reviewer_tokens`, `data_keys` | DDL; write `schema_migrations` |
| `chuvar_agent` | **nobody, as of #82/#86** — see below | read grants/scopes/facts; append `audit_log`; stage diffs and grant requests | **write grants**; read `reviewer_tokens`, `data_keys`, `audit_log`; read **other subjects' proposals**; DDL |
| `chuvar_broker` | `brokerd` | read `grants`/`grant_scopes`/`capability_grant_identities`/`capability_grant_tokens`; append `audit_log` | anything touching `facts`/`fact_scopes`/`staged_diffs`; read `reviewer_tokens`, `data_keys`, or its own `audit_log` writes back; DDL |

`mcpserver` no longer holds a database credential at all — #82/#86 replaced `DATABASE_URL` with
a revocable agent-class API token (`CHUVAR_API_TOKEN`, see "Minting and deploying an agent
token" below). `chuvar_agent` is retained rather than dropped (dropping a cluster-global
stamped role is its own migration risk; a dormant `NOLOGIN` role that nothing authenticates as
carries none — AGENTS.md §3.6), but nothing connects as it in a deployment that has adopted the
agent token. The Can/Cannot columns above describe what the role still grants on paper, not
what any running process currently exercises.

`chuvar_agent` holds only *column-level* `SELECT` (`id`, `status`, `created_at`) on
`staged_diffs` and `grant_requests`, so it can learn the id of what it wrote and nothing
else — not another subject's proposed content, nor their stated justification for wanting a
grant. That required narrowing the inserts' `RETURNING` clauses, since Postgres demands
`SELECT` on every column a `RETURNING` reads.

The one that matters: `chuvar_agent` **cannot write `grants`**. With the shared owner
credential, anything holding `DATABASE_URL` could `INSERT INTO grants` and give itself every
scope, with a matching `audit_log` row — the consent model defeated in two statements, seen
by no API-layer control.

### Roles are cluster-global — collisions are refused

Postgres roles live in the cluster, not the database. The migration stamps each role it
creates with a `COMMENT` naming the database, and **refuses to run** if a role of that name
already exists without a matching stamp. Sharing a role across two Chuvar databases would
silently grant one deployment's data to the other's credential holders; that is a decision
for someone who knows both deployments, not for whichever migration ran second.

If you hit that refusal, either drop the colliding role or give this deployment its own
cluster.

### Provisioning (required — the roles arrive unusable)

The migration creates both roles `NOLOGIN` and passwordless on purpose: a credential belongs
to a deployment, not to a repository. Until you do this, every service keeps connecting as
the owner and logs a `SUPERUSER` warning on each start.

```sh
docker compose exec postgres psql -U chuvar -d chuvar
```

```sql
ALTER ROLE chuvar_app    WITH LOGIN PASSWORD 'generate-a-real-one';
ALTER ROLE chuvar_agent  WITH LOGIN PASSWORD 'generate-a-different-one';
ALTER ROLE chuvar_broker WITH LOGIN PASSWORD 'generate-yet-another-one';
```

Then point each database-backed service at its own role — `apiserver` at `chuvar_app`,
`brokerd` at `chuvar_broker`, `cmd/migrate` at the owner — via their `DATABASE_URL`.
`mcpserver` is not part of this step: it holds no `DATABASE_URL` at all (see "Minting and
deploying an agent token" below) and never connects as `chuvar_agent`, which is why that role
now has nobody using it. The warning stops when a service is no longer over-privileged, which
is how you confirm it took effect for the services that do hold a database credential.

### Rotating the database password

The compose file interpolates `${CHUVAR_DB_PASSWORD:-chuvar_dev_only}`. The fallback exists
so a fresh clone runs with no setup; it is checked in, so treat it as public.

```sh
# Generate once and reuse, so .env and the database cannot disagree — and edit
# the existing line rather than appending a second one (the last wins, which
# makes a duplicate silently authoritative).
NEW_PW="$(openssl rand -base64 32)"

docker compose exec -T postgres psql -U chuvar -d chuvar \
  -c "ALTER ROLE chuvar WITH PASSWORD '$NEW_PW';"

touch .env
sed -i '/^CHUVAR_DB_PASSWORD=/d' .env
printf 'CHUVAR_DB_PASSWORD=%s\n' "$NEW_PW" >> .env
chmod 600 .env

docker compose up -d --force-recreate postgres
unset NEW_PW
```

Change the database first: if the `ALTER ROLE` fails you still have a working
`.env`, whereas the reverse leaves the file claiming a password the server never took.

Then update each service's connection string. Prefer a file over an environment variable:

```sh
install -m 600 /dev/null ~/.config/chuvar/apiserver.url
printf 'postgres://chuvar_app:PW@127.0.0.1:54322/chuvar?sslmode=disable\n' > ~/.config/chuvar/apiserver.url
DATABASE_URL_FILE=~/.config/chuvar/apiserver.url go run ./cmd/apiserver
```

`DATABASE_URL_FILE` wins over `DATABASE_URL` when both are set, and the service refuses to
start if the file is group- or world-readable.

### What this does and does not do

It converts **ambient reach** (credentials sitting in the process's environment) into an
**attack-shaped action**: on a single-user host, `docker exec` still yields a superuser
shell, and nothing here prevents that. It is not claimed to — detecting it is the
fail-closed tripwire work (ticket E4). What it removes is the ability to do real damage
*through the credentials the service legitimately holds*.

---

## Minting and deploying an agent token

`mcpserver` (ticket E3, #82/#86) authenticates to `apiserver`'s agent-only listener with a
revocable **agent-class token** instead of holding `DATABASE_URL`. This section is the
procedure for minting one, deploying it, and rotating it — the credential `mcpserver`'s launch
environment needs now, and the two it no longer should.

### Minting

`POST /api/agent-tokens` is gated by `requireStrongFactor` **unconditionally** — unlike
`POST /api/tokens`'s reviewer-token minting, there is **no bootstrap carve-out** here. A
reviewer bearer token with no enrolled second factor (including the `REVIEWER_BOOTSTRAP_TOKEN`
itself) is refused outright, on purpose: an agent-class token is pure standing authority handed
to a long-running, unattended process, with no ongoing human-presence check of its own, so the
one moment a human factor can be demanded is the moment of minting it. A confused or injected
agent holding only a factorless bootstrap token must not be able to mint itself — or another
agent — a standing credential.

Call it against the **reviewer** listener (`HTTP_ADDR`, default `127.0.0.1:8080`), with a
reviewer token and a current TOTP code or WebAuthn assertion, same as any other
`requireStrongFactor`-gated mutation:

```sh
curl -X POST http://127.0.0.1:8080/api/agent-tokens \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN" \
  -H "X-Chuvar-TOTP-Code: 123456" \
  -H 'Content-Type: application/json' \
  -d '{"subject":"agent:mcpserver-prod","label":"mcpserver-prod"}'
```

The response carries the token **plaintext exactly once** — capture it now, the server only
ever persists its hash and cannot show it again. Losing it means revoking and minting a
replacement (see "Rotating" below), not recovering it.

`GET /api/agent-tokens` (bearer-only, no second factor) lists every agent token's `subject`,
`label`, and active/revoked state without ever returning `token_hash` or a plaintext.
`POST /api/agent-tokens/{id}/revoke` (also bearer-only — revocation only ever reduces
authority) revokes one immediately.

### ⚠️ `subject` must match what existing grants are keyed on

`subject` is a separate column from the credential itself — it's the identity every grant and
audit row this token's holder produces gets attributed to, **not** a description of the
physical token (that's what `label` is for). Before deploying a newly minted token, confirm its
`subject` is exactly the string this deployment's grants already use — pre-cutover, that was
whatever `MCP_SUBJECT` was set to at launch. If it differs, existing grants silently stop
matching: `mcpserver` authenticates fine, `GET /api/agent/whoami` returns a subject, every tool
call runs — but every scope check comes back empty, because it's checking grants for a subject
nothing was ever granted to. There is no error for this; it looks exactly like a
correctly-authenticating agent with no grants.

Check before minting or deploying:

```sql
SELECT DISTINCT subject FROM grants;
```

Mint (or rotate into) a token whose `subject` matches one of those rows exactly.

### Deploying

On the agent host, in place of `DATABASE_URL` and `MCP_SUBJECT` (both gone — see below):

```sh
install -m 600 /dev/null ~/.config/chuvar/mcpserver.token
printf '%s' '<the plaintext from minting, no trailing newline needed>' > ~/.config/chuvar/mcpserver.token

CHUVAR_API_TOKEN_FILE=~/.config/chuvar/mcpserver.token \
CHUVAR_API_BASE_URL=http://127.0.0.1:8081 \
go run ./cmd/mcpserver
```

- **`CHUVAR_API_TOKEN_FILE`** at mode `0600` — a file beats an environment variable here for
  the same reason as everywhere else in this codebase (AGENTS.md §3.7): an env var is readable
  via `/proc` by anything running as the same user and is inherited by every child process,
  which is precisely the ambient-reach shape this credential exists to avoid. Plain
  `CHUVAR_API_TOKEN` still works for local development.
- **`CHUVAR_API_BASE_URL`** (read by `mcpserver`) must name the **agent** listener's origin,
  matching `apiserver`'s own `CHUVAR_AGENT_ADDR` (default `127.0.0.1:8081`, no scheme — it's an
  `http.Server.Addr`) — so with defaults on both sides, `CHUVAR_API_BASE_URL=http://127.0.0.1:8081`.
  Never the reviewer listener (`HTTP_ADDR`, default `127.0.0.1:8080`). The two are separate
  `http.Server`s specifically so a process holding only an agent token cannot reach reviewer
  routes even at the network layer; pointing `mcpserver` at the reviewer port doesn't escalate
  anything (the agent token still won't authenticate there), it just fails to connect. Unset,
  `mcpserver` falls back to its own built-in default of `http://127.0.0.1:8081`, which matches
  `apiserver`'s own default and so is correct for a single-host deployment with nothing
  overridden — but should be set explicitly the moment either side's default is overridden, so
  the two can't silently drift apart.
- **Remove `DATABASE_URL`** from the agent host's launch environment — `mcpserver` no longer
  reads it, and leaving a live database credential sitting in an agent's environment for a
  process that no longer consults it is exactly the ambient-reach residue #82/#86 exists to
  close.
- **Remove `MCP_SUBJECT`** too — it no longer exists as a concept. Identity now comes from the
  token, resolved server-side on every request; there is nothing left for it to override, and a
  stale value sitting in the environment is a footgun for a future reader, not a no-op.
- **Naming collision to watch for:** `cmd/approver` and `cmd/pushbridge` also read
  `CHUVAR_API_TOKEN` — for them it's a *reviewer* token against the reviewer listener, a
  structurally different credential from the *agent* token `mcpserver` reads under the same
  variable name. They are never the same value and must never be deployed to the same process
  environment; the shared name is a coincidence of both binaries using the same
  fail-fast-required-config helper, not a shared credential.

### Verifying a deployment

On success, `mcpserver` logs `mcpserver: authenticated, serving on stdio` with the resolved
`subject` and `api_base_url` — confirm the subject matches what you expected before treating
the deployment as done. A bad or revoked token fails boot immediately with a message naming the
token as the problem (distinct from the message for an unreachable or misconfigured
`CHUVAR_API_BASE_URL`), so a startup failure already tells you which of the two to check first.

### Rotating

Revoke the old token and mint a new one with the **same** `subject`:

```sh
curl -X POST http://127.0.0.1:8080/api/agent-tokens/<old-id>/revoke \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN"

curl -X POST http://127.0.0.1:8080/api/agent-tokens \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN" \
  -H "X-Chuvar-TOTP-Code: 123456" \
  -H 'Content-Type: application/json' \
  -d '{"subject":"agent:mcpserver-prod","label":"mcpserver-prod-2026-08"}'
```

Grants are unaffected: `subject` persists across rotation because it lives in its own column,
independent of `token_hash` — a fresh token minted with the old `subject` picks up exactly the
grants the old token's holder had, with no re-approval needed. Deploy the new plaintext via
`CHUVAR_API_TOKEN_FILE` and restart `mcpserver`; the revoked token stops authenticating
immediately.

### Naming convention (not enforced)

Namespacing agent subjects as `agent:<name>` (as in the examples above) is a **convention**,
not a schema constraint — `subject` is plain `TEXT` on both `agent_tokens` and `grants`, with
no format check. It's worth following anyway: `audit_log.subject` is a single shared column
that reviewer mutations populate with the acting reviewer's `label` and agent routes populate
with the acting agent token's `subject` — nothing stops a reviewer label and an agent subject
from colliding as bare strings (`"prod"` meaning two different things in two different audit
rows), and namespacing the agent side is the cheap way to keep that column's values
unambiguous at a glance.

---

## The master key

Reviewer TOTP secrets are encrypted at rest. `apiserver` seals them under a
data-encryption key which is itself wrapped by a **master key** held outside the
database — so a caller who reaches Postgres but not the key file reads
ciphertext. That is the specific attacker this closes: one holding
`DATABASE_URL` who could otherwise read a secret, mint a valid code, and approve
its own grant request.

Only `apiserver` needs the master key. `mcpserver` — the process an agent host
spawns — never receives it, which is the point.

| Setting | Value |
|---|---|
| Default location | `$XDG_STATE_HOME/chuvar/master.key`, else `~/.local/state/chuvar/master.key` |
| Override | `CHUVAR_CUSTODY_KEY_FILE` |
| Mint on first run | `CHUVAR_CUSTODY_CREATE=1` |
| Permissions | no group or other access (`0600` or `0400`); `apiserver` refuses to start otherwise |

### First start

```sh
cd backend && CHUVAR_CUSTODY_CREATE=1 go run ./cmd/apiserver
```

Then **back the file up somewhere outside this machine**, before enrolling
anything. Creation is opt-in precisely so that a later start with a missing key
fails loudly instead of quietly minting a replacement that opens nothing.

### ⚠️ Not sealed at rest yet

The key file is currently **plaintext**, and `apiserver` logs a
`DOOR WEDGED OPEN` warning on every start saying so. Anything that can read the
filesystem as the service user can read the key, so this protects against a
stolen backup, a `pgdata` scrape, or a DB-credentialled process — **not** against
a filesystem reader. Suitable for development and low-value PoC secrets only.
Encrypting the key file under a passphrase is ticket E7; when that lands the
warning goes away and this section changes.

### Rotating the master key

**There is no operator command for this yet.** The envelope supports it — rotating
rewraps the data key and re-encrypts nothing — and `store.RewrapDataKey`
implements it, but no binary calls it. Rotation still needs to answer where the
replacement key comes from and what happens if the process dies mid-rewrap.
Until that exists, treat the master key as fixed for the life of the deployment.

### If the master key is lost

Sealed secrets are unrecoverable — that is what sealing means. Nothing in the
database can open them, and no procedure here can either. Recovery is the
break-glass path below: clear every secret and re-enrol. Bearer tokens are
unaffected (they are hashed, not sealed), so API access survives; only the
second factor is lost.

### Migrating to sealed TOTP secrets

The `seal_totp_secret` migration **refuses to run** while any plaintext
`totp_secret` is present, and reports how many. That refusal is deliberate:
dropping populated secrets would reset the ever-enrolled count to zero and
reopen the token-enrollment gate (see "Why there is no API path for this"
below), silently, during what looks like a routine upgrade.

To proceed, re-enrolment must be a decision rather than a side effect:

1. Confirm you can re-enrol every device you care about — you will be scanning
   fresh QR codes for all of them.
2. Run the break-glass procedure below to clear the secrets deliberately, in a
   transaction you inspect before committing.
3. Re-run the migration. With no plaintext secrets left, the guard passes.
4. **Enrol a device immediately** — between steps 2 and 4 the deployment is in
   the ungated state, and any bearer token can mint and self-enrol.

---

## brokerd's signing key

`brokerd` (the Agent Capability Broker, issues #95/#79) holds one decrypted
ed25519 git-signing seed in guarded process memory for its whole lifetime —
see `internal/broker/keyring`'s package doc. Whoever can read that seed can
forge an arbitrary git commit signature directly, with no grant token, no
scope check, no commit-payload parsing, no rate limit, and no audit entry —
the broker's entire purpose, bypassed in one file read. This is a sharper
adversary than the master key section above: that key only unlocks TOTP
secrets at rest; this one unlocks unbounded signing authority. Round-2
review flagged that `brokerd` unconditionally used the plaintext file
backend with no way to choose anything else — see `internal/custody`'s
`BackendFromEnv` (`internal/custody/select.go`) and its use in
`cmd/brokerd/main.go`'s `loadSigningKey` for the fix this section documents.

### Choosing a backend — required, no default

`CHUVAR_BROKER_SIGNING_KEY_BACKEND` selects the custody backend and **must**
be set to one of `file`, `age`, or `1password`. There is no default: an
unconfigured `brokerd` refuses to boot rather than silently falling back to
the plaintext file backend, per CLAUDE.md principle 5 ("missing config ⇒ no
boot"). The refusal names the variable to set.

| Backend | `Sealed()` | What it actually protects against |
|---|---|---|
| `file` | **false**, always | Nothing at rest. The seed sits base64-encoded in a `0600` file; any process running as the operator's OS user — including any agent, since every agent on this deployment shares that user (AGENTS.md §3.0) — reads it and forges signatures directly. Development and low-value PoC use only. |
| `age`, with `..._PASSPHRASE_FILE` set | **false** | The same same-OS-user adversary as `file`: the passphrase sits in a second `0600` file the same reader can already open, with no human interaction. Ciphertext-at-rest against a narrower adversary (a stolen backup, a `pgdata` scrape) only. |
| `age`, prompted interactively | **true** | The passphrase is read once from the controlling terminal (no echo, via `golang.org/x/term`) and never touches disk or an environment variable. Genuinely denies the same-OS-user filesystem reader. Requires a real terminal at boot — refuses cleanly (not a hang) under a non-interactive launcher (systemd, CI) with no passphrase file configured. |
| `1password` | **true**, always | The seed lives in a 1Password vault, encrypted under the account's own Secret Key and password, independent of this codebase. `Unseal` also refuses outright if `OP_SERVICE_ACCOUNT_TOKEN` or an `OP_SESSION_*` variable is present in the environment — either would let `op read` succeed with zero human interaction, defeating the point. See `OnePasswordBackend`'s doc comment (`internal/custody/onepassword.go`) for full setup. |

None of these protect against a process that can read `brokerd`'s own
memory once the seed is unsealed — that is the runtime residual
`internal/custody`'s package doc states plainly, not a gap this selector
closes.

### Per-backend configuration

All variables are namespaced under `CHUVAR_BROKER_SIGNING_KEY_` — deliberately
distinct from apiserver's `CHUVAR_CUSTODY_*` (see below).

| Setting | Applies to | Value |
|---|---|---|
| `CHUVAR_BROKER_SIGNING_KEY_BACKEND` | all | `file` \| `age` \| `1password` — required |
| `CHUVAR_BROKER_SIGNING_KEY_FILE` | `file`, `age` | Key file path (`file`) or age-ciphertext path (`age`). Both default to `$XDG_STATE_HOME/chuvar/broker-signing.key`, else `~/.local/state/chuvar/broker-signing.key`, when unset — the filename doesn't change with the backend, only its contents (raw base64 for `file`, age ciphertext for `age`), so set this explicitly if that's confusing for your deployment. |
| `CHUVAR_BROKER_SIGNING_KEY_CREATE` | `file`, `age` | `1` mints a fresh key/ciphertext on first run if none exists. Opt-in on purpose: a silently-minted replacement cannot decrypt anything sealed under a previous key, so a missing key must fail loudly, not regenerate. |
| `CHUVAR_BROKER_SIGNING_KEY_PASSPHRASE_FILE` | `age` | Path to a file holding the decryption passphrase. **Not sealed** (see table above) — set this only when the narrower guarantee, plus restart-without-a-human, is the accepted trade. Omit it to be prompted interactively instead. |
| `CHUVAR_BROKER_SIGNING_KEY_1PASSWORD_REFERENCE` | `1password` | An `op://` secret reference, e.g. `op://Private/chuvar-broker-signing-key/password`. The referenced field must hold base64-encoded key material, same encoding `file` uses. |
| `CHUVAR_BROKER_ALLOW_UNSEALED_KEY` | all | `1` is the explicit development escape hatch: without it, `brokerd` refuses to boot with any backend that reports `Sealed() == false`. With it, `brokerd` boots but logs a loud warning naming the same forging-and-bypass consequence documented above, on every start. |

### First start (development, plaintext)

```sh
cd backend && \
CHUVAR_BROKER_SIGNING_KEY_BACKEND=file \
CHUVAR_BROKER_SIGNING_KEY_CREATE=1 \
CHUVAR_BROKER_ALLOW_UNSEALED_KEY=1 \
go run ./cmd/brokerd
```

### First start (sealed, age with an interactive passphrase)

```sh
cd backend && \
CHUVAR_BROKER_SIGNING_KEY_BACKEND=age \
CHUVAR_BROKER_SIGNING_KEY_FILE=~/.local/state/chuvar/broker-signing.age \
CHUVAR_BROKER_SIGNING_KEY_CREATE=1 \
go run ./cmd/brokerd
```

`brokerd` prompts for the passphrase on the controlling terminal once, with
echo disabled (there is no second, confirmation prompt — a typo here means
discovering it on the next restart, not at entry time). Back that passphrase
up somewhere outside this machine, alongside the ciphertext file — losing
either loses every signature this key could ever have produced.

### apiserver's master key is a separate, still-open gap

`apiserver`'s own master-key loading (`openSealedStore`,
`cmd/apiserver/main.go`) still hardcodes the plaintext `file` backend
unconditionally — this section, and `BackendFromEnv`, do not change that.
It is issue #85 / ticket E7, tracked and disclosed separately (see "The
master key" above); `apiserver` could adopt `BackendFromEnv("CHUVAR_CUSTODY",
...)` the same way later, as its own two-way door.

### Duplicate capability token hashes

Migration `20260811100000_capability_token_hash_unique` makes
`capability_grant_tokens.token_hash` genuinely `UNIQUE`. If two rows already
share a hash, it **refuses to apply** and names the colliding grant ids
rather than resolving the collision itself.

That refusal is deliberate. A shared token hash means one credential derives
more than one grant, so which scope, committer identity and audit
attribution that credential carries is already ambiguous — and the migration
cannot know which grant you intended. Picking a winner automatically would
relocate the ambiguity into the migration; revoking the losers would be a
migration exercising authority on your behalf (principle 4); deleting their
token rows would erase the evidence of what was actually provisioned
(principle 12). So it stops and hands the decision back to you, the same way
`20260802000000_seal_totp_secret` refuses to drop enrolled TOTP secrets.

To resolve, for each colliding hash decide which grant was intended, then:

```sql
-- Inspect what collided.
SELECT t.grant_id, t.token_hash, t.created_at, g.subject, g.revoked_at
FROM capability_grant_tokens t
JOIN grants g ON g.id = t.grant_id
WHERE t.token_hash IN (
    SELECT token_hash FROM capability_grant_tokens
    GROUP BY token_hash HAVING count(*) > 1
)
ORDER BY t.token_hash, t.created_at;

-- Revoke each grant you did not intend (revocation only reduces authority,
-- and the grant row survives as history), then drop its token row so the
-- credential stops deriving it.
UPDATE grants SET revoked_at = now() WHERE id = '<unintended-grant-id>';
DELETE FROM capability_grant_tokens WHERE grant_id = '<unintended-grant-id>';
```

Re-run the migration once one row remains per hash. Note this state is only
reachable while direct SQL is the provisioning path — issue #96 replaces it
with a real creation surface that mints a distinct token per grant.

---

## Reviewer devices and the second factor (TOTP and passkeys)

Mutations that **grant or extend authority** — approving a grant request,
creating a grant directly, approving a staged diff, renewing a grant — require
a device-local second factor on top of the bearer token: a TOTP code
(`X-Chuvar-TOTP-Code`) or, since 2026-08-09, a WebAuthn passkey assertion
(`X-Chuvar-WebAuthn-Assertion`); either satisfies the same server-side gate
(see the 2026-08-09 entry in [decisions.md](decisions.md)). A bearer token is
readable by anything with shell access to the environment holding it; the
second factor is the part a compromised agent session cannot produce.

### Enrolling the first device

Do this **immediately after first start**, and **immediately after upgrading a
deployment that predates the `reviewer_totp` migration**.

That migration adds the secret column as nullable with no backfill, so an
upgraded deployment starts with *zero* enrolled devices. While zero devices are
enrolled, `POST /api/tokens` accepts a bearer token alone — so anything holding
that token can mint a new one and enrol it, defeating every gate above. The API
cannot close that gap by itself: with no enrolled device there is nothing to
check a code against.

`apiserver` logs a `SECURITY`-level warning on every start until this is done.

```sh
curl -X POST http://127.0.0.1:8080/api/tokens \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"alex-phone"}'
```

The response carries the token plaintext (**shown once — store it now**) and a
`totp_enroll_uri`. Scan that into an authenticator app.

From then on the enrolment gate is closed permanently: minting any further
token requires a valid factor from an already-enrolled device (TOTP code or
passkey assertion). The counts it checks — TOTP-enrolled tokens *and* passkey
credentials, both including revoked rows — are monotonic, so revoking devices
or credentials cannot reopen it. Belt and suspenders: a **durable append-only
latch** (`enrollment_latch`) is also set the first time any factor is enrolled,
and the gate stays closed if *either* the latch is set or the counts are
nonzero — so even the break-glass factor reset below, which drops the counts to
zero, cannot reopen enrollment until the latch is *separately and deliberately*
cleared.

> The Tokens page in the approval UI (PR #56) now provides this flow,
> including the first (bootstrap) enrolment; the curl calls above document
> the underlying API and remain valid as a UI-less fallback.

### Adding a passkey

Enroll from the Tokens page in the approval UI ("Passkeys"), or via the API:
`POST /api/webauthn/register/begin` then `/finish`. Registration **always**
requires proving a factor the calling device token has already enrolled — its
TOTP code, or an assertion of a passkey it already holds. There is no
factorless path: every token minted through `POST /api/tokens` gets a TOTP
secret at mint time, so every legitimate device has a factor to prove, and
the tokens that don't (the bootstrap token, tokens predating the
`reviewer_totp` migration) are refused outright with a 403. That refusal is
the point: a bearer token that could mint itself a passkey would pass every
gate above, so "add a passkey" must never be reachable with less proof than
the gates it unlocks.

Passkey assertions are single-use and challenge-bound (`POST
/api/webauthn/assert/begin`, five-minute expiry), validated against the RP
ID/origin derived from `CORS_ALLOWED_ORIGIN` (`WEBAUTHN_RP_ID` overrides). A
passkey whose signature counter regresses — the standard cloned-authenticator
signal — is **revoked automatically in the same statement that detects it**
and the event is audited (`webauthn_clone_suspected`); enroll a replacement
rather than expecting it to recover. Revoking a passkey
(`POST /api/webauthn/credentials/{id}/revoke`) is bearer-only, like device
revocation, and like it does not un-enrol the deployment.

### Adding another device

Same call, from an already-enrolled device, with a current code:

```sh
curl -X POST http://127.0.0.1:8080/api/tokens \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN" \
  -H "X-Chuvar-TOTP-Code: 123456" \
  -H 'Content-Type: application/json' \
  -d '{"label":"alex-laptop"}'
```

### Revoking a device

Revocation is **not** TOTP-gated — it only ever reduces authority, and gating it
would break "revoke a lost device from a working one".

```sh
curl -X POST http://127.0.0.1:8080/api/tokens/<id>/revoke \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN"
```

Revoking a device does **not** un-enrol the deployment. That is intentional —
see the recovery section below for why, and what it costs you.

---

## ⚠️ Recovery: every enrolled device is lost

> **This procedure disables the second factor for the entire deployment and
> destroys every bearer token along with it.** It is the one operation that
> intentionally weakens a security control, and it is **not recorded in
> `audit_log`** — Chuvar's audit trail is written by the application layer, and
> this bypasses it. Nothing in the system will show that it happened. Treat it
> as a break-glass action: note it wherever you record operational incidents,
> and re-bootstrap immediately.
>
> Unlike earlier versions of this runbook, recovery no longer leaves existing
> bearer tokens working: it revokes **every** reviewer token in the same
> transaction that clears the factors, so no surviving token — yours or a
> stolen one — can race you through the moment enrollment is reopened. You
> re-bootstrap from `REVIEWER_BOOTSTRAP_TOKEN` afterward, exactly like a fresh
> install.

### Try these first

Work down this list. Only reach the last step if the ones above genuinely don't apply.

1. **Any other enrolled device still working?** Use it to mint a replacement
   ("Adding another device" above). No recovery needed.
2. **Any passkey still working?** A passkey assertion satisfies the same gates
   a TOTP code does, including minting a replacement token — a surviving
   passkey means no recovery is needed either.
3. **Authenticator app backed up?** Most (Authy, 1Password, Google Authenticator)
   sync or export TOTP seeds. Restoring the app restores the code. Synced
   passkeys (iCloud Keychain, a password manager) restore the same way.
4. **Clock drift?** A code rejected as invalid on an otherwise-good device is
   usually skew, not loss. Check the device's time sync before assuming the
   device is gone.

### Why there is no API path for this

There isn't one, by design. Any API-reachable reset would be indistinguishable
from the attack the gate exists to stop — an attacker holding a stolen bearer
token driving the same reset. `REVIEWER_BOOTSTRAP_TOKEN` does not help either: a
fresh bootstrap token still faces a nonzero ever-enrolled count and cannot mint.

The cost of that choice is this section. It assumes the operator has database
access, which suits the current deployment shape (single operator, own
hardware) and would need revisiting for anything multi-tenant.

### The procedure

Recovery is **two deliberate steps, in order**: first clear every factor and
every bearer token; then, separately and by hand, reset the durable enrollment
latch. Step 1 alone does **not** reopen enrollment — the latch (below) keeps the
token-mint gate closed until you take step 2. That separation is the whole
point: clearing factors must never *by itself* reopen the gate, or a
break-glass reset and an attacker's self-mint would be the same event.

**Step 1 — clear factors and revoke every token.** Run it inside a transaction
and **inspect before committing**:

```sh
docker compose exec postgres psql -U chuvar -d chuvar
```

```sql
BEGIN;

-- 1. See what you are about to affect. Expect one row per device that has ever
--    enrolled, revoked ones included — and every passkey ever registered.
SELECT id, label, revoked_at, (totp_secret_enc IS NOT NULL) AS enrolled
FROM reviewer_tokens ORDER BY created_at;
SELECT id, label, revoked_at FROM webauthn_credentials ORDER BY created_at;

-- 2. Delete every reviewer token. ON DELETE CASCADE takes every passkey and
--    every pending challenge with it, so this one statement both clears the
--    second factor AND revokes every bearer token. Deliberately all of them,
--    with no WHERE clause: any token left alive is a token that could mint an
--    enrolled device the instant step 2 (the latch reset) runs — including a
--    stolen one racing you. You re-bootstrap from REVIEWER_BOOTSTRAP_TOKEN
--    afterward, so losing your own tokens here is expected, not collateral.
DELETE FROM reviewer_tokens;

-- 3. Confirm the factor counts are actually zero. BOTH MUST return 0, or the
--    reset has not worked and committing achieves nothing.
SELECT count(*) AS ever_enrolled
FROM reviewer_tokens WHERE totp_secret_enc IS NOT NULL;
SELECT count(*) AS ever_enrolled_passkeys FROM webauthn_credentials;

COMMIT;  -- or ROLLBACK; if step 3 did not return 0 twice
```

Deleting rows here (rather than nulling secrets or setting `revoked_at`) is the
one sanctioned break-glass deletion of otherwise-append-only history — and it is
exactly as invisible to `audit_log` as the rest of this procedure, which is why
the warning at the top of this section exists. It is safe *only* because the
durable latch, not these mutable rows, is now what preserves the enrollment gate
across a reset (see the `enrollment_latch` migration) — **and only on a
deployment that has actually applied both `20260810000000_enrollment_latch`
and `20260811110000_enrollment_latch_backfill`.** The first migration only
creates the table; on its own it does not set the latch for a factor that was
enrolled before either migration ran, so a deployment that upgraded straight
to `20260810000000` and never applied the backfill would have an unset latch
despite genuine prior enrollment — and Step 1 above would, by itself, fully
reopen `POST /api/tokens` instead of leaving Step 2 as the only thing standing
between recovery and re-exposure. `go run ./cmd/migrate` applies every pending
migration in order, so any deployment migrated after both landed is covered
automatically; this is only a trap for a deployment frozen between the two.
Confirm before relying on this claim: `SELECT version FROM schema_migrations`
should read `20260811110000` or later.

**Step 2 — reset the durable latch, on purpose, as a separate statement.** The
latch is set the first time any factor is ever enrolled and is **not** touched by
step 1: until you clear it, `POST /api/tokens` stays gated even though every
factor is gone — which is exactly what stops a bearer token from self-enrolling
the instant the factors are cleared. Resetting it is your explicit signal that
this is a sanctioned re-bootstrap, not that attack:

```sql
DELETE FROM enrollment_latch;
```

Do this only when you are certain, and only after step 1 has committed. It is
never folded into the transaction above and never a byproduct of clearing
factors — that single-statement, hand-run separation is the control.

### Immediately afterwards

Every bearer token is gone, so API access is down until you re-bootstrap. With
no active tokens, `apiserver` mints a fresh bootstrap token from
`REVIEWER_BOOTSTRAP_TOKEN` on next start (see "Enrolling the first device"), and
because you cleared the latch in step 2 the deployment is back in the ungated
bootstrap state — that first token can enrol without a factor. **Enrol a device
now**, not later: `apiserver` logs the `SECURITY` warning on each start as a
backstop, but the window is open from the moment you reset the latch.
