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
| `chuvar_agent` | `mcpserver` | read grants/scopes/facts; append `audit_log`; stage diffs and grant requests | **write grants**; read `reviewer_tokens`, `data_keys`, `audit_log`; read **other subjects' proposals**; DDL |
| `chuvar_broker` | `brokerd` | read `grants`/`grant_scopes`/`capability_grant_identities`/`capability_grant_tokens`; append `audit_log` | anything touching `facts`/`fact_scopes`/`staged_diffs`; read `reviewer_tokens`, `data_keys`, or its own `audit_log` writes back; DDL |

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

Then point each service at its own role — `apiserver` at `chuvar_app`, `mcpserver` at
`chuvar_agent`, `brokerd` at `chuvar_broker`, `cmd/migrate` at the owner — via their
`DATABASE_URL`. The warning stops when a service is no longer over-privileged, which is
how you confirm it took effect.

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
