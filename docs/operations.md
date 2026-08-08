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

Three roles, so no service holds authority it does not use:

| Role | Used by | Can | Cannot |
|---|---|---|---|
| owner (`chuvar`) | `cmd/migrate` only | everything, including DDL | — |
| `chuvar_app` | `apiserver` | all DML; read `reviewer_tokens`, `data_keys` | DDL; write `schema_migrations` |
| `chuvar_agent` | `mcpserver` | read grants/scopes/facts; append `audit_log`; stage diffs and grant requests | **write grants**; read `reviewer_tokens`, `data_keys`, `audit_log`; read **other subjects' proposals**; DDL |

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
ALTER ROLE chuvar_app   WITH LOGIN PASSWORD 'generate-a-real-one';
ALTER ROLE chuvar_agent WITH LOGIN PASSWORD 'generate-a-different-one';
```

Then point each service at its own role — `apiserver` at `chuvar_app`, `mcpserver` at
`chuvar_agent`, `cmd/migrate` at the owner — via their `DATABASE_URL`. The warning stops
when a service is no longer over-privileged, which is how you confirm it took effect.

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

## Reviewer devices and the TOTP second factor

Mutations that **grant or extend authority** — approving a grant request,
creating a grant directly, approving a staged diff, renewing a grant — require
a device-local TOTP code on top of the bearer token. A bearer token is readable
by anything with shell access to the environment holding it; the second factor
is the part a compromised agent session cannot produce.

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
token requires a valid code from an already-enrolled device. The count it
checks includes revoked rows, so revoking devices cannot reopen it.

> The Tokens page in the approval UI (PR #56) now provides this flow,
> including the first (bootstrap) enrollment; the curl calls above document
> the underlying API and remain valid as a UI-less fallback.

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

> **This procedure disables the second factor for the entire deployment.**
> It is the one operation that intentionally weakens a security control, and it
> is **not recorded in `audit_log`** — Chuvar's audit trail is written by the
> application layer, and this bypasses it. Nothing in the system will show that
> it happened. Treat it as a break-glass action: note it wherever you record
> operational incidents, and re-enrol immediately.

### Try these first

Work down this list. Only reach the last step if the ones above genuinely don't apply.

1. **Any other enrolled device still working?** Use it to mint a replacement
   ("Adding another device" above). No recovery needed.
2. **Authenticator app backed up?** Most (Authy, 1Password, Google Authenticator)
   sync or export TOTP seeds. Restoring the app restores the code.
3. **Clock drift?** A code rejected as invalid on an otherwise-good device is
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

Run it inside a transaction and **inspect before committing**:

```sh
docker compose exec postgres psql -U chuvar -d chuvar
```

```sql
BEGIN;

-- 1. See what you are about to affect. Expect one row per device that has ever
--    enrolled, revoked ones included.
SELECT id, label, revoked_at, (totp_secret_enc IS NOT NULL) AS enrolled
FROM reviewer_tokens ORDER BY created_at;

-- 2. Clear every secret. The absence of a WHERE clause is deliberate — see below.
UPDATE reviewer_tokens SET totp_secret_enc = NULL;

-- 3. Confirm the gate is actually reopened. This MUST return 0, or the reset
--    has not worked and committing achieves nothing.
SELECT count(*) AS ever_enrolled
FROM reviewer_tokens WHERE totp_secret_enc IS NOT NULL;

COMMIT;  -- or ROLLBACK; if step 3 did not return 0
```

**Why no `WHERE` clause.** The gate counts every row that has *ever* carried a
secret, revoked rows included — that is what makes it un-reopenable by an
attacker who can revoke. So `WHERE revoked_at IS NULL` would clear only the
active devices, leave the count nonzero, and keep the gate shut. Step 3 is there
to catch exactly that mistake before you commit.

Active bearer tokens keep working throughout; only the second factor is removed.

### Immediately afterwards

The deployment is now in the ungated state described in "Enrolling the first
device" — any bearer token can mint and self-enrol. **Enrol a device now**, not
later. `apiserver` will log the `SECURITY` warning on next start as a backstop,
but the window is open from the moment you commit.
