# Operations

Runbook for operating a Chuvar deployment. Scope is deliberately narrow: this
covers procedures that are **security-sensitive**, **destructive**, or
**specific to Chuvar's own invariants**.

Anything that's standard use of an underlying tool is linked, not restated —
those projects document their own tools better than we can, and a copy here
just goes stale:

- Applying/rolling back migrations — [golang-migrate](https://github.com/golang-migrate/migrate/blob/master/README.md)
  (Chuvar applies migrations automatically at startup via `db.Migrate`; you
  rarely need the CLI)
- Running `psql`, dumps, restores — [PostgreSQL client docs](https://www.postgresql.org/docs/current/app-psql.html)
- Container lifecycle — [Docker Compose CLI](https://docs.docker.com/reference/cli/docker/compose/)

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

That migration adds `totp_secret` as a nullable column with no backfill, so an
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

> There is no UI for this yet — it is a deliberate one-time operator action.
> Tracked in Notion as a gap.

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
SELECT id, label, revoked_at, (totp_secret IS NOT NULL) AS enrolled
FROM reviewer_tokens ORDER BY created_at;

-- 2. Clear every secret. The absence of a WHERE clause is deliberate — see below.
UPDATE reviewer_tokens SET totp_secret = NULL;

-- 3. Confirm the gate is actually reopened. This MUST return 0, or the reset
--    has not worked and committing achieves nothing.
SELECT count(*) AS ever_enrolled
FROM reviewer_tokens WHERE totp_secret IS NOT NULL;

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
