package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abradner/chuvar/backend/internal/broker/keyring"
)

const validTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// commitPayload builds a well-formed, unsigned git commit object payload for
// the given committer email.
func commitPayload(committerEmail string) []byte {
	return []byte(fmt.Sprintf(
		"tree %s\nauthor Agent <%s> 1723190400 +0000\ncommitter Agent <%s> 1723190400 +0000\n\ncommit message\n",
		validTree, committerEmail, committerEmail,
	))
}

func testBroker(t *testing.T) (*Broker, *Cache) {
	t.Helper()
	pool := testPool(t)

	seed := make([]byte, keyring.SeedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("generating test seed: %v", err)
	}
	key, err := keyring.Load(seed)
	if err != nil {
		t.Fatalf("keyring.Load: %v", err)
	}
	t.Cleanup(key.Destroy)

	cache := NewCache(pool)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	return New(pool, cache, key, 0, 0), cache // rate limiting disabled by default; dedicated test enables it
}

func TestBroker_Preflight_OK(t *testing.T) {
	b, cache := testBroker(t)
	pool := b.pool
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar"})
	if res.Code != OK {
		t.Fatalf("Preflight() = %+v, want OK", res)
	}
	if res.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil for a no-expiry grant", *res.ExpiresAt)
	}
}

func TestBroker_Preflight_WithExpiryReportsIt(t *testing.T) {
	b, cache := testBroker(t)
	ttl := time.Hour
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, &ttl)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar"})
	if res.Code != OK {
		t.Fatalf("Preflight() = %+v, want OK", res)
	}
	if res.ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want a value for a TTL'd grant")
	}
	got, err := time.Parse(time.RFC3339, *res.ExpiresAt)
	if err != nil {
		t.Fatalf("ExpiresAt %q did not parse as RFC3339: %v", *res.ExpiresAt, err)
	}
	if got.Before(time.Now().Add(50*time.Minute)) || got.After(time.Now().Add(70*time.Minute)) {
		t.Errorf("ExpiresAt = %v, want roughly one hour from now", got)
	}
}

func TestBroker_Preflight_BadToken(t *testing.T) {
	b, _ := testBroker(t)
	res := b.Preflight(Request{Op: "preflight", Token: "nonsense", Scope: "git.sign:github.com/abradner/chuvar"})
	if res.Code != NoGrant {
		t.Fatalf("Preflight() with bad token = %+v, want NO_GRANT", res)
	}
}

func TestBroker_Preflight_ScopeNotCovered(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "git.sign:github.com/someone-else/other-repo"})
	if res.Code != ScopeDenied {
		t.Fatalf("Preflight() for an uncovered target = %+v, want SCOPE_DENIED", res)
	}
}

func TestBroker_Preflight_InvalidScopeSyntaxRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "Not A Valid Scope"})
	if res.Code != ScopeDenied {
		t.Fatalf("Preflight() with a syntactically invalid scope = %+v, want SCOPE_DENIED", res)
	}
}

func TestBroker_Preflight_NoSideEffects(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	for i := 0; i < 5; i++ {
		if res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar"}); res.Code != OK {
			t.Fatalf("Preflight() call %d = %+v, want OK", i, res)
		}
	}

	var count int
	if err := b.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE grant_id = $1`, fx.GrantID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 0 {
		t.Errorf("audit_log rows after 5 preflight calls = %d, want 0 (preflight must have no side effects)", count)
	}
}

func TestBroker_Sign_OK(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != OK {
		t.Fatalf("Sign() = %+v, want OK", res)
	}
	if res.Signature == "" {
		t.Fatal("Sign() OK but Signature is empty")
	}

	signer, err := b.key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	verifySSHSIG(t, signer.PublicKey(), "git", commitPayload("agent@example.com"), res.Signature)

	var count int
	if err := b.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE grant_id = $1 AND event_type = 'capability_signed' AND subject = 'agent-a'`,
		fx.GrantID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for capability_signed = %d, want 1", count)
	}
}

func TestBroker_Sign_BadToken(t *testing.T) {
	b, _ := testBroker(t)
	res := b.Sign(context.Background(), Request{Op: "sign", Token: "nonsense", Scope: "git.sign:github.com/abradner/chuvar", Payload: commitPayload("a@example.com")})
	if res.Code != NoGrant {
		t.Fatalf("Sign() with bad token = %+v, want NO_GRANT", res)
	}
}

func TestBroker_Sign_RevokedGrantRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	cache.Remove(fx.GrantID) // simulates what Watch's NOTIFY path does on revocation

	res := b.Sign(context.Background(), Request{Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: commitPayload("agent@example.com")})
	if res.Code != NoGrant {
		t.Fatalf("Sign() with a revoked grant's token = %+v, want NO_GRANT", res)
	}
}

func TestBroker_Sign_ScopeNotCovered(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/someone-else/other-repo",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() for an uncovered target = %+v, want SCOPE_DENIED", res)
	}
}

// TestBroker_Sign_UntargetedCapabilityGrantNeverCached is the third leg of
// the three-scenario matrix the 2026-08-09 fail-closed/require-target
// decision calls for (docs/capability-broker.md decision log), alongside
// TestBroker_Sign_ScopeNotCovered ("targeted grant, different-target
// request" — SCOPE_DENIED) and TestBroker_Sign_OK ("targeted grant,
// matching-target request" — OK): "untargeted grant, targeted request."
//
// The grant is inserted directly with a bare "git.sign" scope — no
// capability-grant creation surface exists yet (#96) to have refused this at
// write time, so a fixture (or an operator's psql) inserting it straight is
// the realistic path, exactly as scope.ValidateCapability's doc comment
// describes. The expected code is NO_GRANT, not SCOPE_DENIED, and that is a
// deliberate consequence of where this build enforces the require-target
// rule, not an arbitrary pick between the two:
//
//   - cache.go's parseScopes runs scope.ValidateCapability over every scope
//     on a capability grant row and skips (logs, does not cache) the whole
//     grant if any scope fails it — see TestCache_Load_SkipsUntargetedCapabilityScope.
//     An untargeted capability grant is therefore never present in
//     Cache.byToken at all.
//   - Broker.Sign's (and Preflight's) very first step is
//     b.cache.Lookup(req.Token). For this grant's token, that lookup misses
//     — the same map-miss codes.go's NoGrant doc comment describes as
//     "no active grant matches the presented token at all" — and returns
//     NO_GRANT before checkScope, and therefore before SCOPE_DENIED, is
//     ever reached.
//
// SCOPE_DENIED presupposes "an active grant was found (the token matched)"
// (codes.go) — that premise is false here by construction, so SCOPE_DENIED
// would misdescribe what happened. From the caller's perspective, holding a
// token for a grant the broker refuses to load is indistinguishable from
// holding a token for a grant that was never issued, which is exactly what
// NO_GRANT is for.
func TestBroker_Sign_UntargetedCapabilityGrantNeverCached(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != NoGrant {
		t.Fatalf("Sign() with a targeted request against an untargeted (never-cached) grant = %+v, want NO_GRANT", res)
	}
	if res.Signature != "" {
		t.Fatal("Sign() produced a signature for a grant that was never cached")
	}
}

// TestBroker_Preflight_UntargetedCapabilityGrantNeverCached is Preflight's
// side of TestBroker_Sign_UntargetedCapabilityGrantNeverCached — checkScope's
// shared gate means the two must never disagree (see checkScope's own doc
// comment on why it is shared).
func TestBroker_Preflight_UntargetedCapabilityGrantNeverCached(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar"})
	if res.Code != NoGrant {
		t.Fatalf("Preflight() with a targeted request against an untargeted (never-cached) grant = %+v, want NO_GRANT", res)
	}
}

// TestBroker_Sign_UnrelatedOperationRefused: authorization must not rest on
// scope coverage alone. No grant-creation surface exists yet (#96), so
// nothing upstream guarantees a capability grant with identity+token rows
// carries a git.sign-shaped scope — a grant seeded with an unrelated
// operation's scope, plus a request for that same scope, passes AnyCovers
// and would mint a real git-commit signature for an operation no human ever
// named. checkScope's operation pin is what refuses it.
func TestBroker_Sign_UnrelatedOperationRefused(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"totally.unrelated.operation:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "totally.unrelated.operation:github.com/abradner/chuvar",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() under an unrelated-operation grant = %+v, want SCOPE_DENIED", res)
	}
	if res.Signature != "" {
		t.Fatal("Sign() produced a signature for an operation this broker does not implement")
	}
}

// TestBroker_Preflight_UnrelatedOperationRefused: preflight runs the same
// checkScope gate as Sign, so it can never OK a request Sign would refuse —
// a preflight false positive would strand an agent at exactly the
// publication boundary preflight exists to keep it away from.
func TestBroker_Preflight_UnrelatedOperationRefused(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"totally.unrelated.operation:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Preflight(Request{Op: "preflight", Token: fx.Token, Scope: "totally.unrelated.operation:github.com/abradner/chuvar"})
	if res.Code != ScopeDenied {
		t.Fatalf("Preflight() for an unrelated operation = %+v, want SCOPE_DENIED", res)
	}
}

// TestBroker_Sign_SubOperationRefused exercises the exact-match half of the
// operation pin specifically: "git.sign" *covers* "git.sign.extra" in
// scope.Covers' hierarchy, so AnyCovers alone would authorize it — but
// "git.sign.extra" names an operation this binary doesn't implement, and
// the pin refuses it before coverage is consulted.
func TestBroker_Sign_SubOperationRefused(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign.extra:github.com/abradner/chuvar",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() for a git.sign sub-operation = %+v, want SCOPE_DENIED", res)
	}
	if res.Signature != "" {
		t.Fatal("Sign() produced a signature for a sub-operation this broker does not implement")
	}
}

func TestBroker_Sign_CommitterMismatchRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar",
		Payload: commitPayload("someone-else@example.com"),
	})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() with mismatched committer = %+v, want SCOPE_DENIED", res)
	}
}

func TestBroker_Sign_MalformedPayloadRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: []byte("not a commit object")})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() with a malformed payload = %+v, want SCOPE_DENIED", res)
	}
}

// TestBroker_Sign_HostAuthChallengeRefused is success criterion 7's other
// half at the Broker level: an SSH host-authentication challenge blob
// (structurally nothing like a commit object) must be refused outright,
// never signed under any namespace — including "git", since it wouldn't
// even parse as a commit to reach the signing step.
func TestBroker_Sign_HostAuthChallengeRefused(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	challenge := []byte{0x00, 0x01, 'S', 'S', 'H', '2', 0x00, 0x00, 0xde, 0xad}
	res := b.Sign(context.Background(), Request{Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: challenge})
	if res.Code == OK {
		t.Fatal("Sign() produced a signature over a non-commit payload — success criterion 7 violated")
	}
}

// TestBroker_Sign_GpgsigHeaderRejected refuses to co-sign an
// already-(claimed-)signed commit — see commit.Parse's doc comment.
func TestBroker_Sign_GpgsigHeaderRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	payload := []byte("tree " + validTree + "\n" +
		"author Agent <agent@example.com> 1723190400 +0000\n" +
		"committer Agent <agent@example.com> 1723190400 +0000\n" +
		"gpgsig -----BEGIN SSH SIGNATURE-----\n someb64\n -----END SSH SIGNATURE-----\n\ncommit message\n")

	res := b.Sign(context.Background(), Request{Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: payload})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() with a gpgsig header already present = %+v, want SCOPE_DENIED", res)
	}
}

func TestBroker_Sign_InvalidScopeSyntaxRejected(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "Not A Valid Scope", Payload: commitPayload("agent@example.com"),
	})
	if res.Code != ScopeDenied {
		t.Fatalf("Sign() with a syntactically invalid scope = %+v, want SCOPE_DENIED", res)
	}
}

// TestBroker_Sign_DestroyedKeyReturnsBackendUnreachable exercises the
// Signer() error branch in Broker.Sign — reachable once the signing key has
// been destroyed (a shutdown in progress), per keyring.SigningKey.Signer's
// doc comment.
func TestBroker_Sign_DestroyedKeyReturnsBackendUnreachable(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	b.key.Destroy()

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: commitPayload("agent@example.com"),
	})
	if res.Code != BackendUnreachable {
		t.Fatalf("Sign() with a destroyed signing key = %+v, want BACKEND_UNREACHABLE", res)
	}
}

// TestBroker_Sign_AuditFailureDiscardsSignature exercises the "never
// blind-signs, extended to never hands out an unaudited signature" path:
// the grant is deleted from the database out from under a cache that still
// (correctly, benignly) holds it, so the audit_log insert's foreign key on
// grant_id fails. Sign must return BACKEND_UNREACHABLE, not the otherwise-
// validly-computed signature — see Broker.Sign's doc comment.
func TestBroker_Sign_AuditFailureDiscardsSignature(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	if _, err := b.pool.Exec(context.Background(), `DELETE FROM grants WHERE id = $1`, fx.GrantID); err != nil {
		t.Fatalf("deleting grant out from under the cache: %v", err)
	}

	res := b.Sign(context.Background(), Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: commitPayload("agent@example.com"),
	})
	if res.Code != BackendUnreachable {
		t.Fatalf("Sign() when the audit write fails = %+v, want BACKEND_UNREACHABLE", res)
	}
	if res.Signature != "" {
		t.Error("Sign() returned a signature alongside a failed audit write — it must be discarded, not returned")
	}
}

func TestBroker_Sign_RateLimited(t *testing.T) {
	pool := testPool(t)
	seed := make([]byte, keyring.SeedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("generating seed: %v", err)
	}
	key, err := keyring.Load(seed)
	if err != nil {
		t.Fatalf("keyring.Load: %v", err)
	}
	t.Cleanup(key.Destroy)

	cache := NewCache(pool)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	b := New(pool, cache, key, 2, time.Minute) // budget of 2 per minute for this test

	req := Request{Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar", Payload: commitPayload("agent@example.com")}
	if res := b.Sign(context.Background(), req); res.Code != OK {
		t.Fatalf("Sign() call 1 = %+v, want OK", res)
	}
	if res := b.Sign(context.Background(), req); res.Code != OK {
		t.Fatalf("Sign() call 2 = %+v, want OK", res)
	}
	res := b.Sign(context.Background(), req)
	if res.Code != RateLimited {
		t.Fatalf("Sign() call 3 (over budget) = %+v, want RATE_LIMITED", res)
	}
}

func TestBroker_Handle_UnknownOpRejected(t *testing.T) {
	b, _ := testBroker(t)
	res := b.Handle(context.Background(), Request{Op: "delete-everything"})
	if res.Code == OK {
		t.Fatal("Handle() with an unknown op returned OK")
	}
}

// TestBroker_Serve_EndToEnd drives Broker.Handle through a real Unix socket
// (Listen/Serve), the shape a real client (or the stretch-goal
// cmd/chuvar-sign, not built in this pass) would actually use — exercising
// the socket framing (protocol.go's Request/Result JSON-lines shape) and
// the SO_PEERCRED gate together with the authorization logic, rather than
// calling Broker.Handle directly as every other test in this file does.
func TestBroker_Serve_EndToEnd(t *testing.T) {
	b, cache := testBroker(t)
	fx := insertCapabilityGrant(t, b.pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)
	if err := cache.Load(context.Background()); err != nil {
		t.Fatalf("cache.Load: %v", err)
	}

	socketPath := t.TempDir() + "/brokerd.sock"
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, b.Handle)

	res := sendRequest(t, socketPath, Request{
		Op: "sign", Token: fx.Token, Scope: "git.sign:github.com/abradner/chuvar",
		Payload: commitPayload("agent@example.com"),
	})
	if res.Code != OK {
		t.Fatalf("over the real socket: Sign() = %+v, want OK", res)
	}
	signer, err := b.key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	verifySSHSIG(t, signer.PublicKey(), "git", commitPayload("agent@example.com"), res.Signature)

	// A second, independent connection with a bad token over the same live
	// socket — confirms the socket serves more than one request across its
	// lifetime (one request per *connection*, not one request ever).
	res2 := sendRequest(t, socketPath, Request{Op: "preflight", Token: "wrong", Scope: "git.sign:github.com/abradner/chuvar"})
	if res2.Code != NoGrant {
		t.Fatalf("second connection with a bad token = %+v, want NO_GRANT", res2)
	}
}

func sendRequest(t *testing.T, socketPath string, req Request) Result {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dialing socket: %v", err)
	}
	defer conn.Close()

	enc, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshaling request: %v", err)
	}
	enc = append(enc, '\n')
	if _, err := conn.Write(enc); err != nil {
		t.Fatalf("writing request: %v", err)
	}

	dec := json.NewDecoder(conn)
	var res Result
	if err := dec.Decode(&res); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return res
}

// verifySSHSIG independently decodes and verifies an armored SSHSIG blob
// against pubKey — deliberately not reusing internal/broker/sshsig's own
// encoder to build the comparison, so a bug shared between Sign and this
// check couldn't hide behind a round trip through the same code.
func verifySSHSIG(t *testing.T, pubKey ssh.PublicKey, namespace string, payload []byte, armored string) {
	t.Helper()
	body := extractArmoredBody(t, armored)

	off := 0
	readBytes := func(n int) []byte { b := body[off : off+n]; off += n; return b }
	readU32 := func() uint32 {
		b := readBytes(4)
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	readString := func() []byte { return readBytes(int(readU32())) }

	if string(readBytes(6)) != "SSHSIG" {
		t.Fatal("magic preamble mismatch")
	}
	_ = readU32()    // version
	_ = readString() // publickey (already have it via pubKey param)
	gotNS := string(readString())
	if gotNS != namespace {
		t.Fatalf("namespace = %q, want %q", gotNS, namespace)
	}
	_ = readString() // reserved
	_ = readString() // hash_algorithm
	sigBlob := readString()

	sigOff := 0
	sigReadU32 := func() uint32 {
		b := sigBlob[sigOff : sigOff+4]
		sigOff += 4
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	sigReadString := func() []byte {
		n := int(sigReadU32())
		b := sigBlob[sigOff : sigOff+n]
		sigOff += n
		return b
	}
	sig := &ssh.Signature{Format: string(sigReadString()), Blob: sigReadString()}

	// Reconstruct the "signed data" blob the same way sshsig.Sign's
	// internal signedData does, per PROTOCOL.sshsig: magic, namespace,
	// reserved, hash_algorithm, H(message) — no version, no pubkey.
	var toSign []byte
	toSign = append(toSign, "SSHSIG"...)
	toSign = appendString(toSign, []byte(namespace))
	toSign = appendString(toSign, nil)
	toSign = appendString(toSign, []byte("sha256"))
	sum := sha256.Sum256(payload)
	toSign = appendString(toSign, sum[:])

	if err := pubKey.Verify(toSign, sig); err != nil {
		t.Fatalf("SSHSIG signature does not verify: %v", err)
	}
}

func appendString(buf []byte, s []byte) []byte {
	n := len(s)
	buf = append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(buf, s...)
}

func extractArmoredBody(t *testing.T, armored string) []byte {
	t.Helper()
	const begin = "-----BEGIN SSH SIGNATURE-----\n"
	const end = "-----END SSH SIGNATURE-----\n"
	if len(armored) < len(begin)+len(end) {
		t.Fatalf("armored signature too short: %q", armored)
	}
	inner := armored[len(begin) : len(armored)-len(end)]
	body, err := base64.StdEncoding.DecodeString(removeNewlines(inner))
	if err != nil {
		t.Fatalf("base64-decoding armored body: %v", err)
	}
	return body
}

func removeNewlines(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
