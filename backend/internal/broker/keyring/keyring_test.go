package keyring

import (
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func randSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, SeedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return seed
}

func TestLoad_WrongSeedLength(t *testing.T) {
	if _, err := Load([]byte("too short")); err == nil {
		t.Fatal("Load with a short seed: want error, got nil")
	}
	if _, err := Load(make([]byte, SeedLen+1)); err == nil {
		t.Fatal("Load with an oversized seed: want error, got nil")
	}
}

func TestLoad_SignerProducesValidSignatures(t *testing.T) {
	seed := randSeed(t)
	key, err := Load(seed)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer key.Destroy()

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	// The derived signer must actually correspond to the seed handed in —
	// not just "some valid ed25519 signer" — verified against a signer built
	// directly from the same seed via an entirely independent code path.
	independentSigner, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("building comparison signer: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(independentSigner.PublicKey().Marshal()) {
		t.Error("Signer()'s public key does not match a signer built directly from the same seed")
	}

	msg := []byte("test message")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Errorf("signature from the loaded key does not verify against its own public key: %v", err)
	}
}

func TestSigningKey_DestroyThenSignerErrors(t *testing.T) {
	key, err := Load(randSeed(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key.Destroyed() {
		t.Fatal("Destroyed() = true before Destroy was ever called")
	}

	key.Destroy()

	if !key.Destroyed() {
		t.Fatal("Destroyed() = false after Destroy")
	}
	if _, err := key.Signer(); err == nil {
		t.Fatal("Signer() after Destroy: want error, got nil")
	}

	// Idempotent: a second Destroy must not panic.
	key.Destroy()
}

func TestLoad_DifferentSeedsProduceDifferentKeys(t *testing.T) {
	k1, err := Load(randSeed(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer k1.Destroy()
	k2, err := Load(randSeed(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer k2.Destroy()

	s1, _ := k1.Signer()
	s2, _ := k2.Signer()
	if string(s1.PublicKey().Marshal()) == string(s2.PublicKey().Marshal()) {
		t.Fatal("two independently-generated seeds produced the same public key")
	}
}

// TestLoad_ExhaustingMlockCeilingRecoversAndDestroysEverything exercises the
// #74 custody spike's most surprising finding: memguard allocation past the
// RLIMIT_MEMLOCK-derived ceiling doesn't fail gracefully for just the
// over-budget call — core.Panic's Purge() destroys every *other*
// currently-held buffer in the process too. Load's recover() (see its doc
// comment) turns the panic itself into a plain error, but it cannot and
// does not undo that blast radius — this test proves both halves: the
// panic is recovered (no crash), and the earlier keys are provably dead
// afterward, so a caller can't assume "my Load calls succeeded" implies
// "my previously-loaded keys still work."
//
// Skipped when the host's RLIMIT_MEMLOCK is implausibly large (e.g. running
// as root, or a CI image with raised limits) — this test's cost is
// proportional to the ceiling, and a multi-GB limit would make it either
// impractically slow or effectively untestable without actually holding
// gigabytes of locked memory. This dev host's real ceiling (~512 32-byte
// keys under an 8MB default RLIMIT_MEMLOCK, confirmed in the #74 spike) is
// exactly the case worth exercising for real.
func TestLoad_ExhaustingMlockCeilingRecoversAndDestroysEverything(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RLIMIT_MEMLOCK/mlock accounting is Linux-specific")
	}

	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		t.Skipf("could not read RLIMIT_MEMLOCK: %v", err)
	}
	pageSize := unix.Getpagesize()
	ceiling := int(rlimit.Cur) / pageSize
	if ceiling <= 0 || ceiling > 4096 {
		t.Skipf("RLIMIT_MEMLOCK-derived ceiling (%d pages) is not in a range this test can "+
			"exercise cheaply — skipping rather than locking an impractical amount of memory", ceiling)
	}

	var keys []*SigningKey
	defer func() {
		for _, k := range keys {
			k.Destroy() // idempotent even for the ones Purge already destroyed
		}
	}()

	for i := 0; i < ceiling; i++ {
		k, err := Load(randSeed(t))
		if err != nil {
			t.Fatalf("Load %d/%d (expected to fit within the %d-page ceiling): %v", i, ceiling, ceiling, err)
		}
		keys = append(keys, k)
	}

	// One more should exceed the ceiling, panic internally, and come back
	// as a plain error rather than crashing the test binary.
	if _, err := Load(randSeed(t)); err == nil {
		t.Fatal("Load past the mlock ceiling: want error, got nil — either the ceiling estimate is " +
			"wrong for this host or memguard's panic-on-exhaustion behavior changed")
	}

	// The blast radius: every previously-successful key is now dead, not
	// just the one that failed. This is the property this test exists to
	// pin down — losing it silently (e.g. a memguard upgrade that changes
	// this behavior) would be exactly the kind of drift AGENTS.md §6 asks
	// tests to catch.
	for i, k := range keys {
		if !k.Destroyed() {
			t.Errorf("key %d/%d survived a later Load's mlock-ceiling panic; expected Purge() to have destroyed it too", i, len(keys))
		}
	}
}
