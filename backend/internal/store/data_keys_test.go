package store

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLoadOrCreateDataKey_CreatesThenReuses(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	master := testSecretKey(t)

	first, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	if err != nil {
		t.Fatalf("LoadOrCreateDataKey() error = %v", err)
	}

	// Sealing with the first handle and opening with the second proves the key
	// was persisted and recovered, not regenerated — a fresh key would open
	// nothing and every enrolled secret would be lost on restart.
	sealed, err := first.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	second, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	if err != nil {
		t.Fatalf("second LoadOrCreateDataKey() error = %v", err)
	}
	got, err := second.Open(sealed)
	if err != nil {
		t.Fatalf("reloaded DEK could not open data sealed by the first: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("Open() = %q, want %q", got, "payload")
	}
}

func TestLoadOrCreateDataKey_SeparatePurposesGetSeparateKeys(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	master := testSecretKey(t)

	secrets, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	if err != nil {
		t.Fatalf("LoadOrCreateDataKey(secrets) error = %v", err)
	}
	// The sealed-vault pass (E7) adds its own purpose; the two must not share a
	// key, or they could never be rotated or unlocked independently.
	vault, err := s.LoadOrCreateDataKey(ctx, master, "vault")
	if err != nil {
		t.Fatalf("LoadOrCreateDataKey(vault) error = %v", err)
	}

	sealed, err := secrets.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := vault.Open(sealed); err == nil {
		t.Fatal("the vault DEK opened a value sealed by the secrets DEK; purposes share a key")
	}
}

func TestLoadOrCreateDataKey_WrongMasterKeyIsDiagnosable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets); err != nil {
		t.Fatalf("LoadOrCreateDataKey() error = %v", err)
	}

	_, err := s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets)
	if err == nil {
		t.Fatal("a different master key unwrapped the stored DEK")
	}
	// "message authentication failed" alone sends an operator hunting for
	// corruption; the actionable cause is almost always a replaced key file.
	if !strings.Contains(err.Error(), "key file was replaced") {
		t.Fatalf("error = %v, want it to name the likely cause", err)
	}
}

func TestLoadOrCreateDataKey_RequiresMasterKey(t *testing.T) {
	s, _ := testStore(t)
	if _, err := s.LoadOrCreateDataKey(context.Background(), nil, DataKeyPurposeSecrets); err == nil {
		t.Fatal("LoadOrCreateDataKey(nil master) succeeded, want error")
	}
}

// Master-key rotation must rewrap the DEK and leave sealed data readable. This
// is the property the envelope exists for; if it regresses, rotating a
// compromised master key would mean re-encrypting everything.
func TestRewrapDataKey_RotatesWithoutReEncrypting(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	oldMaster := testSecretKey(t)

	dek, err := s.LoadOrCreateDataKey(ctx, oldMaster, DataKeyPurposeSecrets)
	if err != nil {
		t.Fatalf("LoadOrCreateDataKey() error = %v", err)
	}
	sealed, err := dek.Seal([]byte("enrolled secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	newMaster := testSecretKey(t)
	if err := s.RewrapDataKey(ctx, oldMaster, newMaster, DataKeyPurposeSecrets); err != nil {
		t.Fatalf("RewrapDataKey() error = %v", err)
	}

	after, err := s.LoadOrCreateDataKey(ctx, newMaster, DataKeyPurposeSecrets)
	if err != nil {
		t.Fatalf("LoadOrCreateDataKey() after rotation error = %v", err)
	}
	got, err := after.Open(sealed)
	if err != nil {
		t.Fatalf("data sealed before rotation did not survive it: %v", err)
	}
	if string(got) != "enrolled secret" {
		t.Fatalf("Open() = %q, want %q", got, "enrolled secret")
	}

	if _, err := s.LoadOrCreateDataKey(ctx, oldMaster, DataKeyPurposeSecrets); err == nil {
		t.Fatal("the retired master key still unwraps the DEK after rotation")
	}
}

func TestRewrapDataKey_RejectsWrongOldMaster(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets); err != nil {
		t.Fatalf("LoadOrCreateDataKey() error = %v", err)
	}

	err := s.RewrapDataKey(ctx, testSecretKey(t), testSecretKey(t), DataKeyPurposeSecrets)
	if err == nil {
		t.Fatal("RewrapDataKey() accepted a master key that cannot open the DEK")
	}
}

func TestRewrapDataKey_ErrorsWhenNoKeyExists(t *testing.T) {
	s, _ := testStore(t)
	err := s.RewrapDataKey(context.Background(), testSecretKey(t), testSecretKey(t), "never-created")
	if err == nil || !strings.Contains(err.Error(), "no \"never-created\" key exists") {
		t.Fatalf("RewrapDataKey() error = %v, want a missing-key complaint", err)
	}
}

// The point of the whole exercise: a caller holding DATABASE_URL and nothing
// else must not be able to read an enrolled secret. This reads the column
// directly, exactly as such a caller would.
func TestTOTPSecretIsCiphertextInTheDatabase(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	const secret = "JBSWY3DPEHPK3PXP"
	tok, err := s.CreateReviewerToken(ctx, "sealed-device", "plaintext-token", secret)
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT totp_secret_enc FROM reviewer_tokens WHERE id = $1`, tok.ID).Scan(&stored); err != nil {
		t.Fatalf("reading totp_secret_enc: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("totp_secret_enc is empty; the secret was not stored at all")
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Fatal("the base32 secret appears verbatim in the database column")
	}
	// Guard the encoding too: base64/hex of the secret would also be a leak.
	if strings.Contains(strings.ToUpper(string(stored)), secret) {
		t.Fatal("the secret is recoverable from the stored bytes as text")
	}
}

// A Store without a sealing key must refuse rather than fall back to plaintext.
// This is the branch that keeps a misconfiguration from silently undoing the
// migration.
func TestUnsealedStoreRefusesSecretWork(t *testing.T) {
	sealed, pool := testStore(t)
	ctx := context.Background()
	unsealed := New(pool)

	t.Run("enroll", func(t *testing.T) {
		_, err := unsealed.CreateReviewerToken(ctx, "device", "token-a", "JBSWY3DPEHPK3PXP")
		if err == nil {
			t.Fatal("CreateReviewerToken() with a secret succeeded on an unsealed Store")
		}
		if !strings.Contains(err.Error(), "in the clear") {
			t.Fatalf("error = %v, want it to say why it refused", err)
		}
	})

	// A token with no secret is unaffected: nothing needs sealing, so requiring
	// a key here would break bootstrap on a fresh install.
	t.Run("enroll without a secret is allowed", func(t *testing.T) {
		if _, err := unsealed.CreateReviewerToken(ctx, "device", "token-b", ""); err != nil {
			t.Fatalf("CreateReviewerToken() without a secret error = %v", err)
		}
	})

	t.Run("verify", func(t *testing.T) {
		tok, err := sealed.CreateReviewerToken(ctx, "enrolled", "token-c", "JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("CreateReviewerToken() error = %v", err)
		}
		_, err = unsealed.VerifyReviewerTOTP(ctx, tok.ID, "000000")
		if err == nil {
			t.Fatal("VerifyReviewerTOTP() succeeded on an unsealed Store")
		}
	})

	// An unenrolled token still returns (false, nil): that's a failed gate, not
	// a misconfiguration, and must stay distinguishable from the case above.
	t.Run("verify unenrolled needs no key", func(t *testing.T) {
		tok, err := unsealed.CreateReviewerToken(ctx, "unenrolled", "token-d", "")
		if err != nil {
			t.Fatalf("CreateReviewerToken() error = %v", err)
		}
		ok, err := unsealed.VerifyReviewerTOTP(ctx, tok.ID, "000000")
		if err != nil {
			t.Fatalf("VerifyReviewerTOTP() error = %v, want a clean false", err)
		}
		if ok {
			t.Fatal("VerifyReviewerTOTP() accepted a code for an unenrolled token")
		}
	})
}

// Opening under the wrong key must not look like a wrong code — one is an
// operator problem, the other is a user problem, and conflating them sends
// whoever is on call to the wrong place.
func TestVerifyReviewerTOTP_WrongSealingKeyIsAnError(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateReviewerToken(ctx, "device", "token", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	other := NewSealed(pool, testSecretKey(t))
	ok, err := other.VerifyReviewerTOTP(ctx, tok.ID, "000000")
	if err == nil {
		t.Fatal("VerifyReviewerTOTP() with the wrong sealing key returned no error")
	}
	if ok {
		t.Fatal("VerifyReviewerTOTP() returned true under the wrong key")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want it to name the key mismatch", err)
	}
}
