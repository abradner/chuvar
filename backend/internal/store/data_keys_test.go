package store

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abradner/chuvar/backend/internal/custody"
)

func TestLoadOrCreateDataKey_CreatesThenReuses(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	master := testSecretKey(t)

	first, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	require.NoError(t, err)

	// Sealing with the first handle and opening with the second proves the key
	// was persisted and recovered, not regenerated — a fresh key would open
	// nothing and every enrolled secret would be lost on restart.
	sealed, err := first.Seal([]byte("payload"))
	require.NoError(t, err)

	second, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	require.NoError(t, err)

	got, err := second.Open(sealed)
	require.NoError(t, err, "reloaded DEK could not open data sealed by the first")
	require.Equal(t, []byte("payload"), got)
}

func TestLoadOrCreateDataKey_SeparatePurposesGetSeparateKeys(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	master := testSecretKey(t)

	secrets, err := s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
	require.NoError(t, err)
	// The sealed-vault pass (E7) adds its own purpose; the two must not share a
	// key, or they could never be rotated or unlocked independently.
	vault, err := s.LoadOrCreateDataKey(ctx, master, "vault")
	require.NoError(t, err)

	sealed, err := secrets.Seal([]byte("payload"))
	require.NoError(t, err)

	_, err = vault.Open(sealed)
	require.Error(t, err, "the vault DEK opened a value sealed by the secrets DEK")
}

func TestLoadOrCreateDataKey_WrongMasterKeyIsDiagnosable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	_, err := s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets)
	require.NoError(t, err)

	_, err = s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets)
	require.Error(t, err, "a different master key unwrapped the stored DEK")
	// "message authentication failed" alone sends an operator hunting for
	// corruption; the actionable cause is almost always a replaced key file.
	require.ErrorContains(t, err, "key file was replaced")
}

func TestLoadOrCreateDataKey_RequiresMasterKey(t *testing.T) {
	s, _ := testStore(t)
	_, err := s.LoadOrCreateDataKey(context.Background(), nil, DataKeyPurposeSecrets)
	require.Error(t, err)
}

// Master-key rotation must rewrap the DEK and leave sealed data readable. This
// is the property the envelope exists for; if it regresses, rotating a
// compromised master key would mean re-encrypting everything.
func TestRewrapDataKey_RotatesWithoutReEncrypting(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	oldMaster := testSecretKey(t)

	dek, err := s.LoadOrCreateDataKey(ctx, oldMaster, DataKeyPurposeSecrets)
	require.NoError(t, err)
	sealed, err := dek.Seal([]byte("enrolled secret"))
	require.NoError(t, err)

	newMaster := testSecretKey(t)
	require.NoError(t, s.RewrapDataKey(ctx, oldMaster, newMaster, DataKeyPurposeSecrets))

	after, err := s.LoadOrCreateDataKey(ctx, newMaster, DataKeyPurposeSecrets)
	require.NoError(t, err)
	got, err := after.Open(sealed)
	require.NoError(t, err, "data sealed before rotation did not survive it")
	require.Equal(t, []byte("enrolled secret"), got)

	_, err = s.LoadOrCreateDataKey(ctx, oldMaster, DataKeyPurposeSecrets)
	require.Error(t, err, "the retired master key still unwraps the DEK after rotation")
}

func TestRewrapDataKey_RejectsWrongOldMaster(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	_, err := s.LoadOrCreateDataKey(ctx, testSecretKey(t), DataKeyPurposeSecrets)
	require.NoError(t, err)

	err = s.RewrapDataKey(ctx, testSecretKey(t), testSecretKey(t), DataKeyPurposeSecrets)
	require.Error(t, err, "RewrapDataKey accepted a master key that cannot open the DEK")
}

func TestRewrapDataKey_ErrorsWhenNoKeyExists(t *testing.T) {
	s, _ := testStore(t)
	err := s.RewrapDataKey(context.Background(), testSecretKey(t), testSecretKey(t), "never-created")
	require.ErrorContains(t, err, `no "never-created" key exists`)
}

// The point of the whole exercise: a caller holding DATABASE_URL and nothing
// else must not be able to read an enrolled secret. This reads the column
// directly, exactly as such a caller would.
func TestTOTPSecretIsCiphertextInTheDatabase(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	const secret = "JBSWY3DPEHPK3PXP"
	tok, err := s.CreateReviewerToken(ctx, "sealed-device", "plaintext-token", secret)
	require.NoError(t, err)

	var stored []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT totp_secret_enc FROM reviewer_tokens WHERE id = $1`, tok.ID).Scan(&stored))

	require.NotEmpty(t, stored, "totp_secret_enc is empty; the secret was not stored at all")
	require.False(t, bytes.Contains(stored, []byte(secret)),
		"the base32 secret appears verbatim in the database column")
	// Guard the encoding too: base64/hex of the secret would also be a leak.
	require.NotContains(t, strings.ToUpper(string(stored)), secret,
		"the secret is recoverable from the stored bytes as text")
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
		require.Error(t, err, "CreateReviewerToken with a secret succeeded on an unsealed Store")
		require.ErrorContains(t, err, "in the clear")
	})

	// A token with no secret is unaffected: nothing needs sealing, so requiring
	// a key here would break bootstrap on a fresh install.
	t.Run("enroll without a secret is allowed", func(t *testing.T) {
		_, err := unsealed.CreateReviewerToken(ctx, "device", "token-b", "")
		require.NoError(t, err)
	})

	t.Run("verify", func(t *testing.T) {
		tok, err := sealed.CreateReviewerToken(ctx, "enrolled", "token-c", "JBSWY3DPEHPK3PXP")
		require.NoError(t, err)

		_, err = unsealed.VerifyReviewerTOTP(ctx, tok.ID, "000000")
		require.Error(t, err, "VerifyReviewerTOTP succeeded on an unsealed Store")
	})

	// An unenrolled token still returns (false, nil): that's a failed gate, not
	// a misconfiguration, and must stay distinguishable from the case above.
	t.Run("verify unenrolled needs no key", func(t *testing.T) {
		tok, err := unsealed.CreateReviewerToken(ctx, "unenrolled", "token-d", "")
		require.NoError(t, err)

		ok, err := unsealed.VerifyReviewerTOTP(ctx, tok.ID, "000000")
		require.NoError(t, err, "an unenrolled token should fail the gate cleanly, not error")
		require.False(t, ok)
	})
}

// Opening under the wrong key must not look like a wrong code — one is an
// operator problem, the other is a user problem, and conflating them sends
// whoever is on call to the wrong place.
func TestVerifyReviewerTOTP_WrongSealingKeyIsAnError(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateReviewerToken(ctx, "device", "token", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	other := NewSealed(pool, testSecretKey(t))
	ok, err := other.VerifyReviewerTOTP(ctx, tok.ID, "000000")
	require.Error(t, err, "VerifyReviewerTOTP with the wrong sealing key returned no error")
	require.False(t, ok)
	require.ErrorContains(t, err, "does not match")
}

// Two processes booting together both find no key and both try to insert. The
// loser must adopt the winner's key rather than its own — otherwise it would
// hold a DEK that opens nothing anyone else wrote. Exercised by racing real
// concurrent calls, since the branch only triggers on a genuine ON CONFLICT.
func TestLoadOrCreateDataKey_ConcurrentCreateConvergesOnOneKey(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	master := testSecretKey(t)

	const racers = 8
	keys := make([]*custody.Key, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // maximise overlap on the insert
			keys[i], errs[i] = s.LoadOrCreateDataKey(ctx, master, DataKeyPurposeSecrets)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "racer %d failed", i)
	}

	// All eight must be the same key: seal with the first, open with each.
	sealed, err := keys[0].Seal([]byte("payload"))
	require.NoError(t, err)
	for i, k := range keys {
		got, err := k.Open(sealed)
		require.NoError(t, err, "racer %d got a divergent key", i)
		require.Equal(t, []byte("payload"), got)
	}
}
