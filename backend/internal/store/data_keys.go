package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// DataKeyPurposeSecrets is the DEK that seals short secret values stored in
// ordinary columns — reviewer TOTP secrets today. The sealed-vault pass (E7)
// adds a separate purpose for fact content rather than reusing this one, so
// that the two can be rotated, and eventually unlocked, independently.
const DataKeyPurposeSecrets = "secrets"

// LoadOrCreateDataKey returns the data-encryption key for purpose, unwrapping it
// with master. When no key exists yet it mints one, wraps it, and stores it.
//
// The create path races: two processes booting together can both find nothing
// and both try to insert. InsertDataKey declines to overwrite, so the loser gets
// no row back and re-reads the winner's key here. Getting this wrong would be
// quiet and expensive — the loser would hold a key that opens nothing it didn't
// itself write.
func (s *Store) LoadOrCreateDataKey(ctx context.Context, master *custody.Key, purpose string) (*custody.Key, error) {
	if master == nil {
		return nil, errors.New("store: load data key: no master key supplied")
	}

	row, err := s.q.GetDataKey(ctx, purpose)
	if err == nil {
		key, err := master.Unwrap(row.WrappedKey)
		if err != nil {
			// Almost always the wrong master key rather than corruption: a
			// regenerated key file, or a backup restored beside the wrong one.
			// Say so, because "cipher: message authentication failed" sends
			// people looking in the wrong place entirely.
			return nil, fmt.Errorf("store: unwrapping the %q data key failed — this master key "+
				"cannot open it, which usually means the key file was replaced or restored from a "+
				"different deployment: %w", purpose, err)
		}
		return key, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("store: get data key %q: %w", purpose, err)
	}

	raw, err := custody.GenerateKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := master.Wrap(raw)
	if err != nil {
		return nil, fmt.Errorf("store: wrap data key %q: %w", purpose, err)
	}

	if _, err := s.q.InsertDataKey(ctx, sqlcgen.InsertDataKeyParams{
		Purpose:    purpose,
		WrappedKey: wrapped,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Lost the race. Re-read rather than retrying the insert.
			row, err := s.q.GetDataKey(ctx, purpose)
			if err != nil {
				return nil, fmt.Errorf("store: re-read data key %q after insert conflict: %w", purpose, err)
			}
			key, err := master.Unwrap(row.WrappedKey)
			if err != nil {
				return nil, fmt.Errorf("store: unwrap concurrently-created data key %q: %w", purpose, err)
			}
			return key, nil
		}
		return nil, fmt.Errorf("store: insert data key %q: %w", purpose, err)
	}

	return custody.NewKey(raw)
}

// RewrapDataKey re-wraps an existing DEK under a new master key. The DEK's own
// bytes are unchanged, so nothing sealed under it needs re-encrypting — that
// property is the reason the envelope exists.
//
// No binary calls this yet: rotating the master key is library-only until there
// is a command for it, because rotation also needs to answer where the new key
// comes from and what happens if the process dies mid-rewrap. Kept here, tested,
// so the envelope's central claim is demonstrably true rather than asserted —
// but docs/operations.md says plainly that there is no operator path yet.
func (s *Store) RewrapDataKey(ctx context.Context, oldMaster, newMaster *custody.Key, purpose string) error {
	if oldMaster == nil || newMaster == nil {
		return errors.New("store: rewrap data key: both master keys are required")
	}

	row, err := s.q.GetDataKey(ctx, purpose)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: rewrap data key: no %q key exists", purpose)
		}
		return fmt.Errorf("store: get data key %q: %w", purpose, err)
	}

	raw, err := oldMaster.Open(row.WrappedKey)
	if err != nil {
		return fmt.Errorf("store: the supplied old master key cannot open the %q data key: %w", purpose, err)
	}
	wrapped, err := newMaster.Wrap(raw)
	if err != nil {
		return fmt.Errorf("store: wrap data key %q under new master: %w", purpose, err)
	}

	rows, err := s.q.RewrapDataKey(ctx, sqlcgen.RewrapDataKeyParams{Purpose: purpose, WrappedKey: wrapped})
	if err != nil {
		return fmt.Errorf("store: rewrap data key %q: %w", purpose, err)
	}
	if rows == 0 {
		return fmt.Errorf("store: rewrap data key: %q disappeared mid-rotation", purpose)
	}
	return nil
}
