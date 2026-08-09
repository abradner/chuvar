package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// OnePasswordBackend fetches the master key from 1Password by shelling out
// to the `op` CLI — biometric/system-auth release is exactly the
// human-present ceremony Backend.Unseal's doc comment describes, and it's
// 1Password's own desktop app that prompts for it, not this package.
//
// # Required setup
//
// This backend is only as good as the `op` session it runs in:
//
//  1. Install the 1Password CLI (`op`) and sign in at least once
//     (`op signin`) so a session/biometric-unlock is available — see
//     https://developer.1password.com/docs/cli/get-started/.
//  2. Create an item holding KeyLen (32) bytes of key material, base64
//     encoded, in some field — e.g. `op item create --category=password
//     --title=chuvar-master-key --vault=Private password=<base64>`.
//  3. Set Reference to that item's secret-reference URI, e.g.
//     "op://Private/chuvar-master-key/password" (`op read` accepts this
//     form directly — see `op read --help`).
//
// Tests in this package that need a real, signed-in `op` session skip
// cleanly with a clear message when one isn't available — see
// requireOpCLI in onepassword_test.go — rather than faking a pass; the rest
// of this backend's behavior is covered against a stub CLI that doesn't
// require 1Password account access at all.
type OnePasswordBackend struct {
	// Reference is the op secret-reference URI to read, e.g.
	// "op://Private/chuvar-master-key/password". The referenced field must
	// hold base64-encoded KeyLen bytes — the same on-disk encoding
	// FileBackend uses, so every backend in this package shares one wire
	// format for key material regardless of where it's stored.
	Reference string

	// CLIPath overrides the `op` binary resolved from PATH. Tests point this
	// at a stub executable; production deployments leave it empty.
	CLIPath string
}

func (b *OnePasswordBackend) Name() string { return "1password" }

// Sealed is true: 1Password's vault is encrypted at rest under the
// account's Secret Key and password, independent of anything in this
// package — the strongest of the three shipped-or-designed backends by that
// measure, at the cost of depending on 1Password's own availability and CLI
// being present and authenticated.
func (b *OnePasswordBackend) Sealed() bool { return true }

func (b *OnePasswordBackend) cliPath() string {
	if b.CLIPath != "" {
		return b.CLIPath
	}
	return "op"
}

// Unseal shells out to `op read` for Reference. It never logs or otherwise
// persists what comes back — the returned bytes are the only place the key
// material touches this process.
func (b *OnePasswordBackend) Unseal(ctx context.Context) ([]byte, error) {
	if b.Reference == "" {
		return nil, errors.New("custody: OnePasswordBackend.Reference is empty")
	}
	if !strings.HasPrefix(b.Reference, "op://") {
		return nil, fmt.Errorf("custody: OnePasswordBackend.Reference %q is not an op:// "+
			"secret reference", b.Reference)
	}

	cmd := exec.CommandContext(ctx, b.cliPath(), "read", "--no-newline", b.Reference)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr is `op`'s own diagnostic text ("not signed in", "item not
		// found", ...) — never the secret value itself, since a failing read
		// produced no value to leak in the first place. Still truncated
		// defensively: this package doesn't control the shape of `op`'s
		// error output, and an oversized or unexpected message shouldn't be
		// able to blow up a log line downstream.
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		if msg != "" {
			return nil, fmt.Errorf("custody: op read %s: %w: %s", b.Reference, err, msg)
		}
		return nil, fmt.Errorf("custody: op read %s: %w", b.Reference, err)
	}

	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil {
		return nil, fmt.Errorf("custody: decode 1Password field at %s: %w", b.Reference, err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("custody: 1Password field at %s holds %d bytes, want %d: %w",
			b.Reference, len(key), KeyLen, ErrKeyLen)
	}
	return key, nil
}
