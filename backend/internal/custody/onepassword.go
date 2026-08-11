package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OnePasswordBackend fetches the master key from 1Password by shelling out
// to the `op` CLI — biometric/system-auth release is meant to be the
// human-present ceremony Backend.Unseal's doc comment describes, with
// 1Password's own desktop app prompting for it, not this package.
//
// That guarantee is only as good as the environment `op` runs in. Unseal
// below shells out with no Env override, so `op` inherits this process's
// full environment — and 1Password's CLI honours two designed-for-
// automation, non-interactive auth paths that would let it return the key
// with zero human interaction: OP_SERVICE_ACCOUNT_TOKEN (a credential meant
// for unattended automation) and OP_SESSION_<account> (the token a prior
// `op signin` caches for its session TTL). Either one present in the
// calling environment defeats the whole point of this backend against the
// primary adversary AGENTS.md §3.0 names — an instruction-following agent,
// or commodity exfiltration malware, running as the operator's own OS
// user — which is exactly "zero ambient authority" (CLAUDE.md principle 3):
// an env var reachable through a legitimate interface is a bug, not a
// convenience. Unseal refuses outright when it detects either var, rather
// than silently proceeding. What this package cannot detect from here: a
// cached 1Password *desktop-app* session (its own IPC channel, no env var
// footprint) — an honest residual gap, not a claim this backend closes.
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
// being present and authenticated. This is an at-rest claim about the vault,
// not a claim that every Unseal call is human-gated — see the package doc
// comment and Unseal's ambient-auth-var check for the narrower, separate
// guarantee (and its limits) around the human-present ceremony.
func (b *OnePasswordBackend) Sealed() bool { return true }

func (b *OnePasswordBackend) cliPath() string {
	if b.CLIPath != "" {
		return b.CLIPath
	}
	return "op"
}

// ambientOpAuthVar reports the name of the first environment variable in
// environ that lets `op` authenticate with zero human interaction, or "" if
// none is present. See the package doc comment on OnePasswordBackend for why
// this specific pair of variables defeats the ceremony this backend exists
// to provide, and for the residual (desktop-app session caching) this check
// cannot see.
func ambientOpAuthVar(environ []string) string {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == "OP_SERVICE_ACCOUNT_TOKEN" || strings.HasPrefix(name, "OP_SESSION_") {
			return name
		}
	}
	return ""
}

// opEnvAllowlist names the only environment variables the child `op` process
// is given. The subprocess is spawned with an explicitly constructed Env (not
// left nil, which would inherit os.Environ()) so it never sees the apiserver's
// wider environment — DATABASE_URL, bootstrap tokens, unrelated secrets — none
// of which `op read` needs. It is an allow-list, not a deny-list, on purpose:
// a secret added to the apiserver's environment later can never silently start
// leaking into a subprocess this package spawns. Note what is deliberately
// absent: the OP_SERVICE_ACCOUNT_TOKEN / OP_SESSION_* automation credentials
// Unseal refuses above — withholding them from the child as well is
// belt-and-suspenders, since the biometric/desktop ceremony this backend
// requires locates its own IPC socket via HOME/XDG, not an env token.
var opEnvAllowlist = []string{
	"PATH",            // resolve `op`'s own helper lookups
	"HOME",            // 1Password CLI reads ~/.config/op and finds the desktop socket
	"XDG_CONFIG_HOME", // config-dir override, when set
	"XDG_RUNTIME_DIR", // where the desktop-app integration socket lives, when set
	"XDG_DATA_HOME",   // data-dir override, when set
}

// opChildEnv builds the minimal, allow-listed environment for the `op`
// subprocess. See opEnvAllowlist for why the child does not inherit
// os.Environ().
func opChildEnv() []string {
	env := make([]string, 0, len(opEnvAllowlist))
	for _, name := range opEnvAllowlist {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// unsealDebugStdout, when non-nil, is invoked with the exact byte slice
// Unseal captures from `op`'s stdout buffer, immediately after cmd.Run()
// returns — before Unseal even looks at whether it failed. It exists solely
// so tests can hold a reference to the very backing array the following
// `defer clear(b64)` wipes, and confirm that wipe actually ran by the time
// Unseal returns — including on the failure path, which is what this
// package's tests need to verify but otherwise have no way to observe from
// outside the function. A single nil check; never set outside tests.
var unsealDebugStdout func(b64 []byte)

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
	// Fail closed, loudly (CLAUDE.md principle 5) rather than silently
	// letting a non-interactive `op` auth path stand in for the human-
	// present ceremony this backend promises. See ambientOpAuthVar's doc.
	if v := ambientOpAuthVar(os.Environ()); v != "" {
		return nil, fmt.Errorf("custody: refusing to unseal via 1Password: %s is set in this "+
			"process's environment, which would let `op read` succeed with no human interaction "+
			"instead of the biometric/system-auth ceremony this backend requires — unset it or "+
			"launch apiserver without it (see OnePasswordBackend's doc comment)", v)
	}

	cmd := exec.CommandContext(ctx, b.cliPath(), "read", "--no-newline", b.Reference)
	// Sanitise the subprocess environment: `op` gets a minimal allow-list, not
	// this process's entire environment. See opEnvAllowlist's doc comment.
	cmd.Env = opChildEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Capture stdout's backing array and register its wipe *before* looking
	// at runErr, not after: `op` can write some or all of the base64 key to
	// stdout and only then exit nonzero — e.g. this call's context is
	// cancelled after output has begun — and a defer installed only on the
	// success path would never run for that case, leaving key material
	// sitting in stdout's buffer. Registering it here instead means both the
	// success and the failure return below wipe whatever landed in the
	// buffer, on every return path from this point on. Decode straight from
	// these mutable bytes — not stdout.String(), which would make an
	// immutable string copy of the key that the GC later abandons without
	// zeroing.
	b64 := stdout.Bytes()
	defer clear(b64)
	if unsealDebugStdout != nil {
		unsealDebugStdout(b64)
	}

	if runErr != nil {
		// stderr is `op`'s own diagnostic text ("not signed in", "item not
		// found", ...) — never the secret value itself in the common case
		// where the failing read produced no output at all; b64 above is
		// what covers the rarer case where it did. Still truncated
		// defensively: this package doesn't control the shape of `op`'s
		// error output, and an oversized or unexpected message shouldn't be
		// able to blow up a log line downstream.
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		if msg != "" {
			return nil, fmt.Errorf("custody: op read %s: %w: %s", b.Reference, runErr, msg)
		}
		return nil, fmt.Errorf("custody: op read %s: %w", b.Reference, runErr)
	}

	// The intermediate decoded-key slice below is wiped on its own error
	// paths too — the returned `key` is the sole copy of the master key that
	// leaves this process.
	key := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(key, bytes.TrimSpace(b64))
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("custody: decode 1Password field at %s: %w", b.Reference, err)
	}
	key = key[:n]
	if n != KeyLen {
		clear(key)
		return nil, fmt.Errorf("custody: 1Password field at %s holds %d bytes, want %d: %w",
			b.Reference, n, KeyLen, ErrKeyLen)
	}
	return key, nil
}
