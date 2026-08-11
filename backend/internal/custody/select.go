package custody

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// BackendFromEnv selects and constructs a Backend from explicit environment
// configuration under prefix — e.g. prefix "CHUVAR_BROKER_SIGNING_KEY" reads
// CHUVAR_BROKER_SIGNING_KEY_BACKEND, _FILE, _CREATE, _PASSPHRASE_FILE, and
// _1PASSWORD_REFERENCE. Each cmd/ binary passes its own prefix so brokerd's
// and apiserver's env-var surfaces never collide (see cmd/brokerd/main.go's
// loadSigningKey doc comment on why sharing one namespace across binaries
// protecting different key material would be a category error) — this
// function reads no env var that isn't built from prefix or the two names
// the caller supplies explicitly.
//
// # Fail closed on missing configuration (CLAUDE.md principle 5)
//
// If "<prefix>_BACKEND" is unset, this refuses outright rather than
// defaulting to any particular backend, plaintext or otherwise. Before this
// selector existed, every caller in this codebase hardcoded FileBackend —
// the plaintext backend — as its only option; a caller that has migrated to
// BackendFromEnv but forgotten to configure it now gets a boot-time error
// naming exactly what to set, never a silent, unannounced fallback to the
// weakest backend available.
//
// # Refusing an unsealed backend
//
// Once a backend is selected, this also refuses to hand it back if it
// reports Sealed() == false (FileBackend, always; AgeBackend, when
// configured with PassphrasePath rather than an interactively-prompted
// Passphrase; never OnePasswordBackend, whose vault is sealed
// independently of anything this package does) — UNLESS the environment
// variable named by allowUnsealedVar is exactly "1": the explicit,
// obviously-named development escape hatch each binary names for itself
// (e.g. CHUVAR_BROKER_ALLOW_UNSEALED_KEY). consequence must name,
// concretely, what an attacker who reads the key gets to do with it — it is
// interpolated into both the refusal error and the warning logged when the
// escape hatch is used, so that neither is a generic "not sealed" notice
// but actually names its adversary (CLAUDE.md principle 8).
//
// # Age passphrase delivery
//
// When kind is "age" and "<prefix>_PASSPHRASE_FILE" is unset, this prompts
// interactively on the controlling terminal (no echo) for the passphrase —
// the one delivery mode AgeBackend.Sealed() honestly reports as sealed (see
// its doc comment): the passphrase never touches disk or an environment
// variable, both of which a same-uid reader can already access by the same
// reasoning internal/config.Secret gives for preferring a credential file
// over a bare env var. A caller with no controlling terminal (a systemd
// unit, a CI job) gets a clear boot-time error instead of an indefinite
// hang — see promptPassphrase.
func BackendFromEnv(prefix, allowUnsealedVar, consequence, defaultFile string) (Backend, error) {
	backendVar := prefix + "_BACKEND"
	fileVar := prefix + "_FILE"
	createVar := prefix + "_CREATE"
	agePassphraseFileVar := prefix + "_PASSPHRASE_FILE"
	onePasswordRefVar := prefix + "_1PASSWORD_REFERENCE"

	kind, ok := os.LookupEnv(backendVar)
	if !ok || kind == "" {
		return nil, fmt.Errorf("custody: %s is not set — no custody backend configured for this key; "+
			"refusing to boot rather than default to a plaintext backend (set it to \"file\", \"age\", "+
			"or \"1password\"; see docs/operations.md)", backendVar)
	}

	backend, err := buildBackend(kind, fileVar, createVar, agePassphraseFileVar, onePasswordRefVar, defaultFile)
	if err != nil {
		return nil, fmt.Errorf("custody: %s=%s: %w", backendVar, kind, err)
	}

	if !backend.Sealed() {
		if os.Getenv(allowUnsealedVar) != "1" {
			return nil, fmt.Errorf("custody: %s backend is NOT sealed at rest — %s — refusing to boot "+
				"(CLAUDE.md principle 5: missing/insufficient config means no boot, not a silent "+
				"downgrade); set %s=1 to proceed anyway, for development only", backend.Name(), consequence, allowUnsealedVar)
		}
		slog.Warn("custody: booting with an UNSEALED backend via explicit development override — "+consequence,
			"backend", backend.Name(), "override", allowUnsealedVar)
	}

	return backend, nil
}

func buildBackend(kind, fileVar, createVar, agePassphraseFileVar, onePasswordRefVar, defaultFile string) (Backend, error) {
	create := os.Getenv(createVar) == "1"
	path := os.Getenv(fileVar)
	if path == "" {
		path = defaultFile
	}

	switch kind {
	case "file":
		// path may still be "" here (no fileVar, no defaultFile) — FileBackend
		// itself falls back to DefaultKeyPath in that case, which is the
		// right behavior for a caller with no more specific default of its
		// own to offer.
		return &FileBackend{Path: path, AllowCreate: create}, nil

	case "age":
		if path == "" {
			return nil, fmt.Errorf("requires %s to name the age-encrypted key file", fileVar)
		}
		age := &AgeBackend{Path: path, AllowCreate: create}
		if pp := os.Getenv(agePassphraseFileVar); pp != "" {
			// PassphrasePath: Sealed() == false (co-located file, readable
			// by the same same-uid adversary as the key itself) — the
			// caller's Sealed()/allowUnsealedVar gate below still applies,
			// same as it does to FileBackend.
			age.PassphrasePath = pp
			return age, nil
		}
		passphrase, err := promptPassphrase(fmt.Sprintf("passphrase to unseal %s: ", path))
		if err != nil {
			return nil, fmt.Errorf("has no passphrase source — set %s to a co-located file (NOT "+
				"sealed against a same-user reader) or run interactively so this can prompt: %w",
				agePassphraseFileVar, err)
		}
		age.Passphrase = passphrase
		return age, nil

	case "1password":
		ref := os.Getenv(onePasswordRefVar)
		if ref == "" {
			return nil, fmt.Errorf("requires %s to name the op:// secret reference", onePasswordRefVar)
		}
		return &OnePasswordBackend{Reference: ref}, nil

	default:
		return nil, fmt.Errorf("unknown backend %q (want \"file\", \"age\", or \"1password\")", kind)
	}
}

// promptPassphrase reads a passphrase from the controlling terminal without
// echoing it — the human-present ceremony AgeBackend.Passphrase's doc
// comment describes, and the one age-backend configuration that actually
// earns Sealed() == true (see its doc comment: PassphrasePath does not).
// It refuses outright, rather than blocking forever, when stdin isn't a
// real terminal: a systemd unit or a CI job has no ceremony to perform and
// should get a clear boot-time error instead of a hang.
func promptPassphrase(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not an interactive terminal, so there is no one to prompt")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase from terminal: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty passphrase")
	}
	return string(b), nil
}
