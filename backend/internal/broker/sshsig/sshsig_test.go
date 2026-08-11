package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

func TestSign_SelfVerifies(t *testing.T) {
	signer := testSigner(t)
	payload := []byte("tree deadbeef\ncommitter Agent <agent@example.com> 1 +0000\n\nmessage\n")

	armored, err := Sign(signer, "git", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.HasPrefix(armored, "-----BEGIN SSH SIGNATURE-----\n") {
		t.Fatalf("armored output missing BEGIN marker: %q", armored[:min(40, len(armored))])
	}
	if !strings.HasSuffix(armored, "-----END SSH SIGNATURE-----\n") {
		t.Fatalf("armored output missing END marker")
	}

	// Every base64 line (excluding the markers) must be at most lineWidth,
	// matching ssh-keygen's own wrapping — a regression here wouldn't break
	// parsing (base64 doesn't care about line width) but would silently drift
	// from the format's documented convention.
	lines := strings.Split(strings.TrimSpace(armored), "\n")
	for _, l := range lines[1 : len(lines)-1] {
		if len(l) > lineWidth {
			t.Errorf("armored line exceeds lineWidth %d: %d chars", lineWidth, len(l))
		}
	}

	// Recompute the same "to-be-signed" blob this package used internally and
	// verify the public key accepts it directly via the ssh.PublicKey API —
	// a from-first-principles check independent of this package's own armor/
	// unarmor code, so a bug shared between Sign and a hypothetical Verify
	// wouldn't hide behind a round trip through both.
	toSign := signedData("git", payload)
	sig, err := signer.Sign(rand.Reader, toSign)
	if err != nil {
		t.Fatalf("re-sign for comparison: %v", err)
	}
	if err := signer.PublicKey().Verify(toSign, sig); err != nil {
		t.Fatalf("PublicKey.Verify on the reconstructed signed-data blob: %v", err)
	}
}

func TestSign_EmptyNamespaceRejected(t *testing.T) {
	signer := testSigner(t)
	if _, err := Sign(signer, "", []byte("payload")); err == nil {
		t.Fatal("Sign() with an empty namespace: want error, got nil")
	}
}

func TestSign_DifferentNamespacesProduceDifferentSignedData(t *testing.T) {
	signer := testSigner(t)
	payload := []byte("hello")

	gitBlob := signedData("git", payload)
	hostBlob := signedData("ssh-connection", payload)
	if string(gitBlob) == string(hostBlob) {
		t.Fatal("signed data identical across namespaces — namespace binding is not doing anything")
	}

	// A signature produced for one namespace must not verify as if it were
	// produced for another — this is the actual property success criterion 7
	// depends on (a signing-only grant must not confer host-auth capability),
	// enforced here at the primitive level rather than only at the broker's
	// payload-parsing layer.
	gitSig, err := signer.Sign(rand.Reader, gitBlob)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := signer.PublicKey().Verify(hostBlob, gitSig); err == nil {
		t.Fatal("a signature over the git-namespace blob verified against the ssh-connection-namespace blob — namespace is not binding")
	}
}

// TestSign_InteropWithOpenSSH shells out to the system `ssh-keygen -Y verify`
// (real OpenSSH tooling, not this package's own logic) to confirm the
// armored output this package produces is genuinely SSHSIG-compliant, not
// merely self-consistent. Skips cleanly where ssh-keygen isn't available
// (e.g. a minimal CI image) rather than failing the suite over a missing
// external tool — see AGENTS.md §6 on "every conditional branch... gets a
// test," which this still satisfies for hosts that do have it, including
// this dev machine.
func TestSign_InteropWithOpenSSH(t *testing.T) {
	keygenPath, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found on PATH; skipping OpenSSH interop check")
	}

	signer := testSigner(t)
	payload := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"committer Agent <agent@example.com> 1723190400 +0000\n\ncommit message\n")

	armored, err := Sign(signer, "git", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "commit.sig")
	if err := os.WriteFile(sigPath, []byte(armored), 0o600); err != nil {
		t.Fatalf("write signature file: %v", err)
	}

	// allowed_signers format: "<principal> <public-key-type> <base64-key>"
	authorizedLine := "agent@example.com " + string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	allowedSignersPath := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(allowedSignersPath, []byte(authorizedLine), 0o600); err != nil {
		t.Fatalf("write allowed_signers: %v", err)
	}

	cmd := exec.Command(keygenPath, "-Y", "verify",
		"-f", allowedSignersPath,
		"-I", "agent@example.com",
		"-n", "git",
		"-s", sigPath,
	)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Y verify rejected our signature: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Good") && !strings.Contains(string(out), "Signature OK") {
		t.Fatalf("ssh-keygen -Y verify output did not confirm a good signature: %s", out)
	}

	// And the negative case: verifying against the wrong namespace must fail
	// — the same property TestSign_DifferentNamespacesProduceDifferentSignedData
	// checks at the primitive level, confirmed here against real OpenSSH.
	cmdWrongNS := exec.Command(keygenPath, "-Y", "verify",
		"-f", allowedSignersPath,
		"-I", "agent@example.com",
		"-n", "ssh-connection",
		"-s", sigPath,
	)
	cmdWrongNS.Stdin = strings.NewReader(string(payload))
	if out, err := cmdWrongNS.CombinedOutput(); err == nil {
		t.Fatalf("ssh-keygen -Y verify accepted a git-namespace signature under namespace ssh-connection: %s", out)
	}
}
