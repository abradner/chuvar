// Package sshsig produces SSH signatures in the armored SSHSIG format that
// `git` expects when `gpg.format = ssh` (the format openssh's
// `ssh-keygen -Y sign` produces, and `ssh-keygen -Y verify` and
// `git log --show-signature` consume). See openssh's PROTOCOL.sshsig.
//
// This package signs whatever bytes it is given, in whatever namespace it is
// told — it does not know about git commit objects or chuvar's grant model.
// The "never blind-signs" constraint (capability-broker.md, "The broker must
// not blind-sign") is enforced by internal/broker/commit and internal/broker
// deciding what may reach Sign and which namespace it is signed under, not by
// this package. Keeping this package generic-but-narrow (a namespace and a
// payload, nothing else) is what lets that caller be the one place the
// constraint lives, rather than duplicated here.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// magicPreamble opens both the "to-be-signed" blob and the final armored
// structure, per PROTOCOL.sshsig.
const magicPreamble = "SSHSIG"

// sigVersion is the only version PROTOCOL.sshsig defines.
const sigVersion uint32 = 1

// hashAlgorithm is fixed at sha256 — PROTOCOL.sshsig also allows sha512, but
// there is no reason for chuvar to support two and sha256 matches what
// ssh-keygen defaults to and what every consumer expects.
const hashAlgorithm = "sha256"

// lineWidth matches openssh's own SSHSIG_LINEWIDTH (sshsig.c), so output
// this package produces is byte-for-byte the shape a human comparing it to
// `ssh-keygen -Y sign` output would expect — not load-bearing for
// correctness (any base64 line width parses the same), but worth matching
// rather than picking an arbitrary different one.
const lineWidth = 70

// writeString appends an SSH wire-format "string": a big-endian uint32
// length prefix followed by the raw bytes. Every variable-length field in
// both the outer SSHSIG structure and the inner "to-be-signed" blob is one
// of these — see PROTOCOL.sshsig's grammar.
func writeString(buf *bytes.Buffer, s []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf.Write(lenBuf[:])
	buf.Write(s)
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

// signedData builds the blob that actually gets signed, per PROTOCOL.sshsig's
// "signed data" structure — which is deliberately smaller than the final
// armored blob below: just the magic preamble, namespace, reserved, hash
// algorithm, and H(message). No version and no public key here (both belong
// only to the outer, unsigned wrapper) — including the pubkey in this blob
// was an earlier bug in this package, caught by TestSign_InteropWithOpenSSH
// failing against real `ssh-keygen -Y verify` even though every self-check
// in this package passed, because self-checks reconstruct the same (wrong)
// blob on both the signing and verifying side and so can't catch a
// structural mismatch against the actual spec.
func signedData(namespace string, payload []byte) []byte {
	sum := sha256.Sum256(payload)

	var buf bytes.Buffer
	buf.WriteString(magicPreamble)
	writeString(&buf, []byte(namespace))
	writeString(&buf, nil) // reserved, per spec: always empty
	writeString(&buf, []byte(hashAlgorithm))
	writeString(&buf, sum[:])
	return buf.Bytes()
}

// Sign produces an armored SSHSIG signature over payload, under the given
// namespace, using signer. namespace is caller-controlled deliberately —
// git commit signatures use "git"; this package has no opinion and enforces
// nothing about which namespaces are legitimate, because it has no basis to:
// that judgment belongs to whatever decided payload was safe to sign in the
// first place.
func Sign(signer ssh.Signer, namespace string, payload []byte) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("sshsig: namespace must not be empty")
	}
	pubKeyBlob := signer.PublicKey().Marshal()

	toSign := signedData(namespace, payload)
	sig, err := signer.Sign(rand.Reader, toSign)
	if err != nil {
		return "", fmt.Errorf("sshsig: signing: %w", err)
	}
	// ssh.Marshal on a *ssh.Signature encodes exactly {string Format, string
	// Blob} (Signature's third field, Rest, is tagged `ssh:"rest"` and is
	// empty on a signature we just produced) — precisely the wire-format
	// "signature blob" PROTOCOL.sshsig's outer structure embeds as its own
	// "signature" string field.
	sigBlob := ssh.Marshal(sig)

	var out bytes.Buffer
	out.WriteString(magicPreamble)
	writeUint32(&out, sigVersion)
	writeString(&out, pubKeyBlob)
	writeString(&out, []byte(namespace))
	writeString(&out, nil)
	writeString(&out, []byte(hashAlgorithm))
	writeString(&out, sigBlob)

	return armor(out.Bytes()), nil
}

// armor base64-encodes body and wraps it in the "-----BEGIN/END SSH
// SIGNATURE-----" markers git and ssh-keygen expect, line-wrapped at
// lineWidth like ssh-keygen's own output.
func armor(body []byte) string {
	encoded := base64.StdEncoding.EncodeToString(body)

	var sb strings.Builder
	sb.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for i := 0; i < len(encoded); i += lineWidth {
		end := i + lineWidth
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END SSH SIGNATURE-----\n")
	return sb.String()
}
