package api

// A minimal, from-scratch virtual WebAuthn authenticator used only to drive
// real registration/assertion ceremonies against the real go-webauthn
// library in tests. Deliberately not a mock of this package's own code: it
// builds genuine CBOR (via the library's own webauthncbor/webauthncose
// packages, so the wire format matches exactly what a browser + real
// authenticator would produce), a genuine ECDSA P-256 keypair, and genuine
// signatures — every ceremony test in webauthn_test.go exercises the actual
// parsing, signature verification, RP ID/origin checks, and counter logic
// this package's handlers run in production, not a stand-in for them.
// Attestation is "none" throughout: chuvar never validates an attestation
// chain (webauthnRegisterFinish accepts whatever go-webauthn's own
// CreateCredential validates, which for fmt "none" is just the structural
// checks), so a self-signed key is sufficient to cover every path this
// package actually runs.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

type virtualAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	counter      uint32
	// backupEligible/backupState must be reported identically at every
	// ceremony for one credential — go-webauthn's login.go hard-fails an
	// assertion whose BackupEligible flag doesn't match what registration
	// reported (see the webauthn_credentials migration's doc comment), so a
	// test simulating one authenticator keeps the same value throughout.
	backupEligible bool
	backupState    bool
}

func newVirtualAuthenticator(t *testing.T, credentialID string, backupEligible bool) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return &virtualAuthenticator{key: key, credentialID: []byte(credentialID), backupEligible: backupEligible}
}

func rpIDHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

// flags returns the authenticator-data flags byte common to both ceremonies:
// UP (user present) and UV (user verified) always set — every ceremony this
// package initiates requests UserVerification: required (api.go's
// requireExistingSecondFactor / cmd/apiserver's newWebAuthn) — plus BE/BS
// per this authenticator's simulated backup posture. AT (attested credential
// data) and ED (extensions) are added by the caller when relevant.
func (v *virtualAuthenticator) flags() byte {
	var f byte = 0x01 | 0x04 // UP | UV
	if v.backupEligible {
		f |= 0x08 // BE
	}
	if v.backupState {
		f |= 0x10 // BS
	}
	return f
}

func (v *virtualAuthenticator) coseKeyBytes(t *testing.T) []byte {
	t.Helper()
	pub := v.key.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey), // COSE kty=2 (EC2)
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: x,
		YCoord: y,
	}
	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("webauthncbor.Marshal(cose key) error = %v", err)
	}
	return b
}

// authenticatorData builds the raw authData bytes per §6.1 of the spec.
// attested is true only for registration — that's the AT flag plus the
// attested-credential-data block (AAGUID, credential ID, COSE public key).
func (v *virtualAuthenticator) authenticatorData(t *testing.T, rpID string, attested bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(rpIDHash(rpID))

	flags := v.flags()
	if attested {
		flags |= 0x40 // AT
	}
	buf.WriteByte(flags)

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, v.counter)
	buf.Write(counter)

	if attested {
		buf.Write(make([]byte, 16)) // AAGUID: all-zero for this test authenticator
		idLen := make([]byte, 2)
		binary.BigEndian.PutUint16(idLen, uint16(len(v.credentialID)))
		buf.Write(idLen)
		buf.Write(v.credentialID)
		buf.Write(v.coseKeyBytes(t))
	}
	return buf.Bytes()
}

func buildClientDataJSON(t *testing.T, ceremonyType protocol.CeremonyType, challenge protocol.URLEncodedBase64, origin string) []byte {
	t.Helper()
	cd := map[string]any{
		"type":        string(ceremonyType),
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	}
	b, err := json.Marshal(cd)
	if err != nil {
		t.Fatalf("json.Marshal(clientDataJSON) error = %v", err)
	}
	return b
}

// sign computes the WebAuthn assertion/attestation signature over authData
// || SHA-256(clientDataJSON): ES256 (COSE alg -7) is "ECDSA using P-256 and
// SHA-256", so the value actually ECDSA-signed is SHA-256 of that
// concatenation — matching webauthncose.EC2PublicKeyData.Verify's own
// hash-then-verify shape (protocol/assertion.go's sigData construction).
func (v *virtualAuthenticator) sign(t *testing.T, authData, clientDataJSON []byte) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256(clientDataJSON)
	sigData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	sig, err := ecdsa.SignASN1(rand.Reader, v.key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() error = %v", err)
	}
	return sig
}

// register performs a full registration ceremony against a
// *protocol.CredentialCreation (as returned by POST /api/webauthn/register/begin)
// and returns the JSON body a browser's navigator.credentials.create() would
// hand back — ready to POST to /register/finish. label is folded into the
// same JSON body (registerFinishRequest ignores every other field it
// doesn't recognise, and vice versa: the standard encoding/json behaviour
// webauthnRegisterFinish's doc comment relies on).
func (v *virtualAuthenticator) register(t *testing.T, creation *protocol.CredentialCreation, rpID, origin, label string) []byte {
	t.Helper()
	cdj := buildClientDataJSON(t, protocol.CreateCeremony, creation.Response.Challenge, origin)
	authData := v.authenticatorData(t, rpID, true)

	attObj := struct {
		Fmt      string                 `json:"fmt"`
		AttStmt  map[string]interface{} `json:"attStmt"`
		AuthData []byte                 `json:"authData"`
	}{Fmt: "none", AttStmt: map[string]interface{}{}, AuthData: authData}
	attObjBytes, err := webauthncbor.Marshal(attObj)
	if err != nil {
		t.Fatalf("webauthncbor.Marshal(attestationObject) error = %v", err)
	}

	body := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(v.credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(v.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdj),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObjBytes),
		},
		"label": label,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal(registration response) error = %v", err)
	}
	return b
}

// assert performs a full assertion ceremony against a
// *protocol.CredentialAssertion (as returned by POST /api/webauthn/assert/begin)
// and returns the JSON body a browser's navigator.credentials.get() would
// hand back, base64-encoded exactly as webauthnAssertionHeader expects.
// Increments the simulated counter first — a real authenticator's counter
// reflects *this* use, not the last one — unless overridden by the caller via
// setCounter for clone-signal tests.
func (v *virtualAuthenticator) assert(t *testing.T, assertion *protocol.CredentialAssertion, rpID, origin string) string {
	t.Helper()
	v.counter++
	return v.assertWithCounter(t, assertion, rpID, origin, v.counter)
}

// assertWithCounter is assert with an explicit counter value, letting a test
// simulate a cloned authenticator reporting a regressed or repeated counter
// without needing a second real authenticator.
func (v *virtualAuthenticator) assertWithCounter(t *testing.T, assertion *protocol.CredentialAssertion, rpID, origin string, counter uint32) string {
	t.Helper()
	v.counter = counter
	cdj := buildClientDataJSON(t, protocol.AssertCeremony, assertion.Response.Challenge, origin)
	authData := v.authenticatorData(t, rpID, false)
	sig := v.sign(t, authData, cdj)

	body := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(v.credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(v.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdj),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal(assertion response) error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
