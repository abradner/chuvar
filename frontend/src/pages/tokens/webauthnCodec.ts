// Converts between the JSON shape backend/internal/api/webauthn.go's
// register/assert endpoints speak (go-webauthn's protocol.CredentialCreation
// / protocol.CredentialAssertion, and the response the browser hands back
// from navigator.credentials.create()/.get()) and the ArrayBuffer-based
// shapes the real navigator.credentials Web API requires. Hand-written
// rather than a WebAuthn JSON helper library (e.g. @github/webauthn-json):
// the conversion is a fixed, small set of known fields (challenge, a handful
// of credential IDs), not a general-purpose concern, and AGENTS.md's UI
// standard asks for "no heavy dependency unless you can justify it" —
// pulling in a dependency to base64url-decode half a dozen fields isn't
// justified at this scale. usePasskeys.ts is the only caller.

// base64url (no padding) <-> ArrayBuffer, matching Go's base64.RawURLEncoding
// (protocol.URLEncodedBase64's wire format — see backend/webauthn.go's
// package comment) exactly on both sides.
export function base64urlToBuffer(b64url: string): ArrayBuffer {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  // Chunk-and-join rather than a per-byte `binary += String.fromCharCode(b)`:
  // that concat is O(n²) (each += reallocates and recopies the growing string).
  // Converting a bounded slice at a time with String.fromCharCode(...chunk) and
  // joining once is linear. The chunk stays well under the argument-count limit
  // browsers impose on spread/apply, so no "too many function arguments" risk.
  const CHUNK = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Wire shapes live in api/client.ts (every other wire-format interface in
// this codebase does too) — this file only converts them, it doesn't own them.
import type { CredentialCreationOptionsJSON, CredentialRequestOptionsJSON } from "../../api/client";

// --- Decode: backend JSON -> browser API options ---

export function decodeCreationOptions(json: CredentialCreationOptionsJSON): CredentialCreationOptions {
  const pk = json.publicKey;
  return {
    publicKey: {
      rp: pk.rp,
      user: {
        id: base64urlToBuffer(pk.user.id),
        name: pk.user.name,
        displayName: pk.user.displayName,
      },
      challenge: base64urlToBuffer(pk.challenge),
      pubKeyCredParams: pk.pubKeyCredParams,
      timeout: pk.timeout,
      excludeCredentials: pk.excludeCredentials?.map((c) => ({
        type: c.type,
        id: base64urlToBuffer(c.id),
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
      authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
      attestation: pk.attestation as AttestationConveyancePreference | undefined,
    },
  };
}

export function decodeRequestOptions(json: CredentialRequestOptionsJSON): CredentialRequestOptions {
  const pk = json.publicKey;
  return {
    publicKey: {
      challenge: base64urlToBuffer(pk.challenge),
      timeout: pk.timeout,
      rpId: pk.rpId,
      allowCredentials: pk.allowCredentials?.map((c) => ({
        type: c.type,
        id: base64urlToBuffer(c.id),
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
      userVerification: pk.userVerification as UserVerificationRequirement | undefined,
    },
  };
}

// --- Encode: browser API response -> backend JSON ---

// encodeCreationResponse produces the body webauthnRegisterFinish
// (backend/internal/api/webauthn.go) parses via
// protocol.ParseCredentialCreationResponseBytes, plus a "label" field that
// handler separately reads from the same bytes (its own doc comment).
export function encodeCreationResponse(cred: PublicKeyCredential, label: string): unknown {
  const response = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
    },
    label,
  };
}

// encodeAssertionResponse produces the value carried in the
// X-Chuvar-WebAuthn-Assertion header (base64 of this JSON — see
// webauthnAssertionHeader's doc comment in the backend).
export function encodeAssertionResponse(cred: PublicKeyCredential): unknown {
  const response = cred.response as AuthenticatorAssertionResponse;
  const body: Record<string, unknown> = {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
    },
  };
  if (response.userHandle) {
    (body.response as Record<string, unknown>).userHandle = bufferToBase64url(response.userHandle);
  }
  return body;
}

// encodeAssertionHeader is the full header value: base64 of the JSON body
// above, matching webauthnAssertionHeader's "base64 of the assertion JSON"
// contract exactly (not base64url — the backend decodes with
// encoding/base64.StdEncoding).
export function encodeAssertionHeader(cred: PublicKeyCredential): string {
  const json = JSON.stringify(encodeAssertionResponse(cred));
  // btoa operates on a binary string (one code unit per byte); JSON from
  // JSON.stringify of ASCII-safe base64url content is already within that
  // range, so no UTF-8 encoding step is needed here.
  return btoa(json);
}
