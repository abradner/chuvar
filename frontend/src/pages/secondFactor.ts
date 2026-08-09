// The one shared "prove a second factor" ceremony for the pages that call
// strong-factor-gated mutations (Grants, StagedDiffs). TOTP and passkeys are
// equally accepted server-side (requireStrongFactor,
// backend/internal/api/api.go — the 2026-08-09 decision in
// docs/decisions.md), so the UI must offer both wherever it offers one: a
// reviewer whose authenticator app is unavailable but whose passkey isn't
// (or vice versa) should never be blocked by the politeness layer when the
// enforcement layer would let them through. window.prompt is the same
// deliberately-minimal stopgap UI those pages already use — this module
// exists so the TOTP-or-passkey choice lives in exactly one place rather
// than being re-implemented per page.
//
// Politeness, not enforcement: the server's gate is the chokepoint (deletion
// test — removing this module would change how a factor is collected, never
// whether one is required).
import { api, type SecondFactor } from "../api/client";
import { decodeRequestOptions, encodeAssertionHeader } from "./tokens/webauthnCodec";

export type { SecondFactor };

function browserSupportsPasskeys(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && typeof navigator?.credentials?.get === "function";
}

// promptSecondFactor collects one factor for a gated mutation: a typed TOTP
// code, or — left blank — a passkey assertion via the real
// navigator.credentials.get() ceremony. Returns null when the operator
// cancels (the caller should quietly do nothing, matching every existing
// prompt-cancel path); throws when a chosen ceremony fails (the caller's
// existing catch turns that into its error banner). Codes are trimmed:
// browsers commonly preserve accidental spaces when pasting, which would
// otherwise fail server-side validation on correct digits. Found in review
// of the original TOTP prompts; preserved here when they were unified.
export async function promptSecondFactor(action: string): Promise<SecondFactor | null> {
  const supportsPasskeys = browserSupportsPasskeys();
  const hint = supportsPasskeys ? " (leave blank to use a passkey)" : "";
  const input = window.prompt(`Enter TOTP code to ${action}${hint}`);
  if (input === null) return null;
  const totpCode = input.trim();
  if (totpCode) return { totpCode };
  if (!supportsPasskeys) {
    // Blank without passkey support used to silently cancel; an explicit
    // error is more legible than a prompt that reappears doing nothing.
    throw new Error("A TOTP code is required — this browser does not support passkeys.");
  }
  const options = await api.webauthnAssertBegin();
  const cred = (await navigator.credentials.get(decodeRequestOptions(options))) as PublicKeyCredential | null;
  if (!cred) return null;
  return { webauthnAssertion: encodeAssertionHeader(cred) };
}
