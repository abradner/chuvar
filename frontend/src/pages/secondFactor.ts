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
import { api, ApiError, type SecondFactor } from "../api/client";
import { decodeRequestOptions, encodeAssertionHeader } from "./tokens/webauthnCodec";

export type { SecondFactor };

function browserSupportsPasskeys(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && typeof navigator?.credentials?.get === "function";
}

export interface PromptSecondFactorOptions {
  // createToken's factor is conditional server-side (its own doc comment,
  // backend/internal/api/tokens.go): required only once a factor of either
  // kind has ever been enrolled anywhere, never for a fresh install, and
  // never after the direct-database break-glass recovery in
  // docs/operations.md restores that same "nothing enrolled" state. That
  // caller passes optional: true so the two "this device genuinely has
  // nothing to prove" signals below degrade to an empty SecondFactor
  // instead of erroring — every other caller leaves this unset and keeps
  // today's unconditional behavior byte-for-byte.
  optional?: boolean;
}

// promptSecondFactor collects one factor for a gated mutation: a typed TOTP
// code, or — left blank — a passkey assertion via the real
// navigator.credentials.get() ceremony. Returns null when the operator
// cancels (the caller should quietly do nothing, matching every existing
// prompt-cancel path); throws when a chosen ceremony fails (the caller's
// existing catch turns that into its error banner) — unless opts.optional
// is set and the failure is specifically "this device has no factor to
// offer" (see PromptSecondFactorOptions), in which case it resolves to an
// empty SecondFactor instead. Codes are trimmed: browsers commonly preserve
// accidental spaces when pasting, which would otherwise fail server-side
// validation on correct digits. Found in review of the original TOTP
// prompts; preserved here when they were unified.
export async function promptSecondFactor(
  action: string,
  opts?: PromptSecondFactorOptions,
): Promise<SecondFactor | null> {
  const supportsPasskeys = browserSupportsPasskeys();
  const hint = supportsPasskeys ? " (leave blank to use a passkey)" : "";
  const input = window.prompt(`Enter TOTP code to ${action}${hint}`);
  if (input === null) return null;
  const totpCode = input.trim();
  if (totpCode) return { totpCode };
  if (!supportsPasskeys) {
    if (opts?.optional) return {};
    // Blank without passkey support used to silently cancel; an explicit
    // error is more legible than a prompt that reappears doing nothing.
    throw new Error("A TOTP code is required — this browser does not support passkeys.");
  }
  let options;
  try {
    options = await api.webauthnAssertBegin();
  } catch (e) {
    // webauthnAssertBegin scopes to the calling reviewer token's own
    // credentials (backend's own doc comment) and answers 409 when it has
    // none — that is the "no passkey enrolled" signal, not a transient
    // failure, so an optional caller degrades to no factor rather than
    // surfacing it. Any other status (auth failure, server error) still
    // propagates; only "nothing to offer" is safe to swallow here.
    if (opts?.optional && e instanceof ApiError && e.status === 409) return {};
    throw e;
  }
  const cred = (await navigator.credentials.get(decodeRequestOptions(options))) as PublicKeyCredential | null;
  if (!cred) return null;
  return { webauthnAssertion: encodeAssertionHeader(cred) };
}
