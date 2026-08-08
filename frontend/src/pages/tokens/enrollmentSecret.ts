// enrollmentSecret pulls the base32 secret out of an otpauth:// URI — the form
// most authenticator apps accept under "enter a setup key manually". Falls back
// to the whole URI rather than throwing: this runs during render, where an
// unhandled parse error would blank the page instead of degrading, and the
// operator can still enrol from the raw URI. The value is unrecoverable after
// that one render (see CreatedReviewerToken), so failing soft matters more here
// than anywhere else in the app. Presentation-side (a display formatting
// choice), which is why it lives with the view rather than the hook — its own
// file only so the view exports nothing but components (fast-refresh lint).
export function enrollmentSecret(uri: string): string {
  try {
    // `||`, not `??`: searchParams.get returns "" (not null) for a valueless
    // `?secret=`, and an empty setup key field is the one outcome worse than
    // showing the raw URI — the operator would have nothing to enrol from and
    // no way to get it back. Found in review.
    return new URL(uri).searchParams.get("secret") || uri;
  } catch {
    return uri;
  }
}
