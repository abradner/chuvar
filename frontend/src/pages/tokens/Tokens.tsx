// The page: layout and plumbing only — it calls the hook and hands the result
// to the view. Kept as one thin file rather than a separate "container"
// component: with hooks, a component whose only job is holding state and
// passing props is a layer with no behaviour of its own (AGENTS.md §6, "UI
// component standard"). If this feature ever needs a second view over the same
// data, or layout complex enough to test, that is the moment to split — not
// before.
import { TokensView } from "./TokensView";
import { useTokens } from "./useTokens";

export interface TokensPageProps {
  onRevealChange?: (pending: boolean) => void;
}

export function TokensPage({ onRevealChange }: TokensPageProps = {}) {
  const { tokens, loadError, error, busyId, creating, justCreated, create, dismissReveal, revoke } = useTokens({
    onRevealChange,
  });

  return (
    <TokensView
      tokens={tokens}
      loadError={loadError}
      error={error}
      busyId={busyId}
      creating={creating}
      justCreated={justCreated}
      onCreate={create}
      onDismissReveal={dismissReveal}
      onRevoke={revoke}
    />
  );
}
