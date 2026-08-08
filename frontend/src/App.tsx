import { useCallback, useState } from "react";
import { StagedDiffsPage } from "./pages/StagedDiffs";
import { GrantsPage } from "./pages/Grants";
import { TokensPage } from "./pages/tokens/Tokens";

type Tab = "staged-diffs" | "grants" | "tokens";

export default function App() {
  const [tab, setTab] = useState<Tab>("staged-diffs");
  // Tabs unmount their page, which for TokensPage means discarding a
  // just-created bearer token and TOTP setup key that exist nowhere else — the
  // server kept only a hash. The page reports when one is on screen; switching
  // away then costs a confirm. Held here because the nav lives here, and the
  // page cannot veto its own unmount.
  const [revealPending, setRevealPending] = useState(false);

  // Stable identity: TokensPage reports through this from an effect keyed on
  // it, so a new function each render would re-fire that effect every render.
  const handleRevealChange = useCallback((pending: boolean) => setRevealPending(pending), []);

  const switchTab = (next: Tab) => {
    if (next === tab) return;
    if (
      revealPending &&
      !window.confirm("The new token and setup key are still on screen and cannot be shown again. Leave anyway?")
    ) {
      return;
    }
    setRevealPending(false);
    setTab(next);
  };

  return (
    <div className="app">
      <header>
        <h1>Chuvar</h1>
        <p className="subtitle">approval dashboard</p>
        <nav>
          <button className={tab === "staged-diffs" ? "active" : ""} onClick={() => switchTab("staged-diffs")}>
            Staged diffs
          </button>
          <button className={tab === "grants" ? "active" : ""} onClick={() => switchTab("grants")}>
            Grants
          </button>
          <button className={tab === "tokens" ? "active" : ""} onClick={() => switchTab("tokens")}>
            Tokens
          </button>
        </nav>
      </header>
      <main>
        {tab === "staged-diffs" && <StagedDiffsPage />}
        {tab === "grants" && <GrantsPage />}
        {tab === "tokens" && <TokensPage onRevealChange={handleRevealChange} />}
      </main>
    </div>
  );
}
