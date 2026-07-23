import { useState } from "react";
import { StagedDiffsPage } from "./pages/StagedDiffs";
import { GrantsPage } from "./pages/Grants";

type Tab = "staged-diffs" | "grants";

export default function App() {
  const [tab, setTab] = useState<Tab>("staged-diffs");

  return (
    <div className="app">
      <header>
        <h1>Chuvar</h1>
        <p className="subtitle">approval dashboard</p>
        <nav>
          <button className={tab === "staged-diffs" ? "active" : ""} onClick={() => setTab("staged-diffs")}>
            Staged diffs
          </button>
          <button className={tab === "grants" ? "active" : ""} onClick={() => setTab("grants")}>
            Grants
          </button>
        </nav>
      </header>
      <main>{tab === "staged-diffs" ? <StagedDiffsPage /> : <GrantsPage />}</main>
    </div>
  );
}
