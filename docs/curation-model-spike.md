# Curation model spike — embedding choice + scope classifier prototype

Research spike run 2026-08-11/12 covering issues **#64** (choose an embedding
model for dedupe/classify) and **#63** (prototype a tiny in-memory scope
classifier), run together because the issues name each other as siblings —
the classifier is expected to build on whatever embedding model #64 picks.
Run **on the real target host**, in the style of `docs/broker-spikes.md`:
working prototypes and measured numbers, not desk research. All prototype
code lived under a disposable scratch directory outside the repo and was
deleted at the end of the run; nothing under `backend/` changed. No database
was needed and none was started — see "What was not tested" for what that
costs.

Preserved here for the same reason `broker-spikes.md` was: the applied
conclusion will end up as a one-line comment in `internal/embed` when a real
`Embedder` lands, and the next person to ask "why MiniLM and not
bge-small?" or "why not just use the hashing classifier, it's free?"
deserves the reproduction, not a restatement of the verdict.

---

## Host facts (verified, not assumed)

- `uname -a`: Linux, kernel `6.18.39+rpt-rpi-2712`, aarch64.
- Device tree model string: **Raspberry Pi Compute Module 5 Lite Rev 1.0**
  — same BCM2712 SoC family as the "Raspberry Pi 5" host named in
  `broker-spikes.md`'s spikes, not a different board generation.
- `getconf PAGESIZE`: **16384 bytes** — confirmed again; still not the
  common 4096 on x86_64, still worth re-checking rather than assuming for
  any future measurement on this host.
- `nproc`: 4 cores.
- `free -h`: 7.9Gi RAM total (1.2Gi free, 4.0Gi available at spike start),
  2.0Gi swap (1.6Gi in use at spike start — this host was under some
  pre-existing memory pressure from other work; RSS deltas below are
  measured against that baseline, not a clean-boot baseline).
- Go **1.26.5 linux/arm64**, resolved via `mise`. `mise exec -- go` only
  resolves `go` for commands run inside the chuvar tree (same limitation
  `broker-spikes.md` recorded); prototype code living outside the tree used
  `mise`'s resolved absolute Go binary path directly.
- Outbound network access to GitHub and HuggingFace was available from this
  host for the duration of the spike — used only to fetch a prebuilt
  inference binary and two model files, once, as setup steps. This does not
  contradict the "no external network dependency" constraint in #64, which
  is about the embedder's *runtime* behavior, not about how its one-time
  binary/model artifacts are acquired — every self-hosted piece of software
  is fetched from somewhere once. It does mean this spike cannot speak to
  what a fully air-gapped install/update flow needs; see "What was not
  tested."

## What was built

### For #64: two local embedding-model candidates, served locally

**Inference engine:** `llama.cpp` release `b10360` (commit `48d22e295`),
prebuilt `ubuntu-arm64` binary tarball fetched from the project's GitHub
releases (13.4MB compressed, 32MB unpacked, `llama-server` + shared
libraries). Ran and linked correctly against this host's glibc with no
compilation needed — no toolchain, no build step, matching the "small
enough for modest hardware" bar before a single model byte is even loaded.

**Model candidates**, both quantized to `Q8_0` (the smallest quantization
level generally considered to preserve embedding quality — anything more
aggressive trades meaningfully more accuracy for marginal size savings on
models already this small) and both producing **384-dimensional** vectors,
matching the `vector(384)` column already committed in the `facts` table
schema and `internal/embed.Dim`'s existing comment naming MiniLM as its
placeholder rationale:

| Candidate | Source | File size (Q8_0) | Params (approx.) |
|---|---|---|---|
| `all-MiniLM-L6-v2` | `leliuga/all-MiniLM-L6-v2-GGUF` (HF) | 23.9 MB | ~23M |
| `bge-small-en-v1.5` | `ggml-org/bge-small-en-v1.5-Q8_0-GGUF` (HF) | 35.0 MB | ~33M |

Each was served as `llama-server -m <model>.gguf --embedding --pooling mean
--port <port> --host 127.0.0.1`, one process per model, on ports in the
assigned disposable range (55901/55902). This exposes an OpenAI-compatible
`POST /v1/embeddings` endpoint over loopback HTTP — the shape suggested by
the issue's "in-process or via a local OpenAI-compatible server (Ollama /
llama.cpp)" framing. Ollama itself was not installed on this host and was
not separately tried; see "What was not tested."

**Reproduction:** download the matching `llama-b10360-bin-<platform>.tar.gz`
asset from the `ggml-org/llama.cpp` GitHub releases page for the target
architecture, download a `Q8_0` GGUF of the target model from the HF repos
above, run the `llama-server` command above, and `curl -X POST
http://127.0.0.1:<port>/v1/embeddings -d '{"input": "some text"}'` (or
`{"input": ["a", "b", ...]}` for a batch). No compilation, no Python
environment, no GPU.

### For #63: two classifier prototypes, evaluated identically

**Classical baseline** (pure Go, `mise`-resolved Go 1.26.5, stdlib only, no
dependencies): a feature-hashing bag-of-words vectorizer (lowercase,
`[a-z0-9]+` tokenize, FNV-1a hash into a 512-slot vector, term-frequency
counts, L2-normalized) feeding a **nearest-centroid classifier** — per-class
centroid computed from training vectors, classify by highest cosine
similarity (a dot product, since vectors are pre-normalized). This is the
"genuinely tiny classical baseline" the issue calls out: no model file, no
embedding call, no external process.

**Embedding-based classifier**: the same nearest-centroid strategy, but
built on top of the #64 candidates' embedding vectors instead of hashed
bag-of-words — isolates whether semantic embeddings actually buy accuracy
over the classical approach for *this* task, using an identical evaluation
methodology so the two numbers are directly comparable.

**Evaluation corpus**: 24 hand-labelled short facts across 4 scope labels
(`identity.personal`, `identity.schedule`, `projects.chuvar.architecture`,
`projects.chuvar.preferences`) — invented for this spike, not sourced from a
settled taxonomy (none exists yet; `AGENTS.md` §3.4 states the taxonomy is
still open). 8–9 items in the two largest classes, 4–6 in the two smallest.
Evaluated with **leave-one-out cross-validation** (LOOCV: each item held out
and classified using centroids built from the other 23) rather than a
train/test split, because a corpus this small would leave too few examples
per class in either split to mean anything — LOOCV uses every item as a test
case exactly once, which is the honest choice for a corpus this size, not a
free pass on the small-N problem itself (see "What was not tested").

**Reproduction:** a Go module with a `main.go` implementing the vectorizer,
centroid builder, and LOOCV loop over an inlined corpus (mirrored exactly
from the Python corpus module used for the embedding-based run, same texts
and labels, so the two accuracy numbers are comparable); `go run .` prints
LOOCV accuracy, per-miss detail, and latency. The embedding-based variant is
a short Python script that re-embeds the same corpus via the already-running
local `llama-server` and runs the identical LOOCV loop.

---

## Measurements

### Load time and idle memory (#64)

Measured from process launch to the first successful `/health` response,
and resident memory (`VmRSS`) at that moment.

| Model | Load time | RSS at ready |
|---|---|---|
| MiniLM-L6-v2 Q8_0 | 0.227 s | 61.4 MB |
| bge-small-en-v1.5 Q8_0 | 0.237 s | 84.9 MB |

Both load in well under a second — the model file is small enough that
loading is dominated by process/HTTP-server startup, not weight parsing.

### Single-item embedding latency (#64)

40 sequential `POST /v1/embeddings` calls over loopback HTTP, after one
warm-up call excluded from the sample, each call sending one short
sentence (representative fact length).

| Model | mean | p50 | p95 | min | max |
|---|---|---|---|---|---|
| MiniLM-L6-v2 | 4.30 ms | 3.66 ms | 7.90 ms | 3.51 ms | 12.46 ms |
| bge-small-en-v1.5 | 10.79 ms | 7.46 ms | 22.27 ms | 5.88 ms | 41.49 ms |

MiniLM is roughly 2–2.5x faster across the board. Both numbers include full
loopback HTTP round-trip overhead (JSON encode/decode, TCP on 127.0.0.1),
not just model forward-pass time — realistic for the "call a local sidecar
server" deployment shape, not a lower bound on raw inference speed.

### Batched throughput (#64)

One request with 50 inputs in a single `input` array, versus the sequential
per-item numbers above.

| Model | per-item, batch=50 | per-item, sequential (p50) | speedup |
|---|---|---|---|
| MiniLM-L6-v2 | 2.00 ms | 3.66 ms | ~1.8x |
| bge-small-en-v1.5 | 4.55 ms | 7.46 ms | ~1.6x |

Batching roughly halves per-item cost by amortizing HTTP/request overhead —
worth using for any bulk-embed path (e.g. a future bulk-import feature),
though the write path's actual traffic pattern (one staged fact at a time,
human-paced) may never exercise this.

### Scale test — 300 synthetic facts, sequential (#64)

A larger, templated synthetic corpus (not the hand-labelled evaluation
corpus — see methodology note in "What was not tested") embedded one at a
time to check whether per-item latency or memory holds steady under
sustained, not just momentary, load.

| Model | throughput | mean | p50 | p95 | RSS before | RSS after | ΔRSS |
|---|---|---|---|---|---|---|---|
| MiniLM-L6-v2 | 186 items/s | 5.31 ms | 3.74 ms | 11.34 ms | 67.8 MB | 67.8 MB | +16 KB |
| bge-small-en-v1.5 | 113.5 items/s | 8.74 ms | 6.30 ms | 19.95 ms | 91.2 MB | 91.2 MB | +64 KB |

Memory is flat under 300 sequential embeds — no leak signal at this scale
and duration (single-digit seconds of continuous load; see "What was not
tested" for the duration this does *not* cover).

### Dedupe quality (#64)

37-item corpus: 8 groups of human-paraphrased "same fact" sentences (27
within-group pairs total) plus 12 mutually distinct facts (639
cross/distinct pairs against everything else). Cosine similarity computed
for every pair; a naive "flag as duplicate if similarity ≥ threshold" rule
— exactly the operation the bouncer's dedupe step performs against the
nearest existing fact — evaluated by sweeping the threshold for best F1,
and separately at a fixed, unremarkable default threshold of 0.85.

| Model | within-group sim (mean / min / max) | cross/distinct sim (mean / min / max) | best-F1 threshold | best F1 | precision/recall @ 0.85 |
|---|---|---|---|---|---|
| MiniLM-L6-v2 | 0.884 / 0.742 / 0.976 | 0.140 / −0.117 / 0.531 | 0.54 | 1.00 | 1.00 / 0.70 |
| bge-small-en-v1.5 | 0.930 / 0.876 / 0.990 | 0.417 / 0.197 / 0.697 | 0.70 | 1.00 | 1.00 / 1.00 |

Both models achieve perfect separation on this corpus at *some* threshold —
the lowest within-group similarity (MiniLM 0.742) is comfortably above the
highest cross/distinct similarity (MiniLM 0.531). But the models differ in
how forgiving they are of an unremarkable fixed threshold: at 0.85, MiniLM
misses 30% of true paraphrase pairs (recall 0.70) while bge-small still
gets all of them. This is a real, measured tradeoff, not a wash — whichever
model ships, the threshold needs tuning against real data, not a
borrowed default.

### Hard-negative probe: near-identical wording, opposite meaning (#64)

The dedupe corpus above tests whether *different phrasings of the same
fact* land close together. It does not test the opposite failure mode:
whether *near-identical phrasings of different (even contradictory) facts*
land far apart. This matters directly for `docs/architecture.md`'s framing
of dedupe as also catching "manipulated or poisoned writes" — a
contradiction is exactly the case where wording is nearly identical but
meaning flips.

| Pair | MiniLM sim | bge-small sim |
|---|---|---|
| "dark roast" vs "light roast" coffee preference | 0.9721 | 0.9690 |
| dentist appointment "14th" vs "15th" | 0.9564 | 0.8884 |
| "allergic" vs "not allergic" to shellfish | 0.9611 | 0.8539 |
| deployment window "2am–4am" vs "2pm–4pm" | 0.9542 | 0.9514 |

**This is the most important finding in this spike.** Every contradictory
pair scores *higher* on cosine similarity than the best-F1 threshold picked
above for genuine paraphrase detection (0.54–0.70) — in most cases higher
than even the 0.85 fixed threshold. Cosine-similarity dedupe **cannot**, on
its own, distinguish "this is the same fact restated" from "this looks like
the same fact but says the opposite." Neither candidate model does better
than the other here in any way that would change a recommendation — this is
a property of embedding-based semantic similarity generally, not a
weakness specific to one model.

This validates, rather than undermines, the existing design: the bouncer
finds the *nearest* candidate and stages it for human review
(`AGENTS.md` §3.1) — it was never designed to auto-merge or auto-discard on
similarity alone. This measurement is the concrete reason that design
choice is load-bearing: **a similarity threshold must never become an
auto-merge/auto-discard decision** for either candidate model. If a future
change ever treats "sim ≥ threshold" as anything stronger than "surface
this pair to a human," that change reopens exactly the poisoned-write
vector `architecture.md` describes catching.

### Scope classifier accuracy — classical baseline vs. embedding-based (#63)

LOOCV over the same 24-item, 4-class corpus, same methodology, for both
approaches.

| Approach | Accuracy | Misses |
|---|---|---|
| Hashing + nearest-centroid, raw tokens | 15/24 = **0.625** | 9 |
| Hashing + nearest-centroid, stopwords removed | 16/24 = **0.667** | 8 |
| MiniLM embedding + nearest-centroid | 18/24 = **0.750** | 6 |
| bge-small embedding + nearest-centroid | 18/24 = **0.750** | 6 |

**This is a negative result worth keeping.** None of these numbers clear a
bar anyone should call "solved." The classical baseline is genuinely weak
(62.5–66.7%) — confirming the issue's own framing that scope assignment
needs more than raw lexical overlap to be "useful rather than noisy": most
misses were `identity.personal` vs `identity.schedule` confusions, where
the actual words used ("appointment", "on the", a date) don't carry the
class signal a human intuitively uses. Embeddings help — a full ~9–12
point jump in absolute accuracy — but plateau at 75%, and several of the
remaining misses (see below) look as much like genuine taxonomy ambiguity
as classifier error:

```
"Alex's dentist appointment is on the 14th at 9am."
  want=identity.schedule got=identity.personal
"The garage door opener remote needs a new battery."
  want=identity.personal got=projects.chuvar.preferences
"The office wifi password was changed last Friday."
  want=projects.chuvar.preferences got=identity.schedule
```

A reasonable person could label any of these differently than this spike
did. Treat 75% as "meaningfully better than the classical baseline, on this
evidence" — not as a production-readiness number. See "What was not
tested" for exactly why this ceiling should not be taken as final.

### Classifier latency (#63)

| Step | Implementation | Latency |
|---|---|---|
| Vectorize (hash + normalize) | Go | 5.20 µs/op |
| Vectorize + centroid classify | Go | 8.30 µs/op |
| Centroid classify only (post-embedding) | Python | ~218 µs/op |
| Embedding call itself | via llama-server | 3.5–11 ms (see above) |

The classical baseline's entire cost (~8 µs) is noise next to a single
Postgres round trip, let alone a human review cycle — genuinely "in-memory,
modest hardware, no measurable cost" territory. The embedding-based
classifier's *added* cost over dedupe (which already pays for the embedding
call) is the centroid-match step alone — measured here at ~218 µs in
unoptimized Python; a Go implementation of the same dot-product-against-4-
centroids operation would be expected to land in the single-digit
microseconds, close to the classical baseline's own vectorize+classify
number, though this specific number (Go centroid-match-only) was not
separately isolated and is not claimed as measured. The embedding call
itself, not the classify step, is what actually costs milliseconds — and
dedupe needs to pay that cost regardless of what the classifier does.

### Projected pgvector index size (#64) — arithmetic, not measured

No Postgres instance was started for this spike (none was needed for
anything above). These are **projections from pgvector's documented
on-disk format** — `vector(384)` stored as 384 × 4-byte float32, plus a
rough per-vector HNSW graph-link estimate at default parameters (`m=16`) —
not a live measurement. Flagged explicitly as arithmetic, not data, per
this spike's own instructions: presenting an estimate as a measurement
would be exactly the kind of quiet overclaim this document exists to avoid.

| Fact count | Raw vector data | Est. total incl. HNSW graph |
|---|---|---|
| 1,000 | 1.5 MB | 1.7 MB |
| 10,000 | 15.4 MB | 17.3 MB |
| 100,000 | 153.6 MB | 172.8 MB |

Even at 100k facts — an implausibly large corpus for chuvar's stated
personal/small-org scale — the projected index size is trivial next to this
host's 234GB disk. Storage was never going to be the constraint; the real
open question is HNSW build time and query latency at realistic scale,
neither of which this arithmetic projection can speak to (see "What was not
tested").

### On-disk and runtime footprint summary

| Component | Size |
|---|---|
| `llama-server` binary + shared libs (ubuntu-arm64 release) | 32 MB unpacked |
| MiniLM-L6-v2 Q8_0 GGUF | 23.9 MB |
| bge-small-en-v1.5 Q8_0 GGUF | 35.0 MB |
| **MiniLM candidate, total on disk** | **~56 MB** |
| MiniLM candidate, RSS at idle | ~60 MB |

For comparison, the Go classical baseline ships as compiled-in code with no
model file and no separate process at all.

---

## Recommendation for #64

**Ship `all-MiniLM-L6-v2` (Q8_0 GGUF), served locally over loopback HTTP by
a `llama-server`-class local inference process, as the CE default
`embed.Embedder` implementation**, replacing `embed.Stub` behind the
existing interface. It already matches the schema's committed 384-dim
column and the placeholder comment in `internal/embed/embed.go`, needs no
migration, loads in well under a second, costs ~60MB resident and ~4ms
per embedding call, and cleanly separates real paraphrase pairs from
distinct facts (0.742 vs 0.531 similarity, a real margin) on the corpus
built for this spike.

**Accepted costs:**

- **bge-small-en-v1.5 has a meaningfully wider quality margin** — perfect
  precision/recall at an unremarkable 0.85 threshold, versus MiniLM's 0.70
  recall at that same threshold (needs ~0.54 for perfect separation on this
  corpus) — for about 2.5x the latency and 1.4x the memory, both still
  small in absolute terms. If MiniLM's tighter margins cause real
  false-negative dedupe misses once real data exists, bge-small is the
  next thing to try, not a bigger model.
- **This is a local sidecar process, not literal in-process Go.** It adds
  one more process to the launch topology (`AGENTS.md` §3.6 currently
  enumerates `apiserver`/`migrate`/`mcpserver`/`brokerd`/`approver`/
  `pushbridge`; a local embedder process isn't on that list yet) — something
  to launch, supervise, restart, and health-check, not a pure library call
  inside `apiserver`'s own process space. A pure in-process route (e.g. an
  ONNX Runtime cgo binding) was not evaluated here — see "What was not
  tested" — and remains the way to remove this cost if it turns out to
  matter more than it looks like from here.
- **The model file itself is fetched from an external host (HuggingFace) at
  build/deploy time**, not at runtime — satisfies #64's "no external
  network dependency" as a runtime property, but self-hosted deployments
  still need a real answer for how that file gets bundled, pinned, and
  checksum-verified. Not designed here.
- **Cosine similarity cannot distinguish duplication from contradiction**
  (measured: 0.85–0.97 similarity on wording-similar, meaning-opposite
  pairs — see above). The existing stage-then-review design already
  depends on never treating similarity as an auto-decision; this spike
  makes that dependency an explicitly measured one rather than an assumed
  one. Any future change that lets a similarity score bypass human review
  reopens this.
- **`docs/architecture.md` currently names AWS Bedrock as "the production
  embedder target."** This spike does not resolve that tension — #64's own
  text ("must run with no external network dependency") and CLAUDE.md's
  zero-ambient-authority stance point the other way, and reconciling the
  two (a paid-tier plugin swap behind the same kind of interface
  `RetrievalBackend` already uses, versus a hosted-deployment carve-out) is
  a decision for whoever picks up #107's pluggable-provider seam, not
  something a model-choice spike should quietly override.

## Recommendation for #63

**Build the scope classifier on top of the #64 embedding model
(nearest-centroid over embeddings, or a small linear layer trained on top
of it — the latter not evaluated here), not the from-scratch classical
hashing baseline.** Measured evidence: embedding + nearest-centroid beat
the classical baseline by a full ~9–12 points of LOOCV accuracy (0.75 vs.
0.625–0.667) on the identical corpus and methodology, and the *marginal*
cost over what dedupe already pays for is small — the extra step is a
handful of centroid dot-products, not another network or subprocess call.

**Accepted costs:**

- **75% is a measured ceiling on a small, self-labelled, genuinely
  ambiguous corpus — not a production-readiness number.** Several of the
  6 remaining misses look as much like taxonomy ambiguity (is a dentist
  appointment `identity.schedule` or `identity.personal`?) as classifier
  error. Don't read 75% as "the classifier is 75% accurate"; read it as
  "embeddings measurably beat the classical baseline here, by this much,
  on this evidence."
- **The classical baseline remains the one candidate that works with no
  embedder available at all** — dependency-free, ~1000x faster in
  isolation (8.3µs vs. several milliseconds dominated by the embedding
  call), and a legitimate fallback if the classify path ever needs to run
  somewhere the embedder genuinely isn't (a degraded mode, not the
  default). That's a real, if narrow, use for a materially less accurate
  approach — a conscious tradeoff to make explicitly if it's ever needed,
  not a reason to make it the default.
- **Committing to "classifier rides on the embedding call" also commits
  the classify path to whatever `#64` costs and risks** (sidecar process,
  build-time model fetch) — it's not a separate, independently-swappable
  decision from here forward.

---

## What was not tested, and what would change the recommendation

This section is the point of the document — read it before re-litigating
either recommendation.

- **No real user data.** Every number above comes from a corpus built by
  hand for this spike (24–37 short sentences), because chuvar is pre-launch
  and no real fact corpus exists yet. A real corpus — with real near-
  duplicate noise (typos, partial overlaps, differing granularity, actual
  user phrasing rather than deliberately-constructed paraphrases) and a
  real, larger scope taxonomy — could shift the dedupe threshold, the
  classifier accuracy ceiling, or the model ranking in either direction.
  This is the single biggest thing that would change either
  recommendation, and nothing here substitutes for re-running this
  evaluation once real facts exist.
- **The scope taxonomy used for #63 is invented, not decided.** `AGENTS.md`
  §3.4 states the taxonomy is genuinely open. A different taxonomy —
  coarser categories, a different hierarchy, or `identity.personal` and
  `identity.schedule` merged into one class — would likely raise measured
  accuracy substantially, since several observed misses are exactly at
  that boundary. Don't treat the 75% ceiling as fixed until the taxonomy
  is.
- **No concurrent-request load test.** Every latency number here is either
  strictly sequential or a single batch-of-50 request. `llama-server`'s
  logs show `n_slots = 4` (parallel request slots), so concurrent
  throughput is very likely better than the sequential numbers suggest —
  but "very likely" is not "measured." If a bulk-import feature is ever
  built, measure real concurrent throughput before sizing it, don't
  extrapolate from the batch-of-50 number above.
- **No live Postgres/pgvector index.** The index-size table above is
  arithmetic from pgvector's documented on-disk format, explicitly not a
  measurement. HNSW build time, memory during index construction, and
  query latency at realistic corpus sizes (1k–100k facts) were never run
  against a real database. This is the most consequential gap for #64's
  downstream retrieval cost and should be closed before committing HNSW
  parameters (`m`, `ef_construction`), separately from the model choice
  this spike answers.
- **No long-duration memory test.** RSS was flat across 300 sequential
  embeds, but that's single-digit seconds of continuous load. Behavior
  over hours or days of intermittent use, restart cadence, and the
  interaction between the model file being memory-mapped versus fully
  resident were not tested.
- **No pure in-process (non-subprocess) embedding route was attempted** —
  e.g. an ONNX Runtime cgo binding (such as `hugot`) that would avoid the
  local-sidecar-process cost named above entirely. This was a time-box
  decision, not a finding that the in-process route is worse. If the
  extra-process launch-topology cost turns out to matter more in practice
  than it looks like from this spike, that route — not a hand-rolled Go
  transformer implementation — is the next thing to spike.
- **Ollama was not tried.** Not installed on this host; `llama.cpp`'s
  `llama-server` already provides the same OpenAI-compatible embeddings
  endpoint the issue's "consider at least" list wanted, so standing up a
  second server implementation of the same idea was judged low-value
  under this spike's time-box. If Ollama's model-management ergonomics
  (pull-by-name, built-in update flow) matter more in practice than raw
  footprint, that could change the operational choice without changing
  the model choice.
- **No mid-size or larger local model was tried** (e.g. `nomic-embed-
  text-v1.5` at roughly 137M params, versus MiniLM's ~23M or bge-small's
  ~33M) — deliberately, since "small enough for modest hardware" is an
  explicit constraint and both candidates tested already fit it
  comfortably. If real-data accuracy later proves inadequate, a mid-size
  model is the next rung to test before reaching for anything
  Bedrock-scale.
- **The `docs/architecture.md` vs. #64 tension (Bedrock vs. no-network-
  dependency) was deliberately left unresolved** — see the accepted-costs
  note above. Reconciling it is scoped to #107, not this spike.
