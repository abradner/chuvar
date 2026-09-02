#!/usr/bin/env bash
# Size and classify a commit range for a quality audit.
#   scope.sh <base> <target> [label] [out-dir]
# Prints the facts that decide how to slice the fleet, and writes
# <out-dir>/commits-<label>.txt with bot bumps (Dependabot/Renovate/deps
# chores) excluded — the file every digger and assessor is pointed at.
set -euo pipefail
base=${1:?base ref}; target=${2:?target ref}; label=${3:-range}; out=${4:-.}
range="$base..$target"
mkdir -p "$out"

bots='(^|[0-9a-f]{4,40} )(chore|fix)\(deps(-dev)?\)|dependabot|renovate'  # hash prefix from --oneline, or start of a hash-stripped line
# `|| true` on the pipeline as a whole would mask a real git-log failure (bad range) behind
# grep's expected "no bot-free lines" exit 1 — under pipefail either failure looks the same.
# Check git log on its own first; only grep's no-match is tolerated.
if ! log_out=$(git log --oneline --no-merges "$range"); then
  echo "fatal: git log failed for range '$range' — check base/target refs" >&2
  exit 1
fi
echo "$log_out" | grep -viE "$bots" > "$out/commits-$label.txt" || true

total=$(git log --oneline "$range" | wc -l | tr -d ' ')
merges=$(git log --oneline --merges "$range" | wc -l | tr -d ' ')
real=$(wc -l < "$out/commits-$label.txt" | tr -d ' ')
echo "== RANGE $range ($label) =="
echo "commits: $total  merges: $merges  bot-bumps: $((total - merges - real))  audited: $real"
git diff --shortstat "$range"

echo; echo "== DIRECTORY FOOTPRINT (top 15) =="
git diff --name-only "$range" | awk -F/ '{if (NF>2) print $1"/"$2; else if (NF>1) print $1; else print "(root)"}' \
  | sort | uniq -c | sort -rn | head -15

echo; echo "== MIGRATIONS =="
# Tries common conventions; add your own directory to the list below if this repo uses one.
migrate_dirs="db/migrate migrations"
mig_found=0
for d in $migrate_dirs; do
  [ -d "$d" ] || continue
  added=$(git diff --name-only --diff-filter=A "$range" -- "$d")
  [ -n "$added" ] && { echo "$added" | sed "s|^|  |"; mig_found=1; }
done
[ "$mig_found" -eq 0 ] && echo "  (none)"

echo; echo "== NEW RAKE TASKS / BIN SCRIPTS =="
new_scripts=$(git diff --name-only --diff-filter=A "$range" -- lib/tasks bin)
if [ -n "$new_scripts" ]; then
  echo "$new_scripts" | sed 's|^|  |'
else
  echo "  (none)"
fi

echo; echo "== PAYLOAD / CONTRACT VERSION BUMPS =="
# Optional, repo-specific: list the files that carry a schema/contract/payload version constant,
# one per line, in a sibling `contract-paths.txt` next to this script. Skipped if absent or empty
# — an unset list must never fall through to `git diff` with no path restriction.
contract_paths="$(dirname "$0")/contract-paths.txt"
if [ -s "$contract_paths" ]; then
  paths=()
  while IFS= read -r p; do [ -n "$p" ] && paths+=("$p"); done < "$contract_paths"
  if [ "${#paths[@]}" -gt 0 ]; then
    if diff_out=$(git diff "$range" -- "${paths[@]}" 2>&1); then
      echo "$diff_out" | grep -E '^[+-].*(SCHEMA_VERSION|CONTRACT_VERSION|"version")' || echo "  (none)"
    else
      echo "  (git diff failed — check contract-paths.txt entries and the range: $diff_out)"
    fi
  else
    echo "  (skipped — contract-paths.txt has no non-blank lines)"
  fi
else
  echo "  (skipped — no contract-paths.txt; see SKILL.md 'Establish before first use')"
fi

echo; echo "== FEATURE THEMES (commit scopes, by frequency) =="
# Two sed invocations, not one: the always-succeeding hash-strip below would set the
# t-flag before the classification checks even run, making the first t branch on the
# hash-strip's own success rather than the paren-pattern match — every line would then
# skip straight to keeping its post-strip text, never reaching "(untyped)".
sed -E 's/^[0-9a-f]+ //' "$out/commits-$label.txt" \
  | sed -E 's/^([[:alnum:]_]+)\(([^)]+)\).*/\2/; t; s/^([[:alnum:]_]+):.*/\1/; t; s/.*/(untyped)/' \
  | sort | uniq -c | sort -rn | head -12

echo; echo "== REVIEW-FEEDBACK BATCHES (a lot of first-pass findings are already fixed here) =="
grep -iE 'review feedback|feedback batch|self-review|UAT round' "$out/commits-$label.txt" || echo "  (none)"

echo; echo "wrote $out/commits-$label.txt"
