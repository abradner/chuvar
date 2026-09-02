#!/usr/bin/env bash
# Regression test for scope.sh's bot-bump filter, its feature-theme classification,
# and the two scope.sh copies staying identical.
# Run: .claude/skills/quality-audit/test-scope.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."

fail=0

# Both copies of scope.sh are meant to be byte-identical (quality-audit and
# quality-audit-refresh use the same script). A drift here means one was edited
# without the other and the two skills silently disagree on scoping.
if ! diff -q .claude/skills/quality-audit/scope.sh .claude/skills/quality-audit-refresh/scope.sh >/dev/null; then
  echo "FAIL: quality-audit/scope.sh and quality-audit-refresh/scope.sh have diverged"
  fail=1
fi

# Extract just the bots pattern from the script under test, so this test exercises
# the actual shipped regex rather than a copy that could drift from it.
# grep's own no-match under pipefail would abort the script here before the emptiness
# check below ever runs — tolerate that specifically, let the check report it properly.
bots=$(grep -o "bots='[^']*'" .claude/skills/quality-audit/scope.sh | sed "s/^bots='//; s/'\$//" || true)
if [ -z "$bots" ]; then
  echo "FAIL: could not extract the bots pattern from scope.sh"
  exit 1
fi

cases_exclude=(
  "abc1234 chore(deps): bump foo"
  "def5678 fix(deps-dev): bump bar"
  "111aaaa dependabot: something"
  "222cccc chore: bump renovate config"
)
cases_keep=(
  "333bbbb chore: unrelated cleanup"
  "444dddd chore(deps-something-else): looks close but different"
  "555eeee feat: a real feature"
)

for line in "${cases_exclude[@]}"; do
  if echo "$line" | grep -viE "$bots" >/dev/null; then
    echo "FAIL: expected to EXCLUDE (bot bump), but it survived the filter: $line"
    fail=1
  fi
done

for line in "${cases_keep[@]}"; do
  if ! echo "$line" | grep -viE "$bots" >/dev/null; then
    echo "FAIL: expected to KEEP (real commit), but the filter excluded it: $line"
    fail=1
  fi
done

# FEATURE THEMES classification: a real regression once had every line fall through
# unclassified (the always-succeeding hash-strip poisoned the t-flag ahead of the
# paren-pattern check, because both substitutions shared one sed invocation). Run the
# SHIPPED script end to end against a throwaway git repo with controlled commits, so a
# revert to the single-invocation form fails this test rather than just a duplicated
# pattern under test.
here="$(pwd)"
fixture_repo=$(mktemp -d)
fixture_scope=$(mktemp -d)
git -C "$fixture_repo" init -q -b main
git -C "$fixture_repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m 'base'
git -C "$fixture_repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m 'feat(auth): add login'
git -C "$fixture_repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m 'chore: cleanup'
git -C "$fixture_repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m 'random text no colon'
# Same reasoning: an empty FEATURE THEMES section (the exact regression this exists to
# catch) would make grep's no-match abort the script under pipefail, before the diagnostic
# comparison below ever runs.
themes=$(cd "$fixture_repo" && bash "$here/.claude/skills/quality-audit/scope.sh" HEAD~3 HEAD fixture "$fixture_scope" \
  | sed -n '/FEATURE THEMES/,/REVIEW-FEEDBACK/p' | grep -E '^ *[0-9]+ ' | sed -E 's/^ *[0-9]+ //' || true)
rm -rf "$fixture_repo" "$fixture_scope"
expected=$(printf 'auth\nchore\n(untyped)')
if [ "$(echo "$themes" | sort)" != "$(echo "$expected" | sort)" ]; then
  echo "FAIL: FEATURE THEMES classification wrong; got:"
  echo "$themes" | sed 's/^/  /'
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "OK: scope.sh copies match; bot-bump filter correct on ${#cases_exclude[@]} exclude + ${#cases_keep[@]} keep cases; feature-theme classification correct end to end"
fi
exit "$fail"
