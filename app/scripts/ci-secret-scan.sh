#!/bin/sh
# CI secret scan — dependency-free (pure git + grep), so it runs on any runner
# including air-gapped shell executors with no image pulls.
#
# Exists because two P0 findings shipped undetected: a GitHub PAT committed in a
# git remote URL, and app/.env (JWT key, DB passwords, OIDC secret, GitLab PAT)
# baked into published images. This gates both classes at merge time.
#
# Upgrade path: swap/add `gitleaks detect` once an image is mirrored internally.
set -eu

cd "$(dirname "$0")/../.."   # repo root
fail=0

say_fail() { echo "FAIL: $1"; fail=1; }

echo "== 1. secret-bearing files must not be tracked =="
tracked_secrets=$(git ls-files | grep -Ei '(^|/)\.env$|(^|/)\.env\.(local|prod|production|staging)$|(^|/)secrets?\.(ya?ml|json|env)$|\.pem$|\.key$|(^|/)id_rsa$' || true)
if [ -n "$tracked_secrets" ]; then
    say_fail "secret-bearing files are tracked in git:"
    echo "$tracked_secrets" | sed 's/^/    /'
else
    echo "  ok"
fi

echo "== 2. no credential material in tracked file contents =="
# Live-credential patterns. Docs/examples are excluded so we don't fail on
# placeholder strings in .example files or documentation.
hits=$(git grep -nIE \
    '(glpat-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|hvs\.[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})' \
    -- . ':(exclude)*.example' ':(exclude)docs/**' ':(exclude)*.md' 2>/dev/null || true)
if [ -n "$hits" ]; then
    say_fail "credential-shaped strings found in tracked files:"
    echo "$hits" | sed 's/^/    /'
else
    echo "  ok"
fi

echo "== 3. credentials must not be embedded in git remote URLs =="
# GitLab CI itself clones via https://gitlab-ci-token:<job-token>@host/... — that
# is ephemeral and expected, so it is excluded. Likewise oauth2:<token> helpers.
remote_creds=$(git remote -v 2>/dev/null \
    | grep -E '://[^/@[:space:]]+:[^/@[:space:]]+@' \
    | grep -vE '://(gitlab-ci-token|oauth2|x-access-token):' || true)
if [ -n "$remote_creds" ]; then
    say_fail "a git remote embeds credentials in its URL (rotate the credential, use a helper instead)"
else
    echo "  ok"
fi

echo "== 4. .dockerignore must exclude .env from image build contexts =="
for ctx in app dashboard; do
    [ -d "$ctx" ] || continue
    # only contexts that actually COPY the whole tree matter
    if grep -rqE '^COPY \. ' "$ctx"/Dockerfile* 2>/dev/null; then
        if [ ! -f "$ctx/.dockerignore" ]; then
            say_fail "$ctx/ does 'COPY .' but has no .dockerignore (secrets would be baked into image layers)"
        elif ! grep -qE '^\.env$' "$ctx/.dockerignore"; then
            say_fail "$ctx/.dockerignore does not exclude .env"
        else
            echo "  ok: $ctx"
        fi
    fi
done

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "SECRET SCAN FAILED — do not merge. Rotate anything exposed; secrets belong in Vault/CI variables, injected at runtime."
    exit 1
fi
echo ""
echo "SECRET SCAN PASSED"
