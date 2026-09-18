#!/usr/bin/env bash
# Deploy pairfob-origin to a self-hosted Cloudflare account.
#
# wrangler does not expand ${VAR} inside its configuration file: it uploads the
# literal string. The account-specific D1 id therefore cannot live in the
# committed wrangler.jsonc, so this script renders an untracked copy with the
# real id substituted and points wrangler at that.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORIGIN_DIR="$ROOT/workers/pairfob-origin"
SOURCE_CONFIG="$ORIGIN_DIR/wrangler.jsonc"
# Untracked: .gitignore covers wrangler.deploy.jsonc.
RENDERED_CONFIG="$ORIGIN_DIR/wrangler.deploy.jsonc"
# Must match the placeholder committed in wrangler.jsonc.
D1_ID_PLACEHOLDER="00000000-0000-0000-0000-000000000000"

usage() {
  cat >&2 <<'EOF'
usage: deploy-origin.sh [--dry-run] [--config-only]

Renders wrangler.deploy.jsonc from wrangler.jsonc with the account-specific D1
database id, then deploys the Worker.

Options:
  --dry-run      Run `wrangler deploy --dry-run` (no remote change).
  --config-only  Render the config and exit without invoking wrangler.
  -h, --help     Show this help.

Environment:
  PAIRFOB_D1_DATABASE_ID  Required. The D1 uuid from `wrangler d1 list`.
  PAIRFOB_ALLOW_NO_DL     Deploy even though public-dist has no dl/ release tree.
EOF
}

DRY_RUN=0
CONFIG_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --config-only) CONFIG_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "deploy-origin.sh: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

D1_ID="${PAIRFOB_D1_DATABASE_ID:-}"
if [[ -z "$D1_ID" ]]; then
  echo "deploy-origin.sh: PAIRFOB_D1_DATABASE_ID is required (see 'wrangler d1 list')" >&2
  exit 1
fi
# A wrong-shaped id fails late inside the Cloudflare API with an opaque 10021,
# so reject it here where the message can name the cause.
if [[ ! "$D1_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "deploy-origin.sh: PAIRFOB_D1_DATABASE_ID is not a uuid: $D1_ID" >&2
  exit 1
fi

if ! grep -q "$D1_ID_PLACEHOLDER" "$SOURCE_CONFIG"; then
  echo "deploy-origin.sh: placeholder $D1_ID_PLACEHOLDER not found in $SOURCE_CONFIG" >&2
  exit 1
fi

# The rendered config sits beside the source so every relative path in it
# (main, migrations_dir, assets.directory) still resolves.
sed "s|$D1_ID_PLACEHOLDER|$D1_ID|g" "$SOURCE_CONFIG" > "$RENDERED_CONFIG"
echo "deploy-origin.sh: rendered $RENDERED_CONFIG"

if [[ "$CONFIG_ONLY" == 1 ]]; then
  exit 0
fi

if [[ ! -f "$ORIGIN_DIR/public-dist/index.html" ]]; then
  echo "deploy-origin.sh: missing public-dist; run scripts/pack-origin-assets.sh first" >&2
  exit 1
fi

# The release tree is what /dl serves, and the pack copies it only under
# PAIRFOB_PACK_DL=1 after removing public-dist outright. A deploy without it
# succeeds and then serves no /dl at all: /dl/VERSION 404s, so the phone reports
# a failed update check and `pairfob update` and install.sh cannot resolve a
# version either. That is a silent outage, so refuse here instead.
# PAIRFOB_ALLOW_NO_DL=1 is the deliberate opt-out for an origin that is not
# meant to host binaries.
if [[ "${PAIRFOB_ALLOW_NO_DL:-}" != "1" && ! -f "$ORIGIN_DIR/public-dist/dl/VERSION" ]]; then
  echo "deploy-origin.sh: public-dist/dl/VERSION is missing, so this deploy would serve no /dl" >&2
  echo "repack with: PAIRFOB_PACK_DL=1 ./scripts/pack-origin-assets.sh" >&2
  echo "(build the release first with ./scripts/release.sh, or set PAIRFOB_ALLOW_NO_DL=1 to deploy without binaries)" >&2
  exit 1
fi

cd "$ORIGIN_DIR"
if [[ "$DRY_RUN" == 1 ]]; then
  exec ./node_modules/.bin/wrangler deploy --dry-run -c "$RENDERED_CONFIG"
fi
exec ./node_modules/.bin/wrangler deploy -c "$RENDERED_CONFIG"
