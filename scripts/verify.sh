#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

unformatted="$(gofmt -l ./cmd ./internal)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt required:" >&2
  echo "$unformatted" >&2
  exit 1
fi

bash -n "$ROOT/scripts/install.sh"
bash -n "$ROOT/scripts/release.sh"
bash -n "$ROOT/scripts/pack-origin-assets.sh"
bash -n "$ROOT/scripts/ship-guard.sh"
bash -n "$ROOT/scripts/dev-acme.sh"
bash -n "$ROOT/scripts/dev-up.sh"
bash -n "$ROOT/scripts/dev-down.sh"
bash -n "$ROOT/plugin/herdr/open-pane.sh"
bash -n "$ROOT/plugin/herdr/pairfob.sh"

jq empty proto/pairfob-vectors.json proto/pgp-words.json proto/rpc.schema.json
go vet ./...
go test ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
bun test scripts/load-mux.test.ts
bun test scripts/dev-acme.test.ts
bun test scripts/ship-guard.test.ts
bun test plugin/herdr/plugin.test.ts
(cd "$ROOT/site/doc" && bun test)

(
  cd pwa
  bun test src
  bun run test:qa
  bun run typecheck
  bun run typecheck:qa
  bun run build
)

# Pack into scratch. Verifying that the pack works must not write the tree that
# is about to be deployed: the pack removes its destination outright and only
# restores the release binaries when asked to, so packing into public-dist here
# would silently strip /dl from an already-correct deploy tree. Binaries stay
# out of this pack, which keeps the Worker e2e small (release.sh says the same).
PACK_DEST="$ROOT/.tmp/verify-public-dist"
trap 'rm -rf "$PACK_DEST"' EXIT
PAIRFOB_PACK_DEST="$PACK_DEST" "$ROOT/scripts/pack-origin-assets.sh"
test -f "$PACK_DEST/install.sh"
test -f "$PACK_DEST/doc/index.html"

(
  cd workers/pairfob-origin
  bun test src
  bun test e2e
  bun run typecheck
  bun run e2e:wrangler
)
