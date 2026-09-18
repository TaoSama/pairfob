# Self-hosted deployment

How to run this origin on your own Cloudflare account. The reference here is
`pair.taoai.site`; substitute your own hostname throughout.

## What the account needs

| Requirement | Why |
| --- | --- |
| Workers **Paid** ($5/mo) | Durable Objects are the relay. The free tier's DO allowance does not cover a persistent WebSocket relay, and SQLite-backed DO storage is billed on the paid plan. |
| A zone on the account | `routes` uses `custom_domain: true`, which requires the hostname's zone to be managed by Cloudflare. |
| D1 | `grants` / `daemons` / `self_grants` — the enroll ledger. |
| Analytics Engine | Binding `METRICS`, dataset `pairfob`. |
| Workers Assets | Binding `ASSETS`, serves the marketing site, `/doc`, and the `/pair` PWA. |

## Credentials

Deploying needs a Cloudflare API token on the account that holds the zone.
Nothing in this repo can substitute for it, and no token is present on the
machine this was written on — this is the one hard prerequisite.

The interactive path is `wrangler login`, which opens a browser and needs no
token. For a non-interactive shell, create a token instead and export it:

```sh
export CLOUDFLARE_API_TOKEN=...   # the token value
export CLOUDFLARE_ACCOUNT_ID=...  # dashboard → Workers & Pages → Account ID
```

Cloudflare's own instruction for a Wrangler deploy token is to pick the
**"Edit Cloudflare Workers"** template under *Create Token*, rather than to
assemble permissions by hand, and then to narrow *Resources* to the one account
and the one zone (`taoai.site`) you deploy to. That template is the recommended
starting point; the list below is what this Worker actually exercises, so you
can audit the template or build an equivalent custom token:

| Scope | Permission | Needed for |
| --- | --- | --- |
| Account | Workers Scripts : Edit | Uploading the script; also covers the Durable Object classes and the Analytics Engine binding — there is no separate Durable Objects permission in Cloudflare's [permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/). |
| Account | Workers KV Storage : Edit | Included in the Workers template. Workers Assets uploads are backed by internal KV-family storage, so a hand-rolled token that omits this is the usual cause of an assets-upload failure. |
| Account | D1 : Edit | `d1 create`, `d1 migrations apply`, `d1 execute`. |
| Account | Workers Tail : Read | `wrangler tail` only. Omit if you will not stream logs. |
| Zone | Workers Routes : Edit | Binding the Worker to `pair.taoai.site`. |
| Zone | DNS : Edit | `custom_domain: true` creates the proxied `pair` record during deploy. |
| Zone | Zone : Read | Resolving the zone id for the hostname. |
| User | User Details : Read | `wrangler whoami` only. |

Store the token outside the repo — `~/.claude/.credentials/` with mode `600` is
the convention here. Do not put it in `/tmp`, in `wrangler.jsonc`, in
`.dev.vars`, or on a command line where it lands in shell history.

Two permissions deliberately **not** requested: `Workers R2 Storage` (no R2
binding) and `Account Analytics : Read`. Writing to an Analytics Engine dataset
is part of the Worker's runtime, authorized by the script upload; `Account
Analytics : Read` only governs *querying* analytics via the API, which no step
in this runbook does. Add it only if you later query the dataset over SQL.

## Bindings

Declared in `wrangler.jsonc`; all seven appear in a `wrangler deploy --dry-run`:

- `DAEMON_ROOM` — Durable Object, class `DaemonRoom` (SQLite), one per `daemon_id`.
- `PAIRING_INDEX` — Durable Object, class `PairingIndex` (SQLite), sharded pairing lookup.
- `DB` — D1, database name `pairfob`.
- `METRICS` — Analytics Engine dataset `pairfob`.
- `ASSETS` — static assets from `./public-dist`.
- `BUILD`, `P2P_OPEN` — plain vars.

Both DO classes are created by the `v1` migration tag in `wrangler.jsonc`
(`new_sqlite_classes`). They are exported from `src/index.ts`, so no extra step
is needed beyond deploying.

## Secrets

Three, all read from `Env` in `src/env.ts`:

- `OPERATOR_TOKEN` — bearer token for `/v2/admin/*`. Without it `handleAdmin`
  returns `503` (`src/admin.ts:24`), so admin endpoints are simply closed.
- `IP_HASH_PEPPER` — HMAC pepper for hashed enroll IPs. **Without it every
  `/v2/enroll` fails with `500`** (`src/enroll.ts:28`). This one is mandatory.
  It also backs the account failure-budget subjects, so `/v2/account/*` returns
  `500` without it too (`src/account.ts:78`).
- `BOOTSTRAP_SERVICE_TOKEN` — opens the very first account, once. Without it
  `/v2/account/bootstrap` returns `503` (`src/account.ts:161`) and no account
  can ever be created, which leaves every phone locked out of `/v2/ws`. Kept
  distinct from `OPERATOR_TOKEN` on purpose: the relay operator credential must
  not also be a registration credential (`src/account-guards.test.ts:28`).

Generate them locally and keep them out of the repo and out of shell history
files. Store the values under `~/.claude/.credentials/tokens/` with mode 600;
this document deliberately records only the path.

## The D1 id is not in the repo

`wrangler` does **not** expand `${VAR}` inside its configuration file — it
uploads the literal string (verified against wrangler 4.126.0). The committed
`wrangler.jsonc` therefore carries the all-zero placeholder
`00000000-0000-0000-0000-000000000000`, and `scripts/deploy-origin.sh` renders
an untracked `wrangler.deploy.jsonc` next to it with the real id substituted
from `PAIRFOB_D1_DATABASE_ID`. The rendered file sits in the same directory so
that `main`, `migrations_dir`, and `assets.directory` still resolve.

## Deploy order

Steps 3 and 5-8 change remote state.

```sh
# 1. Authenticate: either `wrangler login` (interactive) or export
#    CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID. See "Credentials" above.
cd workers/pairfob-origin
./node_modules/.bin/wrangler whoami

# 2. Install deps (this repo uses bun for the Worker).
#    If your npm registry is an internal mirror, force the public one —
#    a mirror that lacks @cloudflare/workerd-* will 503 and leave a broken
#    node_modules: bun install --registry https://registry.npmjs.org
bun install

# 3. Create the D1 database, then keep the uuid it prints.
./node_modules/.bin/wrangler d1 create pairfob
export PAIRFOB_D1_DATABASE_ID=<uuid>          # also in `wrangler d1 list`

# 4. Build and pack the assets into public-dist. pack-origin-assets.sh also
#    runs the VitePress build for /doc, and refuses to run until
#    pwa/dist/index.html exists.
#
#    PAIRFOB_PACK_DL=1 is what copies dist/dl into public-dist, and the pack
#    starts by removing public-dist outright. Omitting it therefore ships an
#    Assets bundle with no /dl at all: /dl/VERSION 404s, so the phone's
#    "check for updates" reports a failed check and `pairfob update` and
#    install.sh cannot resolve a version either. Run scripts/release.sh first
#    (or keep an existing dist/dl) so there is something to copy.
(cd ../../pwa && bun install && bun run build)
PAIRFOB_PACK_DL=1 ../../scripts/pack-origin-assets.sh

# 5. Apply the eleven ordered migrations against the remote database.
#    On an instance with real enrollments, export first — the migrations are
#    forward-only and 0003 drops a table (see "Rollback").
../../scripts/deploy-origin.sh --config-only
./node_modules/.bin/wrangler d1 migrations apply pairfob --remote \
  -c wrangler.deploy.jsonc

# 6. Upload the secrets (prompts for the value; do not pass it on argv).
./node_modules/.bin/wrangler secret put IP_HASH_PEPPER -c wrangler.deploy.jsonc
./node_modules/.bin/wrangler secret put OPERATOR_TOKEN -c wrangler.deploy.jsonc
./node_modules/.bin/wrangler secret put BOOTSTRAP_SERVICE_TOKEN -c wrangler.deploy.jsonc

# 7. Dry run, then deploy.
../../scripts/deploy-origin.sh --dry-run
../../scripts/deploy-origin.sh
```

Step 8 is DNS. Because the route is a `custom_domain`, wrangler is expected to
create the proxied DNS record for `pair.taoai.site` during deploy, provided the
parent zone `taoai.site` is already on the account. This has not been exercised
against a live account here, so treat it as the expected path rather than a
confirmed one: after the first deploy, check the zone's DNS tab for a proxied
record on `pair`, and add one manually if it is absent.

Verify, in this order — DNS first, because a failure of the two `curl`s below
is otherwise indistinguishable from the record not existing yet:

```sh
# The record resolves at all (NXDOMAIN here means the custom domain was not
# created; add the proxied `pair` record by hand and re-check).
dig +short pair.taoai.site

# Served by Cloudflare: expect a cf-ray header and HTTP 200.
curl -sSI https://pair.taoai.site/v2/health | head -1

curl -s https://pair.taoai.site/v2/health     # {"ok":true,"protocol":2}
curl -s https://pair.taoai.site/api/config    # {"protocol":2,...}
```

Allow for propagation and for the edge certificate to be issued; a fresh custom
domain can answer TLS errors for a few minutes before it settles.

`probeOriginProtocol` in the Go client requires `/api/config` to report
`protocol: 2` (`cmd/pairfob/enroll.go:405`), so that second check is the one
that gates a daemon.

## Enrolling a daemon

No manual grant row is required. `/v2/enroll` is self-serve: when the posted
`daemon_id` is unknown, the Worker mints its own internal one-slot grant
(`mintOpenGrant`, `src/enroll.ts:63` and `:129`) and inserts the `grants` row in
the same D1 batch as the per-IP ledger claim (`insertSelfServeGrant`,
`src/d1.ts:109`). `PAIRFOB_JOIN_TOKEN` and `PAIRFOB_JOIN_GRANT` are rejected by
the client on purpose (`cmd/pairfob/enroll.go:62`, `cmd/pairfob/protocol.go:52`)
because the grant is now server-minted rather than operator-issued.

So a fresh daemon only needs the origin:

```sh
PAIRFOB_ORIGIN=https://pair.taoai.site pairfob enroll
```

The daemon mints and journals its own `daemon_id` and `reconnect_token` before
the request, and the Worker echoes them back (`cmd/pairfob/enroll.go:121`).
Retrying an identical request is idempotent and does not consume another slot.

Two caps apply, and both are silent from the client's side except as `429`:

- `SELF_GRANT_PER_IP` = 3 grants per hashed IP per 24 h, enforced inside the D1
  `INSERT` (`src/constants.ts:26`, `src/d1.ts:34`).
- `allowEnrollIP` = 5 enrolls per IP per hour, per isolate only
  (`src/limits.ts:4`). This is a first pass, not a global limit.

If a self-hosted instance ever does need a grant inserted by hand — for example
to raise `max_daemons` above the open-enroll value of 1 — the row shape is in
`migrations/0001_grants.sql`:

```sh
./node_modules/.bin/wrangler d1 execute pairfob --remote -c wrangler.deploy.jsonc \
  --command "INSERT INTO grants (grant_id, grant_hash, max_daemons, used, label, created_at) VALUES ('g_0123456789abcdef', 'unused', 8, 0, 'manual', unixepoch()*1000);"
```

`grant_hash` is `NOT NULL UNIQUE` but is not a user credential — nothing
authenticates against it on the open-enroll path — so any unique filler works.
Timestamps in this schema are epoch **milliseconds**.

## Operations

Admin calls need the bearer token:

```sh
curl -s -H "Authorization: Bearer $OPERATOR_TOKEN" https://pair.taoai.site/v2/admin/stats
curl -s -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" \
  https://pair.taoai.site/v2/admin/daemons/<daemon_id>/kick
```

Kicking releases the grant slot (`src/d1.ts:134`). `/v2/grants` and
`/v2/admin/grants` are retired and answer `404 unbound`.

See `observability.md` for logs and metrics, and `waf.md` for the abuse rules
that back up the per-IP cap.

## Rollback

Code and schema roll back differently, and the asymmetry matters: **the Worker
is reversible, the database is not.**

### Code

Every deploy creates a version. To go back:

```sh
cd workers/pairfob-origin
./node_modules/.bin/wrangler deployments list          # find the last good version id
./node_modules/.bin/wrangler rollback <version-id> -m "reason"
./node_modules/.bin/wrangler deployments status        # confirm what is live
```

`wrangler rollback` with no version id returns to the immediately previous one.
A rollback restores the script and its bindings; it does **not** revert D1 rows,
Durable Object storage, or secrets.

### Schema

There are no down-migrations in `migrations/`, and `0003_room_reconnect_authority.sql:13`
executes `DROP TABLE daemons`. Rolling the code back past a migration that has
already been applied therefore does not restore the dropped data — the old code
may query tables the new schema no longer has. Before `d1 migrations apply` on
an instance carrying real enrollments, take a backup:

```sh
./node_modules/.bin/wrangler d1 export pairfob --remote --output pairfob-backup.sql \
  -c wrangler.deploy.jsonc
```

Restoring means creating a fresh database from that dump and swapping
`PAIRFOB_D1_DATABASE_ID`, not un-applying a migration.

### Secrets and DNS

- A bad secret is rolled forward, not back: `wrangler secret put <NAME>` again.
  Rotating `IP_HASH_PEPPER` invalidates every stored hashed IP, which resets the
  per-IP enroll ledger rather than corrupting it.
- To detach the hostname, remove the entry from `routes` and redeploy, then
  delete the `pair` DNS record in the zone. Deleting the record alone leaves the
  custom domain attached to the Worker.

### Fastest way out

If the origin is broken and the cause is not yet known, `wrangler rollback` to
the last good version first and diagnose afterwards — it is a metadata change
and takes effect globally in seconds, whereas a fix-forward deploy has to
re-upload and re-propagate the assets.

## What is unverified here

This section was written before any deploy had been performed. Since then the
runbook has been executed against the `TaoSama` account and `pair.taoai.site`,
so the items below are no longer all open. Observed on that deploy:

- The deploy itself, with `PAIRFOB_D1_DATABASE_ID` read from `wrangler d1 list`
  and `CLOUDFLARE_API_TOKEN` exported: the Worker uploaded, the custom domain
  `pair.taoai.site` served, and all three secrets were already present via
  `wrangler secret list`.
- `custom_domain` does resolve and auto-created the record: `/v2/health`,
  `/api/config` and `/v2/account/state` all answer 200 on `pair.taoai.site`.
- A token from the "Edit Cloudflare Workers" template is sufficient for a
  deploy that uploads Assets.
- `/dl` is served from Assets once packed with `PAIRFOB_PACK_DL=1`:
  `/dl/VERSION` returns the version with `cache-control: no-store`, and a
  downloaded `pairfob-linux-amd64` matched its `SHA256SUMS` entry byte for byte.
- From the devbox, every one of these calls needs the proxy
  (`https_proxy=http://127.0.0.1:23456`); without it they hang to an SSL
  timeout rather than failing fast.

Still unobserved, read from code only:

- Everything about `/v2/enroll`, the grant tables, and the caps is read from
  `src/enroll.ts`, `src/d1.ts`, `src/constants.ts`, and `migrations/`. No enroll
  has been run against a deployed Worker.
- The migration commands have not been executed against a database that had
  real enrollments in it, and the forward-only 0003 drop has not been exercised
  on live data.
- The token permission table is assembled from Cloudflare's permissions
  reference plus its instruction to use the "Edit Cloudflare Workers" template.
  The template was exercised and is sufficient; the narrower hand-built set —
  specifically the claim that Workers Assets uploads need
  `Workers KV Storage : Edit` — is still reasoned rather than observed.
- `wrangler rollback`, `deployments list`, and `d1 export --remote --output`
  were confirmed to exist with these flags in wrangler 4.126.0 via `--help`;
  none of them were run against an account.
- The Workers Paid requirement is a plan-level reading of Cloudflare's pricing
  for Durable Objects, not a measured limit.

What *was* executed locally, with no credentials:

- `wrangler --version` → `4.126.0`.
- `wrangler deploy --dry-run` against the rendered config resolves all seven
  bindings (`DAEMON_ROOM`, `PAIRING_INDEX`, `DB`, `METRICS`, `ASSETS`, `BUILD`,
  `P2P_OPEN`) and bundles the Worker, so the configuration parses and the two
  Durable Object classes are exported as the `v1` migration expects.
- `scripts/deploy-origin.sh` was exercised three ways: it rejects a missing
  `PAIRFOB_D1_DATABASE_ID`, rejects a non-uuid value, and with a throwaway uuid
  renders `wrangler.deploy.jsonc` carrying that id and the `pair.taoai.site`
  route. `git check-ignore` confirms the rendered file is untracked. The
  throwaway render was deleted afterwards.
- A dry-run against the committed `wrangler.jsonc` fails with
  `assets.directory ... does not exist` until `public-dist` is built, which is
  the packing step in the deploy order above, not a configuration fault.
- `bun` is installed here and the Worker unit suite passes (133 pass / 0 fail at
  the time of writing), but that suite exercises the request handlers in
  isolation; it says nothing about the remote steps above.
