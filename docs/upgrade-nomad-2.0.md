# Bayreuth NOMAD 2.0 migration

This branch merges FAIRmat's `v2.0.0` template while retaining the Bayreuth
Traefik configuration, UBT JSON allowlist, Academic Cloud parser configuration,
four processing workers, and explicit named storage. The tabular plugin is pinned
to `94c3492a596efca93ffd6555b03ecf4247c57277` to separate the platform migration
from changes to plugin behavior. The backend and GUI packages are both 2.0.0.

## Before deployment

For a disposable fresh-data backend smoke test (not a restore rehearsal):

```sh
docker build --target final -t nomad-oasis-upgrade:2.0-test .
docker compose -f tests/compose-upgrade-smoke.yaml up -d --wait
docker compose -f tests/compose-upgrade-smoke.yaml exec -T app curl -fsS http://localhost:8000/-/health
docker compose -f tests/compose-upgrade-smoke.yaml down
```

This stack exposes no host ports and does not read production configuration.
Its test volumes are retained by `down`; they are distinct from production.

- Do not publish an untested image as `main`: production Watchtower follows it.
  Build/test an immutable upgrade image first; disable Watchtower during cutover.
- The production Compose file contains fixed container, network, and volume
  names. A different Compose project name alone does NOT isolate staging.
  Staging must override every container name, volume source, filesystem mount,
  external network, and Traefik label. Never start this file directly in a
  second checkout as a staging deployment.
- Preserve the existing ignored `.env`, `.env.north`, and
  `configs/access/allowed-emails.json`. Allowlist backup files are ignored too.
  A missing JSON file intentionally removes the exact-email restriction while
  retaining the verified-domain rule; verify the production file before cutover.
- Record running image digests and take a coordinated, restorable backup of
  MongoDB, `.volumes/fs`, Temporal PostgreSQL, NORTH state, and private config
  after stopping writes and draining processing. Test restoration in isolation.

## URL and authorization changes

GUI v2 is served at `/` (the upstream GUI selector is retained); GUI v1 remains
at `/gui/`. APIs use `/backend/api/v1`, NORTH uses `/backend/north/`, and the
OAuth callback is
`https://data.ing.uni-bayreuth.de/backend/north/hub/oauth_callback`.
The internal app health check remains `http://localhost:8000/-/health`.
Update bookmarks/integrations and confirm the callback with Keycloak.

The user resolver is asynchronous in NOMAD 2.0. The distribution wrapper awaits
the resolver before enforcing the same policy. The old empty-base-path URL patch
is no longer invoked. Nginx injects the policy-specific 403 handler into both
GUIs, including their SPA fallback responses. NORTH retains its independent
verified-email/domain/allowlist check. Verify login, logout, denied login,
personal/upload tokens, and notebook launch before opening the deployment.

## Elasticsearch cutover

Follow https://docs.nomad-lab.eu/howto/oasis/migrate/v2.0.html, option 2:
rebuild an ES9 index from existing archives. Do not mount the ES7 volume in ES9.
This branch uses a NEW named volume `nomad_oasis_elastic_9` and sets
`NOMAD_ELASTIC_VERSION=9` on app/workers. Retain `nomad_oasis_elastic` for rollback.
MongoDB's database name and filesystem mounts remain unchanged.

After backup and tested-image selection, stop the old deployment without `-v`,
start the upgraded stack, wait for health, then run:

```sh
docker compose exec app python -m nomad_ubt_access admin uploads index --parallel 4
```

Indexing reads stored archives; it is not blanket reparsing. Do not regenerate
all uploads as part of the platform migration: that could rerun AI guesses or
overwrite generated artifacts. Materials indexing and logtransfer are removed
in NOMAD 2.0; only the entries index is required.

Compare entry counts and representative searches/archives with the backup.
Check existing TableValues property filters and scatter expressions in both
GUIs, including tables with missing cells. Test a new CSV/Excel upload, automatic
generation, review edits, row/column modes, uncertainty and unit handling, plots,
and NORTH. Restart the proxy after backend recreation to refresh upstream DNS.

## Rollback

Keep writes disabled until validation passes. Restore the old image digests,
configuration, ES7 volume and coordinated data backup if needed. Merely
downgrading containers is not sufficient after shared data has changed.
Do not delete old volumes during this migration. Production cutover remains
blocked until restored-data and browser tests pass.
