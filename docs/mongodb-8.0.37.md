# MongoDB 8.0.37 kernel compatibility patch

Galadriel's Ubuntu kernel reports `7.0.0-43-generic` while
`/proc/version_signature` identifies its upstream base as 7.0.14. The old
Docker Library `mongo:8.0` container contained MongoDB 8.0.29, which refused
startup after the host reboot. MongoDB tracks the Ubuntu detection correction
as https://jira.mongodb.org/browse/SERVER-131779, fixed in 8.0.37.

The Docker Library `mongo:8.0.37` tag was unavailable at deployment time.
MongoDB's publisher image `mongodb/mongodb-community-server:8.0.37-ubuntu2204`
is available and is pinned by digest in Compose. No safety-check bypass or
database major-version change is used. Startup logs now remain visible and
the health check executes a real database ping.

## Existing installation migration

Do not change only the image on an existing database: Docker Library's image
used UID/GID 999, while the publisher image uses UID/GID 1000.

The November 11 deployment stopped app/workers/MongoDB, took offline archives
of both MongoDB volumes, and tested the patch against an isolated database copy
with no application connections. Every collection validated and a disposable
read/write check passed. Baseline: 20 uploads, 76 entries, 37 schema definitions.

New production volumes were restored from that same backup and assigned
ownership 1000:1000:

- `nomad_oasis_mongo_8037` -> `/data/db`
- `nomad_oasis_mongo_config_8037` -> `/data/configdb`

The default publisher entrypoint and new volumes were verified before cutover.
Compose continues to use the logical volume keys `mongo` and `mongo_config`.
Fresh installations get newly initialized volumes with the image's ownership.

## Backup and rollback

Private backup directory on Galadriel:
`/home/rayan/nomad-oasis-backups/pre-8.0.37-20261111/`.
It contains `mongo-data.tar.gz`, `mongo-config.tar.gz`, previous Compose/config
files, and the original MongoDB container manifest. Do not commit backups.

Original volumes `nomad_oasis_mongo` and `nomad_oasis_mongo_config` are retained
unchanged. Do not delete or mount them with the patched image. Rolling back to
8.0.29 also requires a compatible host kernel; it cannot start on the current
host. After new writes occur, rollback requires a data reconciliation plan,
not simply switching to the older volumes.

Check database version, collection counts, app/worker health, and public
`/-/health`, `/backend/api/v1/info`, and GUI routes after deployment. Existing
Elasticsearch data should not be rebuilt merely for this MongoDB patch.
