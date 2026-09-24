# mark1-migrate: psql + clickhouse-client + tools/migrate-db.sh + every migration dir in one image,
# tagged by the same <sha7> as the services so the schema version is the code version.
# Build from the repo ROOT:  docker build -f deploy/helm/omium-mark1/migrate/Dockerfile -t omium/mark1-migrate:<sha7> .
ARG CLICKHOUSE_TAG=26.7
FROM clickhouse/clickhouse-server:${CLICKHOUSE_TAG} AS clickhouse

# Debian, not alpine: the ClickHouse binary is glibc-linked (the "static" tgz is the same file).
FROM postgres:15
# The pinned postgres image lags its distro's security fixes; the upgrade is what keeps the scan clean.
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/local/bin/gosu /usr/local/bin/docker-entrypoint.sh
COPY --from=clickhouse /usr/bin/clickhouse /usr/local/bin/clickhouse
RUN ln -s clickhouse /usr/local/bin/clickhouse-client \
    && mkdir -p /opt/mark1/migrations/m1 /opt/mark1/migrations/adj /opt/mark1/migrations/in
COPY tools/migrate-db.sh /opt/mark1/migrate-db.sh
# The runtime layout is the migrate Job's contract (templates/migrate-job.yaml lanes m1, adj, in): `in` stays an empty lane.
COPY migrations/*.sql /opt/mark1/migrations/m1/
COPY migrations/adjudicator/ /opt/mark1/migrations/adj/
USER 65532:65532
ENTRYPOINT ["/bin/bash"]
