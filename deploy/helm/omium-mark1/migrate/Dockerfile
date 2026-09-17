# mark1-migrate: psql + clickhouse-client + scripts/migrate-db.sh + every migration dir in one image,
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
COPY scripts/migrate-db.sh /opt/mark1/migrate-db.sh
COPY migrations/ /opt/mark1/migrations/m1/
COPY python/adjudicator/migrations/ /opt/mark1/migrations/adj/
COPY python/intel/migrations/ /opt/mark1/migrations/in/
USER 65532:65532
ENTRYPOINT ["/bin/bash"]
