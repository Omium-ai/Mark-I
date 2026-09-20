"""pydantic-settings config (06 §1.1): DSN as @property with sslmode=require, intel_app
role only."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INTEL_", frozen=True)

    # No default on purpose: a missing DSN is a boot refusal that crashloops (06 §1.1),
    # never a service limping along against localhost. The DSN carries the intel_app
    # NOBYPASSRLS role — this service NEVER holds a superuser DSN.
    pg_dsn: SecretStr
    pg_pool_min: int = 2
    pg_pool_max: int = 10
    http_timeout_s: float = 30.0
    # No defaults, same boot-refusal posture as the DSN (06 §1.1): these two URLs are the
    # service's ONLY ledger/cert read paths — 08 §3.3's query chokepoint (intel holds no
    # ClickHouse credential, 05 §6) and adjudicator-svc's cert route (06 §1.2). A service
    # limping along without them would silently serve nothing.
    querychoke_base_url: str
    adjudicator_base_url: str
    # corpus.export's two inputs (06 §13): the export root (s3://<bucket> or a local path) and
    # the tenant-root pepper (hex; controld's enroll.TenantRoot derives from the same bytes).
    # Optional: absent, the job parks with its own refusal — but they were never declared
    # here, so the chart's INTEL_CORPUS_ROOT_URI / INTEL_TENANT_HMAC_PEPPER were read by
    # nothing and every nightly export failed in prod with "required".
    corpus_root_uri: str | None = None
    tenant_hmac_pepper: SecretStr | None = None

    @property
    def pg_dsn_app(self) -> str:
        dsn = self.pg_dsn.get_secret_value()
        if "sslmode=" in dsn:
            return dsn
        return dsn + ("&" if "?" in dsn else "?") + "sslmode=require"


def load_settings() -> Settings:
    return Settings()
