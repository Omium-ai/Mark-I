"""pydantic-settings config (06 §1.1): DSN as @property with sslmode=require, intel_app
role only."""

from typing import Literal

from pydantic import Field, SecretStr, field_validator
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
    # rm.contributions (16 L8): the ingest bucket (read) and the RM training root (write)
    contributions_root_uri: str | None = None
    rm_root_uri: str | None = None
    # SSE-KMS key every rm/contributions/* PutObject must name; required when rm_root_uri is s3://
    rm_contributions_kms_key_arn: str | None = None
    # SM mark1-training-policy; empty ⇒ every closed-provider row exports eval-only
    authorized_training_providers: str = ""
    # 16 §L1: memory.extract's model path (raw name, shared with the adjudicator) and its caps
    llm_router_url: str = Field(default="", validation_alias="LLM_ROUTER_URL")
    memory_max_sessions_per_day: int = 30  # per tenant per UTC day, ledgered (m1_101)
    memory_max_sessions_per_run: int = 30  # the one-run bound on top of it
    memory_max_input_tokens: int = 20_000
    # 16-release L3: Customer.io region the register names; else boot refusal (controld R1 same var)
    customerio_region: Literal["us", "eu"] = Field(
        default="us", validation_alias="CUSTOMERIO_REGION"
    )

    @field_validator("customerio_region", mode="before")
    @classmethod
    def _region_default(cls, v: object) -> object:
        return v or "us"

    @property
    def pg_dsn_app(self) -> str:
        dsn = self.pg_dsn.get_secret_value()
        if "sslmode=" in dsn:
            return dsn
        return dsn + ("&" if "?" in dsn else "?") + "sslmode=require"


def load_settings() -> Settings:
    return Settings()
