"""pydantic-settings config (06 §1.1): DSN as @property with sslmode=require,
adjudicator_app role only."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADJ_", frozen=True)

    # 16 §L1: the cloud judge's only model path (shared with intel); empty ⇒ nights count skipped
    llm_router_url: str = Field(default="", validation_alias="LLM_ROUTER_URL")
    judge_max_tasks_per_day: int = 60  # per tenant per UTC day, ledgered (m1_101)
    judge_max_tasks_per_run: int = 60  # the one-run bound on top of it

    # No default on purpose: a missing DSN is a boot refusal that crashloops (06 §1.1),
    # never a service limping along against localhost. The DSN carries the
    # adjudicator_app NOBYPASSRLS role — this service NEVER holds a superuser DSN.
    pg_dsn: SecretStr
    pg_pool_min: int = 2
    pg_pool_max: int = 10
    http_timeout_s: float = 30.0
    # controld's query choke — this service's ONLY ledger read path (05 §6). Empty ⇒
    # spectral.estimate refuses at run time rather than the whole service at boot.
    querychoke_base_url: str = ""
    querychoke_token: SecretStr = SecretStr("")
    # controld's EVIDENCE_READ_TOKEN, E1's own credential; empty ⇒ no E1 read, cloud RM skipped.
    evidence_token: SecretStr = SecretStr("")
    tenant_hmac_pepper: str = ""  # hex; the pepper controld enroll.TenantRoot derives from

    @property
    def pg_dsn_app(self) -> str:
        dsn = self.pg_dsn.get_secret_value()
        if "sslmode=" in dsn:
            return dsn
        return dsn + ("&" if "?" in dsn else "?") + "sslmode=require"


def load_settings() -> Settings:
    return Settings()
