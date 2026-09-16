"""regime — the per-tenant regime source (06 §8.4; m1_075): the compiler's `Regime` read from
`m1_tenant_regimes` under the tenant GUC. usd rows resolve their pinned model through
app/pricing; quota rows carry the fitted window limit and the tenant-confirmed S. No row
means nothing can be priced: `load_regime` refuses, the compile parks, the report stays
indicative (06 §8.5)."""

import asyncpg

from app.policy_compiler.cpvs import Regime
from app.pricing import price_for
from app.tvo.report import COST_BASIS_USD


class RegimeUnset(RuntimeError):
    """No regime row for the tenant (basis, pinned model / window limit, S, V unset)."""


async def set_regime(
    conn: asyncpg.Connection,
    tenant_id: str,
    *,
    cost_basis: str,
    v_default: float,
    set_by: str,
    price_model_id: str | None = None,
    window_limit_tokens: int | None = None,
    shadow_price_usd: float | None = None,
) -> None:
    """Upsert the tenant's row; m1_075's CHECK refuses cross-basis inputs and the trigger
    appends the history row. An unpinned model is refused here, at set time, not at 03:00."""
    if price_model_id is not None:
        price_for(price_model_id)
    await conn.execute(
        "INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, "
        "window_limit_tokens, shadow_price_usd, v_default, set_by) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7) "
        "ON CONFLICT (tenant_id) DO UPDATE SET cost_basis = EXCLUDED.cost_basis, "
        "price_model_id = EXCLUDED.price_model_id, "
        "window_limit_tokens = EXCLUDED.window_limit_tokens, "
        "shadow_price_usd = EXCLUDED.shadow_price_usd, v_default = EXCLUDED.v_default, "
        "set_by = EXCLUDED.set_by, set_at = now()",
        tenant_id,
        cost_basis,
        price_model_id,
        window_limit_tokens,
        shadow_price_usd,
        v_default,
        set_by,
    )


async def load_regime(conn: asyncpg.Connection, tenant_id: str) -> Regime:
    row = await conn.fetchrow(
        "SELECT cost_basis, price_model_id, window_limit_tokens, shadow_price_usd, v_default "
        "FROM m1_tenant_regimes WHERE tenant_id = $1",
        tenant_id,
    )
    if row is None:
        raise RegimeUnset(
            f"tenant {tenant_id}: no regime row (cost basis, pinned model / window limit, S, V) "
            "-- cannot price attempts (06 §8.4)"
        )
    if row["cost_basis"] == COST_BASIS_USD:
        return Regime(
            cost_basis=row["cost_basis"],
            v_default=float(row["v_default"]),
            price=price_for(row["price_model_id"]),
        )
    return Regime(
        cost_basis=row["cost_basis"],
        v_default=float(row["v_default"]),
        window_limit_tokens=row["window_limit_tokens"],
        shadow_price_usd=float(row["shadow_price_usd"]),
    )
