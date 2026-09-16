"""pricing — the pinned, versioned `model_prices` table (06 §8.4), shipped as repo data.

`model_prices.v1.json` is loaded once; every ModelPrice it hands out carries
`<version>@sha256:<digest of the file bytes>` as its price_table_version, so a report or a
compiled draft traces to the exact table that priced it (`sha256sum model_prices.v1.json`
reproduces the digest without this code). A model the table does not pin is refused by name,
never priced by guess — report.py then issues `indicative`, not a number with a hidden basis.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from app.tvo.report import ModelPrice

TABLE_PATH = Path(__file__).with_name("model_prices.v1.json")

UsdPerMtok = Annotated[float, Field(ge=0.0, allow_inf_nan=False)] | None


class PriceRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: Literal["anthropic", "openai", "google"]
    model_id: str = Field(min_length=1)
    input: UsdPerMtok
    output: UsdPerMtok
    cache_write: UsdPerMtok
    cache_read: UsdPerMtok
    effective_from: date
    source: str = Field(pattern=r"^https://")
    retrieved_at: date

    def unpublished(self) -> tuple[str, ...]:
        return tuple(
            c for c in ("input", "output", "cache_write", "cache_read") if getattr(self, c) is None
        )


_ROWS = TypeAdapter(list[PriceRow])


class UnpinnedModel(LookupError):
    """No pinned price row for the model: refused, never a guess (06 §8.4)."""


@dataclass(frozen=True)
class PriceTable:
    version: str
    rows: Mapping[str, ModelPrice]
    unpinned: Mapping[str, str]

    def price_for(self, model_id: str) -> ModelPrice:
        if model_id in self.rows:
            return self.rows[model_id]
        raise UnpinnedModel(
            f"{model_id!r}: {self.unpinned.get(model_id, f'no row in {self.version}')}"
        )


@lru_cache(maxsize=4)
def load_table(path: Path = TABLE_PATH) -> PriceTable:
    raw = path.read_bytes()
    doc = json.loads(raw)
    version = f"{doc['version']}@sha256:{hashlib.sha256(raw).hexdigest()}"
    rows: dict[str, ModelPrice] = {}
    unpinned: dict[str, str] = {}
    for r in _ROWS.validate_python(doc["rows"]):
        if r.model_id in rows or r.model_id in unpinned:
            raise ValueError(f"{path.name}: duplicate row for {r.model_id!r}")
        if missing := r.unpublished():
            gap = "/".join(missing)
            unpinned[r.model_id] = f"{r.provider} publishes no {gap} price ({r.source})"
            continue
        rows[r.model_id] = ModelPrice(
            version, r.input / 1e6, r.output / 1e6, r.cache_write / 1e6, r.cache_read / 1e6
        )
    return PriceTable(version, MappingProxyType(rows), MappingProxyType(unpinned))


def price_for(model_id: str) -> ModelPrice:
    return load_table().price_for(model_id)
