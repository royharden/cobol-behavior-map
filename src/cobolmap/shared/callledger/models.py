"""Immutable accounting inputs; none grants permission for paid dispatch."""

from collections.abc import Mapping
from dataclasses import dataclass
import re
import unicodedata

from .money import MoneyError, canonical_money


class LedgerError(ValueError):
    """Stable machine-readable ledger failure with a human-readable message."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _model_id(value: object) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(char.isspace() or unicodedata.category(char).startswith("C") for char in value)
    ):
        raise LedgerError("invalid_model_id", "Model IDs must be bounded text without whitespace/control characters.")


def _integer(value: object, field: str, maximum: int | None = None) -> None:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise LedgerError("invalid_bounds", f"{field} must be a nonnegative integer within its cap.")


def _money(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise LedgerError("invalid_money", f"{field} must be canonical decimal text.")
    try:
        canonical = canonical_money(value)
    except MoneyError as error:
        raise LedgerError(error.code, error.message) from error
    if canonical != value:
        raise LedgerError("invalid_money", f"{field} must be canonical decimal text.")


@dataclass(frozen=True)
class PricePlan:
    """Inert sealed price/run pins; this object is never price authorization."""

    run_plan_sha256: str
    prices_sha256: str
    model_ids: tuple[str, ...]
    worst_schedule_usd: str

    def __post_init__(self) -> None:
        for value in (self.run_plan_sha256, self.prices_sha256):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LedgerError("invalid_price_plan", "Price-plan hashes must be lowercase SHA-256 hex.")
        if not isinstance(self.model_ids, tuple) or not self.model_ids:
            raise LedgerError("invalid_price_plan", "A nonempty tuple of pinned model IDs is required.")
        for model_id in self.model_ids:
            _model_id(model_id)
        if len(set(self.model_ids)) != len(self.model_ids):
            raise LedgerError("invalid_price_plan", "Pinned model IDs must be unique.")
        _money(self.worst_schedule_usd, "worst_schedule_usd")

    def as_dict(self) -> dict[str, object]:
        return {
            "run_plan_sha256": self.run_plan_sha256,
            "prices_sha256": self.prices_sha256,
            "model_ids": list(self.model_ids),
            "worst_schedule_usd": self.worst_schedule_usd,
        }


@dataclass(frozen=True)
class CostBounds:
    """Explicit category bounds; missing values remain unknown, including fees."""

    model_id: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int | None
    cache_write_tokens: int | None
    reasoning_tokens: int | None
    other_fees_usd: str | None
    all_fees_bounded: bool

    def __post_init__(self) -> None:
        _model_id(self.model_id)
        _integer(self.input_tokens, "input_tokens", 6000)
        _integer(self.output_tokens, "output_tokens", 2500)
        for field in ("cache_read_tokens", "cache_write_tokens", "reasoning_tokens"):
            value = getattr(self, field)
            if value is not None:
                _integer(value, field)
        if self.other_fees_usd is not None:
            _money(self.other_fees_usd, "other_fees_usd")
        if type(self.all_fees_bounded) is not bool:
            raise LedgerError("invalid_bounds", "all_fees_bounded must be a boolean.")

    @property
    def complete(self) -> bool:
        return self.all_fees_bounded and all(
            value is not None
            for value in (
                self.cache_read_tokens,
                self.cache_write_tokens,
                self.reasoning_tokens,
                self.other_fees_usd,
            )
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "other_fees_usd": self.other_fees_usd,
            "all_fees_bounded": self.all_fees_bounded,
        }


_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "other_tokens",
    "reasoning_in_output",
)


def normalize_usage(usage: Mapping[str, object] | None) -> dict[str, int | bool | None]:
    """Preserve unknown categories explicitly; infer neither overlap nor price."""
    if usage is None:
        return dict.fromkeys(_USAGE_KEYS)
    if not isinstance(usage, Mapping):
        raise LedgerError("invalid_usage", "Usage must be a mapping or None.")
    if any(key not in _USAGE_KEYS for key in usage):
        raise LedgerError("invalid_usage", "Usage contains unknown categories.")
    result: dict[str, int | bool | None] = {}
    for field in _USAGE_KEYS:
        value = usage.get(field)
        if field == "reasoning_in_output":
            if value is not None and type(value) is not bool:
                raise LedgerError("invalid_usage", "reasoning_in_output must be boolean or None.")
        elif value is not None and (type(value) is not int or value < 0):
            raise LedgerError("invalid_usage", f"{field} must be a nonnegative integer or None.")
        result[field] = value
    return result
