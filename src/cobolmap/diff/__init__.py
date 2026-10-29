"""Exact observation comparator facade; no runtime or oracle execution."""
from .comparator import classify_bytes, compare

__all__ = ["classify_bytes", "compare"]
