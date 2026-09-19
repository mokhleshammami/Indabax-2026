"""Lane A — provenance, taint propagation, authority capping, lifecycle, memory.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    class ProvenanceEngine:
        def __init__(self, *, ablation: str = "none") -> None: ...
        def analyze(self, request: DefenseRequest) -> TaintSummary: ...
        def check_authority(self, request: DefenseRequest, taint: TaintSummary) -> AuthorityVerdict: ...

Lane A may add any modules under `aegis/provenance/`; it must keep these three
signatures stable.

The implementation below is a *placeholder* so the pipeline runs from day one.
Lane A replaces it.
"""

from __future__ import annotations

from aegis.types import (
    AuthorityVerdict,
    DefenseRequest,
    TaintSummary,
)


class ProvenanceEngine:
    """Placeholder implementation — replaced by Lane A."""

    def __init__(self, *, ablation: str = "none") -> None:
        self.ablation = ablation

    def analyze(self, request: DefenseRequest) -> TaintSummary:
        return TaintSummary()

    def check_authority(self, request: DefenseRequest, taint: TaintSummary) -> AuthorityVerdict:
        return AuthorityVerdict()


__all__ = ["ProvenanceEngine"]
