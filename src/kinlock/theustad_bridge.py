"""Adapter from Kinlock's typed certificate to the source-locked TheUstad checker."""

from __future__ import annotations

import time
from typing import Any

from ._vendor.theustad_causal_commit import verify_causal_certificate


class VendoredTheUstadVerifier:
    """Planner-independent verifier used by the public hackathon runtime.

    The class deliberately depends only on the certificate's serialized form.
    It does not call Kinlock's policy engine and cannot grant authority; it only
    establishes whether the supplied proof is internally valid.
    """

    def __init__(self, evidence_key: bytes, max_clock_skew: float = 5.0):
        if not evidence_key:
            raise ValueError("evidence_key is required")
        self.evidence_key = evidence_key
        self.max_clock_skew = max_clock_skew

    def verify(self, certificate: Any, now: float | None = None):
        doc = certificate.to_dict() if hasattr(certificate, "to_dict") else dict(certificate)
        return verify_causal_certificate(
            doc,
            evidence_key=self.evidence_key,
            now=time.time() if now is None else now,
            max_clock_skew=self.max_clock_skew,
        )
