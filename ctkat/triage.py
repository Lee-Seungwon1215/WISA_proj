"""triage.yaml — the human-judgment layer consumed by `ctkat screen`.

Triage is deliberately a SEPARATE file from the pipeline config (ctkat.yaml).
ctkat.yaml describes the deterministic pipeline to run (and should stay frozen
for reproducibility); triage.yaml records how a HUMAN judged the results —
whether an asm-scan variable-latency candidate operates on public,
secret-derived, or mixed data, any legacy verdict override, and the evidence-v2
review artifact state. Keeping them apart means the same ctkat.yaml can be
screened by different reviewers / at different triage maturity without editing
the pipeline config.

Absent `--triage`, everything defaults to `untriaged` (the honest default the
corpus already uses) — which, under default-deny, is a gating result.

Schema:

    registry: docs/accepted_variable_time.md   # optional; override default registry path
    harnesses:
      kem_dec:
        varlat: public          # public | secret-risk | mixed | none | untriaged
        review: reviewed
        review_id: rvw-mlkem-evidence-v1
        note: "fips202 shake divisions are public"
      sign:
        verdict: accepted-variable-time   # optional manual verdict_class override
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .verdict_class import VERDICT_CLASSES


class HarnessTriage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # How a reviewer judged this harness's asm-scan variable-latency candidates.
    varlat: Literal["public", "secret-risk", "mixed", "none", "untriaged"] = "untriaged"
    # Optional manual verdict_class override (domain triage the auto-classifier
    # can't derive — e.g. a ct FAIL that is a scheme's analyzed-safe rejection
    # sampling). Validated against the known taxonomy so a typo fails at load.
    verdict: Optional[str] = None
    # Optional free-text note appended to the harness's summary notes.
    note: Optional[str] = None
    # Evidence v2 review maturity. A note is not a review artifact: final review
    # states require a stable ID that the curated corpus resolves to
    # docs/reviews/<review_id>.yaml.
    review: Literal["not-needed", "pending", "reviewed", "disputed", "expired"] = "pending"
    review_id: Optional[str] = None

    @field_validator("verdict")
    @classmethod
    def _known_class(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VERDICT_CLASSES:
            raise ValueError(
                f"unknown verdict_class {v!r}; expected one of {list(VERDICT_CLASSES)}"
            )
        return v

    @field_validator("review_id")
    @classmethod
    def _valid_review_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", v):
            raise ValueError("review_id must use lowercase [a-z0-9._-]")
        return v

    @model_validator(mode="after")
    def _review_artifact_contract(self) -> HarnessTriage:
        if self.review in {"reviewed", "disputed", "expired"} and not self.review_id:
            raise ValueError(f"review={self.review!r} requires review_id")
        has_manual_judgment = (
            self.varlat != "untriaged" or self.verdict is not None or self.note is not None
        )
        if self.review == "not-needed" and (self.review_id or has_manual_judgment):
            raise ValueError("review=not-needed cannot carry review_id or a manual triage judgment")
        return self


class TriageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Optional override of the accepted-variable-time registry path (default:
    # docs/accepted_variable_time.md, resolved relative to the triage file).
    registry: Optional[Path] = None
    harnesses: Dict[str, HarnessTriage] = Field(default_factory=dict)

    # --- adapters to the evidence-v2 summary builder -------------------------
    def varlat_map(self) -> Dict[str, str]:
        """harness -> varlat label (the `triage` arg of summarize)."""
        return {h: t.varlat for h, t in self.harnesses.items()}

    def verdict_overrides(self) -> Dict[str, str]:
        """harness -> manual verdict_class (only where set)."""
        return {h: t.verdict for h, t in self.harnesses.items() if t.verdict}

    def note_overrides(self) -> Dict[str, str]:
        """harness -> manual note (only where set)."""
        return {h: t.note for h, t in self.harnesses.items() if t.note}

    def review_statuses(self) -> Dict[str, str]:
        """harness -> evidence-v2 review state."""
        return {h: t.review for h, t in self.harnesses.items()}

    def review_ids(self) -> Dict[str, str]:
        """harness -> stable review artifact ID (only where set)."""
        return {h: t.review_id for h, t in self.harnesses.items() if t.review_id}


def load_triage(path: Path) -> TriageConfig:
    """Load + validate a triage.yaml. Mirrors config.load_config (utf-8 +
    yaml.safe_load + model_validate). An empty file is a valid empty triage."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if raw is None:
        return TriageConfig()
    if not isinstance(raw, dict):
        raise ValueError(f"triage root must be a mapping, got {type(raw).__name__}")
    return TriageConfig.model_validate(raw)
