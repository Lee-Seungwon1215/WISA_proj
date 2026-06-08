"""triage.yaml — the human-judgment layer consumed by `ctkat screen`.

Phase 1 (Bundle R): triage is deliberately a SEPARATE file from the pipeline
config (ctkat.yaml). ctkat.yaml describes the deterministic pipeline to run (and
should stay frozen for reproducibility); triage.yaml records how a HUMAN judged
the results — whether an asm-scan variable-latency candidate operates on public
or secret-derived data, and any manual verdict_class override. Keeping them apart
means the same ctkat.yaml can be screened by different reviewers / at different
triage maturity without editing the pipeline config, and the triage verdicts live
in a reviewable, diffable artifact next to docs/accepted_variable_time.md.

Absent `--triage`, everything defaults to `untriaged` (the honest default the
corpus already uses) — which, under default-deny, is a gating result.

Schema:

    registry: docs/accepted_variable_time.md   # optional; override default registry path
    harnesses:
      kem_dec:
        varlat: public          # public | secret-risk | none | untriaged
        note: "fips202 shake divisions are public"
      sign:
        verdict: accepted-variable-time   # optional manual verdict_class override
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .verdict_class import VERDICT_CLASSES


class HarnessTriage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # How a reviewer judged this harness's asm-scan variable-latency candidates.
    varlat: Literal["public", "secret-risk", "none", "untriaged"] = "untriaged"
    # Optional manual verdict_class override (domain triage the auto-classifier
    # can't derive — e.g. a ct FAIL that is a scheme's analyzed-safe rejection
    # sampling). Validated against the known taxonomy so a typo fails at load.
    verdict: Optional[str] = None
    # Optional free-text note appended to the harness's summary notes.
    note: Optional[str] = None

    @field_validator("verdict")
    @classmethod
    def _known_class(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VERDICT_CLASSES:
            raise ValueError(
                f"unknown verdict_class {v!r}; expected one of {list(VERDICT_CLASSES)}"
            )
        return v


class TriageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Optional override of the accepted-variable-time registry path (default:
    # docs/accepted_variable_time.md, resolved relative to the triage file).
    registry: Optional[Path] = None
    harnesses: Dict[str, HarnessTriage] = Field(default_factory=dict)

    # --- adapters to the verdict_class.summarize() keyword args -------------
    def varlat_map(self) -> Dict[str, str]:
        """harness -> varlat label (the `triage` arg of summarize)."""
        return {h: t.varlat for h, t in self.harnesses.items()}

    def verdict_overrides(self) -> Dict[str, str]:
        """harness -> manual verdict_class (only where set)."""
        return {h: t.verdict for h, t in self.harnesses.items() if t.verdict}

    def note_overrides(self) -> Dict[str, str]:
        """harness -> manual note (only where set)."""
        return {h: t.note for h, t in self.harnesses.items() if t.note}


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
