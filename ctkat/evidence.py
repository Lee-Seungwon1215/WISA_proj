"""CT-KAT evidence schema v2 and its fail-closed overall-state fold.

The legacy ``verdict_class`` taxonomy mixed three different things in one
label: raw detector output, human attribution, and the final action a user
should take.  That made combinations such as a raw timing ``FAIL`` next to a
headline ``robust`` possible.

Schema v2 keeps each evidence layer separate and computes one five-state
``overall`` value from those layers.  ``fold_overall`` is intentionally pure so
the CLI, corpus builder, migration tool, and validation gate all use the exact
same decision table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Collection, Mapping, Optional

SCHEMA_VERSION = "2.0"
LEGACY_TIMING_BACKEND = "experimental-first-order-v1"


class Correctness(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_RUN = "not-run"


class Structural(StrEnum):
    NO_FINDING = "no-finding"
    FINDING = "finding"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    NOT_RUN = "not-run"


class AsmEvidence(StrEnum):
    NO_CANDIDATE = "no-candidate"
    CANDIDATE = "candidate"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    NOT_RUN = "not-run"


class AsmAttribution(StrEnum):
    PUBLIC = "public"
    SECRET_RISK = "secret-risk"
    MIXED = "mixed"
    UNRESOLVED = "unresolved"
    NOT_APPLICABLE = "not-applicable"


class TimingValidity(StrEnum):
    VALID = "valid"
    CONFOUNDED = "confounded"
    INSUFFICIENT_POWER = "insufficient-power"
    ENVIRONMENT_REJECTED = "environment-rejected"
    ERROR = "error"
    NOT_RUN = "not-run"


class TimingSignal(StrEnum):
    NO_SIGNAL = "no-signal-observed"
    WARNING = "warning"
    SIGNAL = "signal"
    NOT_INTERPRETABLE = "not-interpretable"
    NOT_RUN = "not-run"


class ReviewStatus(StrEnum):
    NOT_NEEDED = "not-needed"
    PENDING = "pending"
    REVIEWED = "reviewed"
    DISPUTED = "disputed"
    EXPIRED = "expired"


class Overall(StrEnum):
    NO_FINDING = "no-finding-observed"
    RISK = "risk-detected"
    NEEDS_REVIEW = "needs-review"
    INCONCLUSIVE = "inconclusive"
    TOOL_ERROR = "tool-error"


_REVIEW_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
_REVIEWED_LEGACY_ACCEPTANCE = {"accepted-variable-time"}


def structural_from_statuses(statuses: Collection[str]) -> Structural:
    """Collapse raw matrix statuses without discarding incomplete cells."""
    normalized = {status.upper() for status in statuses if status}
    if not normalized or normalized <= {"NA", "NONE"}:
        return Structural.NOT_RUN
    unknown = normalized - {"PASS", "FAIL", "ERROR", "NA", "NONE"}
    if unknown:
        raise ValueError(f"unknown structural status(es): {sorted(unknown)}")
    attempted = normalized - {"NA", "NONE"}
    if attempted == {"ERROR"}:
        return Structural.ERROR
    if "ERROR" in attempted:
        return Structural.INCOMPLETE
    if "FAIL" in attempted:
        return Structural.FINDING
    if attempted == {"PASS"}:
        return Structural.NO_FINDING
    return Structural.NOT_RUN


def asm_from_cells(
    *,
    candidate_count: int,
    error_count: int,
    cell_count: int,
    not_run_count: int = 0,
) -> AsmEvidence:
    """Collapse asm evidence while preserving partial/error coverage."""
    if min(candidate_count, error_count, cell_count, not_run_count) < 0:
        raise ValueError("asm cell/count values cannot be negative")
    if error_count + not_run_count > cell_count:
        raise ValueError("asm error/not-run counts exceed the cell count")
    if cell_count <= 0:
        if candidate_count or error_count or not_run_count:
            raise ValueError("asm counts require at least one cell")
        return AsmEvidence.NOT_RUN
    if not_run_count >= cell_count:
        if candidate_count or error_count:
            raise ValueError("all asm cells are not-run but contain results")
        return AsmEvidence.NOT_RUN
    if error_count >= cell_count:
        return AsmEvidence.ERROR
    if error_count or not_run_count:
        return AsmEvidence.INCOMPLETE
    if candidate_count:
        return AsmEvidence.CANDIDATE
    return AsmEvidence.NO_CANDIDATE


def asm_attribution_from_triage(
    asm: AsmEvidence | str,
    triage: str,
) -> AsmAttribution:
    asm_value = AsmEvidence(asm)
    if asm_value in {AsmEvidence.NO_CANDIDATE, AsmEvidence.NOT_RUN}:
        return AsmAttribution.NOT_APPLICABLE
    if asm_value == AsmEvidence.ERROR:
        return AsmAttribution.UNRESOLVED
    mapping = {
        "public": AsmAttribution.PUBLIC,
        "secret-risk": AsmAttribution.SECRET_RISK,
        "mixed": AsmAttribution.MIXED,
        "untriaged": AsmAttribution.UNRESOLVED,
        "none": AsmAttribution.UNRESOLVED,
        "": AsmAttribution.UNRESOLVED,
    }
    if triage not in mapping:
        raise ValueError(f"unknown asm attribution/triage value: {triage!r}")
    return mapping[triage]


def timing_from_raw(
    raw_status: str,
    validity: str = "",
) -> tuple[TimingValidity, TimingSignal]:
    """Map the legacy timing status without pretending it has validated power.

    A completed legacy timing run without explicit validity defaults to
    ``insufficient-power``. Backend-v2 callers supply the environment,
    harness-control, and power decision explicitly; migration manifests may
    also preserve a stricter historical classification.
    """
    raw = raw_status.upper()
    if raw in {"", "NONE", "NOT-RUN"}:
        if validity and validity != TimingValidity.NOT_RUN:
            raise ValueError("timing validity was supplied but timing did not run")
        return TimingValidity.NOT_RUN, TimingSignal.NOT_RUN
    if raw == "ERROR":
        return TimingValidity.ERROR, TimingSignal.NOT_INTERPRETABLE
    if raw == "INSUFFICIENT":
        timing_validity = (
            TimingValidity(validity) if validity else TimingValidity.INSUFFICIENT_POWER
        )
        if timing_validity not in {
            TimingValidity.INSUFFICIENT_POWER,
            TimingValidity.ENVIRONMENT_REJECTED,
            TimingValidity.CONFOUNDED,
            TimingValidity.ERROR,
        }:
            raise ValueError(
                "raw timing status INSUFFICIENT requires a non-interpretable timing validity"
            )
        return timing_validity, TimingSignal.NOT_INTERPRETABLE
    if raw not in {"PASS", "WARNING", "FAIL"}:
        raise ValueError(f"unknown raw timing status: {raw_status!r}")

    timing_validity = TimingValidity(validity) if validity else TimingValidity.INSUFFICIENT_POWER
    signal = {
        "PASS": TimingSignal.NO_SIGNAL,
        "WARNING": TimingSignal.WARNING,
        "FAIL": TimingSignal.SIGNAL,
    }[raw]
    return timing_validity, signal


def review_from_legacy(
    *,
    legacy_basis: str,
    legacy_verdict_class: str,
    asm_attribution: AsmAttribution | str,
    review_status: str = "",
    review_id: str = "",
) -> ReviewStatus:
    """Derive review maturity while refusing to infer "reviewed" from a note."""
    attribution = AsmAttribution(asm_attribution)
    review_needed = (
        legacy_basis in {"review", "stop"}
        or legacy_verdict_class
        in {
            "accepted-variable-time",
            "needs-analysis",
            "ct-leak",
            "varlat-secret-risk",
        }
        or attribution
        in {
            AsmAttribution.PUBLIC,
            AsmAttribution.SECRET_RISK,
            AsmAttribution.MIXED,
            AsmAttribution.UNRESOLVED,
        }
    )
    if review_status:
        requested = ReviewStatus(review_status)
        if requested == ReviewStatus.NOT_NEEDED and review_needed:
            raise ValueError("review=not-needed contradicts manual or unresolved evidence")
        return requested

    if review_needed:
        # An ID alone is not proof that the review reached a final state.
        return ReviewStatus.PENDING
    return ReviewStatus.NOT_NEEDED


def fold_overall(
    *,
    correctness: Correctness | str,
    structural: Structural | str,
    asm: AsmEvidence | str,
    asm_attribution: AsmAttribution | str,
    timing_validity: TimingValidity | str,
    timing_signal: TimingSignal | str,
    review: ReviewStatus | str,
    legacy_verdict_class: str = "",
) -> Overall:
    """Compute the only user-facing action state.

    Priority is deliberate:

    1. A functionally failing artifact invalidates downstream claims.
    2. Confirmed risk is never hidden by an unrelated tool failure.
    3. Tool errors and partial/invalid measurements cannot become clean.
    4. Human attribution that is pending/disputed/expired stays needs-review.
    5. Only then may the result say no-finding-observed.
    """
    correctness = Correctness(correctness)
    structural = Structural(structural)
    asm = AsmEvidence(asm)
    attribution = AsmAttribution(asm_attribution)
    timing_validity = TimingValidity(timing_validity)
    timing_signal = TimingSignal(timing_signal)
    review = ReviewStatus(review)

    if correctness == Correctness.FAIL:
        return Overall.INCONCLUSIVE

    timing_risk = timing_validity == TimingValidity.VALID and timing_signal == TimingSignal.SIGNAL
    automatic_structural_risk = legacy_verdict_class == "build-sensitive-ct"
    reviewed_risk = review == ReviewStatus.REVIEWED and (
        legacy_verdict_class in {"ct-leak", "varlat-secret-risk"}
        or attribution in {AsmAttribution.SECRET_RISK, AsmAttribution.MIXED}
    )
    if timing_risk or automatic_structural_risk or reviewed_risk:
        return Overall.RISK

    if (
        correctness == Correctness.ERROR
        or structural == Structural.ERROR
        or asm == AsmEvidence.ERROR
        or timing_validity == TimingValidity.ERROR
    ):
        return Overall.TOOL_ERROR

    if (
        structural == Structural.INCOMPLETE
        or asm == AsmEvidence.INCOMPLETE
        or timing_validity
        in {
            TimingValidity.CONFOUNDED,
            TimingValidity.INSUFFICIENT_POWER,
            TimingValidity.ENVIRONMENT_REJECTED,
        }
        or (
            timing_validity == TimingValidity.VALID
            and timing_signal == TimingSignal.NOT_INTERPRETABLE
        )
    ):
        return Overall.INCONCLUSIVE

    if timing_validity == TimingValidity.VALID and timing_signal == TimingSignal.WARNING:
        return Overall.NEEDS_REVIEW

    manual_attribution = attribution in {
        AsmAttribution.PUBLIC,
        AsmAttribution.SECRET_RISK,
        AsmAttribution.MIXED,
        AsmAttribution.UNRESOLVED,
    }
    structural_acceptance = (
        structural == Structural.FINDING and legacy_verdict_class in _REVIEWED_LEGACY_ACCEPTANCE
    )
    structural_unresolved = structural == Structural.FINDING and not structural_acceptance
    legacy_manual_unreviewed = (
        legacy_verdict_class
        in {
            "accepted-variable-time",
            "ct-leak",
            "varlat-secret-risk",
        }
        and review != ReviewStatus.REVIEWED
    )
    if (
        review in {ReviewStatus.PENDING, ReviewStatus.DISPUTED, ReviewStatus.EXPIRED}
        or attribution == AsmAttribution.UNRESOLVED
        or (manual_attribution and review != ReviewStatus.REVIEWED)
        or (structural_acceptance and review != ReviewStatus.REVIEWED)
        or legacy_manual_unreviewed
        or legacy_verdict_class in {"needs-analysis", "ct-clean-untriaged"}
        or structural_unresolved
    ):
        return Overall.NEEDS_REVIEW

    no_layer_ran = (
        structural == Structural.NOT_RUN
        and asm == AsmEvidence.NOT_RUN
        and timing_validity == TimingValidity.NOT_RUN
    )
    if no_layer_ran:
        return Overall.INCONCLUSIVE

    return Overall.NO_FINDING


@dataclass(frozen=True)
class EvidenceV2:
    correctness: Correctness
    structural: Structural
    asm: AsmEvidence
    asm_attribution: AsmAttribution
    timing_validity: TimingValidity
    timing_signal: TimingSignal
    review: ReviewStatus
    review_id: str = ""
    legacy_verdict_class: str = ""
    overall: Optional[Overall] = None

    def __post_init__(self) -> None:
        if self.review_id and not _REVIEW_ID_RE.fullmatch(self.review_id):
            raise ValueError(
                "review_id must be a lowercase artifact ID using [a-z0-9._-] "
                f"(got {self.review_id!r})"
            )
        if (
            self.review
            in {
                ReviewStatus.REVIEWED,
                ReviewStatus.DISPUTED,
                ReviewStatus.EXPIRED,
            }
            and not self.review_id
        ):
            raise ValueError(f"review={self.review.value!r} requires review_id")
        if self.review == ReviewStatus.NOT_NEEDED and self.review_id:
            raise ValueError("review=not-needed cannot carry review_id")

        if self.timing_validity == TimingValidity.NOT_RUN:
            if self.timing_signal != TimingSignal.NOT_RUN:
                raise ValueError("timing not-run requires timing_signal=not-run")
        elif self.timing_signal == TimingSignal.NOT_RUN:
            raise ValueError("attempted timing cannot have timing_signal=not-run")

        if self.asm in {AsmEvidence.NO_CANDIDATE, AsmEvidence.NOT_RUN}:
            if self.asm_attribution != AsmAttribution.NOT_APPLICABLE:
                raise ValueError(f"asm={self.asm.value} requires asm_attribution=not-applicable")
        elif self.asm == AsmEvidence.CANDIDATE:
            if self.asm_attribution == AsmAttribution.NOT_APPLICABLE:
                raise ValueError("asm=candidate requires an attribution state")

        expected = fold_overall(
            correctness=self.correctness,
            structural=self.structural,
            asm=self.asm,
            asm_attribution=self.asm_attribution,
            timing_validity=self.timing_validity,
            timing_signal=self.timing_signal,
            review=self.review,
            legacy_verdict_class=self.legacy_verdict_class,
        )
        if self.overall is None:
            object.__setattr__(self, "overall", expected)
        elif self.overall != expected:
            raise ValueError(
                f"overall={self.overall.value!r} contradicts evidence fold "
                f"(expected {expected.value!r})"
            )

    def as_dict(self) -> dict[str, str]:
        assert self.overall is not None
        return {
            "schema_version": SCHEMA_VERSION,
            "correctness": self.correctness.value,
            "structural": self.structural.value,
            "asm": self.asm.value,
            "asm_attribution": self.asm_attribution.value,
            "timing_validity": self.timing_validity.value,
            "timing_signal": self.timing_signal.value,
            "review": self.review.value,
            "review_id": self.review_id,
            "overall": self.overall.value,
            "legacy_verdict_class": self.legacy_verdict_class,
        }

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> EvidenceV2:
        version = str(row.get("schema_version", ""))
        if version != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION!r}, got {version!r}")
        overall_raw = str(row.get("overall", ""))
        return cls(
            correctness=Correctness(str(row["correctness"])),
            structural=Structural(str(row["structural"])),
            asm=AsmEvidence(str(row["asm"])),
            asm_attribution=AsmAttribution(str(row["asm_attribution"])),
            timing_validity=TimingValidity(str(row["timing_validity"])),
            timing_signal=TimingSignal(str(row["timing_signal"])),
            review=ReviewStatus(str(row["review"])),
            review_id=str(row.get("review_id", "")),
            legacy_verdict_class=str(row.get("legacy_verdict_class", "")),
            overall=Overall(overall_raw),
        )


def build_evidence(
    *,
    correctness: str,
    ct_statuses: Collection[str],
    asm_candidate_count: int,
    asm_error_count: int,
    asm_cell_count: int,
    asm_not_run_count: int = 0,
    triage: str,
    raw_timing_status: str,
    timing_validity: str,
    legacy_verdict_class: str,
    legacy_basis: str,
    review_status: str,
    review_id: str,
) -> EvidenceV2:
    """Shared adapter from legacy/raw layer data into the v2 record."""
    structural = structural_from_statuses(ct_statuses)
    asm = asm_from_cells(
        candidate_count=asm_candidate_count,
        error_count=asm_error_count,
        cell_count=asm_cell_count,
        not_run_count=asm_not_run_count,
    )
    attribution = asm_attribution_from_triage(asm, triage)
    validity, signal = timing_from_raw(raw_timing_status, timing_validity)
    review = review_from_legacy(
        legacy_basis=legacy_basis,
        legacy_verdict_class=legacy_verdict_class,
        asm_attribution=attribution,
        review_status=review_status,
        review_id=review_id,
    )
    return EvidenceV2(
        correctness=Correctness(correctness),
        structural=structural,
        asm=asm,
        asm_attribution=attribution,
        timing_validity=validity,
        timing_signal=signal,
        review=review,
        review_id=review_id,
        legacy_verdict_class=legacy_verdict_class,
    )
