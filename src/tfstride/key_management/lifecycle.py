from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal

ManagedKeyLifecycleApplicability = Literal[
    "applicable",
    "not_applicable",
    "unknown",
]
ManagedKeyLifecycleAssessment = Literal[
    "compliant",
    "action_required",
    "unknown",
    "not_evaluated",
]
ManagedKeyLifecycleIssue = Literal[
    "rotation_disabled",
    "rotation_period_missing",
    "rotation_policy_missing",
    "rotation_automation_missing",
    "rotation_interval_too_long",
    "expiration_policy_missing",
    "expiration_interval_too_long",
    "key_lifetime_too_long",
]

_VALID_APPLICABILITY: Final[frozenset[str]] = frozenset(
    {
        "applicable",
        "not_applicable",
        "unknown",
    }
)
_VALID_ASSESSMENTS: Final[frozenset[str]] = frozenset(
    {
        "compliant",
        "action_required",
        "unknown",
        "not_evaluated",
    }
)
_VALID_ISSUES: Final[frozenset[str]] = frozenset(
    {
        "rotation_disabled",
        "rotation_period_missing",
        "rotation_policy_missing",
        "rotation_automation_missing",
        "rotation_interval_too_long",
        "expiration_policy_missing",
        "expiration_interval_too_long",
        "key_lifetime_too_long",
    }
)


@dataclass(frozen=True, slots=True)
class ManagedKeyLifecyclePosture:
    """Provider-neutral managed-key lifecycle decision and ordered provenance."""

    applicability: ManagedKeyLifecycleApplicability
    assessment: ManagedKeyLifecycleAssessment
    issues: tuple[ManagedKeyLifecycleIssue, ...] = field(default_factory=tuple)
    uncertainties: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.applicability not in _VALID_APPLICABILITY:
            raise ValueError(f"unsupported managed-key lifecycle applicability: {self.applicability!r}")
        if self.assessment not in _VALID_ASSESSMENTS:
            raise ValueError(f"unsupported managed-key lifecycle assessment: {self.assessment!r}")

        issues = tuple(self.issues)
        invalid_issues = tuple(issue for issue in issues if issue not in _VALID_ISSUES)
        if invalid_issues:
            raise ValueError(f"unsupported managed-key lifecycle issue: {invalid_issues[0]!r}")

        evaluated = self.applicability == "applicable"
        if evaluated == (self.assessment == "not_evaluated"):
            raise ValueError("managed-key lifecycle applicability and assessment are inconsistent")
        if (self.assessment == "action_required") != bool(issues):
            raise ValueError("managed-key lifecycle issues must exactly match an action-required assessment")

        object.__setattr__(self, "issues", issues)
        object.__setattr__(self, "uncertainties", tuple(self.uncertainties))

    @property
    def is_applicable(self) -> bool:
        """Whether the provider established that lifecycle evaluation applies."""

        return self.applicability == "applicable"

    @property
    def requires_attention(self) -> bool:
        """Whether known lifecycle issues require action."""

        return self.assessment == "action_required"

    @property
    def is_indeterminate(self) -> bool:
        """Whether applicability or lifecycle compliance could not be determined."""

        return self.applicability == "unknown" or self.assessment == "unknown"
