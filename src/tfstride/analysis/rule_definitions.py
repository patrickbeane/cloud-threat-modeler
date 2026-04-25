from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tfstride.models import BoundaryType, Finding, ResourceInventory, TrustBoundary


BoundaryIndex = dict[tuple[BoundaryType, str, str], TrustBoundary]


@dataclass(frozen=True, slots=True)
class RuleEvaluationContext:
    inventory: ResourceInventory
    boundary_index: BoundaryIndex


class RuleDetector(Protocol):
    def __call__(self, context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
        ...


@dataclass(frozen=True, slots=True)
class ExecutableRule:
    rule_id: str
    detector: RuleDetector

    def evaluate(self, context: RuleEvaluationContext) -> list[Finding]:
        return self.detector(context, self.rule_id)