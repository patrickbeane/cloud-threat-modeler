from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal

StorageVersioningState = Literal["enabled", "disabled", "unknown", "not_observed"]

_VALID_STATES: Final[frozenset[str]] = frozenset(
    {
        "enabled",
        "disabled",
        "unknown",
        "not_observed",
    }
)
_ATTENTION_STATES: Final[frozenset[str]] = frozenset({"disabled", "unknown"})


@dataclass(frozen=True, slots=True)
class StorageVersioningPosture:
    """Provider-neutral object versioning state and its ordered uncertainties."""

    state: StorageVersioningState
    uncertainties: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.state not in _VALID_STATES:
            raise ValueError(f"unsupported storage versioning state: {self.state!r}")
        object.__setattr__(self, "uncertainties", tuple(self.uncertainties))

    @property
    def requires_attention(self) -> bool:
        """Whether the posture is disabled or cannot be determined."""

        return self.state in _ATTENTION_STATES
