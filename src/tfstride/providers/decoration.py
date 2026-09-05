from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Generic, Protocol, TypeVar

from tfstride.models import NormalizedResource

_ContextT = TypeVar("_ContextT")
_StageContextT = TypeVar("_StageContextT", contravariant=True)

DecorationContextFactory = Callable[[list[NormalizedResource]], _ContextT]


class ResourceDecorationStage(Protocol[_StageContextT]):
    """Apply one resource decoration stage using a provider-owned context."""

    def apply(
        self,
        resources: list[NormalizedResource],
        context: _StageContextT,
    ) -> None: ...


class ResourceDecorationRunner(Generic[_ContextT]):
    """Build one context and run an ordered resource decoration stage sequence."""

    def __init__(
        self,
        *,
        context_factory: DecorationContextFactory[_ContextT],
        stages: Sequence[ResourceDecorationStage[_ContextT]],
    ) -> None:
        self._context_factory = context_factory
        self._stages = tuple(stages)

    def decorate(self, resources: list[NormalizedResource]) -> None:
        context = self._context_factory(resources)
        for stage in self._stages:
            stage.apply(resources, context)
