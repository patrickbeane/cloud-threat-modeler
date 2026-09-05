from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import dataclass

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.decoration import ResourceDecorationRunner

_FIRST_MARKER = "arn:test:first-decoration"
_SECOND_MARKER = "arn:test:second-decoration"


@dataclass(frozen=True, slots=True)
class _DecorationContext:
    token: object


class _RecordingContextFactory:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.contexts: list[_DecorationContext] = []
        self.resources: list[list[NormalizedResource]] = []

    def __call__(self, resources: list[NormalizedResource]) -> _DecorationContext:
        self._events.append("context")
        self.resources.append(resources)
        context = _DecorationContext(token=object())
        self.contexts.append(context)
        return context


_StageAction = Callable[[list[NormalizedResource], _DecorationContext], None]


class _RecordingStage:
    def __init__(
        self,
        label: str,
        events: list[str],
        action: _StageAction | None = None,
    ) -> None:
        self._label = label
        self._events = events
        self._action = action
        self.resources: list[list[NormalizedResource]] = []
        self.contexts: list[_DecorationContext] = []

    def apply(
        self,
        resources: list[NormalizedResource],
        context: _DecorationContext,
    ) -> None:
        self._events.append(f"stage:{self._label}")
        self.resources.append(resources)
        self.contexts.append(context)
        if self._action is not None:
            self._action(resources, context)


def _resource() -> NormalizedResource:
    return NormalizedResource(
        address="example_resource.target",
        provider="example",
        resource_type="example_resource",
        name="target",
        category=ResourceCategory.DATA,
    )


def _add_attached_role(
    role_arn: str,
) -> _StageAction:
    def add_role(
        resources: list[NormalizedResource],
        _context: _DecorationContext,
    ) -> None:
        resources[0].add_attached_role_arn(role_arn)

    return add_role


def _observe_attached_roles(
    observations: list[tuple[str, ...]],
) -> _StageAction:
    def observe(
        resources: list[NormalizedResource],
        _context: _DecorationContext,
    ) -> None:
        observations.append(resources[0].attached_role_arns)

    return observe


class _DecorationFailure(RuntimeError):
    pass


def _fail_stage(
    _resources: list[NormalizedResource],
    _context: _DecorationContext,
) -> None:
    raise _DecorationFailure("decoration failed")


class ResourceDecorationRunnerTests(unittest.TestCase):
    def test_runner_builds_one_context_then_runs_ordered_stages_with_shared_state(self) -> None:
        events: list[str] = []
        resources = [_resource()]
        downstream_attached_roles: list[tuple[str, ...]] = []
        context_factory = _RecordingContextFactory(events)
        first = _RecordingStage("first", events, _add_attached_role(_FIRST_MARKER))
        second = _RecordingStage("second", events, _observe_attached_roles(downstream_attached_roles))
        runner = ResourceDecorationRunner[_DecorationContext](
            context_factory=context_factory,
            stages=(first, second),
        )

        runner.decorate(resources)

        self.assertEqual(events, ["context", "stage:first", "stage:second"])
        self.assertEqual(len(context_factory.contexts), 1)
        self.assertEqual(len(context_factory.resources), 1)
        self.assertIs(context_factory.resources[0], resources)
        self.assertIs(first.resources[0], resources)
        self.assertIs(second.resources[0], resources)
        self.assertIs(first.contexts[0], context_factory.contexts[0])
        self.assertIs(second.contexts[0], context_factory.contexts[0])
        self.assertEqual(downstream_attached_roles, [(_FIRST_MARKER,)])

        resources[0].add_attached_role_arn(_SECOND_MARKER)
        self.assertEqual(resources[0].attached_role_arns, (_FIRST_MARKER, _SECOND_MARKER))

    def test_runner_snapshots_the_configured_stage_sequence(self) -> None:
        events: list[str] = []
        context_factory = _RecordingContextFactory(events)
        stages = [_RecordingStage("configured", events)]
        runner = ResourceDecorationRunner[_DecorationContext](
            context_factory=context_factory,
            stages=stages,
        )
        stages.append(_RecordingStage("late", events))

        runner.decorate([])

        self.assertEqual(events, ["context", "stage:configured"])

    def test_runner_stops_after_stage_failure_and_propagates_exception(self) -> None:
        events: list[str] = []
        context_factory = _RecordingContextFactory(events)
        after = _RecordingStage("after", events)
        runner = ResourceDecorationRunner[_DecorationContext](
            context_factory=context_factory,
            stages=(
                _RecordingStage("before", events),
                _RecordingStage("failing", events, _fail_stage),
                after,
            ),
        )

        with self.assertRaisesRegex(_DecorationFailure, "decoration failed"):
            runner.decorate([_resource()])

        self.assertEqual(events, ["context", "stage:before", "stage:failing"])
        self.assertEqual(after.resources, [])
        self.assertEqual(after.contexts, [])

    def test_runner_builds_context_for_an_empty_stage_sequence(self) -> None:
        events: list[str] = []
        resources: list[NormalizedResource] = []
        context_factory = _RecordingContextFactory(events)
        runner = ResourceDecorationRunner[_DecorationContext](
            context_factory=context_factory,
            stages=(),
        )

        runner.decorate(resources)

        self.assertEqual(events, ["context"])
        self.assertEqual(len(context_factory.contexts), 1)
        self.assertIs(context_factory.resources[0], resources)


if __name__ == "__main__":
    unittest.main()
