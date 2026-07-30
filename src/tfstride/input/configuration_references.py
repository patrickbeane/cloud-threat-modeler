from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from tfstride.models import (
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)


@dataclass(slots=True)
class _PlannedModule:
    address: str | None
    resources: tuple[TerraformResource, ...]
    child_modules: tuple[_PlannedModule, ...]


@dataclass(slots=True)
class _ResourceBinding:
    configuration_address: str
    configuration: Mapping[str, Any]
    instances: tuple[TerraformResource, ...]
    mapping_state: TerraformReferenceResolutionState | None


@dataclass(slots=True)
class _ModuleContext:
    configuration: Mapping[str, Any]
    planned: _PlannedModule
    parent: _ModuleContext | None
    input_expressions: Mapping[str, Any]
    mapping_state: TerraformReferenceResolutionState | None
    bindings: dict[str, _ResourceBinding]


_MISSING = object()


def attach_configuration_reference_resolutions(
    configuration: Any,
    planned_root_module: Mapping[str, Any],
    resources: Sequence[TerraformResource],
) -> None:
    """Attach conservative configuration-reference resolutions to planned resources."""
    if not isinstance(configuration, Mapping):
        return
    root_configuration = configuration.get("root_module")
    if not isinstance(root_configuration, Mapping):
        return

    resources_by_address = {resource.address: resource for resource in resources}
    planned_root = _build_planned_module(planned_root_module, resources_by_address)
    _process_module(
        root_configuration,
        planned_root,
        parent=None,
        input_expressions={},
        mapping_state=None,
    )


def _build_planned_module(
    raw_module: Mapping[str, Any],
    resources_by_address: Mapping[str, TerraformResource],
) -> _PlannedModule:
    address = raw_module.get("address")
    if not isinstance(address, str) or not address:
        address = None

    resources: list[TerraformResource] = []
    raw_resources = raw_module.get("resources", [])
    if isinstance(raw_resources, list):
        for raw_resource in raw_resources:
            if not isinstance(raw_resource, Mapping):
                continue
            resource_address = raw_resource.get("address")
            if not isinstance(resource_address, str):
                continue
            resource = resources_by_address.get(resource_address)
            if resource is not None:
                resources.append(resource)

    child_modules: list[_PlannedModule] = []
    raw_children = raw_module.get("child_modules", [])
    if isinstance(raw_children, list):
        for raw_child in raw_children:
            if isinstance(raw_child, Mapping):
                child_modules.append(_build_planned_module(raw_child, resources_by_address))

    return _PlannedModule(
        address=address,
        resources=tuple(resources),
        child_modules=tuple(child_modules),
    )


def _process_module(
    configuration: Mapping[str, Any],
    planned: _PlannedModule,
    *,
    parent: _ModuleContext | None,
    input_expressions: Mapping[str, Any],
    mapping_state: TerraformReferenceResolutionState | None,
) -> None:
    context = _ModuleContext(
        configuration=configuration,
        planned=planned,
        parent=parent,
        input_expressions=input_expressions,
        mapping_state=mapping_state,
        bindings=_resource_bindings(configuration, planned),
    )

    for binding in context.bindings.values():
        for resource in binding.instances:
            _attach_resource_resolutions(resource, binding, context)

    raw_module_calls = configuration.get("module_calls", {})
    if not isinstance(raw_module_calls, Mapping):
        return
    for call_name, raw_call in raw_module_calls.items():
        if not isinstance(call_name, str) or not isinstance(raw_call, Mapping):
            continue
        child_configuration = raw_call.get("module")
        if not isinstance(child_configuration, Mapping):
            continue
        child_modules = _planned_children_for_call(planned, call_name)
        if not child_modules:
            continue

        child_mapping_state = _merge_mapping_states(
            mapping_state,
            _expansion_state(raw_call),
            TerraformReferenceResolutionState.AMBIGUOUS if len(child_modules) > 1 else None,
        )
        child_inputs = raw_call.get("expressions", {})
        if not isinstance(child_inputs, Mapping):
            child_inputs = {}
        for child_module in child_modules:
            _process_module(
                child_configuration,
                child_module,
                parent=context,
                input_expressions=child_inputs,
                mapping_state=child_mapping_state,
            )


def _resource_bindings(
    configuration: Mapping[str, Any],
    planned: _PlannedModule,
) -> dict[str, _ResourceBinding]:
    bindings: dict[str, _ResourceBinding] = {}
    raw_resources = configuration.get("resources", [])
    if not isinstance(raw_resources, list):
        return bindings

    for raw_resource in raw_resources:
        if not isinstance(raw_resource, Mapping):
            continue
        address = raw_resource.get("address")
        resource_type = raw_resource.get("type")
        name = raw_resource.get("name")
        mode = raw_resource.get("mode", "managed")
        if not all(isinstance(value, str) and value for value in (address, resource_type, name, mode)):
            continue

        instances = tuple(
            resource
            for resource in planned.resources
            if resource.resource_type == resource_type and resource.name == name and resource.mode == mode
        )
        mapping_state = _merge_mapping_states(
            _expansion_state(raw_resource),
            TerraformReferenceResolutionState.AMBIGUOUS if len(instances) > 1 else None,
        )
        bindings[address] = _ResourceBinding(
            configuration_address=address,
            configuration=raw_resource,
            instances=instances,
            mapping_state=mapping_state,
        )
    return bindings


def _planned_children_for_call(
    planned: _PlannedModule,
    call_name: str,
) -> tuple[_PlannedModule, ...]:
    prefix = f"module.{call_name}"
    if planned.address:
        prefix = f"{planned.address}.{prefix}"
    return tuple(
        child
        for child in planned.child_modules
        if child.address == prefix or (child.address is not None and child.address.startswith(f"{prefix}["))
    )


def _expansion_state(configuration: Mapping[str, Any]) -> TerraformReferenceResolutionState | None:
    if "count_expression" in configuration or "for_each_expression" in configuration:
        return TerraformReferenceResolutionState.UNSUPPORTED
    return None


def _merge_mapping_states(
    *states: TerraformReferenceResolutionState | None,
) -> TerraformReferenceResolutionState | None:
    if TerraformReferenceResolutionState.UNSUPPORTED in states:
        return TerraformReferenceResolutionState.UNSUPPORTED
    if TerraformReferenceResolutionState.AMBIGUOUS in states:
        return TerraformReferenceResolutionState.AMBIGUOUS
    return None


def _attach_resource_resolutions(
    resource: TerraformResource,
    binding: _ResourceBinding,
    context: _ModuleContext,
) -> None:
    expressions = binding.configuration.get("expressions", {})
    if not isinstance(expressions, Mapping):
        return

    source_mapping_state = _merge_mapping_states(context.mapping_state, binding.mapping_state)
    resolutions = list(resource.reference_resolutions)
    for path, expression in _reference_expressions(expressions):
        configuration_resolution = _resolve_configuration_expression(expression, context, seen=frozenset())
        planned_value = _value_at_path(resource.values, path)
        path_unknown = _path_is_unknown(resource.unknown_values, path)

        if planned_value is not _MISSING and not path_unknown:
            resolution = TerraformReferenceResolution(
                path=path,
                state=TerraformReferenceResolutionState.RESOLVED,
                provenance=TerraformReferenceProvenance.PLANNED_VALUE,
                planned_value=planned_value,
                references=configuration_resolution.references,
            )
        elif not path_unknown:
            resolution = TerraformReferenceResolution(
                path=path,
                state=TerraformReferenceResolutionState.UNRESOLVED,
                provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                references=configuration_resolution.references,
                targets=configuration_resolution.targets,
                reason="referenced expression is not represented as a planned value or unknown path",
            )
        elif source_mapping_state is not None:
            resolution = TerraformReferenceResolution(
                path=path,
                state=source_mapping_state,
                provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                references=configuration_resolution.references,
                targets=configuration_resolution.targets,
                reason=(
                    "configuration block uses count, for_each, or an expanded module instance"
                    if source_mapping_state is TerraformReferenceResolutionState.UNSUPPORTED
                    else "configuration block maps to multiple planned resource instances"
                ),
            )
        else:
            resolution = TerraformReferenceResolution(
                path=path,
                state=configuration_resolution.state,
                provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                references=configuration_resolution.references,
                targets=configuration_resolution.targets,
                reason=configuration_resolution.reason,
            )
        resolutions.append(resolution)

    resource.reference_resolutions = tuple(sorted(resolutions, key=lambda item: _path_sort_key(item.path)))


def _reference_expressions(
    expressions: Mapping[str, Any],
) -> tuple[tuple[TerraformExpressionPath, Mapping[str, Any]], ...]:
    found: list[tuple[TerraformExpressionPath, Mapping[str, Any]]] = []

    def visit(value: Any, path: TerraformExpressionPath) -> None:
        if isinstance(value, Mapping):
            if "references" in value:
                found.append((path, value))
                return
            for key, child in value.items():
                if isinstance(key, str):
                    visit(child, (*path, key))
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, index))

    for key, expression in expressions.items():
        if isinstance(key, str):
            visit(expression, (key,))
    return tuple(found)


def _resolve_configuration_expression(
    expression: Mapping[str, Any],
    context: _ModuleContext,
    *,
    seen: frozenset[tuple[int, str]],
) -> TerraformReferenceResolution:
    raw_references = expression.get("references")
    if not isinstance(raw_references, list) or any(
        not isinstance(reference, str) or not reference for reference in raw_references
    ):
        return _configuration_result(
            TerraformReferenceResolutionState.UNSUPPORTED,
            reason="configuration references have an unsupported value shape",
        )

    references = tuple(dict.fromkeys(raw_references))
    if not references:
        return _configuration_result(
            TerraformReferenceResolutionState.UNRESOLVED,
            reason="configuration expression has no references",
        )

    module_input = _exact_module_input(references, context)
    if module_input is not None:
        return _resolve_module_input(module_input, context, seen=seen)

    matched_bindings: dict[str, tuple[_ResourceBinding, list[str]]] = {}
    unmatched: list[str] = []
    for reference in references:
        binding = _binding_for_reference(context, reference)
        if binding is None:
            unmatched.append(reference)
            continue
        matched = matched_bindings.setdefault(
            binding.configuration_address,
            (binding, []),
        )
        matched[1].append(reference)

    targets_by_address: dict[str, TerraformReferenceTarget] = {}
    candidate_state: TerraformReferenceResolutionState | None = None
    unresolved_binding = False
    selected_references = set(_maximal_references(unmatched))
    for binding, binding_references in matched_bindings.values():
        maximal_binding_references = _maximal_references(binding_references)
        selected_references.update(maximal_binding_references)
        target_mapping_state = _merge_mapping_states(context.mapping_state, binding.mapping_state)
        candidate_state = _merge_mapping_states(candidate_state, target_mapping_state)
        if not binding.instances:
            unresolved_binding = True
            continue
        target_reference = maximal_binding_references[0]
        for target in binding.instances:
            targets_by_address[target.address] = TerraformReferenceTarget(
                address=target.address,
                reference=target_reference,
            )

    maximal_references = tuple(reference for reference in references if reference in selected_references)
    targets = tuple(sorted(targets_by_address.values(), key=lambda target: target.address))

    if candidate_state is TerraformReferenceResolutionState.UNSUPPORTED:
        return _configuration_result(
            TerraformReferenceResolutionState.UNSUPPORTED,
            references=maximal_references,
            targets=targets,
            reason="referenced resource uses count, for_each, or an expanded module instance",
        )
    if candidate_state is TerraformReferenceResolutionState.AMBIGUOUS:
        return _configuration_result(
            TerraformReferenceResolutionState.AMBIGUOUS,
            references=maximal_references,
            targets=targets,
            reason="referenced configuration block maps to multiple planned resource instances",
        )
    if len(targets) > 1 or (targets and (unmatched or unresolved_binding)):
        return _configuration_result(
            TerraformReferenceResolutionState.AMBIGUOUS,
            references=maximal_references,
            targets=targets,
            reason="configuration expression has multiple possible targets",
        )
    if len(targets) == 1:
        return _configuration_result(
            TerraformReferenceResolutionState.SYMBOLIC,
            references=maximal_references,
            targets=targets,
            reason=(
                "configuration expression references one modeled resource, but resulting value equivalence is unproven"
            ),
        )
    if unresolved_binding:
        unresolved_reason = "referenced configuration block has no planned resource instance"
    elif any(reference.startswith("module.") for reference in unmatched):
        unresolved_reason = "child-module output references are not traversed by the configuration resolver"
    else:
        unresolved_reason = "configuration references do not identify a modeled resource"
    return _configuration_result(
        TerraformReferenceResolutionState.UNRESOLVED,
        references=maximal_references,
        reason=unresolved_reason,
    )


def _exact_module_input(
    references: tuple[str, ...],
    context: _ModuleContext,
) -> str | None:
    if context.parent is None or len(references) != 1:
        return None
    reference = references[0]
    for input_name in context.input_expressions:
        if isinstance(input_name, str) and reference == f"var.{input_name}":
            return input_name
    return None


def _resolve_module_input(
    input_name: str,
    context: _ModuleContext,
    *,
    seen: frozenset[tuple[int, str]],
) -> TerraformReferenceResolution:
    reference = f"var.{input_name}"
    if context.parent is None:
        return _configuration_result(
            TerraformReferenceResolutionState.UNRESOLVED,
            references=(reference,),
            reason="module input has no parent module call",
        )

    seen_key = (id(context), input_name)
    if seen_key in seen:
        return _configuration_result(
            TerraformReferenceResolutionState.UNSUPPORTED,
            references=(reference,),
            reason="module input pass-through contains a cycle",
        )
    expression = context.input_expressions.get(input_name)
    if not isinstance(expression, Mapping) or "references" not in expression:
        return _configuration_result(
            TerraformReferenceResolutionState.UNRESOLVED,
            references=(reference,),
            reason="module input does not contain a symbolic resource reference",
        )

    parent_resolution = _resolve_configuration_expression(
        expression,
        context.parent,
        seen=seen | {seen_key},
    )
    return _configuration_result(
        parent_resolution.state,
        references=(reference,),
        targets=parent_resolution.targets,
        reason=(
            f"symbolic candidate propagated through module input {reference}"
            if parent_resolution.state is TerraformReferenceResolutionState.SYMBOLIC
            else parent_resolution.reason
        ),
    )


def _binding_for_reference(
    context: _ModuleContext,
    reference: str,
) -> _ResourceBinding | None:
    matches = [
        binding
        for address, binding in context.bindings.items()
        if reference == address or reference.startswith(f"{address}.") or reference.startswith(f"{address}[")
    ]
    if not matches:
        return None
    return max(matches, key=lambda binding: len(binding.configuration_address))


def _maximal_references(references: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        reference
        for reference in references
        if not any(
            other != reference and (other.startswith(f"{reference}.") or other.startswith(f"{reference}["))
            for other in references
        )
    )


def _configuration_result(
    state: TerraformReferenceResolutionState,
    *,
    references: tuple[str, ...] = (),
    targets: tuple[TerraformReferenceTarget, ...] = (),
    reason: str | None = None,
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=(),
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=targets,
        reason=reason,
    )


def _value_at_path(value: Any, path: TerraformExpressionPath) -> Any:
    current = value
    for segment in path:
        if isinstance(segment, str) and isinstance(current, Mapping):
            if segment not in current:
                return _MISSING
            current = current[segment]
            continue
        if (
            isinstance(segment, int)
            and isinstance(current, Sequence)
            and not isinstance(
                current,
                str | bytes | bytearray,
            )
        ):
            if segment < 0 or segment >= len(current):
                return _MISSING
            current = current[segment]
            continue
        return _MISSING
    return current


def _path_is_unknown(value: Any, path: TerraformExpressionPath) -> bool:
    current = value
    for segment in path:
        if current is True:
            return True
        if isinstance(segment, str) and isinstance(current, Mapping):
            if segment not in current:
                return False
            current = current[segment]
            continue
        if (
            isinstance(segment, int)
            and isinstance(current, Sequence)
            and not isinstance(
                current,
                str | bytes | bytearray,
            )
        ):
            if segment < 0 or segment >= len(current):
                return False
            current = current[segment]
            continue
        return False
    return _contains_unknown(current)


def _contains_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(_contains_unknown(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return any(_contains_unknown(item) for item in value)
    return False


def _path_sort_key(path: TerraformExpressionPath) -> tuple[str, ...]:
    return tuple(f"{type(segment).__name__}:{segment}" for segment in path)
