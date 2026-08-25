from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from tfstride.models import (
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)

_ObjectMapping = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _ResourceConfiguration:
    address: str
    resource_type: str
    name: str
    mode: str
    provider_config_key: str | None
    expressions: _ObjectMapping


@dataclass(frozen=True, slots=True)
class _ModuleCallConfiguration:
    module: _ModuleConfiguration
    expressions: _ObjectMapping


@dataclass(frozen=True, slots=True)
class _ModuleConfiguration:
    resources: tuple[_ResourceConfiguration, ...]
    module_calls: Mapping[str, _ModuleCallConfiguration]


@dataclass(slots=True)
class _PlannedModule:
    address: str | None
    resources: tuple[TerraformResource, ...]
    child_modules: tuple[_PlannedModule, ...]


@dataclass(slots=True)
class _ResourceBinding:
    configuration_address: str
    configuration: _ResourceConfiguration
    instances: tuple[TerraformResource, ...]


@dataclass(slots=True)
class _ModuleContext:
    planned: _PlannedModule
    parent: _ModuleContext | None
    input_expressions: _ObjectMapping
    bindings: dict[str, _ResourceBinding]


_MISSING = object()


def attach_configuration_reference_resolutions(
    configuration: object,
    planned_root_module: object,
    resources: Sequence[TerraformResource],
) -> None:
    """Attach conservative configuration-reference resolutions to planned resources."""
    configuration_object = _object_mapping(configuration)
    planned_root_object = _object_mapping(planned_root_module)
    if configuration_object is None or planned_root_object is None:
        return
    root_configuration = _module_configuration(configuration_object.get("root_module"))
    if root_configuration is None:
        return

    resources_by_address = {resource.address: resource for resource in resources}
    planned_root = _build_planned_module(planned_root_object, resources_by_address)
    _process_module(
        root_configuration,
        planned_root,
        parent=None,
        input_expressions={},
    )


def _build_planned_module(
    raw_module: _ObjectMapping,
    resources_by_address: Mapping[str, TerraformResource],
) -> _PlannedModule:
    address = raw_module.get("address")
    if not isinstance(address, str) or not address:
        address = None

    resources: list[TerraformResource] = []
    raw_resources = raw_module.get("resources", [])
    if isinstance(raw_resources, list):
        for raw_resource in raw_resources:
            resource_object = _object_mapping(raw_resource)
            if resource_object is None:
                continue
            resource_address = resource_object.get("address")
            if not isinstance(resource_address, str):
                continue
            resource = resources_by_address.get(resource_address)
            if resource is not None:
                resources.append(resource)

    child_modules: list[_PlannedModule] = []
    raw_children = raw_module.get("child_modules", [])
    if isinstance(raw_children, list):
        for raw_child in raw_children:
            child_object = _object_mapping(raw_child)
            if child_object is not None:
                child_modules.append(_build_planned_module(child_object, resources_by_address))

    return _PlannedModule(
        address=address,
        resources=tuple(resources),
        child_modules=tuple(child_modules),
    )


def _process_module(
    configuration: _ModuleConfiguration,
    planned: _PlannedModule,
    *,
    parent: _ModuleContext | None,
    input_expressions: _ObjectMapping,
) -> None:
    context = _ModuleContext(
        planned=planned,
        parent=parent,
        input_expressions=input_expressions,
        bindings=_resource_bindings(configuration, planned),
    )

    for binding in context.bindings.values():
        for resource in binding.instances:
            _attach_resource_resolutions(resource, binding, context)

    for call_name, raw_call in configuration.module_calls.items():
        child_modules = _planned_children_for_call(planned, call_name)
        if not child_modules:
            continue

        for child_module in child_modules:
            _process_module(
                raw_call.module,
                child_module,
                parent=context,
                input_expressions=raw_call.expressions,
            )


def _resource_bindings(
    configuration: _ModuleConfiguration,
    planned: _PlannedModule,
) -> dict[str, _ResourceBinding]:
    bindings: dict[str, _ResourceBinding] = {}
    for resource_configuration in configuration.resources:
        instances = tuple(
            resource
            for resource in planned.resources
            if resource.resource_type == resource_configuration.resource_type
            and resource.name == resource_configuration.name
            and resource.mode == resource_configuration.mode
        )
        bindings[resource_configuration.address] = _ResourceBinding(
            configuration_address=resource_configuration.address,
            configuration=resource_configuration,
            instances=instances,
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


def _attach_resource_resolutions(
    resource: TerraformResource,
    binding: _ResourceBinding,
    context: _ModuleContext,
) -> None:
    if binding.configuration.provider_config_key is not None:
        resource.provider_config_key = binding.configuration.provider_config_key
    expressions = binding.configuration.expressions

    # Source expansion alone does not determine relationship confidence;
    # target cardinality and unresolved expression evidence do.
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
    expressions: _ObjectMapping,
) -> tuple[tuple[TerraformExpressionPath, _ObjectMapping], ...]:
    found: list[tuple[TerraformExpressionPath, _ObjectMapping]] = []

    def visit(value: object, path: TerraformExpressionPath) -> None:
        mapping = _object_mapping(value)
        if mapping is not None:
            if "references" in mapping:
                found.append((path, mapping))
                return
            for key, child in mapping.items():
                visit(child, (*path, key))
            return
        sequence = _object_sequence(value)
        if sequence is not None:
            for index, child in enumerate(sequence):
                visit(child, (*path, index))

    for key, expression in expressions.items():
        visit(expression, (key,))
    return tuple(found)


def _resolve_configuration_expression(
    expression: _ObjectMapping,
    context: _ModuleContext,
    *,
    seen: frozenset[tuple[int, str]],
) -> TerraformReferenceResolution:
    raw_references = _non_empty_strings(expression.get("references"))
    if raw_references is None:
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
    unresolved_binding = False
    selected_references = set(_maximal_references(unmatched))
    for binding, binding_references in matched_bindings.values():
        maximal_binding_references = _maximal_references(binding_references)
        selected_references.update(maximal_binding_references)
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
    expression = _object_mapping(context.input_expressions.get(input_name))
    if expression is None or "references" not in expression:
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


def _value_at_path(value: object, path: TerraformExpressionPath) -> object:
    current = value
    for segment in path:
        mapping = _object_mapping(current)
        if isinstance(segment, str) and mapping is not None:
            if segment not in mapping:
                return _MISSING
            current = mapping[segment]
            continue
        sequence = _object_sequence(current)
        if isinstance(segment, int) and sequence is not None:
            if segment < 0 or segment >= len(sequence):
                return _MISSING
            current = sequence[segment]
            continue
        return _MISSING
    return current


def _path_is_unknown(value: object, path: TerraformExpressionPath) -> bool:
    current = value
    for segment in path:
        if current is True:
            return True
        mapping = _object_mapping(current)
        if isinstance(segment, str) and mapping is not None:
            if segment not in mapping:
                return False
            current = mapping[segment]
            continue
        sequence = _object_sequence(current)
        if isinstance(segment, int) and sequence is not None:
            if segment < 0 or segment >= len(sequence):
                return False
            current = sequence[segment]
            continue
        return False
    return _contains_unknown(current)


def _contains_unknown(value: object) -> bool:
    if value is True:
        return True
    mapping = _object_mapping(value)
    if mapping is not None:
        return any(_contains_unknown(item) for item in mapping.values())
    sequence = _object_sequence(value)
    if sequence is not None:
        return any(_contains_unknown(item) for item in sequence)
    return False


def _module_configuration(value: object) -> _ModuleConfiguration | None:
    raw_module = _object_mapping(value)
    if raw_module is None:
        return None

    resources: list[_ResourceConfiguration] = []
    raw_resources = _object_sequence(raw_module.get("resources", []))
    if raw_resources is not None:
        for raw_resource in raw_resources:
            resource = _resource_configuration(raw_resource)
            if resource is not None:
                resources.append(resource)

    module_calls: dict[str, _ModuleCallConfiguration] = {}
    raw_module_calls = _object_mapping(raw_module.get("module_calls", {}))
    if raw_module_calls is not None:
        for call_name, raw_call in raw_module_calls.items():
            call_object = _object_mapping(raw_call)
            if call_object is None:
                continue
            child_module = _module_configuration(call_object.get("module"))
            if child_module is None:
                continue
            module_calls[call_name] = _ModuleCallConfiguration(
                module=child_module,
                expressions=_object_mapping(call_object.get("expressions", {})) or {},
            )

    return _ModuleConfiguration(
        resources=tuple(resources),
        module_calls=module_calls,
    )


def _resource_configuration(value: object) -> _ResourceConfiguration | None:
    raw_resource = _object_mapping(value)
    if raw_resource is None:
        return None
    address = raw_resource.get("address")
    resource_type = raw_resource.get("type")
    name = raw_resource.get("name")
    mode = raw_resource.get("mode", "managed")
    if not all(isinstance(item, str) and item for item in (address, resource_type, name, mode)):
        return None
    assert isinstance(address, str)
    assert isinstance(resource_type, str)
    assert isinstance(name, str)
    assert isinstance(mode, str)
    provider_config_key_value = raw_resource.get("provider_config_key")
    provider_config_key = (
        provider_config_key_value if isinstance(provider_config_key_value, str) and provider_config_key_value else None
    )
    return _ResourceConfiguration(
        address=address,
        resource_type=resource_type,
        name=name,
        mode=mode,
        provider_config_key=provider_config_key,
        expressions=_object_mapping(raw_resource.get("expressions", {})) or {},
    )


def _object_mapping(value: object) -> _ObjectMapping | None:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        return None
    return cast(_ObjectMapping, value)


def _object_sequence(value: object) -> Sequence[object] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return None
    return cast(Sequence[object], value)


def _non_empty_strings(value: object) -> tuple[str, ...] | None:
    sequence = _object_sequence(value)
    if sequence is None or any(not isinstance(item, str) or not item for item in sequence):
        return None
    return tuple(cast(str, item) for item in sequence)


def _path_sort_key(path: TerraformExpressionPath) -> tuple[str, ...]:
    return tuple(f"{type(segment).__name__}:{segment}" for segment in path)
