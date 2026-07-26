from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)

_MUTATION_OPERATION_ORDER = ("create", "update", "delete")
_MUTATION_ACTION_OPERATIONS: dict[str, tuple[str, ...]] = {
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/create"): ("create",),
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/replace"): ("update",),
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/upsert"): ("create", "update"),
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/delete"): ("delete",),
}
_ITEM_WILDCARD = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/*"
_MUTATING_ROLE_KINDS = frozenset({"built_in_data_contributor", "custom"})
_SCOPE_CONTRACTS: dict[str, tuple[str, str]] = {
    "account": (
        AzureResourceType.COSMOSDB_ACCOUNT,
        "exact_cosmosdb_for_nosql_account",
    ),
    "database": (
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        "exact_cosmosdb_for_nosql_database",
    ),
    "container": (
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        "exact_cosmosdb_for_nosql_container",
    ),
}
_SCOPE_BLAST_RADIUS = {
    "account": 3,
    "database": 2,
    "container": 1,
}


class AzureAppServiceCosmosDbRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_cosmosdb_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            if azure_facts(app).public_network_access_enabled is not True:
                continue

            mutation_paths = [
                path
                for path in azure_facts(app).app_service_cosmosdb_access_paths
                if _is_deterministic_mutation_path(path, app, context)
            ]
            if not mutation_paths:
                continue

            target_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_resource_address",
            )
            account_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_account_address",
            )
            database_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_database_address",
            )
            container_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_container_address",
            )
            identity_addresses = _path_string_values(
                mutation_paths,
                "identity_address",
            )
            assignment_addresses = _path_string_values(
                mutation_paths,
                "role_assignment_address",
            )
            role_definition_addresses = _path_string_values(
                mutation_paths,
                "role_definition_address",
            )
            operations = _mutation_operations(mutation_paths)
            scope_types = _scope_types(mutation_paths)
            has_read_access = any("read" in _string_values(path.get("access_classes")) for path in mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if "delete" in operations else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=max(
                    max(_SCOPE_BLAST_RADIUS[scope_type] for scope_type in scope_types),
                    2 if len(target_addresses) > 1 else 1,
                ),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *account_addresses,
                            *database_addresses,
                            *container_addresses,
                            *target_addresses,
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_mutation_rationale(
                        app,
                        operations,
                        scope_types,
                        len(target_addresses),
                        has_read_access=has_read_access,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_endpoint",
                            _public_endpoint_evidence(app),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "cosmosdb_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "custom_role_actions",
                            _custom_role_action_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=deterministic Cosmos DB for NoSQL native "
                                    "RBAC grant containing exact item mutation DataActions"
                                ),
                                (
                                    "does_not_establish=Cosmos DB network reachability or "
                                    "successful operations after independent network controls"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operations = _path_mutation_operations(path)
    scope_type = _known_string(path.get("scope_type"))
    scope_contract = _SCOPE_CONTRACTS.get(scope_type or "")
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") != "cosmosdb_for_nosql_native_role_assignment"
        or path.get("evaluation_basis") != "modeled_native_rbac_assignment"
        or path.get("authorization_model") != "cosmosdb_for_nosql_native_rbac"
        or path.get("access_state") != "granted"
        or path.get("assignment_scope_state") != "resolved"
        or path.get("assignable_scope_compatibility_state") != "resolved"
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or scope_contract is None
        or path.get("resource_scope") != scope_contract[1]
        or path.get("cosmosdb_resource_type") != scope_contract[0]
        or not operations
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    target_address = _known_string(path.get("cosmosdb_resource_address"))
    assignment_address = _known_string(path.get("role_assignment_address"))
    role_name = _known_string(path.get("role_definition_name"))
    role_reference = _known_string(path.get("role_definition_reference"))
    assignment_scope = _known_string(path.get("assignment_scope"))
    if not all(
        (
            identity_address,
            principal_id,
            target_address,
            assignment_address,
            role_name,
            role_reference,
            assignment_scope,
        )
    ):
        return False

    identity = _resource_by_address(
        context,
        identity_address,
        expected_types=(
            *AZURE_APP_SERVICE_RESOURCE_TYPES,
            AzureResourceType.USER_ASSIGNED_IDENTITY,
        ),
    )
    assignment = _resource_by_address(
        context,
        assignment_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
    )
    if identity is None or assignment is None:
        return False
    if not _same_identifier(azure_facts(identity).principal_id, principal_id):
        return False
    if path.get("identity_kind") == "system_assigned" and identity.address != app.address:
        return False
    if (
        path.get("identity_kind") == "user_assigned"
        and identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
    ):
        return False

    assignment_facts = azure_facts(assignment)
    role_data_actions = _string_values(path.get("role_data_actions"))
    if (
        not _same_identifier(
            assignment_facts.cosmosdb_sql_principal_id,
            principal_id,
        )
        or assignment_facts.cosmosdb_sql_role_assignment_scope != assignment_scope
        or assignment_facts.cosmosdb_sql_role_assignment_scope_kind != scope_type
        or assignment_facts.cosmosdb_sql_role_assignment_scope_state != "resolved"
        or assignment_facts.cosmosdb_sql_assignable_scope_compatibility_state != "resolved"
        or assignment_facts.cosmosdb_sql_role_kind != path.get("role_kind")
        or assignment_facts.cosmosdb_sql_role_definition_reference != role_reference
        or assignment_facts.cosmosdb_sql_role_definition_name != role_name
        or assignment_facts.cosmosdb_sql_role_data_actions != role_data_actions
    ):
        return False

    if not _target_relationship_is_exact(
        path,
        assignment,
        context,
    ):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if path.get("role_kind") == "custom":
        role_definition = _resource_by_address(
            context,
            role_definition_address,
            expected_type=AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
        )
        if (
            role_definition is None
            or assignment_facts.resolved_cosmosdb_sql_role_definition_address != role_definition.address
            or azure_facts(role_definition).cosmosdb_sql_role_definition_data_actions != role_data_actions
        ):
            return False
    return True


def _target_relationship_is_exact(
    path: Mapping[str, Any],
    assignment: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    assignment_facts = azure_facts(assignment)
    scope_type = _known_string(path.get("scope_type"))
    target_address = _known_string(path.get("cosmosdb_resource_address"))
    account_address = _known_string(path.get("cosmosdb_account_address"))
    target = _resource_by_address(context, target_address)
    account = _resource_by_address(
        context,
        account_address,
        expected_type=AzureResourceType.COSMOSDB_ACCOUNT,
    )
    if (
        target is None
        or account is None
        or assignment_facts.resolved_cosmosdb_account_address != account.address
        or path.get("cosmosdb_account_id") != azure_facts(account).cosmosdb_account_id
        or path.get("cosmosdb_resource_type") != target.resource_type
        or path.get("cosmosdb_resource_id") != _cosmosdb_resource_id(target)
    ):
        return False

    database_address = _known_string(path.get("cosmosdb_database_address"))
    container_address = _known_string(path.get("cosmosdb_container_address"))
    if scope_type == "account":
        return (
            target.address == account.address
            and database_address is None
            and container_address is None
            and assignment_facts.resolved_cosmosdb_database_address is None
            and assignment_facts.resolved_cosmosdb_container_address is None
        )

    database = _resource_by_address(
        context,
        database_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_DATABASE,
    )
    if (
        database is None
        or azure_facts(database).resolved_cosmosdb_account_address != account.address
        or assignment_facts.resolved_cosmosdb_database_address != database.address
        or path.get("cosmosdb_database_id") != azure_facts(database).cosmosdb_sql_database_id
        or path.get("cosmosdb_database_name") != azure_facts(database).cosmosdb_sql_database_name
    ):
        return False
    if scope_type == "database":
        return (
            target.address == database.address
            and container_address is None
            and assignment_facts.resolved_cosmosdb_container_address is None
        )

    container = _resource_by_address(
        context,
        container_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_CONTAINER,
    )
    return bool(
        scope_type == "container"
        and container is not None
        and target.address == container.address
        and azure_facts(container).resolved_cosmosdb_account_address == account.address
        and azure_facts(container).resolved_cosmosdb_database_address == database.address
        and assignment_facts.resolved_cosmosdb_container_address == container.address
        and path.get("cosmosdb_container_id") == azure_facts(container).cosmosdb_sql_container_id
        and path.get("cosmosdb_container_name") == azure_facts(container).cosmosdb_sql_container_name
    )


def _path_mutation_operations(path: Mapping[str, Any]) -> list[str]:
    access_classes = set(_string_values(path.get("access_classes")))
    role_data_actions = _string_values(path.get("role_data_actions"))
    operations: set[str] = set()
    for matched_action in _string_values(path.get("matched_data_actions")):
        normalized = matched_action.strip().casefold()
        action_operations = _MUTATION_ACTION_OPERATIONS.get(normalized)
        required_class = "entity_delete" if normalized.endswith("/delete") else "entity_write"
        if (
            action_operations is None
            or required_class not in access_classes
            or not _role_actions_allow_action(role_data_actions, normalized)
        ):
            continue
        operations.update(action_operations)
    return [operation for operation in _MUTATION_OPERATION_ORDER if operation in operations]


def _role_actions_allow_action(
    role_data_actions: list[str],
    normalized_action: str,
) -> bool:
    return any(
        (normalized := action.strip().casefold()) == normalized_action or normalized == _ITEM_WILDCARD
        for action in role_data_actions
    )


def _mutation_operations(paths: list[dict[str, Any]]) -> list[str]:
    operations = {operation for path in paths for operation in _path_mutation_operations(path)}
    return [operation for operation in _MUTATION_OPERATION_ORDER if operation in operations]


def _scope_types(paths: list[dict[str, Any]]) -> list[str]:
    values = {value for path in paths if (value := _known_string(path.get("scope_type"))) in _SCOPE_CONTRACTS}
    return [scope_type for scope_type in ("account", "database", "container") if scope_type in values]


def _mutation_rationale(
    app: NormalizedResource,
    operations: list[str],
    scope_types: list[str],
    target_count: int,
    *,
    has_read_access: bool,
) -> str:
    rationale = (
        f"{app.display_name} has public network access explicitly enabled and its "
        "runtime managed identity has deterministic Azure Cosmos DB for NoSQL native "
        f"RBAC grants for item {', '.join(operations)} operations across "
        f"{target_count} exact modeled target(s). A compromise through an allowed "
        "public application path could mutate items using the workload identity. "
        f"{_scope_impact(scope_types)} "
        "This does not mean that the Cosmos DB for NoSQL account, database, or "
        "container is itself public; Cosmos DB network controls and configured App "
        "Service access restrictions are independent controls."
    )
    if not has_read_access:
        rationale += " The modeled mutation grants do not establish item read access or information disclosure."
    return rationale


def _scope_impact(scope_types: list[str]) -> str:
    if "account" in scope_types:
        return "At least one account-scoped grant can reach databases and containers throughout the modeled account."
    if "database" in scope_types:
        return "The broadest modeled grant is database-scoped and can reach containers within that exact database."
    return "The modeled grants are limited to exact container scopes."


def _public_endpoint_evidence(app: NormalizedResource) -> list[str]:
    facts = azure_facts(app)
    return [
        f"address={app.address}",
        f"type={app.resource_type}",
        "public_network_access_enabled=true",
        (f"public_network_fallback_state={facts.public_network_fallback_state or 'unknown'}"),
        (f"ip_restriction_default_action={facts.app_service_ip_restriction_default_action or 'not_configured'}"),
        f"ip_restriction_count={len(facts.app_service_access_restrictions)}",
    ]


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path['identity_address']}",
                    f"identity_kind={path['identity_kind']}",
                    f"principal_id={path['principal_id']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path['cosmosdb_resource_address']}",
                    f"target_type={path['cosmosdb_resource_type']}",
                    f"target_id={path.get('cosmosdb_resource_id') or 'unknown'}",
                    f"account_address={path['cosmosdb_account_address']}",
                    (f"database_address={path.get('cosmosdb_database_address') or 'not_applicable'}"),
                    (f"container_address={path.get('cosmosdb_container_address') or 'not_applicable'}"),
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    (f"mutation_operations={','.join(_path_mutation_operations(path))}"),
                    (f"matched_data_actions={','.join(_mutation_data_actions(path))}"),
                    f"scope_type={path['scope_type']}",
                    f"assignment_scope={path['assignment_scope']}",
                    f"resource_scope={path['resource_scope']}",
                    "assignment_scope_state=resolved",
                    "assignable_scope_compatibility_state=resolved",
                    "access_state=granted",
                    "authorization_model=cosmosdb_for_nosql_native_rbac",
                )
            )
            for path in paths
        }
    )


def _mutation_data_actions(path: Mapping[str, Any]) -> list[str]:
    return [
        action
        for action in _string_values(path.get("matched_data_actions"))
        if action.strip().casefold() in _MUTATION_ACTION_OPERATIONS
    ]


def _scope_breadth_evidence(paths: list[dict[str, Any]]) -> list[str]:
    counts = {
        scope_type: sum(path.get("scope_type") == scope_type for path in paths)
        for scope_type in ("account", "database", "container")
    }
    broadest = next(scope_type for scope_type in ("account", "database", "container") if counts[scope_type])
    return [
        "; ".join(
            (
                f"account_scoped_grants={counts['account']}",
                f"database_scoped_grants={counts['database']}",
                f"container_scoped_grants={counts['container']}",
                f"broadest_scope={broadest}",
                f"blast_radius_factor={_SCOPE_BLAST_RADIUS[broadest]}",
            )
        )
    ]


def _custom_role_action_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"role_definition_address={path['role_definition_address']}",
                    (f"role_data_actions={','.join(_string_values(path.get('role_data_actions')))}"),
                    (f"matched_mutation_actions={','.join(_mutation_data_actions(path))}"),
                )
            )
            for path in paths
            if path.get("role_kind") == "custom"
        }
    )


def _resource_by_address(
    context: RuleEvaluationContext,
    address: object,
    *,
    expected_type: str | None = None,
    expected_types: tuple[str, ...] = (),
) -> NormalizedResource | None:
    if not isinstance(address, str) or not address:
        return None
    resource = context.inventory.get_by_address(address)
    if resource is None:
        return None
    allowed_types = expected_types or ((expected_type,) if expected_type is not None else ())
    if allowed_types and resource.resource_type not in allowed_types:
        return None
    return resource


def _cosmosdb_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return facts.cosmosdb_account_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return facts.cosmosdb_sql_database_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return facts.cosmosdb_sql_container_id
    return None


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().casefold() == right.strip().casefold())
