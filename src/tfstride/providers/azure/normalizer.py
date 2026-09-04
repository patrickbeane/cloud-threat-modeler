from __future__ import annotations

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.azure.aks_normalizers import normalize_kubernetes_cluster
from tfstride.providers.azure.app_service_normalizers import (
    normalize_function_app,
    normalize_linux_function_app,
    normalize_linux_web_app,
    normalize_windows_function_app,
    normalize_windows_web_app,
)
from tfstride.providers.azure.audit_normalizers import (
    normalize_advanced_threat_protection,
    normalize_monitor_diagnostic_setting,
    normalize_security_center_auto_provisioning,
    normalize_security_center_contact,
    normalize_security_center_setting,
    normalize_security_center_subscription_pricing,
    normalize_security_center_workspace,
)
from tfstride.providers.azure.compute_normalizers import (
    normalize_linux_virtual_machine,
    normalize_windows_virtual_machine,
)
from tfstride.providers.azure.container_registry_normalizers import normalize_container_registry
from tfstride.providers.azure.cosmosdb_normalizers import normalize_cosmosdb_account
from tfstride.providers.azure.cosmosdb_nosql_normalizers import (
    normalize_cosmosdb_sql_container,
    normalize_cosmosdb_sql_database,
    normalize_cosmosdb_sql_role_assignment,
    normalize_cosmosdb_sql_role_definition,
)
from tfstride.providers.azure.data_normalizers import (
    normalize_storage_account,
    normalize_storage_account_network_rules,
    normalize_storage_container,
)
from tfstride.providers.azure.identity_normalizers import (
    normalize_federated_identity_credential,
    normalize_role_assignment,
    normalize_role_definition,
    normalize_user_assigned_identity,
)
from tfstride.providers.azure.key_vault_normalizers import (
    normalize_key_vault,
    normalize_key_vault_access_policy,
    normalize_key_vault_certificate,
    normalize_key_vault_key,
    normalize_key_vault_secret,
)
from tfstride.providers.azure.management_lock_normalizers import normalize_management_lock
from tfstride.providers.azure.mssql_normalizers import (
    normalize_mssql_database,
    normalize_mssql_firewall_rule,
    normalize_mssql_server,
    normalize_mssql_server_security_alert_policy,
    normalize_mssql_virtual_network_rule,
)
from tfstride.providers.azure.network_normalizers import (
    normalize_application_gateway,
    normalize_load_balancer,
    normalize_network_interface,
    normalize_network_interface_security_group_association,
    normalize_network_security_group,
    normalize_network_security_rule,
    normalize_network_watcher_flow_log,
    normalize_private_dns_zone,
    normalize_private_dns_zone_virtual_network_link,
    normalize_private_endpoint,
    normalize_public_ip,
    normalize_subnet,
    normalize_subnet_network_security_group_association,
    normalize_virtual_network,
)
from tfstride.providers.azure.postgresql_normalizers import (
    normalize_postgresql_flexible_server,
    normalize_postgresql_flexible_server_configuration,
    normalize_postgresql_flexible_server_database,
    normalize_postgresql_flexible_server_firewall_rule,
)
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.service_bus_entity_normalizers import (
    normalize_servicebus_queue,
    normalize_servicebus_subscription,
    normalize_servicebus_topic,
)
from tfstride.providers.azure.service_bus_normalizers import (
    normalize_servicebus_namespace,
    normalize_servicebus_namespace_customer_managed_key,
    normalize_servicebus_namespace_network_rule_set,
)
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.normalization import ResourceNormalizer, normalize_provider_inventory

_AZURE_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    AzureResourceType.STORAGE_ACCOUNT: normalize_storage_account,
    AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES: normalize_storage_account_network_rules,
    AzureResourceType.STORAGE_CONTAINER: normalize_storage_container,
    AzureResourceType.SERVICE_BUS_NAMESPACE: normalize_servicebus_namespace,
    AzureResourceType.SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET: normalize_servicebus_namespace_network_rule_set,
    AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY: normalize_servicebus_namespace_customer_managed_key,
    AzureResourceType.SERVICE_BUS_QUEUE: normalize_servicebus_queue,
    AzureResourceType.SERVICE_BUS_TOPIC: normalize_servicebus_topic,
    AzureResourceType.SERVICE_BUS_SUBSCRIPTION: normalize_servicebus_subscription,
    AzureResourceType.COSMOSDB_ACCOUNT: normalize_cosmosdb_account,
    AzureResourceType.COSMOSDB_SQL_DATABASE: normalize_cosmosdb_sql_database,
    AzureResourceType.COSMOSDB_SQL_CONTAINER: normalize_cosmosdb_sql_container,
    AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION: normalize_cosmosdb_sql_role_definition,
    AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT: normalize_cosmosdb_sql_role_assignment,
    AzureResourceType.CONTAINER_REGISTRY: normalize_container_registry,
    AzureResourceType.KEY_VAULT: normalize_key_vault,
    AzureResourceType.KEY_VAULT_ACCESS_POLICY: normalize_key_vault_access_policy,
    AzureResourceType.KEY_VAULT_SECRET: normalize_key_vault_secret,
    AzureResourceType.KEY_VAULT_KEY: normalize_key_vault_key,
    AzureResourceType.KEY_VAULT_CERTIFICATE: normalize_key_vault_certificate,
    AzureResourceType.ROLE_ASSIGNMENT: normalize_role_assignment,
    AzureResourceType.ROLE_DEFINITION: normalize_role_definition,
    AzureResourceType.MANAGEMENT_LOCK: normalize_management_lock,
    AzureResourceType.USER_ASSIGNED_IDENTITY: normalize_user_assigned_identity,
    AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL: normalize_federated_identity_credential,
    AzureResourceType.VIRTUAL_NETWORK: normalize_virtual_network,
    AzureResourceType.SUBNET: normalize_subnet,
    AzureResourceType.NETWORK_SECURITY_GROUP: normalize_network_security_group,
    AzureResourceType.NETWORK_SECURITY_RULE: normalize_network_security_rule,
    AzureResourceType.NETWORK_WATCHER_FLOW_LOG: normalize_network_watcher_flow_log,
    AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION: normalize_subnet_network_security_group_association,
    AzureResourceType.NETWORK_INTERFACE: normalize_network_interface,
    AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION: (
        normalize_network_interface_security_group_association
    ),
    AzureResourceType.PUBLIC_IP: normalize_public_ip,
    AzureResourceType.LOAD_BALANCER: normalize_load_balancer,
    AzureResourceType.APPLICATION_GATEWAY: normalize_application_gateway,
    AzureResourceType.PRIVATE_ENDPOINT: normalize_private_endpoint,
    AzureResourceType.PRIVATE_DNS_ZONE: normalize_private_dns_zone,
    AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK: normalize_private_dns_zone_virtual_network_link,
    AzureResourceType.LINUX_WEB_APP: normalize_linux_web_app,
    AzureResourceType.WINDOWS_WEB_APP: normalize_windows_web_app,
    AzureResourceType.FUNCTION_APP: normalize_function_app,
    AzureResourceType.LINUX_FUNCTION_APP: normalize_linux_function_app,
    AzureResourceType.WINDOWS_FUNCTION_APP: normalize_windows_function_app,
    AzureResourceType.KUBERNETES_CLUSTER: normalize_kubernetes_cluster,
    AzureResourceType.LINUX_VIRTUAL_MACHINE: normalize_linux_virtual_machine,
    AzureResourceType.WINDOWS_VIRTUAL_MACHINE: normalize_windows_virtual_machine,
    AzureResourceType.MSSQL_SERVER: normalize_mssql_server,
    AzureResourceType.MSSQL_DATABASE: normalize_mssql_database,
    AzureResourceType.MSSQL_FIREWALL_RULE: normalize_mssql_firewall_rule,
    AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE: normalize_mssql_virtual_network_rule,
    AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY: normalize_mssql_server_security_alert_policy,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER: normalize_postgresql_flexible_server,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_DATABASE: normalize_postgresql_flexible_server_database,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE: normalize_postgresql_flexible_server_firewall_rule,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION: normalize_postgresql_flexible_server_configuration,
    AzureResourceType.MONITOR_DIAGNOSTIC_SETTING: normalize_monitor_diagnostic_setting,
    AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING: normalize_security_center_subscription_pricing,
    AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING: normalize_security_center_auto_provisioning,
    AzureResourceType.SECURITY_CENTER_CONTACT: normalize_security_center_contact,
    AzureResourceType.SECURITY_CENTER_WORKSPACE: normalize_security_center_workspace,
    AzureResourceType.SECURITY_CENTER_SETTING: normalize_security_center_setting,
    AzureResourceType.ADVANCED_THREAT_PROTECTION: normalize_advanced_threat_protection,
}
SUPPORTED_AZURE_TYPES = frozenset(_AZURE_RESOURCE_NORMALIZERS)


class AzureNormalizer(ProviderNormalizer):
    """Normalize supported AzureRM data, identity, network, compute, AKS, and app resources."""

    provider = "azure"

    def __init__(self, resource_decorator: AzureResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AzureResourceDecorator()
        self._resource_normalizers = dict(_AZURE_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_azure_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        return normalize_provider_inventory(
            resources,
            provider=self.provider,
            owns_resource=self.owns_resource,
            resource_normalizers=self._resource_normalizers,
            decorate_resources=self._resource_decorator.decorate,
        )


def _is_azure_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/azurerm") or resource.resource_type.startswith(AzureResourceType.PREFIX)
