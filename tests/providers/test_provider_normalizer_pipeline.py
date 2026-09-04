from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from tfstride.models import (
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.resource_metadata import InventoryMetadata

_AWS_SUPPORTED_TYPE = "aws_s3_bucket"
_GCP_SUPPORTED_TYPE = "google_storage_bucket"
_AZURE_SUPPORTED_TYPE = "azurerm_storage_account"
_AWS_ACCOUNT_ID = "111122223333"
_DECORATION_MARKER = "arn:test:decorated"

_ResourceNormalizer = Callable[[TerraformResource], NormalizedResource]


class _RecordingDecorator:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.addresses: tuple[str, ...] = ()
        self.provider_config_keys: tuple[str | None, ...] = ()
        self.reference_resolutions: tuple[tuple[TerraformReferenceResolution, ...], ...] = ()

    def decorate(self, resources: list[NormalizedResource]) -> None:
        self.addresses = tuple(resource.address for resource in resources)
        self.provider_config_keys = tuple(resource.provider_config_key for resource in resources)
        self.reference_resolutions = tuple(resource.reference_resolutions for resource in resources)
        self._events.append(f"decorate:{','.join(self.addresses)}")
        for resource in resources:
            resource.add_attached_role_arn(_DECORATION_MARKER)


def _build_aws_normalizer(
    decorator: _RecordingDecorator,
    resource_normalizer: _ResourceNormalizer,
) -> ProviderNormalizer:
    normalizer = AwsNormalizer(resource_decorator=cast(AwsResourceDecorator, decorator))
    normalizer._resource_normalizers[_AWS_SUPPORTED_TYPE] = resource_normalizer
    return normalizer


def _build_gcp_normalizer(
    decorator: _RecordingDecorator,
    resource_normalizer: _ResourceNormalizer,
) -> ProviderNormalizer:
    normalizer = GcpNormalizer(resource_decorator=cast(GcpResourceDecorator, decorator))
    normalizer._resource_normalizers[_GCP_SUPPORTED_TYPE] = resource_normalizer
    return normalizer


def _build_azure_normalizer(
    decorator: _RecordingDecorator,
    resource_normalizer: _ResourceNormalizer,
) -> ProviderNormalizer:
    normalizer = AzureNormalizer(resource_decorator=cast(AzureResourceDecorator, decorator))
    normalizer._resource_normalizers[_AZURE_SUPPORTED_TYPE] = resource_normalizer
    return normalizer


_NormalizerFactory = Callable[[_RecordingDecorator, _ResourceNormalizer], ProviderNormalizer]


@dataclass(frozen=True, slots=True)
class _NormalizerCase:
    provider: str
    provider_name: str
    supported_type: str
    unsupported_type: str
    supported_types: frozenset[str]
    factory: _NormalizerFactory
    primary_account_id: str | None = None


_NORMALIZER_CASES = (
    _NormalizerCase(
        provider="aws",
        provider_name="registry.terraform.io/hashicorp/aws",
        supported_type=_AWS_SUPPORTED_TYPE,
        unsupported_type="aws_unmodeled_service",
        supported_types=frozenset(SUPPORTED_AWS_TYPES),
        factory=_build_aws_normalizer,
        primary_account_id=_AWS_ACCOUNT_ID,
    ),
    _NormalizerCase(
        provider="gcp",
        provider_name="registry.terraform.io/hashicorp/google",
        supported_type=_GCP_SUPPORTED_TYPE,
        unsupported_type="google_unmodeled_service",
        supported_types=frozenset(SUPPORTED_GCP_TYPES),
        factory=_build_gcp_normalizer,
    ),
    _NormalizerCase(
        provider="azure",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        supported_type=_AZURE_SUPPORTED_TYPE,
        unsupported_type="azurerm_unmodeled_service",
        supported_types=frozenset(SUPPORTED_AZURE_TYPES),
        factory=_build_azure_normalizer,
    ),
)


@dataclass(frozen=True, slots=True)
class _PipelineRun:
    inventory: ResourceInventory
    decorator: _RecordingDecorator
    events: tuple[str, ...]
    supported_sources: tuple[TerraformResource, TerraformResource]
    unsupported_addresses: tuple[str, str]


def _reference_resolution(name: str) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=("dependency_id",),
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(f"module.{name}.id",),
    )


def _terraform_resource(
    *,
    address: str,
    resource_type: str,
    provider_name: str,
    provider_config_key: str | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name=provider_name,
        values={},
        provider_config_key=provider_config_key,
        reference_resolutions=reference_resolutions,
    )


def _run_pipeline(case: _NormalizerCase) -> _PipelineRun:
    first = _terraform_resource(
        address=f"{case.supported_type}.zeta",
        resource_type=case.supported_type,
        provider_name=case.provider_name,
        provider_config_key=f"{case.provider}.zeta",
        reference_resolutions=(_reference_resolution("zeta"),),
    )
    second = _terraform_resource(
        address=f"{case.supported_type}.alpha",
        resource_type=case.supported_type,
        provider_name="registry.example.com/custom/provider",
        provider_config_key=f"{case.provider}.alpha",
        reference_resolutions=(_reference_resolution("alpha"),),
    )
    unsupported_zeta = _terraform_resource(
        address=f"{case.unsupported_type}.zeta",
        resource_type=case.unsupported_type,
        provider_name=case.provider_name,
    )
    unsupported_alpha = _terraform_resource(
        address=f"{case.unsupported_type}.alpha",
        resource_type=case.unsupported_type,
        provider_name=case.provider_name,
    )
    foreign = _terraform_resource(
        address="random_pet.foreign",
        resource_type="random_pet",
        provider_name="registry.terraform.io/hashicorp/random",
    )

    events: list[str] = []

    def normalize_resource(resource: TerraformResource) -> NormalizedResource:
        events.append(f"normalize:{resource.address}")
        arn = (
            f"arn:aws:iam::{case.primary_account_id}:role/{resource.name}"
            if case.primary_account_id is not None
            else None
        )
        return NormalizedResource(
            address=resource.address,
            provider=case.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=resource.address,
            arn=arn,
        )

    decorator = _RecordingDecorator(events)
    normalizer = case.factory(decorator, normalize_resource)
    inventory = normalizer.normalize([first, foreign, unsupported_zeta, second, unsupported_alpha])
    return _PipelineRun(
        inventory=inventory,
        decorator=decorator,
        events=tuple(events),
        supported_sources=(first, second),
        unsupported_addresses=(unsupported_alpha.address, unsupported_zeta.address),
    )


class ProviderNormalizerPipelineContractTests(unittest.TestCase):
    def test_pipeline_filters_orders_and_accounts_for_provider_resources(self) -> None:
        for case in _NORMALIZER_CASES:
            with self.subTest(provider=case.provider):
                run = _run_pipeline(case)
                supported_addresses = tuple(resource.address for resource in run.supported_sources)

                self.assertEqual(run.inventory.provider, case.provider)
                self.assertEqual(
                    tuple(resource.address for resource in run.inventory.resources),
                    supported_addresses,
                )
                self.assertEqual(
                    run.events,
                    (
                        f"normalize:{supported_addresses[0]}",
                        f"normalize:{supported_addresses[1]}",
                        f"decorate:{','.join(supported_addresses)}",
                    ),
                )
                self.assertEqual(run.inventory.unsupported_resources, list(run.unsupported_addresses))

    def test_pipeline_propagates_source_context_before_decoration_then_freezes(self) -> None:
        for case in _NORMALIZER_CASES:
            with self.subTest(provider=case.provider):
                run = _run_pipeline(case)
                expected_provider_config_keys = tuple(source.provider_config_key for source in run.supported_sources)
                expected_reference_resolutions = tuple(source.reference_resolutions for source in run.supported_sources)

                self.assertEqual(run.decorator.provider_config_keys, expected_provider_config_keys)
                self.assertEqual(run.decorator.reference_resolutions, expected_reference_resolutions)
                self.assertEqual(
                    tuple(resource.provider_config_key for resource in run.inventory.resources),
                    expected_provider_config_keys,
                )
                self.assertEqual(
                    tuple(resource.reference_resolutions for resource in run.inventory.resources),
                    expected_reference_resolutions,
                )
                for resource in run.inventory.resources:
                    self.assertEqual(resource.attached_role_arns, (_DECORATION_MARKER,))
                    with self.assertRaisesRegex(RuntimeError, "decoration state is frozen"):
                        resource.add_attached_role_arn("arn:test:late-decoration")

    def test_pipeline_emits_complete_inventory_metadata(self) -> None:
        for case in _NORMALIZER_CASES:
            with self.subTest(provider=case.provider):
                run = _run_pipeline(case)
                expected_metadata = {
                    InventoryMetadata.SUPPORTED_RESOURCE_TYPES.key: sorted(case.supported_types),
                    InventoryMetadata.TOTAL_INPUT_RESOURCES.key: 5,
                    InventoryMetadata.PROVIDER_RESOURCE_COUNT.key: 4,
                    InventoryMetadata.NORMALIZED_RESOURCE_COUNT.key: 2,
                    InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.key: {case.unsupported_type: 2},
                }
                if case.primary_account_id is not None:
                    expected_metadata[InventoryMetadata.PRIMARY_ACCOUNT_ID.key] = case.primary_account_id

                self.assertEqual(run.inventory.metadata_snapshot(), expected_metadata)


if __name__ == "__main__":
    unittest.main()
