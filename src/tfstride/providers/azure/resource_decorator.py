from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.resource_decoration_stages import (
    AzureDecorationStage,
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.decoration import ResourceDecorationRunner


class AzureResourceDecorator(ResourceDecorationRunner[AzureDecorationContext]):
    """Run ordered Azure storage, network, and compute relationship stages."""

    def __init__(
        self,
        *,
        index_builder: AzureResourceIndexBuilder | None = None,
        stages: Sequence[AzureDecorationStage] | None = None,
    ) -> None:
        index_builder = index_builder or AzureResourceIndexBuilder()
        super().__init__(
            context_factory=lambda resources: AzureDecorationContext(index=index_builder.build(resources)),
            stages=stages if stages is not None else default_azure_decoration_stages(),
        )
