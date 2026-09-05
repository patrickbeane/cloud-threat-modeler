from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.decoration import ResourceDecorationRunner
from tfstride.providers.gcp.resource_decoration_stages import (
    GcpDecorationStage,
    default_gcp_decoration_stages,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder


class GcpResourceDecorator(ResourceDecorationRunner[GcpDecorationContext]):
    """Run ordered GCP resource decoration stages."""

    def __init__(
        self,
        *,
        index_builder: GcpResourceIndexBuilder | None = None,
        stages: Sequence[GcpDecorationStage] | None = None,
    ) -> None:
        index_builder = index_builder or GcpResourceIndexBuilder()
        super().__init__(
            context_factory=lambda resources: GcpDecorationContext(index=index_builder.build(resources)),
            stages=stages if stages is not None else default_gcp_decoration_stages(),
        )
