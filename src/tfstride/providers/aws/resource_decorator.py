from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.aws.resource_decoration_stages import (
    AwsDecorationStage,
    default_aws_decoration_stages,
)
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder
from tfstride.providers.decoration import ResourceDecorationRunner


class AwsResourceDecorator(ResourceDecorationRunner[AwsDecorationContext]):
    def __init__(
        self,
        *,
        index_builder: AwsResourceIndexBuilder | None = None,
        stages: Sequence[AwsDecorationStage] | None = None,
    ) -> None:
        index_builder = index_builder or AwsResourceIndexBuilder()
        super().__init__(
            context_factory=lambda resources: AwsDecorationContext(index=index_builder.build(resources)),
            stages=stages if stages is not None else default_aws_decoration_stages(),
        )
