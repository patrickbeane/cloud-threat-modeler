from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, TypeVar

from tfstride.models import NormalizedResource
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")


class _MetadataWriteValidator(Protocol):
    def validate(self, field: MetadataField[Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class ProviderResourceFacts:
    """Provider-neutral typed access to normalized resource metadata."""

    resource: NormalizedResource
    _metadata_write_validator: ClassVar[_MetadataWriteValidator]

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        self._metadata_write_validator.validate(field)
        self.resource.set_metadata_field(field, value)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        self._metadata_write_validator.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        self._metadata_write_validator.validate(field)
        self.resource.extend_metadata_field(field, values)


__all__ = ["ProviderResourceFacts"]
