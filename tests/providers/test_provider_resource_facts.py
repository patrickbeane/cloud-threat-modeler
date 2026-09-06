from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from typing import Any, ClassVar

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_facts import ProviderResourceFacts
from tfstride.resource_metadata import MetadataField, OptionalStringMetadataField, StringListMetadataField

_SCALAR_FIELD = OptionalStringMetadataField("test_scalar")
_LIST_FIELD = StringListMetadataField("test_values")


class _RejectedMetadataWrite(ValueError):
    pass


class _RecordingMetadataWriteValidator:
    def __init__(self, resource: NormalizedResource, *, reject: bool = False) -> None:
        self._resource = resource
        self._reject = reject
        self.fields: list[MetadataField[Any]] = []
        self.metadata_before_validation: list[dict[str, Any]] = []

    def validate(self, field: MetadataField[Any]) -> None:
        self.fields.append(field)
        self.metadata_before_validation.append(self._resource.metadata_snapshot())
        if self._reject:
            raise _RejectedMetadataWrite(field.key)


class _TestProviderResourceFacts(ProviderResourceFacts):
    __slots__ = ()

    _metadata_write_validator: ClassVar[_RecordingMetadataWriteValidator]


def _resource() -> NormalizedResource:
    return NormalizedResource(
        address="test_resource.app",
        provider="test",
        resource_type="test_resource",
        name="app",
        category=ResourceCategory.COMPUTE,
    )


def _facts(*, reject: bool = False) -> tuple[_TestProviderResourceFacts, _RecordingMetadataWriteValidator]:
    resource = _resource()
    validator = _RecordingMetadataWriteValidator(resource, reject=reject)
    _TestProviderResourceFacts._metadata_write_validator = validator
    return _TestProviderResourceFacts(resource), validator


class ProviderResourceFactsTests(unittest.TestCase):
    def test_resource_view_is_frozen_and_slotted(self) -> None:
        resource = _resource()
        validator = _RecordingMetadataWriteValidator(resource)
        _TestProviderResourceFacts._metadata_write_validator = validator
        facts = _TestProviderResourceFacts(resource)

        self.assertIs(facts.resource, resource)
        self.assertFalse(hasattr(facts, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            facts.resource = _resource()  # pyright: ignore[reportAttributeAccessIssue]

    def test_get_preserves_typed_defaults_without_validation(self) -> None:
        facts, validator = _facts()

        self.assertIsNone(facts.get(_SCALAR_FIELD))
        self.assertEqual(facts.get(_LIST_FIELD), [])
        self.assertEqual(validator.fields, [])

    def test_set_validates_before_writing(self) -> None:
        facts, validator = _facts()

        facts.set(_SCALAR_FIELD, "configured")

        self.assertEqual(validator.fields, [_SCALAR_FIELD])
        self.assertEqual(validator.metadata_before_validation, [{}])
        self.assertEqual(facts.get(_SCALAR_FIELD), "configured")

    def test_append_and_extend_validate_before_preserving_list_semantics(self) -> None:
        facts, validator = _facts()

        facts.append(_LIST_FIELD, "first")
        facts.append(_LIST_FIELD, None)
        facts.extend(_LIST_FIELD, ["second", "first", None, "third", "second"])

        self.assertEqual(validator.fields, [_LIST_FIELD, _LIST_FIELD, _LIST_FIELD])
        self.assertEqual(
            validator.metadata_before_validation,
            [
                {},
                {"test_values": ["first"]},
                {"test_values": ["first"]},
            ],
        )
        self.assertEqual(facts.get(_LIST_FIELD), ["first", "second", "third"])

    def test_rejected_writes_do_not_mutate_resource(self) -> None:
        for operation in ("set", "append", "extend"):
            with self.subTest(operation=operation):
                facts, validator = _facts(reject=True)
                metadata_before = facts.resource.metadata_snapshot()

                with self.assertRaises(_RejectedMetadataWrite):
                    if operation == "set":
                        facts.set(_SCALAR_FIELD, "blocked")
                    elif operation == "append":
                        facts.append(_LIST_FIELD, "blocked")
                    else:
                        facts.extend(_LIST_FIELD, ["blocked"])

                self.assertEqual(facts.resource.metadata_snapshot(), metadata_before)
                self.assertEqual(len(validator.fields), 1)


if __name__ == "__main__":
    unittest.main()
