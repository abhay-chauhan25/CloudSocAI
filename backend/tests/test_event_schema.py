"""The Event schema enforces immutability, strict field names, and UTC timestamps."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.event import Event, PrincipalType


def event_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "source": "cloudtrail",
        "timestamp": "2026-10-05T09:00:00Z",
        "account_id": "123456789012",
        "service": "iam",
        "event_name": "ListUsers",
        "event_type": "AwsApiCall",
        "read_only": True,
        "region": "us-east-1",
        "principal_type": PrincipalType.IAM_USER,
        "principal": "developer",
        "principal_arn": "arn:aws:iam::123456789012:user/developer",
        "session_name": None,
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "mfa_authenticated": None,
        "source_address": "198.51.100.23",
        "source_ip": "198.51.100.23",
        "user_agent": "aws-cli/2.17.0",
        "success": True,
        "error_code": None,
        "error_message": None,
        "request_parameters": None,
        "raw_event": {},
    }
    fields.update(overrides)
    return fields


def test_valid_event_is_created() -> None:
    event = Event(**event_fields())

    assert event.timestamp == datetime(2026, 10, 5, 9, 0, tzinfo=UTC)
    assert str(event.source_ip) == "198.51.100.23"


def test_event_is_immutable() -> None:
    event = Event(**event_fields())

    with pytest.raises(ValidationError, match="frozen"):
        event.event_name = "DeleteTrail"


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="extra"):
        Event(**event_fields(evnt_name="typo"))


def test_naive_timestamp_is_rejected() -> None:
    # A timestamp without a timezone is ambiguous; correlation windows would be wrong.
    with pytest.raises(ValidationError, match="timezone"):
        Event(**event_fields(timestamp="2026-10-05T09:00:00"))


def test_timestamp_with_offset_is_converted_to_utc() -> None:
    event = Event(**event_fields(timestamp="2026-10-05T11:00:00+02:00"))

    assert event.timestamp == datetime(2026, 10, 5, 9, 0, tzinfo=UTC)
    assert event.timestamp.tzinfo == UTC


def test_empty_event_id_is_rejected() -> None:
    with pytest.raises(ValidationError, match="event_id"):
        Event(**event_fields(event_id=""))


def test_invalid_source_ip_is_rejected() -> None:
    with pytest.raises(ValidationError, match="source_ip"):
        Event(**event_fields(source_ip="not-an-ip"))
