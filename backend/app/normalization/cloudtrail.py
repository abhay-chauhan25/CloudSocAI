"""Convert raw CloudTrail records into normalized Events.

Raw records are untrusted: fields can be missing, have the wrong type, or
vary between event versions and APIs. Every field read here is checked, and
any problem raises ``NormalizationError`` with a specific reason.

When normalizing a batch, a bad record never stops the batch and is never
dropped silently: it is reported in ``NormalizationResult.errors`` with its
position and event ID, so the caller can log or surface it.
"""

import ipaddress
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.collectors.cloudtrail_file import RawRecord
from app.schemas.event import Event, PrincipalType

AWS_SERVICE_SUFFIX = ".amazonaws.com"


class NormalizationError(ValueError):
    """A raw record could not be converted into an Event."""


@dataclass(frozen=True)
class RecordError:
    """Why one record in a batch failed to normalize."""

    index: int
    event_id: str | None
    reason: str


@dataclass(frozen=True)
class NormalizationResult:
    events: list[Event]
    errors: list[RecordError]


def normalize_cloudtrail_records(records: list[RawRecord]) -> NormalizationResult:
    """Normalize a batch, collecting per-record failures instead of aborting."""
    events: list[Event] = []
    errors: list[RecordError] = []
    for index, record in enumerate(records):
        try:
            events.append(normalize_cloudtrail_record(record))
        except NormalizationError as exc:
            raw_id = record.get("eventID")
            event_id = raw_id if isinstance(raw_id, str) and raw_id else None
            errors.append(RecordError(index=index, event_id=event_id, reason=str(exc)))
    return NormalizationResult(events=events, errors=errors)


def normalize_cloudtrail_record(record: RawRecord) -> Event:
    """Convert one raw CloudTrail record into an Event."""
    event_name = _required_str(record, "eventName")
    identity = _required_dict(record, "userIdentity")
    source_address = _optional_str(record, "sourceIPAddress")
    success, error_code, error_message = _outcome(record, event_name)

    try:
        return Event(
            event_id=_required_str(record, "eventID"),
            source="cloudtrail",
            timestamp=_required_str(record, "eventTime"),
            account_id=_optional_str(record, "recipientAccountId"),
            service=_service_name(_required_str(record, "eventSource")),
            event_name=event_name,
            event_type=_optional_str(record, "eventType"),
            read_only=_optional_bool(record, "readOnly"),
            region=_required_str(record, "awsRegion"),
            **_identity_fields(identity),
            mfa_authenticated=_mfa_authenticated(record, identity, event_name),
            source_address=source_address,
            source_ip=_parse_ip(source_address),
            user_agent=_optional_str(record, "userAgent"),
            success=success,
            error_code=error_code,
            error_message=error_message,
            request_parameters=_optional_dict(record, "requestParameters"),
            raw_event=record,
        )
    except ValidationError as exc:
        raise NormalizationError(_summarize_validation_error(exc)) from exc


# --- service / region / source (Task 18) ---------------------------------------


def _service_name(event_source: str) -> str:
    """'iam.amazonaws.com' -> 'iam'. Unexpected formats are kept, not guessed at."""
    if event_source.endswith(AWS_SERVICE_SUFFIX):
        return event_source.removesuffix(AWS_SERVICE_SUFFIX)
    return event_source


def _parse_ip(source_address: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    # sourceIPAddress may hold a service name ("lambda.amazonaws.com") or
    # "AWS Internal" instead of an IP; those are kept in source_address only.
    if source_address is None:
        return None
    try:
        return ipaddress.ip_address(source_address)
    except ValueError:
        return None


# --- identity (Task 17) --------------------------------------------------------


def _identity_fields(identity: dict[str, Any]) -> dict[str, Any]:
    """Map CloudTrail's userIdentity variants onto one consistent set of fields."""
    principal_type = _principal_type(identity.get("type"))
    arn = _optional_str(identity, "arn")
    session_context = _optional_dict(identity, "sessionContext") or {}
    session_issuer = _optional_dict(session_context, "sessionIssuer") or {}

    principal: str | None
    principal_arn = arn
    session_name: str | None = None

    match principal_type:
        case PrincipalType.ROOT:
            principal = "root"
        case PrincipalType.IAM_USER:
            principal = _optional_str(identity, "userName")
        case PrincipalType.ASSUMED_ROLE:
            # The session ARN changes per session; the role ARN in sessionIssuer
            # is the stable identity that correlation and baselines need.
            principal = _optional_str(session_issuer, "userName")
            principal_arn = _optional_str(session_issuer, "arn") or arn
            session_name = arn.rsplit("/", 1)[-1] if arn and arn.count("/") >= 2 else None
        case PrincipalType.FEDERATED_USER:
            principal = arn.rsplit("/", 1)[-1] if arn else None
        case PrincipalType.AWS_SERVICE:
            principal = _optional_str(identity, "invokedBy")
        case PrincipalType.AWS_ACCOUNT:
            principal = _optional_str(identity, "accountId")
        case PrincipalType.UNKNOWN:
            principal = _optional_str(identity, "userName") or arn

    return {
        "principal_type": principal_type,
        "principal": principal,
        "principal_arn": principal_arn,
        "session_name": session_name,
        "access_key_id": _optional_str(identity, "accessKeyId") or None,  # root sign-in uses ""
    }


def _principal_type(raw_type: Any) -> PrincipalType:
    try:
        return PrincipalType(raw_type)
    except ValueError:
        return PrincipalType.UNKNOWN


def _mfa_authenticated(record: RawRecord, identity: dict[str, Any], event_name: str) -> bool | None:
    # Console sign-ins record MFA in additionalEventData; API calls made with a
    # session record it in sessionContext. Absent means "unknown", not "no".
    if event_name == "ConsoleLogin":
        extra = _optional_dict(record, "additionalEventData") or {}
        return _yes_no(_optional_str(extra, "MFAUsed"), true="Yes", false="No")

    session_context = _optional_dict(identity, "sessionContext") or {}
    attributes = _optional_dict(session_context, "attributes") or {}
    return _yes_no(_optional_str(attributes, "mfaAuthenticated"), true="true", false="false")


def _yes_no(value: str | None, *, true: str, false: str) -> bool | None:
    if value is None:
        return None
    if value == true:
        return True
    if value == false:
        return False
    raise NormalizationError(f"unexpected MFA value {value!r}")


# --- outcome (Task 19) ---------------------------------------------------------


def _outcome(record: RawRecord, event_name: str) -> tuple[bool, str | None, str | None]:
    """Return (success, error_code, error_message).

    API calls signal failure with errorCode. Failed console sign-ins are
    different: they have no errorCode, only responseElements.ConsoleLogin ==
    "Failure" plus an errorMessage.
    """
    error_code = _optional_str(record, "errorCode")
    error_message = _optional_str(record, "errorMessage")
    if error_code is not None:
        return False, error_code, error_message

    if event_name == "ConsoleLogin":
        response = _optional_dict(record, "responseElements") or {}
        if _optional_str(response, "ConsoleLogin") == "Failure":
            return False, None, error_message

    return True, None, error_message


# --- typed field access ----------------------------------------------------------


def _required_str(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if value is None or value == "":
        raise NormalizationError(f"missing required field {key!r}")
    if not isinstance(value, str):
        raise NormalizationError(f"field {key!r} must be a string, got {type(value).__name__}")
    return value


def _optional_str(mapping: dict[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    if value is not None and not isinstance(value, str):
        raise NormalizationError(f"field {key!r} must be a string, got {type(value).__name__}")
    return value


def _optional_bool(mapping: dict[str, Any], key: str) -> bool | None:
    value = mapping.get(key)
    if value is not None and not isinstance(value, bool):
        raise NormalizationError(f"field {key!r} must be a boolean, got {type(value).__name__}")
    return value


def _required_dict(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = _optional_dict(mapping, key)
    if value is None:
        raise NormalizationError(f"missing required field {key!r}")
    return value


def _optional_dict(mapping: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = mapping.get(key)
    if value is not None and not isinstance(value, dict):
        raise NormalizationError(f"field {key!r} must be an object, got {type(value).__name__}")
    return value


def _summarize_validation_error(exc: ValidationError) -> str:
    # Report field locations and messages only, not the offending input values,
    # which are attacker-influenced and may be very large.
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors()
    )
