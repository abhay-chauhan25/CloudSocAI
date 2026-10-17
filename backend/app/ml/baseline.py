"""A synthetic baseline of normal AWS activity, regenerated from a seed.

The anomaly model needs many examples of normal behaviour, and CloudSOC's
own history is a few dozen events. So normal hours are generated from four
profiles that describe how real accounts are commonly used. The same seed
always produces the same events, so the model and its threshold are
reproducible without storing a dataset or a trained model file.

The profiles are assumptions, not measurements. A production system would
learn from weeks of the account's own history instead.
"""

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from app.schemas.event import Event, PrincipalType

BASELINE_START = datetime(2026, 9, 1, tzinfo=UTC)

# (service, action, read_only)
Action = tuple[str, str, bool]

DEVELOPER_READS: tuple[Action, ...] = (
    ("s3", "ListBuckets", True),
    ("s3", "GetObject", True),
    ("s3", "ListObjectsV2", True),
    ("ec2", "DescribeInstances", True),
    ("ec2", "DescribeSecurityGroups", True),
    ("lambda", "ListFunctions", True),
    ("lambda", "GetFunction", True),
    ("logs", "FilterLogEvents", True),
    ("cloudwatch", "GetMetricData", True),
    ("sts", "GetCallerIdentity", True),
    ("iam", "GetUser", True),
)
DEVELOPER_WRITES: tuple[Action, ...] = (
    ("s3", "PutObject", False),
    ("ec2", "StartInstances", False),
    ("ec2", "StopInstances", False),
    ("lambda", "UpdateFunctionCode", False),
)
AUTOMATION_ACTIONS: tuple[Action, ...] = (
    ("s3", "PutObject", False),
    ("s3", "GetObject", True),
    ("ecr", "GetAuthorizationToken", True),
    ("ecr", "BatchGetImage", True),
    ("ecs", "UpdateService", False),
    ("ecs", "DescribeServices", True),
    ("lambda", "UpdateFunctionCode", False),
    ("cloudformation", "DescribeStacks", True),
    ("sts", "GetCallerIdentity", True),
)
ADMIN_READS: tuple[Action, ...] = (
    ("iam", "ListUsers", True),
    ("iam", "GetUser", True),
    ("iam", "ListRoles", True),
    ("iam", "ListAttachedUserPolicies", True),
    ("cloudtrail", "DescribeTrails", True),
    ("cloudtrail", "GetTrailStatus", True),
    ("config", "DescribeConfigRules", True),
    ("kms", "ListKeys", True),
    ("ec2", "DescribeInstances", True),
)
ADMIN_SECURITY_WRITES: tuple[Action, ...] = (
    ("iam", "CreateUser", False),
    ("iam", "AttachUserPolicy", False),
    ("iam", "CreateAccessKey", False),
    ("iam", "PutRolePolicy", False),
    ("iam", "UpdateAccessKey", False),
)
CONSOLE_READS: tuple[Action, ...] = (
    ("ec2", "DescribeInstances", True),
    ("s3", "ListBuckets", True),
    ("cloudwatch", "DescribeAlarms", True),
    ("billing", "GetBillingData", True),
)
CONSOLE_LOGIN: Action = ("signin", "ConsoleLogin", False)


@dataclass(frozen=True)
class Profile:
    name: str
    weight: float  # share of all baseline hours


PROFILES = (
    Profile("developer", 0.45),
    Profile("automation", 0.30),
    Profile("admin", 0.15),
    Profile("console", 0.10),
)


def generate_baseline(windows: int, seed: int) -> list[Event]:
    """Events for ``windows`` normal principal-hours, deterministic for a seed."""
    # Seeded on purpose: reproducibility matters here, unpredictability does not.
    rng = random.Random(seed)  # noqa: S311
    events: list[Event] = []
    for index in range(windows):
        profile = rng.choices(PROFILES, weights=[p.weight for p in PROFILES])[0]
        start = BASELINE_START + timedelta(hours=index)
        principal = f"{profile.name}-{rng.randrange(20)}"
        ips = [_ip(rng) for _ in range(1 if rng.random() < 0.9 else 2)]
        actions, failure_rate = _hour_of(profile.name, rng)
        for position, action in enumerate(actions):
            events.append(
                _event(
                    f"baseline-{seed}-{index}-{position}",
                    action,
                    principal,
                    start + timedelta(seconds=rng.randrange(3600)),
                    rng.choice(ips),
                    success=rng.random() >= failure_rate,
                )
            )
    return events


def _hour_of(profile: str, rng: random.Random) -> tuple[list[Action], float]:
    """The actions in one normal hour for a profile, and its per-call failure rate."""
    if profile == "developer":
        count = rng.randint(1, 40)
        actions = [
            rng.choice(DEVELOPER_WRITES if rng.random() < 0.15 else DEVELOPER_READS)
            for _ in range(count)
        ]
        return actions, 0.03
    if profile == "automation":
        # Pipelines repeat a small fixed set of calls, often many times.
        routine = rng.sample(AUTOMATION_ACTIONS, rng.randint(2, 5))
        return [rng.choice(routine) for _ in range(rng.randint(5, 120))], 0.01
    if profile == "admin":
        actions = [rng.choice(ADMIN_READS) for _ in range(rng.randint(1, 25))]
        if rng.random() < 0.35:
            actions += rng.sample(ADMIN_SECURITY_WRITES, rng.randint(1, 2))
        return actions, 0.03
    reads = [rng.choice(CONSOLE_READS) for _ in range(rng.randint(0, 11))]
    return [CONSOLE_LOGIN, *reads], 0.05


def _ip(rng: random.Random) -> IPv4Address:
    # RFC 5737 documentation ranges only.
    network = rng.choice(("192.0.2", "198.51.100", "203.0.113"))
    return IPv4Address(f"{network}.{rng.randint(1, 254)}")


def _event(
    event_id: str,
    action: Action,
    principal: str,
    timestamp: datetime,
    ip: IPv4Address,
    *,
    success: bool,
) -> Event:
    service, event_name, read_only = action
    return Event(
        event_id=event_id,
        source="cloudtrail",
        timestamp=timestamp,
        account_id="123456789012",
        service=service,
        event_name=event_name,
        event_type="AwsConsoleSignIn" if service == "signin" else "AwsApiCall",
        read_only=read_only,
        region="us-east-1",
        principal_type=PrincipalType.IAM_USER,
        principal=principal,
        principal_arn=f"arn:aws:iam::123456789012:user/{principal}",
        session_name=None,
        access_key_id=None,
        mfa_authenticated=None,
        source_address=str(ip),
        source_ip=ip,
        user_agent="baseline",
        success=success,
        error_code=None if success else "AccessDenied",
        error_message=None,
        request_parameters=None,
        raw_event={},
    )
