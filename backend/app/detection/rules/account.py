"""Detections about how the account is accessed: root use and sign-in without MFA."""

from app.detection.base import SingleEventDetector, outcome_suffix
from app.schemas.event import Event, PrincipalType
from app.schemas.finding import Severity


class RootAccountUse(SingleEventDetector):
    detector_id = "root-account-use"
    name = "Root account used"
    description = "The account root user signed in or made an API call."
    rationale = (
        "The root user has unrestricted access that IAM policies cannot limit. AWS "
        "recommends using it only for the few tasks that require it (some billing and "
        "account settings), so any root activity deserves review. False positives: "
        "those rare legitimate tasks. Calls that an AWS service makes on root's behalf "
        "are excluded."
    )
    severity = Severity.HIGH
    mitre_techniques = ("T1078.004",)  # Valid Accounts: Cloud Accounts

    def matches(self, event: Event) -> bool:
        identity = event.raw_event.get("userIdentity", {})
        return (
            event.principal_type is PrincipalType.ROOT
            and event.event_type != "AwsServiceEvent"
            and "invokedBy" not in identity
        )

    def explain(self, event: Event) -> str:
        return (
            f"The root user called {event.event_name} ({event.service}) "
            f"from {event.source_address!r}{outcome_suffix(event)}."
        )


class ConsoleLoginWithoutMfa(SingleEventDetector):
    detector_id = "console-login-without-mfa"
    name = "Console sign-in without MFA"
    description = "A root or IAM user signed in to the AWS console without MFA."
    rationale = (
        "Without MFA a stolen or guessed password is enough to take over the identity. "
        "Root sign-in without MFA is rated higher. Federated and SSO sign-ins are "
        "excluded: their MFA happens at the identity provider, so CloudTrail records "
        "MFAUsed=No even when MFA was used — a classic false positive."
    )
    severity = Severity.MEDIUM
    mitre_techniques = ("T1078.004",)  # Valid Accounts: Cloud Accounts

    def matches(self, event: Event) -> bool:
        return (
            event.event_name == "ConsoleLogin"
            and event.success
            # "is False", not "not ...": None means the record does not say.
            and event.mfa_authenticated is False
            and event.principal_type in (PrincipalType.ROOT, PrincipalType.IAM_USER)
        )

    def explain(self, event: Event) -> str:
        return (
            f"{event.principal!r} signed in to the console without MFA "
            f"from {event.source_address!r}."
        )

    def severity_for(self, event: Event) -> Severity:
        return Severity.HIGH if event.principal_type is PrincipalType.ROOT else self.severity
