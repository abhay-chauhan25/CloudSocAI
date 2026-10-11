"""Detections about IAM changes: new users, new credentials, and admin privileges."""

from app.detection.base import SingleEventDetector, request_param
from app.schemas.event import Event, PrincipalType
from app.schemas.finding import Severity

ATTACH_POLICY_EVENTS = {
    "AttachUserPolicy": "userName",
    "AttachGroupPolicy": "groupName",
    "AttachRolePolicy": "roleName",
}


def is_aws_managed_administrator_access(policy_arn: str) -> bool:
    """True for AWS's AdministratorAccess policy in any partition (aws, aws-us-gov, ...).

    The account field of an AWS-managed policy ARN is "aws"; a customer policy
    that happens to be named AdministratorAccess has an account ID there.
    """
    parts = policy_arn.split(":")
    return (
        len(parts) == 6
        and parts[0] == "arn"
        and parts[2] == "iam"
        and parts[4] == "aws"
        and parts[5] == "policy/AdministratorAccess"
    )


class IamUserCreated(SingleEventDetector):
    detector_id = "iam-user-created"
    name = "IAM user created"
    description = "A new IAM user was created."
    rationale = (
        "Attackers create users as a persistence backdoor that survives a password or "
        "key reset of the identity they first compromised. Administrators also create "
        "users routinely, so on its own this is low severity; it matters most when "
        "combined with new credentials or privileges for the same user."
    )
    severity = Severity.LOW
    mitre_techniques = ("T1136.003",)  # Create Account: Cloud Account

    def matches(self, event: Event) -> bool:
        return event.service == "iam" and event.event_name == "CreateUser" and event.success

    def explain(self, event: Event) -> str:
        return f"{event.principal!r} created the IAM user {self.resource_for(event)!r}."

    def resource_for(self, event: Event) -> str | None:
        return request_param(event, "userName")


class AccessKeyCreated(SingleEventDetector):
    detector_id = "access-key-created"
    name = "Access key created"
    description = "A long-term access key was created for an IAM user or the root user."
    rationale = (
        "A new access key gives whoever holds it lasting API access, and creating one "
        "for another user is a common way to keep access after the original "
        "credentials are revoked. Keys for the root user are rated higher: AWS "
        "recommends root has none. False positives: planned key rotation."
    )
    severity = Severity.MEDIUM
    mitre_techniques = ("T1098.001",)  # Account Manipulation: Additional Cloud Credentials

    def matches(self, event: Event) -> bool:
        return event.service == "iam" and event.event_name == "CreateAccessKey" and event.success

    def explain(self, event: Event) -> str:
        target = request_param(event, "userName")
        if target is None:
            whose = "the root user" if self._is_root_key(event) else "themselves"
            return f"{event.principal!r} created an access key for {whose}."
        if target == event.principal:
            return f"{event.principal!r} created an access key for themselves."
        return f"{event.principal!r} created an access key for a different user, {target!r}."

    def severity_for(self, event: Event) -> Severity:
        return Severity.HIGH if self._is_root_key(event) else self.severity

    def resource_for(self, event: Event) -> str | None:
        # Without userName, the key belongs to the caller.
        return request_param(event, "userName") or event.principal

    @staticmethod
    def _is_root_key(event: Event) -> bool:
        return event.principal_type is PrincipalType.ROOT and not request_param(event, "userName")


class AdministratorAccessAttached(SingleEventDetector):
    detector_id = "admin-policy-attached"
    name = "AdministratorAccess policy attached"
    description = (
        "The AWS-managed AdministratorAccess policy was attached to a user, group, or role."
    )
    rationale = (
        "AdministratorAccess grants every action on every resource, so attaching it is "
        "the most direct form of privilege escalation. False positives: deliberate "
        "admin onboarding, which should be rare and reviewed. Not covered: inline "
        "policies or customer policies granting the same rights."
    )
    severity = Severity.HIGH
    mitre_techniques = ("T1098.003",)  # Account Manipulation: Additional Cloud Roles

    def matches(self, event: Event) -> bool:
        policy_arn = request_param(event, "policyArn")
        return (
            event.service == "iam"
            and event.event_name in ATTACH_POLICY_EVENTS
            and event.success
            and policy_arn is not None
            and is_aws_managed_administrator_access(policy_arn)
        )

    def explain(self, event: Event) -> str:
        return f"{event.principal!r} attached AdministratorAccess to {self.resource_for(event)}."

    def resource_for(self, event: Event) -> str | None:
        key = ATTACH_POLICY_EVENTS[event.event_name]
        name = request_param(event, key)
        kind = key.removesuffix("Name")
        return f"{kind} {name!r}" if name is not None else f"an unnamed {kind}"
