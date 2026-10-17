"""Identity posture: the root user and IAM users' credentials."""

from datetime import timedelta

from app.posture.base import PostureCheck, require
from app.posture.snapshot import CredentialReportRow, PostureSnapshot
from app.schemas.finding import Finding, Severity

MAX_ACCESS_KEY_AGE = timedelta(days=90)


def _root_arn(snapshot: PostureSnapshot) -> str:
    return f"arn:aws:iam::{snapshot.account_id}:root"


class RootMfaDisabled(PostureCheck):
    check_id = "root-mfa-disabled"
    name = "Root user has no MFA"
    description = "The account summary reports AccountMFAEnabled = 0."
    rationale = (
        "The root user can do anything, including closing the account, and cannot be "
        "restricted by IAM policies. With only a password protecting it, one phished or "
        "reused password is a full account takeover. There is no legitimate exception."
    )
    remediation = "Enable MFA on the root user, preferably a hardware security key."
    reference = "CIS AWS Foundations Benchmark: MFA enabled for the root user"
    severity = Severity.CRITICAL
    service = "iam"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        iam = require(snapshot.iam)
        if iam.account_summary.account_mfa_enabled:
            return []
        return [
            self.build_finding(
                snapshot,
                resource=_root_arn(snapshot),
                reason=f"Account {snapshot.account_id}: AccountMFAEnabled = 0.",
            )
        ]


class RootAccessKeysPresent(PostureCheck):
    check_id = "root-access-keys-present"
    name = "Root user has access keys"
    description = "The account summary reports AccountAccessKeysPresent > 0."
    rationale = (
        "Root access keys give unrestricted programmatic access, never expire, and are "
        "easily leaked through code or CI logs. Nothing requires them: every task that "
        "needs root can be done in the console."
    )
    remediation = "Delete the root user's access keys; use IAM roles for programmatic access."
    reference = "CIS AWS Foundations Benchmark: no root user access keys"
    severity = Severity.CRITICAL
    service = "iam"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        iam = require(snapshot.iam)
        count = iam.account_summary.account_access_keys_present
        if not count:
            return []
        return [
            self.build_finding(
                snapshot,
                resource=_root_arn(snapshot),
                reason=f"Account {snapshot.account_id}: AccountAccessKeysPresent = {count}.",
            )
        ]


class ConsoleUserWithoutMfa(PostureCheck):
    check_id = "iam-user-console-without-mfa"
    name = "IAM user can sign in without MFA"
    description = "A credential report row has password_enabled = true and mfa_active = false."
    rationale = (
        "A console password alone is phishable and often reused. Users who only use "
        "the API have no password and are not affected. Break-glass users are a "
        "common, deliberate exception, but should still have MFA."
    )
    remediation = "Require MFA for the user, or remove the console password if unused."
    reference = "CIS AWS Foundations Benchmark: MFA for all IAM users with a console password"
    severity = Severity.HIGH
    service = "iam"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        iam = require(snapshot.iam)
        return [
            self.build_finding(
                snapshot,
                resource=row.arn,
                reason=f"IAM user {row.user!r}: password_enabled = true, mfa_active = false.",
            )
            for row in iam.credential_report
            if not row.is_root and row.password_enabled and not row.mfa_active
        ]


class AccessKeyNotRotated(PostureCheck):
    check_id = "iam-access-key-not-rotated"
    name = "Active access key older than 90 days"
    description = "An active access key's last rotation is more than 90 days before the snapshot."
    rationale = (
        "The longer a long-term key lives, the more places it has been copied to and the "
        "longer a leaked copy keeps working. Rotation limits that window; replacing keys "
        "with roles removes it."
    )
    remediation = "Create a new key, switch callers to it, then deactivate and delete the old one."
    reference = "CIS AWS Foundations Benchmark: access keys rotated every 90 days or less"
    severity = Severity.MEDIUM
    service = "iam"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        iam = require(snapshot.iam)
        findings = []
        for row in iam.credential_report:
            if row.is_root:
                continue  # root keys are a critical finding of their own, whatever their age
            for slot, active, rotated in _keys(row):
                if not active or rotated is None:
                    continue
                age = snapshot.captured_at - rotated
                if age > MAX_ACCESS_KEY_AGE:
                    findings.append(
                        self.build_finding(
                            snapshot,
                            resource=f"{row.arn}/access-key-{slot}",
                            reason=(
                                f"IAM user {row.user!r}: access key {slot} is active and was "
                                f"last rotated {rotated:%Y-%m-%d}, {age.days} days before "
                                "the snapshot."
                            ),
                        )
                    )
        return findings


def _keys(row: CredentialReportRow):
    yield 1, row.access_key_1_active, row.access_key_1_last_rotated
    yield 2, row.access_key_2_active, row.access_key_2_last_rotated
