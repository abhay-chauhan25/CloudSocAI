"""Logging posture: whether CloudTrail records everything, and can be trusted."""

from app.posture.base import PostureCheck, require
from app.posture.snapshot import PostureSnapshot
from app.schemas.finding import Finding, Severity


class NoMultiRegionTrailLogging(PostureCheck):
    check_id = "cloudtrail-no-multi-region-logging"
    name = "No multi-region CloudTrail trail is logging"
    description = "No trail is both multi-region and currently logging."
    rationale = (
        "Without a logging multi-region trail, activity in regions the team does not use "
        "goes unrecorded beyond the 90-day event history — exactly where an attacker would "
        "launch resources. CloudSOC's own detections depend on these logs."
    )
    remediation = "Create a multi-region trail (or enable logging on the existing one)."
    reference = "CIS AWS Foundations Benchmark: CloudTrail enabled in all regions"
    severity = Severity.HIGH
    service = "cloudtrail"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        cloudtrail = require(snapshot.cloudtrail)
        trails = cloudtrail.trails
        status = cloudtrail.status
        if any(
            trail.is_multi_region
            and trail.trail_arn in status
            and status[trail.trail_arn].is_logging
            for trail in trails
        ):
            return []
        described = (
            ", ".join(
                f"{trail.name} (multi-region: {trail.is_multi_region}, logging: "
                f"{status[trail.trail_arn].is_logging if trail.trail_arn in status else 'unknown'})"
                for trail in trails
            )
            or "no trails"
        )
        return [
            self.build_finding(
                snapshot,
                resource=f"arn:aws:cloudtrail:*:{snapshot.account_id}:trail/*",
                reason=f"Account {snapshot.account_id}: {described}.",
            )
        ]


class LogFileValidationDisabled(PostureCheck):
    check_id = "cloudtrail-log-validation-disabled"
    name = "CloudTrail log file validation is off"
    description = "A trail has LogFileValidationEnabled = false."
    rationale = (
        "Validation adds signed digest files, so tampering with or deleting delivered logs "
        "can be proven. Without it, an attacker who reaches the log bucket can edit the "
        "evidence undetected."
    )
    remediation = "Enable log file validation on the trail."
    reference = "CIS AWS Foundations Benchmark: CloudTrail log file validation enabled"
    severity = Severity.MEDIUM
    service = "cloudtrail"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        cloudtrail = require(snapshot.cloudtrail)
        return [
            self.build_finding(
                snapshot,
                resource=trail.trail_arn,
                reason=f"Trail {trail.name!r}: LogFileValidationEnabled = false.",
            )
            for trail in cloudtrail.trails
            if not trail.log_file_validation
        ]
