"""Network posture: security groups exposing remote administration to the internet."""

from app.posture.base import PostureCheck, require
from app.posture.snapshot import IpPermission, PostureSnapshot
from app.schemas.finding import Finding, Severity

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
ANYWHERE = ("0.0.0.0/0", "::/0")


def _covers(permission: IpPermission, port: int) -> bool:
    if permission.ip_protocol == "-1":  # all protocols, all ports
        return True
    if permission.ip_protocol not in ("tcp", "6"):
        return False
    low = permission.from_port if permission.from_port is not None else 0
    high = permission.to_port if permission.to_port is not None else 65535
    return low <= port <= high


def _open_to_anywhere(permission: IpPermission) -> list[str]:
    cidrs = [r.cidr_ip for r in permission.ip_ranges] + [
        r.cidr_ipv6 for r in permission.ipv6_ranges
    ]
    return [cidr for cidr in cidrs if cidr in ANYWHERE]


class AdminPortOpenToInternet(PostureCheck):
    check_id = "sg-admin-port-open-to-internet"
    name = "Remote administration open to the internet"
    description = "A security group allows inbound SSH (22) or RDP (3389) from 0.0.0.0/0 or ::/0."
    rationale = (
        "Internet-wide scanners find open SSH and RDP within minutes and try stolen and "
        "default passwords and known exploits. Administration should go through Session "
        "Manager, a VPN, or a narrow allow-list. A group not attached to anything is "
        "harmless today but one attachment away from exposure."
    )
    remediation = (
        "Restrict the rule to known address ranges, or replace it with SSM Session Manager."
    )
    reference = "CIS AWS Foundations Benchmark: no security group ingress to remote admin ports"
    severity = Severity.HIGH
    service = "ec2"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        ec2 = require(snapshot.ec2)
        findings = []
        for group in ec2.security_groups:
            exposed = sorted(
                {
                    f"{ADMIN_PORTS[port]} ({port}) from {cidr}"
                    for permission in group.ip_permissions
                    for cidr in _open_to_anywhere(permission)
                    for port in ADMIN_PORTS
                    if _covers(permission, port)
                }
            )
            if exposed:
                findings.append(
                    self.build_finding(
                        snapshot,
                        resource=(
                            f"arn:aws:ec2:{snapshot.region}:{snapshot.account_id}:"
                            f"security-group/{group.group_id}"
                        ),
                        reason=(
                            f"Security group {group.group_id} ({group.group_name!r}) allows "
                            f"inbound {'; '.join(exposed)}."
                        ),
                    )
                )
        return findings
