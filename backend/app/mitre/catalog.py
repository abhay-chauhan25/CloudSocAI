"""A small, curated subset of MITRE ATT&CK (Enterprise), pinned to one version.

Only the techniques CloudSOC's rules map to are listed. Names and tactics are
copied from attack.mitre.org for the pinned version and must be re-checked
when upgrading: ATT&CK changes between versions (v20 renamed TA0005 to
"Stealth", added "Defense Impairment", and moved cloud-log tampering from
T1562.008 to T1685.002).
"""

from dataclasses import dataclass

ATTACK_VERSION = "20.0"
ATTACK_BASE_URL = "https://attack.mitre.org"


@dataclass(frozen=True)
class Tactic:
    """The attacker's goal: the "why" of a technique."""

    tactic_id: str
    name: str

    @property
    def url(self) -> str:
        return f"{ATTACK_BASE_URL}/tactics/{self.tactic_id}/"


@dataclass(frozen=True)
class Technique:
    """How an attacker achieves a goal. One technique can serve several tactics."""

    technique_id: str  # e.g. "T1098.003" for a sub-technique
    name: str
    tactics: tuple[Tactic, ...]

    @property
    def url(self) -> str:
        return f"{ATTACK_BASE_URL}/techniques/{self.technique_id.replace('.', '/')}/"


# Enterprise tactics in matrix order (ATT&CK v20).
TACTICS: tuple[Tactic, ...] = (
    RECONNAISSANCE := Tactic("TA0043", "Reconnaissance"),
    RESOURCE_DEVELOPMENT := Tactic("TA0042", "Resource Development"),
    INITIAL_ACCESS := Tactic("TA0001", "Initial Access"),
    EXECUTION := Tactic("TA0002", "Execution"),
    PERSISTENCE := Tactic("TA0003", "Persistence"),
    PRIVILEGE_ESCALATION := Tactic("TA0004", "Privilege Escalation"),
    STEALTH := Tactic("TA0005", "Stealth"),
    DEFENSE_IMPAIRMENT := Tactic("TA0112", "Defense Impairment"),
    CREDENTIAL_ACCESS := Tactic("TA0006", "Credential Access"),
    DISCOVERY := Tactic("TA0007", "Discovery"),
    LATERAL_MOVEMENT := Tactic("TA0008", "Lateral Movement"),
    COLLECTION := Tactic("TA0009", "Collection"),
    COMMAND_AND_CONTROL := Tactic("TA0011", "Command and Control"),
    EXFILTRATION := Tactic("TA0010", "Exfiltration"),
    IMPACT := Tactic("TA0040", "Impact"),
)

TECHNIQUES: dict[str, Technique] = {
    technique.technique_id: technique
    for technique in (
        Technique(
            "T1078.004",
            "Valid Accounts: Cloud Accounts",
            (INITIAL_ACCESS, PERSISTENCE, PRIVILEGE_ESCALATION, STEALTH),
        ),
        Technique("T1136.003", "Create Account: Cloud Account", (PERSISTENCE,)),
        Technique(
            "T1098.001",
            "Account Manipulation: Additional Cloud Credentials",
            (PERSISTENCE, PRIVILEGE_ESCALATION),
        ),
        Technique(
            "T1098.003",
            "Account Manipulation: Additional Cloud Roles",
            (PERSISTENCE, PRIVILEGE_ESCALATION),
        ),
        Technique(
            "T1685.002",
            "Disable or Modify Tools: Disable or Modify Cloud Log",
            (DEFENSE_IMPAIRMENT,),
        ),
    )
}


def tactic_rank(tactic: Tactic) -> int:
    """Position in the matrix, for ordering tactics the way analysts read them."""
    return TACTICS.index(tactic)
