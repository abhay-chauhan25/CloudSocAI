"""Run correlation over the stored findings and save the resulting incidents."""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.correlation.engine import build_incident, group_findings, qualifies_as_incident
from app.repositories.incidents import (
    list_open_incidents,
    list_unassigned_findings,
    save_incident,
)
from app.schemas.incident import Incident


@dataclass(frozen=True)
class CorrelationReport:
    created: list[Incident]
    updated: list[Incident]


def run_correlation(session: Session) -> CorrelationReport:
    """Attach new findings to open incidents, or create incidents from them.

    Findings that do not qualify yet (a single low-risk finding) stay
    unassigned and are reconsidered on the next run, when a related finding
    may have arrived. Does not commit: the caller owns the transaction.
    """
    created: list[Incident] = []
    updated: list[Incident] = []
    groups = group_findings(list_open_incidents(session), list_unassigned_findings(session))
    for group in groups:
        if group.existing is not None:
            incident = build_incident(group.findings, group.existing.incident_id)
            updated.append(incident)
        elif qualifies_as_incident(group.findings):
            incident = build_incident(group.findings)
            created.append(incident)
        else:
            continue
        save_incident(session, incident)
    return CorrelationReport(created=created, updated=updated)
