# CloudSOC AI — Project Information & Technical Blueprint

## 1. Project Overview

**CloudSOC AI** is a portfolio-grade, AWS-focused security monitoring, threat-detection, and investigation platform. It is best understood as a **lightweight cloud SIEM + CSPM + AI-assisted SOC analyst**.

### One-sentence pitch

> CloudSOC AI is an AWS cloud-security monitoring and threat-detection platform that collects cloud activity and configuration data, detects misconfigurations and suspicious behavior using deterministic rules and machine-learning anomaly detection, correlates related events into incidents, and uses an LLM to explain findings, map them to MITRE ATT&CK, and recommend investigation and remediation steps.

### Primary goal

The project should demonstrate practical knowledge of:

- Cybersecurity fundamentals
- Security Operations Center (SOC) workflows
- SIEM architecture
- Cloud security
- AWS
- IAM and least privilege
- Network security
- Security logging and telemetry
- Detection engineering
- Incident correlation
- Risk scoring
- MITRE ATT&CK
- Python backend development
- REST APIs
- PostgreSQL and data modeling
- React and TypeScript frontend development
- Docker
- Terraform / Infrastructure as Code
- Testing and CI/CD
- Machine learning anomaly detection
- Responsible LLM integration
- Full-stack system design

The project is deliberately designed so that each component teaches an important concept rather than hiding the security logic behind an LLM.

---

## 2. What Problem Does CloudSOC AI Solve?

Organizations running workloads in AWS need to answer two major security questions:

1. **Is our AWS environment configured securely?**
2. **Is suspicious or malicious activity occurring?**

CloudSOC AI addresses both.

### Security posture

The system examines AWS configuration to find issues such as:

- Public S3 buckets
- Security groups exposing SSH or RDP to the Internet
- Overly permissive IAM policies
- Administrative privileges
- Old or unused credentials
- Missing MFA
- Disabled or incorrectly configured logging
- Unencrypted resources

This portion resembles **Cloud Security Posture Management (CSPM)**.

### Threat detection

The system also analyzes security telemetry over time to identify suspicious behavior such as:

- Access keys being created unexpectedly
- Administrative policies being attached
- Root account activity
- CloudTrail being stopped or deleted
- Bursts of authentication failures
- Activity from a new IP address
- Activity from an unusual AWS region
- Unusual API-call volume
- Suspicious sequences of IAM activity
- Network scanning
- Unusual outbound traffic

This portion resembles a **Security Information and Event Management (SIEM)** system.

---

## 3. Is CloudSOC AI a SIEM?

Yes. A major part of CloudSOC AI is a small, AWS-focused SIEM.

A traditional SIEM performs roughly:

```text
Security logs
    ↓
Collection
    ↓
Normalization
    ↓
Detection
    ↓
Correlation
    ↓
Alerts / Findings
    ↓
Incidents
    ↓
Analyst investigation
```

CloudSOC AI performs:

```text
CloudTrail + VPC Flow Logs + AWS configuration
    ↓
Ingestion
    ↓
Normalization
    ↓
Rule-based detection + CSPM + ML
    ↓
Correlation
    ↓
Risk scoring
    ↓
Findings / Incidents
    ↓
AI-assisted investigation
    ↓
Dashboard
```

CloudSOC AI extends a basic SIEM with:

- CSPM-style cloud configuration checks
- Behavioral anomaly detection
- LLM-assisted incident explanation and investigation
- Natural-language investigation capabilities

A good resume description is:

> **CloudSOC AI — AI-Powered Cloud SIEM & Threat Detection Platform**

---

## 4. Core Design Principle

The most important architectural rule is:

> **Rules and machine-learning models detect suspicious behavior. The LLM explains and investigates the evidence.**

Do **not** use an LLM as the sole detection engine.

Correct architecture:

```text
Raw telemetry
    ↓
Normalization
    ↓
Deterministic rules
    ↓
ML anomaly detection
    ↓
Correlation
    ↓
Risk scoring
    ↓
Incident
    ↓
LLM investigation
```

The LLM should never initially have permission to modify AWS resources or automatically remediate an incident.

The AI layer should be advisory.

---

## 5. High-Level Architecture

```text
                            AWS ACCOUNT
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
         CloudTrail        VPC Flow Logs        AWS APIs
             │                  │                  │
             │                  │             boto3 scanners
             │                  │          IAM / S3 / EC2 / etc.
             │                  │                  │
             └──────────────────┼──────────────────┘
                                │
                                ▼
                         INGESTION LAYER
                                │
                                ▼
                       NORMALIZATION LAYER
                                │
                                ▼
                           PostgreSQL
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
                 ▼              ▼              ▼
             Rule Engine    ML Anomaly      CSPM Engine
                            Detection
                 │              │              │
                 └──────────────┼──────────────┘
                                ▼
                             FINDINGS
                                │
                                ▼
                       CORRELATION ENGINE
                                │
                                ▼
                            INCIDENTS
                                │
                      ┌─────────┴─────────┐
                      │                   │
                      ▼                   ▼
                 MITRE Mapping        LLM Analyst
                      │                   │
                      └─────────┬─────────┘
                                ▼
                            FastAPI
                                │
                                ▼
                        React Dashboard
```

---

## 6. Core Security Concepts

### Event

An event records that something happened.

Example:

```text
developer → CreateAccessKey
```

An event is not automatically malicious.

### Finding

A finding represents something the detection system considers security-relevant.

Example:

```text
IAM access key created for privileged user
Severity: Medium
Risk: 55/100
```

### Incident

An incident groups related events and/or findings into a larger security story.

Example:

```text
Possible IAM Account Compromise

03:04 Login from new IP
03:05 CreateAccessKey
03:06 AttachUserPolicy
03:08 AssumeRole

Risk: 94/100
Severity: Critical
```

Important rule:

> **Event != Finding != Incident**

---

## 7. AWS Telemetry

### 7.1 CloudTrail

CloudTrail is the primary telemetry source for the first version.

It records AWS API activity such as:

- CreateAccessKey
- AttachUserPolicy
- CreateUser
- CreateRole
- AssumeRole
- StopLogging
- DeleteTrail
- PutBucketPolicy
- AuthorizeSecurityGroupIngress
- ConsoleLogin

Conceptual event:

```json
{
  "eventTime": "2026-10-04T19:34:12Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "72.14.22.31",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "developer"
  }
}
```

### Initial ingestion model

```text
AWS
 ↓
CloudTrail
 ↓
S3
 ↓
CloudSOC collector
 ↓
Normalizer
 ↓
Database
```

Start with batch ingestion. Real-time/event-driven ingestion can be added later.

---

## 8. Event Normalization

Raw AWS data should be transformed into a predictable internal schema.

Example:

```json
{
  "id": "evt_39201",
  "timestamp": "2026-10-04T19:34:12Z",
  "source": "cloudtrail",
  "service": "iam",
  "event_name": "CreateAccessKey",
  "principal": "developer",
  "principal_type": "IAMUser",
  "source_ip": "72.14.22.31",
  "region": "us-east-1",
  "resource": "developer",
  "success": true,
  "raw_event": {}
}
```

Benefits:

- Detection logic does not depend on raw AWS JSON structure.
- Tests become easier.
- Additional log sources can later use the same internal model.
- The API and frontend work against stable schemas.

---

## 9. Database

Use **PostgreSQL**.

Initial logical tables:

```text
events
findings
incidents
resources
security_checks
ml_scores
ai_analyses
```

### events

Suggested fields:

```text
id
timestamp
source
event_name
service
principal
principal_type
source_ip
region
resource
success
raw_event
```

### findings

```text
id
event_id
detector_id
title
description
severity
risk_score
mitre_technique
created_at
status
```

### incidents

```text
id
title
severity
risk_score
status
first_seen
last_seen
principal
summary
```

### ai_analyses

```text
id
incident_id
summary
attack_explanation
mitre_mapping
recommended_actions
model
created_at
```

Database models should evolve through migrations rather than ad-hoc schema edits once the project matures.

---

## 10. Detection Engine

The detection engine is one of the most important parts of the project.

Start with deterministic rules.

Example:

```python
def detect_access_key_creation(event):
    if event.event_name == "CreateAccessKey":
        return Finding(
            title="IAM access key created",
            severity="medium",
            risk_score=50,
        )
```

Later, rules can become data-driven.

Example conceptual YAML:

```yaml
id: IAM-001
name: Administrative policy attached

event:
  source: cloudtrail
  event_name: AttachUserPolicy

conditions:
  policy_contains:
    - AdministratorAccess

severity: high

mitre:
  technique: T1098
```

Every rule should have:

- Unique ID
- Human-readable name
- Description
- Trigger logic
- Severity
- Explainable reason
- Optional MITRE mapping
- Positive test
- Negative test

---

## 11. Initial Detection Set

Aim for approximately 15–20 strong detections rather than dozens of shallow rules.

Recommended initial detections:

1. Root account used
2. Access key created
3. AdministratorAccess attached
4. IAM user created
5. IAM role created
6. IAM policy modified
7. MFA removed or changed
8. CloudTrail stopped
9. CloudTrail deleted
10. Security group exposes SSH to `0.0.0.0/0`
11. Security group exposes RDP to `0.0.0.0/0`
12. Public S3 configuration detected
13. Burst of failed console logins
14. Activity from a previously unseen IP
15. Activity from a new AWS region
16. Unusually high API-call volume
17. Sensitive Secrets Manager access anomaly
18. New credential followed by privilege change
19. Privilege change followed by role assumption
20. Suspicious multi-event IAM sequence

---

## 12. Correlation Engine

Individual events can be benign. Sequences can be suspicious.

Example:

```text
New source IP
      +
CreateAccessKey
      +
AttachUserPolicy
      +
AdministratorAccess
      +
AssumeRole
      ↓
Possible IAM Account Compromise
```

Correlation should consider:

- Principal / user
- Source IP
- Resource
- AWS account
- Region
- Time window
- Detection types
- Event order

Example correlation rule:

```text
CreateAccessKey
+
AttachUserPolicy
for the same principal
within 10 minutes
→ create or update an IAM privilege-escalation incident
```

---

## 13. Risk Scoring

Risk scoring must be explainable.

Possible model:

```text
Risk Score =
  Base detection severity
+ identity privilege
+ asset exposure
+ behavioral anomaly
+ correlation strength
+ sensitive resource impact
```

Example:

```text
New IP                       +10
CreateAccessKey              +15
AdministratorAccess          +30
Unusual region               +10
High anomaly score           +15
Multiple correlated events   +15
```

Result:

```text
Risk Score: 95 / 100
Severity: Critical
```

The UI should eventually be able to show **why** the score was assigned.

---

## 14. MITRE ATT&CK

Where appropriate, detections and incidents should map to MITRE ATT&CK techniques.

Examples relevant to cloud security include:

- Valid Accounts
- Cloud Accounts
- Account Manipulation
- Additional Cloud Credentials
- Additional Cloud Roles

The project should not blindly accept an LLM's MITRE mapping. Prefer curated mappings attached to detections, with the LLM allowed to explain them.

---

## 15. CSPM Engine

The CSPM engine examines AWS resource configuration through `boto3`.

Potential clients:

```python
boto3.client("s3")
boto3.client("iam")
boto3.client("ec2")
boto3.client("cloudtrail")
```

### S3 checks

- Public access
- Public bucket policy
- Encryption disabled
- Versioning disabled

### IAM checks

- AdministratorAccess attached
- `Action: "*"`
- `Resource: "*"`
- Old access keys
- Unused access keys
- Missing MFA
- Excessive permissions

### EC2 / networking checks

- SSH open to Internet
- RDP open to Internet
- Database ports open to Internet
- Overly permissive security groups

### Logging checks

- CloudTrail disabled
- Incorrect trail coverage
- Important logging controls disabled

The project can later integrate native AWS findings rather than pretending to replace mature AWS security services.

---

## 16. VPC Flow Logs and Network Security

After CloudTrail functionality is stable, add VPC Flow Logs.

Useful fields include:

```text
source IP
destination IP
source port
destination port
protocol
packets
bytes
start time
end time
ACCEPT / REJECT
```

Potential network detections:

- Port scanning
- High connection frequency
- Repeated rejected connections
- Unusual destination ports
- Large outbound transfer
- Previously unseen destination
- Unusual protocol usage

Example:

```text
Source 10.0.1.14 contacted 47 unique ports on one target
within 60 seconds.

Finding: Potential Port Scan
Risk: 81/100
```

---

## 17. Machine Learning

ML should be added only after deterministic detection works.

### First model

Use **Isolation Forest** from scikit-learn.

It is appropriate for learning anomaly-detection concepts without unnecessary deep-learning complexity.

Potential features:

```text
API calls per hour
failed calls per hour
unique services accessed
unique resources accessed
unique source IPs
unique regions
bytes transferred
connections per minute
unique destination ports
time-of-day representation
```

### Example behavioral profile

Normal:

```text
Principal: developer
Region: us-east-1
Activity time: 09:00–20:00
API requests: 10–40/hour
Services: EC2, S3, Lambda
```

Observed:

```text
03:42
eu-west-1
new IP
427 API calls/hour
IAM + Secrets Manager + STS
```

Possible result:

```text
Anomaly score: 0.96
```

CloudSOC should pair the score with interpretable feature differences where possible.

### ML principle

ML contributes a signal. It does not independently prove malicious activity.

---

## 18. Combining Security Signals

A major project goal is multi-signal detection.

Example:

```text
Rule:
AdministratorAccess attached
       ↓
+30

ML:
Identity anomaly = 0.94
       ↓
+20

Correlation:
Access key created two minutes earlier
       ↓
+20

Context:
Sensitive privileged identity
       ↓
+15
```

The resulting incident is stronger than any individual signal.

---

## 19. AI SOC Analyst

The LLM receives structured incident evidence after detection and correlation.

Example input:

```json
{
  "incident": "Possible IAM Account Compromise",
  "risk_score": 94,
  "events": [
    "ConsoleLogin from new IP",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AssumeRole"
  ],
  "anomaly_score": 0.91
}
```

Request structured output such as:

```json
{
  "summary": "...",
  "why_suspicious": "...",
  "attack_scenario": "...",
  "mitre_techniques": [],
  "recommended_investigation": [],
  "recommended_remediation": [],
  "confidence": 0.0
}
```

### AI responsibilities

The LLM may:

- Summarize an incident
- Explain why evidence is suspicious
- Construct a readable timeline
- Explain curated MITRE mappings
- Recommend investigation steps
- Recommend remediation
- Answer questions using retrieved CloudSOC data

The LLM should not initially:

- Delete users
- Disable credentials
- Modify policies
- Change security groups
- Destroy infrastructure
- Make irreversible AWS changes
- Override deterministic security findings

---

## 20. Natural-Language Investigation

A later feature is **Ask CloudSOC**.

Examples:

> What happened with IAM user developer today?

> Why is incident 42 critical?

> Show critical IAM incidents this week.

Architecture:

```text
User question
    ↓
Query interpretation
    ↓
Safe structured retrieval from CloudSOC database
    ↓
Relevant events/findings/incidents
    ↓
LLM
    ↓
Grounded answer
```

The LLM should answer from retrieved CloudSOC evidence rather than inventing security facts.

---

## 21. Backend API

Use **FastAPI**.

Initial endpoints:

```text
GET /health

GET /events
GET /events/{id}

GET /findings
GET /findings/{id}

GET /incidents
GET /incidents/{id}

GET /dashboard/summary
```

Later:

```text
POST /ingest/cloudtrail
POST /scans/aws
POST /incidents/{id}/analyze
POST /investigate/query
```

Use Pydantic for request/response schemas.

---

## 22. Frontend

Use:

- React
- TypeScript
- Vite

### Dashboard

Show:

- Overall security score
- Active incidents
- Findings by severity
- Recent incidents
- Top affected identities/resources
- Detection trends
- MITRE ATT&CK coverage
- CSPM findings

Conceptual dashboard:

```text
┌──────────────────────────────────────────────────────┐
│                    CLOUDSOC AI                       │
├──────────────────────────────────────────────────────┤
│ Security Score                 Active Incidents      │
│     78 / 100                         12              │
├──────────────────────────────────────────────────────┤
│ CRITICAL     HIGH      MEDIUM       LOW              │
│    2           7         14          22              │
├──────────────────────────────────────────────────────┤
│ Recent Incidents                                     │
│ CRITICAL   Possible IAM Compromise        94         │
│ HIGH       Public S3 Bucket               87         │
│ HIGH       Suspicious Network Activity    82         │
└──────────────────────────────────────────────────────┘
```

### Incident page

Display:

- Risk score
- Severity
- Principal
- Source IP
- Region
- First/last seen
- Timeline
- Related findings
- Risk-score explanation
- MITRE mappings
- AI analysis
- Recommended investigation
- Recommended remediation

---

## 23. Technology Stack

### Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic
- PostgreSQL

### AWS

- boto3
- CloudTrail
- S3
- IAM
- EC2
- VPC Flow Logs

### Security

- MITRE ATT&CK
- Custom detection rules
- Correlation rules
- Explainable risk scoring

### ML

- scikit-learn
- pandas
- NumPy
- Isolation Forest initially

### AI

- LLM provider behind an abstraction layer
- Structured outputs
- Grounded incident context

### Frontend

- React
- TypeScript
- Vite

### Infrastructure

- Docker
- Docker Compose
- Terraform
- AWS

### Quality

- pytest
- Ruff
- mypy where practical
- GitHub Actions

---

## 24. Proposed Repository Structure

```text
CloudSocAI/

├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── collectors/
│   │   │   ├── cloudtrail.py
│   │   │   ├── vpc_flow.py
│   │   │   └── aws_config.py
│   │   ├── normalization/
│   │   │   ├── cloudtrail.py
│   │   │   └── flow_logs.py
│   │   ├── detection/
│   │   │   ├── engine.py
│   │   │   ├── rules/
│   │   │   └── correlation.py
│   │   ├── posture/
│   │   │   ├── iam.py
│   │   │   ├── s3.py
│   │   │   ├── ec2.py
│   │   │   └── cloudtrail.py
│   │   ├── ml/
│   │   │   ├── features.py
│   │   │   ├── train.py
│   │   │   └── inference.py
│   │   ├── ai/
│   │   │   ├── analyst.py
│   │   │   ├── prompts.py
│   │   │   └── schemas.py
│   │   ├── mitre/
│   │   ├── risk/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── main.py
│   └── tests/
│
├── frontend/
│
├── infrastructure/
│   ├── terraform/
│   └── docker/
│
├── sample-data/
│   ├── cloudtrail/
│   └── flow-logs/
│
├── docs/
│   ├── architecture.md
│   ├── detections.md
│   ├── threat-model.md
│   └── setup.md
│
├── docker-compose.yml
├── information.md
├── CLAUDE.md
├── README.md
└── .env.example
```

This structure is a target architecture. Do not create empty complexity prematurely. Directories should be introduced as their corresponding task is implemented.

### Naming conventions

| Context | Name |
|---|---|
| Prose, docs, UI | CloudSOC AI |
| Repository / root folder | `CloudSocAI` |
| Python import package | `app` (in `backend/app/`) |
| Python distribution name (`pyproject.toml`) | `cloudsoc` |

### Structure decisions

- **Flat `backend/app/` layout, not `src/` layout.** CloudSOC is a deployed application, not a library published to PyPI, and a top-level `app` package is the FastAPI convention.
- **Detection rules are Python classes in `backend/app/detection/rules/`.** There is no separate top-level rules directory. Data-driven (e.g. YAML) rules would be a later, explicitly justified change.

---

## 25. Security Lab

Create a controlled AWS sandbox with Terraform.

Potential lab resources:

```text
IAM test identities
IAM test roles
S3 bucket
VPC
EC2 instance
security groups
CloudTrail
```

The lab exists to safely generate expected telemetry.

Example scenario:

```text
LAB-001
Create a security group exposing SSH to the Internet.

Expected result:
CSPM-NETWORK-001 fires.
```

Another:

```text
LAB-002
Create a test identity
→ create access key
→ attach elevated test policy

Expected result:
IAM correlation detection creates an incident.
```

Only test against infrastructure you own or are explicitly authorized to use.

---

## 26. Synthetic Sample Data

The project must be demonstrable without an AWS account.

Include sanitized/synthetic data such as:

```text
sample-data/cloudtrail/normal-user-activity.json
sample-data/cloudtrail/iam-privilege-change.json
sample-data/cloudtrail/new-region-login.json
sample-data/cloudtrail/cloudtrail-disabled.json

sample-data/flow-logs/normal-traffic.log
sample-data/flow-logs/port-scan.log
```

Benefits:

- Unit testing
- Integration testing
- Demo mode
- Recruiters can run the project
- No AWS costs required for basic evaluation

---

## 27. Testing Philosophy

Every security detection should have at least:

1. A positive test that must trigger.
2. A negative test that must not trigger.

Example:

```text
AttachUserPolicy
policy = AdministratorAccess
→ high-severity finding
```

Negative:

```text
AttachUserPolicy
policy = ReadOnlyAccess
→ no AdministratorAccess finding
```

Correlation test:

```text
CreateAccessKey
+
AttachUserPolicy
within 10 minutes
→ incident
```

Negative correlation:

```text
CreateAccessKey
+
normal activity
→ no critical incident
```

Testing is especially important in security because false positives and false negatives are part of the engineering problem.

---

## 28. Development Roadmap

> **The authoritative, numbered task roadmap is `CLAUDE.md` Section 25 (Stages 0–19, tasks 1–165).** Refer to work by its Stage/task number there. The phases below are a high-level conceptual summary only, are not numbered to match, and must not be used to sequence tasks.

The project should be built sequentially. Each phase depends on concepts introduced earlier.

### Specification and foundation

- Understand project architecture
- Define Event, Finding, Incident
- Define initial detection catalog
- Establish repository
- Configure Python project
- Configure tests/linting
- Create documentation

### Synthetic CloudTrail ingestion

- Learn CloudTrail structure
- Add sample CloudTrail events
- Parse local JSON
- Validate input

### Normalization

- Define internal Event schema
- Convert raw CloudTrail records into normalized events
- Test normalizer

### Persistence

- Introduce PostgreSQL
- Learn relational modeling
- Add SQLAlchemy
- Add migrations
- Persist events

### Detection engine

- Build detector interface
- Implement first rules
- Produce findings
- Test positive/negative cases

### Findings persistence and risk scoring

- Persist findings
- Define severity model
- Build explainable initial risk scoring

### FastAPI

- Expose events and findings
- Add API schemas
- Learn HTTP/REST
- Add health endpoint
- Add API tests

### Real AWS CloudTrail ingestion

- Learn boto3 authentication
- Apply least privilege
- Retrieve CloudTrail logs from S3
- Decompress/parse
- Reuse normalization pipeline

### CSPM

- Inspect IAM
- Inspect S3
- Inspect EC2/security groups
- Inspect logging configuration
- Convert posture problems into standardized findings

### Correlation and incidents

- Define correlation windows
- Group related findings
- Create incidents
- Build timelines
- Update risk scores

### Frontend foundation

- Create React/TypeScript app
- Learn components/state/data fetching
- Connect to FastAPI
- Display dashboard data

### Incident UI

- Findings list
- Incident list
- Incident detail
- Timeline
- Risk explanation

### MITRE ATT&CK

- Add curated technique mappings
- Explain tactic/technique concepts
- Display mappings

### AI analyst

- Introduce LLM abstraction
- Build context builder
- Require structured output
- Store analyses
- Display AI investigation
- Discuss hallucination and prompt-injection risks

### ML foundation

- Build feature extraction
- Understand anomaly detection
- Train Isolation Forest
- Evaluate behavior
- Choose threshold
- Add anomaly signal

### Multi-signal risk engine

- Combine rules, context, correlation, and ML
- Keep scoring explainable
- Test edge cases

### VPC Flow Logs

- Parse and normalize flow logs
- Learn TCP/IP and flow metadata
- Add network detections

### Network anomaly detection

- Port-scan behavior
- Connection-volume anomalies
- Outbound transfer anomalies
- Integrate with incidents

### Ask CloudSOC

- Natural-language questions
- Safe query/retrieval layer
- Ground answers in database evidence
- Protect against arbitrary database access

### Terraform security lab

- Learn IaC
- Provision controlled lab
- Generate test telemetry
- Tear resources down safely

### Dockerization

- Containerize backend/frontend (PostgreSQL already runs in Docker Compose from the Persistence stage)
- Docker Compose local environment
- Explain networking/volumes/environment variables

### CI/CD and quality

- GitHub Actions
- Tests
- Linting
- Type checking
- Dependency/security checks where useful

### Portfolio polish

- README
- Architecture diagram
- Threat model
- Demo data
- Screenshots
- Demo walkthrough
- Resume bullets
- Interview talking points

---

## 29. MVP

Do not try to build the complete platform before obtaining a working vertical slice.

The first meaningful MVP is:

```text
Synthetic CloudTrail JSON
        ↓
Parser
        ↓
Normalized Event
        ↓
PostgreSQL
        ↓
8 deterministic detection rules in the first slice
        ↓
Findings
        ↓
FastAPI
        ↓
Simple dashboard
```

Only after that works should the project expand into ML and AI.

---

## 30. Final Portfolio Version

The eventual project can include:

```text
CloudTrail
VPC Flow Logs
AWS CSPM scans
Deterministic rules
Correlation
Incidents
Explainable risk scoring
MITRE ATT&CK
ML anomaly detection
LLM investigation
Natural-language investigation
React dashboard
Terraform lab
Docker
CI/CD
Automated tests
```

---

## 31. Learning Objectives

By the end of the project, the developer should be able to explain the following without relying on generated code.

### AWS

- IAM
- Users vs roles
- Policies
- STS / AssumeRole
- Access keys
- S3
- EC2
- VPC
- Security groups
- CloudTrail
- VPC Flow Logs
- Least privilege

### Networking

- TCP/IP
- Source/destination IP
- Ports
- Protocols
- CIDR
- `0.0.0.0/0`
- Inbound/outbound traffic
- VPCs
- Subnets
- Flow logs

### Cybersecurity

- SOC
- SIEM
- CSPM
- IAM
- Detection engineering
- False positives
- False negatives
- Correlation
- Alert vs finding vs incident
- Risk scoring
- MITRE ATT&CK
- Behavioral detection
- IOC vs behavior
- Incident investigation
- Least privilege

### Backend / software engineering

- Python
- Project structure
- Pydantic
- FastAPI
- REST
- HTTP
- JSON
- PostgreSQL
- SQLAlchemy
- Database migrations
- Testing
- Logging
- Error handling
- Environment variables

### Frontend

- React
- TypeScript
- Components
- Props/state
- Hooks
- API requests
- Loading/error states
- Data visualization
- Frontend/backend separation

### Infrastructure

- Docker
- Containers
- Images
- Docker Compose
- Networking
- Volumes
- Terraform
- Infrastructure as Code
- CI/CD

### AI / ML

- Feature engineering
- Training vs inference
- Isolation Forest
- Anomaly detection
- Thresholds
- Precision/recall concepts
- False positives
- Model evaluation
- Structured LLM outputs
- Grounding
- Hallucinations
- Prompt injection
- Guardrails
- Why AI should not be the sole security decision-maker

---

## 32. Final Demo Goal

A polished demonstration should show:

```text
Controlled AWS security scenario
          ↓
CloudTrail / Flow Log event generated
          ↓
CloudSOC ingests telemetry
          ↓
Event normalized
          ↓
Detection rule triggers
          ↓
ML adds anomaly signal when relevant
          ↓
Related findings correlate
          ↓
Incident created
          ↓
Explainable risk score calculated
          ↓
MITRE technique displayed
          ↓
AI analyst explains evidence
          ↓
Dashboard updates
```

The developer should be able to explain every stage.

---

## 33. Resume Positioning

Potential project title:

**CloudSOC AI — AI-Powered Cloud SIEM & Threat Detection Platform**

Potential description:

> Built an AWS-focused security monitoring platform that ingests CloudTrail and VPC Flow Logs, detects IAM privilege escalation and cloud misconfigurations using custom detection rules, correlates security events into incidents, and performs behavioral anomaly detection.

Potential second bullet:

> Developed an AI-assisted investigation layer that summarizes incident evidence, explains risk, maps detections to MITRE ATT&CK, and recommends investigation and remediation actions through a React security dashboard.

These should eventually be updated to include measurable, truthful results from the completed project.

---

## 34. Guiding Engineering Principles

1. Build security logic before AI features.
2. Build one working vertical slice before expanding.
3. Prefer explainability over cleverness.
4. Keep Event, Finding, and Incident distinct.
5. Test every important detection.
6. Use least privilege.
7. Never commit credentials.
8. Only run security tests against authorized systems.
9. Keep AI advisory rather than autonomous.
10. Maintain synthetic sample data.
11. Document architectural decisions.
12. Understand every component before moving on.
13. Favor a smaller polished system over a large unfinished one.
14. Make the project demonstrable locally.
15. Treat learning as a first-class deliverable.
