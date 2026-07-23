# AWS Certified Security – Specialty (SCS-C03)

Study notes for the SCS-C03 exam. Anchored against SAA-C03 content in the parent `README.md` — this doc focuses on the security-specific depth the specialty exam expects.

<!-- TOC depthfrom:2 depthto:3 withlinks:true updateonsave:true orderedlist:false -->

- [Exam Overview](#exam-overview)
- [Domain Map (SCS-C03 blueprint)](#domain-map-scs-c03-blueprint)
- [Domain 1 — Threat Detection and Incident Response (14%)](#domain-1--threat-detection-and-incident-response-14)
  - [GuardDuty](#guardduty)
  - [Detective](#detective)
  - [Security Hub](#security-hub)
  - [Incident Response Playbooks](#incident-response-playbooks)
- [Domain 2 — Security Logging and Monitoring (18%)](#domain-2--security-logging-and-monitoring-18)
  - [CloudTrail (deep dive)](#cloudtrail-deep-dive)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [CloudWatch Logs + Metrics + Alarms](#cloudwatch-logs--metrics--alarms)
  - [Athena on Security Logs](#athena-on-security-logs)
- [Domain 3 — Infrastructure Security (20%)](#domain-3--infrastructure-security-20)
  - [VPC Security (SG vs NACL deep dive)](#vpc-security-sg-vs-nacl-deep-dive)
  - [AWS WAF, Shield, Firewall Manager](#aws-waf-shield-firewall-manager)
  - [Network Firewall](#network-firewall)
  - [PrivateLink, VPC Endpoints, Endpoint Policies](#privatelink-vpc-endpoints-endpoint-policies)
- [Domain 4 — Identity and Access Management (16%)](#domain-4--identity-and-access-management-16)
  - [IAM Policy Evaluation Logic](#iam-policy-evaluation-logic)
  - [SCPs, Permission Boundaries, Session Policies](#scps-permission-boundaries-session-policies)
  - [IAM Identity Center and Federation](#iam-identity-center-and-federation)
  - [Resource-based Policies](#resource-based-policies)
- [Domain 5 — Data Protection (18%)](#domain-5--data-protection-18)
  - [KMS Deep Dive](#kms-deep-dive)
  - [Envelope Encryption](#envelope-encryption)
  - [Secrets Manager vs Parameter Store](#secrets-manager-vs-parameter-store)
  - [S3 Encryption + Bucket Policies](#s3-encryption--bucket-policies)
  - [Certificate Manager (ACM) and Private CA](#certificate-manager-acm-and-private-ca)
- [Domain 6 — Management and Security Governance (14%)](#domain-6--management-and-security-governance-14)
  - [Organizations, SCPs, Control Tower](#organizations-scps-control-tower)
  - [AWS Config](#aws-config)
  - [Trusted Advisor](#trusted-advisor)
  - [Audit Manager](#audit-manager)
- [Cross-cutting Traps and Anti-patterns](#cross-cutting-traps-and-anti-patterns)
- [Study Order Recommendation](#study-order-recommendation)

<!-- /TOC -->

## Exam Overview

| Field | Value |
|---|---|
| Code | **SCS-C03** |
| Duration | **170 minutes** |
| Questions | **65** (multiple choice / multiple response) |
| Passing score | **750 / 1000** |
| Cost | **$300 USD** |
| Prereq (recommended) | 5 years IT security + 2 years AWS security. In practice: SAA-C03 material + hands-on IAM/KMS/GuardDuty. |
| Format | Pearson VUE / online proctored |

**How it differs from SAA-C03:**

- SAA asks *"which service should I pick?"* — SCS asks *"how do I harden / detect / respond?"*
- Much more emphasis on **IAM policy evaluation order**, **KMS key policies vs grants**, **CloudTrail configurations**, **GuardDuty findings triage**.
- Expect scenario questions with multiple *correct-sounding* answers where you must pick the one that's **most secure** or **least-privilege**.

## Domain Map (SCS-C03 blueprint)

| Domain | Weight | Core question | Anchor services |
|---|---|---|---|
| 1. Threat Detection and Incident Response | 14% | *"Something bad is happening — how do I know, and how do I respond?"* | GuardDuty, Detective, Security Hub, EventBridge |
| 2. Security Logging and Monitoring | 18% | *"What happened, and can I prove it?"* | CloudTrail, VPC Flow Logs, CloudWatch, Athena |
| 3. Infrastructure Security | 20% | *"How do I keep attackers out at network + host level?"* | VPC, SG/NACL, WAF, Shield, Network Firewall, PrivateLink |
| 4. Identity and Access Management | 16% | *"Who is allowed to do what, and how do I prove least privilege?"* | IAM, STS, Identity Center, SCPs, Permission Boundaries |
| 5. Data Protection | 18% | *"How do I keep data confidential in-transit and at-rest?"* | KMS, ACM, Secrets Manager, Macie, S3 encryption |
| 6. Management and Security Governance | 14% | *"How do I enforce security across many accounts?"* | Organizations, Control Tower, Config, Audit Manager |

## Domain 1 — Threat Detection and Incident Response (14%)

### GuardDuty

**Anchored against a managed IDS/IPS** — GuardDuty is a **detection** service (not prevention). It ingests three data streams and produces **findings** without you configuring any agent or rules.

**Data sources (know these — favourite exam trap):**

1. **VPC Flow Logs** — for network-level detection (port scanning, cryptomining C2)
2. **CloudTrail Management Events** — for API-level anomalies (root user activity, unusual regions)
3. **DNS logs** — for domain-based detection (queries to known-bad domains)

**Optional protection plans (add-ons):**

- **S3 Protection** — detects data exfil from S3 buckets
- **EKS Protection** — audit + runtime monitoring
- **Malware Protection** — scans EBS volumes attached to suspicious EC2 instances
- **RDS Protection** — detects suspicious login patterns
- **Lambda Protection** — anomalous network activity from functions

**Common Anti-patterns (exam wrong answers):**

- *"Use GuardDuty to block malicious traffic"* → wrong; GuardDuty **detects only**. Combine with WAF / Network Firewall / EventBridge → Lambda for response.
- *"Enable VPC Flow Logs to enable GuardDuty"* → wrong; GuardDuty ingests VPC Flow Logs **independently** without you configuring them separately.
- *"GuardDuty needs an agent"* → wrong; it's fully agentless (data sources come from AWS control plane).

> *Mental model: GuardDuty = **eyes**. Wire it to EventBridge to get **hands** (auto-remediation).*

### Detective

**Anchored against Splunk / graph-database forensics** — Detective ingests GuardDuty findings + VPC Flow Logs + CloudTrail and builds a **behavior graph** for investigation.

**When to reach for Detective vs Security Hub:**

- **Security Hub** = summary dashboard of many findings ("what's wrong?")
- **Detective** = investigation tool for a single finding ("*why* is this wrong, what's the blast radius?")

### Security Hub

**Aggregator** — pulls findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partners into a single pane. Runs **security standards** (CIS, PCI, AWS Foundational) that continuously score your account.

**What it is NOT:**

- **NOT a detection engine** — it consumes findings, doesn't generate its own (except from its enabled standards checks).
- **NOT the same as Config** — Config tracks resource state; Security Hub tracks security findings.

### Incident Response Playbooks

**Numbered response flow (canonical SCS pattern — memorise):**

1. **GuardDuty** raises finding
2. **EventBridge** rule matches the finding pattern
3. **SSM Automation** or **Lambda** runs the response (quarantine instance, revoke credentials, snapshot EBS for forensics)
4. **SNS** notifies the security team
5. **Detective** used to investigate root cause after the fire is out

## Domain 2 — Security Logging and Monitoring (18%)

### CloudTrail (deep dive)

**The single most-tested service on SCS-C03.** Know cold:

- **Management events** (default ON) vs **Data events** (S3 object-level, Lambda invoke — pay extra, must enable per-resource) vs **Insights events** (anomaly detection on API rate — separate cost).
- **Organization trail** — one trail across all accounts, delivered to a central S3 bucket in the audit account.
- **CloudTrail Lake** — managed data lake, SQL queries via built-in engine (like Athena but scoped to CloudTrail). Retains up to 7 years.
- **Log file integrity validation** — SHA-256 hash chained across log files; use `aws cloudtrail validate-logs` to detect tampering.
- **S3 bucket policies** — the central audit bucket needs `s3:PutObject` from `cloudtrail.amazonaws.com` and `s3:GetBucketAcl`.

**Common Anti-patterns (exam wrong answers):**

- *"Enable CloudTrail to log S3 object reads"* → wrong; management events don't cover object-level. Enable **data events for S3**.
- *"CloudTrail logs are always encrypted"* → wrong; S3 delivery uses SSE-S3 by default, but you can (and should) use SSE-KMS for stronger control.

### VPC Flow Logs

**Anchored against a firewall log** — records IP traffic in/out of an ENI. Three levels: **VPC**, **subnet**, **ENI**.

- Deliver to CloudWatch Logs, S3, or Kinesis Data Firehose.
- **Sampling** — traffic captured is a sample; not every packet. Use for pattern analysis, not for guaranteed forensic completeness.
- Doesn't capture: DHCP, DNS to Amazon resolver, metadata service (169.254.x.x), Windows license activation.

### CloudWatch Logs + Metrics + Alarms

- **Metric filters** convert log patterns into CloudWatch metrics — e.g. count `"Root user access"` occurrences in CloudTrail logs → alarm on ≥1.
- **Contributor Insights** — top-N reports over log streams (top IPs, top failing users).

### Athena on Security Logs

Common SCS pattern: **CloudTrail → S3 → Athena** for ad-hoc "who did what when" queries. Same for VPC Flow Logs. Use **partition projection** on `year=/month=/day=` prefixes to keep query cost low.

## Domain 3 — Infrastructure Security (20%)

### VPC Security (SG vs NACL deep dive)

Big table of the SG/NACL differences, plus the **evaluation order** (NACL inbound → SG inbound → subnet routing → SG outbound → NACL outbound) — memorise this cold.

### AWS WAF, Shield, Firewall Manager

- **WAF** = L7 rules (SQLi, XSS, rate limits, geo, custom).
- **Shield Standard** (free, auto) vs **Shield Advanced** ($3k/month; cost protection, DRT, L7 protection).
- **Firewall Manager** = policy-based **enforcement** across an Organization for WAF + Shield Advanced + Network Firewall + SG audit.

### Network Firewall

**Anchored against a Palo Alto / on-prem network firewall** — stateful L3/L4/L7 with **Suricata rules**, deployed inline in a dedicated firewall subnet. Deep-packet inspection between VPCs (via Transit Gateway) or between VPC + internet.

### PrivateLink, VPC Endpoints, Endpoint Policies

- **Gateway endpoints** (S3 + DynamoDB only, free) vs **Interface endpoints** (ENI-based, PrivateLink, $).
- **Endpoint policies** = IAM-style policy attached to the endpoint that restricts *which* S3 buckets / DynamoDB tables can be reached through it.
- **VPC peering vs PrivateLink** — PrivateLink is one-way, only exposes a service; VPC peering is bi-directional, whole-VPC.

## Domain 4 — Identity and Access Management (16%)

### IAM Policy Evaluation Logic

**Numbered evaluation flow (memorise cold — favourite exam trap):**

1. **Explicit DENY anywhere** → DENY, stop.
2. **SCP** — does the org allow the action? If not → DENY.
3. **Resource-based policy** — does the resource allow the principal?
4. **Identity-based policy** — does the principal's policy allow the action?
5. **Permission boundary** — does the boundary allow it?
6. **Session policy** (STS AssumeRole with `--policy`) — does the session narrow it further?
7. If any layer says DENY → DENY. Only if all layers ALLOW → ALLOW.

**Key rule:** cross-account access requires an ALLOW in **both** the resource policy *and* the identity policy (in the calling account).

### SCPs, Permission Boundaries, Session Policies

- **SCPs** — apply to an account/OU/root; do NOT grant permissions, only bound them.
- **Permission boundaries** — apply to an IAM user/role; used for delegation (dev creates roles but can't exceed the boundary).
- **Session policies** — apply per-STS-session, further narrow the assumed-role permissions.

### IAM Identity Center and Federation

- **Successor to AWS SSO**. Integrates with external IdPs (Okta, Azure AD) via SAML or SCIM.
- **Permission sets** = role templates deployed to accounts.

### Resource-based Policies

Only the following resources have them (memorise): **S3 buckets, KMS keys, SNS topics, SQS queues, Lambda functions, ECR repos, EFS file systems, Secrets Manager secrets, API Gateway (resource policy), IAM roles (trust policy)**.

## Domain 5 — Data Protection (18%)

### KMS Deep Dive

- **Key types:** AWS-managed (auto-rotated yearly, can't customize) vs Customer-managed (rotate on demand, custom policy) vs AWS-owned (invisible).
- **Symmetric** (default, AES-256 GCM) vs **Asymmetric** (RSA / ECC for sign+verify, envelope encryption).
- **Key policies** are mandatory — root user access defaults enabled; IAM policies alone can't grant KMS access without the key policy.
- **Grants** — temporary programmatic permissions on a key (used by AWS services like RDS on your behalf); expire and can be retired.
- **Multi-Region keys** — separate KMS keys with the same key material replicated across regions; app can encrypt in one region, decrypt in another.

### Envelope Encryption

**Numbered flow (SSE-KMS on S3):**

1. Client uploads object → S3 requests a **data key** from KMS.
2. KMS generates plaintext DEK + encrypted DEK (using the CMK).
3. S3 encrypts the object with the plaintext DEK, discards the plaintext DEK, stores the encrypted DEK alongside the object.
4. On download, S3 sends the encrypted DEK to KMS, KMS returns the plaintext DEK, S3 decrypts.

Result: every object gets a unique DEK; the CMK never touches the data.

### Secrets Manager vs Parameter Store

| | Secrets Manager | Parameter Store (SSM) |
|---|---|---|
| Auto rotation | **Yes** (Lambda-based rotator) | No (unless you build it) |
| KMS integration | Yes | Yes (SecureString) |
| Cost | ~$0.40/secret/mo + API calls | Free (Standard tier) |
| Max size | 64 KB | 4 KB (Standard), 8 KB (Advanced) |
| Cross-account access | Resource policy | via KMS grants |

**Rule of thumb:** DB creds → Secrets Manager (rotation); config values / API keys → Parameter Store.

### S3 Encryption + Bucket Policies

Anchored against the SAA `README.md` S3 encryption section. Depth for SCS:

- **Bucket key** — reduces KMS API calls by 99% (S3 uses one bucket-level DEK, caches it; still per-object DEKs). Big cost saver.
- **Deny unencrypted uploads:** bucket policy with `s3:x-amz-server-side-encryption` condition.
- **Deny non-TLS:** bucket policy with `aws:SecureTransport: false → Deny`.
- **Block Public Access** overrides everything — even a public bucket policy is neutered if BPA is on.

### Certificate Manager (ACM) and Private CA

- **ACM public certs** — free, auto-rotated. Only usable with AWS integrations (ALB, CloudFront, API Gateway, App Runner). **Cannot be exported.**
- **ACM Private CA** — hierarchy of your own CAs for internal mTLS / IoT. Paid per CA + per cert issued.
- **Import external cert to ACM** — one-way, no auto-rotation. You must re-import before expiry.

## Domain 6 — Management and Security Governance (14%)

### Organizations, SCPs, Control Tower

- **Control Tower** = opinionated multi-account landing zone; sets up Organizations + SCPs + Config aggregator + audit/log accounts automatically. Guardrails = pre-canned SCPs + Config rules.

### AWS Config

- Records resource **configuration state over time** — powers *"what was the SG's rule at 2 pm yesterday?"* questions.
- **Config Rules** = compliance evaluators (managed or custom Lambda-backed).
- **Conformance Packs** = bundles of rules for a compliance framework (CIS, PCI, HIPAA).
- **Aggregator** = collect Config data from all accounts in an org into a central account.

### Trusted Advisor

- Security checks (open SG ports, S3 public buckets, root MFA, IAM key rotation).
- **Business/Enterprise Support** unlocks full check set.

### Audit Manager

Automates evidence collection against frameworks (SOC 2, PCI, HIPAA). Continuously pulls from Config, CloudTrail, Security Hub findings into audit-ready reports.

## Cross-cutting Traps and Anti-patterns

- **"Enable CloudTrail on the compromised account to investigate"** → too late; CloudTrail should already be on in every account, logging to a **separate** audit account.
- **"Use root user for emergency access"** → wrong; use a break-glass IAM role with MFA, log root user API alarms via CloudWatch.
- **"IAM policies enforce KMS access"** → partially wrong; KMS also requires **key policy** to grant access.
- **"S3 encryption protects against a public bucket"** → wrong; encryption is at-rest confidentiality only. Public access = anyone can read decrypted data via S3 API.
- **"Shield Standard covers L7 attacks"** → wrong; Standard is L3/L4 only. **Shield Advanced** + **WAF** for L7.
- **"GuardDuty replaces WAF"** → wrong; detection vs prevention.

## Study Order Recommendation

Rough sequencing based on payoff-per-hour:

1. **IAM policy evaluation logic** (Domain 4) — highest-leverage single topic; every domain touches it.
2. **KMS + envelope encryption** (Domain 5) — second-highest; drives S3/EBS/Secrets Manager questions.
3. **CloudTrail configurations** (Domain 2) — organization trails, data events, integrity validation.
4. **GuardDuty + EventBridge auto-response** (Domain 1) — the canonical incident-response flow.
5. **VPC security + WAF/Shield/Network Firewall** (Domain 3) — network stack.
6. **Organizations + Control Tower + Config** (Domain 6) — multi-account governance.

> *Mental model for the whole exam: **prevent, detect, respond, prove**. Every question maps to one of those verbs. If you can name which verb the scenario is asking about, you've already narrowed the answer set by half.*
