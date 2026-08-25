# AWS Certified Security – Specialty (SCS-C03)

Study notes for the SCS-C03 exam. Anchored against SAA-C03 content in the parent `README.md` — this doc focuses on the security-specific depth the specialty exam expects.

<!-- TOC depthfrom:2 depthto:3 withlinks:true updateonsave:true orderedlist:false -->

- [Exam Overview](#exam-overview)
- [Domain Map (SCS-C03 blueprint)](#domain-map-scs-c03-blueprint)
- [AWS Organizations — foundational structure](#aws-organizations--foundational-structure)
- [Preventive vs Detective vs Responsive — the three-tier framework](#preventive-vs-detective-vs-responsive--the-three-tier-framework)
- [Domain 1 — Threat Detection and Incident Response (14%)](#domain-1--threat-detection-and-incident-response-14)
  - [GuardDuty](#guardduty)
  - [Detective](#detective)
  - [Security Hub](#security-hub)
  - [Amazon Inspector](#amazon-inspector)
  - [Incident Response Playbooks](#incident-response-playbooks)
- [Domain 2 — Security Logging and Monitoring (18%)](#domain-2--security-logging-and-monitoring-18)
  - [CloudTrail (deep dive)](#cloudtrail-deep-dive)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [CloudWatch Logs + Metrics + Alarms](#cloudwatch-logs--metrics--alarms)
  - [Athena on Security Logs](#athena-on-security-logs)
  - [ELB Access Logs and Connection Logs (ALB / NLB)](#elb-access-logs-and-connection-logs-alb--nlb)
- [Domain 3 — Infrastructure Security (20%)](#domain-3--infrastructure-security-20)
  - [VPC Security (SG vs NACL deep dive)](#vpc-security-sg-vs-nacl-deep-dive)
  - [AWS WAF, Shield, Firewall Manager](#aws-waf-shield-firewall-manager)
  - [Network Firewall](#network-firewall)
  - [VPC Traffic Mirroring](#vpc-traffic-mirroring)
  - [PrivateLink, VPC Endpoints, Endpoint Policies](#privatelink-vpc-endpoints-endpoint-policies)
  - [AWS IoT Core — policy variables and client-ID injection](#aws-iot-core--policy-variables-and-client-id-injection)
  - [EC2 Instance Connect / Session Manager — IAM requirements and misleading errors](#ec2-instance-connect--session-manager--iam-requirements-and-misleading-errors)
  - [Session Manager Deep Dive](#session-manager-deep-dive)
- [Domain 4 — Identity and Access Management (16%)](#domain-4--identity-and-access-management-16)
  - [IAM Policy Evaluation Logic](#iam-policy-evaluation-logic)
  - [AWS Credential Provider Chain](#aws-credential-provider-chain)
  - [MFA Enforcement — MultiFactorAuthPresent + MultiFactorAuthAge](#mfa-enforcement--multifactorauthpresent--multifactorauthage)
  - [SCPs, Permission Boundaries, Session Policies](#scps-permission-boundaries-session-policies)
  - [IAM Identity Center and Federation](#iam-identity-center-and-federation)
  - [Resource-based Policies](#resource-based-policies)
  - [IAM Access Analyzer](#iam-access-analyzer)
- [Domain 5 — Data Protection (18%)](#domain-5--data-protection-18)
  - [KMS Deep Dive](#kms-deep-dive)
  - [Envelope Encryption](#envelope-encryption)
  - [Secrets Manager vs Parameter Store](#secrets-manager-vs-parameter-store)
  - [S3 Encryption + Bucket Policies](#s3-encryption--bucket-policies)
  - [AWS Backup](#aws-backup)
  - [S3 Access Points](#s3-access-points)
  - [EBS Encryption at Scale](#ebs-encryption-at-scale)
  - [EBS Snapshot Cross-Account Backup (CMK-encrypted)](#ebs-snapshot-cross-account-backup-cmk-encrypted)
  - [Certificate Manager (ACM) and Private CA](#certificate-manager-acm-and-private-ca)
- [Domain 6 — Management and Security Governance (14%)](#domain-6--management-and-security-governance-14)
  - [Organizations, SCPs, Control Tower](#organizations-scps-control-tower)
  - [AWS Config](#aws-config)
  - [Trusted Advisor](#trusted-advisor)
  - [Audit Manager](#audit-manager)
  - [Service Catalog](#service-catalog)
  - [CloudFormation Service Role (deploy least privilege)](#cloudformation-service-role-deploy-least-privilege)
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

## AWS Organizations — foundational structure

Nearly every domain of this exam assumes you can picture the Org tree. Delegated admins for GuardDuty / Config / Security Hub, SCPs and RCPs, cross-account CloudTrail, KMS grants across accounts — all sit on top of this shape.

```text
                        ┌───────────────────────────┐
                        │   MANAGEMENT ACCOUNT      │  ← pays the bills, sets policy
                        │   (also called "master")  │     billing, SCPs, RCPs, delegation
                        └────────────┬──────────────┘
                                     │
                                     ▼
                        ┌───────────────────────────┐
                        │        ROOT               │  ← always exactly one; the top OU
                        │        (Org root)         │
                        └────────────┬──────────────┘
                     ┌───────────────┼──────────────┐
                     ▼               ▼              ▼
              ┌────────────┐  ┌────────────┐  ┌────────────┐
              │  OU: Prod  │  │  OU: Dev   │  │ OU: Audit  │  ← Organizational Units
              └─────┬──────┘  └─────┬──────┘  └─────┬──────┘     (up to 5 levels deep)
             ┌─────┼─────┐          │               │
             ▼     ▼     ▼          ▼               ▼
        ┌──────┐┌──────┐┌──────┐┌───────┐   ┌──────────────┐
        │ Acct ││ Acct ││ Acct ││ Acct  │   │  Log Archive │  ← MEMBER ACCOUNTS
        │  A1  ││  A2  ││  A3  ││  D1   │   │   Security   │     (real AWS accounts,
        └──────┘└──────┘└──────┘└───────┘   └──────────────┘      one root user each)
```

**What lives at each level:**

| Level | What it is | What you attach here |
|---|---|---|
| **Management account** | The one account that created the Org. Payer + admin. Never run workloads here — blast radius is the whole Org. | Delegate admin for services (GuardDuty, Config, Security Hub, IAM Access Analyzer, etc.) |
| **Root** | The invisible top-of-tree OU. Only one, always exists. | SCPs / RCPs / Backup / Tag policies that apply to *every* account |
| **OU** | A folder that groups accounts. Nestable up to 5 levels. | SCPs / RCPs scoped to that branch (e.g. "Prod OU denies s3 outside org") |
| **Account** | A real AWS account. Isolated blast radius, own IAM realm, own root user. | Directly-attached SCPs (rare — usually via OU) |

**Policy types you can attach (memorise the four):**

- **SCP** (Service Control Policy) — bounds what **IAM principals** in the account can do.
- **RCP** (Resource Control Policy, 2024+) — bounds who can access **resources** in the account (the resource-side counterpart to SCPs).
- **Tag policy** — enforces which tag keys/values may be used.
- **Backup policy** — mandates AWS Backup plans across the tree.

All four inherit down: a policy on the Root applies to every OU + account beneath.

**Classic multi-account landing zone (what Control Tower builds):**

```text
Root
├── Security OU
│   ├── Log Archive account   ← receives central CloudTrail, Config, GuardDuty findings
│   └── Audit account         ← read-only for security engineers to investigate
├── Sandbox OU                ← ephemeral dev/experimentation, SCP-locked to cheap regions
├── Workloads OU
│   ├── Prod OU
│   └── NonProd OU
└── Suspended OU              ← quarantine for compromised or deprecated accounts
```

**Rules the exam tests:**

- **One Org root, one management account.** You cannot have two.
- **An account can be in only one Org.** Moving between Orgs requires leaving + rejoining.
- **SCPs don't grant** — they only bound. They cap what identity policies could otherwise allow.
- **The management account is exempt from SCPs.** This is why you don't run workloads there.
- ***"All features"* mode** vs consolidated-billing-only: SCPs, RCPs, delegation, and Config aggregation require **All features**.

> *Mental model: an Org is a **tree of nested folders**, each folder a policy boundary. Accounts are the leaves. The management account is the root gardener — pays the water bill, plants and prunes, but doesn't itself hold the flowers.*

## Preventive vs Detective vs Responsive — the three-tier framework

Every SCS-C03 "how do I enforce X?" question maps to one of three tiers. The exam picks the tier by keyword — get the keyword right and the answer set collapses to one or two options.

```text
┌───────────────────────────────────────────────────────────────┐
│  PREVENTIVE   → the bad action never happens                  │
│                 (API call blocked at IAM/SCP/policy layer)    │
├───────────────────────────────────────────────────────────────┤
│  DETECTIVE    → the bad state is seen, after the fact         │
│                 (finding raised, log entry captured)          │
├───────────────────────────────────────────────────────────────┤
│  RESPONSIVE   → the bad state is auto-corrected               │
│  (corrective)   (Lambda/SSM Automation flips config back)     │
└───────────────────────────────────────────────────────────────┘
```

**Which AWS services live in each tier:**

| Tier | Services / mechanisms | Fires at… |
|---|---|---|
| **Preventive** | SCPs, RCPs, IAM identity policies, IAM permission boundaries, session policies, KMS key policies, S3 bucket policies, resource-based policies, Security Groups, NACLs, S3 Block Public Access, Lambda resource policies, VPC endpoint policies | **API request time** — before state changes |
| **Detective** | AWS Config (rules, conformance packs), GuardDuty, Inspector, Macie, IAM Access Analyzer, Security Hub standards, CloudTrail, VPC Flow Logs, Trusted Advisor | **After the fact** — non-compliant state exists during the observation window |
| **Responsive / corrective** | EventBridge → Lambda auto-remediation, SSM Automation runbooks (`AWS-*` remediation documents), Config auto-remediation, Security Hub Custom Actions | **After detection** — closes the window but doesn't eliminate it |

**Keyword decoder (memorise cold):**

| Stem phrase | Tier the question wants |
|---|---|
| *"Prevent…"* / *"Ensure that…cannot"* / *"Block…"* / *"Enforce that…"* | **Preventive** |
| *"Detect…"* / *"Report on…"* / *"Identify non-compliant…"* / *"Continuously assess…"* | **Detective** |
| *"Auto-remediate…"* / *"Automatically restore compliant state"* / *"Respond to non-compliance"* | **Responsive** |
| *"Prevent insecure configurations"* (**the tell**) | **Preventive**, not detective — the exam is punishing anyone who picks Config here |
| *"Without requiring developers to take extra steps"* | **Preventive** (passive guardrail, not a workflow) |

**Worked example — Lambda function-URL `AuthType = NONE`:**

The classic stem contained two preventive keywords: *"prevent insecure configurations"* and *"without requiring developers to perform extra deployment steps."*

| Tier | Solution | Why the exam rejects it (except preventive) |
|---|---|---|
| **Preventive** ✅ | **SCP** with `lambda:FunctionUrlAuthType = NONE` Deny on Create + Update | API request refused; no bad state ever exists |
| Detective | AWS Config rule flagging `AuthType = NONE` | Fires *after* creation — public URL exists during the evaluation window |
| Responsive | EventBridge → Lambda that flips `AuthType` back to `AWS_IAM` | Reactive; still exposes a live public endpoint before remediation |

The preventive SCP shape:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthenticatedFunctionUrls",
      "Effect": "Deny",
      "Action": ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "lambda:FunctionUrlAuthType": "NONE" }
      }
    }
  ]
}
```

**Why the exam almost always rewards preventive when both are available:**

- **No exposure window** — an SCP-blocked request never creates the bad resource. A Config rule + auto-remediation combo still has a window (Config evaluates on ~15-min intervals for periodic rules, seconds-to-minutes on ChangeTracked events).
- **No extra services to run** — SCP is a policy attached to the Org. Config + Lambda auto-remediation is another service, another IAM role, another Lambda to maintain.
- **No developer-side change** — passive guardrail; devs get `AccessDenied` and immediately do the right thing.

**When detective *is* the correct answer:**

- *"Continuously check that all S3 buckets have encryption enabled"* → **Config rule** `s3-bucket-server-side-encryption-enabled`
- *"Report on IAM users without MFA"* → **Config rule** / **IAM credential report**
- *"Identify EC2 instances with unpatched CVEs"* → **Inspector**
- *"Score our account against CIS / PCI"* → **Security Hub standards**
- *"Alert on suspicious API activity across all accounts"* → **GuardDuty + EventBridge + SNS**

**When responsive is the correct answer:**

- *"Auto-quarantine an EC2 flagged by GuardDuty"* → **EventBridge → SSM Automation / Lambda**
- *"Automatically re-encrypt any bucket that becomes non-compliant"* → **Config auto-remediation** via SSM
- *"Trigger a runbook when a finding severity ≥ 7 arrives"* → **EventBridge rule → Lambda**

**SCP condition-key quick lookup (for preventive-tier questions):**

| Guardrail you want | Condition key |
|---|---|
| Unauthenticated Lambda function URL | `lambda:FunctionUrlAuthType` |
| S3 uploads must be encrypted | `s3:x-amz-server-side-encryption` |
| Force TLS on S3 | `aws:SecureTransport` |
| Region restriction | `aws:RequestedRegion` |
| Deny actions outside the org | `aws:PrincipalOrgID` |
| Enforce MFA on sensitive actions | `aws:MultiFactorAuthPresent` |
| Restrict EC2 instance types | `ec2:InstanceType` |
| Block untagged resource creation | `aws:RequestTag/<key>` + `aws:TagKeys` |

> *Mental model: SCPs, RCPs, IAM/bucket/key policies, Security Groups = **the door lock** (preventive). Config, GuardDuty, Inspector, Macie = **the CCTV** (detective). EventBridge → Lambda / SSM Automation = **the alarm-triggered response** (responsive). "Prevent" wants a lock; "detect" wants a camera; "auto-fix" wants the alarm-and-response. Match the verb, then the service tier picks itself.*

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

#### Canonical detect-and-alert pipeline: GuardDuty → EventBridge → SNS

The single most-tested "compromise detected, notify the team" flow on SCS-C03. Every "continuous, native, no extra infrastructure" scenario decomposes to this chain.

**Numbered runtime flow:**

1. GuardDuty analyses VPC Flow Logs + CloudTrail + DNS → detects an anomaly (e.g. EC2 instance C2 callback, cryptomining, unusual API from an instance role).
2. GuardDuty emits a **finding event** (JSON) onto the **default EventBridge bus** — no configuration needed for the emit.
3. EventBridge rule matches on `source = aws.guardduty` + a severity filter → targets an SNS topic.
4. SNS pushes to every subscribed endpoint — email distribution list, Slack via Lambda, PagerDuty webhook, etc.
5. Total wall-clock: seconds.

**EventBridge event pattern (memorise the shape — high-severity only):**

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": { "severity": [ { "numeric": [ ">=", 7 ] } ] }
}
```

Severity scale: **Low 1.0–3.9, Medium 4.0–6.9, High 7.0–8.9**. Filter with `>= 7` to catch High only; `>= 4` to catch Medium and above.

**SNS gotchas the exam loves:**

- **Email subscriptions must be confirmed** — first-time subscribers get a confirmation email; unconfirmed subscribers get nothing.
- Distribution-list emails work — SNS treats the list address like any single subscriber and hands off to the mail server for fan-out.
- SNS handles retries + delivery status; no custom code to write.

**Why not the plausible alternatives:**

- **CloudWatch Alarm on GuardDuty** — findings aren't metrics by default; you'd need a metric filter first. Indirect and lossy on severity.
- **Lambda polling GuardDuty every N minutes** — pull-based, adds infra to manage, loses "continuous."
- **SES for the notification** — SES is outbound *application* email; alerting fan-out = SNS.
- **CloudTrail as detector** — CloudTrail records API calls; it doesn't detect malware or compromise patterns.
- **Inspector as detector** — Inspector finds *vulnerabilities* (CVEs, network reachability); it doesn't spot compromise-in-progress.

**Exam Triggers:**

- *"Continuous, native, no extra agents, detect compromised EC2"* → **enable GuardDuty**
- *"Notify by email on high-severity findings"* → **EventBridge rule → SNS topic → email subscription**
- *"Filter findings by severity"* → **EventBridge event pattern with `severity` numeric matcher**
- *"Compromise went undetected for N days"* → the question wants *detection* → **GuardDuty**, not CloudTrail

> *Mental model: **GuardDuty is the eyes; EventBridge is the nerve; SNS is the mouth.** Every "detect + alert" question decomposes into this chain — anything else brings infra the question doesn't want.*

#### GuardDuty tuning — trusted IP list vs threat IP list vs suppression rules

Three GuardDuty knobs sound similar and get confused on the exam. Each has a distinct effect on the finding pipeline:

| Feature | Direction | Effect on findings | Hosted where |
|---|---|---|---|
| **Trusted IP list** | Allowlist | GuardDuty **skips analysis** — no findings generated for these IPs | S3 file, referenced by URI |
| **Threat IP list** | Denylist (custom threat intel) | Any traffic to/from these IPs **generates** a new finding | S3 file, referenced by URI |
| **Suppression rule** | Filter on generated findings | Findings **still generated** and billed, but auto-archived → hidden from Console | Configured inside GuardDuty (no S3 file) |

**Question-phrasing decoder:**

- *"No longer produces findings"* → **trusted IP list** (skips analysis entirely).
- *"Hide known false-positive findings without stopping generation"* → **suppression rule**.
- *"Add our own threat intel"* → **threat IP list**.

**Trusted IP list — file format and example**

Plain-text, one IP or CIDR per line. Blank lines and `#` comments allowed. Upload to S3, then reference the S3 URI from GuardDuty.

```text
# trusted-ips.txt — uploaded to s3://my-security-config/guardduty/trusted-ips.txt

# Corporate egress (offices)
203.0.113.42
203.0.113.43
198.51.100.0/24

# Internal VPC CIDR (private subnets)
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Vendor SaaS callback ranges (e.g. Datadog synthetic monitors)
54.94.142.0/23
```

**Rules the file must obey:**

- One entry per line (IPv4/IPv6 address or CIDR).
- Max **2,000 entries**; max object size **35 MB**.
- Blank lines and lines starting with `#` treated as comments (plain-text format).
- Must be in S3; GuardDuty reads it by S3 URI.

**Register the file with GuardDuty (CLI):**

```bash
aws guardduty create-ip-set \
  --detector-id 12abc34d567890 \
  --name "CorporateTrustedIPs" \
  --format TXT \
  --location "s3://my-security-config/guardduty/trusted-ips.txt" \
  --activate
```

**Refresh:** GuardDuty does **not** auto-refresh. Update the file in S3 → re-activate the IP set via `update-ip-set` (or the Console).

**Limits and org-wide behaviour:**

- **Trusted IP list:** one per account per region, up to 2,000 entries.
- **Threat IP list:** up to six per account per region, up to 250,000 entries combined.
- In an Organization, the **delegated GuardDuty administrator** manages a central trusted/threat IP list for member accounts.

**Common Anti-patterns (exam wrong answers):**

- *"Create a suppression rule to stop findings"* → wrong; findings are still generated (and billed) → doesn't match "no longer produces findings."
- *"Upload trusted IPs directly through the GuardDuty Console form"* → wrong; there is no in-Console form for the list content. **Must** be in S3.
- *"Use a threat IP list to whitelist internal IPs"* → wrong direction — that *increases* findings.
- *"Disable the finding type globally"* → nukes it everywhere, not just for these IPs. Blind spot for real attackers.
- *"Modify VPC Flow Logs to exclude those IPs"* → GuardDuty ingests Flow Logs *independently*; can't be filtered at that layer.
- *"Mark findings as suppressed in Security Hub"* → hides in Security Hub only; GuardDuty still generates and bills.

**Exam Triggers:**

- *"Trusted IPs no longer produce findings"* → **trusted IP list** referenced from S3
- *"Custom threat intel feed"* → **threat IP list**
- *"Hide known false positives, keep generating for audit"* → **suppression rule**
- *"Central IP list across the Org"* → GuardDuty **delegated administrator**

> *Mental model: **trusted IP list = allowlist that skips analysis** (no findings, no cost); **threat IP list = your own denylist** (extra findings); **suppression rule = filter on the output** (findings still generated, just archived). The verb in the question — "produce" vs "hide" vs "flag" — is the tell.*

#### GuardDuty vs Security Hub — when to reach for each (org-wide detection questions)

**A favourite SCS-C03 trap.** The stem describes multi-account monitoring, automatic remediation, and central visibility → the reflex is to reach for Security Hub. Often the leaner correct answer is **GuardDuty delegated administrator + EventBridge + Lambda + SNS** with no Security Hub involvement.

**The decision framework — requirement → service:**

| Stem phrase | Answer |
|---|---|
| *"Detect suspicious activity across all accounts"* | **GuardDuty** (delegated admin) |
| *"Aggregate findings from multiple security services"* (GuardDuty + Inspector + Macie + Access Analyzer) | **Security Hub** |
| *"Continuous compliance against CIS / PCI / AWS Foundational"* | **Security Hub standards** |
| *"Auto-remediate a finding"* | **EventBridge → Lambda / SSM Automation** |
| *"Notify on finding"* | **EventBridge → SNS** |
| *"Single pane of glass across regions and accounts"* | **Security Hub** |
| *"Centralize GuardDuty findings only"* | **GuardDuty delegated administrator** — no Security Hub needed |

**Requirement-to-service mapping table for the classic question:**

| Requirement | Leanest service | Does Security Hub help here? |
|---|---|---|
| Detect suspicious activity | **GuardDuty** | No — Security Hub *consumes* GuardDuty findings, doesn't add detection |
| Across all production accounts | **GuardDuty delegated admin** (org-wide auto-enable) | No — GuardDuty has native multi-account model |
| Auto-remediate | **EventBridge → Lambda** | No — Security Hub doesn't remediate |
| SNS notify on critical finding | **EventBridge → SNS** (or Lambda → SNS) | No |
| Centralise findings in a dedicated account | **GuardDuty delegated admin account** | No — GuardDuty centralises natively |

Every row resolves to GuardDuty + EventBridge + Lambda + SNS. Adding Security Hub is unnecessary indirection.

**GuardDuty multi-account org setup (memorise cold):**

1. **Delegated administrator** — nominate one account (usually the dedicated security/audit account) as GuardDuty delegated admin via AWS Organizations.
2. **Auto-enable on all accounts + all regions** — one toggle in the delegated admin account; new accounts added to the Org get GuardDuty enabled automatically.
3. **Findings centralise** in the delegated admin account by default — no cross-account plumbing.
4. **EventBridge rule in the delegated admin account** matches GuardDuty findings by severity → invokes Lambda.
5. **Lambda** runs remediation (quarantine SG, revoke sessions via `aws:TokenIssueTime`, snapshot EBS) *and* publishes to SNS.

**Numbered runtime flow:**

1. GuardDuty in a member account detects e.g. `UnauthorizedAccess:EC2/InstanceCredentialExfiltration` → generates finding.
2. Finding replicates to the delegated admin account (default behaviour once delegated admin is set up).
3. EventBridge rule in the delegated admin account matches on `source = aws.guardduty` + severity ≥ 7 → invokes Lambda.
4. Lambda takes remediation action + publishes to SNS.
5. SNS fans out to email / Slack / PagerDuty.

**When Security Hub IS the correct answer:**

- *"Aggregate findings from GuardDuty AND Inspector AND Macie AND IAM Access Analyzer"* → multi-source dashboard.
- *"Continuously check compliance against CIS / PCI / AWS Foundational Security Best Practices"* → Security Hub standards (this is Security Hub's *own* detection).
- *"Single pane of glass for security posture across all accounts AND regions"* → Security Hub with cross-region aggregation.
- *"Compare compliance scores between environments over time"* → Security Hub.

**Common Anti-patterns (exam wrong answers):**

- *"Enable Security Hub, aggregate GuardDuty findings, use Security Hub Custom Actions to trigger Lambda"* → works but adds an unnecessary layer for a pure remediation + notify workflow. Wrong when the stem doesn't ask for multi-source aggregation or compliance standards.
- *"Enable GuardDuty in each account, then manually copy findings to the audit account"* → wrong; delegated admin + auto-enable does this natively.
- *"Use CloudTrail Insights instead of GuardDuty"* → CloudTrail Insights is API-rate anomaly detection only; doesn't cover GuardDuty's threat range.
- *"Route findings from GuardDuty to Kinesis Firehose to S3 for the dedicated account"* → works for archival, not real-time remediation + notify.
- *"Enable Security Hub in each account and it will detect suspicious activity"* → Security Hub doesn't detect suspicious activity; it aggregates findings from services that do.

> *Mental model: **GuardDuty = generator**, **Security Hub = aggregator/scorecard**. Pick Security Hub only when the question asks you to combine multiple detection sources or run compliance-standard scoring. Otherwise **GuardDuty + EventBridge + Lambda + SNS** is the leanest correct answer — and the exam rewards leanness.*

### Detective

**Anchored against Splunk / graph-database forensics** — Detective ingests GuardDuty findings + VPC Flow Logs + CloudTrail and builds a **behavior graph** covering the last 12 months. Purpose-built for the "GuardDuty raised a finding — investigate without touching anything" phase.

**Two properties that make Detective the exam-canonical investigation tool:**

- **Read-only** — no remediation actions, no config changes. Zero risk to production during investigation.
- **Pre-built behavioural context** — no SQL to write. Detective already knows which principals + resources + flows are related and surfaces them via graph pivots.

**Numbered investigation flow (memorise for the "analyse in context without changes" question):**

1. GuardDuty raises a finding (e.g. `Impact:IAMUser/AnomalousBehavior`).
2. Analyst clicks **"Investigate in Detective"** directly on the finding — native cross-service link.
3. Detective opens the **entity page** for the IAM principal / instance / role.
4. Analyst pivots through built-in views:
   - **API call volume over time** (spikes vs baseline)
   - **Newly-observed API calls** (things this principal never did before)
   - **Geolocation history** (login sources)
   - **Resource interactions** (what did they touch?)
   - **Related principals** (roles they assumed, who assumed them)
5. Analyst confirms blast radius — all read-only.
6. Findings feed the incident report; remediation is a **separate phase** using tools like the `aws:TokenIssueTime` inline Deny (see IR playbooks below).

**The investigation vs remediation split (exam framing):**

SCS-C03 loves testing whether you separate the two phases:

- **Phase 1 — investigate** (Detective) — no changes, understand what happened.
- **Phase 2 — remediate** (only after investigation) — revoke sessions, rotate creds, isolate compute.

If the stem says *"analyse without making changes that could affect production"* → you're squarely in Phase 1. Any answer that touches IAM, EC2, or bucket config is wrong for that stem.

**Detective vs Security Hub vs Athena — the three "investigation" tools compared:**

| Tool | Strength | Weakness | When it's the answer |
|---|---|---|---|
| **Detective** | Pre-built graph + behavioural context; one-click from GuardDuty; read-only | Only useful once GuardDuty flags something | *"Analyse in context / behaviour graph / investigate without making changes"* |
| **Security Hub** | Cross-account aggregation, compliance scoring, dashboard of many findings | Doesn't drill into *why* / *how* a single finding happened | *"Aggregate findings from multiple services"* / *"single pane across accounts"* |
| **Athena on CloudTrail** | Arbitrary SQL over years of logs | Slower to set up, no pre-built graph, requires SQL | *"Ad-hoc SQL over historical logs"* / *"custom query with joins"* |

**What Detective is NOT:**

- **NOT Security Hub** — Security Hub is the scorecard/dashboard; Detective is the microscope on a single finding.
- **NOT a detection engine** — it consumes GuardDuty/Flow Logs/CloudTrail. Doesn't generate its own findings.
- **NOT for remediation** — read-only by design.
- **NOT a SIEM replacement** — no custom rule authoring, no alerting. Investigation-focused.
- **NOT the same as Access Analyzer** — Access Analyzer finds *public/cross-account access* on resources; Detective investigates *behaviour* of principals + resources.

**Common Anti-patterns (exam wrong answers):**

- *"Use Security Hub to investigate the specific GuardDuty finding"* — dashboard, not investigation. Wrong tool for "in context."
- *"Query CloudTrail with Athena to gather evidence"* — works but slow to set up and no pre-built graph. Fails "quickly."
- *"Enable CloudTrail Insights on the user"* — Insights is a *detection* mechanism (API-rate anomaly), not investigation. Also can't retroactively analyse.
- *"Delete or disable the IAM user first"* → violates "without making changes." Also removes forensic breadcrumbs.
- *"Attach a Deny-all IAM policy"* — same trap.
- *"Deploy a Lambda to query CloudTrail and email findings"* — requires code + deployment; not "quickly."
- *"Snapshot every EBS volume"* — massively overbroad for an IAM-user finding.

**Exam Triggers:**

- *"Analyse activity in context / behaviour graph"* → **Detective**
- *"Investigate a GuardDuty finding without remediating"* → **Detective**
- *"One-click pivot from GuardDuty to investigation"* → **Detective**
- *"Collect evidence quickly without affecting production"* → **Detective**, not Athena
- *"Aggregate findings from multiple services into one dashboard"* → **Security Hub** (different question)
- *"Ad-hoc SQL over months of CloudTrail data"* → **Athena** (different question)

> *Mental model: **GuardDuty raises the flag; Detective is the microscope you use before you touch anything**. Detective's behaviour graph is pre-built, read-only, and one click from any GuardDuty finding. When the exam says "analyse in context without making changes," it's Detective every time. Remediation is a separate phase using separate tools.*

### Security Hub

**Aggregator** — pulls findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partners into a single pane. Runs **security standards** (CIS, PCI, AWS Foundational) that continuously score your account.

**What it is NOT:**

- **NOT a detection engine** — it consumes findings, doesn't generate its own (except from its enabled standards checks).
- **NOT the same as Config** — Config tracks resource state; Security Hub tracks security findings.

### Amazon Inspector

**Anchored against a continuous vulnerability scanner (like Qualys / Tenable / Snyk).** Inspector is the **known-vulnerability layer** of the SCS-C03 detection stack — CVE-based, static analysis, agentless registration. Broader than "image scanning": it covers three resource types.

**Three resource types Inspector scans:**

| Resource | What Inspector scans for | How it discovers work |
|---|---|---|
| **EC2 instances** | OS-level CVEs + application-language CVEs + network reachability findings | Via the **SSM agent** — enabling Inspector auto-installs / auto-registers it |
| **ECR container images** | OS package CVEs + programming-language package CVEs (Python, Node.js, Java, .NET, Go, etc.) | Automatic on **push**; also re-scans on new CVE data |
| **Lambda functions** | CVEs in the function's code + dependencies (both zip and container-image Lambdas) | Automatic on **deploy**; also re-scans on new CVE data |

One-toggle-per-region to enable. No per-resource setup, no manual scan trigger.

**The continuous "new + re-scan old" model (favourite exam property):**

1. **Push a new image / launch a new EC2 / deploy a new Lambda** → immediate scan.
2. **A new CVE is published in the NIST NVD (or AWS's vulnerability database)** → Inspector automatically **re-scans every previously scanned resource** to check whether the new CVE applies. Findings appear without you doing anything.
3. **Update an existing image / patch an instance** → re-scan on the next event.

Consequence: an ECR image pushed six months ago still gets re-evaluated the moment a fresh Log4j-style CVE lands. This is what "continuously assess for new vulnerabilities" means on the exam.

**What Inspector is NOT (favourite exam confusions):**

- **NOT GuardDuty** — Inspector finds *known unpatched flaws* (static, CVE-based). GuardDuty finds *active malicious behaviour* (dynamic, behavioural). "You're vulnerable" vs "you're being attacked."
- **NOT Macie** — Macie scans **S3 objects for sensitive-data classification** (PII, PHI). Completely different job.
- **NOT AWS Config** — Config tracks resource *configuration* over time. Inspector tracks *vulnerabilities* in software running on those resources.
- **NOT Security Hub** — Security Hub is an aggregator/scorecard. It *consumes* Inspector findings; it doesn't do the scanning itself.
- **NOT the older Inspector Classic (v1)** — Inspector v2 (current, exam-relevant) is agentless-registration, continuous, multi-resource. Classic was agent-based and only did EC2.
- **NOT a runtime IDS** — no traffic inspection, no signature matching on live packets. Static analysis of installed packages.

**Threat + vulnerability stack — where Inspector sits:**

```text
                  ┌─────────────────────────────────────────┐
                  │       "What could go wrong?"           │
                  │        (vulnerability layer)           │
                  │              INSPECTOR                 │
                  └─────────────────────────────────────────┘
                  ┌─────────────────────────────────────────┐
                  │      "Is something wrong right now?"   │
                  │          (threat layer)                │
                  │             GUARDDUTY                  │
                  └─────────────────────────────────────────┘
                  ┌─────────────────────────────────────────┐
                  │        "Where is sensitive data?"      │
                  │          (data-classification layer)   │
                  │              MACIE                     │
                  └─────────────────────────────────────────┘
                  ┌─────────────────────────────────────────┐
                  │      "Show me all findings, scored"    │
                  │          (aggregator layer)            │
                  │           SECURITY HUB                 │
                  └─────────────────────────────────────────┘
```

**Common Anti-patterns (exam wrong answers):**

- *"Use Inspector to detect active attacks on EC2"* → wrong; that's GuardDuty. Inspector finds unpatched CVEs, not attackers.
- *"Inspector needs a manual scan schedule"* → wrong; it's continuous on both event (push/deploy) and CVE-database updates.
- *"Inspector requires you to install and manage an agent on every EC2"* → wrong; v2 uses the SSM agent, and Inspector auto-registers it.
- *"Use Inspector to classify sensitive data in S3"* → wrong; that's Macie.
- *"Inspector alone gives you compliance scoring against CIS/PCI"* → wrong; Inspector is a source. Compliance scoring against standards lives in **Security Hub**.

**Exam Triggers:**

- *"Continuously assess EC2 / ECR / Lambda for known vulnerabilities"* → **Inspector**
- *"Scan container images on push AND when new CVEs are published"* → **Inspector for ECR**
- *"Find CVEs in Lambda function dependencies"* → **Inspector for Lambda**
- *"Detect if the instance is being actively attacked / cryptomining"* → **GuardDuty**, not Inspector
- *"Classify sensitive data in S3"* → **Macie**, not Inspector
- *"Aggregate findings from Inspector + GuardDuty + Macie in one dashboard"* → **Security Hub**, consuming Inspector's output

> *Mental model: Inspector = **doctor doing a checkup for known diseases** (CVEs). GuardDuty = **security camera watching for break-ins** (behaviour). Both continuous, different jobs. ECR image scanning is one of Inspector's three arms, not its whole body.*

### Incident Response Playbooks

**Numbered response flow (canonical SCS pattern — memorise):**

1. **GuardDuty** raises finding
2. **EventBridge** rule matches the finding pattern
3. **SSM Automation** or **Lambda** runs the response (quarantine instance, revoke credentials, snapshot EBS for forensics)
4. **SNS** notifies the security team
5. **Detective** used to investigate root cause after the fire is out

#### SSM Automation runbooks — the auto-remediation engine

**Anchored against a serverless YAML workflow engine (like GitHub Actions or a Step Functions state machine, but scoped to AWS-API sequences).** A runbook is a JSON or YAML document defining an ordered list of steps; SSM executes them for you — no compute to run, no Lambda to package.

**Two flavours:**

- **AWS-managed runbooks** — hundreds pre-built and pre-tested, prefix `AWS-*` or `AWSSupport-*`. Free to use (you pay only for the underlying API calls or Lambda invocations, not the orchestration).
- **Custom runbooks** — you author your own for org-specific workflows.

**Step types (the SDK of runbooks):**

| Step type | What it does |
|---|---|
| `aws:executeAwsApi` | Call any AWS API directly (e.g. `ec2:StopInstances`, `s3:PutBucketEncryption`) |
| `aws:executeScript` | Run Python or PowerShell inline (fallback for logic not expressible as one API call) |
| `aws:invokeLambdaFunction` | Call an existing Lambda |
| `aws:runCommand` | Send an SSM Run Command to one or more EC2/on-prem instances |
| `aws:approve` | **Pause for manual approval** — a human clicks "approve" before workflow continues |
| `aws:branch` | Conditional branching on prior step outputs |
| `aws:sleep` / `aws:waitForAwsResourceProperty` | Wait for a resource to reach a state |

**AWS-managed runbooks worth knowing for SCS-C03:**

| Runbook | What it does |
|---|---|
| `AWSSupport-IsolateEC2Instance` | Swaps the instance's SG to a deny-all quarantine SG |
| `AWS-StopEC2Instance` | Stops an instance |
| `AWS-EnableS3BucketEncryption` | Turns on default encryption on a bucket |
| `AWS-DisablePublicAccessForSecurityGroup` | Removes `0.0.0.0/0` inbound rules |
| `AWS-EnableCloudTrail` | Creates/enables a trail with sensible defaults |
| `AWS-UpdateCFNStackWithApproval` | Pushes a CFN change but pauses for human approval |
| `AWS-PatchInstanceWithRollback` | Patches with automatic rollback on failure |

Browse them in the console under **Systems Manager → Documents → Owned by Amazon**.

**Why the exam prefers runbooks over "just write a Lambda":**

- **Pre-tested + AWS-supported** — the `AWS-*` runbooks are what AWS themselves use in Config auto-remediation, Security Hub Custom Actions, and Support tooling. Battle-hardened.
- **Retry + error handling built in** — each step has retry, timeout, and onFailure branches without you writing them.
- **Approval steps** — `aws:approve` gives you human-in-the-loop for high-blast-radius actions (approve before deleting a snapshot). A Lambda has to build this via SNS + custom flow.
- **Cross-account / cross-region built in** — one runbook execution can act on resources in many accounts/regions if the service role permits.
- **Cleaner CloudTrail audit** — one Automation execution ID ties every downstream API call together.
- **No code to maintain** — YAML instead of a Lambda function; easier to review in change control.

**Where SCS-C03 questions plug them in:**

1. **Config auto-remediation** — a non-compliant Config rule triggers a specified Automation runbook to fix it (e.g. `AWS-EnableS3BucketEncryption` on any bucket the `s3-bucket-server-side-encryption-enabled` rule flags).
2. **EventBridge → runbook** — GuardDuty finding fires EventBridge, which invokes an Automation runbook as the target (`AWSSupport-IsolateEC2Instance`) — native alternative to `EventBridge → Lambda`.
3. **Security Hub Custom Actions** — analyst clicks "Isolate Instance" on a finding; Security Hub fires an EventBridge event that triggers an Automation runbook.
4. **Maintenance Windows / State Manager** — scheduled runbook execution for routine hardening/patching.

**What SSM Automation runbooks is NOT:**

- **NOT SSM Run Command** — Run Command sends a single shell command to instances (`sudo apt-get update` across a fleet). Runbooks are workflows that can *include* a Run Command step but do more.
- **NOT Step Functions** — Step Functions is a general-purpose state machine for your own apps. Runbooks are specialised for AWS-resource orchestration.
- **NOT Lambda** — no code deployment; you author YAML/JSON. A runbook may *call* Lambda as a step.
- **NOT SSM Session Manager** — that's for shell access to instances.

**Exam Triggers:**

- *"Auto-remediate an unencrypted S3 bucket"* → **Config rule + Automation runbook** (`AWS-EnableS3BucketEncryption`)
- *"Automatically isolate an EC2 flagged by GuardDuty"* → **EventBridge → Automation runbook** (`AWSSupport-IsolateEC2Instance`)
- *"Change requires human approval before executing"* → **Automation runbook with `aws:approve` step**
- *"Serverless workflow to orchestrate several AWS API calls in response to a finding"* → **Automation runbook**, not Lambda

**Common Anti-patterns (exam wrong answers):**

- *"Write a Lambda function to remediate S3 encryption"* → works but reinvents `AWS-EnableS3BucketEncryption`; exam prefers the managed runbook.
- *"Use Step Functions for auto-remediation"* → Step Functions is for application state machines, not AWS-resource remediation.
- *"Use SSM Run Command to fix a Config non-compliance"* → Run Command sends OS-level commands to instances; it can't call AWS APIs like `s3:PutBucketEncryption` directly.

> *Mental model: **Automation runbooks = a serverless "if this then AWS API call, wait, next AWS API call" pipeline** with retries, human approval, and rollback built in. Whenever the exam says "auto-remediate" or "orchestrate a sequence of AWS actions in response to X," they're the AWS-native answer — leaner than Lambda, more governance-friendly than a bash script.*

#### Revoke compromised session credentials (the "stop exfil now" pattern)

**The canonical SCS-C03 "attacker holds stolen temp creds, stop them immediately, minimise disruption" question.** GuardDuty raises `Exfiltration:S3/AnomalousBehavior` (or `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`); the attacker is downloading using STS creds harvested from a compromised EC2 instance profile.

**The one right move:** attach an **inline Deny policy to the compromised IAM role** that revokes every session issued before "now" — the exact policy the IAM Console's **"Revoke sessions"** button generates:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RevokeOldSessions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-07-24T14:30:00Z"
        }
      }
    }
  ]
}
```

**Why this is the surgical answer:**

- STS creds live **~1 to 6 hours** — waiting them out means hours more exfil.
- IAM stamps every STS session with a `TokenIssueTime`. A Deny that fires when `TokenIssueTime < NOW` kills **every existing session on that role instantly** — the stolen creds go dead mid-request.
- **New sessions minted after the timestamp still work** — legitimate workloads that AssumeRole after the fix resume automatically.
- **No bucket-policy change** — every other principal reading the bucket keeps working. Zero collateral disruption.

**Numbered incident-response flow (memorise):**

1. **Revoke sessions on the compromised role** — attach the inline `aws:TokenIssueTime` Deny → stops in-flight exfil in seconds.
2. **Isolate the compromised EC2** — terminate, stop, or swap SG to deny-all-egress. Blocks new cred harvesting via IMDSv2.
3. **Snapshot** the instance's EBS volume for forensics before termination.
4. **Feed the finding** to Detective + Security Hub for blast-radius investigation (which objects were read? See S3 data events + CloudTrail).
5. **Hand off** to dev team for the permanent fix (patch the vulnerability, tighten the role's `s3:GetObject` scope — was `Resource: *` too broad?).

**The subtle IAM detail exam loves:**

- **`aws:TokenIssueTime`** — condition key for revoking active sessions.
- **Inline Deny wins** because IAM evaluates Deny before Allow — the role's Allow policy still grants `s3:GetObject`, but the explicit Deny short-circuits it.
- **`aws:MultiFactorAuthPresent`** — different key, for requiring MFA, not revocation.
- **`aws:SessionExpirationTime`** — when the session expires; not for revocation.

**Common Anti-patterns (exam wrong answers):**

- *"Terminate the EC2 instance"* alone → attacker already exfiltrated the creds; they keep working from the attacker's machine until natural expiry. Termination stops NEW cred harvesting but doesn't stop CURRENT exfil.
- *"Attach a Deny statement to the S3 bucket policy blocking all access"* → too disruptive; blocks every legitimate consumer. Fails the "minimise disruption" requirement.
- *"Rotate the IAM access keys"* → EC2 instance profiles don't use static access keys; there are no keys to rotate.
- *"Delete the IAM role"* → nukes the role for every legitimate workload using it; breaks any trust relationships depending on the ARN. Overkill.
- *"Enable S3 Object Lock"* → protects against *deletion*, not exfil / downloads.
- *"Modify the role's trust policy so EC2 can't assume it"* → stops future AssumeRole calls but doesn't kill sessions already outstanding — stolen creds keep working until expiry.
- *"Wait for the STS credentials to expire naturally"* → up to 6 hours of continued exfil. Not "immediate."

**Exam Triggers:**

- *"Attacker using compromised temp credentials"* + *"stop immediately"* → **revoke IAM role sessions via `aws:TokenIssueTime` inline Deny**
- *"Minimise disruption to legitimate users"* → surgical revocation, **not** a bucket-policy blanket Deny
- *"Compromised EC2 instance profile"* → dual action: revoke sessions + isolate the EC2
- *"Immediate action while permanent fix is in progress"* → **inline policy on the role**, not architecture changes

> *Mental model: the stolen creds are hostages. Deleting the role knocks down the whole building; a bucket-policy Deny cuts the water main. The **TokenIssueTime revocation** is a targeted taser — every session issued before the timestamp goes limp instantly, legitimate ones minted after keep working.*

#### Compromised EC2 with attached role — the three-layer combined lockdown runbook

**The canonical SCS-C03 "fastest way to completely block access from a possibly-compromised EC2 that must stay running" question.** Distinct from the two adjacent playbooks — *revoke sessions* (single lever) and *isolate for live forensics* (network-level, all-services) — this pattern is about **completely locking out an IAM role's access to a target resource** while keeping the instance available and running. The exam wants **all three layers applied together**, not a single fastest option.

**Why one action isn't enough — the three temporal windows:**

```text
     PAST                     PRESENT                    FUTURE
────────────────────────────────────────────────────────────────►
 already-issued           ongoing S3 calls          new creds requests
 STS creds cached          from cached creds         via IMDS
       │                          │                        │
       ▼                          ▼                        ▼
 Layer 1: revoke        Layer 2: bucket-policy   Layer 3: detach role
 sessions (aws:         Deny on role ARN         from instance profile
 TokenIssueTime)
```

Each layer closes a different temporal or scope gap. Any single layer alone leaves a window open.

**The three layers side-by-side:**

| # | Action | What it closes | Closes what gap the others don't |
|---|---|---|---|
| **1** | **Revoke all active sessions for the IAM role** (`aws:TokenIssueTime < NOW` inline Deny) | Existing cached STS creds — the ones an attacker may have already exfiltrated | Layer 3 doesn't kill cached creds (they remain valid ~6h); Layer 2 doesn't cover non-S3 access |
| **2** | **Update the S3 bucket policy to Deny the role's ARN** | Bucket-side authorisation lock scoped to this specific resource | Layer 1 protects the role globally but the bucket keeps trusting the role otherwise; adds defence in depth even if Layer 1 rolls back |
| **3** | **Remove the IAM role from the EC2 instance profile** (`DisassociateIamInstanceProfile`) | Future credential issuance via IMDS — no new STS tokens minted for the compromised instance | Layer 1 kills existing creds but IMDS immediately mints new ones (with new `TokenIssueTime`) unless the profile association is severed |

**The JSON each layer produces:**

**Layer 1 — inline Deny on the role (the console's "Revoke sessions" button generates this):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RevokeAllOutstandingSessions",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {
        "aws:TokenIssueTime": "2026-08-17T14:30:00Z"
      }
    }
  }]
}
```

Attached via `iam:PutRolePolicy` on the compromised role. Kills every session issued before the timestamp; sessions minted after (which shouldn't happen once Layer 3 is applied) work normally.

**Layer 2 — S3 bucket policy addition (in the bucket-owning account):**

```json
{
  "Sid": "DenyCompromisedRoleAccess",
  "Effect": "Deny",
  "Principal": { "AWS": "arn:aws:iam::<acct>:role/EC2-App-Role" },
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::sensitive-bucket",
    "arn:aws:s3:::sensitive-bucket/*"
  ]
}
```

Applied via `s3:PutBucketPolicy`. Bucket-side Deny that fires on every `GetObject` from the role, regardless of Layer 1 state.

**Layer 3 — API call, no JSON:**

```bash
# Find the association ID
aws ec2 describe-iam-instance-profile-associations \
  --filters "Name=instance-id,Values=<i-xxxxxxxxxxxx>"

# Disassociate
aws ec2 disassociate-iam-instance-profile \
  --association-id <association-id>
```

Instance is now running with no attached IAM role — IMDS returns no credentials on any subsequent request.

**Numbered runtime flow — the runbook (fire in parallel, sequentially in seconds):**

1. Security engineer determines the instance is compromised.
2. **Fire all three actions in parallel** via a script or the CLI in rapid sequence:
   - `iam:PutRolePolicy` — Layer 1 inline Deny with `aws:TokenIssueTime`.
   - `s3:PutBucketPolicy` — Layer 2 bucket policy Deny.
   - `ec2:DisassociateIamInstanceProfile` — Layer 3 detach.
3. Every existing S3 call from the instance fails (Layer 1 or Layer 2 catches it — whichever evaluates first).
4. Instance tries to fetch new creds via IMDS → no role association → IMDS returns nothing → SDK errors out (Layer 3).
5. Complete blocked state, seconds after issuing the three API calls.
6. Instance keeps *running* (satisfies the stem's "cannot immediately terminate") but has zero AWS API access.

**Why "fire in parallel" — the propagation-timing caveat:**

IAM is **eventually consistent**, not instant. Typical propagation is **1–5 seconds**; occasional worst case is tens of seconds during control-plane load. Individual layers:

- Layer 1 (IAM policy change) — propagates to IAM authorisation plane in ~seconds.
- Layer 2 (S3 bucket policy) — evaluated at S3; in practice often faster than IAM propagation for the specific service.
- Layer 3 (instance profile disassociation) — takes effect immediately (no more IMDS creds).

Firing all three in parallel means the earliest-propagating one starts blocking within seconds, and each subsequent layer completes independently. Sequential execution would still work but stretches the exposure window.

**Comparison with the two adjacent IR playbooks:**

| Playbook | When to reach for it | Uses |
|---|---|---|
| **Revoke sessions** (single lever, earlier subsection) | Small-scope incident; role compromise where the instance itself will be replaced immediately | Layer 1 alone |
| **This three-layer runbook** | Instance must stay running; complete role lockdown across all temporal windows | Layers 1 + 2 + 3 combined |
| **Isolate for live forensics (NACL)** | Memory preservation for forensic analysis; block ALL network traffic | Subnet NACL Deny — network-level, not IAM-level |

The three-layer runbook is the **IAM-level equivalent** of the NACL isolate pattern — where NACL blocks all network, the three-layer runbook blocks all IAM access via the role.

**The role-chaining edge case:**

If the compromised workload has chained `AssumeRole` from the instance role into a *different* role, Layer 1's `aws:TokenIssueTime` policy on the instance role does **not** touch the chained role's cached credentials. The attacker could still use the downstream role.

**Mitigation:** trace via CloudTrail for recent `AssumeRole` events originating from the compromised instance's role. Apply the three-layer runbook to every role in the chain.

**The clock-skew edge case:**

Layer 1's `DateLessThan: aws:TokenIssueTime` uses a wall-clock timestamp. If the timestamp written into the policy is stale (behind the actual TokenIssueTime of the most recently issued token), that token slips through. The IAM Console's "Revoke sessions" button handles this correctly; hand-crafted policies with a stale timestamp can miss. **Always use current time or slightly-future time.**

**What "fastest" means in this stem — subtle:**

The stem says *"fastest way to block further access."* This does NOT mean "which single action is fastest" — it means "how fast can we get to the completely-blocked state." Since IAM is eventually consistent (not instant), the fastest path to *complete* blocking is:

- Fire all three actions **in parallel**, not sequentially.
- Accept that each layer has its own few-seconds propagation.
- Confirm blocked state via CloudTrail (`errorCode: AccessDenied` on subsequent calls from the instance).

**What the plausible-looking wrong answers get wrong:**

- ***"Detach the IAM role from the EC2 instance"*** (single action) — leaves ~6h window while cached STS creds remain valid. Directionally right as **one** of three, but insufficient alone.
- ***"Revoke sessions only"*** — kills current sessions but IMDS immediately mints new ones with fresh `TokenIssueTime`, unless Layer 3 is applied.
- ***"S3 bucket policy Deny only"*** — blocks S3 but the role's cached creds still work against other AWS services.
- ***"Terminate the EC2 instance"*** — stem explicitly says instance cannot be terminated.
- ***"Isolate with a Deny NACL"*** — works but breaks the critical application (network-level isolation).
- ***"Rotate the IAM role's trust policy"*** — doesn't kill existing sessions; would take effect on next `AssumeRole`.
- ***"Delete the IAM role"*** — destructive; breaks other consumers; requires deleting attached policies + instance profile associations first, so it's slow.

**Exam Triggers:**

- *"Fastest way to block further access from compromised EC2 with attached role, keep instance running"* → **three-layer runbook** (revoke sessions + bucket policy Deny + detach role)
- *"Compromised EC2, immediate lockdown of IAM role"* → **three-layer runbook**
- *"Kill outstanding sessions from a compromised role"* → **Layer 1 only** (`aws:TokenIssueTime` inline Deny)
- *"Block instance's network traffic for forensics"* → **NACL isolate** (different playbook — see earlier subsection)
- *"Bucket-side lock against a specific role"* → **Layer 2 only** (bucket policy Deny with principal ARN)

**Common Anti-patterns:**

- Treating this as a single-action question — the exam wants the runbook, not one lever.
- Assuming "instant" propagation — IAM is seconds-latent; fire in parallel to minimise window.
- Missing role chaining — an attacker who chained roles keeps downstream access unless you revoke there too.
- Forgetting Layer 3 — cached creds get killed by Layer 1, but IMDS mints new ones unless you detach.
- Forgetting Layer 2 — makes the response depend entirely on IAM propagation; bucket-side Deny adds independent defence.

> *Mental model: **a compromised EC2 with an attached IAM role has three separate access surfaces that a complete response must close**: (1) already-cached STS tokens, (2) the target resource's authorisation, and (3) IMDS's ability to mint fresh tokens. Layer 1 (revoke sessions via `aws:TokenIssueTime`), Layer 2 (bucket-policy Deny on role ARN), and Layer 3 (detach role from instance profile) address these three surfaces respectively. The exam's "fastest way to block further access" means fastest to the **completely-blocked state** — which requires all three fired in parallel, not any single "fastest" lever. Miss any layer and you leave a temporal or resource-scoped window. The IAM-level equivalent of the NACL isolate pattern.*

#### Isolate a compromised EC2 for live forensics — NACL beats Security Group

**The canonical SCS-C03 "isolate but preserve memory" question.** Stem hints:

- *"Keep the instance running for investigation / memory preservation"* → not `StopInstances` / `TerminateInstances`.
- *"Blocks traffic as quickly as possible"* → kill **existing** connections, not just new ones.
- *"Only resource in the subnet"* → the enabling constraint that makes NACL safe here.

**Answer:** create a **new NACL with explicit Deny for all inbound + outbound** and associate it with the subnet.

**Why NACL beats Security Group for immediate containment:**

| | Security Group | NACL |
|---|---|---|
| Stateful? | **Yes** — established connections tracked | **No** — every packet evaluated independently |
| Effect on *existing* TCP flows when rule changes | **Continue** until the connection-tracking entry expires (can be hours) | **Killed on the next packet** (blocked immediately) |
| Deny rules | No — SGs are allowlist-only | Yes — explicit Deny available |
| Scope | Attached per ENI/instance | Attached per subnet |
| Fit for "kill traffic now" | ❌ new flows blocked, old flows persist | ✅ everything drops immediately |

The critical exam nuance: **SG rule changes do not terminate existing connections.** Because the attacker has *active* network connections in the stem, an SG change would leave them running until their TCP state ages out. NACL-level Deny stops every packet on the next hop.

**Why the "only resource in the subnet" phrase matters:** NACLs are subnet-wide — a Deny NACL would kill traffic for every instance in that subnet. When only the compromised instance is there, associating a Deny NACL has zero collateral impact. In shared subnets you'd fall back to an isolation SG on the ENI (accepting the "existing connections linger" trade-off) or move the ENI, but this question deliberately rules that out.

**Numbered isolation flow:**

1. **Create a new NACL** in the same VPC with `Deny` on `0.0.0.0/0` for both inbound and outbound (all protocols, all ports).
2. **Associate the NACL with the subnet** → replaces whatever NACL was there (a subnet has exactly one NACL). Every existing packet flow drops.
3. **Do not stop/terminate the instance** — RAM contents survive only in a running instance; memory forensics requires the process still to be live.
4. **Snapshot the EBS volume(s)** for disk forensics.
5. **Preserve memory** — capture via EC2 Instance Connect (if the isolation NACL still allows the specific security-team CIDR — usually you'd allow a jump-box IP explicitly in the NACL rules) or via SSM Session Manager **only if you carved a narrow allow rule for the SSM endpoints** before locking down. Otherwise memory capture must happen via console-mounted tooling on a rescue instance.
6. **Tag the instance** as `IncidentResponse:Quarantined` for downstream audit.
7. Hand off to Detective + Security Hub for blast-radius investigation.

**Order-of-operations warning:** a fully deny-all NACL cuts off SSM Session Manager, IMDSv2 access from remote tooling, and any other AWS-service call from the instance. If your runbook needs SSM connectivity for memory dumping, either:

- Add a narrow allow rule for the SSM VPC endpoint IPs before the Deny becomes total, or
- Accept that further work will be console/EBS-driven.

**Why the plausible-looking alternatives are wrong:**

- *"Change the instance's Security Group to a deny-all SG"* → SGs are stateful; **existing connections continue**. Fails "as quickly as possible."
- *"Modify the SG on the ENI to remove the current inbound rule"* → same trap; new inbound blocked, established flows persist.
- *"Stop or terminate the EC2 instance"* → destroys RAM state; fails the "memory preservation" requirement.
- *"Detach the ENI"* → drops network but is disruptive and doesn't preserve the connections in a state investigators can trace; also, some instance types don't support ENI detach on the primary interface.
- *"Add an outbound-deny rule to the route table"* → route tables don't have Deny; you can only remove routes (which affects only new lookups).
- *"Use AWS Network Firewall to block traffic"* → adds a component that isn't already present; slower than an NACL swap.
- *"Delete the VPC / subnet"* → nukes everything, disruptive, and can't delete a subnet with a running instance anyway.

**Exam Triggers:**

- *"Isolate an EC2 but keep it running for memory forensics"* → **NACL with Deny rules on the subnet** (assuming instance is alone in the subnet)
- *"Block traffic as quickly as possible"* + active existing connections → **NACL**, not SG
- *"Only resource in the subnet"* → the enabling constraint for the NACL answer
- *"Isolate compromised EC2 in a shared subnet"* → different question — use an **isolation SG on the ENI** (accepts existing-connection lag) or move the ENI to a quarantine subnet

> *Mental model: **SG = doorman with a memory** (once a guest is in, changing the guest list doesn't kick them out until they leave). **NACL = airport security scanner** (every packet re-screened, ban list applied instantly). For "kill traffic now, keep the box running" — NACL every time.*

#### AWS-notified-you-of-compromise — the 6-step account-compromise playbook

**Distinct from a GuardDuty finding.** When *AWS itself* (Trust & Safety / Abuse Response) notifies you of suspicious activity — usually because an access key leaked publicly, cryptomining was detected on your fleet, or unusual API activity fired their internal alarms — a specific containment procedure kicks in. The exam tests this as a "before responding to AWS Support" question.

**The containment triangle (the three actions the exam usually picks):**

1. **Rotate and delete exposed IAM access keys.** Deactivate + delete any static credentials that could be compromised. Create new keys and update wherever they're used. Also rotate console passwords for potentially affected IAM users.
2. **Review CloudTrail logs for unauthorized activity.** Look for API calls from unfamiliar IPs / regions / user agents, unusual timestamps, `iam:Create*` calls (attacker persistence), `sts:AssumeRole` from external principals, resource creation you don't recognise.
3. **Delete any resources you did not create.** Rogue EC2 instances (often cryptomining), unfamiliar IAM users / roles / access keys (backdoors), unauthorised security groups, snapshots, S3 buckets, Lambda functions. Attackers plant persistence + monetise.

**The full six-step AWS-documented playbook (memorise all six to spot the correct three in variants):**

| # | Step | Why |
|---|---|---|
| 1 | **Change the root user password + enable MFA on root** | Root is the ultimate backdoor — take it out of the attacker's hands first |
| 2 | **Rotate and delete exposed IAM access keys** | Kill the static credentials the attacker likely used |
| 3 | **Delete unauthorized IAM users; rotate legitimate IAM user credentials** | Remove backdoors + refresh compromised auth |
| 4 | **Delete resources you did not create** (EC2, snapshots, SGs, roles, buckets, Lambdas) | Attackers plant persistence + revenue-generating resources |
| 5 | **Respond to the AWS Support case** with what you've done | Support may lift throttles / share more details |
| 6 | **Follow up with root-cause analysis** — how did they get in? | Prevent recurrence (leaked key on GitHub, phished user, exposed CI credential, etc.) |

**Why the containment steps come *before* responding to Support:**

The stem's *"before responding to AWS Support"* is the tell. AWS Support flagged the compromise — they expect *you* to have contained it before you reply. Support isn't going to fix the compromise for you; they've told you what's wrong and are waiting for confirmation you've cut the attacker off. Responding without containing first is the anti-pattern.

**Post-containment hardening (Step 6 territory — the exam's follow-up-question pool):**

- Enable **MFA on root and all IAM users** if not already.
- Enable **GuardDuty** across all regions (future behavioural detection).
- Enable **CloudTrail** across all regions + log file integrity validation.
- Add an **SCP denying root usage** in member accounts (org-wide guardrail).
- **Scan public repos** (GitHub secret scanning) for leaked keys — the leading cause of AWS account compromise.
- **Rotate KMS keys, Secrets Manager secrets, Parameter Store SecureStrings** the attacker may have accessed.
- Enable **IAM Access Analyzer** to find any resources exposed externally.

**Common Anti-patterns (exam wrong answers):**

- *"Contact AWS Support first and let them investigate on your behalf"* → Support triggered the notification; they won't do the investigation for you.
- *"Wait to see if the activity continues"* → indefinite exposure; the whole point is "before responding."
- *"Terminate your entire AWS account"* → nuclear; loses legitimate workloads.
- *"Enable AWS Shield Advanced"* → DDoS protection, unrelated to compromise.
- *"Enable GuardDuty after the notification arrives"* → helpful for future, doesn't investigate the past compromise. Should already have been on.
- *"Restore all resources from the latest backup"* → premature; without root-cause you may restore over the attack pathway.
- *"Ignore the notification if users can still log in"* → the notification is about a specific principal / key, not overall availability.

**Exam Triggers:**

- *"AWS notified you of suspicious activity"* → **6-step compromised-account playbook**
- *"Before responding to AWS Support"* → **containment triangle** (rotate keys, review CloudTrail, delete rogue resources)
- *"After containment — how do we prevent recurrence?"* → **hardening: root MFA, GuardDuty, scan repos, IAM Access Analyzer, SCP denying root**

> *Mental model: an AWS-issued abuse notification puts you on the hook to prove containment before you reply. The **containment triangle** is: **cut off access** (rotate/delete keys) + **scope what happened** (CloudTrail review) + **remove backdoors** (delete rogue resources). Support is Step 5, hardening is Step 6 — neither is a substitute for the triangle. This is distinct from a GuardDuty-finding IR flow, where the trigger is internal AWS detection, not an external abuse report.*

##### The full AWS Knowledge Center recipe (11 actions, not 6)

**The 6-step summary above is an abstraction.** The actual [AWS Knowledge Center article on potential account compromise](https://aws.amazon.com/premiumsupport/knowledge-center/potential-account-compromise/) lists **11 discrete actions**. Different exam variants pull **any three** — the correct trio depends on the stem's wording:

| # | Action | Phase |
|---|---|---|
| 1 | Rotate + delete root and IAM access keys | **Containment** |
| 2 | Change root password + IAM user passwords | **Containment** |
| 3 | **Check your AWS bill** for unfamiliar charges / Regions / services | **Damage assessment** |
| 4 | Verify running EC2 instances / EBS volumes / snapshots / IAM users are yours | **Containment / assessment** |
| 5 | Delete resources you didn't create | **Containment** |
| 6 | Delete API keys and IAM users you didn't create | **Containment** |
| 7 | Review CloudTrail for unauthorised activity | **Investigation** |
| 8 | **Use AWS `git-secrets` to scan repos for leaked credentials** | **Root-cause analysis** |
| 9 | Enable MFA on root + all IAM users | **Hardening** |
| 10 | Respond to AWS Support with what you've done | **Follow-up** |
| 11 | Root-cause analysis + preventive controls | **Follow-up** |

**Two important ones that get missed on the exam:**

- **#3 Check the AWS bill.** Attackers show up on the bill — unusual services (Bedrock/SageMaker/GPU instances they don't normally use), unfamiliar Regions (attackers pick Regions where monitoring is weakest), a spike right at the compromise time. The bill often surfaces the *entire footprint* of the attack in one page. It's the fastest scoping tool most people ignore.
- **#8 `git-secrets`.** [github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets) is the AWS-published open-source tool that scans repos for AWS access key patterns. The leading cause of AWS account compromise is a developer committing an access key to a public GitHub repo — so *"scan for evidence of unauthorized use"* on the exam maps to running `git-secrets` against your codebase to find the leak source.

**Which trio does the exam pick? — depends on the stem's wording:**

| Stem phrase | Trio the exam wants |
|---|---|
| *"Before responding to AWS Support"* / *"immediate steps to contain"* | **Containment triangle** — #1 (rotate keys) + #7 (CloudTrail review) + #5 (delete rogue resources) |
| *"Handle this issue"* / *"actions to take"* (unqualified — broader read) | **Immediate + assess + prevent** — #1 (rotate keys) + #3 (bill check) + #8 (git-secrets scan) |
| *"Prevent recurrence after the incident"* / *"harden after cleanup"* | **Hardening** — #9 (MFA on root/users) + #8 (git-secrets in CI) + IAM Access Analyzer |
| *"How did they get in?"* | **Root-cause** — #8 (git-secrets scan) + #7 (CloudTrail review of AssumeRole / login events) |

The single most-common miss: **assuming every variant of this question wants the containment triangle.** It doesn't. Unqualified "handle the issue" wording invites the broader "one from each phase" trio (#1, #3, #8) — the same three the AWS Knowledge Center article itself leads with.

**Both trios are correct in their respective variants.** If the stem picks one over the other, it's telling you which phase to weight — read the verb.

**Anti-patterns still valid across every variant:**

- *"Contact AWS Support first and let them investigate"* → Support flagged the compromise; Step 10, not Step 1.
- *"Enable GuardDuty / Config / CloudTrail after the notification"* → should already be on; enabling now doesn't investigate the past compromise.
- *"Terminate the entire AWS account"* → nuclear.
- *"Enable AWS Shield Advanced"* → DDoS, unrelated.
- *"Restore from backup"* → premature; may restore over the attack pathway.
- *"Change the AWS Region for all resources"* → makes no sense.

> *Updated mental model: **AWS's own compromise playbook has 11 actions, not 6, spread across five phases** (containment → assessment → investigation → root-cause → hardening → follow-up). The exam picks any three. The stem's verb tells you which phase to prioritise — *"immediate containment"* picks Phase 1; *"handle the issue"* invites one from each phase; *"prevent recurrence"* picks hardening. The **bill check** (#3) and **`git-secrets` scan** (#8) are the two most commonly-missed actions — memorise them alongside the containment triangle.*

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

#### Federated-user forensics: identifying who took a destructive action

**The canonical SCS-C03 forensics question** — "a federated user terminated an EC2 instance; find them." The audit trail is a **relay race** because federated users have no persistent IAM identity — every AWS action logs the *assumed role*, never the human's name.

**The two events you must join:**

1. **`AssumeRoleWithSAML`** (or `AssumeRoleWithWebIdentity` for OIDC) — the moment the human's IdP-issued assertion is exchanged for AWS creds:
   - `userIdentity.principalId` — synthetic ID like `AROA1234:alice@company.com`
   - `requestParameters.principalArn` (the IdP) + `roleArn` (the role assumed)
   - **SAML NameID** (usually the email/UPN) — the "who" evidence
2. **`TerminateInstances`** (or any subsequent action) — sees the assumed role only:
   - `userIdentity.type` = `AssumedRole`
   - `userIdentity.arn` = `arn:aws:sts::acct:assumed-role/RoleName/session-name`
   - **`session-name`** (last path segment) — most IdPs set this to the user's email/UPN → often the shortcut

**Numbered forensic flow:**

1. Find the destructive event in CloudTrail Event History → `EventName = TerminateInstances`.
2. Note `userIdentity.arn` → extract the **role session name** (last segment). Often that's already the username.
3. If not, note the `eventTime` and `principalId` prefix (`AROAxxxx`).
4. Filter CloudTrail for `EventName = AssumeRoleWithSAML` around that time, matching the same `principalId` prefix or `roleArn`.
5. Read the SAML `NameID` in `requestParameters` → that's the federated user.

**Join key across events (in order of preference):**

- **`sts:sourceIdentity`** — immutable string the IdP passes at assume time; propagates to *every* downstream CloudTrail event. Requires `sts:SetSourceIdentity` in the trust policy + IdP configuration. Best possible attribution — collapses the two-event join to a single event.
- **Role session name** — usually set by the IdP to the user's email/UPN; visible in every subsequent event's `userIdentity.arn`.
- **`principalId` correlation** — fall back to matching `AROAxxxx:session-name` prefix between the destructive event and the `AssumeRoleWithSAML` event.

**Federation-type variations:**

| Federation type | Join event to look for |
|---|---|
| **SAML** (Okta / AD FS / PingFederate) | `AssumeRoleWithSAML` |
| **OIDC** (GitHub Actions, Google, IIC via OIDC) | `AssumeRoleWithWebIdentity` |
| **IAM Identity Center** | `AssumeRoleWithSAML` under the hood, but IIC's own logs give you the answer directly |
| **IAM users** (no federation) | Single event — `userIdentity.userName` is already the human |

**Modern one-step alternative — set it up before the incident:**

- Turn on **`sts:sourceIdentity`** in the SAML/OIDC trust policy — every downstream event carries the human's identity in a single field.
- **CloudTrail Lake** — SQL join of `TerminateInstances` to `AssumeRoleWithSAML` by `principalId` in a single query.
- **Athena on the org trail in S3** — same story at scale.

**Common Anti-patterns (exam wrong answers):**

- *"Query IAM for the user"* → IAM has no user record for federated identities; nothing to query.
- *"Check the IdP logs directly"* → the IdP knows who *logged in*, not what they did in AWS. Only useful if `AssumeRoleWithSAML` is missing (rare).
- *"Enable CloudTrail after the incident"* → too late; CloudTrail management events are on by default anyway, but the write-side actions must already have been logged.
- *"Use AWS Config to identify the actor"* → Config records resource state changes, not caller identity.

**Exam Triggers:**

- *"Federated user did X — identify them"* → **CloudTrail: destructive event → session name / `AssumeRoleWithSAML` join**
- *"Ensure future forensics is one-step"* → **enable `sts:sourceIdentity`** in the trust policy
- *"Attribute actions across an org trail"* → **CloudTrail Lake (SQL)** or **Athena on the S3-delivered trail**

> *Mental model: for federated users, the audit trail is a **relay race** — the destructive event holds the baton (session name), and `AssumeRoleWithSAML` holds the runner (the human). Join by `principalId` or session name. Configure `sts:sourceIdentity` up front and the race collapses to a single leg.*

#### Auditing configuration changes — the CloudTrail + Config + EventBridge trio

**The canonical "select three" pattern for any "review changes to resource X" question.** Whether the exam names security groups, NACLs, S3 bucket policies, IAM roles, or KMS keys — the three-layer audit trio is always the answer. Each layer covers a different flavour of "review."

| Layer | What it answers | Where you look |
|---|---|---|
| **CloudTrail** | *"Which API call caused this change? Who called it, from where, with what parameters?"* | Event History (last 90 days) or the S3-delivered trail; `userIdentity` field names the caller |
| **AWS Config** | *"What state was this resource in at time T? What changed between T and T+1?"* | Config Configuration Timeline for the resource, or Config Rules for continuous compliance |
| **EventBridge rule** on the CloudTrail event | *"Notify me the moment anyone modifies this."* | Real-time alert to SNS/Lambda; can also trigger auto-remediation |

The trio covers **history + state-over-time + real-time detection**. Missing any one is a partial answer.

**Generalised EventBridge event pattern (swap the `eventName` list for whichever resource type):**

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "RevokeSecurityGroupEgress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup",
      "ModifySecurityGroupRules"
    ]
  }
}
```

Target: SNS topic → email/Slack, or a Lambda that auto-remediates.

**What each layer gives you that the others don't:**

- **CloudTrail** is the audit-trail-of-record — the only layer that captures the exact API-call payload (parameters, source IP, user agent) and the *who* (calling principal ARN).
- **Config** is the *state* view — shows the resource as a whole across time. CloudTrail says "AuthorizeSecurityGroupIngress was called with these params"; Config says "the SG's rules were X before and Y after." Diff-over-time is easier to reason about here.
- **EventBridge + SNS/Lambda** is the *push* layer — CloudTrail and Config are historical/pull; alone they don't page anyone. Wire an EventBridge rule to make change detection push-based.

**Common Anti-patterns (exam wrong answers for "audit changes to resource X"):**

- *"VPC Flow Logs"* → traffic, not configuration. Common trap when the resource is SG/NACL/subnet.
- *"GuardDuty"* → behavioural threat detection, not config-change auditing.
- *"Amazon Inspector"* → CVE scanning, not change tracking.
- *"Trusted Advisor"* → best-practice snapshot (weekly cadence); doesn't track changes over time.
- *"Security Hub alone"* → aggregator; not itself a source of change history.
- *"IAM Access Analyzer"* → finds cross-account/public exposure, not change tracking.

**Exam Triggers:**

- *"Audit history of changes to \<resource\>"* → **CloudTrail** (API history) + **AWS Config** (state timeline)
- *"Real-time alert on modifications to \<resource\>"* → **EventBridge on CloudTrail events → SNS/Lambda**
- *"Continuous compliance check (e.g. no SG allows `0.0.0.0/0:22`)"* → **AWS Config managed rule** (`restricted-ssh`, etc.)
- *"What state was this resource in yesterday at 3pm?"* → **AWS Config Configuration Timeline**
- *"Who made this change and when?"* → **CloudTrail** `userIdentity` + `eventTime`

> *Mental model: **three complementary layers**. **CloudTrail = the API call log** (who did what), **Config = the state timeline** (what the resource looked like at time T), **EventBridge = the notifier** (tell me now). Any "audit / history / real-time notify" question resolves to picking one, two, or all three of these — and every alternative (Flow Logs, GuardDuty, Inspector, Trusted Advisor, Access Analyzer) answers a different question entirely.*

### VPC Flow Logs

**Anchored against a firewall log** — records IP traffic in/out of an ENI. Three levels: **VPC**, **subnet**, **ENI**.

- Deliver to CloudWatch Logs, S3, or Kinesis Data Firehose.
- **Sampling** — traffic captured is a sample; not every packet. Use for pattern analysis, not for guaranteed forensic completeness.
- Doesn't capture: DHCP, DNS to Amazon resolver, metadata service (169.254.x.x), Windows license activation.

### CloudWatch Logs + Metrics + Alarms

- **Metric filters** convert log patterns into CloudWatch metrics — e.g. count `"Root user access"` occurrences in CloudTrail logs → alarm on ≥1.
- **Contributor Insights** — top-N reports over log streams (top IPs, top failing users).

#### Durable log capture on Auto Scaling / stateless EC2

**The canonical SCS-C03 "logs lost on scale-in" question.** Whenever the stem says instance-local logs got lost during termination and asks for the "most efficient" durable solution → the answer is **CloudWatch Agent → CloudWatch Logs**, not a periodic S3 upload.

**Why continuous streaming beats periodic batch:**

- Any `s3 sync` on a cron / every-N-hours schedule still loses **up to N hours** of logs if the instance dies mid-cycle — the exact failure mode the question is punishing.
- CloudWatch Agent flushes every **~5 seconds** by default; worst-case loss on termination is that 5-second buffer.
- The agent is a single AMI install + one JSON config; no upload script, no cron, no S3 lifecycle policy, no IAM plumbing for the app.

**What CloudWatch Logs gives you natively:**

- **Retention per log group** — 1 day to 10 years, or `NEVER_EXPIRE`. Set once, done. No S3 lifecycle needed for the audit-retention part.
- **Encryption** — SSE-KMS with a customer-managed CMK on the log group for separation-of-duties (see Domain 5).
- **Metric filters + alarms** — free pattern-matching without setting up Athena.
- **Cross-account central log account** — via subscription filter → destination in the audit account.

**CloudWatch Logs retention values (memorise — the exam uses these exact periods):**

| Period | Days |
|---|---|
| 1, 3, 5, 7, 14 days | 1 / 3 / 5 / 7 / 14 |
| 30, 60, 90, 120, 150 days | monthly increments |
| 12, 18, 24 months | 365 / 545 / 731 |
| 3, 5, **6**, 8, 10 years | 1096 / 1827 / **2192** / 2922 / 3653 |
| Never expire | ∞ |

**6 years = 2192 days is a first-class option.** If the stem asks for a specific retention period like 5, 6, 7, 8, or 10 years, CloudWatch Logs supports it natively — no custom automation needed.

**Retention vs lifecycle policy — the terminology decoder (exam trap):**

The exam punishes anyone who conflates "delete after N years" across services. Two similar-sounding features, different owners:

| Feature | Service | What it does |
|---|---|---|
| **Retention** (per log group) | **CloudWatch Logs** | Deletes log events older than N days. First-class support for 6, 8, 10 years. |
| **Lifecycle policy** (per bucket + prefix) | **Amazon S3** | Transitions objects between storage classes (Standard → IA → Glacier) *and/or* deletes them after N days. |
| **Object Lock** (compliance / governance mode) | **Amazon S3** | Prevents deletion for a fixed period (WORM / legal hold). Different primitive — retention, not expiry. |

**One-line decoder:**

- *"Retain log events for N years"* + CloudWatch Logs stem → **retention setting** (never "lifecycle policy")
- *"Delete S3 objects after N years"* → **S3 lifecycle expiration action**
- *"Transition S3 objects to Glacier after N days"* → **S3 lifecycle transition action**
- *"Prevent deletion for N years (legal hold / WORM)"* → **S3 Object Lock**

**Why picking "lifecycle policy" in a CloudWatch-Logs stem is wrong:** the words *"lifecycle policy"* don't apply to CloudWatch Logs — there's no such setting there. Choosing that answer signals you also picked the wrong storage backend (S3 instead of CW Logs), which fails the "no data loss on scale-in" half of the requirement.

**The real-world hybrid pattern (also appears in exam questions):**

- **CloudWatch Logs** for hot / queryable logs (last 30–90 days).
- **Subscription filter → Kinesis Data Firehose → S3** for long-term cheap archive (Glacier after N days via S3 lifecycle).
- Best of both: near-real-time capture *and* cheap multi-year retention.

**A corrected S3-based answer (if the exam ever asks the reverse):**

- **ASG lifecycle hook** on `EC2_INSTANCE_TERMINATING` → holds instance in `Terminating:Wait` up to an hour so shutdown scripts finish.
- **Shutdown script** (systemd unit or lifecycle-hook consumer) → `aws s3 sync /var/log/app s3://…` before completion.
- Or **Fluent Bit / Firehose agent** streaming continuously to S3.
- Plus an **S3 lifecycle policy** for retention.
- Works but has more moving parts than CloudWatch Agent → why the exam rejects it as "most efficient."

**Common Anti-patterns (exam wrong answers):**

- *"Periodic S3 upload every N hours/days"* → still loses up to N hours on termination. Wrong for any "durability on scale-in" question.
- *"Persist EBS volumes past termination"* → creates orphan volumes to track; ASG default is delete-on-termination anyway.
- *"Mount EFS as shared log storage"* → works but adds a network FS to every worker, ties cost/throughput to fleet size, no native retention story.
- *"Use SSM Session Manager to grab logs before termination"* → manual, doesn't scale, doesn't cover unexpected terminations.
- *"Enable CloudTrail to capture the logs"* → CloudTrail is for API calls, not application logs.

**Exam Triggers:**

- *"Instance-local logs lost on termination"* + *"most efficient"* → **CloudWatch Agent → CloudWatch Logs**
- *"Retain for N years"* → **CloudWatch Logs retention** (never "lifecycle policy" — that's S3 vocabulary)
- *"Retain for exactly 6 years"* → CloudWatch Logs retention **= 2192 days** (first-class option)
- *"Cheap long-term archive of logs"* → **Subscription filter → Firehose → S3** with S3 lifecycle to Glacier
- *"Encrypt application logs with a customer-managed key"* → **CloudWatch Logs SSE-KMS on the log group**
- *"Prevent deletion of logs for legal-hold period"* → **S3 Object Lock**, not CloudWatch Logs retention

**More anti-patterns for the retention half:**

- *"Set CloudWatch Logs lifecycle policy to 6 years"* → the words "lifecycle policy" don't apply to CW Logs; there's only **retention**. The wording itself is the trap.
- *"Upload logs to S3 and configure a lifecycle policy to expire objects after 6 years"* → reintroduces the durability problem (S3 sync loses data on scale-in) even if the delete-after-6-years part is correct in isolation.
- *"Use S3 Object Lock for 6-year retention"* → Object Lock **prevents deletion** (WORM); it's a legal-hold primitive, not an expiry mechanism.
- *"Never Expire + Lambda that deletes old logs manually"* → drift-prone, reinventing native retention.

> *Mental model: CloudWatch Agent is a **fire hose that never sleeps**; any "every N minutes/hours" upload is a **bucket brigade** — buckets get dropped when the runner (instance) trips.*

> *Terminology mental model: "**Retention**" is CloudWatch Logs vocabulary. "**Lifecycle policy**" is S3 vocabulary. "**Object Lock**" is S3 WORM/legal-hold. Picking the wrong term reveals you chose the wrong storage backend — even if your instinct about "delete after N years" was correct.*

#### Lambda + CloudWatch Logs — write-side vs read-side troubleshooting

**The canonical SCS-C03 "Lambda logs aren't appearing / error loading Log Streams" question class.** The trap is that the *symptom* (can't see logs) looks like a read problem but the *cause* is almost always on the write side — the Lambda's execution role failed to create the log streams that would otherwise be visible.

**Two IAM sides — two completely separate principals, two completely separate action sets:**

| Side | Principal | Actions needed |
|---|---|---|
| **Write** (Lambda → CloudWatch Logs) | The Lambda's **execution role** | `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` |
| **Read** (User → CloudWatch Logs) | The **human's IAM principal** | `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `logs:GetLogEvents`, `logs:FilterLogEvents`, `logs:StartQuery`, `logs:GetQueryResults` |

Same-looking error message can point at either side. Every exam question has a tell.

**The write-side trio (memorise as a group — they always travel together for Lambda logging):**

```text
logs:CreateLogGroup    ← create the log group /aws/lambda/<fn-name>
logs:CreateLogStream   ← create the per-execution stream
logs:PutLogEvents      ← write events to the stream
```

The **most-missed action is `CreateLogStream`** because engineers hand-authoring the policy tend to think of the "group" and the "events" but forget the intermediate "stream" layer. Symptom: log group exists, but console shows *"error loading Log Streams"* because no streams were ever created.

**The CloudWatch Logs hierarchy — three levels, three IAM actions:**

```text
Log Group      (/aws/lambda/myFunc)              ← CreateLogGroup permission
  └── Log Stream  (2026/08/15/[$LATEST]abc123…)  ← CreateLogStream permission
        └── Log Event  ("START RequestId: …")    ← PutLogEvents permission
```

Miss any one and the pipeline breaks at that level:

- Miss `CreateLogGroup` → group never created → downstream stream/event creation fails.
- **Miss `CreateLogStream`** → **group exists but no stream inside** → `PutLogEvents` fails with `ResourceNotFoundException`; console shows *"error loading Log Streams."*
- Miss `PutLogEvents` → stream created but never populated → empty streams appear.

**AWS-recommended shortcut — `AWSLambdaBasicExecutionRole`:** the managed policy that grants all three write-side actions in one attach. Whenever the Lambda console creates a new function, this is what it attaches by default. Any hand-authored replacement almost always forgets `CreateLogStream`.

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
        ],
        "Resource": "*"
    }]
}
```

**Three signals for telling write-side vs read-side apart on the exam:**

### Signal 1 — the person diagnosing has admin

If the stem says *"the specialist has administrator permissions"* → **the read side is already covered.** Admin has `logs:*` including all reads. The failure has to be upstream — the write side.

If the stem instead says *"the specialist has only [narrow policy]"* → then check whether they also have logs read permissions.

### Signal 2 — the exact error text

- *"Access denied"* / *"not authorized"* / *"AccessDenied"* → the *user's* permissions are the ceiling → **read side**.
- *"Error loading log streams"* / *"no log streams found"* / *"resource not found"* → the streams don't exist → **write side**.

The phrasing *"error loading"* is ambiguous — sounds like a read failure but the exam pairs it with "specialist has admin" specifically so you rule out the read side.

### Signal 3 — which policy is on screen

**Whatever policy JSON the stem prints is the one you're being asked to fix.**

- If the stem shows the **Lambda execution-role policy** → write-side question. Look for missing `logs:*` actions in the trio.
- If the stem shows the **user's IAM policy** → read-side question. Look for missing `logs:Describe*` / `logs:Get*` / `logs:FilterLogEvents` / `logs:StartQuery` actions.

**Why "error loading Log Streams" is not really a read error:**

The console flow when a user clicks *"View logs in CloudWatch"*:

1. Console calls `logs:DescribeLogStreams` with the log group name — admin can read, this succeeds.
2. Log group exists (execution role had `CreateLogGroup`).
3. `DescribeLogStreams` returns an **empty list** — no streams were ever created (execution role lacked `CreateLogStream`).
4. Console UI can't render an empty list gracefully → shows *"error loading Log Streams."*

The API call *succeeded* — the user (admin) had read permission. But the *result* was empty because the write side never populated streams. Ambiguous UI wording → mistaken read-error interpretation.

**The two mirror-image exam question shapes:**

| Shape | Stem tells | Actor | Artefact shown | Fix |
|---|---|---|---|---|
| **Write-side failure** | *"Lambda logs not appearing / error loading Log Streams"* | Someone with admin | **Lambda execution-role policy** | Add missing `logs:*` action(s) to the execution role — usually `CreateLogStream` |
| **Read-side failure** | *"IAM user gets AccessDenied when viewing Logs Insights results"* | Someone with narrow permissions | **User's IAM policy** | Add `logs:StartQuery`, `logs:GetQueryResults`, `logs:DescribeLogStreams`, `logs:GetLogEvents` to the user |

The exam picks a side by (a) whose policy JSON is on screen and (b) whether the human has admin.

**KMS complications — logs encrypted with a customer-managed CMK:**

Both sides can fail if the log group uses SSE-KMS with a customer-managed key:

- **Write-side KMS failure** — execution role lacks `kms:Decrypt` / `kms:GenerateDataKey` on the CMK → writes fail with encryption errors. Also, the CMK's key policy must allow the `logs.<region>.amazonaws.com` service principal to use the key.
- **Read-side KMS failure** — user lacks `kms:Decrypt` on the CMK → they can list streams but can't read the event bodies (opaque or `DecryptionFailure`).

Both look like "logs aren't appearing" but the fixes are on opposite principals *and* on the KMS key policy.

**VPC-Lambda variation (bonus — appears in a different question class):**

If the Lambda runs inside a VPC and logs still don't appear even with all three permissions, the issue is usually **network reachability to CloudWatch Logs**:

- Lambda in a private subnet with no NAT gateway → can't reach `logs.<region>.amazonaws.com`.
- **Fix:** add a **CloudWatch Logs interface VPC endpoint** (`com.amazonaws.<region>.logs`) so Lambda sends logs privately, or add a NAT gateway.

**The Lambda-logs troubleshooting checklist (walk in order):**

| # | Check | Fix |
|---|---|---|
| 1 | Does the execution role have `logs:CreateLogGroup`? | Add it |
| 2 | Does the execution role have **`logs:CreateLogStream`**? | **Add it — most common miss** |
| 3 | Does the execution role have `logs:PutLogEvents`? | Add it |
| 4 | Is the log group name `/aws/lambda/<functionName>` (case-sensitive)? | Fix naming or scope the Resource ARN |
| 5 | Is there a KMS CMK on the log group the role can't access? | Add `kms:Decrypt` / `kms:GenerateDataKey`; update KMS key policy to allow `logs.<region>.amazonaws.com` |
| 6 | Is the function in a VPC without a Logs VPC endpoint or NAT? | Add a Logs interface endpoint |
| 7 | Has the function ever been invoked? | Invoke it once — no invoke = no logs |
| 8 | If the user is diagnosing, do they have read actions? | Add `logs:Describe*` / `logs:Get*` / `logs:FilterLogEvents` |

Rows 1–3 solved by attaching `AWSLambdaBasicExecutionRole`.

**Common Anti-patterns (exam wrong answers):**

- *"Give the diagnosing user more permissions"* — if they have admin, that's not the issue; the execution role is.
- *"Enable CloudWatch Logs in the region"* — Logs is always on; no service-level enable.
- *"Restart / redeploy the Lambda function"* — doesn't grant permissions.
- *"Grant `cloudwatch:*` to the execution role"* — wrong service; CloudWatch Metrics ≠ CloudWatch Logs. Action prefix is `logs:*`.
- *"Enable CloudTrail data events for Lambda"* — CloudTrail records API calls, not application logs.
- *"Increase Lambda memory / timeout"* — resource limits don't affect logging permissions.
- *"Add `s3:*` to the execution role"* — wrong service.
- *"Fix the IAM user's read policy"* when the artefact shown is the execution role — wrong side.

**Exam Triggers:**

- *"Lambda logs missing / 'error loading Log Streams' / admin diagnoses"* → **execution role missing `logs:CreateLogStream`** (or one of the trio)
- *"User can't run Logs Insights query"* → **user missing `logs:StartQuery` + `logs:GetQueryResults`**
- *"Lambda in VPC can't send logs"* → **CloudWatch Logs VPC interface endpoint** (`com.amazonaws.<region>.logs`) or NAT gateway
- *"KMS-encrypted log group + Lambda write fails"* → `kms:Decrypt` + `kms:GenerateDataKey` on the execution role + KMS key policy allow for `logs.<region>.amazonaws.com`
- *"Fastest way to grant a Lambda basic logging"* → attach the AWS-managed policy **`AWSLambdaBasicExecutionRole`**

> *Mental model: **Lambda CloudWatch logging has two IAM sides, one per principal.** Write side (execution role) needs the trio `CreateLogGroup` + `CreateLogStream` + `PutLogEvents`. Read side (user) needs `Describe*` + `Get*` + `FilterLogEvents` + `StartQuery`. The exam picks a side by whose policy is on screen and whether the diagnoser has admin. **"Error loading Log Streams" almost always means the write side failed to create streams — not a read-side denial.** Fastest write-side fix: attach `AWSLambdaBasicExecutionRole`. Fastest read-side fix: add the read actions to the user. When in doubt, follow the JSON — the exam is asking you to fix the policy it shows you.*

### Athena on Security Logs

Common SCS pattern: **CloudTrail → S3 → Athena** for ad-hoc "who did what when" queries. Same for VPC Flow Logs. Use **partition projection** on `year=/month=/day=` prefixes to keep query cost low.

### ELB Access Logs and Connection Logs (ALB / NLB)

**Canonical exam question: "centralize load balancer logs for audit + create metrics on TLS ciphers used by clients."** The trap is picking the wrong destination or the wrong query engine for one of the two halves.

**Two log types on ALB (know the difference):**

| Log type | Records | Availability |
|---|---|---|
| **Access logs** | Per-**request** metadata: URI, HTTP status, elb_status_code, target, latency, user agent, `ssl_cipher`, `ssl_protocol`, matched rule | ALB + NLB |
| **Connection logs** (added ~2023) | Per-**TLS handshake** metadata: client cert info, TLS version, negotiated cipher, connection outcome | ALB only |

For the "which ciphers are clients using?" question, either log type has the cipher field; **connection logs** are more focused if you don't need per-request detail.

**Three delivery destinations (updated 2024+ via unified vended-logs delivery):**

| Destination | Use case | What you pair with it |
|---|---|---|
| **Amazon S3** | Cheap long-term archive, compliance retention | **Athena** for SQL search (partition projection on `year=/month=/day=`) |
| **CloudWatch Logs** | Real-time search + native metric creation | **Logs Insights** for ad-hoc queries; **metric filters** or **Contributor Insights** for TLS-cipher metrics |
| **Amazon Data Firehose** | Stream to Splunk / OpenSearch / third-party SIEM, or S3 with transformation | Firehose delivery role + downstream sink config |

You pick the destination in the LB's Attributes tab when you enable the feature. Multiple destinations can be enabled simultaneously.

**Which destination for the "audit search + TLS cipher metrics" question:**

- **Cleanest single-destination answer (current AWS reality):** deliver to **CloudWatch Logs** → **Logs Insights** for audit search + **metric filter on `ssl_cipher`** for the cipher metrics. Single pipeline covers both halves.
- **Classic S3-based answer (older exam bank):** deliver to **S3** → **Athena** for audit search + **Contributor Insights** for cipher metrics (which requires bridging S3 → CloudWatch Logs via Firehose or Lambda, adding a moving part).
- **Modern hybrid for scale:** S3 (cheap archive + Athena for compliance) *and* CloudWatch Logs (real-time queries + metrics) enabled simultaneously.

If the exam is up-to-date on vended-logs delivery, the CW Logs answer wins on efficiency. If the answer choices still describe the classic pattern, S3 + Athena + Contributor Insights is the fallback.

**Data flow diagram:**

```text
┌──────────────┐    ┌─────────────┐   ┌──────────────┐
│     ALB      │───►│  S3 Bucket  │──►│    Athena    │  ← audit / archive
│ access +     │    │  (central)  │   │    (SQL)     │
│ connection   │    └─────────────┘   └──────────────┘
│    logs      │
│              │    ┌─────────────┐   ┌──────────────┐
│  (choose 1+  │───►│ CloudWatch  │──►│  Logs        │  ← real-time search
│ destination) │    │    Logs     │   │  Insights    │
│              │    │             │──►│  Metric      │  ← TLS cipher metrics
│              │    └─────────────┘   │  filter /    │
│              │                      │  Contributor │
│              │                      │  Insights    │
│              │                      └──────────────┘
│              │    ┌─────────────┐   ┌──────────────┐
│              │───►│  Firehose   │──►│  Splunk /    │  ← third-party SIEM
└──────────────┘    │             │   │  OpenSearch  │
                    └─────────────┘   └──────────────┘
```

**TLS listener security policy — the "restrict" side of the same question class:**

- Listener security policy (`ELBSecurityPolicy-TLS13-1-2-2021-06`, etc.) controls **which ciphers the LB will negotiate** — server-side enforcement.
- Logging/metrics tell you **what clients actually used** — audit / observation.
- Exam decoder: *"restrict clients to modern TLS"* → **listener security policy**. *"prove no client uses weak ciphers"* → **logs + metrics**.

**What ELB logging is NOT:**

- **NOT CloudTrail** — CloudTrail captures API calls (CreateLoadBalancer, ModifyListener), not per-request or per-connection data.
- **NOT VPC Flow Logs** — Flow Logs are network 5-tuples + bytes/packets. No HTTP or TLS metadata.
- **NOT the built-in ALB CloudWatch metrics** — those count aggregates per LB (`RequestCount`, `HTTPCode_Target_5XX_Count`, `ClientTLSNegotiationErrorCount`) but don't break down by *which cipher* clients used.
- **NOT Classic ELB access logs only** — Classic ELB is legacy; assume ALB/NLB on the exam unless stated.

**Exam Triggers:**

- *"Centralize ALB / NLB access logs, searchable"* → **S3 + Athena** (classic) or **CloudWatch Logs + Logs Insights** (modern)
- *"Metrics on which TLS ciphers clients use"* → **metric filter / Contributor Insights on `ssl_cipher`** field
- *"Restrict clients to modern TLS versions/ciphers"* → **ALB listener security policy**
- *"Per-TLS-handshake details including client cert"* → **connection logs** (ALB only)
- *"Ship LB logs to Splunk"* → **Firehose** destination

**Common Anti-patterns (exam wrong answers):**

- *"Use CloudTrail to audit ALB TLS ciphers"* — wrong log type; CloudTrail is API-level.
- *"Use VPC Flow Logs for TLS cipher analysis"* — wrong; Flow Logs have no L7 metadata.
- *"Use built-in ALB CloudWatch metrics for cipher breakdown"* — the built-ins don't break down by cipher; you need log-derived metrics.
- *"Send logs to EFS for centralization"* — regional, not native audit, not searchable at scale.
- *"Enable CloudTrail data events on the ALB"* — CloudTrail data events cover S3 objects and Lambda invokes, not ALB requests.

> *Mental model: ALB has **three logging destinations** — pick by downstream tool. **S3 → Athena** for cheap archival SQL; **CloudWatch Logs → Logs Insights / metric filters** for real-time search + native metrics; **Firehose → SIEM** for streaming into your existing security stack. The listener security policy is the *lock*; the logs are the *camera*.*

## Domain 3 — Infrastructure Security (20%)

### VPC Security (SG vs NACL deep dive)

**Anchored against a doorman + airport-security-scanner analogy.** Security Groups are the **doorman with a memory** — once a guest is checked in, changing the guest list doesn't kick them out; return traffic auto-flows because the SG *remembers* the outbound request. NACLs are the **airport security scanner** — every packet re-screened, no memory of prior packets, so return traffic needs its own explicit allow rule.

**Packet evaluation order (memorise cold):**

> **NACL inbound → SG inbound → subnet route table → SG outbound → NACL outbound**

For an inbound request, NACL fires first at the subnet boundary, then SG at the ENI. For an outbound reply, the reverse.

#### SG vs NACL — the full comparison

| Property | Security Group | NACL |
|---|---|---|
| **State** | **Stateful** — remembers connections; return traffic auto-allowed | **Stateless** — every packet re-evaluated independently in each direction |
| **Rule actions** | **Allow only** — no explicit deny; deny is implicit-by-absence | **Allow and Deny** — explicit deny rules supported |
| **Rule evaluation** | **All rules evaluated**; if any allows, packet passes | **First match wins** in ascending rule-number order; evaluation stops on first match |
| **Attachment scope** | Per-**ENI** (per-instance effectively) | Per-**subnet** (all ENIs in the subnet share it) |
| **Default posture** | Deny-all inbound, allow-all outbound (default SG) | Default NACL: allow-all in/out. Custom NACL: deny-all until rules added. |
| **Rule reference** | Can reference other SGs (`sg-abc123`) as source/destination | CIDR blocks only — no SG references |
| **Best for** | Application-tier access control (ENI-level) | Subnet-boundary defence-in-depth, explicit-deny for compliance |

#### Statelessness — the mechanic that trips exam candidates

**Mnemonic:** *"NACL forgets, SG remembers."* — both start with the same letter as the property they lack/have.

For an outbound-initiated TLS connection (EC2 → external HTTPS), the NACL must be configured on **both directions**:

- **Outbound rule:** allow TCP 443 (dst port) → covers the SYN and every subsequent client-to-server packet.
- **Inbound rule:** allow TCP **1024-65535** (dst port) → covers return traffic, because the server's SYN-ACK arrives back on the client's **ephemeral** destination port (not on 443).

Without the inbound ephemeral allow, the SYN-ACK is silently dropped and TLS never completes. With a stateful SG, this is invisible — the SG remembers the outbound request and permits the return automatically.

**Ephemeral port ranges (why 1024-65535 is the safe default):**

| Source | Ephemeral range |
|---|---|
| Linux kernel 2.4+ | 32768-60999 |
| Windows Server 2003 and earlier | 1025-5000 |
| Windows Server 2008+ | 49152-65535 |
| **NAT Gateway, ELB, Lambda** | **1024-65535** |
| **AWS-recommended catch-all for NACLs** | **1024-65535** |

AWS-managed services (NAT Gateway, ELB targets, Lambda ENIs) use the widest range, so `1024-65535` is the only safe inbound allow for return traffic.

#### Rule ordering — the specific-Deny-before-broad-Allow trap

**Scenario:** an EC2 in a public subnet needs outbound TLS on 443 **and** must **explicitly deny** inbound MySQL on 3306.

**Correct NACL config — DENY 3306 must have a LOWER rule number than the ephemeral ALLOW:**

**Inbound rules:**

| Rule # | Type | Protocol | Port | Source | Action |
|---|---|---|---|---|---|
| **90** | MySQL | TCP | **3306** | `0.0.0.0/0` | **DENY** |
| 100 | Custom TCP | TCP | **1024-65535** | `0.0.0.0/0` | ALLOW |
| * | ALL | ALL | ALL | ALL | DENY (implicit) |

**Outbound rules:**

| Rule # | Type | Protocol | Port | Destination | Action |
|---|---|---|---|---|---|
| 100 | HTTPS | TCP | **443** | `0.0.0.0/0` | ALLOW |
| * | ALL | ALL | ALL | ALL | DENY (implicit) |

**Why ordering matters:** 3306 is inside the ephemeral range 1024-65535. If the DENY 3306 rule is numbered **above** the ALLOW 1024-65535 (e.g. DENY at rule 110, ALLOW at rule 100), then:

1. Inbound packet destined for port 3306 arrives.
2. Rule 100 (ALLOW 1024-65535) evaluated → matches (3306 ∈ range) → **ALLOW applied. Evaluation stops.**
3. Rule 110 (DENY 3306) **never consulted** — the DENY is dead code.

Putting DENY 3306 at rule 90 forces it to fire first for any port-3306 packet, before the broader ALLOW is reached. This is the **specific-Deny-before-broad-Allow pattern** and it's what the exam tests.

#### Numbered packet walkthrough — outbound TLS on the correct NACL

1. **SYN out** — EC2 sends `src:10.0.1.20:51234 → dst:server:443`.
   - Outbound NACL: Rule 100 ALLOW 443 matches → **sent**.
2. **SYN-ACK in** — Server sends `src:server:443 → dst:10.0.1.20:51234`.
   - Inbound NACL: Rule 90 (DENY 3306) doesn't match (dst is 51234). Rule 100 (ALLOW 1024-65535) matches → **admitted**.
3. **ACK out** — EC2 sends `src:10.0.1.20:51234 → dst:server:443`.
   - Outbound NACL: Rule 100 ALLOW 443 matches again → **sent**.
4. **TLS ClientHello, ServerHello, application data** — each packet re-evaluated identically. NACL has **no memory** of steps 1-3.

**Attacker attempts MySQL — first-match-wins kills it:**

1. Attacker sends `src:attacker:52001 → dst:10.0.1.20:3306`.
2. Inbound NACL: Rule 90 (DENY 3306) matches → **DROPPED. Evaluation stops.**
3. Rule 100 never reached.

#### What it is NOT — SG vs NACL disambiguation

| It's not… | It's… |
|---|---|
| **SG with an explicit Deny rule** | SGs don't support Deny — only implicit deny by absence of an Allow |
| **SG needing return-traffic rules** | SGs are stateful — outbound rule alone permits return |
| **NACL with "all rules evaluated" logic** | NACL is first-match-wins in rule-number order |
| **NACL referencing another SG or PrefixList as source** | NACLs take CIDR blocks only |
| **NACL per-ENI attachment** | NACLs attach per-subnet — every ENI in the subnet shares them |
| **AWS Network Firewall for this scenario** | Overkill; a NACL Deny handles subnet-boundary block with zero extra infra |

#### Common Anti-patterns (exam wrong answers)

- *"Allow inbound TCP 443 for return TLS traffic"* → wrong; return arrives on ephemeral destination port, not 443. Allowing inbound 443 opens the instance to inbound web connections from anywhere.
- *"Configure the security group to deny inbound 3306"* → SGs don't support Deny. Absence-of-Allow is functionally similar but fails compliance requirements for an *explicit* Deny rule.
- *"Place DENY 3306 at rule 200, after the broader ALLOW at 100"* → dead code; ALLOW matches first for port 3306, DENY never reached.
- *"Allow inbound 32768-60999 (Linux ephemeral range only)"* → too narrow; NAT Gateway / ELB / Lambda use 1024-65535 and return traffic through those breaks.
- *"NACLs are stateful, no return-path rule needed"* → confuses NACL with SG. This is *the* trap the exam tests.
- *"Use ALLOW 0-65535 inbound"* → too broad; hides intent and defeats the point of an explicit deny policy.
- *"Change the route table to block MySQL"* → route tables control next-hop, not port-level filtering.

#### Exam Triggers

- *"Explicitly deny a specific port at the subnet boundary"* → **NACL** (SGs can't Deny).
- *"Block traffic immediately including existing connections"* → **NACL** (stateless — kills every packet on next hop; SG changes leave existing connections until TCP ages out).
- *"Outbound TLS + inbound explicit deny of DB port"* → **NACL with DENY at lower rule number than ephemeral ALLOW 1024-65535**.
- *"NACL rules not firing as expected"* → **check rule-number ordering — first match wins**.
- *"Instance can send but not receive"* → **stateless NACL missing return-path ephemeral allow**.
- *"Ephemeral ports"* → **1024-65535** for the safe catch-all.
- *"Reference another SG as source/destination"* → **SG only** — NACLs use CIDR blocks.
- *"Per-ENI access control"* → **SG** (NACLs are per-subnet).

> *Mental model: **NACL forgets, SG remembers.** SGs are stateful doorkeepers — once you're checked in, the return traffic flows automatically. NACLs are airport-security scanners — every packet re-screened independently, no memory of prior packets, both directions must be explicitly configured. This forces two mechanics for any outbound-initiated flow on a NACL: an **outbound allow** for the request path (e.g. TCP 443) AND an **inbound allow** for the ephemeral return path (1024-65535). If you also need to explicitly deny a well-known port that overlaps the ephemeral range (3306, 3389, 1433, 22), the DENY must be numbered **below** the ephemeral ALLOW — because NACLs evaluate ascending, first match wins, and 3306 is inside 1024-65535. Miss either mechanic and the config is silently broken.*

### AWS WAF, Shield, Firewall Manager

- **WAF** = L7 rules (SQLi, XSS, rate limits, geo, custom).
- **Shield Standard** (free, auto) vs **Shield Advanced** ($3k/month; cost protection, DRT, L7 protection).
- **Firewall Manager** = policy-based **enforcement** across an Organization for WAF + Shield Advanced + Network Firewall + SG audit.

### Network Firewall

**Anchored against a Palo Alto / on-prem network firewall** — stateful L3/L4/L7 with **Suricata rules**, deployed inline in a dedicated firewall subnet. Deep-packet inspection between VPCs (via Transit Gateway) or between VPC + internet.

### VPC Traffic Mirroring

**Anchored against a network tap in software.** Copies inbound + outbound packets from a source ENI to a target ENI / NLB / GWLB endpoint so an **out-of-band IDS/IPS/SIEM** can inspect the full packet contents. Not inline — mirroring is passive, so the IDS analysing packets can never break production traffic.

**When the exam wants Traffic Mirroring — the two phrases:**

- *"Full packet contents"* / *"deep packet inspection"* / *"inspect payload, not just metadata"* — rules out VPC Flow Logs (5-tuple metadata only, no payload).
- *"Third-party IDS / IPS / SIEM on a dedicated EC2 instance"* — you need somewhere to pipe the packets. Network Firewall doesn't distribute to your own instance; Traffic Mirroring does.

**The four objects (memorise this vocabulary):**

| Object | What it is |
|---|---|
| **Mirror source** | The **ENI** whose ingress + egress traffic you want to copy (attached to the app EC2s) |
| **Mirror target** | The **ENI** on the IDS instance, or an **NLB / GWLB endpoint** if fanning out to a fleet |
| **Mirror filter** | Rules selecting which packets to mirror (protocol, port range, CIDR, direction). Common start: all IPv4+IPv6, both directions |
| **Mirror session** | Ties source + target + filter together; has a **session number** used for priority when multiple sessions target the same source |

Traffic is copied via **VXLAN encapsulation** (UDP 4789). The IDS decapsulates before analysis.

**Numbered configuration flow:**

1. Deploy the IDS on a Nitro-based EC2 (m5n / c5n / r5n for high network throughput).
2. Create a **Mirror Target** pointing at the IDS instance's ENI (or an NLB fronting an IDS fleet).
3. Create a **Mirror Filter** — "all IPv4 + IPv6, both directions" to catch every packet, or scoped filters to reduce cost.
4. Create a **Mirror Session** per source ENI, pointing at the target + filter.
5. IDS receives VXLAN-encapsulated packets → decapsulates → inspects payloads → alerts.

**Constraints worth memorising:**

- **Source must be Nitro-based** (m5, c5, r5, m5n, c5n, r5n, and later). Older instance families can't be mirror sources — this is a common trap when the stem specifies a specific instance type.
- **Cross-VPC / cross-account mirroring** works via VPC peering, Transit Gateway, or AWS RAM sharing — useful for a central inspection VPC.
- **VXLAN overhead** ≈ 54 bytes per packet on the wire between source and target — plan bandwidth (the "m5n" hint in the exam scenario is about this).
- **Per-session per-hour cost** — filter aggressively if you don't need to mirror every byte.

**Inspection primitives — cheat-sheet:**

| Requirement | Answer |
|---|---|
| *"Full packet contents to a third-party IDS/SIEM"* | **VPC Traffic Mirroring** |
| *"L3/L4 metadata only, cheap"* | **VPC Flow Logs** |
| *"Inline stateful firewall with Suricata rules"* | **AWS Network Firewall** |
| *"Centralised inspection VPC for many VPCs, using third-party appliances"* | **Gateway Load Balancer (GWLB)** + partner appliances + Transit Gateway |
| *"Behavioural threat detection natively"* | **GuardDuty** |
| *"CVE / vulnerability scanning of packages"* | **Amazon Inspector** |

**Traffic Mirroring vs Network Firewall vs GWLB (the trio that gets confused):**

- **Traffic Mirroring** — passive out-of-band copy to *your own* IDS. Zero risk to production traffic. Best when you already own an IDS/IPS you want packets fed to.
- **Network Firewall** — inline stateful firewall AWS runs for you. Suricata rules. Enforcement, not just inspection. Best when you want AWS to do the L7 filtering.
- **Gateway Load Balancer (GWLB)** — inline transparent load balancer for a fleet of third-party firewall / IDS / IPS appliances. Best for scaling a *vendor* appliance (Palo Alto, Check Point, Fortinet) inline across many VPCs.

**Common Anti-patterns (exam wrong answers):**

- *"Enable VPC Flow Logs"* → 5-tuple metadata only; fails "full packet contents."
- *"Enable AWS Network Firewall"* → inline enforcement, doesn't pipe packets to *your* IDS instance.
- *"Route all traffic through the IDS as a NAT/inspection hop"* → turns monitoring into an availability bottleneck; disables source/dest check; complex route-table gymnastics.
- *"Install the IDS agent on each application instance"* → agent-based, misses attacks between hops and network-level anomalies. Also violates the *"dedicated IDS instance"* stipulation.
- *"Enable EC2 detailed monitoring"* → CloudWatch metrics only.
- *"Use GuardDuty as the IDS"* → GuardDuty is AWS-native behavioural detection; the stem specifies a *third-party* IDS running on the EC2.

**Exam Triggers:**

- *"Full packet contents / inspect payload / deep packet inspection"* → **VPC Traffic Mirroring**
- *"Third-party IDS on a dedicated EC2"* → **Traffic Mirroring** (mirror target = IDS instance ENI)
- *"Fanning out to a fleet of IDS instances"* → Traffic Mirroring target = **NLB or GWLB endpoint**
- *"Centralised inspection VPC for many source VPCs"* → **Traffic Mirroring + Transit Gateway + RAM sharing**
- *"Inline stateful firewall managed by AWS"* → **Network Firewall** (different question)
- *"Scale a vendor firewall appliance inline"* → **GWLB** (different question)

> *Mental model: Traffic Mirroring = **a network tap in software**, passive and out-of-band. Flow Logs give you the receipt (5-tuple); Traffic Mirroring gives you the entire package (payload). Whenever the stem says "full packet contents" or names a third-party IDS/SIEM on an EC2, it's Traffic Mirroring — pair it with a Nitro-based `n`-suffixed instance for the throughput.*

### PrivateLink, VPC Endpoints, Endpoint Policies

- **Gateway endpoints** (S3 + DynamoDB only, free) vs **Interface endpoints** (ENI-based, PrivateLink, $).
- **Endpoint policies** = IAM-style policy attached to the endpoint that restricts *which* S3 buckets / DynamoDB tables can be reached through it.
- **VPC peering vs PrivateLink** — PrivateLink is one-way, only exposes a service; VPC peering is bi-directional, whole-VPC.

### AWS IoT Core — policy variables and client-ID injection

**The canonical SCS-C03 "malicious IoT device manipulates client ID with injected characters to access unauthorized topics" question.** The vulnerability is using **client-supplied identity** in IoT policies; the fix is switching to **certificate-anchored identity variables**.

**The attack — why naive IoT policies fail:**

The vulnerable pattern:

```json
{
  "Effect": "Allow",
  "Action": ["iot:Subscribe", "iot:Publish"],
  "Resource": "arn:aws:iot:us-east-1:123456789012:topic/devices/${iot:ClientId}/*"
}
```

Looks safe — *"each client can pub/sub only to `devices/<their-id>/*`."* But **`iot:ClientId` is the string the client sends in the MQTT CONNECT packet** — attacker-controlled. Injection payloads:

- `ClientId = "*"` → matches every topic
- `ClientId = "#"` → MQTT single-level wildcard
- `ClientId = "victim/../attacker"` → path traversal
- `ClientId = "victim/#"` → wildcard escalation

The policy substitutes the client-supplied string directly into the ARN pattern, escalating access.

**IoT policy variables — the two categories (memorise which are safe):**

| Category | Variable | Trustworthy for authz? |
|---|---|---|
| **Client-controlled** | `iot:ClientId` | ❌ Attacker-controlled |
| **Client-controlled** | `iot:Connection.Thing.ThingTypeName` (derived) | ❌ Not cert-anchored |
| **Cryptographically-verified** | **`iot:Connection.Thing.ThingName`** | ✅ Only populated when cert is attached to a thing |
| **Cryptographically-verified** | `iot:Connection.Thing.IsAttached` (boolean) | ✅ Cert-anchored |
| **Cryptographically-verified** | `iot:Certificate.Subject.CommonName` | ✅ Signed by the CA |
| **Cryptographically-verified** | `iot:Certificate.Subject.Organization` | ✅ Same |

**Rule:** any IoT policy that uses `iot:ClientId` outside a *"ClientId must equal ThingName"* check has a client-ID-injection vulnerability.

**The two-part mitigation (the exam's canonical answer):**

1. **Replace `${iot:ClientId}` with `${iot:Connection.Thing.ThingName}`** in every Subscribe/Publish policy Resource — the thing name is tied to the device's registered X.509 certificate.
2. **Restrict the `iot:Connect` action so the client ID must equal the thing name** — via a Connect resource ARN like `client/${iot:Connection.Thing.ThingName}`. Rejects any client whose MQTT CONNECT string doesn't match its cert-verified identity.

**The fixed policy applying both mitigations:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OnlyConnectAsRegisteredThing",
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:us-east-1:123456789012:client/${iot:Connection.Thing.ThingName}"
    },
    {
      "Sid": "SubscribeOnlyToOwnTopics",
      "Effect": "Allow",
      "Action": "iot:Subscribe",
      "Resource": "arn:aws:iot:us-east-1:123456789012:topicfilter/devices/${iot:Connection.Thing.ThingName}/*"
    },
    {
      "Sid": "PublishOnlyToOwnTopics",
      "Effect": "Allow",
      "Action": "iot:Publish",
      "Resource": "arn:aws:iot:us-east-1:123456789012:topic/devices/${iot:Connection.Thing.ThingName}/*"
    }
  ]
}
```

**Numbered runtime flow — legitimate vs attacker:**

**Legit client `thing-1234`:**

1. Connects with X.509 cert (attached to thing `thing-1234`) + `ClientId = "thing-1234"`.
2. IoT resolves cert → thing name → sets `iot:Connection.Thing.ThingName = "thing-1234"`.
3. Connect policy resource `client/thing-1234` matches → Allow.
4. Subscribes to `devices/thing-1234/data` → matches → Allow.

**Attacker `attacker-XYZ` trying to spoof `thing-1234`:**

1. Connects with own cert (attached to thing `attacker-XYZ`) but sends `ClientId = "thing-1234"`.
2. IoT resolves cert → thing name comes from **the cert**, not the ClientId → `iot:Connection.Thing.ThingName = "attacker-XYZ"`.
3. Connect policy resource becomes `client/attacker-XYZ` but the client submitted `ClientId = "thing-1234"` → **mismatch** → Connect refused before any topic operation.

**Adjacent hardening layers worth pairing:**

- **AWS IoT Device Defender** — audits IoT Core config for anti-patterns (unauthenticated devices, certs used by multiple things, permissive policies). Detective.
- **IoT Just-in-Time Provisioning (JITP)** — auto-registers devices at first connect using their cert; ensures 1:1 cert-thing binding from the start.
- **AWS Private CA integration** — issue device certs from your own CA; ensures no self-signed / unauthorised certs.
- **`iot:Connection.Thing.IsAttached = true` condition** — require cert-thing binding as an additional check.
- **CloudTrail on IoT Core** — logs `Connect` events with the actual verified thing name for forensics.

**What plausible-looking wrong answers get wrong:**

- *"Use IAM policies for IoT Core"* — IoT Core uses its own IoT policies attached to certificates, not IAM identity policies. IAM covers the management-plane API, not MQTT.
- *"Rotate the certificate more frequently"* — doesn't prevent client-ID injection.
- *"Use MQTT username/password authentication"* — doesn't address the client-ID authorization problem.
- *"Enable AWS WAF on the IoT endpoint"* — WAF is HTTP/HTTPS; MQTT isn't in scope.
- *"Enable GuardDuty / CloudTrail"* — detective, not preventive.
- *"Add a validation Lambda before topic access"* — reinvents what `${iot:Connection.Thing.ThingName}` does natively; higher effort.
- *"Use device shadow to store expected ID"* — device shadow is for state sync, not auth.
- *"Set MQTT keepalive shorter"* — connection timeout; not related.
- *"Encrypt IoT messages"* — TLS is already in use; doesn't stop injection at authz.

**Exam Triggers:**

- *"Devices manipulate client ID / MQTT wildcards escalate access"* → **replace `iot:ClientId` with `iot:Connection.Thing.ThingName`** + **enforce ClientId = ThingName in Connect policy**
- *"Detect IoT anti-patterns / permissive policies"* → **IoT Device Defender**
- *"Auto-register devices on first connect"* → **IoT Just-in-Time Provisioning (JITP)**
- *"Issue device certs from a private CA"* → **AWS Private CA** integrated with IoT Core

> *Mental model: **in AWS IoT Core, `iot:ClientId` is client-supplied and never safe for authorization; `iot:Connection.Thing.ThingName` is cryptographically anchored to the device's registered X.509 certificate and is the only safe identity variable for topic-scoped policies**. The two-part mitigation for the character-injection attack class: (1) use `iot:Connection.Thing.ThingName` in every Subscribe/Publish policy Resource — never `iot:ClientId`; (2) force the connecting `ClientId` to equal the thing name via a Connect resource ARN like `client/${iot:Connection.Thing.ThingName}` — this rejects any client whose CONNECT string doesn't match its cert-verified identity at connect time, before any topic operation. Pair with Device Defender for continuous anti-pattern detection, JITP for automated cert-thing binding, and Private CA for controlled cert issuance.*

### EC2 Instance Connect / Session Manager — IAM requirements and misleading errors

**The canonical SCS-C03 "SSH from a laptop works but EC2 Instance Connect / Session Manager fails" question.** The exam trap: the surface error points at SSH-layer problems (host key validation failure, encryption errors), but the actual root cause is IAM permissions on the instance profile. AWS-native connection tooling requires the instance to be able to *call AWS APIs from inside itself* — traditional SSH does not.

**The two connection flows side-by-side:**

**Flow A — Traditional SSH (works even without any IAM):**

```text
┌─────────────────────┐            ┌─────────────────────────────────┐
│  User's laptop      │            │  EC2 instance                   │
│                     │            │                                 │
│  ssh -i key.pem     │            │  sshd on port 22                │
│  ec2-user@ip        │            │                                 │
│                     │            │  Instance profile: not needed   │
│                     │            │  SSM Agent: not needed          │
│                     │  TCP :22   │  Only needs:                    │
│                     ├──────────► │  - Port 22 reachable            │
│                     │            │  - authorized_keys populated    │
│                     │  RSA/Ed25519│                                │
│                     │  handshake │                                 │
│                     │  ◄───────► │                                 │
│                     │            │                                 │
│  Client validates   │            │                                 │
│  host key (TOFU     │            │                                 │
│  or known_hosts)    │            │                                 │
└─────────────────────┘            └─────────────────────────────────┘

No AWS API involvement anywhere. Peer-to-peer protocol.
```

**Flow B — EC2 Instance Connect (needs IAM on the instance profile):**

```text
┌─────────────────────┐            ┌─────────────────────┐            ┌─────────────────────────────────┐
│  User's browser or  │            │  AWS Instance       │            │  EC2 instance                   │
│  CLI (mssh)         │            │  Connect API        │            │                                 │
│                     │            │  + SSM services     │            │  ec2-instance-connect agent     │
│                     │            │                     │            │  SSM Agent (amazon-ssm-agent)   │
│                     │            │                     │            │                                 │
│                     │  (1)       │                     │            │  Instance profile MUST have:    │
│                     ├──────────► │                     │            │  - AmazonSSMManagedInstanceCore │
│                     │  SendSSH   │                     │            │    (or equivalent perms:        │
│                     │  PublicKey │                     │            │     ssmmessages:*, ec2messages:*│
│                     │  API call  │                     │            │     ssm:*)                      │
│                     │            │                     │            │                                 │
│                     │            │                     │  (2)       │                                 │
│                     │            │                     ├──────────► │  Push temp public key to        │
│                     │            │                     │  Push key  │  ~/.ssh/authorized_keys         │
│                     │            │                     │  (via SSM  │  (agent writes the temp key,    │
│                     │            │                     │  channel)  │   valid 60s)                    │
│                     │            │                     │            │                                 │
│                     │            │                     │            │  ← Requires AWS API path to     │
│                     │            │                     │            │    work. Broken without SSM     │
│                     │            │                     │            │    permissions.                 │
│                     │            │                     │            │                                 │
│                     │  (3)       │                     │            │                                 │
│                     ├────────────┼─────────────────────┼──────────► │  TCP :22 to sshd                │
│                     │  TCP :22   │                     │            │  Uses the temp public key       │
│                     │  with the  │                     │            │                                 │
│                     │  temp key  │                     │            │                                 │
│                     │            │                     │            │                                 │
│                     │  If step 2 │                     │            │                                 │
│                     │  fails →   │                     │            │                                 │
│                     │  step 3    │                     │            │                                 │
│                     │  fails at  │                     │            │                                 │
│                     │  handshake │                     │            │                                 │
│                     │  → user    │                     │            │                                 │
│                     │  sees "host│                     │            │                                 │
│                     │  key valid-│                     │            │                                 │
│                     │  ation     │                     │            │                                 │
│                     │  failure"  │                     │            │                                 │
└─────────────────────┘            └─────────────────────┘            └─────────────────────────────────┘

AWS API involvement mandatory. Instance profile permissions matter.
```

The critical difference: **Flow A is peer-to-peer** (no AWS API path). **Flow B has an AWS API round-trip** where AWS pushes a temporary SSH key to the instance via the SSM channel, and the instance must be able to *participate in that push* — which requires the SSM-related permissions on its instance profile.

**Session Manager follows the same pattern — same IAM requirement:**

```text
┌─────────────────────┐            ┌─────────────────────┐            ┌─────────────────────────────────┐
│  User's browser or  │            │  SSM service        │            │  EC2 instance                   │
│  aws ssm start-     │            │                     │            │                                 │
│  session            │  (1)       │                     │            │  SSM Agent running              │
│                     ├──────────► │                     │            │                                 │
│                     │  StartSess │                     │            │  Instance profile:              │
│                     │  ion API   │                     │            │   AmazonSSMManagedInstanceCore  │
│                     │            │                     │            │                                 │
│                     │            │                     │  (2)       │                                 │
│                     │  WebSocket │                     ├──────────► │  Establishes control channel    │
│                     │  session   │                     │  session   │  (via ssmmessages)              │
│                     │  ◄─────────┼─────────────────────┼──────────► │                                 │
│                     │            │                     │            │  ← Same IAM requirement as      │
│                     │            │                     │            │    Instance Connect. Same       │
│                     │            │                     │            │    failure mode without it.     │
└─────────────────────┘            └─────────────────────┘            └─────────────────────────────────┘

No port 22 exposure at all — everything through SSM.
```

Session Manager is often preferred over Instance Connect because it needs no inbound port 22 at all — but shares the exact same IAM prerequisite on the instance profile.

**Why the "host key validation failure" error is misleading:**

When Instance Connect's Step 2 (push temp key via SSM) fails silently because the instance profile lacks `AmazonSSMManagedInstanceCore`, the temp key is never written to `authorized_keys`. In Step 3, the client tries to SSH with the temp key. The instance doesn't recognise the key → sshd rejects the authentication attempt → the client's connection state manifests as a **handshake failure**, which some clients render as *"host key validation failure"* even though the actual failure is upstream in the temp-key push.

**The `AmazonSSMManagedInstanceCore` managed policy — what it grants:**

- `ssm:UpdateInstanceInformation` — register the instance with SSM.
- `ssmmessages:CreateControlChannel` / `CreateDataChannel` — the SSM Session Manager / Instance Connect data plane.
- `ec2messages:*` — SSM Agent messaging.
- `ssm:GetDocument`, `ssm:ListInstanceAssociations`, `ssm:PutInventory`, etc.

**This is the "table stakes" policy for any AWS-native instance-connection tooling** — Session Manager, Instance Connect, Run Command, Patch Manager, Fleet Manager, State Manager. Without it, all of these fail.

**Diagnostic checklist — "Instance Connect / Session Manager fails but SSH works":**

| # | Check | Fix |
|---|---|---|
| 1 | Does the instance profile have **`AmazonSSMManagedInstanceCore`**? | Attach it |
| 2 | Is the **SSM Agent** running on the instance? (`systemctl status amazon-ssm-agent`) | Start / install / update it |
| 3 | Can the instance reach SSM endpoints? (Public IP + IGW, NAT, or **VPC interface endpoints** for `ssm`, `ssmmessages`, `ec2messages`) | Add endpoints or fix networking |
| 4 | Is the **`ec2-instance-connect`** package installed on the instance? | Install (Amazon Linux 2 / most modern AMIs have it; Ubuntu / RHEL may need manual install) |
| 5 | Does the **caller's** IAM identity have `ec2-instance-connect:SendSSHPublicKey`? | Grant it to the user/role calling Instance Connect |
| 6 | Is the security group allowing inbound port 22 from Instance Connect's IP range (for public Instance Connect) or from the **EIC Endpoint** ENI? | Update SG |
| 7 | Is the instance registered as a managed instance in SSM Fleet Manager? | Should appear automatically once #1 + #2 + #3 are satisfied |

The **#1 check is the exam's answer** — the most-often-missed and produces the misleading "host key" error.

**The three IAM sides of Instance Connect (know each — the exam picks by wording):**

| Side | Principal | Permission |
|---|---|---|
| **Instance side** | Instance profile | **`AmazonSSMManagedInstanceCore`** (or equivalent) — this section |
| **Caller side** | IAM user / role making the connection | **`ec2-instance-connect:SendSSHPublicKey`** on the specific instance ARN |
| **Network side** | Security group / NACL / VPC endpoint | Port 22 inbound from Instance Connect's IPs or the EIC Endpoint's ENI |

**What plausible-looking wrong answers get wrong:**

- *"Rotate the host keys again"* — the visible error is misleading; fixing host keys doesn't touch the IAM path.
- *"Re-publish the fingerprint via the serial console"* — a real mechanism for a different scenario (Instance Connect browser client's fingerprint cache), not this one.
- *"Update `~/.ssh/known_hosts`"* — user-side host-key tracking; irrelevant to Instance Connect.
- *"The IAM policy for Instance Connect is missing permissions on the caller"* — that would fail with `AccessDenied`, not a host-key error.
- *"Enable MFA"* — Instance Connect doesn't require MFA at the SSH layer.
- *"The Instance Connect endpoint is misconfigured"* — would fail at connection setup, not handshake.
- *"Rotate the SSH key pair on the caller's side"* — Instance Connect uses temporary keys, not the caller's.
- *"Restart sshd"* — sshd is running (SSH from alternative sources succeeds).
- *"CloudHSM is unreachable"* — the CloudHSM mention in the stem is a red herring; the CloudHSM host-key rotation is orthogonal to the IAM issue.

**Common Anti-patterns for this question class:**

- Focusing on SSH-layer error text (host keys, fingerprints, encryption) — misleads away from IAM.
- Assuming CloudHSM / crypto involvement means the answer is crypto-related.
- Suggesting SSH config changes on the instance — doesn't touch the AWS API path.
- Forgetting that Session Manager has the same IAM prerequisite (they share the SSM channel).

**Exam Triggers:**

- *"Instance Connect fails / Session Manager fails / SSM Run Command fails"* + *"standard SSH works"* → **`AmazonSSMManagedInstanceCore`** missing from instance profile
- *"Misleading SSH-layer error but actual cause is IAM"* → check the **instance profile's managed policies** first
- *"AWS-native connection tooling requires IAM on the instance"* → the SSM-family policy
- *"Private subnet + Instance Connect"* → also need **EIC Endpoint** or SSM VPC endpoints (`ssm`, `ssmmessages`, `ec2messages`)

**Related to (but distinct from) the credential provider chain issue** (see [[aws-credential-provider-chain]]):

- Credential provider chain: "the SDK is using the wrong identity" — client-side SDK behaviour.
- This section: "the instance can't participate in the AWS-managed SSH push path" — instance-side IAM.

Both are "wrong-cause diagnostic" traps but for different mechanisms.

> *Mental model: **AWS-native instance connection tooling requires AWS-native permissions on the instance.*** Traditional SSH is a peer-to-peer protocol (no AWS API involvement); anything AWS-native — Instance Connect, Session Manager, Run Command, Patch Manager — requires the instance to *call AWS APIs from inside itself*, which needs an instance profile with **`AmazonSSMManagedInstanceCore`** (the "SSM-family enabler" managed policy). When AWS-native tooling fails but standard SSH works, the first thing to check is whether this policy is attached. The visible error may point at SSH-layer artefacts (host key validation, encryption) but the actual cause is usually IAM on the instance profile. Bonus: Session Manager needs no port 22 at all — everything routes through the SSM channel — making it the exam's preferred replacement for SSH in most modern scenarios.

### Session Manager Deep Dive

**The AWS-recommended SSH replacement.** Session Manager provides interactive shell + port forwarding + file transfer *without* opening any inbound ports on the instance. Everything flows through an outbound HTTPS/WebSocket tunnel between the instance's SSM Agent and the SSM data plane. For SCS-C03 this is the exam's default answer to any "give admins shell access to a private-subnet instance" question.

**Architecture — the WebSocket tunnel:**

```text
┌─────────────────────┐              ┌─────────────────────┐              ┌─────────────────────────────┐
│  Admin's browser or │              │  SSM service        │              │  EC2 instance               │
│  aws ssm start-     │              │  (control plane +   │              │                             │
│  session            │  (1)         │   data plane)       │              │  SSM Agent                  │
│                     ├────────────► │                     │              │  (outbound HTTPS to SSM)    │
│                     │  StartSession│                     │              │                             │
│                     │  API call    │                     │              │  Instance profile:          │
│                     │              │                     │              │  AmazonSSMManagedInstance-  │
│                     │              │                     │  (2)         │  Core (mandatory)           │
│                     │              │                     ├───◄──────────┤                             │
│                     │              │                     │  Agent opens │                             │
│                     │              │                     │  control     │                             │
│                     │              │                     │  channel     │                             │
│                     │              │                     │              │                             │
│                     │  (3)         │                     │              │                             │
│                     │◄─────────────┤                     ├──────────────┤                             │
│                     │  Bidirectional│                    │  Data plane  │                             │
│                     │  WebSocket    │                    │  bridged     │                             │
│                     │  data tunnel  │                    │  through SSM │                             │
└─────────────────────┘              └─────────────────────┘              └─────────────────────────────┘

No port 22, no sshd, no keys.  Zero inbound exposure.
Instance only has to reach SSM endpoints OUTBOUND.
```

Compare to Instance Connect's flow (previous section) — Session Manager is fundamentally different: **no port 22 at all**, no SSH handshake, no host keys. The instance is unreachable from outside its VPC's outbound path.

**The features that make Session Manager the exam's default modern-access answer:**

#### Feature 1 — Session recording to S3 / CloudWatch Logs

Sessions can be **fully recorded** to S3 buckets or CloudWatch Log groups. Every command, every keystroke, every screen output → captured verbatim, timestamped, and persisted.

Configuration via **Session Manager Preferences** (a special SSM document `SSM-SessionManagerRunShell` — actually a JSON preference stored per-region):

```json
{
  "schemaVersion": "1.0",
  "description": "Session Manager preferences",
  "sessionType": "Standard_Stream",
  "inputs": {
    "s3BucketName": "sessions-audit-bucket",
    "s3KeyPrefix": "sessions/",
    "s3EncryptionEnabled": true,
    "cloudWatchLogGroupName": "/aws/ssm/sessions",
    "cloudWatchEncryptionEnabled": true,
    "kmsKeyId": "arn:aws:kms:us-east-1:<acct>:key/<key-id>",
    "runAsEnabled": false,
    "runAsDefaultUser": ""
  }
}
```

Once configured, every session in that region is auto-recorded — no per-session opt-in. Meets compliance requirements (SOC 2, HIPAA, PCI-DSS) that mandate audit trails of administrative access.

**What Instance Connect can't do:** Instance Connect delivers a real SSH channel; you'd need to enable sshd session logging separately on each instance and ship the logs off. Session Manager gives this natively at the AWS layer.

#### Feature 2 — KMS encryption of session data

Two layers of encryption:

- **In transit**: session data flows over TLS to AWS's SSM data plane by default.
- **End-to-end encryption**: enable **KMS encryption on the Session Manager Preferences** (`kmsKeyId`) → session data is additionally encrypted between the client and the agent using a KMS-managed key. Even AWS's SSM service can't inspect the payload.

This is the exam's *"encrypted in transit end-to-end"* answer for interactive shell access.

**KMS permissions needed:**

- Admin's IAM identity: `kms:GenerateDataKey` on the CMK.
- Instance profile: `kms:Decrypt` on the CMK.
- KMS key policy: allow both principals.

#### Feature 3 — Private-subnet access via VPC endpoints

For instances in private subnets with no internet gateway or NAT, Session Manager works via three **VPC interface endpoints**:

- `com.amazonaws.<region>.ssm` — SSM control plane
- `com.amazonaws.<region>.ssmmessages` — Session Manager data plane (mandatory for Session Manager)
- `com.amazonaws.<region>.ec2messages` — SSM Agent messaging (mandatory)

Optionally also `com.amazonaws.<region>.s3` (Gateway) and `com.amazonaws.<region>.logs` if the sessions are logged.

With these endpoints, the instance:

- Has no public IP
- Has no NAT
- Has no inbound ports
- Reaches SSM privately over the AWS backbone

This is the **exam-canonical answer for "give admins shell access to a fully private-subnet instance"** — no bastion host required.

#### Feature 4 — Port forwarding

Session Manager can forward local ports through the SSM tunnel to a port on the instance (or, in the case of the Remote Port Forwarding document, to a target reachable *from* the instance):

```bash
# Forward local port 3306 to RDS reachable from the instance
aws ssm start-session \
  --target i-0abcdef \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"host":["rds.example.com"],"portNumber":["3306"],"localPortNumber":["3306"]}'
```

Use cases:

- **Reach an RDS instance** in a private subnet from your laptop via `mysql -h localhost -P 3306` — no public database, no VPN.
- **Reach a private webapp** via `curl localhost:8080` tunnelled to the private ALB.
- **RDP / VNC** on Windows / Linux GUI instances.

**Instance Connect can't do this** — it's SSH-only. Session Manager's port forwarding is a distinct capability.

#### Feature 5 — Session preferences with fine-grained controls

The preferences document controls behaviour per region:

- **`runAsEnabled: true` + `runAsDefaultUser`** — sessions run as a specific non-root OS user (least-privilege enforcement on the OS side).
- **`idleSessionTimeout`** — auto-terminate idle sessions after N minutes.
- **`maxSessionDuration`** — cap the total session duration.
- **`shellProfile`** — inject custom shell startup commands (e.g., load `~/.bashrc`, restrict PATH).

These provide OS-level guardrails on top of the AWS-side IAM controls.

#### Feature 6 — Cross-account SSM administration

Use SSM with **delegated administrator** (an account in the Org designated to run Session Manager across all member accounts) to give a central security team shell access to any instance without individual account admin roles. Same pattern as GuardDuty / Config delegated admin.

**IAM prerequisites — the two sides:**

| Side | Principal | Actions needed |
|---|---|---|
| **Admin (caller)** | IAM user/role starting the session | `ssm:StartSession` on the specific instance ARN + `ssm:TerminateSession` on their own sessions; optionally `ssm:ResumeSession` |
| **Instance** | Instance profile | **`AmazonSSMManagedInstanceCore`** (same as Instance Connect) |
| **KMS (if encrypting)** | Both sides via key policy | `kms:GenerateDataKey` (admin), `kms:Decrypt` (instance) |

The `ssm:StartSession` action on the admin side can be scoped by resource ARN:

```json
{
  "Effect": "Allow",
  "Action": "ssm:StartSession",
  "Resource": [
    "arn:aws:ec2:us-east-1:<acct>:instance/i-0abcdef",
    "arn:aws:ssm:us-east-1:<acct>:document/SSM-SessionManagerRunShell"
  ]
}
```

Or tag-based scoping — grant `ssm:StartSession` only when the target instance carries specific tags. Common pattern:

```json
{
  "Effect": "Allow",
  "Action": "ssm:StartSession",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringEquals": {
      "ssm:resourceTag/Environment": "dev"
    }
  }
}
```

Admin can only start sessions on `Environment=dev` instances.

**Session Manager vs Instance Connect — quick comparison for the exam:**

| Aspect | Session Manager | Instance Connect |
|---|---|---|
| Protocol | HTTPS/WebSocket to SSM | SSH on port 22 |
| Inbound port required | **None** | 22 (or EIC Endpoint ENI) |
| sshd running | Not needed | Yes |
| Session recording | ✅ Native (S3 / CW Logs) | ❌ Not built-in |
| KMS end-to-end encryption of session | ✅ Yes | ❌ (TLS only) |
| Port forwarding | ✅ Yes | ❌ |
| SSH tooling compatible (scp, PuTTY) | ❌ | ✅ |
| Private subnet | SSM VPC endpoints | EIC Endpoint |
| Instance profile requirement | `AmazonSSMManagedInstanceCore` | `AmazonSSMManagedInstanceCore` |
| Compliance-friendly (audit trail) | ✅ Best in class | Partial |
| Modern default | ✅ | Legacy transition option |

**Common Anti-patterns (exam wrong answers):**

- *"Use SSH with a bastion host in a public subnet"* — legacy pattern; Session Manager makes bastions unnecessary. Exam usually rejects bastion when Session Manager is an option.
- *"Open port 22 to the corporate CIDR"* — Session Manager needs zero inbound; opening 22 defeats the purpose.
- *"Store SSH keys in Secrets Manager"* — Session Manager needs no keys at all; better than "manage keys carefully."
- *"Use CloudTrail to record shell commands"* — CloudTrail records API calls, not shell content. Session Manager's session logging captures shell content.
- *"Enable IAM MFA to protect the instance"* — MFA governs the AWS API layer, doesn't protect the shell session content.
- *"Use AWS Systems Manager Run Command"* — Run Command executes a specific command, not interactive shell. Different feature. Same IAM prerequisite.
- *"Skip the SSM VPC endpoints"* — private-subnet instances without endpoints can't reach SSM; sessions fail.
- *"Enable Session Manager without recording"* — misses the compliance win.

**Exam Triggers:**

- *"Interactive shell / SSH replacement for EC2 without exposing port 22"* → **Session Manager**
- *"Record all administrative session content for audit"* → **Session Manager session logging** to S3 / CW Logs
- *"Reach a database in a private subnet from a laptop"* → **Session Manager port forwarding** (`AWS-StartPortForwardingSessionToRemoteHost`)
- *"Give admins shell access to instances in fully private subnets, no public IPs, no NAT, no bastion"* → **Session Manager + SSM VPC endpoints** (`ssm`, `ssmmessages`, `ec2messages`)
- *"End-to-end encrypted session data"* → **Session Manager with KMS key** in preferences
- *"Central security team runs sessions across all Org accounts"* → **Session Manager + delegated admin** in AWS Organizations
- *"Restrict which instances an admin can shell into"* → **`ssm:StartSession` with `ssm:resourceTag`** condition
- *"Run interactive sessions as a specific OS user (not root)"* → **`runAs` mode** in Session Manager preferences

**Related SSM features (know the family):**

- **Run Command** (`ssm:SendCommand`) — execute a specific command on one or many instances. Non-interactive.
- **Patch Manager** — scheduled OS patching via SSM.
- **State Manager** — enforce desired state (packages installed, config files, etc.).
- **Fleet Manager** — inventory + browser-based RDP + Registry Editor for Windows.
- **Automation runbooks** — YAML workflows (see [[ssm-automation-runbooks--the-auto-remediation-engine]]).
- **Parameter Store** — hierarchical config store (also SSM family).

All share the same `AmazonSSMManagedInstanceCore` prerequisite on the instance profile.

> *Mental model: **Session Manager is the AWS-recommended replacement for SSH — no inbound ports, native session recording, KMS-encrypted end-to-end, works in fully private subnets via VPC endpoints, and IAM-scoped access with tag-based conditions.*** Instance Connect delivers a real SSH channel with ephemeral keys (SSH-tooling-compatible); Session Manager delivers a WebSocket tunnel through SSM (audit-friendly, zero-inbound). Both need `AmazonSSMManagedInstanceCore` on the instance profile. For the exam's "modern admin access + compliance + no inbound exposure" answer, Session Manager wins on almost every axis — the only reason to prefer Instance Connect is legacy SSH-tooling compatibility.

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

**Visual — the evaluation gauntlet (memorise this shape):**

```text
              ┌─────────────────────┐
              │   API request       │
              │   (from principal)  │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐   any layer with an
              │  Explicit DENY?     │─── explicit Deny stops
              │  (any layer)        │    the whole chain
              └──────────┬──────────┘         │
                       no│                    ▼
                         ▼                  DENY
              ┌─────────────────────┐
              │  SCP allows?        │─── no ──►  DENY
              │  (org / OU / acct)  │
              └──────────┬──────────┘
                       yes│
                         ▼
              ┌─────────────────────┐
              │  VPC endpoint       │─── no ──►  DENY
              │  policy allows?     │    (only if request
              │  (if request routes │     goes via endpoint)
              │   through one)      │
              └──────────┬──────────┘
                       yes│
                         ▼
              ┌─────────────────────┐
              │  Resource-based     │─── allow? ──► short-circuit ALLOW
              │  policy?            │              (for same-account,
              │  (S3 bucket, KMS,   │               resource-policy alone
              │   Lambda, ECR, …)   │               can grant access)
              └──────────┬──────────┘
                 no policy│    ────────────────►
                    or no │
                    match │
                         ▼
              ┌─────────────────────┐
              │  Identity policy    │─── no ──►  DENY
              │  allows?            │
              └──────────┬──────────┘
                       yes│
                         ▼
              ┌─────────────────────┐
              │  Permission         │─── no ──►  DENY
              │  boundary allows?   │
              │  (if attached)      │
              └──────────┬──────────┘
                       yes│
                         ▼
              ┌─────────────────────┐
              │  Session policy     │─── no ──►  DENY
              │  allows?            │
              │  (if STS AssumeRole │
              │   with --policy)    │
              └──────────┬──────────┘
                       yes│
                         ▼
                       ALLOW
```

Rules the picture encodes:

- **Any Deny short-circuits** — a single Deny at any layer wins over every Allow beneath.
- **Every non-Deny layer must produce an Allow** (or be absent) — evaluation is AND-based across identity + boundary + session + SCP + VPC-endpoint layers.
- **Resource-based policies are the one asymmetry** — for same-account access, a resource policy allow can grant even without an identity-policy allow. For cross-account, both sides must allow.
- **VPC endpoint policy** only matters if the request actually routes through an endpoint (check the VPC route table). Public-internet-routed requests skip this gate.

#### Troubleshooting checklist — "admin permissions but AccessDenied"

**The most-tested SCS-C03 troubleshooting question class.** When an entity holds `AdministratorAccess` but still gets `AccessDenied`, adding more to the identity policy can't help — the ceiling is a *different layer*. Work down this six-item checklist:

| # | Layer | How to check | Common miss? |
|---|---|---|---|
| 1 | **Explicit Deny anywhere** in the chain | `simulate-principal-policy`; CloudTrail `errorMessage` names the layer | Occasionally |
| 2 | **SCP** at Org / OU / account | Organizations Console; `simulate-principal-policy` includes SCP eval | Rarely — first thing engineers check |
| 3 | **Resource-based policy** on the target (S3 bucket policy, KMS key policy, Lambda policy, ECR policy, Secrets Manager policy) | Read the resource's policy directly | Sometimes |
| 4 | **Permission boundary** on the entity | `aws iam get-role/get-user` → look for `PermissionsBoundary` | Sometimes |
| 5 | **Session policy** (only if creds came from STS AssumeRole with `--policy` / `--policy-arns`) | Inspect the `AssumeRole` CloudTrail event's `requestParameters` | **★ Very common miss** |
| 6 | **VPC endpoint policy** (if request routes through a VPC endpoint) | VPC → Endpoints → the specific endpoint → Policy tab; verify route table sends the request there | **★ Very common miss** |

**Session policy and VPC endpoint policy are the two the exam loves** because they're per-session / per-network-path — invisible when you only look at the entity's attached policies + boundary. Both cap admin permissions silently.

**CloudTrail is the fastest diagnostic.** The `errorMessage` field on a failed call names the responsible policy layer verbatim:

- *"…with an explicit deny in a service control policy"* → SCP
- *"…with an explicit deny in a permissions boundary"* → Permission boundary
- *"…because no session policy allows the action"* → Session policy
- *"…because no VPC endpoint policy allows the action"* → VPC endpoint policy
- *"…with an explicit deny in a resource-based policy"* → Resource policy

Read this string first before spelunking policies.

**Common Anti-patterns (exam wrong answers):**

- *"Attach `AdministratorAccess` to the user"* — already has it.
- *"Reset the user's password / rotate access keys"* — auth is fine; authorisation is failing.
- *"Add the user to a group with more permissions"* — same problem; identity policy isn't the ceiling.
- *"Enable MFA on the user"* — MFA doesn't grant permissions.
- *"Wait for eventual consistency"* — IAM propagates in seconds; not the issue.
- *"Restart the CLI / clear cached credentials"* — session-side, not policy-side.

**Exam Triggers:**

- *"Admin but AccessDenied"* → check the **six ceilings**, not the identity policy
- *"Worked for one user, fails for another with the same role"* → **session policy** on one of the assume calls
- *"Works from public internet, fails from inside VPC"* → **VPC endpoint policy** on the route
- *"Cross-account access fails"* → resource policy in the target account + identity policy in the caller account must **both** allow
- *"Denied via SCP"* → check org / OU / account SCPs

> *Mental model: IAM policy evaluation is a **ceiling stack**, not an addition. Identity policy sets intent; SCP, resource policy, permission boundary, session policy, and VPC endpoint policy each cap it below their own limit. When admin gets AccessDenied, don't add to the identity policy — look **up** the stack for the ceiling. The two the exam favours (session policy + VPC endpoint policy) are invisible in the entity's own config.*

### AWS Credential Provider Chain

**The canonical SCS-C03 "EC2 has an IAM role attached but API calls are using an IAM user" question.** The role isn't broken — a higher-priority credential source is shadowing it. Fundamentally different from the IAM policy evaluation troubleshooting above: **this is a client-side SDK behaviour, not a server-side authorisation check.**

**The full provider chain (priority order — memorise cold):**

| # | Source | How it's set |
|---|---|---|
| 1 | **Explicit code parameters** | `boto3.client('s3', aws_access_key_id=…)` etc. |
| 2 | **Environment variables** | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| 3 | **AWS CLI credentials file** | `~/.aws/credentials` (per-profile static keys) |
| 4 | **AWS CLI config file** | `~/.aws/config` (per-profile static keys, or `role_arn` for assume-role chains) |
| 5 | **Container credentials** | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — for ECS tasks + EKS pods |
| 6 | **Instance profile via IMDS** | `169.254.169.254/latest/meta-data/iam/security-credentials/<role>` — for EC2 |

The SDK walks this list top-down, uses the **first** source it finds, and **stops**. Instance-profile creds are at the **bottom** — any higher source shadows the attached role entirely.

**Why the role appears "not used" even though it's attached:**

Something placed IAM user credentials in one of the higher-priority locations on the instance. Most common causes:

- **`~/.aws/credentials` file** exists (e.g., `/home/ec2-user/.aws/credentials` or `/root/.aws/credentials`) with static IAM user access keys.
- **Environment variables** set in the shell / systemd unit / cron job / Dockerfile — `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` exported.
- **`~/.aws/config`** has explicit `aws_access_key_id` in a profile.
- **AMI baked with credentials** — someone ran `aws configure` before creating the image; keys ship with every launch.
- **Container inherits env vars** from the host or from a Dockerfile `ENV` directive.

The instance profile role is still *attached and functional* — the SDK just never reaches step 6 in the chain because step 2, 3, or 4 already returned a credential.

**Two-command diagnostic (master this):**

```bash
aws configure list         # shows which source is winning (Type column)
aws sts get-caller-identity # shows the ARN the SDK is signing requests as
```

**Reading `aws configure list` — the Type column tells you the source:**

| Type value | Source |
|---|---|
| `iam-role` | ✅ Instance profile via IMDS (**the desired state**) |
| `env` | Environment variables (`AWS_ACCESS_KEY_ID` etc.) |
| `shared-credentials-file` | `~/.aws/credentials` |
| `config-file` | `~/.aws/config` (explicit keys) |
| `container-role` | ECS/EKS task credentials |

**Reading `aws sts get-caller-identity` — the ARN tells you the identity:**

- `arn:aws:iam::<acct>:user/<name>` → an IAM user (shadowed the role — problem)
- `arn:aws:sts::<acct>:assumed-role/<role-name>/<session>` → instance role (desired state)

**The fix — remove the higher-priority credentials:**

```bash
# 1. Delete the shared-credentials file
rm ~/.aws/credentials
# Or edit to remove aws_access_key_id / aws_secret_access_key lines

# 2. Remove explicit keys from ~/.aws/config if present

# 3. Unset environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_PROFILE

# 4. Check systemd units for env vars
sudo grep -rn 'AWS_ACCESS_KEY_ID' /etc/systemd/system /etc/default
# Edit the unit → systemctl daemon-reload && systemctl restart <svc>

# 5. Check shell profiles and cron
grep -rn 'AWS_ACCESS_KEY_ID' /home /root /etc/cron.* /etc/profile*

# 6. Verify
aws configure list          # should now show Type: iam-role
aws sts get-caller-identity # should now show assumed-role ARN
```

**Numbered diagnostic flow:**

1. Run `aws configure list` — read the Type column.
2. If Type is anything but `iam-role`, that source is shadowing the instance role.
3. Locate the source (file / env var / systemd unit) and remove it.
4. Re-run `aws configure list` and `aws sts get-caller-identity` to confirm the SDK is now using the instance role.

**Why this pattern is bad beyond "wrong identity":**

- **Static IAM user access keys are long-lived**, unlike the STS temp creds the instance profile provides.
- **Long-lived keys have a longer window of compromise** — a leaked user key stays valid until manually rotated.
- **Manual rotation** is required for static keys; instance profile creds auto-rotate through IMDS every few hours.
- **CloudTrail audit trail is misleading** — the caller identity shows an IAM user, not the instance, making cross-referencing to compute resources harder.
- **The IAM user probably has broader permissions** than the role — users tend to accrete permissions; roles tend to be scoped for a specific workload.
- **Static keys placed in files** are prime SSRF exfiltration targets.

**Diagnosis flow diagram:**

```text
┌─────────────────────────────────────┐
│  API call from EC2 instance uses    │
│  wrong identity (IAM user vs role)  │
└──────────────┬──────────────────────┘
               ▼
     aws configure list  ── shows Type column
               │
      ┌────────┴──────────────────────────────┐
      │ Type = iam-role                       │ ← desired state; check IAM policy on role
      │                                       │
      │ Type = shared-credentials-file        │ ← ~/.aws/credentials exists → remove
      │                                       │
      │ Type = env                            │ ← env vars set → unset in shell / systemd / cron
      │                                       │
      │ Type = config-file                    │ ← ~/.aws/config has explicit keys → remove
      │                                       │
      │ Type = container-role                 │ ← ECS/EKS task creds; different mechanism
      └───────────────────────────────────────┘
```

**Prevention (best practices):**

- **Never bake AWS credentials into an AMI.** Base images should be credential-free; roles come from the instance profile.
- **Prefer instance profiles / task roles / IRSA** (IAM Roles for Service Accounts) for EKS. Never install static keys onto compute.
- **Use SSM Parameter Store / Secrets Manager** for external secrets an app needs — not IAM user access keys.
- **Add SCP guardrails** preventing `iam:CreateAccessKey` for regular IAM users; force everything through roles.
- **Enable AWS Config rules** `iam-user-no-policies-check`, `access-keys-rotated`, and `iam-user-unused-credentials-check` to flag static-key sprawl.
- **Turn on IAM Access Analyzer's unused-access analysis** to identify IAM users with stale keys.

**What plausible-looking wrong answers miss:**

- ***"The IAM role's trust policy doesn't allow EC2"*** — would cause total failure to assume; the stem says calls succeed, just as the wrong identity.
- ***"The instance profile is misconfigured"*** — if that were true, no role identity would appear anywhere.
- ***"IMDS is disabled"*** — would cause the SDK to fall through to nothing, resulting in `NoCredentialsError`. But the stem says calls succeed, so credentials are being found somewhere.
- ***"The IAM role has insufficient permissions"*** — permissions issues surface as `AccessDenied`, not "wrong identity."
- ***"CloudTrail is showing the wrong identity due to a delay"*** — CloudTrail records the actual signing principal in near-real-time; not a delay artefact.
- ***"Reset the EC2 instance's metadata service"*** — restarting IMDS doesn't clear file/env-based credentials.

**Contrast with the eval-logic troubleshooting:**

| Symptom | Layer | Fix |
|---|---|---|
| *"Wrong identity is signing requests"* | **Credential provider chain** (client-side SDK) | Remove higher-priority credential source |
| *"Right identity, AccessDenied on action"* | **Policy evaluation chain** (server-side IAM) | Fix the ceiling layer (SCP, boundary, session policy, VPC endpoint policy, resource policy) |

Both classes of question look similar in the console; the diagnostic tool is different.

**Common Anti-patterns (exam wrong answers):**

- Attributing "wrong identity" to a policy problem — that's *server-side*; this is a *client-side* precedence issue.
- Restarting the instance or the IMDS service — doesn't clear files or env vars.
- Recreating the instance profile — the profile is fine; the SDK just isn't reaching it.
- Modifying the trust policy — irrelevant unless the SDK is failing to assume.

**Exam Triggers:**

- *"EC2 has role attached but API calls use IAM user credentials"* → **credential provider chain** — higher-priority source shadowing IMDS
- *"How to diagnose which credentials the SDK is using?"* → **`aws configure list`** (Type column) + **`aws sts get-caller-identity`** (Arn)
- *"Fix an EC2 that's using static keys instead of the role"* → **remove `~/.aws/credentials`**, unset env vars, check systemd units
- *"Prevent EC2 fleet from ever using static IAM keys"* → **AMI hardening** + **SCP denying `iam:CreateAccessKey`** + Config rules
- *"Force API calls from EC2 to use only the instance profile"* → remove all higher-priority sources; ensure the SDK's chain falls through to IMDS

**The one-command diagnostic to internalise:**

```bash
aws configure list && aws sts get-caller-identity
```

Type column → source. ARN → identity. Two commands, one line, entire diagnosis.

> *Mental model: **the AWS SDK doesn't automatically use the instance role — it walks a priority-ordered credential provider chain and uses the first source it finds.*** Instance-profile creds via IMDS are at the **bottom** of that chain. Environment variables, `~/.aws/credentials`, and `~/.aws/config` static keys all shadow it. When the exam says "role attached but wrong identity" — it's a **client-side precedence problem, not a server-side policy problem**. Fix by removing the higher-priority credential source, not by touching the role. Master `aws configure list` (Type column) + `aws sts get-caller-identity` (ARN) as the two-command diagnostic that answers every "which credentials are being used?" question in one line.*

### MFA Enforcement — MultiFactorAuthPresent + MultiFactorAuthAge

**The canonical SCS-C03 "require MFA on these actions AND cap session validity to N hours" question.** Two policy conditions used together, one for each half:

- **`aws:MultiFactorAuthPresent`** — Boolean. `"true"` means the caller authenticated with MFA in this session. Answers *"did you use MFA?"*
- **`aws:MultiFactorAuthAge`** — Numeric (seconds). Answers *"how long ago was MFA validated?"* Filter with `NumericLessThan` to enforce freshness.

**Combined statement (add to `Condition` block):**

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  },
  "NumericLessThan": {
    "aws:MultiFactorAuthAge": "10800"
  }
}
```

Both keys are AND-ed within a single statement — the request must satisfy every key for Allow to fire. Fail either → no Allow → implicit Deny.

**Seconds cheat-sheet (memorise cold — the exam uses these):**

| Duration | Seconds |
|---|---|
| 1 hour | 3600 |
| 2 hours | 7200 |
| **3 hours** | **10800** |
| 4 hours | 14400 |
| 8 hours | 28800 |
| 12 hours | 43200 |
| 24 hours | 86400 |

**MaxSessionDuration vs `aws:MultiFactorAuthAge` — the exam trap:**

Both sound like "how long a session lasts" — they solve different problems. Getting this wrong is the classic multi-select miss.

| | `MaxSessionDuration` | `aws:MultiFactorAuthAge` |
|---|---|---|
| Type | **Role attribute** | **IAM policy condition key** |
| Where set | On the role itself (`aws iam update-role`) | Inside a policy statement's `Condition` block |
| Values | 1–12 hours (3600–43200 s) | 0–∞ seconds, filter with `NumericLessThan` |
| Enforces MFA usage? | ❌ No — pure lifetime cap | ✅ Yes (paired with `MultiFactorAuthPresent`) |
| Applies to IAM users? | ❌ No — assumed roles only | ✅ Yes — users and roles |
| Evaluated when? | Once at AssumeRole | On every API call |
| Fits *"add to the policy"* wording? | ❌ No | ✅ Yes |

**Why `MaxSessionDuration` is wrong for the "add to the IAM policy" style question:**

1. It's not a condition key — it's a role property. Wouldn't fit inside `"Condition": { ... }`.
2. It doesn't enforce MFA freshness — someone could complete an unauthenticated session and still get the full duration.
3. It only applies to assumed roles — IAM users with long-lived access keys aren't governed by it.
4. It fires once at AssumeRole, not on every API call — no rolling per-request check.

**When `MaxSessionDuration` *is* the correct answer:**

- *"Cap how long a role's STS credentials remain valid"* → **MaxSessionDuration**
- *"Prevent long-lived assumed-role tokens"* → **MaxSessionDuration**
- Nothing about MFA or per-request policy conditions in the stem → **MaxSessionDuration**

**Other adjacent condition keys worth knowing (and why they're not this):**

- **`aws:TokenIssueTime`** — datetime, not age. Used to *revoke* sessions issued before a timestamp (the compromised-creds pattern in Domain 1). Wrong for rolling age caps.
- **`aws:CurrentTime`** — request time. Used for business-hours restrictions ("Mon–Fri 9–5"). Not for session age.
- **`aws:SessionExpirationTime`** — read-only artifact of the STS session; not settable in a Condition.
- **`aws:SecureTransport`** — TLS enforcement, not MFA.

**Common Anti-patterns (exam wrong answers):**

- *"Set MaxSessionDuration on the role to 3 hours"* — wrong tool + wrong layer + wrong scope (see the four reasons above).
- *"Use `aws:TokenIssueTime` to cap session age"* — that's for absolute-time revocation, not rolling freshness.
- *"Use `aws:CurrentTime NumericLessThan 10800`"* — mixes up "current time" (Unix timestamp) with "seconds since MFA."
- *"Add `Effect: Deny` with `Bool: aws:MultiFactorAuthPresent: false`"* — works as a Deny statement but the exam asks what to add as **conditions on the existing Allow**, not a separate statement.
- *"`NumericGreaterThan aws:MultiFactorAuthAge`"* — inverted; that would say "only allow after N hours since MFA," the opposite of what's needed.

**Exam Triggers:**

- *"Require MFA for these actions"* → **`aws:MultiFactorAuthPresent: true`** (Bool)
- *"Session valid for no longer than N hours"* → **`aws:MultiFactorAuthAge < N × 3600`** (NumericLessThan)
- *"Revoke sessions issued before a timestamp"* → **`aws:TokenIssueTime`** (compromised-creds pattern)
- *"Only allow during business hours"* → **`aws:CurrentTime`** with `DateGreaterThan` / `DateLessThan`
- *"Cap the lifetime of an assumed-role token"* → **`MaxSessionDuration`** role attribute (not a policy condition)
- *"Reject non-TLS requests"* → **`aws:SecureTransport`**

> *Mental model: **`aws:MultiFactorAuthPresent`** = "did you use MFA?" (yes/no). **`aws:MultiFactorAuthAge`** = "how long ago?" (seconds). Combine them for the *"MFA required + session ≤ N hours"* requirement. **`MaxSessionDuration`** answers a completely different question ("what's the max lifetime of a role's STS token?") and lives on the role, not in the policy — anyone who picks it in an MFA question has fallen for the plausible-name trap.*

#### The Allow-vs-Deny inversion trap (favourite MFA exam wrong-answer)

**Two policy shapes both seem to enforce MFA — only one actually does.** The trap: an *Allow with `BoolIfExists: true`* silently leaks when the MFA context key is absent. The correct idiom is a *Deny with `BoolIfExists: false`*.

**The wrong shape (the trap):**

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": { "aws:MultiFactorAuthPresent": "true" }
  }
}
```

Two things break:

- **Doesn't block other Allow policies.** IAM eval is "Deny beats Allow; a conditional Allow that fails is just an inactive Allow." Any *other* policy granting `s3:*` without an MFA condition still fires. Your conditional Allow doesn't invalidate the unconditional one.
- **`BoolIfExists: true` leaks on absent context.** Some request paths don't populate `aws:MultiFactorAuthPresent` at all (certain service-principal calls, AWS-internal automation). `IfExists` treats a missing key as "condition doesn't apply" → the Allow still fires without MFA.

**The correct shape (exam-canonical):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyIfNoMFA",
    "Effect": "Deny",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
    "Condition": {
      "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
    }
  }]
}
```

Two things this fixes:

- **Deny short-circuits everything** — cross-account grants, group policies, resource-based bucket policies. Nothing gets through.
- **`BoolIfExists: false` catches missing context.** Requests where the MFA key is absent are treated as "the condition applies and is false" → Deny fires → request blocked.

**The `BoolIfExists` truth table (memorise the bottom row — that's the leak):**

| Context state | `BoolIfExists: MFA = true` on **Allow** | `BoolIfExists: MFA = false` on **Deny** |
|---|---|---|
| MFA present, value = true | Allow fires ✅ | Deny doesn't fire ✅ (correct) |
| MFA present, value = false | Allow blocked ❌ | Deny fires ❌ (correct — blocks) |
| MFA context absent entirely | **Allow fires ❌ — LEAK** | **Deny fires ❌ — BLOCKS (correct)** |

Same operator, opposite framing, opposite security outcome.

**Why the exam favours the Deny variant every time:**

- **Composability** — works alongside existing Allow policies without modifying them.
- **Leak-proof** — `IfExists: false` catches the missing-context case.
- **Short-circuits** — explicit Deny beats any Allow anywhere.
- **Auditor-friendly** — reads as "deny anything without MFA," obvious in policy review.

**`Bool` vs `BoolIfExists` — when to use each:**

- **`Bool`** (strict) — condition evaluates only when the key is present. Missing key → condition doesn't apply.
- **`BoolIfExists`** — evaluates when the key is present *and* when it's missing. Use this for **security guardrails** you want always applied.

For MFA enforcement: **always `BoolIfExists`**, never bare `Bool` — the missing-context case is exactly where you don't want to accidentally allow.

**Common Anti-patterns (exam wrong answers):**

- *"Allow if `aws:MultiFactorAuthPresent = true`"* — the classic trap; leaks when MFA context is missing and doesn't block sibling Allow policies.
- *"`Bool: MultiFactorAuthPresent = false` on Deny"* — strict; doesn't fire when the key is absent, so paths without MFA context aren't blocked. Use `BoolIfExists` instead.
- *"`Null: aws:MultiFactorAuthPresent = true` on Deny"* — denies when the key is null; conflicts with legitimate service-principal calls. Overbroad.
- *"Add the MFA Allow condition to every existing policy"* — you'd need to modify every policy that grants access. A single Deny guardrail is cleaner.

> *Mental model: **MFA enforcement is a Deny problem, not an Allow problem.** An Allow with a condition says "I grant access when X" — it doesn't revoke access another Allow already granted. A Deny with the inverse says "I refuse access when NOT X" — and Deny short-circuits. Reach for **Deny + `BoolIfExists: false`** every time.*

### SCPs, Permission Boundaries, Session Policies

- **SCPs** — apply to an account/OU/root; do NOT grant permissions, only bound them.
- **Permission boundaries** — apply to an IAM user/role; used for delegation (dev creates roles but can't exceed the boundary).
- **Session policies** — apply per-STS-session, further narrow the assumed-role permissions.

#### SCP deep dive — behaviour, coverage, and structural patterns

**The three exam-canonical facts about SCPs (memorise this trio):**

1. **SCP is a ceiling — actions not allowed or explicitly denied by the effective SCP cannot be performed, even if the IAM identity policy grants them.** SCPs bound the maximum; they never grant. Removing an SCP restriction just raises the ceiling; identity policies still need to allow the action.
2. **SCPs affect every user and role in a member account — including the root user of that member account.** Root of a member account is *not* exempt. This lets you Deny-lock even root from disabling CloudTrail, GuardDuty, Config, etc.
3. **SCPs do NOT affect service-linked roles (SLRs).** SLRs are AWS-managed roles that services use to integrate with each other and with Organizations — AWS reserves the right for them to function even in accounts with restrictive SCPs. This is the *most-missed* SCP fact on the exam.

**Full "who's affected vs who isn't" matrix:**

| Principal / mechanism | Affected by SCPs? |
|---|---|
| IAM users in a member account | ✅ Yes |
| IAM roles (regular, customer-managed) in a member account | ✅ Yes |
| **Root user of a member account** | ✅ Yes |
| **Service-linked roles (SLRs)** | ❌ **No — exempt** |
| **Root user of the management account** | ❌ No — exempt |
| Any principal in the management account | ❌ No — exempt |
| Cross-account access via *resource-based* policy on a resource in your account | ❌ Not governed by SCPs — that's what **RCPs** handle |
| AWS-managed operations tied to Organizations itself | ❌ Exempt |

Common SLRs the exam names (know the pattern — they all start with `AWSServiceRoleFor…`):

- `AWSServiceRoleForAutoScaling`
- `AWSServiceRoleForOrganizations`
- `AWSServiceRoleForConfig`
- `AWSServiceRoleForSecurityHub`
- `AWSServiceRoleForTrustedAdvisor`
- `AWSServiceRoleForECS`
- `AWSServiceRoleForRDS`

An SCP that denies `iam:CreateRole` won't block SLR creation. An SCP that denies `ec2:RunInstances` won't stop Auto Scaling from launching instances via its SLR.

**Seven behavioural rules (memorise all seven):**

| # | Rule | Implication |
|---|---|---|
| 1 | SCPs **only restrict**, never grant | Identity policies must still allow actions |
| 2 | SCPs are **inherited down the tree** (root → OU → account) | Effective SCP = intersection of every layer |
| 3 | SCPs affect **all IAM principals in member accounts**, including root | Root user of a member account is not exempt |
| 4 | SCPs do **NOT** affect the **management account** | Never run workloads in the management account |
| 5 | SCPs do **NOT** affect **service-linked roles** | AWS services keep functioning via their SLRs |
| 6 | SCPs require **AWS Organizations with All Features mode** | Consolidated-billing mode doesn't support SCPs |
| 7 | Default `FullAWSAccess` SCP is attached at every level until you replace it | Attach Deny-based SCPs to narrow, or replace with a narrower Allow |

**Two structural patterns — memorise the difference:**

- **Denylist pattern** (recommended for most cases): keep the default `FullAWSAccess` SCP at every level, add Deny-based SCPs to restrict specific actions. Simple; only define what you're blocking. Most exam scenarios use this.
- **Allowlist pattern** (high-security): replace `FullAWSAccess` with a custom Allow-based SCP. Only listed services are usable at all. Rigorous but requires maintaining an exhaustive list; new services silently fail until added.

**Denylist example — restrict regions:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyRegionsOutsideEurope",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": ["eu-west-1", "eu-central-1", "eu-west-2"]
      }
    }
  }]
}
```

**Allowlist example — only specific services usable:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowOnlySpecificServices",
    "Effect": "Allow",
    "Action": [
      "ec2:*",
      "s3:*",
      "rds:*",
      "iam:*",
      "sts:*"
    ],
    "Resource": "*"
  }]
}
```

**Common SCP idioms worth memorising (each is a testable scenario on its own):**

- **Restrict regions** — `aws:RequestedRegion` StringNotEquals (see above).
- **Require MFA on sensitive actions** — Deny with `aws:MultiFactorAuthPresent = false` (see [[mfa-enforcement--multifactorauthpresent--multifactorauthage]]).
- **Prevent leaving the Org** — Deny `organizations:LeaveOrganization`.
- **Prevent disabling security services** — Deny `guardduty:DeleteDetector`, `config:StopConfigurationRecorder`, `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `securityhub:DisableSecurityHub`.
- **Force encryption** — Deny `ec2:CreateVolume` / `s3:PutObject` where `ec2:Encrypted = false` or `s3:x-amz-server-side-encryption` is missing (see [[ebs-encryption-at-scale]] and [[s3-encryption--bucket-policies]]).
- **Prevent public S3 buckets** — Deny `s3:PutBucketPolicy` where the granted principal is outside the org (via `aws:PrincipalOrgID` condition, see [[aws-principalorgid-vs-awsresourceorgid--the-two-arrow-model]]).
- **Prevent org data exfil** — Deny actions where `aws:ResourceOrgID != <my-org-id>`.
- **Prevent root-user access-key creation** — Deny `iam:CreateAccessKey` with `aws:PrincipalArn` matching root ARN. Because SCPs affect root in member accounts (Rule #3), this actually works.
- **Force use of a specific deployment path** — Deny `ec2:RunInstances` unless `aws:CalledVia` includes `servicecatalog.amazonaws.com` (see [[service-catalog]]).
- **Prevent Lambda function URLs with `AuthType = NONE`** — Deny with `lambda:FunctionUrlAuthType = NONE` (see [[preventive-vs-detective-vs-responsive--the-three-tier-framework]]).

**How SCPs interact with the other IAM ceilings:**

SCPs are one of six ceilings the request must clear (see [[iam-policy-evaluation-logic]]):

1. Explicit Deny anywhere → Deny wins.
2. **SCP** — the org-scale ceiling (this section).
3. Resource-based policy — required for cross-account.
4. Identity policy — the intent.
5. Permission boundary — per-entity ceiling.
6. Session policy — per-session ceiling.
7. VPC endpoint policy — network-path ceiling.

An admin can still get `AccessDenied` because the SCP two layers up denies the action, or because an SLR exemption doesn't apply. Read CloudTrail's `errorMessage` field — it names the responsible layer.

**Common Anti-patterns (exam wrong answers):**

- *"SCPs grant permissions"* — no; SCPs cap the maximum, never grant.
- *"SCPs affect the management account"* — no; management account exempt.
- *"SCPs affect service-linked roles"* — no; SLRs exempt (the most-missed fact).
- *"SCPs work without AWS Organizations"* — no; require Organizations with All Features mode.
- *"Consolidated-billing mode supports SCPs"* — no; needs All Features.
- *"Root user of any account is exempt from SCPs"* — no; only management-account root is exempt. Member-account root is bounded.
- *"SCPs can be used to grant cross-account access"* — no; they never grant. Cross-account = identity policy + resource-based policy.
- *"SCPs control what an S3 bucket policy can grant to external principals"* — no; SCPs govern in-org identities, not the resource side. Use **RCPs** for that.
- *"SCPs affect already-established connections"* — no; policy evaluation happens on new API calls, not on in-flight TCP sessions.

**Exam Triggers:**

- *"Central control over maximum permissions for accounts in the Org"* → **SCPs**
- *"Prevent every user (including root) in member accounts from doing X"* → **SCP** with a Deny statement
- *"AWS services must keep working via their SLRs even with restrictive SCPs"* → **SLR exemption** — no SCP change needed
- *"Restrict regions across all accounts"* → **SCP** with `aws:RequestedRegion` StringNotEquals
- *"Prevent leaving the Org / disabling CloudTrail"* → **SCP** with specific action Denies
- *"Force use of Service Catalog / specific deploy path"* → **SCP** with `aws:CalledVia` condition
- *"Delegate role-creation to devs but cap their permissions"* → **permission boundary**, not SCP
- *"Narrow permissions for a specific STS AssumeRole session"* → **session policy**, not SCP

> *Mental model: **SCPs are a ceiling stack across the Organization**. They bound every IAM principal in every member account — root included — except two categories: the management account (fully exempt) and service-linked roles (functional exemption so AWS services keep working). Effective SCP = intersection of every layer from Org root down. Denylist patterns (`FullAWSAccess` + Deny statements) are the standard; allowlist patterns lock down to a whitelist of services. Anything that expects SCPs to grant, to affect the management account, or to restrict SLRs is a trap the exam plants.*

#### `aws:PrincipalOrgID` vs `aws:ResourceOrgID` — the two-arrow model

Both are global IAM condition keys carrying an AWS Organizations ID (`o-xxxxx`). Every S3 (and most other) API request stamps **both** into the request context — you pick which one to condition on based on which direction of leakage you're trying to prevent.

**One-line difference:**

- **`aws:PrincipalOrgID`** = *who is calling?* → org ID of the **IAM user/role making the request**
- **`aws:ResourceOrgID`** = *what are they touching?* → org ID of the **AWS resource being acted on**

```
                ┌───────────────────┐         ┌───────────────────┐
   Request  →   │  Calling identity │  ─────► │   Target resource │
                │  (IAM user/role)  │         │   (S3 bucket etc) │
                └───────────────────┘         └───────────────────┘
                        ▲                                ▲
                        │                                │
                aws:PrincipalOrgID              aws:ResourceOrgID
              ("who is asking?")               ("what are they touching?")
```

**Scenario A — external identity reading YOUR bucket (inbound leakage):**

- `aws:PrincipalOrgID` = **their org** (or empty if no org)
- `aws:ResourceOrgID` = **your org**
- Block with a **bucket policy** using `aws:PrincipalOrgID != o-MY-ORG` → Deny

**Scenario B — your IAM user writing to SOMEONE ELSE'S bucket (outbound leakage / data exfil):**

- `aws:PrincipalOrgID` = **your org** (caller is one of yours)
- `aws:ResourceOrgID` = **their org**
- Block with an **SCP** using `aws:ResourceOrgID != o-MY-ORG` → Deny

**Decoder table:**

| You want to stop… | Use this key | Put it in… |
|---|---|---|
| External identities reading your data | `aws:PrincipalOrgID` | Resource-based policy (bucket policy, KMS key policy). SCPs also work but only govern your own principals. |
| Your identities writing data out to external accounts | `aws:ResourceOrgID` | **SCP** at the org root. Also usable in identity-based IAM policies. |
| Belt-and-suspenders on both directions | Both keys | SCP + bucket policy — the exam-favourite combo |

**Concrete side-by-side:**

| Perspective | Request context | Which key catches it |
|---|---|---|
| "Alice from Company B tried to read our-bucket" | PrincipalOrgID=**B**, ResourceOrgID=**A** | `aws:PrincipalOrgID != o-A` on our bucket policy |
| "Bob from our company tried to write to their-bucket" | PrincipalOrgID=**A**, ResourceOrgID=**B** | `aws:ResourceOrgID != o-A` in our SCP |

#### Canonical SCP: prevent S3 sharing with identities outside the Organization

**The classic SCS-C03 exam SCP.** Apply at the org root (or the highest OU covering all accounts).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3AccessOutsideOrg",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-abcd1234ef"
        }
      }
    }
  ]
}
```

**Why each piece is load-bearing:**

- **`aws:PrincipalOrgID`** — the only condition key that natively expresses "in my org / not in my org" at org scale (survives account add/remove).
- **`StringNotEqualsIfExists`** — the `IfExists` variant evaluates the condition only when the key is present. Without it, service-principal calls (CloudTrail, Config) that don't populate the key get denied — breaks legitimate flows.
- **`Deny` on `s3:*`** — SCPs work by bounding what identity policies can do; this Deny caps every S3 action.
- **Pair with a bucket policy** using the same condition for the actual cross-org data-access denial; the SCP is the belt-and-suspenders governance layer.

**Common Anti-patterns (wrong SCP statements to spot):**

- **Using `aws:SourceAccount`** — only covers a single account, not the whole org. Doesn't scale as accounts are added/removed.
- **Omitting `IfExists`** — strict `StringNotEquals` treats a missing key as *not equal*, so legitimate service calls get denied.
- **Applying to `s3:PutObject` only** — misses `s3:PutBucketPolicy`, `s3:PutObjectAcl`, `s3:PutBucketAcl`, `s3:PutAccessPointPolicy` — the actions that actually create external sharing.
- **`Deny` on `s3:GetObject` only** — doesn't stop the write side; someone in your org could still push objects to an external bucket a third party will later read.
- **`aws:PrincipalOrgPaths` StringEquals to a full OU path** — brittle; breaks when OUs are restructured. `PrincipalOrgID` is stable across restructures.

**Exam Triggers:**

- *"Prevent S3 objects being shared with IAM identities outside the organization"* → SCP with **`aws:PrincipalOrgID` StringNotEqualsIfExists** on `s3:*`
- *"Enforce across an organization / at scale"* → SCP with `aws:PrincipalOrgID`, not `aws:SourceAccount`
- *"Prevent our users writing to external accounts"* → SCP with **`aws:ResourceOrgID`**
- *"Belt-and-suspenders with BPA"* → BPA blocks public; SCP + bucket policy with `aws:PrincipalOrgID` blocks cross-org

**Nuance — SCP vs the newer RCP:**

- **Resource Control Policies (RCPs)** (late-2024) are the resource-side equivalent of SCPs: attach to the org and gate access to *resources in your org* regardless of who's calling. Cleaner deployment than repeating the same condition on every bucket policy.
- SCP with `aws:PrincipalOrgID` is still the exam-correct answer to the classic question — RCPs are only starting to appear in newer material.

> *Mental model: **Principal** = who's holding the request; **Resource** = what the request is aimed at. Every request has both sides. Pick your condition key based on which side of that arrow you're trying to lock down.*

### IAM Identity Center and Federation

- **Successor to AWS SSO**. Integrates with external IdPs (Okta, Azure AD) via SAML or SCIM.
- **Permission sets** = role templates deployed to accounts.

### Resource-based Policies

Only the following resources have them (memorise): **S3 buckets, KMS keys, SNS topics, SQS queues, Lambda functions, ECR repos, EFS file systems, Secrets Manager secrets, API Gateway (resource policy), IAM roles (trust policy)**.

### IAM Access Analyzer

**Anchored against `strace` for IAM.** Access Analyzer has grown from a single feature into an **umbrella of five related capabilities**. The exam distinguishes each one — pick the wrong feature from the family and you fail the question.

**The five features under the Access Analyzer umbrella (memorise all five):**

| Feature | What it does | Exam trigger |
|---|---|---|
| **External access analysis** (the original) | Finds resources shared *outside your zone of trust* — buckets, KMS keys, IAM roles, Lambda functions, SQS queues, Secrets Manager secrets, EBS/EFS/RDS snapshots exposed publicly or cross-account | *"Find resources shared externally"* / *"identify cross-account access"* |
| **Policy generation** | Ingests 90 days of CloudTrail management events and generates a **least-privilege policy** listing the actions the role actually used | *"Generate a policy from actual usage history"* / *"replace AWS-managed with customer-managed, most efficient"* |
| **Unused access analysis** | Identifies unused IAM roles, unused permissions on used roles, unused access keys | *"Find unused IAM roles or permissions"* |
| **Custom policy checks** | Validates a policy against a reference — e.g., *"is my new policy more permissive than the previous version?"* — for CI gates | *"Block PR from merging if it grants broader access"* |
| **Policy validation** | Checks a policy for syntax, security warnings, best-practice violations before you attach it | *"Validate a policy before deploying"* |

#### Policy generation — the "least-privilege replacement for AWS-managed policies" workflow

**The canonical SCS-C03 "replace broad AWS-managed policies with a customer-managed least-privilege policy, most operationally efficient" question.** The workflow is deliberately counterintuitive:

**Numbered flow:**

1. **Create a CloudTrail trail for management events** (or verify one exists). Access Analyzer needs CloudTrail data as input.
2. **Keep the existing broad AWS-managed policies attached** while you observe the workload. Critical: the script must run *successfully* so CloudTrail records the full set of API calls. Removing permissions first causes the script to fail on the first denial and you never see the rest.
3. **Run the workload for a representative period** — days if it's periodic. Enough to cover every code path (regular runs, edge cases, retries, error handlers).
4. **IAM → Access Analyzer → Generate policy** → select the role → specify the CloudTrail trail + time window → click Generate.
5. Access Analyzer produces a **JSON policy** listing the actions the role actually called, with resource ARNs where inferable.
6. **Review + tighten** — sanity-check against your knowledge of the workload; replace remaining `*` resources with specific ARNs where possible; add conditions (MFA, region, tag) which the generator doesn't infer.
7. **Attach the generated policy as a customer-managed policy** and **detach the broad AWS-managed policies**.
8. **Run the workload again to validate.** Any `AccessDenied` → extend the observation window or add the missing action manually.

**Why "keep broad policies attached first" is the subtle correct move:**

Counterintuitive — leaving overly-permissive policies attached during observation *feels* wrong. But it's necessary. The workload has to *succeed at every code path* so every API call ends up in CloudTrail. If you strip permissions first, the script fails at the first `AccessDenied` and Access Analyzer sees an incomplete picture. This is the exam's specific test — you either understand the observe-then-narrow pattern or you don't.

**What policy generation is NOT:**

- **NOT Access Advisor.** Access Advisor shows *services* accessed (coarse); policy generation shows *actions* (fine-grained) and generates the JSON for you.
- **NOT real-time.** Reads historical CloudTrail data; management events must have been recorded during the window.
- **NOT capable of inferring conditions.** The generator emits Allow statements only; conditions (MFA, region, tag, encryption) added by hand.
- **NOT complete for every resource.** Some API calls don't include the resource ARN in the CloudTrail event → the generator uses `*` and you tighten manually.
- **NOT capable of inferring Deny statements.** Add `Deny` for anti-patterns by hand.
- **NOT data-event-aware by default.** Reads management events; won't catch S3-object-level or Lambda-invoke actions unless you've enabled data events *and* the generator can process them.

#### External access analysis — the original feature

Point Access Analyzer at your account (or the Org) and it identifies **resources shared externally** — beyond the *zone of trust* (the account or the org). Reports include:

- **S3 buckets** with public or cross-account access via bucket policy / ACL / access point
- **KMS keys** granting external principals `Decrypt` / `Encrypt`
- **IAM roles** whose trust policy allows external principals to assume
- **Lambda functions** with cross-account permissions on the function
- **SQS queues / SNS topics** with cross-account subscribe/receive
- **Secrets Manager secrets** with cross-account resource policies
- **EFS file systems** shared cross-account
- **EBS / RDS / RDS-cluster snapshots** shared with other accounts

Continuous — new findings appear as resources change. Wire to EventBridge → SNS for real-time alerting.

**Zone-of-trust configuration:** you specify what counts as "trusted" — usually the AWS account itself, or the AWS Organization. Anything outside that boundary is a finding.

#### Unused access analysis — permission-hygiene feature

Flags:

- **IAM roles that haven't been assumed** in the last N days
- **Unused permissions** on used roles (actions granted but never called)
- **Unused access keys** on IAM users

Feeds directly into policy-generation workflows — remove unused permissions first, then generate.

#### Custom policy checks — for CI/CD gates

Programmatic checks that answer questions like:

- *"Does this new policy grant more permissions than the previous version?"* — regression prevention
- *"Does this policy grant access to the resources I listed?"* — targeted check
- *"Does this policy grant access outside my zone of trust?"* — external-access precheck before deploy

Callable from CI pipelines — block PRs that fail the check.

#### Policy validation — syntax + best-practice linter

Real-time as you edit a policy in the Console (or via `iam:ValidatePolicy` API). Flags:

- Syntax errors
- Security warnings (overly-broad conditions, `*` where a specific action fits)
- Suggestions (use `IfExists`, prefer specific ARNs)

**Data-source scope of policy generation:**

- Reads **CloudTrail management events** from the specified trail.
- **90-day maximum window.**
- Doesn't read data events by default.
- Requires the trail's S3 bucket to be readable by Access Analyzer's service role.
- Cross-account supported (point at a trail in another account — organisation-trail pattern).

**Limitations worth knowing (exam sometimes tests):**

- **Resource-level ARNs not always inferable** — some API calls don't include the ARN; generator falls back to `*`.
- **Condition keys not inferred** — add MFA / region / tag conditions by hand.
- **New API calls after the window aren't captured** — re-run periodically as the workload evolves.
- **Some services aren't supported** for action-level inference; you get service-level (`s3:*`) instead of specific.

**Comparison — "how do I get a least-privilege policy?":**

| Data source | Granularity | Effort |
|---|---|---|
| **Access Analyzer policy generation** | Action-level + resource ARNs where inferable | Very low — one click |
| **Access Advisor last-accessed** | Service-level only | Low but coarse |
| **CloudTrail Insights** | Anomaly rates | Wrong tool |
| **Manual CloudTrail log parsing** | Action-level (custom code) | Very high |
| **Read docs + hand-author** | Depends on rigour | Very high |
| **`*ReadOnlyAccess` managed policy + iterate** | Coarse | Medium |

Access Analyzer wins on both axes — the granularity of manual parsing at the effort of one-click.

**Common Anti-patterns (exam wrong answers):**

- *"Remove the broad policies first, then observe what fails"* — deliberately not the answer. Script must run successfully so CloudTrail captures every call.
- *"Trial-and-error: start with no permissions, add on each AccessDenied"* — the classic anti-pattern; time-consuming and error-prone.
- *"Use `AmazonEC2ReadOnlyAccess` instead"* — still AWS-managed, still broader than needed.
- *"Use IAM Access Advisor"* — service-level only; insufficient for a least-privilege policy.
- *"Use AWS Config to generate the policy"* — Config tracks resource state, not API-call history.
- *"Enable CloudTrail Insights"* — anomaly detection, not policy generation.
- *"Use CloudFormation Guard"* — template linter, unrelated to IAM.
- *"Use Trusted Advisor"* — best-practice snapshot; no policy generation.
- *"Access Analyzer detects external access, not policy generation"* → external access is a *different feature* under the same umbrella; the exam distinguishes them.

**Exam Triggers:**

- *"Least-privilege customer-managed policy replacing AWS-managed + most operationally efficient"* → **Access Analyzer policy generation from CloudTrail**
- *"Generate a policy from actual usage history"* → **Access Analyzer policy generation**
- *"Find resources shared externally"* → **Access Analyzer external access analysis**
- *"Find unused IAM roles or permissions"* → **Access Analyzer unused access analysis**
- *"Validate a policy before deploying / block CI on more-permissive policies"* → **Access Analyzer custom policy checks / validation**
- *"90-day CloudTrail-based analysis of role activity"* → **Access Analyzer policy generation**

> *Mental model: **IAM Access Analyzer is `strace` for IAM** — five features under one umbrella, each answering a different least-privilege question. The exam distinguishes them:*
> - *"Who's calling me from outside?" → **external access analysis***
> - *"What did this role actually use?" → **policy generation** (with the counterintuitive "keep broad policies attached first" workflow)*
> - *"What's stale?" → **unused access analysis***
> - *"Is this new policy more permissive?" → **custom policy checks***
> - *"Is this policy well-formed?" → **policy validation***
> *For "replace AWS-managed with customer-managed, most efficient" → policy generation every time. Anyone suggesting hand-authoring, trial-and-error, Access Advisor, or CloudTrail parsing has picked the high-effort path.*

## Domain 5 — Data Protection (18%)

### KMS Deep Dive

- **Key types:** AWS-managed (auto-rotated yearly, can't customize) vs Customer-managed (rotate on demand, custom policy) vs AWS-owned (invisible).
- **Symmetric** (default, AES-256 GCM) vs **Asymmetric** (RSA / ECC for sign+verify, envelope encryption).
- **Key policies** are mandatory — root user access defaults enabled; IAM policies alone can't grant KMS access without the key policy.
- **Grants** — temporary programmatic permissions on a key (used by AWS services like RDS on your behalf); expire and can be retired.
- **Multi-Region keys** — separate KMS keys with the same key material replicated across regions; app can encrypt in one region, decrypt in another.

#### Customer-managed KMS key vs client-side encryption (disambiguation)

Both terms contain "customer" — easy to conflate, favourite exam trap. They are **two orthogonal axes**:

| Axis | Question it answers | Options |
|---|---|---|
| **Key ownership** | *Who controls the key policy, rotation, and lifecycle?* | AWS-managed, **customer-managed**, or customer-supplied |
| **Where encryption happens** | *Does plaintext reach AWS before it's encrypted?* | **Server-side** (AWS encrypts) or **client-side** (your app encrypts first) |

A **customer-managed KMS key (CMK)** answers ownership only. The key material still lives inside AWS KMS HSMs — you never see the bytes. You just own the *policy, alias, rotation schedule, and grants*.

**Mode matrix (memorise for the exam):**

| Mode | Key material lives | Encryption happens | Typical use |
|---|---|---|---|
| **SSE-S3** | AWS-owned, invisible | Server-side | Default S3 encryption |
| **SSE-KMS with `aws/s3`** | AWS KMS HSM, AWS-controlled policy | Server-side | Zero-config KMS on S3 |
| **SSE-KMS with a customer-managed CMK** | AWS KMS HSM, your policy | Server-side | The two-lock separation-of-duties design (above) |
| **SSE-C** | You send the key in every request header | Server-side (AWS uses it in memory, discards) | Rare; niche compliance |
| **CSE-KMS** | AWS KMS HSM (customer-managed CMK) | **Client-side** — app calls KMS for a DEK, encrypts locally | Pre-encrypt before `PutObject` |
| **CSE-C** | You hold the key entirely, off AWS | **Client-side** | HYOK / BYOK |

**The overlap that trips people up:** `CSE-KMS` uses a **customer-managed CMK** *and* is client-side encryption. So "customer-managed KMS key" can appear in either server-side or client-side modes — the term alone doesn't tell you where encryption happens.

**Quick decision rule:**

- Question says *"customer-managed KMS key"* → about **who owns the key policy**, not where encryption happens.
- Question says *"client-side encryption"* → about **where encryption happens**, usually implies a KMS or externally-held key.
- Both terms together → almost always **CSE-KMS** (client-side using a customer-managed CMK).

> *Mental model: "Customer-managed" = **who holds the policy**. "Client-side" = **where the encryption code runs**. Two independent axes — always disambiguate before picking an answer.*

### Envelope Encryption

**Numbered flow (SSE-KMS on S3):**

1. Client uploads object → S3 requests a **data key** from KMS.
2. KMS generates plaintext DEK + encrypted DEK (using the CMK).
3. S3 encrypts the object with the plaintext DEK, discards the plaintext DEK, stores the encrypted DEK alongside the object.
4. On download, S3 sends the encrypted DEK to KMS, KMS returns the plaintext DEK, S3 decrypts.

Result: every object gets a unique DEK; the CMK never touches the data.

#### Client-side encryption + tamper detection for DynamoDB (AWS Database Encryption SDK)

**The canonical SCS-C03 "protect from the point of creation + detect unauthorised changes" question.** Two phrases in the stem lock in the answer:

- *"From the point of creation until it is stored and later read"* → **client-side encryption**. SSE-KMS starts at storage, not at creation, so it's out.
- *"Detect whether anyone has changed the stored data without authorization"* → **cryptographic signing / integrity**, not audit logs. CloudTrail tells you *who* wrote; only a signature tells you whether the stored bytes have been altered.

**The tool:** the **AWS Database Encryption SDK for DynamoDB** (formerly the *DynamoDB Encryption Client*), a client-side encryption library. It uses **KMS** as the master key provider and does two things in one call:

1. **Encrypts** sensitive attributes on the client before `PutItem`.
2. **Signs** each item with an HMAC (also derived via KMS). On `GetItem`, the SDK verifies the signature — tampered items fail verification and error out instead of returning silently bad data.

**Numbered flow:**

1. App calls `EncryptItem` with plaintext + table config specifying which attributes to encrypt vs sign vs leave plaintext.
2. SDK asks KMS for a **data key** (envelope encryption): plaintext DEK + encrypted DEK.
3. SDK encrypts the sensitive attributes with the DEK, computes an HMAC over the item, and stores encrypted DEK + signature as extra DynamoDB attributes alongside the ciphertext.
4. App `PutItem` → DynamoDB stores the encrypted + signed item.
5. On `GetItem`, `DecryptItem` retrieves the encrypted DEK, asks KMS to decrypt (KMS enforces its key policy here), verifies HMAC, decrypts attributes. **Signature failure = error, not silent bad data.**

**Attribute-action model — memorise the three types:**

- **ENCRYPT_AND_SIGN** — sensitive; encrypted and included in signature.
- **SIGN_ONLY** — plaintext but tamper-detectable (primary/sort keys — DynamoDB needs them plaintext for lookups, but you still want to detect if someone rewires key ↔ payload).
- **DO_NOTHING** — plaintext, not signed (GSI keys / non-sensitive searchable fields).

**Client-side vs server-side decoder (memorise for the exam):**

| Stem phrase | Encryption scope required |
|---|---|
| *"Encrypt data at rest"* | Server-side (SSE-KMS is enough) |
| *"Encrypt in transit"* | TLS |
| *"Encrypt from the point of creation"* / *"before data leaves the application"* / *"AWS should never see plaintext"* | **Client-side** (AWS Database Encryption SDK) |
| *"Detect tampering / unauthorised modification of stored data"* | **Cryptographic signing** (SDK's HMAC), NOT audit logs |

**Common Anti-patterns (exam wrong answers):**

- *"Enable SSE-KMS on the DynamoDB table"* → satisfies at-rest encryption only, starts at storage. Fails "from point of creation." Doesn't sign.
- *"Enable DynamoDB Streams + CloudTrail to log changes"* → audit trail, not tamper detection. An attacker with a legitimate role writes normally-looking updates that Streams records as any other change.
- *"Store hashes of each row in a separate table"* → home-grown; exam prefers managed. Loses per-attribute granularity, no key rotation help.
- *"Use QLDB instead"* → cryptographic verifiability, but different service; the question specified DynamoDB.
- *"TLS + SSE-KMS is enough"* → protects the pipe and the disk, not the item at the service boundary, and no signing.
- *"Encrypt the whole item as one blob before PutItem"* → reinvents what the SDK gives you; no attribute-level granularity, no signing, no key rotation.

**Exam Triggers:**

- *"Highly sensitive data + protect from creation + detect tampering"* → **AWS Database Encryption SDK for DynamoDB** with KMS
- *"Attribute-level encryption in DynamoDB"* → **Database Encryption SDK**, not SSE-KMS
- *"AWS operators should never see plaintext"* → **client-side encryption** pattern
- *"Cryptographically verify data has not been altered"* → SDK's **SIGN** actions

> *Mental model: **SSE-KMS = door lock** on storage (keeps casual reads out). **Client-side encryption + signing = tamper-evident seal on the envelope itself** — the mailman never sees the letter, and if anyone slit the seal, you know on open. "From creation" + "detect tampering" → reach for the AWS Database Encryption SDK.*

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

#### Enforce encryption on `PutObject` — the bucket-policy Deny (memorise cold)

**The canonical "enforce SSE at rest" answer the exam picks over "enable default encryption on the bucket."** Since 2023 S3 defaults to SSE-S3 on every new bucket, so uploads are technically encrypted regardless — but the exam still rewards the bucket-policy Deny because it's a **codified guardrail** that survives future bucket-setting drift.

**Two condition-key variants (know when each applies):**

- **`Null`** — deny uploads that omit the encryption header entirely:

  ```json
  {
    "Sid": "DenyUnencryptedObjectUploads",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
    "Condition": {
      "Null": { "s3:x-amz-server-side-encryption": "true" }
    }
  }
  ```

- **`StringNotEquals` with `"aws:kms"`** — force **SSE-KMS specifically** (not SSE-S3, not SSE-C):

  ```json
  "Condition": {
    "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" }
  }
  ```

When the stem pairs "KMS for key management" with "encrypt at rest," pick the **`StringNotEquals` = `aws:kms`** variant.

**Common Anti-patterns for this specific "enforce encryption" ask:**

- *"Just enable default encryption on the bucket"* — true but weaker; a future admin can flip the toggle off. The bucket-policy Deny is what the exam rewards.
- *"Enable AWS Config rule to detect unencrypted objects"* — detective, not preventive; too late.
- *"Trust clients to always include the encryption header"* — no enforcement.

#### The "encrypt everything + monitor endpoints + minimal effort" three-action recipe

**A recurring exam pattern** across EC2 + ELB + S3 workloads. Each requirement resolves to one native action; nothing is redundant.

| Requirement | Answer |
|---|---|
| Encrypt at rest (S3) | **KMS + bucket policy denying `s3:PutObject` without `x-amz-server-side-encryption`** |
| Encrypt at rest (EBS) | **Enable EBS default encryption at the region level** (one Console toggle; uses KMS) |
| Encrypt in transit (client → LB) | **ACM certificate + HTTPS listener on the ELB** |
| Encrypt in transit (LB → target) | **HTTPS target group** (or SSL passthrough) |
| Monitor endpoints for anomalous traffic | **Enable Amazon GuardDuty** — agentless, one toggle, natively analyses VPC Flow Logs + CloudTrail + DNS |

**Why each is the "minimal effort" pick:**

- The S3 bucket-policy Deny is **one policy statement** — no code, no infra.
- ACM is **free + auto-rotating** — no cert management overhead.
- GuardDuty is **agentless + regional toggle** — no per-instance install, no rule authoring.

**Common Anti-patterns for the whole recipe:**

- *"Install antivirus / IDS agent on every EC2"* — high operational effort; fails "minimal implementation effort."
- *"Configure VPC Flow Logs + author your own CloudWatch anomaly detection"* — reinvents GuardDuty.
- *"Use CloudFront in front of ELB for TLS"* — over-engineered; the requirement is on the ELB itself.
- *"Enable AWS Config to detect unencrypted S3 uploads"* — detective, not preventive.
- *"Enable AWS Network Firewall for anomaly detection"* — inline enforcement; more setup than GuardDuty for pure detection.

**Exam Triggers:**

- *"Encrypt at rest + minimal effort + S3"* → **KMS + bucket policy denying unencrypted PutObject** (`StringNotEquals` on `aws:kms` if forcing KMS)
- *"Encrypt in transit + ELB"* → **ACM cert + HTTPS listener**
- *"Monitor endpoints for anomalous traffic, native, no agents"* → **GuardDuty**
- *"Encryption at rest for EBS across the region"* → **EBS default encryption** (regional toggle)

> *Mental model: for the classic "encrypt everything + monitor + minimal effort" trio, each requirement has exactly **one native answer** — **KMS+bucket-policy Deny** for S3 at-rest, **ACM+HTTPS** for in-transit, **GuardDuty** for anomaly detection. The bucket-policy Deny is what turns "we default to encryption" into "we refuse anything else" — that's why the exam picks it over "just enable default encryption."*

#### Separation of duties — the two-lock pattern (SSE-KMS with a customer-managed CMK)

**Anchored against the classic "vault needs two keys turned simultaneously" model.** SSE-KMS with a **customer-managed CMK** is the only S3 encryption mode where two independently-owned policies gate the plaintext path — a favourite SCS-C03 scenario.

**The design:**

- **Encryption:** every object stored with SSE-KMS using a customer-managed CMK (never `aws/s3`, never SSE-S3, never SSE-C).
- **Bucket policy** — owned by the **operations team**; grants `s3:*` on the bucket. Grants **no** `kms:*`.
- **KMS key policy** — owned by the **security team**; grants `kms:Decrypt / Encrypt / GenerateDataKey` only to the specific data-consuming principals. The ops team is not granted `kms:Decrypt`.

**Numbered plaintext-download flow (the double lock):**

1. Caller `GetObject` → S3 evaluates the **bucket policy / ACL** (ops-controlled).
2. If allowed, S3 asks KMS to decrypt the object's stored DEK.
3. KMS evaluates the **key policy** (security-controlled) — is the caller allowed `kms:Decrypt`?
4. Only if both succeed does S3 return plaintext.

**Failure-mode table:**

| Mistake | Consequence |
|---|---|
| Ops team makes bucket world-readable | Attackers get **ciphertext only**; no `kms:Decrypt` → cannot obtain plaintext |
| Security team over-grants `kms:Decrypt` | Extra principals still can't read objects unless bucket policy also allows them |
| Both teams err simultaneously | Plaintext leak — the exact scenario the design prevents |

**Two-team ownership rule of thumb (memorise):**

| Resource | Owned by | Grants | Must NOT grant |
|---|---|---|---|
| S3 bucket policy | **Ops team** | `s3:*` to consumers | any `kms:*` |
| KMS key policy | **Security team** | `kms:Decrypt/Encrypt/GenerateDataKey` to consumers | any `s3:*` |
| IAM policies on the app | either | tie-breaker — cannot shortcut either lock | — |

**Why the other S3 encryption modes fail this test:**

- **SSE-S3** — S3-managed keys; no key policy exists to split. Bucket permissions alone gate plaintext.
- **SSE-KMS with `aws/s3`** — the AWS-managed key policy is not editable by you; the security team has no independent lever.
- **SSE-C** — key travels per-request in a header; no policy-driven team boundary.
- **Client-side encryption (CSE)** — not "server-side" as the exam typically requires; also shifts the boundary to the app.

**Exam Triggers:**

- *"Separation of duties between bucket admins and key admins"* → **SSE-KMS + customer-managed CMK**, split policies.
- *"One team's mistake must not expose plaintext"* → **double lock**: bucket policy AND key policy.
- *"Encryption keys managed by the security team only"* → **customer-managed CMK**, never AWS-managed.
- *"Server-side encryption of S3 with independent key control"* → **SSE-KMS + CMK**.

**Common Anti-patterns (exam wrong answers):**

- *"Use SSE-S3, security team owns the bucket policy"* → wrong; SSE-S3 has no separable key policy.
- *"Use `aws/s3` and separate IAM policies"* → wrong; `aws/s3` key policy is not editable.
- *"Use SSE-C and give the security team custody of the key material"* → wrong; SSE-C keys travel per-request, no policy split.
- *"Encrypt client-side before upload"* → wrong; question typically specifies server-side.

> *Mental model: SSE-KMS + CMK is the only S3 mode with **two independently-owned policies** on the plaintext path. Ops holds the bucket key, security holds the crypto key — plaintext requires both locks to open.*

### AWS Backup

**Anchored against a central backup product (like Veeam or Rubrik).** One managed control plane that schedules + retains backups across many AWS resource types, replacing per-service snapshot mechanisms with a single policy surface.

**Why the exam reaches for it:** whenever the stem says *"scheduled backups + retention management"* — especially spanning more than one resource type or with a cross-account/compliance requirement — Backup wins over the per-service alternatives (DynamoDB on-demand backups, RDS automated snapshots, EBS snapshot lifecycle manager, etc.).

**Resource types Backup covers:**

| Category | Resources |
|---|---|
| Compute | EC2 instances, EBS volumes |
| Databases | RDS, Aurora, DynamoDB, DocumentDB, Neptune, RDS on Outposts, Timestream |
| Storage | EFS, FSx (Windows / Lustre / NetApp ONTAP / OpenZFS), S3 (via Backup for S3) |
| Hybrid | Storage Gateway volumes |
| Directories | AWS Managed Microsoft AD |
| SAP | SAP HANA on EC2 |

**Building blocks (memorise the vocabulary):**

- **Backup plan** — schedule (cron) + lifecycle (delete after N days, transition to cold after M days) + destination vault + optional cross-region / cross-account copy.
- **Backup vault** — encrypted container for recovery points. Each vault has its own KMS key + access policy.
- **Backup selection** — which resources this plan protects, chosen by resource ARN or by tag.
- **Recovery point** — one backup instance. Immutable metadata, encrypted contents.

**Three exam-worthy features:**

#### 1. Vault Lock (WORM / compliance mode) — the most-tested Backup feature

Analogous to S3 Object Lock:

- **Compliance mode** — recovery points cannot be deleted until their retention expires, **not even by the root user or AWS Support**. Set a Lock cooling-off period; once past that, it's immutable.
- **Governance mode** — softer; can be overridden by principals with the right permissions.
- Used for regulatory retention (HIPAA, PCI, FINRA 17a-4, SEC).

Exam trigger: *"backups that even the root user cannot delete"* → **Vault Lock in compliance mode**.

#### 2. Cross-region + cross-account copy

- Backup plans can automatically **copy** each recovery point to a vault in another region and/or another account (typically a dedicated backup/archive account).
- Meets DR requirements AND ransomware defence (production account can't destroy the DR copy).

Exam trigger: *"ransomware-resistant offline copy in a separate account"* → **cross-account copy to a locked vault**.

#### 3. Organizations-wide Backup policies (central management)

- Delegated Backup admin account (like GuardDuty / Config / Security Hub).
- **Backup policies** attached at Org / OU / account — the fourth policy type alongside SCPs, RCPs, and Tag policies (see [[aws-organizations--foundational-structure]]).
- Enforce baseline backup plans across the whole Org — accounts can't opt out.

Exam trigger: *"enforce consistent backup posture across all accounts"* → **AWS Backup + Organizations Backup policies**.

**Backup Audit Manager (bonus):**

Continuous compliance reporting on your backup posture:

- Have all required resources been backed up in the last 24 h?
- Do recovery points meet the retention requirement?
- Are backups copied cross-region as required?

Feeds evidence into **AWS Audit Manager** frameworks (PCI, HIPAA, NIST).

**When Backup wins vs when the per-service feature wins:**

| Stem asks for… | Winner |
|---|---|
| *"Scheduled backups + retention management"* (any resource) | **AWS Backup** |
| *"Backups across multiple resource types with a single policy"* | **AWS Backup** |
| *"Backups even root cannot delete"* | **AWS Backup + Vault Lock** |
| *"Ransomware-resistant offline copy in a separate account"* | **AWS Backup cross-account copy** |
| *"Enforce backups across all Org accounts"* | **Backup + Organizations Backup policies** |
| *"Restore DynamoDB to any point in the last 35 days"* | **DynamoDB PITR** (native, not Backup) |
| *"On-demand snapshot before a risky RDS migration"* | **RDS manual snapshot** (native, not Backup) |
| *"S3 versioning + Object Lock for compliance"* | **S3-native features**, not Backup |

**What AWS Backup is NOT:**

- **NOT PITR (point-in-time recovery)** — PITR is continuous rewind (DynamoDB, RDS/Aurora have their own). Backup is scheduled snapshots.
- **NOT S3 Object Lock** — Object Lock is per-object WORM in S3. Vault Lock is analogous but scoped to Backup vaults.
- **NOT AWS Backup for S3 = a replacement for S3 versioning** — S3 has its own protection stack (versioning + replication + Object Lock); Backup for S3 exists but the exam usually favours the S3-native tools.
- **NOT a DR failover service** — Backup gives you recovery points; failing over to another region is orchestration you do on top (Route 53, warm standby, etc.).

**Common Anti-patterns (exam wrong answers):**

- *"Write a Lambda cron to call DynamoDB CreateBackup"* — reinvents Backup for a single resource; no central retention, no vault lock, no cross-account copy.
- *"Use PITR for scheduled backups"* — PITR is continuous rewind, not scheduled snapshots. Different feature.
- *"Use S3 lifecycle rules to expire recovery-point objects"* — Backup manages retention in the vault; you don't touch the underlying S3 storage directly.
- *"Rely on RDS automated backups for compliance retention"* — max 35 days, no Vault Lock, no cross-region orchestration, no tag-based selection.
- *"Copy backups manually via CLI to a second region for DR"* — Backup plans automate this via copy actions.

**Exam Triggers:**

- *"Scheduled backups + retention management"* → **AWS Backup**
- *"Backups even root cannot delete"* → **Vault Lock (compliance mode)**
- *"Immutable backups for HIPAA / PCI / FINRA / SEC 17a-4"* → **Vault Lock compliance mode**
- *"Ransomware-resistant offline copy in a separate account"* → **cross-account copy to a locked vault**
- *"Enforce backups across all Org accounts"* → **Backup policies via Organizations**
- *"Compliance report proving backups happened"* → **Backup Audit Manager**

> *Mental model: AWS Backup = **one control plane for backups across many services**, with Vault Lock for immutability, cross-account copy for ransomware defence, and Org-wide policies for scale. Whenever the stem says "scheduled + retention + centralised" — especially with more than one resource type or a compliance / immutability angle — it's Backup, not the per-service snapshot feature.*

### S3 Access Points

**Anchored against "named views on the same bucket, each with its own DNS + policy."** The AWS-native answer to *"our bucket policy has become unmanageable across many consumers."* Split access by consumer: each app / department / tenant gets its own access point with its own scoped policy, own DNS hostname, and optionally a VPC restriction. The bucket policy stays small — it just delegates to access points.

**Three exam-canonical characteristics (the "select three" pattern):**

1. **Each access point has its own DNS hostname (and ARN).** Format: `<name>-<account-id>.s3-accesspoint.<region>.amazonaws.com`. Applications hit the access point instead of the bucket — each consumer talks to its own endpoint.
2. **Each access point has its own access policy (resource-based).** Evaluated *together with* the bucket policy — both must allow (unless the bucket policy delegates access-point authority via `s3:DataAccessPointAccount` / `s3:DataAccessPointArn` condition).
3. **Each access point can be restricted to a specific VPC (network origin).** Set `NetworkOrigin: VPC` at creation and the access point is reachable only from that VPC — internet traffic denied *before IAM evaluates*. Immutable once set.

**Diagram — one bucket, three access points, three consumer patterns:**

```text
                        ┌──────────────────────────────┐
                        │       S3 Bucket              │
                        │       my-business-data       │
                        │                              │
                        │       Bucket policy:         │
                        │       delegates to           │
                        │       access points in       │
                        │       this account           │
                        └───────────┬──────────────────┘
                    ┌───────────────┼───────────────────┐
                    │               │                   │
      ┌─────────────▼──────┐  ┌─────▼──────────┐  ┌─────▼──────────────┐
      │ Access Point:      │  │ Access Point:  │  │ Access Point:      │
      │ customer-portal    │  │ analytics-team │  │ internal-etl       │
      │                    │  │                │  │                    │
      │ Origin: Internet   │  │ Origin: VPC-A  │  │ Origin: VPC-B      │
      │ Policy: customers  │  │ Policy: read-  │  │ Policy: write-only │
      │  can Get their own │  │  only, prefix  │  │  to /raw prefix    │
      │  prefix            │  │  = /processed  │  │                    │
      │                    │  │                │  │                    │
      │ DNS: customer-     │  │ DNS: analytics-│  │ DNS: internal-etl- │
      │  portal-*.s3-ap.…  │  │  team-*.s3-ap.…│  │  *.s3-ap.…         │
      └────────────────────┘  └────────────────┘  └────────────────────┘
```

Same storage, three isolated access surfaces.

**Bucket-policy delegation idiom (memorise):**

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "*" },
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "s3:DataAccessPointAccount": "123456789012"
    }
  }
}
```

The bucket allows access through *any* access point in the same account; each access point's own policy does the narrow scoping.

**What access points are NOT:**

- **NOT a bucket-policy replacement.** Both still evaluate together; access points *simplify*, they don't remove.
- **NOT S3 Object Lambda access points.** Object Lambda APs transform data on read (via a Lambda function). Standard access points just gate access.
- **NOT cross-region.** An access point lives in a specific region; the bucket must be in the same region.
- **NOT renamable.** Access point name is immutable after creation.
- **NOT multi-bucket.** One access point maps to exactly one bucket.
- **NOT a Block Public Access bypass.** BPA still applies; access points also support their own BPA settings.
- **NOT a KMS bypass.** SSE-KMS still requires `kms:Decrypt` on the CMK from callers.

**Common Anti-patterns (exam wrong answers):**

- *"Access points replace the bucket policy"* — no; both evaluate together.
- *"Access points transform data on retrieval"* — that's **Object Lambda access points**, a separate feature.
- *"Access points can be renamed"* — no; immutable name.
- *"Access points span multiple buckets"* — no; one bucket each.
- *"Access points share across regions"* — no; region-scoped.
- *"Access points make buckets public"* — no; BPA still applies.
- *"Network origin can be changed after creation"* — no; immutable.

**Exam Triggers:**

- *"Simplify complicated bucket policies + many consumers"* → **S3 access points** with per-endpoint policies
- *"Restrict specific consumers to a VPC while others use the internet"* → **access points with `NetworkOrigin: VPC` vs `Internet`**
- *"Different DNS endpoints on the same bucket per app"* → access points' unique hostnames
- *"Transform data per-consumer on retrieval"* → **S3 Object Lambda access points** (different feature)
- *"Grant temporary consumer access without editing the bucket policy"* → **create a new access point** with a scoped policy, delete when done

> *Mental model: **S3 access points = named views on the same bucket** — each with its own DNS hostname, its own policy, and optionally its own VPC restriction. The bucket policy shrinks to a delegation statement; the real access scoping lives in per-consumer access-point policies. Different from Object Lambda access points, which additionally *transform* the data as it's read. When the exam says "simplify one giant bucket policy across many consumers," reach for access points.*

### EBS Encryption at Scale

**The canonical SCS-C03 "encrypt all EBS volumes now and in the future"question class.** Splits into two half-problems that need two different fixes, plus a preventive layer and a detective layer for defence in depth.

**The four layers (memorise all four):**

| Layer | Tool | What it does |
|---|---|---|
| **Future volumes (preventive default)** | **EBS encryption by default** (regional account attribute) | Every new EBS volume in the region auto-encrypted with the default KMS key — regardless of source (launch template, `CreateVolume`, CloudFormation, Terraform, ad-hoc) |
| **Future volumes (preventive guardrail)** | **SCP with `ec2:Encrypted = false` Deny** | Org-wide belt-and-suspenders — blocks any `CreateVolume` / `RunInstances` where the request context says the volume would be unencrypted |
| **Existing volumes (migration)** | **Snapshot → copy snapshot encrypted → new volume from encrypted snapshot → replace** | The only way to encrypt existing unencrypted volumes; EBS doesn't support in-place encryption |
| **Continuous verification (detective)** | **AWS Config rules** (`ec2-ebs-encryption-by-default`, `encrypted-volumes`) | Ongoing evaluation that (a) default encryption is on in every region, and (b) no unencrypted volumes exist |

#### Part A — enable EBS encryption by default (the "future" fix)

Single API call per region:

```bash
aws ec2 enable-ebs-encryption-by-default --region <region>
```

Optionally specify a customer-managed CMK as the default (otherwise `aws/ebs`):

```bash
aws ec2 modify-ebs-default-kms-key-id \
  --kms-key-id arn:aws:kms:<region>:<account>:key/<cmk-id> \
  --region <region>
```

Console: **EC2 → Data protection and security → EBS encryption → Manage → Enable + choose KMS key**.

Once on:

- Every new volume from `RunInstances`, `CreateVolume`, `CopyImage`, `CopySnapshot`, `CreateSnapshot` — automatically encrypted.
- The `Encrypted` flag in launch templates / CloudFormation / API calls is *effectively forced to `true`* — can't be overridden to `false`.
- **Regional only** — must be enabled per region you operate in.

#### Part B — org-wide preventive SCP (belt-and-suspenders)

Layered on top of the regional default so even if a region's default is turned off (accident or malicious), unencrypted volume creation is still blocked:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedEBSVolumes",
    "Effect": "Deny",
    "Action": [
      "ec2:CreateVolume",
      "ec2:RunInstances"
    ],
    "Resource": "*",
    "Condition": {
      "Bool": {
        "ec2:Encrypted": "false"
      }
    }
  }]
}
```

Apply at Org root / OU containing all workload accounts. This is the *preventive* layer (see [[preventive-vs-detective-vs-responsive--the-three-tier-framework]]).

#### Part C — migrate existing unencrypted volumes (the "now" fix)

**EBS does not support in-place encryption.** For every unencrypted volume you must:

1. **Snapshot** the volume — `aws ec2 create-snapshot`.
2. **Copy the snapshot with encryption enabled** — `aws ec2 copy-snapshot --encrypted --kms-key-id <cmk>`. This is the actual encryption step; the copy target is encrypted even when the source isn't.
3. **Create a new volume from the encrypted snapshot** — `aws ec2 create-volume --snapshot-id <encrypted-snapshot>`.
4. **Detach the unencrypted volume; attach the encrypted replacement** (requires stopping the instance for root-volume swap; can be done live for data volumes on some instance types).
5. **Delete the unencrypted volume + unencrypted snapshot** after validation.

**For ASG-managed instances**, a leaner approach:

1. Enable EBS encryption by default (Part A).
2. **Copy the launch template's AMI with encryption enabled** (`aws ec2 copy-image --encrypted`) → update template to reference the encrypted AMI.
3. **Trigger an ASG instance refresh** (`aws autoscaling start-instance-refresh`) → replaces every instance with encrypted root volumes.

#### Part D — Config rules for continuous verification (detective)

Two managed rules to pair with the recipe:

- **`ec2-ebs-encryption-by-default`** — flags any account/region where encryption-by-default is off.
- **`encrypted-volumes`** — flags any EBS volume that isn't encrypted (catches surviving unencrypted volumes).

Combine with the canonical Config-rule + auto-remediation + SNS pattern (Domain 6 → AWS Config) so any drift is auto-alerted.

**Why "modify the launch template's `Encrypted` flag" is the wrong exam answer:**

| Aspect | Regional default | Launch template `Encrypted: true` |
|---|---|---|
| Scope | All new volumes in the region, regardless of source | Only volumes launched by *that* template |
| Ad-hoc `CreateVolume` calls | ✅ encrypted | ❌ not covered |
| Other launch templates | ✅ encrypted | ❌ not covered |
| CloudFormation / Terraform volumes | ✅ encrypted | ❌ requires each stack to set the flag |
| Bypassable by omission | ❌ (regional attribute) | ✅ (next template forgets) |
| Auditor-friendly | ✅ single regional setting | ❌ audit every template |
| Existing volumes | ❌ (still need migration) | ❌ (still need migration + replacement) |

Launch-template modification is a partial fix — only covers that template's future launches. The regional default is strictly better on every axis.

**The regional-scope gotcha (multi-region operations):**

- Encryption-by-default is **per-account per-region**. Must enable in every region you use.
- Automate rollout via SSM Automation runbook, Firewall Manager (no — Firewall Manager doesn't manage EBS encryption), or a CI script that iterates regions.
- Add a **Config aggregator** in the audit account so you can verify all regions × all accounts from one dashboard.

**Common Anti-patterns (exam wrong answers):**

- *"Modify the launch template's `Encrypted` flag"* — partial fix; doesn't cover ad-hoc creates, other templates, or existing volumes.
- *"Encrypt volumes in place"* — not supported by EBS.
- *"Use AWS Backup to encrypt volumes"* — Backup encrypts recovery points, not the live volumes themselves.
- *"Use Macie / GuardDuty / Inspector"* — wrong services.
- *"Wait for ASG to replace old instances naturally"* — too slow for compliance stems.
- *"Write a Lambda that scans and encrypts volumes"* — reinvents encryption-by-default; higher operational effort.
- *"Enable CloudHSM"* — overkill for standard EBS.
- *"Set up an SSM Automation runbook to enable encryption"* — Automation is for orchestration; the base primitive is the regional default.

**Exam Triggers:**

- *"Encrypt all EBS volumes now and in the future + minimal effort"* → **EBS encryption by default (regional) + migrate existing**
- *"All new volumes must be encrypted regardless of how they're created"* → **regional default**, not per-template config
- *"Prevent org-wide creation of unencrypted volumes"* → **SCP with `ec2:Encrypted = false` Deny**
- *"Continuously verify EBS encryption compliance"* → **Config rules** `ec2-ebs-encryption-by-default` + `encrypted-volumes`
- *"Encrypt an existing unencrypted volume"* → **snapshot → copy snapshot encrypted → new volume → replace**
- *"Encrypt all ASG-managed instance volumes"* → **regional default + encrypted AMI + instance refresh**

> *Mental model: EBS encryption is a **two-half problem** — existing volumes (migration) and future volumes (default encryption). Regional default is the strictly-better lever for the future half (covers every source, can't be bypassed by omission, single regional attribute to audit). Layer an **SCP `ec2:Encrypted = false` Deny** for org-wide preventive enforcement, pair **Config rules** for continuous verification, and use **snapshot → encrypted copy → replace** to migrate existing volumes. Launch-template modification is a partial fix the exam usually punishes.*

### EBS Snapshot Cross-Account Backup (CMK-encrypted)

**The canonical SCS-C03 "protect snapshots against a compromised account / ransomware / cyber attack" question.** When the threat model is a **fully-compromised production account** (not just accidental deletion), single-account defences (Recycle Bin, SCPs, Vault Lock) can eventually be circumvented by an attacker with sufficient privilege. **Cross-account snapshot copy is the only layer that survives full-account compromise** — the protection lives in a different security boundary.

**Threat-model decoder — which snapshot defence for which threat:**

| Threat scenario | Primary defence |
|---|---|
| *Cyber attack / ransomware / compromised production account* | **Cross-account copy** to isolated backup account (this section) |
| *Accidental deletion by an admin* | **EBS Recycle Bin** with retention rule |
| *Compliance mandate for N-year immutable retention* | **AWS Backup + Vault Lock compliance mode** |
| *Prevent snapshot from being shared publicly* | **SCP** with `ec2:ModifySnapshotAttribute` Deny + **AWS Config** rule `ebs-snapshot-public-restorable-check` |
| *Detect unauthorised snapshot deletion* | **CloudTrail** + **EventBridge** alert |

The stem's threat vector determines the primary defence. When the stem says *"cyber attack"* or *"compromised"* → cross-account copy is the answer.

**Why single-account defences aren't enough for account-level compromise:**

- **Recycle Bin** — an attacker with sufficient privilege can disable the retention rule (unless in compliance-mode retention lock — but even then only if compliance-mode was enabled *before* compromise).
- **SCPs** — apply to member accounts; compromise of the management account (or a well-privileged member role) can lift them.
- **Vault Lock (compliance mode)** — still lives in the same account; attacker with root or backup-service admin can eventually work around it.
- **KMS key policy** — attacker with `iam:PassRole` on the right role can bypass; also, if the CMK itself is compromised, all in-account protections fall.

**Cross-account copy fundamentally different:** the backup account is a separate IAM realm, separate root, separate set of principals. Compromise of production doesn't give the attacker any privilege in the backup account.

**The three-step cross-account copy mechanic (for CMK-encrypted snapshots — memorise the steps):**

Because the snapshots are **CMK-encrypted**, the copy has a KMS-permission wrinkle beyond the vanilla snapshot-sharing flow. Three steps:

#### Step 1 — Share the snapshot with the target account

Source (production) account modifies the snapshot's `createVolumePermission`:

```bash
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-0abc123 \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids <backup-account-id>
```

Makes the snapshot **visible and copyable** from the backup account.

#### Step 2 — Grant the backup account KMS access to the source CMK

The CMK's **key policy** (in the source account) must allow the backup account's principals to use the key for the copy operation. Without this, the copy fails with a KMS access error — this is the gotcha the exam specifically tests:

```json
{
  "Sid": "AllowBackupAccountToCopyEncryptedSnapshot",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<backup-account-id>:root" },
  "Action": [
    "kms:Decrypt",
    "kms:CreateGrant",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:DescribeKey",
    "kms:ReEncrypt*"
  ],
  "Resource": "*",
  "Condition": {
    "Bool": { "kms:GrantIsForAWSResource": "true" }
  }
}
```

The `kms:GrantIsForAWSResource` condition scopes the CreateGrant to AWS-service-driven usage (EBS in this case), preventing the backup account from creating arbitrary grants.

#### Step 3 — Backup account issues `CopySnapshot`

From within the backup account, using its own IAM permissions plus the KMS grant above:

```bash
aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id snap-0abc123 \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:<backup-account-id>:key/<backup-cmk> \
  --description "Cross-account backup copy from prod"
```

**Best practice — re-encrypt with a backup-account CMK during the copy.** Not the source CMK. This gives the backup account **cryptographic independence** — a compromised source CMK (or its policy) doesn't render the backup copies unusable.

**Numbered runtime flow:**

1. Production creates a snapshot → encrypted with the source CMK.
2. Automation (AWS Backup / EventBridge → Lambda / SSM Automation) modifies the snapshot attribute to share with the backup account.
3. Automation triggers `CopySnapshot` in the backup account.
4. EBS in the backup account requests KMS operations on the source CMK (allowed via the key policy from Step 2) to decrypt the source DEK.
5. EBS re-encrypts with the backup-account CMK.
6. New encrypted snapshot lives in the backup account, decryptable only via the backup account's CMK.
7. Original production CMK compromise → backup copies remain accessible via backup CMK.
8. Original snapshot deletion → backup copies unaffected (isolated account boundary).

**Regularising the copy on schedule — three managed approaches:**

- **AWS Backup with cross-account copy action in the backup plan** — the modern managed approach. Set a Backup plan that snapshots EBS + copies to a vault in the backup account. Combine with **Vault Lock compliance mode** on the destination vault for WORM immutability. This is the AWS-recommended path (see [[aws-backup]]).
- **EventBridge scheduled rule → Lambda** iterating production snapshots and initiating copies.
- **SSM Automation runbook** (`AWSSupport-*` or custom) executed on schedule.

The AWS Backup approach is the leanest — one policy handles snapshotting + sharing + copying + retention + optional Vault Lock.

**Backup account hardening (best practices):**

- **Minimal IAM** — no admin humans in the account. Only a specific copy role can write; only a specific restore role can read.
- **SCP denying `ec2:DeleteSnapshot`** in the backup account except by a break-glass role.
- **Vault Lock compliance mode** on any AWS Backup vaults in the account.
- **Cross-account CloudTrail** logging to a third audit account for tamper-evident audit trail.
- **No trust relationships** from the backup account to the production account (production shouldn't be able to AssumeRole into backup).
- **MFA required** on any interactive access.

**Complete defence-in-depth stack (four layers, cross-account being the primary):**

| Layer | What it protects against |
|---|---|
| **Cross-account copy** (this section) | Full account compromise — attacker in production can't reach the backup account |
| **AWS Backup + Vault Lock compliance** on the destination vault | Root of backup account can't delete recovery points |
| **EBS Recycle Bin** in production | Accidental deletion (governance) or full anti-deletion (compliance-mode retention lock) |
| **SCP + KMS key policy** hardening | Preventive controls layered on production; belt-and-suspenders |

Cross-account is the **primary** layer for cyber-attack scenarios; the others are complementary.

**What plausible-looking wrong answers get wrong:**

- ***"Enable Recycle Bin only"*** — protects against deletion but not against a fully-compromised account that can disable the RBin rule.
- ***"SCP Deny on `ec2:DeleteSnapshot` in production"*** — SCPs are lift-able if the mgmt account is compromised; doesn't provide an isolated copy.
- ***"Use Vault Lock in production account"*** — same-account WORM; still vulnerable to root of the compromised account (before cooling-off period expires).
- ***"Encrypt with a new CMK per snapshot"*** — doesn't provide isolation from account compromise.
- ***"Take manual snapshots via CLI"*** — no isolation.
- ***"Move snapshots to Glacier / S3 Object Lock"*** — EBS snapshots don't move to those tiers directly.
- ***"Enable MFA delete"*** — S3-only feature.
- ***"Rely on IAM policies alone"*** — attacker with account creds bypasses IAM from the same account.
- ***"Copy the snapshot but don't grant the backup account KMS access"*** — copy fails because the target account can't decrypt during the copy. The CMK cross-account grant is what makes CMK-encrypted cross-account copy work.

**Common Anti-patterns:**

- Missing the KMS key policy step — copy fails silently or with cryptic errors.
- Re-using the source CMK for the copy — no cryptographic independence; source CMK compromise still affects backup.
- One-time manual copy — snapshots go stale; recovery is only as good as the latest copy.
- Backup account too privileged — defeats the isolation.
- Trust relationship from backup → production — allows a production compromise to pivot into the backup account.

**Exam Triggers:**

- *"Protect EBS snapshots from a cyber attack / compromised account / ransomware"* → **cross-account copy to isolated account**
- *"Copy CMK-encrypted snapshot cross-account fails"* → **KMS key policy** on source CMK must grant target-account principals `Decrypt`/`GenerateDataKeyWithoutPlaintext`/`ReEncrypt*`/`DescribeKey`/`CreateGrant` (with `kms:GrantIsForAWSResource: true`)
- *"Ransomware-resistant offline copy"* → **cross-account copy** + Vault Lock compliance in destination account
- *"Recover accidentally deleted snapshot"* → **EBS Recycle Bin** (different question class)
- *"WORM-immutable backups"* → **AWS Backup + Vault Lock compliance** (may be layered inside the backup account)
- *"Prevent snapshot from being made public"* → **SCP** with `ec2:ModifySnapshotAttribute` Deny + Config rule `ebs-snapshot-public-restorable-check`

> *Mental model: **when the threat model is compromise-level (cyber attack, ransomware, malicious insider), same-account defences aren't sufficient — every one of them (SCP, RBin, Vault Lock) can eventually be worked around by an attacker with enough privilege inside the same account. Cross-account snapshot copy to an isolated backup account is the only defence that survives full-account compromise because the protection lives in a different security boundary.*** For CMK-encrypted snapshots, cross-account copy requires **three coordinated steps**: (1) `ec2:ModifySnapshotAttribute` to share the snapshot with the target account, (2) update the **source CMK's key policy** to allow the target account's principals to decrypt / create-grant / re-encrypt, (3) target account issues `CopySnapshot` — re-encrypting with a **backup-account-owned CMK** for cryptographic independence. Regularise via AWS Backup cross-account copy (managed, includes Vault Lock option in destination) or EventBridge → Lambda. Recycle Bin, Vault Lock, and SCPs remain **complementary** layers, not primary for this threat class.

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

#### Canonical recipe: Config rule + auto-remediation + SNS email

**The single most-tested detective+responsive pipeline on SCS-C03.** Whenever the stem describes:

- *A specific compliance rule* (e.g. "no unencrypted RDS", "no public S3", "no untagged EC2")
- *+ email alert on violation*
- *+ auto-terminate / auto-fix the non-compliant resource*
- *+ "most operationally efficient"*

…the answer is a three-service, zero-code pipeline. No Lambda, no polling, no glue.

**The pipeline diagram:**

```text
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│  AWS Config       │──►│  Compliance-change│──►│   SNS topic       │
│  managed rule     │   │  event on         │   │   (email alerts)  │
│                   │   │  EventBridge      │   └───────────────────┘
└─────────┬─────────┘   └───────────────────┘
          │
          ▼
┌───────────────────┐
│  Auto-remediation │
│  via SSM          │
│  Automation       │
│  runbook          │
└───────────────────┘
```

**Numbered runtime flow:**

1. Someone creates / modifies a resource → the service emits a Configuration Item Change to Config.
2. Config evaluates the relevant managed rule → **NON_COMPLIANT**.
3. Config emits a **Compliance Change event** onto the default EventBridge bus (`source: aws.config`, `detail-type: Config Rules Compliance Change`).
4. EventBridge rule matches → SNS topic → email fires to the security-team distribution list.
5. Config auto-remediation kicks off the associated **SSM Automation runbook** → terminates / fixes the resource.
6. Wall-clock: minutes at most; entirely native, no maintenance overhead.

**Requirement → service mapping:**

| Stem phrase | Service |
|---|---|
| *"Prohibit unencrypted / public / non-compliant…"* | **AWS Config managed rule** |
| *"Email alert whenever a non-compliant resource is created"* | **EventBridge → SNS** (or Config's native SNS destination) |
| *"Automatically terminate / remediate"* | **Config auto-remediation → SSM Automation runbook** |

**Managed rules worth memorising (the exam-favourite compliance angles):**

| Rule | What it evaluates |
|---|---|
| `rds-storage-encrypted` | DB instance encryption at rest |
| `rds-cluster-encryption-at-rest-enabled` | Aurora cluster encryption |
| `rds-snapshots-public-prohibited` | No public RDS snapshots |
| `rds-instance-public-access-check` | No `PubliclyAccessible = true` |
| `s3-bucket-server-side-encryption-enabled` | S3 default encryption |
| `s3-bucket-public-read-prohibited` / `s3-bucket-public-write-prohibited` | No public S3 |
| `ec2-ebs-encryption-by-default` | Region-level EBS default encryption on |
| `restricted-ssh` / `restricted-common-ports` | No SG rules exposing SSH / RDP / DB ports to `0.0.0.0/0` |
| `iam-user-mfa-enabled` | Every IAM user has MFA |
| `root-account-mfa-enabled` | Root user has MFA |
| `cloud-trail-enabled` | CloudTrail is on in every region |

Managed rules exist for every common security control — reach for them before authoring a custom rule.

**Why this beats hand-rolled alternatives (the "operationally efficient" ranking):**

| Approach | Operational effort | Fit |
|---|---|---|
| **Config managed rule + auto-remediation runbook + SNS** | Very low — all native | ✅ **best** |
| CloudTrail event → EventBridge → Lambda to check + Lambda to terminate | Higher — you author + maintain two Lambdas | works but not "most efficient" |
| Custom Config rule (Lambda-backed) | Higher — you write the eval logic | wasted effort when a managed rule exists |
| SCP alone | Low, but prevents creation — no alert about a "created" non-compliant resource | wrong tier when the stem asks for alert + terminate |
| Security Hub standards + Custom Actions | Detects, but Custom Actions require analyst clicks | not "automatic" |
| Trusted Advisor + report | No auto-remediation, delayed detection | ❌ |

**Preventive-vs-detective decision (see [[preventive-vs-detective-vs-responsive--the-three-tier-framework]]):**

- If the stem *only* says *"prohibit unencrypted RDS across the org"* → **SCP** (preventive). Nothing is created.
- If the stem adds *"alert + terminate"* → **Config + auto-remediation** (detective + responsive). Something is created, evaluated, and auto-fixed.

The verb in the stem picks the tier.

**Common Anti-patterns (exam wrong answers for this class of question):**

- *"CloudTrail event → Lambda that checks encryption + Lambda that terminates"* — works but requires you to author + operate the code + IAM. Higher effort than Config.
- *"Enable Security Hub and use Custom Actions to delete non-compliant instances"* — Custom Actions require analyst clicks. Not "automatic."
- *"Enable GuardDuty to detect unencrypted RDS"* — wrong service; GuardDuty is behavioural threat detection, not compliance evaluation.
- *"SCP denying resource creation unless compliant"* — preventive; wrong tier for "alert + terminate" wording.
- *"Trusted Advisor + weekly report"* — no auto-remediation; delayed detection.
- *"Write a Lambda that scans resources every hour"* — polling; slower + heavier than event-driven Config.

**Exam Triggers:**

- *"Specific compliance rule + email alert + auto-remediate + operationally efficient"* → **this recipe** (Config managed rule + auto-remediation runbook + SNS)
- *"Delete non-compliant RDS automatically"* → **Config auto-remediation → SSM Automation runbook**
- *"Continuously score compliance across many standards"* → **Security Hub standards** (different question)
- *"Prevent creation entirely so no non-compliant resource ever exists"* → **SCP** (preventive, different tier)

> *Mental model: the Config-rule-plus-remediation-plus-SNS recipe is the **three-service, zero-code detective+responsive pipeline** — swap the managed rule and the runbook for any resource type (RDS, S3, EC2, IAM, SGs). Whenever the stem says "specific compliance rule + alert + auto-fix + most efficient," this shape wins over hand-rolled Lambda, SCP, or Security Hub Custom Actions.*

### Trusted Advisor

- Security checks (open SG ports, S3 public buckets, root MFA, IAM key rotation).
- **Business/Enterprise Support** unlocks full check set.

### Audit Manager

**Anchored against a compliance-framework evidence collector.** Audit Manager is not an evaluator — it's an **aggregator**. It doesn't check anything itself; it consumes signals from Config, Security Hub, CloudTrail, and your manual uploads and maps them to controls inside a named compliance framework, then generates auditor-ready reports.

**Pre-built frameworks (partial list):**

- AWS Foundational Security Best Practices (FSBP)
- AWS Control Tower Guardrails
- AWS Well-Architected Framework
- AWS Generative AI Best Practices
- PCI DSS v3.2.1 / v4.0
- HIPAA Security Rule
- SOC 2
- GDPR
- ISO/IEC 27001
- NIST 800-53 Rev 5 / 800-171 Rev 2 / CSF v1.1
- FedRAMP Moderate / Low
- CIS AWS Benchmark v1.4.0
- ACSC Essential Eight
- GxP EU Annex 11

You can also **author custom frameworks** and reuse individual controls across them.

**Evidence sources (four categories):**

1. **AWS Config rules** — including rules deployed via **Operational Best Practices conformance packs** (see below).
2. **AWS Security Hub findings** — from the FSBP, CIS, PCI, and NIST standards.
3. **AWS CloudTrail events** — proves an API was exercised.
4. **Manual uploads** — screenshots, attestations, policy documents.

**The "Operational Best Practices" naming confusion (high-value exam clarification):**

*"Operational Best Practices"* is an **AWS Config conformance-pack template family name**, NOT an Audit Manager framework name. Config ships templates like `Operational Best Practices for HIPAA Security`, `Operational Best Practices for PCI DSS`, `Operational Best Practices for CIS`. Each is a bundle of ~20-100 Config rules.

Audit Manager **consumes those rule evaluations as evidence** for its own frameworks — so you'll see phrases like *"Config rule from Operational Best Practices for HIPAA Security"* inside Audit Manager control mappings. That's a source reference, not a framework name.

| Mechanism | Where it lives | What it does |
|---|---|---|
| **Operational Best Practices** | AWS Config | Conformance pack of Config rules |
| **AWS Foundational Security Best Practices (FSBP)** | Security Hub + Audit Manager | Security standard / framework |
| **AWS Well-Architected Framework** | Well-Architected Tool + Audit Manager | Six-pillar quality review |

**Numbered flow:**

1. Create an assessment from a pre-built framework (or a custom one).
2. Scope the assessment — which AWS accounts, which services (S3, EC2, IAM, etc.).
3. Audit Manager creates a role in each in-scope account and starts collecting evidence continuously.
4. Every control shows its evidence trail: which Config rule matched, which CloudTrail events, which manual documents.
5. Auditor reviews inside Audit Manager, or export the assessment report as a PDF for offline review.
6. Delegate audit-owner roles to specific reviewers per control (segregation of duties).

**What Audit Manager is NOT:**

- **NOT a rule engine** — it doesn't evaluate anything; Config / Security Hub do.
- **NOT a remediator** — it reports gaps; remediation is via Config remediation actions or SSM.
- **NOT a workload-quality review tool** — that's **Well-Architected Tool** (evidence for auditor is different from workload architectural review).
- **NOT a chaos-testing tool** — that's **AWS FIS**.
- **NOT a resilience scoring tool** — that's **AWS Resilience Hub**.

**Exam Triggers:**

- *"Auditor-ready evidence for PCI / HIPAA / SOC 2 / NIST / FedRAMP"* → **Audit Manager**.
- *"Continuously collect evidence tied to compliance controls"* → **Audit Manager**.
- *"Custom compliance framework mapping to AWS Config rules"* → **Audit Manager custom framework**.
- *"Where does Operational Best Practices for HIPAA live?"* → **AWS Config conformance pack** (Audit Manager consumes its evaluations).

> *Mental model: Audit Manager is a **compliance framework aggregator**, not an evaluator. Config + Security Hub + CloudTrail generate the raw signals; Audit Manager maps those signals to named framework controls (HIPAA, PCI, SOC 2) and produces the auditor-ready report. "Operational Best Practices" is a Config conformance-pack family, not an Audit Manager framework — a distinction the exam explicitly tests.*

### AWS Well-Architected Tool

**Anchored against a structured six-pillar workload review methodology.** Well-Architected Tool (WA Tool) is AWS's native, per-workload architectural review artifact — you answer structured questions across six pillars, and it generates a risk-classified improvement plan plus an auditor-friendly PDF report.

**The six pillars (memorise all six):**

1. **Operational Excellence** — automation, runbooks, observability, incident response readiness.
2. **Security** — identity, detective controls, infrastructure protection, data protection, incident response.
3. **Reliability** — foundations (limits, network), workload architecture, change management, failure management.
4. **Performance Efficiency** — right-sizing, monitoring, tradeoffs.
5. **Cost Optimization** — expenditure awareness, cost-effective resources, matching supply to demand.
6. **Sustainability** — region selection, user behaviour, software patterns, hardware efficiency.

**Lenses (extensions on top of the base framework):**

- Serverless, SaaS, IoT, ML, Data Analytics, Financial Services, Healthcare, HPC, Container Build, SAP, Government, Games Industry, DevOps, Generative AI.

**Risk classification (memorise the vocabulary):**

- **HRI (High Risk Issue)** — a best practice you didn't check that AWS flags as high risk for your workload.
- **MRI (Medium Risk Issue)** — same, medium risk.
- Improvement plan lists mitigations ordered by pillar and HRI/MRI severity.

**Numbered flow:**

1. **Define the workload** — name, description, environment (prod / preprod), AWS accounts + regions, industry.
2. **Select lenses** — always include the AWS Well-Architected Framework Lens; add specialised lenses if applicable.
3. **Answer questions per pillar** — structured questions with best-practice checkboxes.
4. **Review generated HRIs and MRIs** — every unchecked best practice becomes a risk with mitigation guidance.
5. **Generate improvement plan** — auto-generated list of mitigations, ordered by pillar and severity.
6. **Implement mitigations, re-review** — HRI/MRI counts drop as best practices become checked. Track posture over time.
7. **Export PDF report** — hand to the auditor.
8. **Share workload** — cross-account sharing lets a central security team review workloads owned by member accounts.

**What WA Tool is NOT:**

- **NOT a chaos-testing service** — that's **AWS FIS**.
- **NOT an automated resource scanner** — WA Tool is question-driven, not resource-inspecting. (Contrast Config, which inspects resources.)
- **NOT a compliance-framework mapper** — that's **Audit Manager**.
- **NOT a resilience scoring tool** — that's **Resilience Hub** (though the Reliability pillar overlaps).
- **NOT single-workload only** — a single account can host dozens of workload reviews.

**Common wrong-answer traps:**

- *"WA Tool automatically evaluates my resources"* → wrong; it's a **question-based self-assessment** with expert-designed best practices.
- *"WA Tool replaces Audit Manager for HIPAA / PCI"* → wrong; WA Tool is workload-quality, not compliance-framework evidence.
- *"WA Tool provides an RTO/RPO score"* → wrong; that's **Resilience Hub**.

**Exam Triggers:**

- *"Review workloads against **multiple pillars** (Op Ex, Security, Reliability, Cost, Performance, Sustainability)"* → **WA Tool**.
- *"Withstand disruptive events + improve through remediation + provide documentation to auditor"* → **WA Tool** when multiple pillars are named (this is the specific exam trap where Resilience Hub feels right but WA Tool wins).
- *"HRI / MRI / high-risk issue"* → **WA Tool vocabulary**.
- *"Well-Architected Framework"* referenced by name → **WA Tool**.
- *"Cross-account sharing of workload reviews"* → **WA Tool workload sharing**.

> *Mental model: WA Tool is AWS's **structured architectural review** — six pillars, HRI/MRI risk classification, expert-designed best-practice checklist, PDF export. If a question names three or more pillars, or asks for **workload-quality evidence spanning multiple dimensions**, the answer is WA Tool. Specialised tools (Resilience Hub, FIS, Audit Manager, Trusted Advisor, Config) win when the question narrows to a single specific outcome; WA Tool wins on breadth.*

### AWS Resilience Hub

**Anchored against WA Tool's Reliability pillar, but automated and score-driven.** Where WA Tool asks *you* questions, Resilience Hub **inspects your deployed resources**, computes an actual RTO/RPO per disruption type, compares against your target policy, and generates specific remediation actions per gap.

**Four disruption types Resilience Hub assesses:**

1. **Application failure** — bug, misconfiguration.
2. **Infrastructure failure** — single-instance or single-component loss.
3. **AZ disruption** — full Availability Zone loss.
4. **Region disruption** — full Region loss.

For each, Resilience Hub compares your **target RTO/RPO** (set in a resilience policy) against the **assessed RTO/RPO** (computed from resource inspection).

**Numbered flow:**

1. **Define the application** — group resources via CloudFormation stack ARNs, Terraform state, Resource Groups, or App Registry.
2. **Set the resilience policy** — target RTO/RPO per disruption type.
3. **Run assessment** — Resilience Hub inspects each resource (RDS Multi-AZ config, Auto Scaling min/max, S3 replication rules, backup schedules) and computes assessed RTO/RPO.
4. **Review the resilience score** — 0-100, compared against policy. Gaps flagged as **compliant** or **breach** per disruption type.
5. **Review recommendations** — actionable remediation per breach ("convert `db-prod` from Single-AZ to Multi-AZ").
6. **Generate FIS experiment templates** — Resilience Hub can auto-generate an **AWS FIS** experiment matching each disruption type, so you can validate that assessed behaviour matches real behaviour.
7. **Export report** — assessment findings + score + recommendations for the auditor.

**What Resilience Hub is NOT:**

- **NOT a chaos-testing engine** — it *invokes* FIS but doesn't inject faults itself.
- **NOT a six-pillar quality review** — that's **WA Tool** (broader scope).
- **NOT a compliance-framework tool** — that's **Audit Manager**.
- **NOT a backup service** — that's **AWS Backup** (Resilience Hub *evaluates* your backup config, doesn't take backups).

**Exam Triggers:**

- *"Score / measure / assess application resilience"* → **Resilience Hub**.
- *"Meet RTO / RPO targets"* → **Resilience Hub resilience policy**.
- *"Validate the assessed resilience with a chaos experiment"* → **Resilience Hub → generated FIS experiment template**.
- *"Improve resilience through identified remediation actions"* → **Resilience Hub** (only when the question narrows to resilience specifically; if multiple WA pillars are named, WA Tool wins).

> *Mental model: Resilience Hub is **the Reliability pillar of Well-Architected, automated and scored**. It inspects resources rather than asking questions, computes objective RTO/RPO, and integrates with FIS for validation. Wins when the question narrows to resilience with a numeric outcome (score, RTO, RPO); loses to WA Tool when the question spans multiple pillars.*

### AWS Fault Injection Service (FIS)

**Anchored against Netflix's Chaos Monkey.** FIS is AWS's managed chaos-engineering service — deliberately break your own infrastructure under IAM control, with CloudWatch-alarm-driven stop conditions that auto-halt the experiment before it causes a real outage.

Formerly called **AWS Fault Injection Simulator** — renamed to **Service** in 2023, same acronym.

**Action categories:**

| Category | Example actions |
|---|---|
| **EC2** | Terminate, stop, reboot, send spot interruption warning |
| **OS-level (via SSM Agent)** | CPU stress, memory stress, disk fill, kill process, network latency injection, blackhole traffic, DNS resolution failure |
| **RDS / Aurora** | Force failover, reboot, stop DB instance |
| **ECS / EKS** | Task/pod termination, container CPU/memory stress, node drain |
| **Lambda** | Add latency to invocations, throw errors, throttle concurrency |
| **API throttling** | Throttle specific AWS API calls (`kms:Decrypt`, `sts:AssumeRole`, `s3:GetObject`) for a target IAM role |
| **AZ Availability: Power Interruption** | Simulate full AZ loss — the exam's headline action for HA validation |
| **Networking** | Disrupt VPC / Transit Gateway / subnet connectivity |
| **EBS** | Pause volume I/O |

**The five FIS building blocks:**

1. **Experiment template** — the recipe: actions, targets, stop conditions, IAM role.
2. **Actions** — the individual faults; sequenced or parallel.
3. **Targets** — resources selected by tag / ARN / filter; selection mode `ALL`, `COUNT(n)`, `PERCENT(x)`.
4. **Stop conditions** — **CloudWatch Alarms** that auto-halt the experiment when a customer-facing metric degrades (5xx breach, p99 latency spike). **The safety net that makes FIS production-safe.**
5. **IAM role** — the role FIS assumes; tightly scoped to the actions in the template.

**Numbered experiment flow:**

1. Author experiment template.
2. Start experiment (`aws fis start-experiment`).
3. FIS assumes the IAM role and applies fault actions on schedule.
4. CloudWatch alarms monitored continuously — if any goes to ALARM state, FIS **halts the experiment and reverts** where possible.
5. Experiment ends — success, stop condition, or manual halt.
6. Review CloudWatch metrics, X-Ray traces, application logs.

**What FIS is NOT:**

- **NOT a resilience scoring tool** — that's **Resilience Hub**.
- **NOT a compliance evidence tool** — that's **Audit Manager**.
- **NOT a workload review tool** — that's **WA Tool**.
- **NOT a pen-testing / adversarial-traffic tool** — pen testing is authorised via the AWS Customer Support form; FIS attacks *your own* infrastructure.
- **NOT a DDoS simulator** — third-party load-test partners handle that under AWS's testing policy.

**Common wrong-answer traps:**

- *"Use FIS to test WAF rules"* → wrong; WAF has its own test mode.
- *"Use FIS to simulate a DDoS"* → wrong; not its purpose.
- *"FIS runs safely without stop conditions"* → dangerous; every production experiment must have CloudWatch-alarm stop conditions.
- *"FIS is part of AWS Backup / DR"* → wrong; **Backup** handles backups, **Elastic Disaster Recovery (DRS)** handles cross-region failover, **FIS tests both**.

**Exam Triggers:**

- *"Chaos engineering on AWS"* → **FIS**.
- *"Validate multi-AZ failover / test the runbook without a real incident"* → **FIS**.
- *"Simulate an AZ outage"* → **FIS AZ Availability Power Interruption action**.
- *"Inject latency / errors / API throttling"* → **FIS actions**.
- *"Netflix Chaos Monkey equivalent"* → **FIS**.

> *Mental model: FIS is **chaos engineering as a managed service** — break your own infrastructure on purpose, IAM-gated, with CloudWatch-alarm stop conditions so bad experiments auto-revert. Wins when the question asks about **executing** a fault; loses to Resilience Hub when the question asks about **scoring** resilience.*

### Audit / Quality / Resilience Services — which one when

**The disambiguation cheat-sheet.** All five of these services can plausibly answer *"prove workload quality + improve it + hand something to the auditor"* — and the exam deliberately puts them side-by-side. Match the question phrase to the service:

| Question phrase | Service | Why |
|---|---|---|
| *"Multiple WA pillars named (Op Ex, Security, Reliability, Cost, Performance, Sustainability)"* | **Well-Architected Tool** | The pillars ARE WA Tool's structure |
| *"Per-workload review + auditor documentation + recommendations across dimensions"* | **Well-Architected Tool** | WA Tool workload PDF is the artifact |
| *"HRI / MRI / high-risk issue"* | **Well-Architected Tool** | Its native vocabulary |
| *"Score / assessment / RTO / RPO specifically"* | **Resilience Hub** | Its native output |
| *"Meet resilience policy / target RTO / target RPO"* | **Resilience Hub** | Its native policy model |
| *"Compliance framework named (HIPAA / PCI / SOC 2 / NIST / FedRAMP / GDPR / ISO 27001)"* | **Audit Manager** | Its pre-built framework catalog |
| *"Continuously collect evidence tied to controls"* | **Audit Manager** | Its aggregator function |
| *"Inject faults / chaos experiment / test failover"* | **AWS FIS** | Its execution primitive |
| *"Simulate AZ or region loss"* | **AWS FIS** | AZ Availability Power Interruption action |
| *"Account-level cost + performance + security + service-limits checks"* | **Trusted Advisor** | Its check categories |
| *"Deploy 30 pre-built Config rules for HIPAA / PCI / NIST"* | **AWS Config Operational Best Practices conformance pack** | Its template family |
| *"Prescriptive security controls with continuous findings"* | **Security Hub AWS FSBP standard** | The Security Hub standard |

**The pattern-matching rules to memorise:**

1. **Three or more of the six pillars named → WA Tool** (broadest scope wins on breadth).
2. **Word "score" or numeric RTO/RPO → Resilience Hub** (unique output).
3. **Named compliance framework → Audit Manager** (framework catalog).
4. **Word "inject" / "chaos" / "simulate outage" → FIS** (only chaos-execution service).
5. **Word "conformance pack" / "Operational Best Practices" → Config** (the pack template family).
6. **Word "Foundational Security Best Practices / FSBP" → Security Hub standard** (or Audit Manager as consumer).
7. **"Business or Enterprise Support" + cost/perf/security-checks → Trusted Advisor** (account-level, not workload-level).

**Which service supplies what to whom:**

```text
              ┌──────────────────────────┐
              │  AWS Config              │  produces  ┌──────────────────┐
              │  (Operational Best       │──────────► │                  │
              │   Practices packs)       │            │  AWS Audit       │
              └──────────────────────────┘            │  Manager         │
              ┌──────────────────────────┐  produces  │  (aggregates     │
              │  Security Hub            │──────────► │   evidence into  │
              │  (FSBP + other standards)│            │   framework      │
              └──────────────────────────┘            │   reports)       │
              ┌──────────────────────────┐  produces  │                  │
              │  CloudTrail              │──────────► │                  │
              └──────────────────────────┘            └──────────────────┘

              ┌──────────────────────────┐  invokes  ┌──────────────────┐
              │  Resilience Hub          │─────────► │  AWS FIS         │
              │  (score + recommendation)│           │  (chaos exec)    │
              └──────────────────────────┘           └──────────────────┘

              ┌──────────────────────────┐
              │  Well-Architected Tool   │  (self-contained;
              │  (six-pillar review,     │   consumes nothing,
              │   HRI/MRI, PDF report)   │   produces PDF audit doc)
              └──────────────────────────┘

              ┌──────────────────────────┐
              │  Trusted Advisor         │  (account-level
              │  (cost / perf / security │   checks, not
              │   / service limits)      │   workload-scoped)
              └──────────────────────────┘
```

> *Mental model: **the five services form a stack of intent, not alternatives.** Config + Security Hub + CloudTrail generate raw signals → Audit Manager maps them to compliance frameworks. Resilience Hub scores resilience → FIS validates by execution. WA Tool sits alongside as the structured six-pillar review methodology. Trusted Advisor is the account-wide checkup. Pick by matching the **question's phrasing** to the service's **native vocabulary** (HRI/MRI → WA; RTO/RPO → Resilience Hub; framework name → Audit Manager; "inject" → FIS).*

### Service Catalog

**Anchored against a curated internal app store** — Service Catalog is the answer whenever the exam says *"predefined template + third-party or restricted developers + must deploy through an approved path."*

**Core objects:**

- **Product** = a CloudFormation template (versioned — updates ship as new product versions).
- **Portfolio** = a collection of products, plus who's allowed to see them, plus the launch constraints that govern how they deploy.
- **Launch constraint** = an IAM role Service Catalog assumes when provisioning the product; lets end users deploy without holding the underlying resource permissions.
- **Provisioned product** = an instance the user launched (backed by a CloudFormation stack under the hood).

**Canonical multi-account setup (the retail-store exam question):**

1. **Central account** — create a portfolio, add the CloudFormation template as a product.
2. **Share the portfolio to the OU** via AWS Organizations sharing (supports Org root, OU, or specific accounts).
3. **In each member account** — import the shared portfolio and grant portfolio access to only the specific IAM roles/groups the dev teams assume.
4. **Attach a launch constraint** with a service role holding the resource permissions the template needs. Devs get `servicecatalog:ProvisionProduct` on the product; they do NOT need direct IAM permissions on EC2/S3/RDS/etc.
5. Devs launch products from the Service Catalog console/CLI; every deploy is auditable, matches the template, and can be terminated by the same portal.

**Numbered launch flow:**

1. Dev browses portfolio → sees only products they have access to.
2. Dev picks a product and launches it → Service Catalog assumes the **launch constraint** role.
3. That role creates the CloudFormation stack in the dev's account with the dev's parameters.
4. Resources come up in the dev's account; the dev sees them as a "provisioned product" in Service Catalog.

**Constraints (memorise the types):**

- **Launch constraint** — service role used to provision (the security win).
- **Template constraint** — restricts parameter values (e.g. "only these instance types").
- **Notification constraint** — pipe stack events to SNS.
- **Tag update / stack set / resource update** — additional governance knobs.

**What Service Catalog is NOT:**

- **NOT CloudFormation StackSets** — StackSets fans a template out from a central admin; Service Catalog lets *end users* self-serve within limits. StackSets = push-from-centre; Service Catalog = pull-with-guardrails.
- **NOT Systems Manager Automation** — SSM Automation runs runbooks (operational tasks); Service Catalog provisions resources.
- **NOT a code repo** — the template lives inside the product; devs never see the raw template unless you grant it.
- **NOT AWS Marketplace** — Marketplace = third-party AMIs/products for purchase; Service Catalog = *your* org's approved templates.

**Exam Triggers:**

- *"Third-party developers deploy per a predefined plan; restrict who can use the plan"* → **Service Catalog** with portfolio sharing + IAM access.
- *"Developers must deploy without holding the underlying resource permissions"* → **launch constraint** with a service role.
- *"Share pre-approved products across an Organization / OU"* → **Service Catalog Organization sharing**.
- *"Restrict parameter values in a template (e.g. only t3.medium and below)"* → **template constraint**.

**Common Anti-patterns (exam wrong answers):**

- *"Give devs the CloudFormation template in S3 + `cloudformation:CreateStack` permission"* → devs also need every underlying resource permission; violates least privilege.
- *"Use StackSets to give each team the deployment plan"* → StackSets is centrally driven; doesn't let per-store dev teams self-serve at their opening date.
- *"Put the template in CodeCommit and let devs run a pipeline"* → repo access + pipeline permissions widen the surface; harder to restrict per-team access to just the plan.
- *"Share the template on Confluence with a runbook"* → zero enforcement; devs can mutate.

##### Security lens — the "approved AMIs only, in this account only" pattern

**The canonical SCS-C03 "developers launching non-approved software" question.** Service Catalog is the answer whenever the stem says:

- *"Developers launched EC2 instances with unapproved software"*
- *"Restrict launches to company-approved images"*
- *"Only inside a specific account / OU"*

Why it's a *security* tool, not just a deployment tool:

1. **Devs never touch `ec2:RunInstances` directly.** They only get `servicecatalog:ProvisionProduct` on approved products. The launch constraint role has EC2 permissions — the human doesn't. This is real least-privilege delegation.
2. **The AMI (or CFN template referencing an approved AMI) is baked into the product.** Devs can't substitute a random public AMI or one with unapproved packages — they pick a product, not an image ID.
3. **Portfolio sharing is account-scoped.** Share only to the software-development account (or its OU). HR and Finance accounts never see the product, so devs can't accidentally launch there and vice versa.
4. **Template constraints cap the parameter surface.** Even inside an approved product, you can constrain instance types, regions, tags, or encryption settings — devs pick from a whitelist, not a free-text field.
5. **Every provisioning is a first-class CloudTrail event** (`ProvisionProduct` + the downstream CFN + EC2 events under the launch-role identity). Full audit trail.

**Belt-and-suspenders: pair Service Catalog with an SCP** that denies direct `ec2:RunInstances` unless the call is made *via* Service Catalog. Uses `aws:CalledVia`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectEC2Launches",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringNotEquals": {
          "aws:CalledVia": ["servicecatalog.amazonaws.com"]
        }
      }
    }
  ]
}
```

Now even a dev with `ec2:*` in their identity policy can only launch via Service Catalog — the SCP short-circuits any bypass attempt.

**Numbered enforcement flow (memorise for the exam):**

1. Ops team publishes an approved product (CFN template baking in an approved AMI ID + hardening) into a portfolio in the security/shared-services account.
2. **Portfolio shared to the software-development account** (or OU) via AWS Organizations sharing — HR/Finance never see it.
3. Dev-account admin grants developer roles `servicecatalog:ProvisionProduct` on the product only.
4. **Launch constraint** attached with a role that holds `ec2:RunInstances` — the dev's role does not.
5. Optional: **SCP with `aws:CalledVia`** denies any direct `ec2:RunInstances` bypass.
6. Dev launches → Service Catalog assumes the launch role → CFN creates EC2 with the approved AMI. Deviation is impossible.

**Why the other options fail this class of question:**

- *"IAM policy with Deny on ec2:RunInstances unless AMI is one of these"* → brittle; the AMI list rots. Doesn't stop devs from creating other unapproved resources.
- *"AWS Config rule to detect non-compliant AMIs"* → detection *after* launch. Doesn't prevent.
- *"SCP denying ec2:RunInstances entirely"* → devs can't do their job at all.
- *"Custom AMI baked with approved software + trust that devs will use it"* → no enforcement; devs pick freely from the AMI catalog.
- *"CloudFormation Guard / OPA on the template"* → catches template drift but doesn't stop imperative `RunInstances` calls.

> *Mental model: Service Catalog turns "please use the approved image" from a policy document into a **mechanical impossibility**. The dev's IAM identity lacks EC2 permissions; the launch role has them but can only be invoked via the product. No path around it exists.*

> *Mental model: Service Catalog = a curated app store for CloudFormation. Portfolio = an aisle. Product = an item on the shelf. Launch constraint = the item is installed by a robot with the right keys, not by the shopper.*

### CloudFormation Service Role (deploy least privilege)

**The canonical SCS-C03 "some team members can deploy CFN stacks, others get permission errors even though they have `cloudformation:*`" question.** The trap: without a service role, CloudFormation uses the *caller's* credentials to provision resources — inconsistent by design.

**The three-action sequence (the multi-select answer):**

1. **Create an IAM service role for CloudFormation** with all resource permissions the stack templates need (`ec2:*`, `s3:*`, `rds:*`, etc., scoped to what the stacks actually create). Trust policy allows `cloudformation.amazonaws.com` to assume it.
2. **Grant the team-member roles `iam:PassRole`** on the service-role ARN — nothing more. They keep `cloudformation:*` on the stacks but can now hand the role to CFN.
3. **Update each existing stack to use the service role** — this is the step people miss. Creating the role and granting PassRole isn't enough; **CFN records the RoleARN on the stack itself**. Existing stacks won't retroactively adopt it; you must run `UpdateStack --role-arn <arn>` (or set it in a Change Set / the console) on each stack. From that point every future update uses that role.

**Why this fixes the "some succeed, some fail" symptom:**

- Without a service role, CFN uses the caller's credentials to call `ec2:RunInstances`, `s3:CreateBucket`, etc. A team member with `cloudformation:CreateStack` but no `ec2:*` gets `AccessDenied` on the EC2 resource inside the template — even though they "have permission on CloudFormation."
- With a service role attached, CFN assumes the service role via STS and uses ITS permissions for every resource action. The caller's role no longer needs any resource permissions — just `cloudformation:*` on the stack and `iam:PassRole` on the role ARN.
- Every team member now deploys with identical effective resource permissions.

**Numbered flow:**

1. Dev calls `aws cloudformation update-stack --stack-name X --role-arn arn:aws:iam::<acct>:role/cfn-deployer --template-body file://...`.
2. IAM checks the dev's role: `cloudformation:UpdateStack` allowed? `iam:PassRole` on `cfn-deployer` allowed? → yes.
3. CFN assumes `cfn-deployer` via STS.
4. CFN uses `cfn-deployer`'s credentials for every `ec2:RunInstances`, `s3:CreateBucket`, etc. inside the template.
5. Stack update succeeds regardless of what the dev's own role holds.

**Least-privilege math — before vs after:**

Before (the failing state):

```text
Every team member's role needs: cloudformation:* + ec2:* + s3:* + rds:* + … (drift-prone, inconsistent)
```

After (the target state):

```text
Every team member's role needs: cloudformation:* on the stack + iam:PassRole on the service role
The single CFN service role holds: ec2:* + s3:* + rds:* + … (one place to audit)
```

Every resource permission collapses to a single reviewable role. No human role holds those permissions directly.

**Condition keys worth knowing for CFN questions:**

- **`iam:PassedToService`** — condition on `iam:PassRole` restricting *which service* the role can be passed to. Prevents devs from repurposing the CFN deployer role for Lambda / EC2:

```json
"Condition": {
  "StringEquals": {
    "iam:PassedToService": "cloudformation.amazonaws.com"
  }
}
```

- **`cloudformation:RoleArn`** — condition on stack operations to force devs to use *only* the approved service role and no other:

```json
"Condition": {
  "StringEquals": {
    "cloudformation:RoleArn": "arn:aws:iam::<acct>:role/cfn-deployer"
  }
}
```

- **Stack policies** — completely different feature. Governs *update-time resource protection* (e.g. "don't replace this RDS instance during update"), not who can deploy.

**Common Anti-patterns (exam wrong answers):**

- *"Grant Administrator access to all team members"* — violates least privilege; also doesn't scale.
- *"Have each team member create their own CFN service role"* — divergent permissions, exactly the inconsistency you're trying to remove.
- *"Grant `cloudformation:*` to every team member"* — they already have this per the stem; not the missing piece.
- *"Create the service role, grant PassRole, but forget to update existing stacks"* — **the trap** — the role is only in effect once the stack's `RoleARN` field is set.
- *"Use CloudFormation StackSets"* — StackSets is for fanning stacks across accounts/regions; doesn't address per-user permission drift.
- *"Add a resource-based policy to each stack"* — CFN stacks don't have resource-based policies.
- *"Enable a stack policy"* — governs update-time resource protection, not deploy-time permissions.

**Exam Triggers:**

- *"Some team members deploy successfully, others fail with permission errors"* → **CFN service role** (caller-credentials trap)
- *"Deploy CloudFormation with least privilege"* → **service role + `iam:PassRole`** on the caller
- *"Ensure every stack update uses the approved deployer role only"* → **`cloudformation:RoleArn`** condition on stack actions
- *"Prevent devs from passing the deployer role to Lambda/EC2"* → **`iam:PassedToService`** condition
- *"Update each stack to use the CloudFormation service role"* → the completion step people miss

> *Mental model: without a service role, CFN is a **wrapper around whatever perms the caller has** — inconsistent by design. With a service role, CFN is a **contract**: "I will use this exact role's permissions for every deployment, no more, no less." Creating the role isn't enough — each stack has to be updated so CFN **records** the role on the stack itself. Missing that last step is why "some team members can deploy" persists.*

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
