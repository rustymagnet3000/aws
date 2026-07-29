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
  - [Service Catalog](#service-catalog)
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
- *"Retain for N years"* → **CloudWatch Logs retention policy** (native)
- *"Cheap long-term archive of logs"* → **Subscription filter → Firehose → S3** with S3 lifecycle to Glacier
- *"Encrypt application logs with a customer-managed key"* → **CloudWatch Logs SSE-KMS on the log group**

> *Mental model: CloudWatch Agent is a **fire hose that never sleeps**; any "every N minutes/hours" upload is a **bucket brigade** — buckets get dropped when the runner (instance) trips.*

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

> *Mental model: Service Catalog = a curated app store for CloudFormation. Portfolio = an aisle. Product = an item on the shelf. Launch constraint = the item is installed by a robot with the right keys, not by the shopper.*

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
