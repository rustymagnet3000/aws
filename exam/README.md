# AWS Exam

<!-- TOC depthfrom:2 depthto:3 withlinks:true updateonsave:true orderedlist:false -->

- [Useful links](#useful-links)
- [EC2](#ec2)
  - [Availability Zones](#availability-zones)
  - [Elastic IP versus Standard Public IP](#elastic-ip-versus-standard-public-ip)
  - [EC2 SSH Troubleshooting](#ec2-ssh-troubleshooting)
  - [Placement Groups](#placement-groups)
  - [ENIs in ECS](#enis-in-ecs)
  - [EBS Volumes](#ebs-volumes)
  - [Hibernate](#hibernate)
  - [Snapshots](#snapshots)
  - [EC2 Pricing Models](#ec2-pricing-models)
  - [AMI](#ami)
- [EFS](#efs)
- [Scaling and ELB](#scaling-and-elb)
  - [Elastic Load Balancer (ELB)](#elastic-load-balancer-elb)
  - [SSL/TLS and Load Balancers](#ssltls-and-load-balancers)
  - [Connection Draining](#connection-draining)
  - [Cross-Zone Load Balancing](#cross-zone-load-balancing)
  - [Sticky Sessions](#sticky-sessions)
  - [Auto Scaling Group (ASG)](#auto-scaling-group-asg)
  - [CloudWatch Alarms and Scaling](#cloudwatch-alarms-and-scaling)
  - [Scaling Cooldowns](#scaling-cooldowns)
  - [Health Checks](#health-checks)
  - [ALB and EC2 Security Groups](#alb-and-ec2-security-groups)
  - [EC2 without a Public IP](#ec2-without-a-public-ip)
- [ECS (Elastic Container Service)](#ecs-elastic-container-service)
  - [ECS vs ASG + EC2](#ecs-vs-asg--ec2)
  - [Key concepts](#key-concepts)
  - [When to choose EC2 over ECS](#when-to-choose-ec2-over-ecs)
  - [Bottlerocket](#bottlerocket)
  - [ECR (Elastic Container Registry)](#ecr-elastic-container-registry)
  - [ECS Data Volumes](#ecs-data-volumes)
  - [ECS IAM Roles](#ecs-iam-roles)
  - [ECS + ALB (Dynamic Port Mapping)](#ecs--alb-dynamic-port-mapping)
  - [ECS Auto Scaling](#ecs-auto-scaling)
  - [ECS Task Placement (EC2 only)](#ecs-task-placement-ec2-only)
  - [ECS Capacity Providers](#ecs-capacity-providers)
  - [EKS (Elastic Kubernetes Service)](#eks-elastic-kubernetes-service)
  - [IRSA (IAM Roles for Service Accounts)](#irsa-iam-roles-for-service-accounts)
  - [AWS App Runner](#aws-app-runner)
- [RDS (Relational Database Service)](#rds-relational-database-service)
  - [RDS and Aurora Security](#rds-and-aurora-security)
  - [RDS Backups](#rds-backups)
  - [RDS Encryption](#rds-encryption)
  - [RDS Proxy](#rds-proxy)
  - [Read Replicas](#read-replicas)
  - [Multi-AZ](#multi-az)
  - [RDS Custom](#rds-custom)
  - [Aurora](#aurora)
  - [Read Replica Network Costs](#read-replica-network-costs)
  - [RDS Storage Auto Scaling](#rds-storage-auto-scaling)
- [ElastiCache](#elasticache)
  - [ElastiCache Security](#elasticache-security)
  - [ElastiCache Redis Replication](#elasticache-redis-replication)
- [Route 53](#route-53)
  - [Authoritative vs Non-Authoritative DNS](#authoritative-vs-non-authoritative-dns)
  - [DNS Record Types](#dns-record-types)
  - [Public and Private Hosted Zones](#public-and-private-hosted-zones)
  - [Routing Policies](#routing-policies)
  - [TTL (Time to Live)](#ttl-time-to-live)
  - [Route 53 Health Checks](#route-53-health-checks)
  - [Route 53 Resolver (Hybrid DNS)](#route-53-resolver-hybrid-dns)
- [Elastic Beanstalk](#elastic-beanstalk)
- [Solution Architecture Examples](#solution-architecture-examples)
  - [Classic Web App](#classic-web-app)
  - [Stateful Web App → Stateless Evolution](#stateful-web-app--stateless-evolution)
  - [Multi-Region Disaster Recovery](#multi-region-disaster-recovery)
  - [Golden AMI vs Docker Image](#golden-ami-vs-docker-image)
  - [Serverless](#serverless)
  - [Static Website with CloudFront](#static-website-with-cloudfront)
- [S3 (Simple Storage Service)](#s3-simple-storage-service)
  - [S3 Overview](#s3-overview)
  - [S3 Versioning](#s3-versioning)
  - [S3 Storage Classes](#s3-storage-classes)
  - [S3 Object Lock and Glacier Vault Lock](#s3-object-lock-and-glacier-vault-lock)
  - [S3 Event Notifications](#s3-event-notifications)
  - [S3 Requester Pays](#s3-requester-pays)
  - [S3 Security](#s3-security)
  - [S3 Access Points](#s3-access-points)
  - [S3 VPC Endpoint (Gateway)](#s3-vpc-endpoint-gateway)
  - [S3 Access Logs](#s3-access-logs)
  - [S3 CORS](#s3-cors)
  - [S3 Performance](#s3-performance)
  - [S3 Select and S3 Object Lambda](#s3-select-and-s3-object-lambda)
  - [S3 Replication](#s3-replication)
  - [S3 Storage Lens](#s3-storage-lens)
- [AWS Snow Family](#aws-snow-family)
- [AWS DataSync](#aws-datasync)
- [AWS Transfer Family](#aws-transfer-family)
- [Hybrid Cloud Storage](#hybrid-cloud-storage)
  - [AWS Storage Gateway](#aws-storage-gateway)
  - [Amazon FSx](#amazon-fsx)
- [CloudFront and Global Accelerator](#cloudfront-and-global-accelerator)
  - [CloudFront Overview](#cloudfront-overview)
  - [CloudFront vs S3 Transfer Acceleration](#cloudfront-vs-s3-transfer-acceleration)
  - [CloudFront Caching](#cloudfront-caching)
  - [CloudFront Security](#cloudfront-security)
  - [CloudFront Functions and Lambda@Edge](#cloudfront-functions-and-lambdaedge)
  - [AWS Global Accelerator](#aws-global-accelerator)
  - [CloudFront vs Global Accelerator](#cloudfront-vs-global-accelerator)
- [AWS Integration and Messaging](#aws-integration-and-messaging)
  - [SQS (Simple Queue Service)](#sqs-simple-queue-service)
  - [SNS (Simple Notification Service)](#sns-simple-notification-service)
  - [SNS + SQS Fan-Out](#sns--sqs-fan-out)
  - [Kinesis](#kinesis)
  - [SQS vs SNS vs Kinesis](#sqs-vs-sns-vs-kinesis)
- [Amazon Redshift](#amazon-redshift)
  - [OLTP vs OLAP](#oltp-vs-olap)
  - [Why Not RDS for Analytics?](#why-not-rds-for-analytics)
  - [Redshift Key Properties](#redshift-key-properties)
  - [Loading Data into Redshift](#loading-data-into-redshift)
  - [Redshift vs Athena](#redshift-vs-athena)
  - [Redshift Snapshots](#redshift-snapshots)
- [Serverless](#serverless-1)
  - [AWS Lambda](#aws-lambda)
  - [DynamoDB](#dynamodb)
  - [API Gateway](#api-gateway)
  - [Step Functions](#step-functions)
  - [Amazon Cognito](#amazon-cognito)
  - [Serverless Quick Reference](#serverless-quick-reference)

<!-- /TOC -->

## Useful links

- [Somebody who passed](https://medium.com/datamindedbe/hooray-im-an-aws-certified-pro-architect-now-what-89f4d8b22596)
- `acloud.guru` videos
- `whizlabs` practice exams

## EC2

### Availability Zones

A **Region** is a geographic area (e.g. `eu-west-1` = Ireland). Inside each region are **2–6 Availability Zones** (typically 3).

Each AZ is one or more discrete, physically separate data centres connected to other AZs via high-speed, low-latency private fibre — isolated from failures in other AZs (separate power, cooling, networking).

```
eu-west-1 (Ireland)
├── eu-west-1a  ← AZ 1
├── eu-west-1b  ← AZ 2
└── eu-west-1c  ← AZ 3
```

**Why it matters:**

- **High availability** — spread instances across AZs so a data centre failure doesn't take down your app
- **Fault isolation** — an outage in `1a` doesn't affect `1b` or `1c`
- **Low latency between AZs** — fast enough to synchronise databases and replicate data
- **AZ names are account-specific** — `eu-west-1a` in your account may map to a different physical AZ than in someone else's (AWS shuffles this to spread load evenly)

**Key gotcha:** some resources are AZ-scoped (e.g. EBS volumes, subnets) — you can't attach an EBS volume in `1a` to an instance in `1b`.

### Elastic IP versus Standard Public IP

|                                         | Elastic IP                        | Standard Public IP              |
| --------------------------------------- | --------------------------------- | ------------------------------- |
| Type                                    | Static — never changes            | Dynamic — changes on stop/start |
| Assigned to                             | Your account until you release it | Instance only while running     |
| Cost when attached to running instance  | $0.005/hr                         | $0.005/hr                       |
| Cost when unattached / instance stopped | $0.005/hr (you still pay)         | Free (released automatically)   |
| Free tier                               | Counts toward 750hr/month         | Counts toward 750hr/month       |

- If you stop your instance, a standard public IP is released (and you get a different one on restart) — no charge while stopped
- If you stop your instance with an Elastic IP, you keep paying for the Elastic IP because it's reserved in your account
- Elastic IP is only worth it if you need a stable, permanent IP (e.g. DNS records, whitelisting)

### EC2 SSH Troubleshooting

`kex_exchange_identification: read: Connection reset by peer`

### 1. Security Group — open port 22
- EC2 Console → Security Groups → Inbound Rules
- Add rule: Type=SSH, Port=22, Source=`0.0.0.0/0` (to isolate the issue)
- Once working, restrict to your IP with `/32`

### 2. IPv6 vs IPv4
- If your IP is IPv6 (e.g. `2a0a:::.../128`), your VPC/subnet may not have IPv6 routing configured
- Use `curl -4 ifconfig.me` to get IPv4 address instead
- Add a separate IPv4 rule if needed

### 3. Permission denied (publickey)
- Wrong key pair — check EC2 Console → Instance → "Key pair name"
- Fix `.pem` permissions: `chmod 400 newKeyPair.pem`
- Wrong username — Amazon Linux uses `ec2-user`, Ubuntu uses `ubuntu`, etc.

### 4. Accessing instance without the correct key
- Use EC2 Instance Connect: EC2 Console → Instance → Connect → EC2 Instance Connect
- Once in, add your public key to `~/.ssh/authorized_keys`
- To get public key `ssh-keygen -y -f newKeyPair.pem` and paste the output into ~/.ssh/authorized_keys on the instance.

### Placement Groups

Three types for controlling how instances are physically placed:

| Type | Strategy | Max Instances | Use Case |
| --------- | ----------------------------------- | ----------------------------- | ----------------------------------------- |
| Cluster | Packed together in one AZ | Unlimited | HPC, ML training, low-latency workloads |
| Spread | Each on distinct hardware (racks) | 7 per AZ | Small HA pairs, critical isolated instances |
| Partition | Groups of instances per rack/partition | 7 partitions/AZ, 100s of instances | Kafka, Cassandra, Hadoop (rack-aware apps) |

**Cluster** — lowest latency, up to 10 Gbps between instances, but correlated failure risk.

**Spread** — maximizes isolation; hard limit of 7 instances per AZ per group.

**Partition** — instances can see their partition ID, enabling rack-aware data placement.

**Key rules:**
- Can't merge groups or move running instances in — must stop → modify → start
- Cluster groups must be in a single AZ; Spread/Partition can span AZs
- Cluster performs best with uniform instance types

### ENIs in ECS

An **Elastic Network Interface (ENI)** is a virtual network card attachable to an EC2 instance. In ECS, ENIs become important with **awsvpc network mode**, where each task gets its own ENI and therefore its own private IP.

[AWS blog with architecture diagram](https://aws.amazon.com/blogs/aws/new-elastic-network-interfaces-in-the-virtual-private-cloud/)

**Why this is useful:**

- **Task-level security groups** — a dedicated ENI per task lets you attach security groups directly to the task, not the host. Fine-grained control without affecting other tasks on the same instance.
- **Predictable IPs** — each task has its own IP, making service discovery and whitelisting straightforward.
- **Failover / ENI reassignment** — detach an ENI from one instance and reattach it to another. Traffic and the IP follow the ENI, so clients don't need to update DNS or IPs.
- **Required for Fargate** — Fargate always uses awsvpc mode, so every Fargate task is fully network-isolated via its own ENI.

**Tradeoff:** each EC2 instance has a limit on ENIs (and IPs per ENI), which caps how many awsvpc tasks can run on a single host. Larger instance types support more ENIs.

### EBS Volumes

EBS is a hard drive that lives in the cloud and plugs into your EC2 instance over a network cable.

**Why it exists:** an EC2 instance on its own has no persistent storage — if it stops or crashes, everything is gone. EBS solves that. It's the disk your instance reads and writes to, and the data stays there even when the instance is off.

**The USB stick analogy:** you buy a USB stick (EBS volume), plug it into your laptop (EC2 instance), copy files onto it, then unplug it and move it to a different laptop — files are still there. The laptop can be destroyed; the USB stick survives.

**The three things you need to know:**

1. **AZ-locked** — a volume is created in one AZ (`eu-west-1a`) and can only attach to instances in that same AZ
2. **Snapshots are how you move data** — to get data to another AZ or region, snapshot it (backup stored in S3), then create a new volume from it wherever you need
3. **You pay even when not attached** — unlike RAM or CPU, an idle EBS volume still costs money

**What's on your instance:** when you launch EC2, AWS automatically creates a root EBS volume — that's where the OS lives. You can add more volumes on top, like adding a second hard drive.

**Key properties:**

- **Attached over the network** — not physically inside the instance, but behaves like a local disk
- **Locked to an AZ** — an EBS volume in `eu-west-1a` can't be attached to an instance in `eu-west-1b`
- **Survives instance stop/start** — data persists; the root volume can optionally survive termination too
- **One instance at a time** — by default a volume attaches to one instance. **EBS Multi-Attach** is the exception: a single `io1`/`io2` volume can attach to up to 16 instances in the same AZ simultaneously. The instances must manage concurrent writes themselves (typically via a cluster-aware filesystem like GFS2). Use case: high-availability databases (e.g. Oracle RAC) where multiple nodes need shared block storage with no single point of failure.
- **Snapshots** — point-in-time backups stored in S3; snapshots can be copied across regions to migrate data

**Volume types:**

Volume types sit on a speed-vs-cost spectrum. Two dimensions matter: **SSD vs HDD** and **how much performance you need**.

- **SSD** — fast random access; good for databases, OS, apps that read/write small chunks all over the disk
- **HDD** — slow random access but cheap with high throughput; good for streaming large files sequentially

The key metric for SSDs is **IOPS** (Input/Output Operations Per Second) — how many read/write operations the disk handles per second.

| Type | Plain English | Use case |
| ---- | ------------- | -------- |
| gp3 / gp2 | General purpose SSD | Default choice — boot volumes, most workloads |
| io2 / io1 | High performance SSD | DBs needing guaranteed IOPS (Oracle, SQL Server) |
| st1 | Throughput HDD | Large sequential reads — log processing, data warehouses |
| sc1 | Cold HDD | Barely touched data — cheapest, infrequent access |

- `gp3` lets you dial up IOPS independently of volume size
- `io2` gives a *guaranteed* IOPS ceiling — you pay for it whether you use it or not
- HDD types win on throughput (MB/s) for large sequential workloads, not IOPS

**Decision tree:**

```
Need fast random access?
├── Yes → SSD
│   ├── Normal workload (web app, boot volume) → gp3
│   └── High-performance DB with guaranteed IOPS → io2
└── No → HDD (large sequential reads/writes)
    ├── Active big data / logs → st1
    └── Rarely accessed archive → sc1
```

**Gotcha:** only `gp2`, `gp3`, and `io1/io2` can be used as boot volumes — you can't boot from `st1` or `sc1`.

**vs Instance Store:** instance store is physically attached (faster, lower latency) but **ephemeral** — data is lost when the instance stops. EBS persists. Use instance store for temp files/caches; EBS for anything you care about.

**Instance store example — Redis read replica:**

Run Redis on an instance-store-backed instance as a read replica (or cache layer) fronting your primary database. The instance store gives Redis lower-latency disk access for its persistence files (RDB snapshots, AOF log), and the high throughput suits a cache under heavy read load. If the instance dies, you simply launch a replacement and re-warm it from the primary — the data is reproducible, so the ephemeral nature of instance store is an acceptable trade-off for the speed gain.

**Delete on Termination:** controls whether a volume is deleted when its instance is terminated.

| Volume | Default |
| ------ | ------- |
| Root volume | Deleted on termination (enabled by default) |
| Additional volumes | Kept on termination (disabled by default) |

- Root volume deletion can be disabled — useful if you want to preserve it for forensics or reuse
- Additional volumes that survive termination keep accruing charges — easy to forget
- Exam tip: the defaults are *different* between root and additional volumes

### Hibernate

When you hibernate an instance, RAM contents are saved to the root EBS volume, then the instance stops. On restart, RAM is restored and the OS resumes exactly where it left off — no reboot, no re-initialisation.

**Why it's useful:**
- **Fast resume** — applications pick up instantly rather than cold-starting
- **Preserve in-memory state** — long-running processes, caches, and session data survive
- **Save money** — no compute charge while hibernated (only EBS storage)
- **Better than stop/start** — avoids OS boot + app startup overhead

**Typical use case:** A dev environment or data processing job you want to pause overnight and resume in the morning exactly as you left it.

**Requirements:** Root volume must be EBS (not instance store), encrypted, and large enough to hold the RAM contents.

### Snapshots

Snapshots are point-in-time backups of an EBS volume, stored in S3 (managed by AWS — you don't see the bucket).

**Why they're useful:**

- **Backup** — capture the state of a volume at a point in time; restore if data is lost or corrupted
- **Incremental** — only changed blocks are saved after the first snapshot, so they're fast and cost-efficient
- **Volume migration** — create a new EBS volume from a snapshot, even at a different size
- **AMI creation** — snapshots are the basis for custom AMIs (Amazon Machine Images)

**Why copying snapshots is useful:**

- **Cross-region disaster recovery** — copy a snapshot to another region to restore if a region goes down
- **Cross-region deployment** — launch identical instances in a new region from a copied snapshot
- **Cross-account sharing** — share a snapshot with another AWS account (e.g. hand off an environment to a client)
- **Encryption migration** — copy an unencrypted snapshot and enable encryption during the copy; this is the only way to encrypt an existing unencrypted volume

**Creating a Volume from a Snapshot:** EC2 Console → Snapshots → select snapshot → Actions → Create Volume. You choose the AZ at this point — this is how you effectively "move" an EBS volume to a different AZ (snapshot it, create a new volume in the target AZ). You can also change the volume type or size during creation.

**Recycle Bin:** a safety net for accidentally deleted snapshots (and AMIs). You define retention rules — deleted snapshots are held in the Recycle Bin for the retention period (1 day to 1 year) before being permanently deleted. Resources in the bin can't be used until restored, but can be recovered instantly if you catch the mistake in time.

**Key exam points:**

- Snapshots are AZ-agnostic — you can create a volume from a snapshot in any AZ within the region
- Deleting a snapshot doesn't delete data shared with other snapshots (incremental chain is preserved)
- Copy + re-encrypt is the standard pattern for encrypting a volume that wasn't encrypted at creation
- Recycle Bin must be configured proactively — it doesn't protect snapshots by default

### EC2 Pricing Models

Four ways to pay for EC2 — the exam tests whether you can pick the cheapest option for a given scenario.

| Model | Commitment | Discount | Use case |
| ----- | ---------- | -------- | -------- |
| On-Demand | None | 0% | Short-term, unpredictable workloads |
| Reserved Instances | 1 or 3 years | Up to 72% | Steady-state, predictable workloads (databases, web servers) |
| Savings Plans | 1 or 3 years | Up to 72% | Like Reserved but flexible across instance types/regions |
| Spot Instances | None | Up to 90% | Fault-tolerant, interruptible workloads |

**Reserved Instances (RI):**
- Commit to a specific instance type, region, and OS for 1 or 3 years
- Pay all upfront (biggest discount), partial upfront, or no upfront (smallest discount)
- **Convertible RIs** — can change instance type/OS/tenancy during the term, but less discount (~54% vs 72%)
- Best for: databases, web servers, anything that runs 24/7

**Savings Plans:**
- Commit to a **dollar amount per hour** of compute usage (e.g. "$10/hr for 1 year")
- More flexible than RIs — applies across instance families, regions, and even Fargate/Lambda
- Same discounts as RIs but without locking to a specific instance type
- Best for: organisations with diverse or evolving workloads

**Spot Instances:**
- Use spare EC2 capacity at up to 90% discount
- **AWS can reclaim them with 2 minutes notice** — your instance gets interrupted
- Best for: batch processing, data analysis, CI/CD builds, ML training, anything that can handle interruption
- **Not for:** databases, web servers, or anything that can't tolerate sudden termination

**Dedicated Hosts:**
- A physical server dedicated to you — no other AWS customers on the hardware
- Most expensive option
- Use case: software licensing that's per-physical-core/socket (Oracle, Windows Server), or compliance requirements mandating dedicated hardware

**Decision tree:**

```
Is the workload steady and predictable (runs 24/7)?
├── Yes → Reserved Instance or Savings Plan
│   ├── Know the exact instance type? → Reserved Instance
│   └── Want flexibility? → Savings Plan
└── No
    ├── Can it handle interruption? → Spot Instance (cheapest)
    └── Can't handle interruption? → On-Demand
Need dedicated hardware (licensing/compliance)? → Dedicated Host
```

**Exam triggers:**
- *"reduce costs for a database running 24/7"* → Reserved Instance
- *"flexible commitment across multiple instance types"* → Savings Plan
- *"cheapest option for batch processing that can retry"* → Spot Instance
- *"software licensed per physical socket"* → Dedicated Host
- *"short-term, unpredictable workload"* → On-Demand

### AMI

An **AMI (Amazon Machine Image)** is a pre-packaged template used to launch EC2 instances. It includes the OS, application server, application code, and configuration — everything needed to boot a new instance.

Think of an AMI like a **gold image** or VM template: create one instance configured exactly how you want it, snapshot it, and spin up identical instances from that AMI anywhere.

**What an AMI contains:**

- One or more EBS snapshots (or, for instance-store AMIs, a template for the root volume)
- Launch permissions — which AWS accounts can use it
- Block device mapping — which volumes to attach at launch and their sizes

**AMI types (by root device):**

| Type | Storage | Boot time | Persistence |
| ---- | ------- | --------- | ----------- |
| EBS-backed | Root volume is EBS | Fast (~seconds) | Survives stop/start |
| Instance store-backed | Root volume is S3-hosted template | Slower (~minutes) | Ephemeral — lost on stop |

EBS-backed AMIs are the default and almost always preferred. Instance store AMIs are legacy.

**AMI scope:**

- **Region-specific** — an AMI exists in one region; to use it in another, copy it
- **Public** — AWS-provided AMIs (Amazon Linux, Ubuntu, Windows) available to everyone
- **Private** — your own AMIs, visible only to your account by default
- **Shared** — you can grant specific AWS accounts permission to use your AMI

**Custom AMI workflow:**

1. Launch an EC2 instance and configure it (install software, set config, harden OS)
2. Stop the instance (recommended for consistency — avoids partially-written files)
3. EC2 Console → Actions → Image and templates → Create image
4. AWS creates EBS snapshots of all attached volumes and registers the AMI
5. Launch new instances from that AMI in the same region (or copy it first to another region)

**Key exam points:**

An EBS snapshot is a point-in-time backup of an EBS volume, stored incrementally in S3.

- AMIs are built from EBS snapshots — deleting an AMI does **not** automatically delete the underlying snapshots
- Copying an AMI to another region copies the underlying snapshots too (cross-region DR pattern)
- You can copy an AMI and change its encryption settings during the copy (same pattern as snapshots)
- AMIs are locked to a region — always copy before launching in a different region
- Recycle Bin can also protect AMIs from accidental deletion (same rules as snapshots)
- Pre-baking software into an AMI = faster launch times vs. using user data scripts to install at boot

## EFS

EFS (Elastic File System) is a shared network drive that multiple EC2 instances can all read and write at the same time.

**EBS vs EFS in one sentence:** EBS is a USB stick plugged into *one* laptop. EFS is a NAS (network-attached storage) drive that every laptop in the office can access simultaneously.

**Key properties:**

- **Multi-instance** — hundreds of EC2 instances across multiple AZs can mount the same EFS volume concurrently
- **Fully managed NFS** — uses the NFS protocol; Linux only (no Windows support)
- **Elastic** — grows and shrinks automatically; no need to pre-provision a size like EBS
- **Pay for what you use** — billed per GB stored, not pre-allocated capacity
- **More expensive than EBS** — roughly 3× the cost of gp2, but you only pay for actual usage

**Real-world examples:**

- **Web farm with shared content** — 10 EC2 instances behind a load balancer all serve the same WordPress site. Media uploads (images, PDFs) land on EFS so every instance sees the same files instantly. Without EFS, uploads would only exist on one server's EBS volume.
- **CI/CD build cache** — a Jenkins farm where multiple build agents share a common dependency cache (Maven, npm). Each agent mounts EFS, pulling cached packages instead of downloading from the internet on every build.
- **Developer home directories** — each developer's home directory lives on EFS. When they SSH into any EC2 instance in the cluster, their files follow them — same experience regardless of which box they land on.
- **ML training data** — a large dataset stored once on EFS, accessed by multiple training instances running in parallel. No need to copy the dataset to each instance's EBS volume.

**Storage tiers:**

| Tier | Use case |
| ---- | -------- |
| Standard | Frequently accessed files |
| Infrequent Access (IA) | Files not touched in 30+ days — much cheaper |

**Lifecycle management** automatically transitions files between storage tiers based on how recently they were accessed. You define a rule (e.g. "move to Infrequent Access after 30 days of no access") and EFS handles the rest. If a file in IA is accessed again, it's automatically moved back to Standard. This keeps costs down without any manual intervention — same idea as S3 lifecycle rules.

**Performance settings** (configured at creation time):

*Throughput mode:*

| Mode | How it works | Use case |
| ---- | ------------ | -------- |
| Bursting | Scales with storage size; earns burst credits over time | Spiky, unpredictable workloads |
| Provisioned | You specify MB/s regardless of storage size | Consistently high throughput needs |
| Elastic | Automatically scales up/down with demand | Unpredictable workloads, easiest option |

*Performance mode:*

| Mode | Trade-off | Use case |
| ---- | --------- | -------- |
| General Purpose | Lower latency, default | Web serving, CMS, dev environments |
| Max I/O | Higher latency, higher throughput | Thousands of instances accessing simultaneously |

Real-world examples:

- **WordPress farm (General Purpose + Bursting)** — traffic is spiky (quiet overnight, busy during the day), storage is modest. Bursting handles peaks; General Purpose gives low latency for page loads.
- **Genomics pipeline (Max I/O + Provisioned)** — 500 instances all reading a large dataset simultaneously. Max I/O handles the parallelism; Provisioned throughput guarantees the MB/s regardless of how much data is stored.
- **CI/CD cache (General Purpose + Elastic)** — build frequency varies by team activity. Elastic mode handles the unpredictability without over-provisioning.

**EBS vs EFS vs Instance Store — when to pick which:**

| | EBS | EFS | Instance Store |
| - | --- | --- | -------------- |
| Attached to | One instance | Many instances simultaneously | One instance (physically) |
| Persistence | Survives stop/start | Survives stop/start | Lost on stop or termination |
| OS support | Linux + Windows | Linux only | Linux + Windows |
| Capacity | Fixed, pre-provisioned | Elastic, auto-scales | Fixed (comes with instance type) |
| Cost | Mid | Higher (~3× gp2) | Included in instance price |
| Use when | Single instance needs fast persistent disk | Multiple instances need shared access | Throwaway scratch space, maximum speed |

Exam scenario — "shared storage dynamically loaded on hundreds of instances":

You need to distribute software updates to 100s of Linux EC2 instances. Updates should be on shared storage, dynamically loaded, no heavy operations.

Answer: **EFS**. Mount it on all instances — when you update files on EFS, every instance sees them instantly. No downloading, no copying, no per-instance operations.

Why not the others:
- **EBS** — single instance only
- **S3** — shared, but requires downloading files to each instance (heavy operation)
- **Instance Store** — ephemeral, single instance

The keyword pattern: "shared" + "dynamically loaded" + "Linux" → **EFS**.

## Scaling and ELB

**Scalability — the two types:**

- **Vertical scaling** — make the instance bigger (e.g. `t3.micro` → `t3.large`). Simple but has a ceiling, and requires downtime.
- **Horizontal scaling** — add more instances. No ceiling, no downtime. This is what AWS is built for.

**High Availability is a consequence of Horizontal Scaling.** When you spread multiple instances across AZs, losing one AZ doesn't take down your app — the others keep serving traffic. Vertical scaling can't give you this; a single bigger instance is still a single point of failure.

### Elastic Load Balancer (ELB)

ELB is the umbrella service name — ALB, NLB, and GWLB are the three concrete types you actually choose between. When someone says "use an ELB" they mean "pick one of these".

Sits in front of your instances and distributes incoming traffic across them. Also hides the fact you have multiple instances behind a single DNS endpoint.

Three types you need to know:

| Type | Layer | Protocol | Use case |
| ---- | ----- | -------- | -------- |
| ALB (Application) | 7 | HTTP/HTTPS | Web apps, microservices, path-based routing (`/api` → one group, `/images` → another) |
| NLB (Network) | 4 | TCP/UDP | Ultra-high performance, static IP, gaming, IoT |
| GWLB (Gateway) | 3 | IP | Route traffic through firewalls/intrusion detection before it hits your app |

ALB is the default choice for most web workloads.

**GWLB — what it's actually for:**

GWLB is not a CDN or DDoS service. It's for routing traffic through **third-party network appliances** (firewalls, IDS/IPS, deep packet inspection tools from vendors like Palo Alto, Fortinet, or Check Point) before it reaches your app:

```
Internet → GWLB → Firewall appliance → Your app
```

The appliance runs inside your VPC; GWLB handles the traffic steering transparently at Layer 3. Mostly used by enterprises and regulated industries (finance, healthcare, gov) with compliance requirements mandating a specific security appliance.

**Exam trigger:** *"inspect or filter all traffic with a third-party appliance"* → GWLB.

**ALB vs NLB — how to pick:**

- **ALB** — Layer 7, understands HTTP; use when you need path/host-based routing, WebSocket, or to inspect request content.
- **NLB** — Layer 4, just TCP/UDP bytes; use when you need a **static IP** (ALB only gives you a DNS name), ultra-low latency, or non-HTTP protocols.
- **Static IP** is the most common exam trigger for NLB — if a question mentions a client whitelisting an IP, or a firewall that needs a fixed IP, that's NLB.

**Target Group** — the collection of targets that a load balancer routes traffic to. The load balancer forwards a request to a Target Group based on listener rules; the Target Group then picks a healthy target and sends the request there. Health checks are configured per Target Group.

All three load balancer types use Target Groups, but with different target types:

| Load balancer | Valid targets | Routing basis |
| ------------- | ------------- | ------------- |
| ALB | EC2 instances, IPs, Lambda functions | Layer 7 — path, host, headers |
| NLB | EC2 instances, IPs, ALBs | Layer 4 — TCP/UDP only |
| GWLB | Appliance instances | Layer 3 — all IP traffic |

The path-based routing example above (`/api` → one group, `/images` → another) is ALB-specific — each path maps to a different Target Group.

### SSL/TLS and Load Balancers

The ALB decrypts HTTPS traffic at the load balancer, then forwards plain HTTP to your instances — offloading the CPU cost of encryption from EC2:

```
Client → HTTPS → ALB (terminates TLS) → HTTP → EC2
```

- Certificates are managed via **ACM (AWS Certificate Manager)** — ACM handles renewal automatically, no manual cert management
- NLB can also terminate TLS, but uniquely supports **TLS passthrough** — forwards encrypted traffic all the way to the instance when end-to-end encryption is required

**SNI (Server Name Indication)** — allows one ALB to serve **multiple certificates** for multiple domains on a single listener. The client includes the hostname in the TLS handshake; the ALB picks the right cert. Without SNI you'd need one ALB per domain.

**Exam triggers:**

ACM:
- *"automatically renew SSL certificates"* → ACM
- *"a certificate is expiring and causing downtime"* → ACM (would have renewed it automatically)
- *"provision a free public certificate for an ALB"* → ACM (free for use with AWS services)

SNI:
- *"company hosts api.example.com and app.example.com behind one ALB"* → SNI, one cert per domain on the same listener
- *"reduce costs by consolidating multiple load balancers into one"* (where each served a different domain) → SNI enables this

TLS passthrough:
- *"compliance requires encryption in transit all the way to the application"* → NLB passthrough
- *"the application handles its own certificate"* → NLB passthrough
- *"mutual TLS (mTLS) between client and server"* → NLB passthrough (ALB terminates TLS so it can't pass client certs through)

TLS termination at ALB:
- *"reduce CPU load on EC2 instances"* → terminate TLS at the ALB
- *"centralise certificate management across many instances"* → ALB + ACM

### Connection Draining

When an instance is deregistered from a Target Group (e.g. during scale-in or a deployment), the load balancer stops sending **new** requests to it but allows **in-flight requests** to complete before fully removing it. This is called **Connection Draining** on CLB and **Deregistration Delay** on ALB/NLB.

- Default timeout: **300 seconds** (range: 1–3600, or 0 to disable)
- Short-lived requests (APIs, web pages) → lower it (e.g. 30s) to speed up deployments
- Long-running requests (video processing, large uploads) → keep it high so requests aren't cut off

**Exam trigger:** *"instances are being terminated before requests finish"* → increase Deregistration Delay. *"deployments are slow to complete"* → decrease it.

### Cross-Zone Load Balancing

Without cross-zone load balancing, each load balancer node only distributes traffic to instances **in its own AZ**. This can cause uneven load if AZs have different instance counts.

With cross-zone load balancing enabled, each node distributes traffic evenly **across all instances in all AZs**.

| Type | Cross-zone default | Cost |
| ---- | ------------------ | ---- |
| ALB | **Always on**, cannot disable | No charge for inter-AZ data |
| NLB | Off by default | Charged for inter-AZ data if enabled |
| GWLB | Off by default | Charged for inter-AZ data if enabled |

**Exam trigger:** *"traffic is unevenly distributed across AZs"* → cross-zone load balancing is disabled (or you have unequal instance counts per AZ).

### Sticky Sessions

By default, a load balancer routes each request independently — a user could hit a different instance on every request. Sticky sessions (a.k.a. session affinity) bind a user to a specific target for the duration of their session using a **cookie**.

Supported on ALB (not NLB — NLB is Layer 4 and has no concept of a session).

Two cookie types on ALB:

| Cookie type | Generated by | Notes |
| ----------- | ------------ | ----- |
| Duration-based | The ALB (`AWSALB` cookie) | Simplest; you set the TTL |
| Application-based | Your app (custom name) | App controls expiry logic |

**The problem with sticky sessions:** if the target instance fails, the session is lost. The user gets routed to a new instance that has no knowledge of their session.

**The better solution:** make your app stateless — store session data in **ElastiCache** or **DynamoDB** so any instance can serve any request. Sticky sessions are a workaround, not a fix.

**Exam trigger:** *"users are being logged out when the load balancer routes them to a different instance"* → sticky sessions (short-term fix) or move session state to ElastiCache (proper fix).

### Auto Scaling Group (ASG)

Automatically adds or removes EC2 instances based on demand. Works hand-in-hand with an ELB — new instances register with the load balancer automatically.

Three capacity numbers:

- **Minimum** — never go below this (e.g. 2)
- **Desired** — what you want right now (e.g. 4)
- **Maximum** — never exceed this (e.g. 10)

Scaling policies:

| Policy | How it works | Use case |
| ------ | ------------ | -------- |
| Target tracking | "Keep CPU at 60%" | Simplest, recommended default |
| Step scaling | Add 2 instances if CPU > 70%, add 4 if CPU > 90% | Fine-grained control |
| Scheduled | Scale up every weekday at 8am, down at 8pm | Predictable traffic patterns |
| Predictive | ML analyses historical data and provisions capacity before load arrives | Recurring patterns (e.g. Monday morning spike) |

Predictive scaling can be combined with target tracking — predictive handles the ramp-up, target tracking handles unexpected spikes.

If an instance fails a health check, ASG terminates it and launches a replacement automatically.

### CloudWatch Alarms and Scaling

CloudWatch Alarms are the underlying mechanism for scaling — when you create a step scaling policy you're creating an alarm under the hood (e.g. "CPU > 70% for 2 consecutive minutes"). When the alarm fires, ASG executes the scaling action.

- **Scale out** — alarm breaches upper threshold → add instances
- **Scale in** — alarm breaches lower threshold → remove instances
- You can alarm on any CloudWatch metric: CPU, network in/out, or custom app metrics (e.g. requests per instance)

**Exam triggers:**
- *"scale based on the number of messages in an SQS queue"* → custom CloudWatch metric on queue depth → ASG alarm
- *"scale before CPU gets too high"* → target tracking (simpler) or a CloudWatch Alarm with step scaling
- *"ensure the average number of connections per instance is around X"* → target tracking on `ALBRequestCountPerTarget` metric; the word "around" is the giveaway for target tracking over step scaling

### Scaling Cooldowns

After ASG executes a scaling action, it enters a cooldown period (default **300 seconds**) during which it ignores further scaling triggers. This gives new instances time to stabilise before ASG reacts again.

**Scale-out vs scale-in:**
- Be aggressive with scale-out (short cooldown) — add capacity fast when load spikes
- Be conservative with scale-in (longer cooldown) — avoid terminating instances that were just starting to be useful

**Pre-baked AMIs** — if your instances take a long time to become healthy (bootstrapping, installing packages), new capacity arrives slowly and cooldowns need to be longer. A pre-baked AMI with your app already installed means instances are ready faster, so you can reduce the cooldown and scale more responsively.

**Exam triggers:**
- *"instances are being launched and terminated repeatedly"* → cooldown too short
- *"scale-out is too slow to handle traffic spikes"* → cooldown too long, or switch to a pre-baked AMI
- *"reduce costs by terminating unused instances faster"* → reduce scale-in cooldown

**Lab tip:** use the `stress` package to simulate CPU load and trigger scaling policies in practice:

```bash
sudo yum install stress -y
stress --cpu 4 --timeout 300
```

### Health Checks

**ALB health checks** — the ALB periodically sends an HTTP/HTTPS request to each target on a configured path (e.g. `/health`). If the target returns a non-2xx/3xx response, or doesn't respond within the timeout, it's marked unhealthy and taken out of rotation until it passes again.

Settings you can tune:

| Setting | Description | Default |
| ------- | ----------- | ------- |
| Path | Endpoint to hit | `/` |
| Interval | How often to check | 30s |
| Threshold | Consecutive successes/failures to change state | 2 healthy / 3 unhealthy |
| Timeout | How long to wait for a response | 5s |

**ASG health checks** — by default ASG uses EC2 status checks (is the instance running?). You can also enable **ELB health checks** — if the ALB marks an instance unhealthy, ASG terminates and replaces it. This is the more useful setting in production.

**Exam triggers:**
- *"unhealthy instances are still receiving traffic"* → health check misconfigured or threshold too high
- *"instances are being terminated too aggressively"* → health check interval/threshold too sensitive
- *"ASG is not replacing unhealthy instances that fail ALB health checks"* → ASG is only using EC2 checks, needs ELB health checks enabled

### ALB and EC2 Security Groups

The recommended pattern is to restrict EC2 instances so they only accept traffic from the ALB — not directly from the internet.

- **ALB security group** — allows inbound 80/443 from `0.0.0.0/0` (the internet)
- **EC2 security group** — allows inbound on your app port **only from the ALB security group ID** (e.g. `sg-abc123`)

This means:

- Traffic from the internet hits the ALB ✅
- ALB forwards to the EC2 instance ✅
- Someone trying to hit the EC2 public IP directly gets blocked ❌

The EC2 inbound rule references the ALB's security group ID as the source rather than an IP range. AWS evaluates this dynamically — any traffic originating from a resource in that security group is allowed through.

**Why it matters:**

- Hides instances from direct internet exposure
- All traffic flows through the ALB, so you get logging, SSL termination, and routing rules applied consistently
- If an instance's public IP changes, nothing breaks — the security group reference stays valid

### EC2 without a Public IP

When using an ALB, the EC2 instance doesn't need a public IP. The ALB sits in a public subnet and handles all internet-facing traffic; the instance sits in a private subnet, unreachable from the internet directly.

```
Internet → ALB (public subnet, public IP) → EC2 (private subnet, no public IP)
```

**Cost consideration:** the ALB itself costs ~$16/month minimum regardless of traffic. For simple or personal projects that's often overkill.

| Option | Cost | When to use |
| ------ | ---- | ----------- |
| ALB + private EC2 | ~$16+/month | Production, multiple instances, SSL termination at scale |
| EC2 with public IP, SG locked to your IP on port 22, open on 80/443 | ~$0.005/hr | Dev or personal projects |

For a cost-conscious personal project, a single EC2 instance with a public IP and a tight security group is perfectly reasonable — no ALB needed.

## ECS (Elastic Container Service)

Runs Docker containers on AWS. The key choice is the **launch type** — whether you manage the underlying infrastructure or not.

| Launch type | What you manage | What AWS manages |
| ----------- | --------------- | ---------------- |
| **ECS on EC2** | EC2 instances (OS, patching, ASG) | Container scheduling on top of your fleet |
| **ECS on Fargate** | Nothing | Everything — instances, OS, scaling |

**ECS on EC2** is a middle ground: you get containers, but still control the underlying fleet. Useful when you need specific instance types (e.g. GPU), custom AMIs, or cost optimisation via Reserved Instances.

**ECS on Fargate** is fully serverless — you define a task (Docker image, CPU, memory) and AWS runs it. No instances to patch or scale. You pay per vCPU/memory per second.

### ECS vs ASG + EC2

| | ASG + EC2 | ECS + Fargate |
| - | --------- | ------------- |
| Unit of work | Instance | Container (task) |
| OS management | You | AWS |
| Scaling | Scale instances | Scale tasks |
| Best for | Full control, existing AMIs | Containerised apps, minimal ops overhead |

### Key concepts

- **Task definition** — blueprint for your container: image, CPU, memory, ports, env vars
- **Task** — a running instance of a task definition (like a Pod in Kubernetes)
- **Service** — keeps a desired number of tasks running, restarts failed tasks, integrates with ALB
- **Cluster** — logical grouping of tasks/services (and EC2 instances if using EC2 launch type)

### When to choose EC2 over ECS

ECS/Fargate is simpler for most new workloads, but plain EC2 makes more sense when:

| Reason | Real-world example |
| ------ | ------------------ |
| App isn't containerised | A legacy Java monolith deployed as a JAR directly on the OS — containerising it requires real effort and testing |
| Full OS control needed | An ML training job that needs specific NVIDIA drivers, or a security tool that requires custom kernel modules |
| Long-running stateful process | A self-hosted PostgreSQL or Redis instance writing to local disk — containers are ephemeral by design |
| Per-machine software licensing | Oracle DB licensed per physical host — running it in a container doesn't change the licensing model |
| Cost at low scale | A single t3.small running 24/7 on a 1-year Reserved Instance is cheaper than equivalent always-on Fargate tasks |
| Team familiarity | A small team that knows EC2 well and has no container experience — Fargate adds orchestration complexity they may not need yet |

**The honest rule:** if you're building something new and it can be containerised, Fargate wins. EC2 makes sense for existing workloads, OS-level requirements, or licensing constraints.

### Bottlerocket

A minimal Linux OS built by AWS specifically for running containers. Used as the AMI on ECS on EC2 or EKS nodes instead of Amazon Linux.

- **Read-only root filesystem** — the OS partition is immutable, can't be modified at runtime
- **No SSH by default** — access via SSM Session Manager instead
- **Atomic updates** — OS updates are applied as an image swap and roll back automatically on failure
- **Smaller attack surface** — no package manager, no unnecessary services, only what's needed to run containers

**Relationship to ECS:** Bottlerocket is the OS your ECS on EC2 instances boot into. When launching an ECS cluster with EC2, you choose an AMI — normally Amazon Linux 2, but Bottlerocket is the hardened alternative:

```
Bottlerocket (OS) → EC2 instance → ECS agent → containers
```

AWS publishes official Bottlerocket AMIs for ECS and EKS. Your containers behave identically — the difference is purely OS security posture and update management. Not relevant for Fargate (AWS manages the OS for you). Not a general-purpose OS — you can't install arbitrary software on it.

**Exam relevance:** low for SAA-C03, but appears in security hardening or container infrastructure questions. Worth knowing the concept: *"minimal, immutable OS for containers"*.

### Exam triggers

- *"run containers without managing servers"* → ECS on Fargate
- *"migrate a containerised app with minimal infrastructure overhead"* → Fargate
- *"need GPU instances or a custom AMI for containers"* → ECS on EC2
- *"keep a container running and replace it if it crashes"* → ECS Service
- *"scale containers based on load"* → ECS Service + ALB + target tracking policy
- *"harden the OS on container instances"* → Bottlerocket

### ECR (Elastic Container Registry)

AWS's private Docker image registry — where you store, manage, and deploy container images. The AWS equivalent of Docker Hub (but private by default).

```
Developer → docker build → docker push → ECR → ECS/Fargate/EKS pulls image
```

**Key properties:**
- **Private by default** — images only accessible within your AWS account
- **Public gallery** available (public.ecr.aws) for open-source images
- **Integrated with ECS/EKS** — no extra config, just reference the image URI
- **Image scanning** — automatic vulnerability scanning on push
- **Lifecycle policies** — auto-delete old/untagged images to save storage costs

**Exam trigger:** *"store Docker images on AWS"* → ECR.

### ECS Data Volumes

Containers are ephemeral — a Fargate task stops and all data inside is gone. To persist or share data, you need a volume.

| Volume type | Works with | Persistent? | Shared across tasks? | Use case |
| ----------- | ---------- | ----------- | -------------------- | -------- |
| EFS | Fargate + EC2 | Yes | Yes — multiple tasks mount the same EFS | Shared data, CMS uploads, ML models |
| EBS | EC2 only | Yes | No — one task at a time | Database containers on EC2 launch type |
| Ephemeral storage | Fargate | No — lost when task stops | No | Scratch space (20 GB default, up to 200 GB) |
| Bind mounts | EC2 only | Depends on instance | Between containers in same task | Sidecar sharing (log collector reading app logs) |

The exam answer is almost always **EFS + Fargate** — persistent shared storage across serverless containers.

**EBS doesn't work with Fargate** — there's no EC2 instance to attach it to. This is a common trap answer.

**Exam triggers:**
- *"Fargate tasks need persistent shared storage"* → EFS
- *"multiple containers need to access the same files"* → EFS
- *"persistent block storage for ECS containers"* → EBS (EC2 launch type only, not Fargate)

### ECS IAM Roles

Two separate roles — this confuses people:

| Role | Attached to | Purpose |
| ---- | ----------- | ------- |
| Task Execution Role | The ECS agent | Pull images from ECR, write logs to CloudWatch, read secrets from Secrets Manager |
| Task Role | The container itself | Your app's permissions — access S3, DynamoDB, SQS, etc. |

```
┌─────────────────────────────────────────────────────────┐
│  ECS Task                                               │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Task Execution Role (infrastructure plumbing)  │    │
│  │  Used by: ECS Agent                             │    │
│  │                                                 │    │
│  │  → Pull image from ECR                          │    │
│  │  → Write logs to CloudWatch                     │    │
│  │  → Read secrets from Secrets Manager             │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Task Role (your app's permissions)             │    │
│  │  Used by: your container code                   │    │
│  │                                                 │    │
│  │  → Read/write S3                                │    │
│  │  → Query DynamoDB                               │    │
│  │  → Send messages to SQS                         │    │
│  │  → (whatever your app needs)                    │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Execution Role = get the container running.** **Task Role = what the container does once running.**

**Exam triggers:**
- *"container can't pull image from ECR"* → Task Execution Role is missing or wrong
- *"app running in ECS needs to access S3"* → Task Role
- *"ECS tasks can't write logs to CloudWatch"* → Task Execution Role

### ECS + ALB (Dynamic Port Mapping)

When running multiple tasks on the same EC2 instance, each task needs a different port. ECS handles this automatically with **dynamic port mapping** — you don't specify a host port, ECS picks one, and the ALB discovers it.

```
ALB :80 → Instance A:32768 (Task 1)
        → Instance A:32769 (Task 2)
        → Instance B:32770 (Task 3)
```

Each task registers itself with the ALB Target Group on its dynamic port. The ALB routes traffic to the right task. You don't manage any of this — ECS and ALB handle it.

**With Fargate:** dynamic port mapping isn't needed — each task gets its own ENI and private IP. The ALB routes directly to each task's IP on the container port.

**Exam trigger:** *"run multiple containers on the same EC2 instance behind an ALB"* → dynamic port mapping.

### ECS Auto Scaling

**Does scaling tasks cost money?** Depends on the launch type:

On EC2: if the instance has spare CPU/memory, adding tasks is free — you're already paying for the instance. Like renting an apartment: putting more furniture in doesn't increase your rent until you need a second apartment.

```
EC2 instance (4 vCPU, 8 GB) — you pay for this regardless
├── Task A (1 vCPU, 2 GB) — no extra cost
├── Task B (1 vCPU, 2 GB) — no extra cost
├── Task C (1 vCPU, 2 GB) — no extra cost
└── Spare: 1 vCPU, 2 GB   — room for one more

Task D → fits in spare → $0 extra
Task E → no room → Capacity Provider adds new instance → now you pay more
```

On Fargate: every task costs money — you pay per vCPU/memory per second. More tasks = more cost, always.

| | ECS on EC2 | ECS on Fargate |
| - | ---------- | -------------- |
| More tasks costs more? | Only if you need more instances | Always — pay per task |
| Spare capacity | Free to use | No concept of spare |

This is why **binpack saves money** on EC2 — fill up existing instances before adding new ones.

ECS scales **tasks** (not EC2 instances). Three scaling strategies:

| Strategy | How it works |
| -------- | ------------ |
| Target tracking | "Keep average CPU at 60%" — ECS adjusts task count |
| Step scaling | Add 2 tasks if CPU > 70%, add 4 if CPU > 90% |
| Scheduled | Scale up every weekday at 8am |

**Scaling on SQS queue depth** — common exam pattern:

```
SQS queue depth growing → CloudWatch Alarm → ECS Service scales out tasks
Queue drains            → CloudWatch Alarm → ECS Service scales in tasks
```

**Fargate Auto Scaling** is easier — you just set the scaling policy. No capacity providers to manage.

**ECS on EC2 — two layers of scaling (why you need EC2 ASG with ECS):**

With EC2 launch type, you scale **tasks** and **instances** separately. ECS already places tasks on the instance with the most available resources — but if **all** instances are full, there's nowhere to place new tasks.

```
Layer 1 — ECS Service Auto Scaling (tasks):
"I need more containers running"

Layer 2 — EC2 ASG Auto Scaling (instances):
"I need more machines to put containers on"
```

The problem without both layers:

```
ECS: "Scale to 20 tasks"
EC2 cluster: only has capacity for 12 tasks
8 tasks stuck in PENDING ❌

EC2 ASG adds 2 more instances → now capacity for 20 tasks ✅
```

**Capacity Providers** link ECS and ASG together — when ECS needs more task capacity, the ASG automatically adds instances. When tasks scale in, empty instances get terminated. Without Capacity Providers, you'd have to manage the two scaling layers independently.

**This is why Fargate is simpler** — there are no instances. AWS handles the compute. You just scale tasks and never think about the underlying machines.

### ECS Task Placement (EC2 only)

When running ECS on EC2, ECS needs to decide **which instance** to place a task on. Not relevant for Fargate — AWS handles placement.

**Placement strategies:**

| Strategy | How it works | Use case |
| -------- | ------------ | -------- |
| binpack | Pack tasks onto fewest instances (fill up one before using the next) | Cost — minimise running instances |
| spread | Spread tasks across AZs or instances evenly | Availability — survive instance/AZ failure |
| random | Random placement | Testing |

You can **combine strategies** — e.g. spread across AZs first, then binpack by memory within each AZ. This gives you HA (spread across AZs) while minimising cost (fewest instances per AZ).

**Placement constraints:**

- `distinctInstance` — each task on a different instance (no two tasks on the same host)
- `memberOf` — place on instances matching an expression (e.g. only `t3.large` instances, or only instances in a specific AZ)

**Exam triggers:**
- *"reduce EC2 costs for ECS"* → binpack (fewer instances running)
- *"maximise availability for ECS tasks"* → spread across AZs
- *"each task must run on a different instance"* → distinctInstance constraint

### ECS Capacity Providers

Capacity Providers tell ECS **where and how to run tasks** — the link between your service and the underlying compute.

**Three types:**

| Capacity Provider | What it manages |
| ----------------- | --------------- |
| FARGATE | Serverless — AWS provisions compute per task |
| FARGATE_SPOT | Same but on spare capacity — up to 70% cheaper, can be interrupted |
| Auto Scaling Group | Your EC2 instances — scales them up/down based on task demand |

**Capacity Provider Strategy — mixing compute types:**

Run a single service across multiple providers with weights:

```
Service "web-api":
  - FARGATE:      weight 1 (base: 2)  → always keep 2 Fargate tasks (guaranteed)
  - FARGATE_SPOT: weight 3            → scale additional tasks on Spot (cheaper)
```

`base` = minimum tasks on that provider (always running). `weight` = ratio for additional tasks. For every 1 Fargate task added, 3 Spot tasks are added. The base of 2 ensures reliability even if Spot gets reclaimed.

Real-world example: a web API needs at least 2 tasks for reliability but bursts to 20 during peaks. 2 tasks on FARGATE (always running), burst tasks on FARGATE_SPOT (70% cheaper, acceptable if some get interrupted).

**EC2 Capacity Provider — managed scaling:**

Links an ASG to ECS. The Capacity Provider tracks how much CPU/memory is **reserved** across all instances — not actual usage. Each task reserves capacity when placed:

```
EC2 instance (4 vCPU, 8 GB)

Task A reserves 1 vCPU, 2 GB → 3 vCPU, 6 GB remaining
Task B reserves 1 vCPU, 2 GB → 2 vCPU, 4 GB remaining
Task C reserves 1 vCPU, 2 GB → 1 vCPU, 2 GB remaining
Task D needs    2 vCPU, 4 GB → won't fit → Capacity Provider scales out
```

It doesn't matter if Task A is actually using 0.1 vCPU — it reserved 1 vCPU, so that capacity is unavailable. This is why right-sizing task definitions matters: over-reserve and you waste capacity, under-reserve and tasks compete for resources.

You set a **target capacity percentage** (e.g. 80%):

- At 100%: instances packed full before scaling — risk of tasks going PENDING
- At 80%: scale out when 80% reserved — keeps 20% headroom for bursts
- Below target → ASG scales in (remove instances)
- Above target → ASG scales out (add instances)

**"Do busy tasks cause EC2 scaling?" — No.** It's new tasks needing placement that triggers it:

```
App gets busy
→ ECS Service Auto Scaling: "I need more tasks"
→ Capacity Provider: "do I have room on existing instances?"
→ No room → tells ASG to add instances
→ New instances join → tasks get placed
```

A single task hammering the CPU doesn't cause EC2 scaling by itself. The EC2 count only changes when ECS needs to **place new tasks** and there's no room. If a task runs hot but ECS hasn't decided to add more tasks, the instance count stays the same.

**Exam triggers:**
- *"reduce Fargate costs for fault-tolerant tasks"* → FARGATE_SPOT
- *"mix of reliable and cost-effective compute"* → Capacity Provider Strategy (FARGATE + FARGATE_SPOT)
- *"ECS tasks stuck in PENDING on EC2"* → EC2 Capacity Provider not configured

### EKS (Elastic Kubernetes Service)

Managed **Kubernetes** on AWS. Same concept as ECS (run containers) but using the Kubernetes ecosystem instead of AWS's proprietary orchestrator.

**ECS vs EKS:**

| | ECS | EKS |
| - | --- | --- |
| Orchestrator | AWS proprietary | Kubernetes (open-source) |
| Learning curve | Lower — simpler API | Higher — Kubernetes complexity |
| Portability | AWS only | Multi-cloud (same K8s everywhere) |
| Ecosystem | AWS-native tools | Huge K8s ecosystem (Helm, Istio, ArgoCD, etc.) |
| Launch types | EC2 or Fargate | EC2 or Fargate |

**When to use EKS over ECS:**
- Your team already knows Kubernetes
- You need multi-cloud portability (run same workloads on AWS, GCP, Azure)
- You need Kubernetes-specific features (custom controllers, service mesh, operators)
- You're migrating an existing Kubernetes deployment to AWS

**When to use ECS:** everything else. Simpler, cheaper, less operational overhead.

**ECS to EKS concept mapping:**

If you know ECS, you already understand EKS — just different names:

| ECS | EKS / Kubernetes | What it is |
| --- | ---------------- | ---------- |
| Task Definition | Pod spec / Deployment YAML | Blueprint for your container(s) |
| Task | Pod | Running instance of the blueprint |
| Service | Service + Deployment | Keeps desired number of pods running, load balances |
| Cluster | Cluster | Logical grouping of everything |
| Task Role | Service Account (IRSA) | Your app's AWS permissions |
| Task Execution Role | Node IAM Role | Infrastructure plumbing (pull images, write logs) |
| Capacity Provider | Node Group / Fargate Profile | Where pods run (EC2 instances or Fargate) |

**Don't confuse Task Definition with Task:**

- **Task Definition / Pod spec** = the recipe (image, CPU, memory, ports, env vars)
- **Task / Pod** = the meal you cooked from that recipe (a running instance)

You can run 10 Tasks from 1 Task Definition, just like Kubernetes runs 10 Pods from 1 Deployment spec.

A Pod can run multiple containers that share the same network and storage (sidecar pattern — e.g. app container + log collector container). ECS tasks can also have multiple containers, but Kubernetes makes this pattern more first-class.

**EKS compute — same choice as ECS:**

EKS needs compute underneath — you choose EC2 or Fargate, just like ECS:

```
ECS:  Task runs on → EC2 instance or Fargate
EKS:  Pod runs on  → EC2 node or Fargate
      (same concept, different names)
```

| | EKS on EC2 (Node Groups) | EKS on Fargate |
| - | ------------------------ | -------------- |
| You manage | EC2 instances (nodes) | Nothing |
| Scaling | You scale nodes + pods | Just scale pods |
| Cost | Pay for instances | Pay per pod |
| Use case | Full control, GPU, cost optimisation | Serverless, minimal ops |

**Fargate Profiles** define which pods run on Fargate based on namespace and labels. Pods that don't match a profile run on EC2 nodes. This lets you mix both in the same cluster — e.g. production pods on Fargate, batch jobs on EC2 Spot nodes.

**AMIs still matter on EC2 launch type (ECS and EKS):**

When using EC2, the nodes boot from an AMI. AWS provides optimised AMIs (Amazon Linux 2 with container runtime pre-installed), but you can also use Bottlerocket (hardened) or custom AMIs (specific software/security tools). On Fargate, AMIs are irrelevant — AWS manages the host.

| | EC2 launch type | Fargate |
| - | --------------- | ------- |
| AMI | You choose (AWS-optimised, Bottlerocket, custom) | Not applicable — AWS manages |
| OS patching | You (via AMI updates, rolling replacements) | AWS |

**Exam triggers:**
- *"company already uses Kubernetes on-premises"* → EKS
- *"run containers on AWS with minimal complexity"* → ECS/Fargate
- *"run Kubernetes pods without managing nodes"* → EKS on Fargate
- *"need GPU for ML pods on Kubernetes"* → EKS on EC2
- *"harden the OS on container nodes"* → Bottlerocket AMI

### IRSA (IAM Roles for Service Accounts)

How EKS pods get AWS permissions — the equivalent of ECS Task Roles.

In ECS, you attach a Task Role to a task definition and the container gets AWS credentials automatically. In EKS, the same concept exists but uses Kubernetes-native Service Accounts linked to IAM Roles:

```
ECS:  Task Definition → Task Role (IAM) → container gets AWS credentials
EKS:  Pod → Service Account → linked to IAM Role (IRSA) → pod gets AWS credentials
```

**How it works:**

1. Create an IAM Role with the permissions your pod needs (e.g. S3 read)
2. Create a Kubernetes Service Account and annotate it with the IAM Role ARN
3. Assign the Service Account to your pod
4. The pod automatically gets temporary credentials for that IAM Role

**Why not just use the Node IAM Role?** The node role applies to **every pod** on that instance. IRSA gives each pod its own permissions — pod A can access S3 while pod B on the same node cannot. Least-privilege per pod.

**Exam triggers:**
- *"EKS pod needs to access S3/DynamoDB"* → IRSA
- *"least-privilege permissions for Kubernetes pods"* → IRSA (not node role)

### AWS App Runner (being discontinued)

The simplest way to run a container or web app on AWS — even simpler than Fargate. You give it source code or a container image, App Runner handles everything: build, deploy, scale, load balancing, TLS.

**Note:** App Runner stopped accepting new customers April 30, 2026. AWS recommends **ECS Express Mode** as the replacement. May still appear on the current exam.

```
Source code (GitHub) → App Runner → running HTTPS app with auto-scaling
Container image (ECR) → App Runner → running HTTPS app with auto-scaling
```

**App Runner vs Fargate:**

| | App Runner | Fargate |
| - | ---------- | ------- |
| Setup | Minimal — point at code or image | More config — task definitions, services, ALB, target groups |
| Networking | Managed — you get an HTTPS URL | You configure VPC, subnets, security groups, ALB |
| Control | Less — opinionated defaults | More — fine-grained control over everything |
| Use case | Simple web apps, APIs, quick prototypes | Complex architectures, microservices, full control |

**Exam trigger:** *"simplest way to deploy a container with no infrastructure config"* → App Runner. *"need fine-grained control over networking and scaling"* → Fargate.

### Container Services — Quick Reference

| Service | What it is | Use case |
| ------- | ---------- | -------- |
| ECR | Docker image registry | Store and manage container images |
| ECS | AWS container orchestrator | Run containers with AWS-native tooling |
| EKS | Managed Kubernetes | Run containers with K8s ecosystem, multi-cloud |
| Fargate | Serverless compute for ECS/EKS | No instances to manage |
| App Runner | Simplest container deployment (being discontinued) | Quick web apps, minimal config |
| App2Container (A2C) | Containerisation tool | Migrate existing Java/.NET apps to containers without rewriting code |

**App2Container** analyses an existing app running on-prem or EC2, generates a Dockerfile, builds the image, and creates ECS/EKS task definitions. Exam trigger: *"containerise an existing application without rewriting code"* → App2Container.

## RDS (Relational Database Service)

Managed SQL database service. AWS handles provisioning, OS patching, backups, monitoring, and hardware. You manage the database itself — schema, queries, users.

**Supported engines:** PostgreSQL, MySQL, MariaDB, Oracle, Microsoft SQL Server, Amazon Aurora.

**RDS vs DB on EC2:**

| | RDS | DB on EC2 |
| - | --- | --------- |
| OS patching | AWS | You |
| Backups | Automated | You |
| High availability | Multi-AZ with one click | Complex to set up |
| Read scaling | Read replicas built-in | You |
| Cost | Higher | Lower (but more ops work) |

**What you can't do with RDS:** SSH into the instance, install custom software, or access the OS layer. If you need OS-level access to the database host, run the DB on EC2 — but you give up all managed features.

**Exam trigger:** *"managed relational database"* or *"reduce database administration overhead"* → RDS. *"need OS access to the database host"* → DB on EC2.

### RDS and Aurora Security

**Network isolation:**

- RDS/Aurora instances are deployed in your VPC — typically in **private subnets** with no internet access
- **Security groups** control which IPs/resources can connect to the database port
- **Public accessibility** is off by default — keep it that way in production

**Authentication — three options:**

| Method | How it works | Use case |
| ------ | ------------ | -------- |
| Username/password | Traditional DB credentials | Default, simplest |
| IAM database auth | App gets a short-lived token via AWS API instead of a password | Lambda, apps with IAM roles — no credentials to store |
| Kerberos / Active Directory | Integrates with existing AD infrastructure | Enterprises with centralised identity (SQL Server, Oracle, PostgreSQL) |

**IAM database auth engine support:**

| Engine | IAM Auth |
| ------ | -------- |
| MySQL / MariaDB | Yes |
| PostgreSQL | Yes |
| Aurora MySQL / PostgreSQL | Yes |
| Oracle | No — uses Oracle Wallet, Kerberos/AD |
| SQL Server | No — uses Active Directory/Kerberos |

Oracle and SQL Server have their own enterprise authentication ecosystems, so AWS didn't build IAM auth for them.

**Audit logging:**

- Enable database engine logs (slow query, general, error) and send to **CloudWatch Logs**
- Aurora also supports **Advanced Auditing** for fine-grained query-level logging

**Key exam detail:** you **cannot SSH** into RDS or Aurora. There is no OS-level access. All security is managed through AWS controls (security groups, IAM, KMS, parameter groups). If the question mentions SSH → RDS Custom or DB on EC2.

**Exam triggers:**
- *"authenticate to RDS without storing credentials"* → IAM database authentication
- *"database must not be accessible from the internet"* → private subnet + no public accessibility
- *"integrate database authentication with Active Directory"* → Kerberos
- *"audit all queries run against the database"* → CloudWatch Logs / Aurora Advanced Auditing

### RDS Backups

**Automated backups:**

- Run daily during a configurable backup window
- Retention: 0–35 days (0 disables automated backups)
- Also captures transaction logs every 5 minutes — enables **point-in-time recovery** to any second within the retention window
- Stored in S3 (managed by AWS — you don't see the bucket)

**Manual snapshots:**

- You trigger these yourself (or via automation)
- Persist **indefinitely** until you delete them — not subject to retention period
- Useful for keeping a known-good state before a risky migration or schema change

**Snapshots vs Transaction Logs:**

Snapshots and transaction logs work together to enable point-in-time recovery:

- **Snapshot** — a full copy of the database at a point in time. Like taking a photo.
- **Transaction logs** — a continuous record of every change since the last snapshot. Like a video recording between photos.

Point-in-time recovery combines both: restore the most recent snapshot, then replay transaction logs up to the exact second you specify.

```
Snapshot (3am) ──── tx logs ──── tx logs ──── tx logs ──── now
                                      ↑
                          "restore to here" (e.g. 2:47pm)
```

| | Snapshot | Transaction Log |
| - | -------- | --------------- |
| What it captures | Full database state | Changes since last snapshot |
| Granularity | Point-in-time (when taken) | Every 5 minutes |
| Restore precision | Exact snapshot time only | Any second within retention |
| Size | Large (full copy) | Small (just changes) |

Without transaction logs, you could only restore to the exact time a snapshot was taken — not to any arbitrary second.

**Key detail:** restoring a backup (automated or manual) always creates a **new** RDS instance with a new endpoint. It does not restore in-place to the existing instance. Your app must be updated to point to the new endpoint.

**Exam triggers:**
- *"recover the database to a specific point in time"* → automated backups with point-in-time recovery
- *"restore to 5 minutes before the accidental DELETE"* → point-in-time recovery (snapshot + transaction log replay)
- *"keep a backup before a major change"* → manual snapshot
- *"backups are being deleted after 35 days"* → that's the automated retention limit; use manual snapshots for long-term

### RDS Encryption

**At-rest encryption:**

- Uses AWS KMS (Key Management Service) — either AWS-managed key or your own CMK
- Must be enabled **at creation time** — you cannot encrypt an existing unencrypted RDS instance directly
- Encrypts the underlying storage, automated backups, snapshots, and read replicas

**Encrypting an existing unencrypted instance** (the workaround):

1. Take a snapshot of the unencrypted instance
2. Copy the snapshot and enable encryption during the copy
3. Restore the encrypted snapshot to a new RDS instance
4. Switch your app to the new encrypted instance

**In-transit encryption:**

- SSL/TLS connections between your app and RDS — supported by all engines
- Can be enforced with a parameter group setting (e.g. `rds.force_ssl = 1` for PostgreSQL)

**Key rules:**
- If the primary is encrypted, read replicas and snapshots are automatically encrypted with the same key
- An unencrypted primary cannot have encrypted read replicas (and vice versa)
- Snapshot copies can change the encryption key — useful for cross-account sharing with a different KMS key

**Exam triggers:**
- *"encrypt an existing unencrypted database"* → snapshot → copy with encryption → restore
- *"ensure all database connections use SSL"* → enforce SSL via parameter group
- *"share an encrypted snapshot with another account"* → copy snapshot with the target account's KMS key, then share

### RDS Proxy

RDS Proxy sits between your application and the database, pooling and reusing connections. The primary use case is **Lambda + RDS** — each Lambda invocation opens a new database connection, and under load hundreds of concurrent Lambdas can exhaust the database's connection limit.

```
Without proxy:  100 Lambdas → 100 DB connections → DB overwhelmed
With proxy:     100 Lambdas → RDS Proxy (connection pool) → ~10 DB connections
```

**Other benefits:**

- **Faster failover** — RDS Proxy detects Multi-AZ failover and routes to the new primary without your app reconnecting or handling errors
- **IAM authentication** — enforce IAM-based DB auth instead of storing credentials in code or Secrets Manager lookups in every function

**Supported engines:** MySQL, PostgreSQL, MariaDB, SQL Server (and Aurora MySQL/PostgreSQL).

**Never publicly accessible:** RDS Proxy can only be accessed from within the VPC — there is no public accessibility option. This is by design, unlike RDS itself which *can* be made public. Your app (Lambda, EC2, ECS) must be in the same VPC or connected via VPC peering/PrivateLink.

**RDS Proxy security — no passwords in your code:**

RDS Proxy integrates with **Secrets Manager** to handle database credentials. Your Lambda authenticates to RDS Proxy with IAM — it never touches a database password.

```
Without RDS Proxy: Lambda stores DB creds in env vars → connects directly to RDS
With RDS Proxy:    Lambda (IAM role) → RDS Proxy → Secrets Manager (fetches DB creds) → RDS
                   (Lambda never sees the password)
```

Three layers of security:
- **IAM authentication** — Lambda uses its IAM role, no credentials in code
- **Secrets Manager** — RDS Proxy fetches and rotates DB credentials automatically
- **VPC only** — not publicly accessible, reduces attack surface

**Exam triggers:**
- *"Lambda functions timing out connecting to RDS"* → RDS Proxy
- *"too many database connections"* → RDS Proxy
- *"reduce database failover time for the application"* → RDS Proxy
- *"serverless application with a relational database"* → RDS Proxy
- *"avoid storing database credentials in Lambda code"* → RDS Proxy + IAM auth + Secrets Manager

### Read Replicas

A single RDS instance handles both reads and writes. Under heavy read load (reporting, analytics, dashboards) the primary gets overwhelmed even when writes are infrequent. Read replicas offload that traffic to separate instances.

**How they work:**

- The primary handles all writes
- Changes are replicated to replicas **asynchronously**
- Your app directs reads to the replica endpoint, writes to the primary endpoint

**The staleness trade-off:**

Because replication is async, replicas lag behind the primary — typically milliseconds, but more under heavy load:

| Scenario | Use primary or replica? |
| -------- | ----------------------- |
| Reporting and analytics | Replica — slightly stale data is fine |
| Read-heavy dashboard | Replica |
| Financial transaction — read balance after transfer | Primary — must be accurate |
| User reads their own just-written data | Primary |

**Exam triggers:**
- *"improve read performance"* or *"offload reporting queries"* → read replicas
- *"data must always be up to date"* → query the primary, not a replica

### Multi-AZ

Multi-AZ is about **availability**, not performance. AWS maintains a standby instance in a different AZ kept in sync **synchronously**. If the primary fails, RDS automatically fails over to the standby — no manual intervention, no data loss.

- The standby is **not readable** — it exists solely for failover
- Failover typically takes 1–2 minutes (DNS flips to the standby)
- Protects against AZ failure, instance failure, or maintenance events

**Multi-AZ vs Read Replicas — the most common exam confusion:**

| | Multi-AZ | Read Replica |
| - | -------- | ------------ |
| Purpose | High availability | Read scaling |
| Replication | Synchronous | Asynchronous |
| Standby readable? | No | Yes |
| Automatic failover? | Yes | No |
| Data loss on failover? | None | Possible (lag) |

**Exam triggers:**
- *"automatic failover"*, *"high availability"*, or *"survive an AZ failure"* → Multi-AZ
- *"improve read performance"* → Read Replicas
- Both needed → Multi-AZ for HA + Read Replicas for scaling (they can be used together)

**Using them together:**

Multi-AZ and Read Replicas are complementary — you can and often should use both:

```
Primary (Multi-AZ) → synchronous → Standby (failover, not readable)
Primary (Multi-AZ) → asynchronous → Read Replica (readable, slight lag)
```

**Promoting a Read Replica:**

A Read Replica can be promoted to become a standalone primary. This breaks replication and the replica becomes its own independent instance. Common use cases:

- **Cross-region migration** — create a Read Replica in the target region, let it catch up, then promote it and cut over with minimal downtime
- **Disaster recovery** — if the primary region fails entirely, promote a cross-region replica to take over
- **Forking for testing** — promote a replica to create a copy of production for testing without affecting the live database

### RDS Custom

RDS Custom gives you OS and database-engine-level access while still getting some managed benefits (automated backups, monitoring). Standard RDS is a black box — you can't SSH in or install anything on the host. RDS Custom opens that up.

**Available for:** Oracle and SQL Server only.

**RDS vs RDS Custom:**

| | RDS | RDS Custom |
| - | --- | ---------- |
| OS access | No | Yes (SSH, RDP) |
| Custom software on host | No | Yes |
| DB engine customization | No | Yes |
| Managed backups | Yes | Yes |
| Multi-AZ | Yes | Yes |

**When you need RDS Custom — real-world examples:**

Oracle-specific:
- Installing Oracle Application Express (APEX) or custom Oracle patches AWS doesn't ship
- Configuring Oracle Data Guard in ways not supported by standard RDS
- Running Oracle Enterprise Manager agents on the host

SQL Server-specific:
- Installing SSIS, SSRS, or SSAS — these require OS-level installation
- Running CLR assemblies that depend on OS-level libraries
- Custom backup solutions using third-party tools (Commvault, Veeam)

General:
- Legacy enterprise apps (SAP, PeopleSoft) that require specific OS kernel parameters or custom shared libraries
- Compliance regimes (financial, healthcare) mandating OS hardening, antivirus agents, or audit daemons on the DB server
- Custom authentication plugins needing OS-level installation (e.g. Kerberos configurations beyond what RDS exposes)
- Vendor-supplied database software that bundles stored procedures with native OS dependencies

**The common thread:** a third-party or legacy application dictates specific OS or DB-engine-level requirements that standard RDS can't accommodate.

**Exam triggers:**
- *"need to install custom software on the database host"* → RDS Custom
- *"need SSH/RDP access to the database instance"* → RDS Custom
- *"Oracle or SQL Server with OS-level customization"* → RDS Custom
- *"need OS access but still want managed backups"* → RDS Custom (not DB on EC2)

### Aurora

Aurora is AWS's re-engineered version of MySQL and PostgreSQL. Same SQL, same drivers, same client libraries — your app doesn't know the difference. The key architectural change is a **shared distributed storage layer** that decouples compute from storage.

**Shared storage — why Aurora is fundamentally different:**

In standard RDS, each instance has its own EBS volume and replication copies data between volumes. Aurora flips this: all instances (writer + replicas) share a single storage layer.

```
Standard RDS:
Primary (EBS vol) ──replicates──→ Replica (its own EBS vol)

Aurora:
Writer instance ──┐
Read Replica 1 ───┤── Shared storage layer (6 copies, 3 AZs)
Read Replica 2 ───┘
```

This shared storage is why Aurora's other features work:

- **Near-zero replica lag** — replicas read from the same storage, no data copying between instances
- **Fast failover** — a promoted replica already has access to all data, nothing to catch up on
- **Adding replicas is cheap** — no data duplication, just a new compute instance pointing at the same storage
- **Auto-scaling storage** — grows in 10 GB increments up to 128 TB, no pre-provisioning
- **6 copies across 3 AZs** — the storage layer handles this transparently; tolerates loss of 2 copies for writes, 3 for reads

**Why Aurora over standard RDS MySQL/PostgreSQL:**

- **5x throughput over MySQL, 3x over PostgreSQL** (AWS's claim) — due to the custom storage engine
- **Faster failover** — typically under 30 seconds vs 1–2 minutes for standard RDS Multi-AZ
- **Up to 15 read replicas** (vs 5 for standard RDS) with sub-10ms replica lag

**Aurora Serverless:**

Aurora Serverless scales compute capacity up and down automatically — including scaling to zero when idle. You pay per ACU-second (Aurora Capacity Unit) instead of provisioning a fixed instance size.

| | Aurora Provisioned | Aurora Serverless |
| - | ------------------ | ----------------- |
| Compute | Fixed instance size you choose | Auto-scales based on demand |
| Scale to zero | No | Yes (v2 scales to minimum, v1 can fully pause) |
| Cost model | Pay for instance 24/7 | Pay for what you use |
| Use case | Steady, predictable workloads | Intermittent, unpredictable, or dev/test |

**Writer topology:**

By default Aurora has one writer instance (the primary) that handles all reads and writes. Read replicas handle read traffic only. If the primary fails, Aurora promotes a replica — typically under 30 seconds.

Aurora also supports **Multi-Master** (Multi-Writer), where multiple instances can all accept writes:

| | Single-Master (default) | Multi-Master |
| - | ----------------------- | ------------ |
| Writers | 1 | 2+ |
| Failover | Promote a replica (~30s) | Instant — other writer already active |
| Use case | Most workloads | Zero-downtime write requirement |
| Complexity | Simple | App must handle write conflicts |

Assume single-master for the exam unless the question specifically mentions continuous write availability during failover.

**Cluster endpoints:**

Aurora gives you dedicated DNS endpoints that abstract away which instance is which:

```
Your app
├── writes → Writer Endpoint (always points to the primary)
└── reads  → Reader Endpoint (load-balances across all read replicas)
```

| Endpoint | Points to | Load balanced? |
| -------- | --------- | -------------- |
| Writer Endpoint | The current primary instance | No — single target |
| Reader Endpoint | All read replicas | Yes — connection-level load balancing |
| Instance Endpoint | One specific instance by name | No — direct access |

**Why this matters:**

- Your app never hardcodes an instance address — if the primary fails and a replica is promoted, the **Writer Endpoint DNS flips automatically**. No app changes needed.
- The **Reader Endpoint distributes read traffic** across replicas without you building load-balancing logic. Add a replica, it's automatically included.
- **Instance Endpoints** exist for edge cases — e.g. directing a heavy analytics query to a specific larger replica.

With standard RDS Read Replicas, you get separate endpoints per replica and have to manage load balancing yourself (or use Route 53). Aurora handles this natively.

**Custom Endpoints:**

The Reader Endpoint load-balances across *all* replicas equally. This is a problem when your replicas aren't all the same size or purpose — an expensive analytics query hitting a small production replica can hurt live service.

Custom Endpoints let you group specific replicas and route traffic to just that subset:

```
App (production reads) → Custom Endpoint A → Replica 1 (r5.2xlarge)
                                            → Replica 2 (r5.2xlarge)

Analytics team         → Custom Endpoint B → Replica 3 (r5.8xlarge)
```

Real-world scenario: someone runs an expensive reporting query on the production database — it saturates CPU on the replica and degrades live customer traffic. With Custom Endpoints, the analytics team hits a dedicated replica and production reads are isolated.

Once you create Custom Endpoints, avoid using the default Reader Endpoint — it still includes all replicas, which defeats the purpose of your segmentation.

**Exam trigger:** *"isolate reporting/analytics queries from production read traffic"* → Aurora Custom Endpoints.

**Global Aurora:**

Aurora Global Database spans multiple AWS regions — one primary region handles writes, up to 5 secondary regions get read-only replicas.

```
Primary region (us-east-1) ── writes here
├── Secondary region (eu-west-1) ── read-only, <1s replication lag
├── Secondary region (ap-southeast-1) ── read-only, <1s replication lag
└── ...up to 5 secondary regions
```

**Two use cases:**

1. **Disaster recovery** — if the primary region goes down entirely, promote a secondary region to take over. Promotion typically completes in **under 1 minute** with an RPO of **under 1 second**.
2. **Global low-latency reads** — users in Europe read from a European replica instead of crossing the Atlantic to us-east-1.

**Key detail:** replication is under 1 second — much faster than cross-region RDS Read Replicas which can lag by minutes.

**Exam triggers:**
- *"cross-region disaster recovery with RPO under 1 second"* → Aurora Global Database
- *"low-latency reads for users in multiple regions"* → Aurora Global Database
- *"promote a database in another region if the primary region fails"* → Aurora Global Database

**Aurora Cloning:**

Aurora supports **copy-on-write cloning** — an Aurora-only feature not available on standard RDS. The clone shares the same underlying storage as the original; only when data is modified does it allocate new storage for the changed pages.

| | Snapshot restore | Aurora Clone |
| - | ---------------- | ------------ |
| Speed | Minutes to hours (copies all data) | Seconds (copy-on-write) |
| Storage cost | Full copy from the start | Only pays for changed data |
| Available on | All RDS engines | Aurora only |
| Use case | DR, cross-region, encryption changes | Quick dev/test copies of production |

Real-world scenario: you need a copy of your 2 TB production database to test a migration. A snapshot restore takes an hour and costs 2 TB of storage immediately. An Aurora clone is ready in seconds and costs almost nothing until you start making changes.

**Exam trigger:** *"create a copy of a production database quickly for testing"* → Aurora clone.

**Common mistake: clone vs backup for long-term retention:**

A clone is a **live running database** — it costs compute, and it's not a backup strategy. Don't confuse it with snapshots.

| | Aurora Clone | Manual Snapshot | AWS Backup |
| - | ------------ | --------------- | ---------- |
| Purpose | Quick dev/test copy | Point-in-time backup | Centralized backup management |
| Compute cost | Yes — running instance | No — just storage | No — just storage |
| Retention | Lives until you delete the instance | Indefinite | Policy-based (days to years) |
| Cross-region | No | Yes (copy snapshot) | Yes (built-in) |
| Cross-account | No | Yes (share snapshot) | Yes (built-in) |

- *"long-term backup retention"* → manual snapshots or **AWS Backup**
- *"centralized backup policy across multiple databases"* → **AWS Backup**
- *"quick copy for testing"* → Aurora clone
- *"retain backups beyond 35 days"* → manual snapshots (automated backups max out at 35 days)

**When to use standard RDS over Aurora:**

- Cost-sensitive workloads — Aurora is ~20% more expensive than standard RDS
- Portability — avoiding Aurora-specific lock-in if you might leave AWS
- Small databases where the HA/performance benefits aren't justified
- Engines Aurora doesn't support (Oracle, SQL Server, MariaDB)

**Exam triggers:**
- *"MySQL or PostgreSQL compatible with high availability"* → Aurora
- *"database that scales storage automatically"* → Aurora
- *"minimize database cost for infrequent or unpredictable workloads"* → Aurora Serverless
- *"need more than 5 read replicas"* → Aurora (supports up to 15)
- *"fastest failover for a relational database on AWS"* → Aurora
- *"dev/test database that should pause when not in use"* → Aurora Serverless

### Read Replica Network Costs

| Replication path | Data transfer cost |
| ---------------- | ------------------ |
| Same AZ | Free |
| Cross-AZ (same region) | Charged |
| Cross-region | Charged (higher — inter-region data transfer rates) |

**Exam trigger:** *"reduce costs of read replicas"* → keep replicas in the same AZ as the primary (but this reduces availability). Cross-region replicas are the most expensive but needed for DR.

### RDS Storage Auto Scaling

RDS can automatically increase storage when it detects you're running low — no downtime, no manual intervention. You set a **Maximum Storage Threshold** and RDS scales within that limit.

Triggers when:
- Free storage falls below 10% of allocated storage
- Low-storage condition lasts at least 5 minutes
- At least 6 hours since the last storage modification

**Exam trigger:** *"database running out of storage"* or *"automatically increase storage without downtime"* → RDS Storage Auto Scaling.

## ElastiCache

Managed in-memory cache service. Sits between your app and the database, caching frequently accessed data in memory to reduce load on RDS.

```
App → ElastiCache (cache hit? return immediately)
    → RDS (cache miss? query DB, store result in cache)
```

**Two engines:**

| | Redis | Memcached |
| - | ----- | --------- |
| Data structures | Strings, lists, sets, sorted sets, hashes | Simple key-value only |
| Persistence | Yes — survives restarts | No — pure cache |
| Replication | Yes — read replicas + Multi-AZ failover | No |
| Backup/restore | Yes | No |
| Multi-threaded | No (single-threaded) | Yes |
| Use case | Sessions, leaderboards, pub/sub, anything needing durability | Simple caching at scale, disposable data |

**Redis is the default choice** unless you specifically need multi-threaded performance for simple key-value caching.

**Memcached — when and why:**

Memcached is the simplest possible cache — a distributed hash table. You put key-value pairs in, you get them out. That's it.

What Memcached has over Redis:
- **Multi-threaded** — uses all CPU cores, higher throughput per node for simple operations
- **Horizontal scaling** — add/remove nodes and data is redistributed (sharding built-in)

What Memcached lacks:
- No persistence — node dies, data is gone
- No replication — no replicas, no Multi-AZ failover
- No backup/restore
- No data structures — just strings, no lists/sets/sorted sets/hashes/pub-sub
- No transactions

When Memcached makes sense: caching simple objects (HTML fragments, API responses, DB query results) where data loss is acceptable and you want the simplest possible layer with raw multi-threaded throughput.

**Exam shortcut:** any mention of persistence, replication, failover, data structures, backups, or Multi-AZ → **Redis**. "Simple caching, data loss acceptable, multi-threaded" → **Memcached**.

**Redis data durability:**

Redis has two persistence mechanisms — RDB snapshots and AOF:

| | RDB Snapshots | AOF (Append Only File) |
| - | ------------- | ---------------------- |
| How | Point-in-time dump of entire dataset | Logs every write operation to disk |
| Data loss on crash | Everything since last snapshot | Minimal (~1 second) |
| Restart speed | Fast (load one file) | Slower (replay all operations) |
| File size | Smaller (compressed) | Larger (full operation log) |

In ElastiCache Redis, AWS exposes both:
- **Backups** — automated daily snapshots (like RDB)
- **AOF** — available in Multi-AZ replication groups for minimal data loss on failover

For the exam: *"minimize data loss in a Redis cache"* → Multi-AZ with AOF. *"cache that survives restarts"* → Redis with backups enabled. Memcached has no persistence at all.

**Valkey:** an open-source fork of Redis created by the Linux Foundation in 2024 after Redis changed to a restrictive license. API-compatible — same commands, same protocol. ElastiCache now offers Valkey as an engine alongside Redis and Memcached. For exam purposes, treat it as Redis.

**Common architecture patterns:**

**1. DB cache — reduce RDS load:**

App queries ElastiCache first. On a cache miss, query RDS, then write the result to the cache. Subsequent reads are served from memory (microseconds vs milliseconds).

**2. Session store — make your app stateless:**

Instead of sticky sessions on an ALB, store session data in ElastiCache. Any instance behind the load balancer can serve any request — just look up the session by ID.

```
User → ALB → any EC2 instance → ElastiCache (session lookup)
```

This is the proper fix for the sticky sessions problem covered in the ELB section.

**3. Leaderboards / sorted sets (Redis only):**

Redis sorted sets give you ranked data natively — e.g. a gaming leaderboard. `ZADD` to insert scores, `ZRANGE` to get the top N. No need to query and sort in your database.

**Caching patterns:**

**Lazy Loading (Cache-Aside) — the most common pattern:**

Your app manages the cache directly — check cache first, fall back to DB on miss, write result back to cache:

```
Read request
├── Cache hit? → return cached data (fast)
└── Cache miss? → query DB → store in cache → return data
```

| Pros | Cons |
| ---- | ---- |
| Only requested data gets cached — no wasted memory | First request is always slow (3 round trips: cache miss → DB → cache write) |
| Cache failure isn't fatal — app falls back to DB | Stale data — DB updates don't update the cache |
| Simple to implement | |

**Write-Through — solves staleness:**

Every DB write also updates the cache immediately. Data in the cache is always fresh.

| Pros | Cons |
| ---- | ---- |
| Cache is never stale | Higher write latency (write to DB + cache on every write) |
| | Caches data that might never be read — wastes memory |

**TTL (Time to Live) — controls the staleness window:**

Data expires after N seconds. On next request, cache miss triggers a fresh read from the DB. Simple to implement, and limits how stale data can get.

**The production pattern — combine all three:**

Lazy Loading + TTL for reads (cache on first access, expire after N seconds) and Write-Through for writes (update cache immediately on DB writes). Best of both worlds — fresh data on writes, efficient caching on reads, TTL as a safety net.

**Exam triggers:**
- *"reduce read load on the database"* → ElastiCache
- *"store session data for a stateless application"* → ElastiCache (Redis)
- *"in-memory data store with replication and failover"* → ElastiCache Redis
- *"simple caching layer, data is disposable"* → ElastiCache Memcached
- *"users are logged out when routed to a different instance"* → store sessions in ElastiCache instead of using sticky sessions

### ElastiCache Security

**Network:**
- **VPC-only** — ElastiCache clusters are never publicly accessible (same as RDS Proxy). Must be accessed from within the VPC.
- **Security groups** — control which resources can connect to the cache port (default Redis: 6379, Memcached: 11211)

**Authentication:**

| Method | Engine | How it works |
| ------ | ------ | ------------ |
| Redis AUTH | Redis | A token/password set on the cluster; clients must provide it on connect |
| IAM authentication | Redis 7+ | Use IAM users/roles instead of passwords — short-lived tokens |
| None | Memcached | No native auth — rely entirely on security groups |

**Encryption:**
- **In-transit (TLS)** — encrypts data between your app and the cache. Must be enabled at creation time.
- **At-rest** — encrypts data on disk using KMS. Must be enabled at creation time.

**Key detail:** Memcached has no authentication mechanism — security groups are your only line of defence. This is another reason Redis is preferred for anything sensitive.

**Exam triggers:**
- *"secure cache access without passwords"* → IAM authentication (Redis 7+)
- *"encrypt data in the cache"* → at-rest encryption with KMS
- *"encrypt traffic between app and cache"* → in-transit TLS
- *"cache must not be accessible from the internet"* → it never is — ElastiCache is VPC-only

### ElastiCache Redis Replication

Redis replication in ElastiCache follows a similar pattern to RDS — a primary node handles writes, replica nodes handle reads and provide failover.

```
Primary (read/write) → replicates → Replica 1 (read-only)
                     → replicates → Replica 2 (read-only)
```

**Cluster Mode Disabled (single shard):**
- One primary + up to 5 replicas
- All nodes have the full dataset
- Multi-AZ failover — if the primary dies, a replica is promoted automatically
- Use case: dataset fits in one node's memory, you need read scaling and HA

**Cluster Mode Enabled (multiple shards):**
- Data is **sharded** across multiple primary nodes
- Each shard has its own primary + replicas
- Scales both reads **and writes** — each shard handles writes for its portion of the data
- Use case: dataset is too large for one node, or you need write scaling

```
Cluster Mode Enabled:
Shard 1: Primary → Replica
Shard 2: Primary → Replica
Shard 3: Primary → Replica
(each shard holds a portion of the keys)
```

**Exam triggers:**
- *"Redis cache needs high availability"* → Multi-AZ with replicas
- *"scale Redis read throughput"* → add read replicas
- *"Redis dataset is too large for a single node"* → Cluster Mode Enabled (sharding)
- *"scale Redis write throughput"* → Cluster Mode Enabled (writes distributed across shards)

## Route 53

AWS's DNS service. Named after DNS port 53. It does three things: **domain registration**, **DNS routing**, and **health checking**.

### Authoritative vs Non-Authoritative DNS

When you type `example.com` in your browser, a chain of DNS servers work together to resolve it:

```
Browser → Recursive resolver (non-authoritative) → Root NS → TLD NS → Authoritative NS → IP address
```

**Non-authoritative (recursive resolver):**
- Your ISP's DNS server or a public resolver like `8.8.8.8` (Google) or `1.1.1.1` (Cloudflare)
- Doesn't own any DNS records — it asks other servers on your behalf and caches the answers
- Returns cached responses — may be stale until TTL expires
- You **don't control** this server

**Authoritative:**
- The server that **owns** the DNS records for a domain and gives the definitive answer
- When someone asks "what IP is `example.com`?", this server responds with the actual record
- **Route 53 is an authoritative DNS service** — you create hosted zones and manage records, and Route 53 answers queries authoritatively
- You **do control** this server (your records, your TTLs, your routing policies)

**The lookup chain:**

```
1. Browser asks recursive resolver: "what is example.com?"
2. Resolver asks root nameserver: "who handles .com?"
3. Root NS replies: "go ask the .com TLD server"
4. Resolver asks .com TLD: "who handles example.com?"
5. TLD replies: "go ask ns-123.awsdns-45.com" (Route 53)
6. Resolver asks Route 53: "what is example.com?"
7. Route 53 replies: "54.23.100.12" ← authoritative answer
8. Resolver caches it and returns to browser
```

**Why this matters for the exam:** Route 53 is authoritative — you can update a record and it takes effect immediately on Route 53's side. But clients may still see the old value until their resolver's cached TTL expires. If a question asks about DNS propagation delays, it's the caching at recursive resolvers, not Route 53 being slow.

### DNS Record Types

| Record | What it does | Example |
| ------ | ------------ | ------- |
| A | Maps domain to IPv4 address | `example.com` → `54.23.100.12` |
| AAAA | Maps domain to IPv6 address | `example.com` → `2600:1f18::1` |
| CNAME | Maps domain to another domain | `www.example.com` → `example.com` |
| NS | Nameserver records — which servers are authoritative for this zone | `example.com` → `ns-123.awsdns-45.com` |
| Alias | AWS-specific — maps domain to an AWS resource | `example.com` → `my-alb-123.us-east-1.elb.amazonaws.com` |

**CNAME vs Alias — the most important distinction:**

| | CNAME | Alias |
| - | ----- | ----- |
| Works at zone apex (naked domain)? | No — `example.com` can't be a CNAME | Yes — `example.com` can be an Alias |
| Cost | Charged per query | Free for queries to AWS resources |
| Points to | Any domain name | AWS resources only (ALB, CloudFront, S3, etc.) |
| AWS-specific? | No — standard DNS | Yes — Route 53 only |

**Zone apex** = the naked domain (`example.com` without `www`). DNS standard says the apex can't be a CNAME. AWS invented Alias records to solve this — they work like CNAMEs but are allowed at the apex.

**Exam triggers:**
- *"map the root domain to an ALB"* → Alias record (CNAME can't do zone apex)
- *"reduce DNS query costs"* → Alias (free for AWS resources)
- *"point example.com to a CloudFront distribution"* → Alias record

**Alias only works with Route 53:** Alias is not standard DNS — it's AWS-proprietary. If you use a third-party DNS provider (e.g. Cloudflare, GoDaddy) as your authoritative DNS, you can't create Alias records. Cloudflare solves the zone apex problem with **CNAME flattening** — their own equivalent that resolves the CNAME at the edge and returns an A record to the client. For the exam, assume Route 53 is the DNS provider.

### Public and Private Hosted Zones

A **Hosted Zone** is a container for DNS records for a domain. Two types:

| | Public Hosted Zone | Private Hosted Zone |
| - | ------------------ | ------------------- |
| Resolvable from | The internet | Within your VPC(s) only |
| Use case | Public websites, APIs | Internal service discovery |
| Example | `example.com` → `54.23.100.12` | `db.internal.company.com` → `10.0.1.50` |

**Public Hosted Zone:**

When you create a Public Hosted Zone, Route 53 gives you 4 NS (nameserver) records. These are what make Route 53 authoritative for your domain.

**Using Route 53 with a third-party registrar (GoDaddy, OnlyDomains, etc.):**

The domain registrar (where you buy the domain) and the DNS service (where you host the records) are separate things. You can buy a domain from GoDaddy but use Route 53 as your DNS:

1. Buy `example.com` on GoDaddy
2. Create a Public Hosted Zone in Route 53 — AWS gives you 4 NS records
3. Go to GoDaddy and **replace the default nameservers** with Route 53's NS records
4. Now Route 53 is authoritative for `example.com`, even though GoDaddy owns the registration

```
GoDaddy (registrar) → "who handles example.com?" → Route 53's nameservers
Route 53 (DNS)      → "example.com is 54.23.100.12"
```

Why do this? Route 53 gives you Alias records, routing policies, health checks, failover — a basic registrar's DNS can't do any of that.

**Exam trigger:** *"purchased domain from a third-party registrar, want to use Route 53 for DNS"* → create a Public Hosted Zone in Route 53, update the registrar's NS records to point to Route 53.

**Private Hosted Zone:**

A Private Hosted Zone resolves DNS names **only within your VPC(s)**. Queries from the internet get nothing.

```
Public internet → api.example.com → Public Hosted Zone → 54.23.100.12 ✅
Inside VPC      → db.internal.example.com → Private Hosted Zone → 10.0.1.50 ✅
Public internet → db.internal.example.com → ❌ doesn't resolve
```

**Use case:** internal service discovery. Microservices talk to each other using friendly DNS names instead of hardcoded IPs.

Real-world examples:
- `db.internal.company.com` → RDS private IP. Migrate to a new DB instance → update the record, no app changes.
- `cache.internal.company.com` → ElastiCache endpoint
- `auth-service.internal.company.com` → internal ALB for an auth microservice

**Key details:**
- Can be shared across multiple VPCs (even cross-account)
- DNS names are completely private — invisible outside your VPCs
- Often uses `.internal` or a subdomain like `internal.example.com`

**Exam triggers:**
- *"resolve DNS names only within the VPC"* → Private Hosted Zone
- *"internal service discovery without exposing to internet"* → Private Hosted Zone

### Routing Policies

Route 53 doesn't just resolve a domain to one IP — it can decide **which** IP to return based on different strategies.

**Simple:**
- Returns one or more IPs. If multiple, the client picks one at random.
- No health checks.
- Use case: single resource, no clever routing needed.

**Weighted:**
- Split traffic by percentage across multiple resources. E.g. 70% to instance A, 30% to instance B.
- Weights don't have to add up to 100 — they're relative (70/30 is the same as 7/3).
- Use case: gradual deployments — send 10% of traffic to the new version, 90% to the old.

**Latency-based:**
- Routes users to the region with the lowest latency **from their location**.
- AWS measures real-time network latency between the user's resolver and each AWS region — this is not geographic distance. A user in Ireland might get `us-east-1` if the network path is faster than `eu-west-1` at that moment.
- If the lowest-latency region is unhealthy (health check enabled), Route 53 returns the next-best region.
- Use case: global application, minimize response time for users.

Real-world example — API deployed in 3 regions:

```
User in London    → Route 53 measures latency → eu-west-1 (50ms) ✅
User in Tokyo     → Route 53 measures latency → ap-northeast-1 (20ms) ✅
User in São Paulo → Route 53 measures latency → us-east-1 (80ms) ✅
                    (sa-east-1 might be closer geographically but slower network-wise)
```

**Latency vs Geolocation vs Geoproximity — the three that get confused:**

| | Latency | Geolocation | Geoproximity |
| - | ------- | ----------- | ------------ |
| Routes based on | Network latency (measured) | User's continent/country/state | Geographic distance + bias |
| Goal | Fastest response | Content localization, compliance | Fine-tuned geographic control |
| Can override? | No — always picks lowest latency | No — strict location match | Yes — bias shifts traffic toward/away |
| Example | "Send users to whichever region is fastest" | "French users must hit the French site" | "Shift 20% more traffic to eu-west-1 during migration" |
| No match? | Always matches (picks best latency) | Returns default record or nothing | Always matches (nearest resource) |

**The exam distinction:**
- "Fastest" / "lowest latency" / "best performance" → **Latency**
- "Users in France" / "compliance" / "localization" → **Geolocation**
- "Shift traffic" / "bias" / "gradually move traffic between regions" → **Geoproximity**

**Failover:**
- Active-passive setup. Route 53 returns the primary unless its health check fails, then returns the secondary.
- Requires health checks on the primary.
- Use case: disaster recovery — primary in `us-east-1`, standby in `eu-west-1`.

```
User → Route 53 → Primary (healthy?) → Yes → return primary IP
                                      → No  → return secondary IP
```

**Geolocation:**
- Routes based on **where the user is** (continent, country, or US state).
- If no match, returns a default record (if configured) or no answer.
- Use case: content localization (French users → French site), compliance (EU data stays in EU).

**Geoproximity:**
- Routes based on geographic distance between user and resource, with an adjustable **bias**.
- Increase the bias to attract more traffic to a resource; decrease to push traffic away.
- Bias ranges from -99 to +99. Positive = expand the region's catchment area. Negative = shrink it.
- Requires Route 53 **Traffic Flow** (visual editor for complex routing).

Real-world example — migrating from `us-east-1` to `eu-west-1`:

You're moving European customers off `us-east-1` to a new deployment in `eu-west-1`. Rather than a hard cutover, you gradually shift traffic:

```
Week 1: us-east-1 (bias: 0)   eu-west-1 (bias: +20)  → EU gets ~60% of European traffic
Week 2: us-east-1 (bias: 0)   eu-west-1 (bias: +50)  → EU gets ~85% of European traffic
Week 3: us-east-1 (bias: 0)   eu-west-1 (bias: +99)  → EU gets nearly all European traffic
```

Each week you increase `eu-west-1`'s bias, expanding its catchment area and pulling more users toward it. If something goes wrong, dial the bias back down — instant rollback without DNS record changes.

**Geoproximity vs Weighted:** both can shift traffic gradually, but Weighted splits by percentage globally. Geoproximity splits by **geography** — you're moving users in a specific part of the world, not a random 10% of all users.

**Multi-value answer:**
- Returns up to 8 healthy IPs. Client picks one.
- Like Simple, but with health checks — unhealthy IPs are excluded from the response.
- Use case: simple client-side load balancing with health checking. **Not a replacement for ELB** — but better than Simple routing.

**Quick reference:**

| Policy | Decides based on | Health checks? | Use case |
| ------ | ---------------- | -------------- | -------- |
| Simple | Nothing — returns all records | No | Single resource |
| Weighted | Assigned weights | Optional | Gradual deployments, A/B testing |
| Latency | Network latency to regions | Optional | Global apps, minimize latency |
| Failover | Health of primary | Yes (required) | Active-passive DR |
| Geolocation | User's location | Optional | Localization, compliance |
| Geoproximity | Geographic distance + bias | Optional | Fine-tuned geo routing |
| Multi-value | Health of each target | Yes | Simple LB with health checks |

**Exam triggers:**
- *"send 10% of traffic to a new version"* → Weighted
- *"route users to the closest region"* → Latency-based (not Geolocation — latency ≠ geography)
- *"route French users to the French site"* → Geolocation
- *"active-passive disaster recovery"* → Failover
- *"shift traffic gradually from one region to another"* → Geoproximity with bias
- *"return multiple IPs but exclude unhealthy ones"* → Multi-value answer

### TTL (Time to Live)

TTL tells recursive resolvers how long to cache a DNS response before asking Route 53 again. Set per record, in seconds.

| TTL | Resolvers cache for | Trade-off |
| --- | ------------------- | --------- |
| High (e.g. 86400 = 24hrs) | A long time | Fewer DNS queries (cheaper), but changes take hours to propagate |
| Low (e.g. 60 = 1 min) | Briefly | Changes propagate fast, but more DNS queries (higher cost, more load) |

**Pre-migration TTL pattern (common exam trap):**

People make a DNS change (e.g. point `api.example.com` to a new server) and expect it to take effect immediately. But if the TTL was 24 hours, clients worldwide have the old IP cached and won't ask Route 53 again for up to 24 hours. Route 53 isn't slow — the recursive resolvers are serving stale cached answers.

The correct migration pattern:

1. TTL is currently 86400 (24hrs)
2. **Lower TTL to 60s** — then **wait 24hrs** for all existing caches to expire and pick up the new short TTL
3. Make the DNS change (point to new IP)
4. Within ~60s, everyone has the new IP — because resolvers are now re-checking every 60s
5. **Raise TTL back to 86400** — reduce query costs now that the change is stable

The critical step people miss is **step 2 — the wait**. You must wait for the old high TTL to expire before making the change, otherwise clients still have the old IP cached for hours regardless of the new TTL.

**Exam trap:** a question describes a migration where "some users are still reaching the old server hours later". The answer is that TTL wasn't lowered before the change, not that Route 53 is slow or broken.

**Alias records:** TTL is set automatically by Route 53 to match the AWS resource — you can't override it.

**Exam triggers:**
- *"users are still hitting the old server after a DNS change"* → TTL is too high, or wasn't lowered before the change
- *"reduce DNS query costs"* → increase TTL (fewer lookups)
- *"DNS changes must propagate quickly"* → low TTL

### Route 53 Health Checks

Route 53 can monitor the health of your resources and stop returning unhealthy IPs in DNS responses. This is how routing policies like Failover and Multi-value know when to stop sending traffic somewhere.

**Three types of health checks:**

| Type | What it monitors | Use case |
| ---- | ---------------- | -------- |
| Endpoint | Hits a URL or IP directly (HTTP, HTTPS, or TCP) | Monitor a web server, API, or ALB |
| Calculated | Combines results of other health checks (AND/OR logic) | "Healthy if 2 out of 3 child checks pass" |
| CloudWatch Alarm | Monitors a CloudWatch Alarm state | Monitor anything CloudWatch tracks (DynamoDB throttling, custom metrics, etc.) |

**Endpoint health checks — how they work:**

- Route 53 sends requests from ~15 health checkers globally every 30s (or 10s for fast checks — costs more)
- Resource is healthy if ≥18% of checkers report it healthy
- For HTTP/HTTPS checks, a 2xx or 3xx response = healthy
- Can optionally search the response body for a string (first 5,120 bytes)

**Key detail:** health checkers are **public Route 53 IPs**. They must be able to reach your endpoint. If your resource is in a private subnet with no public access, endpoint health checks won't work — use a **CloudWatch Alarm** health check instead.

```
Public resource → Endpoint health check (Route 53 hits it directly) ✅
Private resource → Endpoint health check ❌ (can't reach it)
Private resource → CloudWatch Alarm → Route 53 health check ✅
```

**Calculated health checks:**

Combine up to 256 child health checks with OR, AND, or "at least N of M must pass". Use case: your app has multiple components (web server, API, database) — the parent check is healthy only if all critical children are healthy.

**Health checks + routing policies:**

- **Failover** — health check is **required** on the primary. If it fails, Route 53 returns the secondary.
- **Weighted / Latency / Geolocation / Multi-value** — health checks are optional but recommended. Unhealthy records are excluded from responses.
- **Simple** — no health checks. Route 53 returns all records blindly.

**Exam triggers:**
- *"automatically failover DNS to a standby region"* → Failover routing + health check on primary
- *"health check a resource in a private subnet"* → CloudWatch Alarm health check (not endpoint)

**Route 53 health checks vs your `/health` endpoint:**

These are different things that work together:

- **Your `/health` endpoint** — code in your app that checks dependencies (DB connected? Redis up? Disk space OK?) and returns 200 if healthy, 500 if not. You define what "healthy" means.
- **Route 53 health check** — hits that URL from 15+ global locations every 30s. If it gets a non-2xx/3xx, it marks the resource unhealthy and removes it from DNS responses.

```
Route 53 health checker → GET /health → 200 → healthy, keep in DNS
                                      → 500 → unhealthy, remove from DNS
```

**Why `/health` matters:** without it, Route 53 hits `/` — your homepage might return 200 even if the database is down because static content still renders. Route 53 thinks everything is fine while users see errors. A proper `/health` endpoint checks all critical dependencies and returns 500 if anything is broken.

**CloudWatch Alarm health checks — monitoring private resources:**

Route 53 endpoint health checks come from public IPs — they can't reach resources in private subnets. CloudWatch Alarm health checks solve this by watching a CloudWatch metric instead of hitting a URL directly.

```
Route 53 health checker → Private RDS instance → ❌ blocked

Instead:
Private RDS → CloudWatch metric (CPU, connections, replica lag)
           → CloudWatch Alarm (threshold breached?)
           → Route 53 health check watches alarm state
           → ALARM = unhealthy → remove from DNS
```

Real-world example — Failover routing with private databases:

1. Primary DB in `us-east-1` (private subnet), standby in `eu-west-1` (private subnet)
2. CloudWatch monitors RDS metrics (connections, replica lag, CPU)
3. CloudWatch Alarm fires if metrics cross a threshold
4. Route 53 health check monitors that alarm
5. Alarm = ALARM → Route 53 marks primary unhealthy → DNS flips to standby

**Also useful for non-HTTP resources:** anything CloudWatch can track — DynamoDB throttling, Lambda error rates, SQS queue depth, custom app metrics. None of these have URLs to hit, but they all emit CloudWatch metrics.

**Exam trigger:** *"monitor the health of a resource that has no public endpoint"* → CloudWatch Alarm health check.

**Route 53 health checks vs ELB health checks — why you need both:**

They operate at different levels:

```
User → Route 53 (which region?) → ALB (which instance?) → EC2
       DNS health check              ELB health check
       "is us-east-1 alive?"         "is instance #3 alive?"
       Checks every 30s              Checks every request
       Cached by TTL                 Real-time
```

| | Route 53 health check | ELB health check |
| - | --------------------- | ---------------- |
| Decides | Which region/endpoint to route to | Which instance receives the request |
| Granularity | Endpoint level (ALB, IP) | Instance level |
| Speed | Every 30s, cached by TTL | Real-time, every request |
| Scope | Cross-region failover | Within a single load balancer |

**Without ELB health checks:** Route 53 points users to a region, but if one instance behind the ALB dies, Route 53 doesn't know — it only sees the ALB endpoint. Users get errors until ELB removes the bad instance.

**Without Route 53 health checks:** if an entire region goes down, users still get routed there (DNS cached) with no failover to another region.

You need both layers: Route 53 for **region-level** failover, ELB for **instance-level** failover.

### Route 53 Resolver (Hybrid DNS)

When you have a **hybrid environment** (on-premises + AWS connected via VPN or Direct Connect), DNS doesn't work across the boundary by default. On-prem servers can't resolve AWS private hosted zone names, and EC2 instances can't resolve on-prem DNS names.

Route 53 Resolver endpoints fix this:

**Inbound endpoint** — on-prem servers forward DNS queries to AWS and resolve private hosted zone names:

```
On-prem server → "what is db.internal.company.com?"
              → VPN/Direct Connect → Route 53 Resolver inbound endpoint
              → Private Hosted Zone → 10.0.1.50 ✅
```

**Outbound endpoint** — EC2 instances forward DNS queries to on-prem DNS servers:

```
EC2 instance → "what is legacy-app.corp.local?"
            → Route 53 Resolver outbound endpoint → VPN/Direct Connect
            → On-prem DNS server → 192.168.1.100 ✅
```

**Forwarding rules** control which domains get forwarded where — e.g. "anything ending in `.corp.local` goes to the on-prem DNS server at `192.168.1.10`".

**Exam triggers:**
- *"on-premises servers need to resolve AWS private DNS names"* → Route 53 Resolver inbound endpoint
- *"EC2 instances need to resolve on-premises DNS names"* → Route 53 Resolver outbound endpoint
- *"hybrid DNS resolution across VPN"* → Route 53 Resolver endpoints
- *"stop sending traffic to an unhealthy instance via DNS"* → health check + any routing policy that supports it
- *"check is healthy only if multiple services are healthy"* → Calculated health check

## Elastic Beanstalk

A PaaS (Platform as a Service) — you upload your code and AWS handles everything else: provisioning EC2 instances, ALB, ASG, security groups, CloudWatch monitoring, and deployments.

**Think of it as:** "I don't want to set up infrastructure, just run my app."

Under the hood it creates real AWS resources (EC2, ALB, ASG, etc.) that you can still see and modify — it's not a black box like Lambda. It's a managed wrapper around the infrastructure you'd otherwise configure manually.

**Key properties:**

- **Supported platforms:** Java, .NET, Node.js, Python, Ruby, Go, Docker
- **Free service** — you only pay for the underlying resources it creates
- **Full control** — you can still access and tweak the underlying resources (EC2 instances, ALB settings, etc.)
- **Environment = a running version of your app** — includes the EC2 instances, load balancer, ASG, and configuration

**Deployment strategies:**

| Strategy | How it works | Downtime? | Rollback |
| -------- | ------------ | --------- | -------- |
| All at once | Deploy to all instances simultaneously | Yes | Redeploy old version |
| Rolling | Deploy in batches — some instances run old version during deploy | No | Redeploy old version |
| Rolling with additional batch | Like rolling, but launches new instances first so capacity isn't reduced | No | Redeploy old version |
| Immutable | Launches entirely new instances with new version, swaps when healthy | No | Terminate new instances (fast) |
| Blue/Green | Create a new environment, swap URLs | No | Swap URLs back (fast) |

**Immutable vs Blue/Green:** immutable replaces instances within the same environment. Blue/Green creates a completely separate environment (new ALB, new ASG, everything) and swaps the Route 53 or Elastic Beanstalk URL.

**Beanstalk vs doing it yourself:**

| | Elastic Beanstalk | Manual setup |
| - | ----------------- | ------------ |
| Time to deploy | Minutes | Hours to days |
| Infrastructure knowledge needed | Minimal | Significant |
| Customization | Good (can override most settings) | Full |
| Best for | Standard web apps, quick prototypes, small teams | Complex architectures, very specific requirements |

**Exam triggers:**
- *"deploy an application without managing infrastructure"* → Elastic Beanstalk
- *"developer wants to focus on code, not servers"* → Elastic Beanstalk
- *"deploy with zero downtime and fast rollback"* → Immutable or Blue/Green deployment
- *"PaaS on AWS"* → Elastic Beanstalk

**When NOT to use Beanstalk:**

- **Microservices** — designed for single-app environments. 10 microservices = 10 Beanstalk environments gets unwieldy. ECS with service discovery is a better fit.
- **Complex architectures** — fights you if your setup doesn't fit its model (non-HTTP workloads, custom networking, multi-service communication)
- **Fine-grained control** — it creates resources (ALB, ASG, security groups) behind the scenes. When something breaks, debugging is harder because you didn't set it up.
- **Latest runtimes** — platform versions can lag behind the latest Node.js, Python, etc.

**Exam shortcut:** "developer", "simple deployment", "minimal infrastructure" → **Beanstalk**. "Microservices", "complex architecture", "fine-grained control" → **ECS/Fargate** or plain EC2.

## Solution Architecture Examples

Reference architectures that appear frequently in exam questions. Each combines services covered in earlier sections.

### Classic Web App

The most common exam architecture — a scalable, highly available web application.

```
Users → Route 53 (DNS)
      → ALB (distributes traffic, terminates TLS)
      → ASG (auto-scales EC2 instances across AZs)
      → RDS Multi-AZ (primary + standby for failover)
      → ElastiCache (session store + DB cache)
```

**Why each component:**

| Component | Purpose |
| --------- | ------- |
| Route 53 | DNS resolution, Alias record pointing to ALB |
| ALB | Distributes traffic across instances, SSL termination, health checks |
| ASG | Scales instances based on demand, replaces unhealthy instances |
| RDS Multi-AZ | Database with automatic failover — no data loss |
| ElastiCache Redis | Session store (stateless app) + cache (reduce DB reads) |

**Key design decisions:**
- EC2 instances are **stateless** — sessions stored in ElastiCache, not on the instance
- Instances in **private subnets** — only ALB is in the public subnet
- RDS in **private subnets** — security group allows traffic only from the EC2 security group
- Multi-AZ for both RDS and ALB — survives an AZ failure

### Stateful Web App → Stateless Evolution

A common exam pattern — start with the problem (stateful), show the fix (stateless).

**The problem — stateful with sticky sessions:**

```
Users → Route 53 → ALB (sticky sessions enabled)
                  → EC2 instance A (holds User 1's session in memory)
                  → EC2 instance B (holds User 2's session in memory)
```

Session data (login state, shopping cart) lives in the instance's memory. ALB uses a cookie (`AWSALB`) to route a user to the same instance every time.

**What goes wrong:**
- Instance A dies → User 1's session is gone → logged out, cart emptied
- Can't scale freely — adding instances doesn't help users stuck on a busy instance
- Uneven load — some instances are overloaded while others are idle

**The fix — stateless with ElastiCache:**

```
Users → Route 53 → ALB (no sticky sessions)
                  → any EC2 instance → ElastiCache Redis (session store)
                                     → RDS (database)
```

Move session data to ElastiCache Redis. Now every instance can serve every user — just look up the session by ID. Instances are interchangeable.

| | Stateful (sticky sessions) | Stateless (ElastiCache) |
| - | -------------------------- | ----------------------- |
| Instance fails | Session lost | Session survives in Redis |
| Scaling | Limited — users are pinned | Free — any instance serves any user |
| Load distribution | Uneven | Even |
| Cost | Cheaper (no Redis) | Slightly more (Redis cluster) |

**Alternative session stores:** DynamoDB (serverless, auto-scales) or EFS (shared filesystem). ElastiCache Redis is the most common answer for the exam.

**Exam trigger:** *"users lose their session when an instance is terminated"* → move sessions to ElastiCache. Sticky sessions are the workaround, not the solution.

Exam trap — "which does NOT help with stateless design?":

| Helps with stateless? | Service | Why |
| --------------------- | ------- | --- |
| Yes | ElastiCache | Shared session store across all instances |
| Yes | DynamoDB | Shared state store, serverless |
| Yes | S3 | Shared file/object storage |
| Yes | EFS | Shared filesystem mounted across instances |
| **No** | **EBS** | **Locked to one instance, one AZ — the opposite of shared state** |

EBS is the trap answer. It's instance-specific storage — data on instance A's EBS volume is invisible to instance B.

**Same problem with file uploads:**

User uploads an image to instance A. Their next request goes to instance B (ALB routed it there). Instance B doesn't have the file — the image is gone.

```
Broken:   Upload → Instance A (file on local EBS) → next request → Instance B → file not found ❌

Fix (EFS): Upload → Instance A → EFS (shared drive) → Instance B reads from EFS ✅
Fix (S3):  Upload → Instance A → S3 (object storage) → Instance B reads from S3 ✅
```

| Solution | When to use |
| -------- | ----------- |
| EFS | App expects a filesystem (POSIX paths like `/uploads/photo.jpg`) — e.g. WordPress, legacy apps |
| S3 | App can use an API/SDK to store and retrieve objects — modern apps, cheaper at scale |

S3 is the more common answer for the exam unless the question specifically mentions a shared filesystem or POSIX compatibility.

**Exam triggers:**
- *"uploaded files are not available on all instances"* → EFS or S3
- *"shared filesystem across instances"* → EFS
- *"store user uploads durably and cheaply"* → S3

### Multi-Region Disaster Recovery

Active-passive setup for surviving an entire region failure.

```
Users → Route 53 (Failover routing policy)
      ├── Primary: us-east-1
      │   → ALB → ASG → Aurora (writer)
      └── Secondary: eu-west-1 (standby)
          → ALB → ASG → Aurora Global Database (read replica)
```

**How failover works:**

1. Route 53 health check monitors the primary region's ALB
2. Primary region fails → health check marks it unhealthy
3. Route 53 returns the secondary region's ALB IP
4. Promote Aurora Global Database secondary to writer
5. Secondary region is now the primary — users are served from `eu-west-1`

**Key design decisions:**
- Aurora Global Database for **<1 second replication lag** cross-region
- Route 53 Failover routing — **not** weighted or latency
- Health checks on the primary are **required** for automatic failover
- RTO depends on Aurora promotion time (~1 minute) + TTL propagation

### Golden AMI vs Docker Image

Two approaches to the same problem: **"how do I get my app running fast without bootstrapping at launch time?"**

**Golden AMI:**
- A pre-baked AMI with your OS, app, dependencies, and config already installed
- Launch an EC2 instance → it's ready in seconds, no user data scripts needed
- Update the AMI when the app changes → redeploy instances from the new AMI

**Docker image in a registry (ECR):**
- A pre-built container image with your app and dependencies
- Push to ECR → ECS/Fargate pulls and runs it in seconds
- Update the image → push a new tag → redeploy tasks

| | Golden AMI | Docker Image (ECR) |
| - | ---------- | ------------------ |
| Runs on | EC2 instances | ECS/Fargate containers |
| Contains | Full OS + app + dependencies | App + dependencies (no OS to manage) |
| Update cycle | Rebuild AMI → replace instances | Push new image → redeploy tasks |
| Portability | AWS-only | Runs anywhere Docker runs |
| OS patching | You patch the AMI and redeploy | AWS patches the host (Fargate) |
| Best for | Legacy apps, OS-level requirements, GPU workloads | Microservices, modern apps, teams using containers |

**The honest take:** if your app is containerised, a Docker image in ECR + Fargate is simpler — no AMIs to maintain, no OS to patch, no instance management. Golden AMIs make sense when you can't containerise (legacy apps, OS-level dependencies) or need EC2-specific features (instance store, GPU, custom kernel).

**Exam triggers:**
- *"reduce instance launch time in an ASG"* → Golden AMI (pre-baked)
- *"deploy containers without managing servers"* → Docker image + Fargate
- *"application takes too long to bootstrap from user data"* → Golden AMI

### Serverless

No servers to manage — fully event-driven, pay-per-request.

```
Users → Route 53
      → API Gateway (REST/HTTP API, throttling, auth)
      → Lambda (business logic)
      → DynamoDB (NoSQL database)
```

**Why each component:**

| Component | Purpose |
| --------- | ------- |
| API Gateway | HTTP endpoint, request validation, rate limiting, API keys |
| Lambda | Runs code on demand — scales to zero, scales to thousands |
| DynamoDB | Serverless NoSQL — no provisioning, auto-scales, single-digit ms latency |

**When to use this over the classic web app:**
- Unpredictable or spiky traffic (pay per request, not per hour)
- Simple CRUD APIs
- Event-driven workloads (S3 triggers, SQS consumers)
- Team doesn't want to manage any infrastructure

**When NOT to use this:**
- Long-running processes (Lambda max 15 minutes)
- Relational data that needs complex joins → use RDS instead of DynamoDB
- Consistent high-throughput workloads → EC2 is cheaper at steady load

### Static Website with CloudFront

Cheapest and fastest way to host a static website (HTML, CSS, JS, images).

```
Users → Route 53 (Alias to CloudFront)
      → CloudFront (CDN — caches content at edge locations worldwide)
      → S3 bucket (origin — stores the actual files)
```

**Why each component:**

| Component | Purpose |
| --------- | ------- |
| S3 | Stores static files — cheap, durable, no servers |
| CloudFront | CDN — caches content at 400+ edge locations, HTTPS, low latency globally |
| Route 53 | Alias record pointing to CloudFront distribution |

**Key details:**
- S3 bucket does **not** need to be public — CloudFront uses an **Origin Access Control (OAC)** to access S3 privately
- CloudFront handles HTTPS via ACM certificates — S3 alone only supports HTTP
- Cache invalidation when you deploy new content — or use versioned file names (`app.v2.js`)

**Exam triggers:**
- *"host a static website with low latency globally"* → S3 + CloudFront
- *"serve content from edge locations"* → CloudFront
- *"HTTPS for an S3 static website"* → CloudFront (S3 alone can't do HTTPS with a custom domain)
- *"restrict S3 access to CloudFront only"* → Origin Access Control (OAC)

## S3 (Simple Storage Service)

AWS's object storage — store and retrieve any amount of data, any time, from anywhere.

Useful tool: [AWS Policy Generator](https://awspolicygen.s3.amazonaws.com/policygen.html) — web UI for building S3 bucket policies, IAM policies, SQS/SNS policies, and VPC endpoint policies. Generates the JSON for you instead of writing it by hand.

### S3 Overview

**Key concepts:**

- **Buckets** — containers for objects. Globally unique name, created in a specific region.
- **Objects** — files stored in buckets. Each has a key (full path), value (file content), and metadata.
- **No filesystem** — looks like folders in the console, but it's flat key-value storage. `photos/2024/cat.jpg` is just a key, not a directory hierarchy.

**Key properties:**

- **Unlimited storage** — no capacity planning, no pre-provisioning
- **Object size** — 0 bytes to 5 TB per object. Files over 5 GB must use **multipart upload**.
- **Durability** — 99.999999999% (11 nines) — designed to not lose your data
- **Region-scoped** — data stays in the region you choose (compliance)

**Common use cases:**

- Static website hosting (HTML, CSS, JS, images)
- Backup and archive
- Data lake for analytics
- Application assets (user uploads, media files)
- Log storage

### S3 Versioning

Versioning keeps every version of every object in a bucket. Overwrite a file → S3 keeps the old version. Delete a file → S3 adds a **delete marker** instead of actually removing it.

**Why it matters:**

- **Rollback** — uploaded a bad `index.html`? Restore the previous version instantly. No backups needed.
- **Undelete** — accidentally deleted a file? Remove the delete marker and it's back.
- **Audit trail** — see every version of a file and when it was modified.

**How it works:**

```
Upload cat.jpg (version 1)
Upload cat.jpg (version 2) → version 1 still exists
Upload cat.jpg (version 3) → versions 1 and 2 still exist
Delete cat.jpg             → delete marker added, versions 1-3 still exist
Remove delete marker       → cat.jpg is back (version 3 is latest)
```

**Key details:**

- Versioning is enabled **per bucket** — once enabled, it can be suspended but not disabled
- Suspending versioning doesn't delete existing versions — they're preserved
- Every version is stored and billed — a 1 MB file overwritten 100 times = 100 MB of storage
- Use **lifecycle rules** to delete old versions after N days to control costs
- Any object uploaded before versioning was enabled has version ID `null`

**MFA Delete:** requires MFA to permanently delete a version or suspend versioning. Extra safety net against accidental or malicious deletion. Can only be enabled by the bucket owner using the CLI (not the console).

**Exam triggers:**
- *"protect against accidental deletion"* → versioning + MFA Delete
- *"roll back to a previous version of a file"* → S3 versioning
- *"storage costs are growing unexpectedly"* → check if versioning is keeping old versions; add lifecycle rules to expire them

### S3 Storage Classes

Storage classes sit on a cost-vs-access spectrum. The less frequently you access data, the cheaper the storage — but retrieval costs more.

| Class | Real-world example | Retrieval | Min duration |
| ----- | ------------------ | --------- | ------------ |
| Standard | Product images on an e-commerce site, app config files | Instant | None |
| Intelligent-Tiering | A data lake where some datasets are hot, others go cold unpredictably | Instant (auto-moves) | None |
| Standard-IA | Quarterly financial reports — accessed a few times a year but needed immediately | Instant, per-GB fee | 30 days |
| One Zone-IA | Thumbnail copies or transcoded video — easily re-generated if lost | Instant, cheaper | 30 days |
| Glacier Instant | Medical imaging (X-rays, MRIs) — archived but must load instantly when a doctor requests | Instant | 90 days |
| Glacier Flexible | Annual compliance audit data — "we might need it this week, hours is fine" | 1 min–12 hrs | 90 days |
| Glacier Deep Archive | 7-year regulatory tape replacement (tax records, legal holds) — accessed once a year at most | 12–48 hrs | 180 days |

**Min storage duration** means you pay for at least that many days even if you delete the object sooner. Delete a Glacier Deep Archive object after 1 day → you still pay for 180 days.

**Glacier retrieval modes — don't confuse Flexible with Instant:**

Glacier Flexible Retrieval has 3 retrieval modes (you choose per request):

| Mode | Speed | Cost |
| ---- | ----- | ---- |
| Expedited | 1–5 minutes | Most expensive |
| Standard | 3–5 hours | Mid |
| Bulk | 5–12 hours | Cheapest |

Glacier Deep Archive also has retrieval modes:

| Mode | Speed |
| ---- | ----- |
| Standard | 12 hours |
| Bulk | 48 hours |

There is no "seconds" retrieval for either. The fastest Glacier Flexible can do is **1 minute** (Expedited). If you need millisecond access to archived data, that's **Glacier Instant Retrieval** — a completely different storage class.

**S3 Express One Zone** — a separate class for ultra-low latency (single-digit milliseconds). Not in the table above because it's a different category — designed for speed, not cost optimisation.

| | S3 Standard | S3 Express One Zone |
| - | ----------- | ------------------- |
| Latency | ~tens of milliseconds | Single-digit milliseconds |
| AZs | 3 | 1 |
| Cost per GB | Lower | Higher |
| Cost per request | Higher | Lower (designed for millions of requests) |
| Bucket type | Regular bucket | Directory bucket (different API) |
| Use case | General purpose | ML training, analytics, real-time processing |

Use Express One Zone when the workload makes millions of requests and latency matters more than durability — ML model reading millions of small files, Spark/Athena on hot datasets, real-time financial modelling. For everything else, Standard is cheaper and multi-AZ.

**Intelligent-Tiering** is the "set and forget" option — S3 monitors access patterns and moves objects between tiers automatically. Small monthly monitoring fee per object, but no retrieval charges.

**Lifecycle rules** automatically transition objects between classes:

```
Upload → Standard (Day 0)
       → Standard-IA (Day 30)
       → Glacier Flexible (Day 90)
       → Delete (Day 365)
```

Configure these rules per bucket or per prefix (e.g. only apply to `logs/*`).

**Exam triggers:**
- *"store unlimited data cheaply"* → S3
- *"cheapest storage for data accessed once a year"* → Glacier Deep Archive
- *"automatically move data to cheaper storage over time"* → S3 Lifecycle rules
- *"unknown access pattern"* → S3 Intelligent-Tiering
- *"infrequent access but must be available instantly"* → Standard-IA
- *"archive data, retrieval within 12 hours is acceptable"* → Glacier Flexible Retrieval
- *"non-critical data, cheapest infrequent access"* → One Zone-IA (single AZ risk)

### S3 Object Lock and Glacier Vault Lock

WORM (Write Once Read Many) — prevent objects from being deleted or overwritten, even by root.

**Glacier Vault Lock:**
- Applies a lock policy to an entire Glacier vault
- Once locked, the policy is **permanently immutable** — cannot be changed by anyone, including root
- Use case: regulatory compliance (SEC 17a-4, HIPAA) where you must prove retention policies can't be shortened or data tampered with

**S3 Object Lock:**
- WORM at the S3 bucket level (any storage class, not just Glacier)
- Can be set per-object or as a bucket default
- Two modes:

| Mode | Who can delete/overwrite? |
| ---- | ------------------------- |
| Compliance | No one — not even root. Retention period cannot be shortened. |
| Governance | Admins with special permissions (`s3:BypassGovernanceRetention`) can override. |

Use **Compliance mode** when regulation demands it. Use **Governance mode** when you want protection with an escape hatch for authorised admins.

**Exam triggers:**
- *"ensure data cannot be deleted for 7 years, even by root"* → S3 Object Lock (Compliance mode) or Glacier Vault Lock
- *"WORM storage"* → S3 Object Lock or Glacier Vault Lock
- *"SEC 17a-4 compliance"* → Glacier Vault Lock
- *"prevent deletion but allow admins to override in emergencies"* → S3 Object Lock (Governance mode)

### S3 Event Notifications

Trigger actions automatically when something happens in a bucket — object created, deleted, restored from Glacier, etc.

**Three classic destinations:**

| Destination | Use case |
| ----------- | -------- |
| SNS | Fan out to multiple subscribers (email, HTTP, Lambda, SQS) |
| SQS | Queue for async processing (decouple producer from consumer) |
| Lambda | Run code directly in response to the event |

Real-world examples:
- Image upload → Lambda generates a thumbnail automatically
- Log file lands in S3 → SQS → processing pipeline picks it up
- Object deleted → SNS → notify ops team via email

**EventBridge — the newer, more powerful option:**

S3 can also send events to Amazon EventBridge, which gives you more control:

- Route events to **18+ destinations** (not just SNS/SQS/Lambda)
- **Filter on metadata** — e.g. only trigger on `.jpg` files over 5 MB
- **Archive and replay** events
- **Multiple rules** on the same event — one upload can trigger multiple actions

```
Classic:     S3 → SNS/SQS/Lambda (one destination per notification rule)
EventBridge: S3 → EventBridge → any combination of 18+ targets with filtering
```

**Exam triggers:**
- *"automatically process files when uploaded to S3"* → S3 Event Notification → Lambda
- *"trigger multiple actions from a single S3 event"* → EventBridge
- *"filter S3 events by object metadata"* → EventBridge
- *"decouple file processing from upload"* → S3 → SQS → consumer

**The key insight: one upload triggers a whole workflow — no polling, no cron jobs.**

Dog shelter example — a new dog photo is uploaded for adoption:

```
Photo uploaded to S3 (new-dogs/rex.jpg)
├── Lambda → generate thumbnail for the website listing
├── Lambda → run image moderation (Rekognition — is it actually a dog photo?)
├── SQS → queue triggers a service that updates the website database with the new listing
└── SNS → email/SMS to subscribers: "New dog available for adoption!"
```

One photo upload kicks off four things automatically. No one is checking "did a new file arrive?" on a schedule. The upload **is** the trigger.

Other examples that follow the same pattern:
- **E-commerce** — seller uploads product images → resize for mobile/desktop/thumbnail → update catalog → listing goes live
- **Insurance claim** — customer uploads damage photos → fraud detection model → queue for adjuster review → notify the adjuster
- **Video platform** — raw video uploaded → transcode to multiple resolutions → notify uploader when ready

### S3 Requester Pays

Normally the bucket owner pays for storage **and** data transfer (downloads). With Requester Pays, the person downloading pays the transfer costs instead.

Real-world example: a genomics research institution hosts a 50 TB public dataset (human genome sequences) on S3. Researchers worldwide download from it. Without Requester Pays, the institution pays thousands/month in transfer fees. With it, each researcher's AWS account is billed for their own downloads. The institution only pays for storage.

Other examples: open data programs (weather, satellite imagery, government datasets), shared datasets between companies where each partner pays for what they pull.

**Key detail:** anonymous access doesn't work with Requester Pays — the requester must be an authenticated AWS user so AWS knows who to bill.

**Exam trigger:** *"share a large dataset without paying for data transfer"* → S3 Requester Pays.

### S3 Security

**Bucket policies vs IAM policies:**

Both can grant access to S3. A bucket policy is attached to the bucket ("who can access this bucket?"). An IAM policy is attached to a user/role ("what can this user access?"). When both exist, AWS evaluates them together.

**The golden rule — explicit Deny always wins:**

```
1. Explicit Deny anywhere? → DENIED (game over, nothing overrides this)
2. Explicit Allow?         → ALLOWED
3. Neither?                → DENIED (implicit deny — the default)
```

This applies across all AWS services, not just S3. If a bucket policy says Allow but the user's IAM policy has an explicit Deny on `s3:PutObject`, the user is blocked. The Deny wins every time.

Exam scenario — "bucket policy allows read/write but a user can't PutObject":
The user's IAM policy (or a group/SCP policy) has an explicit Deny. The bucket policy Allow cannot override it.

**Other S3 security controls:**

| Control | What it does |
| ------- | ------------ |
| Bucket policy | JSON policy on the bucket — controls access for any principal (users, accounts, public) |
| IAM policy | JSON policy on the user/role — controls what AWS resources they can access |
| ACLs (legacy) | Per-object or per-bucket access lists. AWS recommends disabling these — use bucket policies instead |
| Block Public Access | Account or bucket-level setting that overrides any policy granting public access. Enabled by default on new buckets. |
| Pre-signed URLs | Temporary URL granting time-limited access to a private object. Use case: let a user download a file without making the bucket public. |

**S3 encryption:**

| Type | How it works |
| ---- | ------------ |
| SSE-S3 | AWS manages the keys entirely — default encryption for new buckets |
| SSE-KMS | You use a KMS key — audit trail via CloudTrail, can control who has access to the key |
| SSE-C | You provide the encryption key with every request — AWS doesn't store it |
| Client-side | You encrypt before uploading — AWS never sees the plaintext |

**Exam triggers:**
- *"user can't access S3 despite bucket policy allowing it"* → explicit Deny in IAM policy
- *"prevent any public access to S3, even if someone misconfigures a policy"* → S3 Block Public Access
- *"give temporary access to a private S3 object"* → pre-signed URL
- *"audit who accessed which encryption key"* → SSE-KMS (CloudTrail logs key usage)
- *"compliance requires customer-managed encryption keys"* → SSE-KMS or SSE-C

### S3 Access Points

When a single bucket is shared by many teams or applications, the bucket policy becomes a giant, unmanageable JSON document. Access Points simplify this — each access point gets its own name, DNS endpoint, and policy.

```
Without Access Points:
One bucket policy with 50 statements for different teams → hard to maintain

With Access Points:
Bucket → Access Point "finance-team" (policy: read-only to /finance/*)
       → Access Point "data-science" (policy: read/write to /datasets/*)
       → Access Point "public-web"   (policy: read-only to /public/*)
```

Each team uses their own access point endpoint instead of the bucket URL. Each has its own simple policy — no giant shared policy to manage.

**Key details:**
- Each access point can be restricted to a specific VPC (no internet access)
- Access points can have their own Block Public Access settings
- The bucket policy can delegate access control to access points entirely

**Exam trigger:** *"simplify access management for a shared S3 bucket with many users"* → S3 Access Points.

### S3 VPC Endpoint (Gateway)

By default, EC2 instances in a private subnet access S3 over the internet (via NAT Gateway). A **VPC Gateway Endpoint** creates a private route from your VPC to S3 — traffic never leaves the AWS network.

```
Without endpoint: EC2 (private subnet) → NAT Gateway → internet → S3 (costs money, slower)
With endpoint:    EC2 (private subnet) → VPC Gateway Endpoint → S3 (free, private, faster)
```

**Why it matters:**
- **Free** — no data processing charges (NAT Gateway charges per GB)
- **Secure** — traffic stays on AWS's private network, never hits the internet
- **Faster** — lower latency than going through NAT

**Key details:**
- Gateway Endpoints work for **S3 and DynamoDB only** — other services use Interface Endpoints (different thing, costs money)
- Configured via route tables — you add the endpoint and update the route table for the private subnet
- Can attach a policy to the endpoint to restrict which buckets are accessible

**Exam triggers:**
- *"access S3 from a private subnet without a NAT Gateway"* → VPC Gateway Endpoint
- *"reduce data transfer costs to S3"* → VPC Gateway Endpoint (free vs NAT Gateway charges)
- *"keep S3 traffic off the public internet"* → VPC Gateway Endpoint

### S3 Access Logs

Log every request made to a bucket — who accessed what, when, from which IP, and the response status. Stored as log files in a **separate** S3 bucket.

**Use case:** security auditing, compliance, access pattern analysis, troubleshooting failed requests.

**Key details:**
- Logs are delivered on a best-effort basis (slight delay, not real-time)
- **Never log to the same bucket** — this creates an infinite loop (logging the log writes generates more logs, which generates more logs...)
- Log format includes: requester, bucket name, request time, action, response status, error code

**Exam triggers:**
- *"audit who accessed S3 objects"* → S3 Access Logs (or CloudTrail for API-level auditing)
- *"S3 storage is growing unexpectedly and the bucket logs to itself"* → logging loop — change the log destination to a different bucket

### S3 CORS

CORS (Cross-Origin Resource Sharing) — a browser security mechanism. When a webpage on `app.example.com` tries to fetch data from `api.example.com` (a different origin), the browser blocks it by default. CORS headers tell the browser "it's OK, allow this."

```
Browser loads page from Bucket A (website.example.com)
  → JavaScript fetches image from Bucket B (assets.example.com)
  → Browser: "different origin, blocked" ❌

Fix: enable CORS on Bucket B → browser allows the cross-origin request ✅
```

**Key details:**

- CORS is configured on the **receiving** bucket (the one being requested), not the sender
- It's a **browser** restriction — server-to-server calls (Lambda, EC2) don't care about CORS
- You specify which origins are allowed, which HTTP methods, and which headers

**Exam triggers:**
- *"static website on S3 can't load assets from another S3 bucket"* → enable CORS on the assets bucket
- *"browser console shows Access-Control-Allow-Origin error"* → CORS not configured

### S3 Performance

S3 automatically scales to **3,500 PUT/POST/DELETE** and **5,500 GET** requests per second **per prefix**. A prefix is the path before the filename — `bucket/folder1/sub/` is one prefix, `bucket/folder2/` is another. Spread reads across prefixes to multiply throughput.

**Multipart upload:**
- **Required** for files over 5 GB, **recommended** for files over 100 MB
- Splits a file into parts, uploads in parallel, S3 reassembles
- Failed parts can be retried individually — don't restart the whole upload

**S3 Transfer Acceleration:**
- Uploads go to the nearest **CloudFront edge location** first, then AWS's private backbone to the bucket's region
- Speeds up long-distance uploads (e.g. user in Australia uploading to `us-east-1`)
- No benefit if the user is already close to the bucket's region

```
Without acceleration: Australia ──── public internet ────→ us-east-1 bucket (slow)
With acceleration:    Australia → nearest edge location → AWS backbone → us-east-1 bucket (fast)
```

**Byte-Range Fetches:**

Download specific byte ranges of a file instead of the whole object. The principle: don't download what you don't need, and parallelise what you do.

Real-world examples:
- **Video streaming** — skip to the middle of a 2 GB video? The player fetches just the byte range for the 30 seconds you're watching, not the entire file
- **CSV processing** — 10 GB CSV on S3, you only need the first 100 rows? Fetch bytes 0–5000 instead of downloading 10 GB
- **Resumable downloads** — 5 GB download fails at 3 GB? Resume from byte 3,000,000,000 instead of starting over
- **Parallel downloads** — split a 10 GB file into 10 x 1 GB ranges, download all 10 in parallel, reassemble locally — 10x faster
- **PDF preview** — fetch just the first few KB to render page 1 of a 500-page PDF

**Exam triggers:**
- *"improve upload speed for large files"* → Multipart upload
- *"speed up uploads from users far from the bucket region"* → S3 Transfer Acceleration
- *"maximise read throughput"* → spread reads across multiple prefixes
- *"download parts of a large file in parallel"* → Byte-Range Fetches

### S3 Select and S3 Object Lambda

Two ways to avoid downloading entire objects — one filters, the other transforms.

**S3 Select — filter rows/columns server-side:**

Run SQL queries directly on S3 objects. Filtering happens on AWS's side, so you only download what you need.

```
Without S3 Select: App → download entire 10 GB CSV → filter locally → use 50 KB
With S3 Select:    App → SQL to S3: "SELECT name, price WHERE price > 100" → receive 50 KB
```

Supports CSV, JSON, and Parquet files (optionally compressed). No setup required — it's built in.

**S3 Object Lambda — transform data before it's returned:**

A Lambda function sits between S3 and the requester, modifying the object on the fly. Same object in S3, different output per caller.

Real-world examples:
- **Redact PII** — marketing team gets names blanked out, analytics team gets full data
- **Convert formats** — store XML, serve JSON
- **Resize images on demand** — store the original, Lambda returns the requested size
- **Watermark documents** — internal users get the original, external partners get a watermarked version

**S3 Select vs S3 Object Lambda:**

| | S3 Select | S3 Object Lambda |
| - | --------- | ---------------- |
| Purpose | Filter rows/columns | Transform the data |
| Output | Subset of original data | Modified version of data |
| Requires | Nothing — built-in SQL | Lambda function you write |
| Use case | "Give me only rows where status=500" | "Redact SSNs before returning" |

**S3 Select vs Athena:** S3 Select is simple queries on a single object. Athena is a full SQL engine across multiple objects with joins, aggregations, and partitions — more powerful but requires a table definition.

**Exam triggers:**
- *"reduce the amount of data retrieved from S3"* → S3 Select
- *"filter CSV data server-side before downloading"* → S3 Select
- *"return different versions of the same S3 object to different users"* → S3 Object Lambda
- *"redact PII from S3 objects before returning"* → S3 Object Lambda
- *"query across many S3 files with SQL"* → Athena (not S3 Select)

### S3 Replication

Two types — same concept, different scope:

| Type | Destination | Use case |
| ---- | ----------- | -------- |
| Cross-Region Replication (CRR) | Bucket in a different region | DR, compliance, lower latency in another region |
| Same-Region Replication (SRR) | Bucket in the same region | Aggregate logs, replicate between prod/test accounts |

**Requirements and behaviour:**

- **Versioning must be enabled** on both source and destination buckets
- Replication is **asynchronous**
- Only **new objects** are replicated after enabling — existing objects are not replicated retroactively
- Use **S3 Batch Replication** to replicate existing objects
- **Delete markers are not replicated** by default (can be enabled) — prevents accidental cascading deletes across buckets
- **No chaining** — if bucket A replicates to B, and B replicates to C, objects in A do not appear in C

**Exam triggers:**
- *"keep a copy of data in another region for DR"* → Cross-Region Replication
- *"replicate logs to a central bucket in the same region"* → Same-Region Replication
- *"existing objects weren't replicated"* → S3 Batch Replication
- *"deleted object still exists in the replica bucket"* → delete markers aren't replicated by default

**Do you actually need CRR?** CRR doubles your storage costs (full copy in another region) plus cross-region data transfer fees. S3 Standard already stores data across **3 AZs** within a region with 11 nines durability — your data is extremely safe without CRR. Only use CRR when compliance requires multi-region copies, you need low-latency access from another region, or you need to survive an entire region failure. For most workloads, S3 in one region with versioning is enough.

**Should delete markers replicate?** Generally no — and that's the default for a reason. If delete markers replicate, someone accidentally deleting a file in the source also "deletes" it in the replica. Your backup is gone too. The whole point of replication for DR is that the replica is a safety net — it should survive mistakes in the source.

| Delete marker replication | When |
| ------------------------- | ---- |
| Disabled (default) | Replica is for DR/backup — accidental deletes shouldn't cascade. Compliance requires retaining data even if deleted from source. |
| Enabled | Both buckets serve live traffic and must stay in exact sync (active-active). |

### S3 Storage Lens

A dashboard that gives you **visibility across all your S3 buckets** — usage metrics, cost optimization recommendations, and activity trends. Think of it as "CloudWatch for S3 storage."

**What it shows:**
- Total storage across all buckets, broken down by storage class
- Which buckets are growing fastest
- How many objects lack encryption
- Which buckets don't have versioning or lifecycle rules
- Cost optimization recommendations (e.g. "move 500 GB of unaccessed data to Glacier")

**Scope:** can aggregate across an entire AWS Organization, a single account, or specific buckets.

**Two tiers:**

| Tier | Metrics | Cost |
| ---- | ------- | ---- |
| Free | 28 usage metrics, 14-day data retention | Free |
| Advanced | 35+ metrics including activity metrics (requests, bytes downloaded), CloudWatch publishing, prefix-level aggregation | Paid |

**Exam trigger:** *"get visibility into S3 usage and cost optimization across multiple accounts"* → S3 Storage Lens.

## AWS Snow Family

AWS's answer to: "how do I move petabytes of data to AWS when the internet is too slow?" AWS ships you a physical device, you load your data onto it, ship it back.

**Three devices:**

| Device | Storage | Form factor | Use case |
| ------ | ------- | ----------- | -------- |
| Snowcone | 8–14 TB | Fits in a backpack | Edge computing, small transfers, remote locations |
| Snowball Edge | 80 TB (Storage) / 42 TB (Compute) | Suitcase-sized | Data migration, edge computing with Lambda/EC2 |
| Snowmobile | 100 PB | A literal shipping container on a truck | Massive data centre migrations (deprecated — no new orders, but may still appear on exam) |

**The maths that makes it click:** transferring 100 TB over a 1 Gbps connection takes ~12 days. Over 100 Mbps, it takes ~120 days. Snowball Edge does it in about a week (load + ship + ingest).

**How it actually works — no modems, no internet:**

The speed gain isn't about a faster connection — it's about **skipping the internet entirely**. You copy data onto the device over your local network (LAN), then physically ship the box.

```
Your data centre:  Servers → LAN (10-25 Gbps) → Snowball Edge  [fast local copy]
Ship the box:      Snowball Edge → courier → AWS data centre    [1-2 days transit]
AWS side:          Snowball Edge → S3                           [AWS internal, fast]
```

Your 1 Gbps internet becomes irrelevant. You're copying at LAN speed locally, then shipping a box. It's like asking "should I email 10,000 photos or put them on a hard drive and FedEx it?" At a certain data volume, FedEx wins.

**Snowball Edge — two flavours:**

| | Storage Optimised | Compute Optimised |
| - | ----------------- | ----------------- |
| Storage | 80 TB | 42 TB |
| Compute | 40 vCPUs | 104 vCPUs, optional GPU |
| Use case | Bulk data transfer | Edge ML inference, video processing |

Both can run EC2 instances and Lambda functions locally — useful for remote locations with no internet (oil rigs, ships, disaster zones).

**Data migration workflow:**

1. Request a device from the AWS console
2. AWS ships it to you
3. Load your data onto the device (encrypted automatically)
4. Ship it back to AWS
5. AWS uploads the data into your S3 bucket

All data is encrypted with KMS keys — if the device is lost in transit, nobody can read it.

**Exam triggers:**
- *"migrate petabytes of data to AWS"* → Snowball Edge or Snowmobile
- *"transfer data from a location with limited/no internet"* → Snowcone or Snowball Edge
- *"run compute at a remote location with no internet"* → Snowball Edge Compute Optimised
- *"move more than 10 PB"* → Snowmobile
- *"data transfer would take weeks over the network"* → Snow Family

Exam scenario — "move hundreds of TB to S3 and process data while in transit":

You have hundreds of TB, a 1 Gbps connection (would take ~12 days), and need to process data during the move. Answer: **Snowball Edge Compute Optimised**. It has 104 vCPUs and can run EC2/Lambda locally — process data on the device while it ships. DataSync and Transfer Acceleration are still bottlenecked by your internet speed. Storage Optimised has more space but less compute — the "processing while in transit" is the giveaway for Compute Optimised.

## AWS DataSync

Managed data transfer service for moving large amounts of data **over the network** — between on-premises storage and AWS, or between AWS services.

**DataSync vs Snow Family:**

| | DataSync | Snow Family |
| - | -------- | ----------- |
| Transfer method | Network (internet or Direct Connect) | Physical device shipped |
| Transfer type | One-time or scheduled/recurring | One-time bulk migration |
| Speed | Up to 10 Gbps per agent | Limited by shipping time |
| Use case | Ongoing sync, incremental transfers | Petabyte-scale initial migration, no/limited internet |

**What DataSync moves:**

| From | To |
| ---- | -- |
| On-premises NFS/SMB file servers | S3, EFS, FSx |
| S3 | S3, EFS, FSx (cross-region, cross-account, or between services) |
| EFS | EFS, S3 |
| FSx | FSx, S3 |

**How it works:**

1. Install a **DataSync agent** on-premises (a VM that connects to your storage)
2. Configure a **task** — source location, destination location, schedule
3. DataSync transfers data, preserving metadata (permissions, timestamps)
4. Only changed data is transferred on subsequent runs (incremental)

```
On-prem NFS server → DataSync agent → internet/Direct Connect → S3/EFS/FSx
```

For AWS-to-AWS transfers (e.g. S3 to S3 cross-region), no agent is needed.

**Key features:**

- **Automatic encryption** in transit and at rest
- **Bandwidth throttling** — limit how much network capacity DataSync uses so it doesn't saturate your connection
- **Scheduling** — run daily, weekly, or on a cron schedule
- **Incremental transfers** — only changed files are synced after the initial transfer
- **Data integrity validation** — verifies data at source and destination match

**Real-world examples:**

- Migrate an on-prem NFS file server to EFS — DataSync handles the initial copy and keeps them in sync until cutover
- Replicate S3 data to another region for DR (alternative to S3 CRR when you need scheduling or filtering)
- Move on-prem backups to S3 Glacier nightly

**Exam triggers:**
- *"move data from on-premises NFS/SMB to AWS"* → DataSync
- *"scheduled/recurring data transfer to S3 or EFS"* → DataSync
- *"migrate a file server to AWS with metadata preserved"* → DataSync
- *"transfer data between AWS storage services"* → DataSync
- *"move data from S3 to EFS"* → DataSync (not S3 Replication — that's S3 to S3 only. No agent needed for AWS-to-AWS.)
- *"one-time 50 PB migration with no internet"* → Snow Family (not DataSync)

Exam scenario — "migrate 30 TB from on-prem NFS to S3":

The answer is **DataSync**, not Snowball Edge. 30 TB over a 1 Gbps connection takes ~3 days — not enough to justify a physical device. DataSync also has a native NFS agent that preserves metadata (permissions, timestamps). Snowball is for when transfer would take weeks to months.

The mental threshold for DataSync vs Snow Family:

| Data volume | Internet | Answer |
| ----------- | -------- | ------ |
| Under ~100 TB | Decent connection | DataSync |
| Hundreds of TB+ | Any | Snow Family |
| Any amount | Poor/no internet | Snow Family |

If the question mentions a modest data size (10–50 TB) without emphasising bad internet, the answer is DataSync. Snow Family questions say "petabytes" or "limited connectivity."

### AWS Transfer Family

Managed SFTP, FTPS, and FTP service for transferring files into and out of **S3 or EFS**. Your existing file transfer workflows keep working — just point them at AWS instead of your on-prem FTP server.

**The problem it solves:** third parties (vendors, partners, customers) upload files to you via SFTP. You don't want to manage an SFTP server. Transfer Family gives you a managed endpoint that drops files directly into S3 or EFS.

```
Partner → SFTP → AWS Transfer Family → S3 bucket
                                      → EFS file system
```

**Key details:**
- Supports **SFTP** (SSH-based), **FTPS** (TLS-based), and **FTP** (unencrypted — use only in VPC)
- Authenticate users via **service-managed identities**, **Active Directory**, or **custom Lambda authoriser**
- You get a DNS endpoint (or bring your own domain with Route 53)
- Pay per protocol endpoint per hour + data transferred

**Exam triggers:**
- *"migrate an existing SFTP server to AWS"* → Transfer Family
- *"partners upload files via SFTP into S3"* → Transfer Family
- *"managed FTP endpoint"* → Transfer Family

**Transfer Family vs DataSync:** Transfer Family is for **external parties pushing files to you** using standard FTP/SFTP protocols. DataSync is for **you moving data** between on-prem and AWS or between AWS services. Different use cases.

## Hybrid Cloud Storage

### AWS Storage Options — Complete Reference

Every storage service in one table:

| Service | Type | Protocol | Shared? | Persistence | Use case |
| ------- | ---- | -------- | ------- | ----------- | -------- |
| EBS | Block | Attached to EC2 | No (1 instance, except Multi-Attach io2) | Survives stop/start | OS volumes, databases |
| Instance Store | Block | Physically attached | No (1 instance) | Lost on stop/termination | Temp scratch space, caches |
| EFS | File (NFS) | NFS | Yes (Linux, multi-AZ) | Persistent | Shared Linux storage, web farms |
| FSx Windows | File (SMB) | SMB | Yes (Windows, AD) | Persistent | Windows file shares |
| FSx Lustre | File (POSIX) | POSIX | Yes (Linux) | Persistent (or scratch) | HPC, ML training, video processing |
| S3 | Object | HTTP API | Yes (any) | Persistent (11 nines) | Anything — files, backups, data lake, static sites |
| S3 Glacier | Object (archive) | HTTP API | Yes (any) | Persistent | Long-term archive, compliance |
| ElastiCache | In-memory | Redis/Memcached protocol | Yes | Redis: optional. Memcached: no | Caching, session store |

**Data transfer services:**

| Service | Method | Use case |
| ------- | ------ | -------- |
| Snow Family | Physical device | One-time massive migration, no internet |
| DataSync | Network (agent) | Scheduled/recurring transfers, file server migration |
| Transfer Acceleration | Network (edge) | Speed up S3 uploads from distant users |
| Storage Gateway | On-prem VM | Ongoing hybrid access (NFS/SMB/iSCSI → S3) |

**Decision tree:**

```
Need block storage for EC2?
├── Persistent → EBS
└── Temporary, max speed → Instance Store

Need shared file storage?
├── Linux → EFS
├── Windows / Active Directory → FSx for Windows
├── HPC / ML / extreme throughput → FSx for Lustre
└── Multi-protocol (NFS + SMB) → FSx for NetApp ONTAP

Need object storage?
├── Frequently accessed → S3 Standard
├── Archive → S3 Glacier
└── Unknown pattern → S3 Intelligent-Tiering

Need caching?
├── Sessions, data structures, replication → ElastiCache Redis
└── Simple key-value, disposable → ElastiCache Memcached

Need to move data to AWS?
├── Petabytes, no internet → Snow Family
├── Over the network, scheduled → DataSync
└── On-prem apps need ongoing AWS storage access → Storage Gateway
```

When your organisation has both on-premises infrastructure and AWS, you need to bridge the two. Different services handle different patterns:

| Service | What it does | Pattern |
| ------- | ------------ | ------- |
| Storage Gateway | On-prem apps access AWS storage using standard protocols (NFS, SMB, iSCSI) | Ongoing access — on-prem apps talk to AWS storage as if it's local |
| DataSync | Bulk/scheduled data transfer | Migration or recurring sync |
| Snow Family | Physical device for massive migrations | One-time, no/limited internet |
| Direct Connect | Dedicated private network link to AWS | Network layer — faster, more reliable than internet |

### AWS Storage Gateway

A VM you run on-premises that gives your local applications access to AWS cloud storage using familiar protocols. Your apps don't know they're talking to AWS — it looks like a local file share, disk, or tape library.

**Three modes:**

**File Gateway (NFS/SMB):**

```
On-prem app → NFS/SMB mount → File Gateway VM → S3
```

- Files are stored as objects in S3, but your app sees a normal file share
- Frequently accessed files are cached locally on the gateway for low-latency access
- Use case: replace on-prem NAS with S3-backed storage, or extend storage to the cloud

**Volume Gateway (iSCSI):**

```
On-prem app → iSCSI block storage → Volume Gateway VM → S3 (with EBS snapshots)
```

Two sub-modes:

| | Cached Volumes | Stored Volumes |
| - | -------------- | -------------- |
| Primary data lives in | S3 (hot data cached locally) | On-premises (async backup to S3) |
| Local storage needed | Small (cache only) | Full dataset |
| Use case | Extend storage to cloud, most data in S3 | Keep all data local, use S3 for backups |

- Both create **EBS snapshots** in S3 that can be restored to EBS volumes in AWS
- Use case: block storage for databases or apps that need iSCSI

**Tape Gateway (Virtual Tape Library):**

```
Backup software (Veeam, Veritas, etc.) → Tape Gateway → S3 Glacier
```

- Presents itself as a physical tape library to your existing backup software
- Virtual tapes are stored in S3 and archived to Glacier
- Use case: replace physical tape infrastructure without changing backup workflows
- The exam loves this one — any mention of "tape backups" or "backup software" → Tape Gateway

**Storage Gateway vs DataSync:**

| | Storage Gateway | DataSync |
| - | --------------- | -------- |
| Purpose | Ongoing access — on-prem apps use AWS storage day-to-day | Data transfer — move or sync data |
| Protocol | NFS, SMB, iSCSI | Agent-based transfer |
| Caching | Yes — frequently accessed data cached locally | No caching |
| Use case | "Extend our on-prem storage to the cloud" | "Migrate our file server to AWS" |

**Exam triggers:**
- *"on-prem applications need to access S3 via NFS"* → File Gateway
- *"replace physical tape backups with cloud storage"* → Tape Gateway
- *"on-prem block storage backed by S3"* → Volume Gateway
- *"extend on-prem storage to the cloud without changing applications"* → Storage Gateway
- *"backup software needs a tape library target"* → Tape Gateway
- *"migrate data to AWS"* → DataSync (not Storage Gateway — Gateway is for ongoing access)

### Amazon FSx

Fully managed third-party file systems on AWS. Where EFS is managed NFS (Linux), FSx covers everything else.

**Four flavours (two matter most for the exam):**

**FSx for Windows File Server:**
- Fully managed **SMB** file share with **NTFS** and **Active Directory** integration
- Windows apps see a native Windows file share — no code changes
- Supports DFS (Distributed File System) for namespaces and replication
- Use case: Windows workloads migrated to AWS that need a shared drive (SharePoint, .NET apps, SQL Server backups, home directories)

**FSx for Lustre:**
- High-performance **parallel file system** — hundreds of GB/s throughput, millions of IOPS
- Integrates natively with S3 — can read/write S3 objects as files and write results back to S3
- Use case: HPC, ML training, video rendering, genomics, financial modelling — any workload that needs massive throughput

**FSx for NetApp ONTAP:**
- Multi-protocol (NFS, SMB, iSCSI) — works with Linux, Windows, and macOS simultaneously
- Use case: hybrid environments migrating NetApp workloads to AWS

**FSx for OpenZFS:**
- High-performance NFS — up to 1 million IOPS
- Use case: Linux workloads migrating from on-prem ZFS storage

**Quick reference:**

| FSx type | Protocol | OS | Use case |
| -------- | -------- | -- | -------- |
| Windows File Server | SMB | Windows | Windows file shares, AD integration |
| Lustre | POSIX | Linux | HPC, ML, video processing — extreme throughput |
| NetApp ONTAP | NFS, SMB, iSCSI | All | Hybrid, multi-protocol |
| OpenZFS | NFS | Linux | ZFS migration, high-performance Linux NFS |

**FSx vs EFS:**

| | EFS | FSx for Windows | FSx for Lustre |
| - | --- | --------------- | -------------- |
| Protocol | NFS | SMB | POSIX |
| OS | Linux only | Windows (and Linux via SMB) | Linux |
| Use case | Shared Linux storage | Windows file shares | HPC, ML, extreme throughput |
| S3 integration | No | No | Yes — reads/writes S3 objects natively |

**Exam triggers:**
- *"Windows file share with Active Directory"* → FSx for Windows File Server
- *"high-performance computing or ML training needs fast shared storage"* → FSx for Lustre
- *"process data in S3 with a high-throughput file system"* → FSx for Lustre
- *"shared storage for Linux workloads"* → EFS (not FSx, unless extreme performance is needed)
- *"multi-protocol file share (NFS + SMB)"* → FSx for NetApp ONTAP

**What POSIX means:**

POSIX (Portable Operating System Interface) is a standard for how file systems behave on Unix/Linux — `open()`, `read()`, `write()`, file paths like `/data/results.csv`, permissions like `chmod 755`. Normal Linux filesystem behaviour.

When an exam question says "POSIX compliant" it means the app expects a real filesystem, not an API. This rules out S3 (object storage, accessed via HTTP API — you can't `cd` into S3). EFS and FSx for Lustre are POSIX — they mount as a regular filesystem and apps don't know the difference from a local disk.

**"POSIX compliant" in a question = not S3.**

**Why Lustre for HPC — parallel file system:**

Lustre stripes data across multiple storage servers simultaneously. When an HPC job reads a file, it pulls from many servers at once — that's how it hits millions of IOPS. EFS is shared but reads from a single path.

```
EFS:    App → one NFS path → storage
Lustre: App → many parallel paths → many storage servers → millions of IOPS
```

Exam keyword map:

| Keywords in question | Answer |
| -------------------- | ------ |
| POSIX + HPC + millions of IOPS | FSx for Lustre |
| POSIX + shared Linux storage | EFS |
| SMB + Windows + Active Directory | FSx for Windows |
| Block storage for one instance | EBS |

**FSx for Lustre — Scratch vs Persistent:**

| | Scratch | Persistent |
| - | ------- | ---------- |
| Data replicated? | No — data lost if server fails | Yes — replicated within same AZ |
| Performance | Higher burst throughput | Consistent throughput |
| Use case | Short-term processing (crunch data, throw away) | Long-term storage (keep results) |
| Cost | Cheaper | More expensive |

**Exam trigger:** *"temporary high-performance processing, data doesn't need to survive"* → Lustre Scratch. *"high-performance storage that must persist"* → Lustre Persistent.

**FSx for Windows — availability:**

| | Single-AZ | Multi-AZ |
| - | --------- | -------- |
| Durability | Replicated within one AZ | Active/standby across two AZs |
| Failover | Manual | Automatic |
| Use case | Dev/test, cost savings | Production, high availability |

## CloudFront and Global Accelerator

### CloudFront Overview

CloudFront is AWS's CDN (Content Delivery Network). It caches content at **400+ edge locations** worldwide so users get data from a server near them instead of crossing the globe.

```
Without CloudFront: User in Tokyo → origin server in us-east-1 (200ms latency)
With CloudFront:    User in Tokyo → edge location in Tokyo (10ms latency, cached)
```

**Key concepts:**

- **Edge locations** — data centres worldwide where CloudFront caches content. Not the same as AWS regions/AZs.
- **Origin** — where CloudFront fetches the original content from. Can be S3, ALB, EC2, or any HTTP endpoint.
- **Distribution** — the CloudFront configuration that ties an origin to edge locations. You get a `d1234.cloudfront.net` domain.
- **TTL (Time to Live)** — how long content stays cached at the edge before CloudFront fetches a fresh copy from the origin.

**What CloudFront caches:**

- Static content — images, CSS, JS, videos, fonts (the classic CDN use case)
- Dynamic content — API responses, personalised pages (shorter TTL)
- Streaming video — both on-demand and live

**Origin types:**

| Origin | Use case |
| ------ | -------- |
| S3 bucket | Static website, media files, software downloads |
| ALB / EC2 | Dynamic content, APIs |
| Custom HTTP origin | Any external web server |
| MediaStore / MediaPackage | Video streaming |

**Key benefits:**
- **Lower latency** — content served from nearby edge, not the origin
- **DDoS protection** — built-in AWS Shield Standard, can add Shield Advanced and WAF
- **HTTPS** — free SSL/TLS certificate via ACM for custom domains
- **Cost** — reduces load on origin (fewer requests), and CloudFront data transfer is cheaper than direct S3/EC2 data transfer

### CloudFront vs S3 Transfer Acceleration

Both use edge locations, but for different things:

| | CloudFront | S3 Transfer Acceleration |
| - | ---------- | ------------------------ |
| Direction | Origin → users (downloads/reads) | Users → S3 (uploads/writes) |
| Caching | Yes — content cached at edges | No — just faster network path |
| Use case | Serve content to users fast | Upload large files to S3 fast |

CloudFront is for **reading**, Transfer Acceleration is for **writing**.

### CloudFront Caching

**Cache key** — by default, CloudFront caches based on the URL path. Two requests to `/images/cat.jpg` get the same cached response.

You can customise the cache key to include:
- **Query strings** — `/api/search?q=dogs` and `/api/search?q=cats` are cached separately
- **Headers** — cache different versions for different `Accept-Language` values
- **Cookies** — cache per-user session data

**Cache invalidation:**
- Force CloudFront to evict cached content before the TTL expires
- `/*` invalidates everything, `/images/*` invalidates a path
- Costs money per invalidation request — better to use **versioned file names** (`app.v2.js`) instead of invalidating `app.js`

**Cache behaviours:**
- Route different URL patterns to different origins
- `/api/*` → ALB (dynamic, short TTL), `/*` → S3 (static, long TTL)
- Each behaviour has its own cache settings, HTTPS settings, and allowed HTTP methods

### CloudFront Security

**Origin Access Control (OAC):**
- Restricts S3 bucket access so **only CloudFront** can read from it — users can't bypass CloudFront and hit S3 directly
- Replaces the older Origin Access Identity (OAI)
- The bucket policy only allows the CloudFront distribution's identity

**Geo Restriction:**
- **Allowlist** — only users in specific countries can access content
- **Blocklist** — block users in specific countries
- Use case: content licensing (e.g. streaming video only available in certain countries)

**HTTPS:**
- **Viewer Protocol Policy** — require HTTPS between the user and CloudFront
- **Origin Protocol Policy** — require HTTPS between CloudFront and the origin
- Certificates from ACM (free) for custom domains

**AWS WAF integration:**
- Attach a WAF Web ACL to a CloudFront distribution
- Block SQL injection, XSS, rate limiting, IP blocklists
- WAF rules are evaluated at the edge — bad traffic is blocked before reaching your origin

**Signed URLs / Signed Cookies:**
- Grant time-limited access to premium or private content
- **Signed URL** — one URL per file (e.g. paid video download)
- **Signed Cookie** — access to multiple files with one cookie (e.g. subscriber access to entire video library)

**Exam triggers:**
- *"restrict S3 access to CloudFront only"* → OAC
- *"block users from specific countries"* → CloudFront Geo Restriction
- *"protect against DDoS at the edge"* → CloudFront + Shield + WAF
- *"time-limited access to a single private file"* → CloudFront Signed URL
- *"time-limited access to many private files"* → CloudFront Signed Cookies

### CloudFront Functions and Lambda@Edge

Run code at edge locations — transform requests/responses without going back to the origin.

**Two options:**

| | CloudFront Functions | Lambda@Edge |
| - | -------------------- | ----------- |
| Language | JavaScript only | Node.js, Python |
| Execution time | Sub-millisecond (< 1ms) | Up to 5–30 seconds |
| Scale | Millions of requests/sec | Thousands of requests/sec |
| Network/file access | No | Yes |
| Request body access | No | Yes |
| Cost | Very cheap (~1/6 of Lambda@Edge) | More expensive |
| Use case | Simple, high-volume transformations | Complex logic needing external calls |

**CloudFront Functions — lightweight, fast, cheap:**
- URL rewrites and redirects (`/old-page` → `/new-page`)
- Add/modify headers (cache-control, security headers, CORS)
- Normalize query strings or cookies for better cache hits
- Simple A/B testing (rewrite URL based on a cookie)

**Lambda@Edge — full power at the edge:**
- Authentication and authorization (check JWT against JWKS endpoint or revocation list)
- Dynamic content generation (SSR at the edge)
- A/B testing with external config (call DynamoDB to get experiment config)
- Image transformation based on User-Agent (serve WebP to Chrome, JPEG to Safari)
- Bot detection with external lookups

**Rule of thumb:** if it's pure string manipulation (rewrite URL, add header, check cookie) → CloudFront Function. If it needs to call anything external → Lambda@Edge.

**JWT validation — which one?**

| Scenario | Where | Why |
| -------- | ----- | --- |
| Check if auth header/cookie exists | CloudFront Function | Simple string check |
| Decode JWT, verify with a static key | CloudFront Function (if logic fits in 10 KB) | No network needed |
| Validate JWT against a JWKS endpoint | Lambda@Edge | Needs network call |
| Check token revocation list | Lambda@Edge | Needs external lookup |
| Full auth against Cognito/DynamoDB | Lambda@Edge | Needs AWS service access |

CloudFront Functions **cannot make network calls** — that's the deciding factor. If validation is self-contained (static key), it can work. If it needs to reach out to anything, Lambda@Edge.

**Cloudflare equivalent (for context, not for the exam):**

| AWS | Cloudflare | Notes |
| --- | ---------- | ----- |
| CloudFront Functions | Snippets | Lightweight request/response transformations, limited runtime |
| Lambda@Edge | Workers | Full programmable runtime at the edge, KV storage, Durable Objects, etc. |

Cloudflare Workers are significantly more capable than Lambda@Edge — they run a full V8 isolate with access to storage (KV, D1, R2), WebSockets, and Durable Objects. Lambda@Edge is limited to short-lived request/response transformations. If you've used Workers, think of Lambda@Edge as a much more constrained version.

**Origin Failover:**

CloudFront can automatically switch to a backup origin if the primary is unavailable. Configure an **Origin Group** with a primary and secondary origin — if the primary returns 5xx or times out, CloudFront retries on the secondary.

```
CloudFront → Primary origin (S3 us-east-1) → 503 error
           → Secondary origin (S3 eu-west-1) → 200 OK ✅
```

Use case: high availability for static content without Route 53 failover.

**Price Classes:**

Limit which edge locations CloudFront uses to reduce cost:

| Price Class | Edge locations | Cost |
| ----------- | -------------- | ---- |
| All | All 400+ worldwide | Highest |
| 200 | Most regions, excludes expensive ones (South America, Australia) | Mid |
| 100 | US, Canada, Europe only | Cheapest |

If your users are only in North America and Europe, Price Class 100 saves money without affecting their experience.

**Exam triggers:**
- *"add security headers to all responses"* → CloudFront Functions
- *"authenticate requests at the edge before reaching origin"* → Lambda@Edge
- *"rewrite URLs at the edge"* → CloudFront Functions
- *"generate dynamic content at the edge"* → Lambda@Edge
- *"origin failover for static content"* → CloudFront Origin Group
- *"reduce CloudFront costs for a regional audience"* → Price Classes

### AWS Global Accelerator

Global Accelerator uses **AWS's global network** to route traffic to your application faster — but it's **not a CDN** and does **not cache** content.

**How it works:**
- You get **2 static anycast IPs** that act as a fixed entry point to your app
- Users hit the nearest edge location, then traffic travels over AWS's private backbone to your origin — not the public internet
- If an origin fails, Global Accelerator automatically reroutes to a healthy one

```
Without GA: User → public internet (variable routing, congestion) → ALB in us-east-1
With GA:    User → nearest edge → AWS private backbone → ALB in us-east-1 (faster, reliable)
```

**Key properties:**
- **Static IPs** — 2 anycast IPs that never change. Good for firewall whitelisting.
- **Health checks** — automatically failover to healthy endpoints across regions
- **No caching** — every request goes to the origin. It's about the network path, not caching.
- **Works with any TCP/UDP traffic** — not just HTTP (gaming, IoT, VoIP)

### CloudFront vs Global Accelerator

The exam loves this comparison:

| | CloudFront | Global Accelerator |
| - | ---------- | ------------------ |
| What it does | Caches content at edges | Routes traffic over AWS backbone |
| Caching | Yes | No |
| Static IPs | No (DNS name only) | Yes (2 anycast IPs) |
| Protocols | HTTP/HTTPS, WebSocket | Any TCP/UDP |
| Best for | Static/dynamic web content, video | Non-HTTP (gaming, IoT), static IP requirement, instant regional failover |
| DDoS protection | Shield Standard included | Shield Standard included |

**Exam triggers:**
- *"improve performance for a website with global users"* → CloudFront
- *"need static IPs for a global application"* → Global Accelerator
- *"non-HTTP protocol with global users (gaming, IoT)"* → Global Accelerator
- *"instant failover between regions"* → Global Accelerator
- *"cache content at edge locations"* → CloudFront
- *"client whitelists an IP for a global service"* → Global Accelerator (static IPs)

## AWS Integration and Messaging

When applications need to talk to each other, you have two patterns:

- **Synchronous** — app A calls app B and waits for a response. Simple but tightly coupled — if B is down, A fails.
- **Asynchronous** — app A puts a message in a queue/topic, app B processes it when ready. Decoupled — A doesn't know or care about B.

AWS provides three services for async communication, each solving a different problem.

### SQS (Simple Queue Service)

A message queue — producers send messages, consumers poll and process them. The oldest AWS service (launched 2004).

```
Producer → SQS Queue → Consumer
           (messages wait here until processed)
```

**Key properties:**

- **Unlimited throughput** — no limit on messages per second
- **Default retention** — 4 days (max 14 days)
- **Message size** — max 256 KB
- **At-least-once delivery** — a message can be delivered more than once (your consumer must be idempotent)
- **Best-effort ordering** — messages may arrive out of order (use FIFO queue for strict ordering)

**Visibility timeout:**

When a consumer picks up a message, it becomes invisible to other consumers for a timeout period (default 30 seconds). If the consumer processes it and deletes it within the timeout → done. If the consumer crashes → the message reappears and another consumer picks it up.

```
Message picked up → invisible for 30s → consumer processes + deletes ✅
Message picked up → invisible for 30s → consumer crashes → message reappears → retry ✅
```

If processing takes longer than the visibility timeout, another consumer picks up the same message → duplicate processing. Fix: increase the timeout to match your processing time.

Real-world example — food delivery order processing (visibility timeout = 30s):

A new order comes in. Worker A picks it up — the message becomes invisible. Worker A needs to validate payment, notify the restaurant, and assign a driver.

- **Worker A finishes in 20s:** deletes the message. Done. Restaurant gets one order. ✅
- **Worker A crashes at 15s:** message reappears after 30s. Worker B picks it up. Order isn't lost. ✅
- **Worker A is slow (takes 45s):** at 30s the message reappears while Worker A is still working. Worker B picks it up. Both workers process the same order — restaurant gets it twice, customer charged twice. ❌

```
Worker A picks up order → invisible 30s → Worker A still processing at 31s...
                                        → message reappears → Worker B picks it up
                                        → two workers processing same order ❌
Fix: set visibility timeout to 60s (longer than your processing time)
```

**The rule: set the visibility timeout longer than your processing time.**

**"Doesn't FIFO make visibility timeout redundant?" — No.** They solve different problems:

```
FIFO prevents:         Producer sends order #123 twice → only one copy enters the queue ✅
FIFO does NOT prevent: Worker A is slow → message reappears → Worker B picks it up ❌
                       (visibility timeout still needed)
```

- **FIFO** = ordering + producer deduplication (same message not *sent* twice within 5 min)
- **Visibility timeout** = consumer protection (same message not *processed* by two workers simultaneously)

You need both. FIFO handles the producer side, visibility timeout handles the consumer side.

**Dead Letter Queue (DLQ):**

Messages that fail processing repeatedly are moved to a separate DLQ instead of retrying forever. You configure a **max receive count** (e.g. 3 attempts) — after that many failures, the message is moved to the DLQ.

**DLQ is for poison messages, not outages:**

If a consumer goes down for 10 minutes, messages just **wait in the main queue** — that's normal SQS behaviour. When the consumer restarts, it drains them. No DLQ involved.

The DLQ catches messages the consumer *tries* to process but *fails every time*:

```
Normal outage:   Order #123 → SQS → consumer down → message waits → consumer restarts → processes ✅
Poison message:  Order #456 → SQS → consumer tries → crashes → retries → crashes → after 3 fails → DLQ
```

Food delivery DLQ examples — messages that fail every attempt:
- Order references a restaurant ID that doesn't exist in the database
- Message has malformed JSON the consumer can't parse
- Order requires an expired payment method → unhandled exception

The DLQ isolates these broken messages so they don't block the thousands of healthy messages behind them.

**DLQ redrive:** once you fix the bug, you can push messages back from the DLQ to the original queue for reprocessing — no data loss.

**DLQ works with SNS too** — if SNS can't deliver to a subscriber, failed messages go to a configured DLQ.

**SQS FIFO:**

| | Standard | FIFO |
| - | -------- | ---- |
| Ordering | Best-effort | Strict first-in-first-out |
| Throughput | Unlimited | 300 msg/s (or 3,000 with batching) |
| Duplicates | Possible | Exactly-once processing |
| Queue name | Any | Must end in `.fifo` |

**Why not always use FIFO?** Throughput. Standard is unlimited. FIFO caps at 300 msg/s (3,000 with batching). For millions of messages per second (log ingestion, click tracking, IoT), FIFO can't keep up.

| Use Standard | Use FIFO |
| ------------ | -------- |
| Email sending queue — order doesn't matter | Financial transactions — debit before credit |
| Image thumbnail generation — any order, same result | Command sequences — "create user" before "assign role" |
| Log processing — timestamps tell the order | Inventory updates — stock count depends on order |

Standard is the default when you need speed and can handle duplicates/reordering. FIFO is the safe choice when order or exactly-once matters.

**SQS + ASG — scaling consumers based on queue depth:**

```
Producers → SQS → Consumers (EC2 in ASG)
                   ↑
CloudWatch Alarm: "ApproximateNumberOfMessagesVisible > 1000" → scale out
```

This is a common exam pattern — scale the number of consumers based on how many messages are waiting.

**Exam triggers:**
- *"decouple application components"* → SQS
- *"buffer writes to a database"* → SQS (see below)
- *"messages processed out of order"* → switch to SQS FIFO
- *"messages being processed twice"* → increase visibility timeout or switch to FIFO
- *"scale consumers based on workload"* → SQS + CloudWatch Alarm + ASG
- *"debug failed messages"* → Dead Letter Queue

**SQS as a database write buffer:**

Your frontend receives 10,000 writes/s during a spike, but your database handles 1,000/s. Without a buffer, the database falls over.

```
Without buffer: Frontend (10,000/s) → Database (1,000/s capacity) → overwhelmed ❌
With SQS:       Frontend (10,000/s) → SQS → Consumer (drains at 1,000/s) → Database ✅
                                      (9,000 messages queue up, processed over time)
```

The queue absorbs the spike. The database never sees more than it can handle. Once the spike passes, the consumer drains the backlog. This is one of the most common SQS patterns on the exam.

### SNS (Simple Notification Service)

Pub/sub — a producer publishes a message to a **topic**, and all subscribers receive it. One message → many receivers.

```
Producer → SNS Topic → Subscriber 1 (SQS queue)
                      → Subscriber 2 (Lambda)
                      → Subscriber 3 (email)
                      → Subscriber 4 (HTTP endpoint)
```

**SQS vs SNS — the core difference:**

| | SQS | SNS |
| - | --- | --- |
| Pattern | Queue (1 producer → 1 consumer) | Pub/sub (1 producer → many subscribers) |
| Who pulls? | Consumer polls the queue | SNS pushes to subscribers |
| Persistence | Messages wait in the queue | No persistence — if subscriber is down, message is lost |
| Use case | Decouple + buffer | Fan out to multiple receivers |

**Subscriber types:** SQS, Lambda, email, SMS, HTTP/HTTPS endpoints, Kinesis Data Firehose.

**SNS FIFO:** pairs with SQS FIFO queues for ordered fan-out. An SNS FIFO topic can only have SQS FIFO queues as subscribers.

**Message filtering:** subscribers can set a **filter policy** — each subscriber only receives messages whose attributes match their filter. Without filtering, every subscriber gets every message.

Real-world example — an order processing system with one SNS topic:

```
Order placed → SNS "orders" topic (message includes status attribute)

Filter policies:
├── SQS "fulfilment" queue    → filter: status = "order_received"   → picks, packs, ships
├── SQS "refunds" queue       → filter: status = "order_cancelled"  → processes refund
├── SQS "analytics" queue     → no filter (gets everything)         → tracks all order events
└── Lambda "VIP notification" → filter: status = "order_received" AND customer_tier = "vip" → SMS alert
```

Without filtering, you'd need separate SNS topics per status — messy. With filtering, one topic handles everything and each subscriber gets only what it cares about.

The filter policy is set on the **subscriber**, not the topic. Each subscriber independently decides what it wants.

**Exam triggers:**
- *"send a notification to multiple services at once"* → SNS
- *"fan out an event to multiple queues"* → SNS + SQS (see fan-out below)
- *"send an email alert when something happens"* → SNS
- *"only certain subscribers should receive certain messages"* → SNS message filtering

### SNS + SQS Fan-Out

The most important messaging pattern for the exam — publish once to SNS, and multiple SQS queues each get a copy.

```
S3 event → SNS Topic → SQS Queue A (image processing)
                      → SQS Queue B (metadata extraction)
                      → SQS Queue C (audit logging)
```

**Why not just send to multiple SQS queues directly?** Because S3 event notifications can only send to **one destination** per event type. SNS solves this — one S3 event → SNS → fan out to as many SQS queues as you need.

**Why SQS behind SNS (not just SNS alone)?**
- SNS has no persistence — if a subscriber is down, the message is lost
- SQS gives each consumer its own queue with retry, DLQ, and independent processing speed
- Each service processes at its own pace — fast services aren't slowed by slow ones

**Exam trigger:** *"one event needs to trigger multiple independent processing pipelines"* → SNS + SQS fan-out.

### Kinesis

Real-time streaming data — ingest and process **continuous, high-volume data** (logs, clickstreams, IoT, metrics).

**Four components:**

| Component | What it does |
| --------- | ------------ |
| Kinesis Data Streams | Ingest and store streaming data for custom processing |
| Kinesis Data Firehose | Load streaming data into destinations (S3, Redshift, OpenSearch) — no code |
| Kinesis Data Analytics | Run SQL or Apache Flink on streaming data in real-time |
| Kinesis Video Streams | Ingest and process video streams |

**Data Streams vs Firehose — the exam comparison:**

| | Data Streams | Firehose |
| - | ------------ | -------- |
| You write code? | Yes — custom consumers (Lambda, KCL app) | No — managed delivery, just configure destination |
| Latency | Real-time (~200ms) | Near real-time (~60s buffer) |
| Storage | 1–365 days retention | No storage — delivers and forgets |
| Scaling | You manage shards | Fully managed, auto-scales |
| Destinations | Anything (your code decides) | S3, Redshift, OpenSearch, Splunk, HTTP |

**Data Streams** = real-time processing with custom code. **Firehose** = dump data into a destination with zero code.

**Firehose vs SQS — why not just use SQS to buffer?**

Different problems. SQS is for **processing** (your consumer takes an action per message). Firehose is for **delivery** (dump data into a destination, zero code).

Example — 10,000 log events/second:

```
With SQS:      App → SQS → you write a consumer that reads, parses, writes to S3
               (you manage the consumer, handle errors, scale it)

With Firehose:  App → Firehose → S3
               (done. zero code. handles batching, compression, encryption, retries)
```

| | SQS | Firehose |
| - | --- | -------- |
| You write consumer code? | Yes | No |
| Processing logic? | Yes — you decide what to do per message | No — just delivers to a destination |
| Message handled individually? | Yes | No — batched (~60s or 1 MB) |
| Use case | "Do something with each message" | "Store all this data somewhere" |

If you just need logs/events dumped into S3 or Redshift, Firehose saves you writing and maintaining a consumer.

**Firehose + Splunk — centralised log delivery:**

Instead of each AWS service having its own Splunk integration, Firehose acts as a single pipeline:

```
CloudWatch Logs  ─┐
VPC Flow Logs    ─┤→ Firehose → Splunk HEC (HTTP Event Collector)
ALB Access Logs  ─┤
WAF Logs         ─┘
```

One delivery pipeline instead of configuring each source separately. Firehose handles batching, retry, and buffering. Can transform data with Lambda before delivery (filter, enrich, reformat). Failed deliveries go to a backup S3 bucket automatically.

Same concept as Cloudflare Logpush → Splunk — managed log delivery, zero consumer code.

**Firehose vs Data Streams — deliver vs react:**

- **Firehose:** "Send all WAF logs to Splunk" → done, zero code
- **Data Streams:** "Read WAF logs in real-time, detect attack patterns, trigger an automated IP block within 200ms, AND send to Splunk" → custom code reacts before delivery

Firehose delivers data. Data Streams lets you **react** to data in real-time before it goes anywhere.

**Shards — how Data Streams scales:**

Each shard is a unit of capacity:
- **1 shard** = 1 MB/s write (1,000 records/s), 2 MB/s read
- Need more throughput? Add more shards.
- **Partition key** determines which shard a record goes to — all records with the same key land on the same shard, guaranteeing ordering per key.

```
Producer sends records with partition keys:
  user_123 → Shard 1 (all user_123 events in order)
  user_456 → Shard 2 (all user_456 events in order)
  user_789 → Shard 1 (hashed to same shard)
```

**Hot shard problem — the Instagram example:**

A celebrity posts a Reel → millions of views, likes, and comments stream in. If the partition key is `celebrity_id`, all those events hit one shard because they share the same key. That shard maxes out at 1 MB/s while other shards sit idle.

```
partition_key = "celebrity_123" → all events on Shard 1 → overwhelmed ❌
partition_key = viewer_id       → events spread across all shards → no bottleneck ✅
```

The fix: choose a partition key with **high cardinality** (many unique values). `viewer_id` has millions of unique values → even distribution. `celebrity_id` has one value → hot shard.

**When you want the same shard (accept the risk):** when ordering matters more than distribution. All payment events for a user must be processed in order → use `user_id` as the key and accept uneven load.

**Exam triggers:**
- *"Kinesis throughput is insufficient"* → add more shards
- *"one shard is overwhelmed"* → hot shard — use a more granular partition key
- *"events must be processed in order per user"* → use user_id as partition key

**Capacity modes — Provisioned vs On-Demand:**

| | Provisioned | On-Demand |
| - | ----------- | --------- |
| Shards | You manage — manually add/remove | Auto-scales based on traffic |
| Scaling | Manual (or custom auto-scaling) | Automatic, up to 200 MB/s write |
| Cost | Pay per shard/hour (cheaper at steady load) | Pay per GB (more expensive, no planning needed) |
| Use case | Predictable, steady traffic | Unpredictable, spiky traffic |

Exam scenario — "traffic might grow 100x during a campaign, unpredictable": **On-Demand**. You can't predict shard count. Too few → data loss. Too many → paying for idle. On-Demand handles it automatically.

**Kinesis vs SQS:**

| | Kinesis Data Streams | SQS |
| - | -------------------- | --- |
| Purpose | Real-time streaming analytics | Decouple application components |
| Ordering | Per-shard ordering guaranteed | Best-effort (Standard) or FIFO |
| Consumers | Multiple consumers read the same data | One consumer per message |
| Retention | 1–365 days (data can be replayed) | 4–14 days (deleted after processing) |
| Replay | Yes — reprocess from any point | No — once deleted, gone |
| Use case | Logs, clickstreams, IoT, real-time dashboards | Task queues, job processing, decoupling |

**Exam triggers:**
- *"real-time processing of streaming data"* → Kinesis Data Streams
- *"load streaming data into S3 or Redshift with no code"* → Kinesis Data Firehose
- *"run SQL on streaming data"* → Kinesis Data Analytics
- *"replay/reprocess data from a stream"* → Kinesis Data Streams (SQS can't replay)
- *"ingest thousands of IoT sensor readings per second"* → Kinesis Data Streams

### SQS vs SNS vs Kinesis

The exam's favourite three-way comparison:

| | SQS | SNS | Kinesis Data Streams |
| - | --- | --- | -------------------- |
| Pattern | Queue | Pub/sub | Stream |
| Consumers | One per message | Many (fan-out) | Many (shared stream) |
| Persistence | Until processed | None | 1–365 days |
| Replay | No | No | Yes |
| Ordering | FIFO available | FIFO available | Per-shard |
| Use case | Decouple, buffer | Notify, fan-out | Real-time analytics, replay |

**Quick decision:**
- Need to **decouple** two services? → SQS
- Need to **notify** many services at once? → SNS
- Need **real-time streaming** with replay? → Kinesis

### Amazon MQ

Managed **ActiveMQ and RabbitMQ** service. Exists for one reason: migrating existing on-prem applications that already use these protocols (AMQP, MQTT, STOMP, OpenWire) to AWS without rewriting code.

- Building something new? → **SQS/SNS** (cloud-native, serverless, scales better)
- Migrating an existing app that uses ActiveMQ/RabbitMQ? → **Amazon MQ** (drop-in replacement, no code changes)

Amazon MQ runs on a provisioned instance (not serverless), supports Multi-AZ for HA, and has both queue and topic features built in (like SQS + SNS combined, but on traditional broker protocols).

**Exam trigger:** *"migrate an application using ActiveMQ/RabbitMQ/MQTT to AWS"* → Amazon MQ. Any other messaging scenario → SQS/SNS.

## Amazon Redshift

AWS's **data warehouse** — designed for running analytics queries across massive datasets (petabytes). Not a transactional database like RDS — it's for **OLAP** (Online Analytical Processing), not OLTP.

### OLTP vs OLAP

| | OLTP (RDS/Aurora) | OLAP (Redshift) |
| - | ------------------ | --------------- |
| Purpose | Run your app (orders, users, payments) | Analyse your data (reports, dashboards, trends) |
| Queries | Simple, fast (get one user by ID) | Complex, slow (aggregate millions of rows) |
| Data | Current state | Historical data from many sources |
| Example | "What's order #123?" | "What were total sales by region for Q4?" |

### Why Not RDS for Analytics?

RDS stores data in **rows**. To answer "total sales by region," it reads every column of every row even though you only need `region` and `amount`. Redshift stores data in **columns** — it only reads the columns you ask for.

```
RDS (row storage):      reads entire rows → slow for "give me one column across 1 billion rows"
Redshift (columnar):    reads only the columns needed → fast for analytics queries
```

### Redshift Key Properties

- **Columnar storage** — optimised for aggregations (SUM, AVG, COUNT)
- **Massively Parallel Processing (MPP)** — queries distributed across many nodes
- **SQL interface** — standard SQL, works with BI tools (Tableau, QuickSight)
- **Not serverless by default** — you provision a cluster (leader node + compute nodes), but **Redshift Serverless** exists for on-demand
- **Up to 16 PB** per cluster

### Loading Data into Redshift

| Method | How it works | Use case |
| ------ | ------------ | -------- |
| COPY from S3 | Bulk load from S3 files (CSV, Parquet, JSON) | Most common — large batch loads |
| Kinesis Data Firehose | Stream data directly into Redshift | Near real-time ingestion |
| DMS (Database Migration Service) | Migrate from RDS/on-prem databases | One-time or ongoing replication |

**Redshift Spectrum** — query data directly in S3 without loading it into Redshift. The data stays in S3, Redshift runs SQL on it. Use case: query infrequent data without paying to store it in Redshift.

### Redshift vs Athena

Both query data in S3 with SQL, but for different use cases:

| | Redshift (+ Spectrum) | Athena |
| - | --------------------- | ------ |
| Data stored in | Redshift cluster (or S3 via Spectrum) | S3 only |
| Infrastructure | Provisioned cluster or Serverless | Serverless only |
| Performance | Faster for complex queries, joins, aggregations | Good for ad-hoc queries |
| Cost model | Pay for cluster (always on) or Serverless (per query) | Pay per query (data scanned) |
| Best for | Regular reporting, dashboards, BI tools | Ad-hoc exploration, infrequent queries |

**Exam shortcut:** "data warehouse", "BI dashboards", "complex analytics on petabytes" → **Redshift**. "Ad-hoc SQL on S3 data, no infrastructure" → **Athena**.

### Redshift Snapshots

- Automated snapshots with configurable retention (1–35 days)
- Manual snapshots persist indefinitely
- Snapshots can be **copied to another region** for DR
- Restore creates a new cluster

**Exam triggers:**
- *"data warehouse for analytics and reporting"* → Redshift
- *"run complex SQL across petabytes of data"* → Redshift
- *"connect BI tools like Tableau to AWS"* → Redshift
- *"query S3 data with SQL, no infrastructure"* → Athena
- *"query S3 data from within Redshift"* → Redshift Spectrum
- *"OLAP workload"* → Redshift
- *"OLTP workload"* → RDS/Aurora

## Serverless

Services where you don't manage any infrastructure — no servers, no patching, no capacity planning. You pay for what you use.

### AWS Lambda

Run code without provisioning servers. Upload your function, define a trigger, AWS handles the rest.

**Key properties:**

- **Languages:** Python, Node.js, Java, .NET, Go, Ruby, custom runtimes
- **Timeout:** max **15 minutes** per invocation — not for long-running jobs
- **Memory:** 128 MB to 10 GB (CPU scales proportionally with memory)
- **Ephemeral storage:** `/tmp` directory, up to 10 GB — cleared between invocations
- **Concurrency:** up to 1,000 concurrent executions per region (soft limit, can increase)
- **Pricing:** pay per request + per GB-second of compute. Free tier: 1M requests + 400,000 GB-seconds/month

**Lambda limits (exam favourites):**

| Limit | Value |
| ----- | ----- |
| Execution timeout | **15 minutes** max |
| Memory | 128 MB – 10 GB |
| Ephemeral storage (`/tmp`) | Up to 10 GB |
| Deployment package (zipped) | 50 MB |
| Deployment package (unzipped) | 250 MB |
| Environment variables | 4 KB total |
| Concurrency per region | 1,000 (soft limit, can increase) |

The **15-minute timeout** is the most tested limit. If a question describes a process taking longer than 15 minutes, Lambda is the wrong answer — use ECS/Fargate, Step Functions, or AWS Batch instead.

The **deployment package size** matters too — if your function + dependencies exceed 250 MB unzipped, use Lambda Layers to split dependencies out, or use a container image (up to 10 GB).

**Common triggers:**

| Trigger | Use case |
| ------- | -------- |
| API Gateway | REST/HTTP API endpoint |
| S3 event | Process file on upload (thumbnail, virus scan) |
| SQS | Process messages from a queue |
| SNS | React to notifications |
| DynamoDB Streams | React to database changes |
| CloudWatch Events/EventBridge | Scheduled tasks (cron), react to AWS events |
| Kinesis | Process streaming data |

**Lambda concurrency:**

Your Lambda function can only run **1,000 copies at the same time** per region (default). All functions **share** this pool.

The problem — one function starves another:

```
Total pool: 1,000
Function A (API backend):       uses 900 during a spike
Function B (image processing):  needs 100 → gets 100 → OK
Function C (payments):          needs 50 → no capacity left → THROTTLED ❌
```

The fix — **Reserved Concurrency** guarantees capacity for critical functions:

```
Function C (payments): 200 reserved → always has 200, nobody can take them
Remaining pool: 800 → shared by Functions A and B
```

Function C always works even if A and B go crazy. Trade-off: A and B now share only 800.

**Reserved vs Provisioned — different problems:**

```
Reserved:    "guarantee me 200 slots" (still has cold starts on first use)
Provisioned: "keep 200 instances warm at all times" (zero cold starts, costs money)
```

| | Unreserved (default) | Reserved | Provisioned |
| - | -------------------- | -------- | ----------- |
| Problem it solves | Nothing — shared pool | Throttling (one function starving others) | Cold starts (latency on first call) |
| Cold starts? | Yes | Yes | No |
| Cost | Free | Free (just reserves slots) | Costs money (instances running idle) |
| Use case | Default | Critical functions that must not be throttled | Latency-sensitive (API backends) |

**Cold starts:** first invocation after idle spins up a new execution environment (~100ms to a few seconds). Subsequent invocations reuse the warm environment. Provisioned Concurrency eliminates this by keeping instances warm.

**Lambda SnapStart:**

Eliminates cold starts by taking a **snapshot of the initialised execution environment** (memory + disk) and restoring from it instead of initialising from scratch.

```
Without SnapStart: Cold start → boot runtime → load dependencies → init framework → seconds
With SnapStart:    Restore cached snapshot → sub-second
```

Supported runtimes: **Java** (11+), **Python** (3.12+), **.NET** (8+).

| | SnapStart | Provisioned Concurrency |
| - | --------- | ----------------------- |
| Languages | Java, Python, .NET | All |
| How | Restores cached snapshot | Keeps instances warm |
| Cold start | Sub-second (snapshot restore) | Zero (already running) |
| Cost | Free for Java; caching + restoration cost for Python/.NET | Costs money (idle instances) |
| Use case | Most cold-start-sensitive functions | Strictest latency requirements, all languages |

**Exam trigger:** *"reduce Lambda cold start times"* → SnapStart (cheaper) or Provisioned Concurrency (fastest).

**Lambda + RDS/Cache real-world examples:**

Lambda calling RDS:
- **E-commerce checkout** — API Gateway → Lambda → RDS Proxy → RDS. Validates cart, calculates total, creates order in PostgreSQL.
- **User signup** — Cognito triggers Lambda → writes user profile to RDS
- **Report generation** — CloudWatch scheduled event → Lambda → queries RDS for daily sales → writes PDF to S3

Lambda calling ElastiCache:
- **Product catalog API** — Lambda checks Redis first. Cache hit → return instantly. Cache miss → query RDS → store in cache → return.
- **Rate limiting** — Lambda increments a counter in Redis per user/IP. Exceeds threshold → reject. Redis TTL auto-expires the counter.
- **Session validation** — Lambda checks Redis for session token → valid? proceed. Expired? return 401.

```
Product API:
Client → API Gateway → Lambda → ElastiCache (hit? return)
                               → RDS (miss → query → cache → return)
```

**RDS invoking Lambda (the reverse direction):**

RDS can call a Lambda function directly **from within the database** using stored procedures or triggers. The database event triggers the Lambda — no polling, no middleware.

```
New row inserted into RDS → DB trigger → invokes Lambda → send welcome email
                                                        → update search index
                                                        → push notification
```

Supported on **Aurora MySQL** and **Aurora PostgreSQL**. The RDS instance needs a Lambda execution IAM role and network access to the Lambda service (NAT Gateway or VPC endpoint).

Real-world examples:
- Insert a new customer row → Lambda sends a welcome email via SES
- Update a product price → Lambda invalidates the CloudFront cache
- Delete a user → Lambda cleans up related S3 files and Cognito account

This is different from **DynamoDB Streams + Lambda** where changes are captured in a stream. With RDS, the database directly invokes Lambda — no stream in between.

**Lambda and VPC:**

By default, Lambda runs in an AWS-managed network **outside your VPC**. It can access the internet and public AWS services, but cannot reach private resources (RDS, ElastiCache).

```
Default (no VPC):  Lambda → internet ✅ → AWS services ✅ → your VPC ❌
In your VPC:       Lambda → your VPC ✅ → RDS/ElastiCache ✅ → internet ❌ (unless NAT)
```

Once Lambda is in your VPC, it loses internet access. To reach the internet or public AWS services:
- **NAT Gateway** — for internet access (costs money)
- **VPC Endpoints** — for AWS services like S3/DynamoDB without NAT (cheaper)

| Put Lambda in VPC? | When |
| ------------------- | ---- |
| Yes | Lambda needs to access RDS, ElastiCache, or other private resources |
| No | Lambda only calls public AWS services (S3, DynamoDB, SQS) — simpler and faster |

**Exam triggers:**
- *"Lambda can't connect to RDS in a private subnet"* → Lambda not configured in VPC
- *"Lambda in VPC can't reach the internet"* → needs NAT Gateway
- *"Lambda in VPC can't reach S3"* → add a VPC Gateway Endpoint (free)

**Synchronous vs Asynchronous invocation:**

| | Synchronous | Asynchronous |
| - | ----------- | ------------ |
| Caller | Waits for response | Gets 202 immediately, doesn't wait |
| Retries on failure | None — caller handles it | 2 automatic retries |
| Error handling | Response returned to caller | Destinations or DLQ |
| Triggered by | API Gateway, ALB, SDK `Invoke` | S3, SNS, EventBridge, CloudWatch Events |

Async invocations go to an **internal queue** — Lambda processes them when ready. If all retries fail, the event goes to a Destination (success/failure) or DLQ.

**Event Source Mapping (SQS, Kinesis, DynamoDB Streams):**

For queue/stream sources, Lambda **polls** in batches — it's neither sync nor async, it's a third model:

```
SQS queue → Lambda polls → pulls batch of 10 messages → processes → deletes on success
Kinesis stream → Lambda polls → pulls batch of records per shard → processes
```

Key gotcha with **Kinesis/DynamoDB Streams**: if a batch fails, the **entire shard is blocked** — Lambda retries the same batch until it succeeds. No other records from that shard are processed. Fixes:
- **Bisect on error** — split the failed batch in half, retry each half (isolate the bad record)
- **Maximum retry attempts** — give up after N retries, send to a DLQ
- **Skip old records** — discard records older than a threshold

SQS is more forgiving — failed messages return to the queue individually and eventually go to the DLQ.

**Recursive loop protection:**

A common architecture mistake — Lambda triggers itself in an infinite loop:

```
Lambda writes to S3 → S3 event triggers Lambda → Lambda writes to S3 → ...infinite loop ❌
Lambda sends to SQS → SQS triggers Lambda → Lambda sends to SQS → ...infinite loop ❌
```

AWS detects recursive loops between Lambda, SQS, and SNS and **stops them automatically** after ~16 invocations. But S3 → Lambda → S3 loops can still rack up charges before detection. Prevention: use a different bucket or prefix for output than input, or check for a flag before processing.

**Exam triggers:**
- *"S3 event triggers Lambda but events are being retried"* → async invocation retries (2 retries default)
- *"Kinesis shard is stuck, no records processing"* → batch failure blocking the shard — enable bisect on error
- *"Lambda costs spiralling unexpectedly"* → check for recursive loop

**Lambda Layers:**

Shared libraries/dependencies packaged separately from your function code. Multiple functions can use the same layer — avoids duplicating dependencies in every deployment package.

**Versions and Aliases:**

- **Version** — an immutable snapshot of your function code + config. `$LATEST` is always the newest.
- **Alias** — a pointer to a version (e.g. `prod` → version 5, `dev` → `$LATEST`). Can split traffic between two versions for canary deployments (e.g. `prod` sends 90% to v5, 10% to v6).

**Lambda Destinations:**

Route the result of an async invocation to another service — on success or failure:

```
Lambda invoked async
├── Success → send result to SQS, SNS, Lambda, or EventBridge
└── Failure → send error to SQS, SNS, Lambda, or EventBridge (for debugging)
```

Better than DLQ — destinations work for both success and failure, DLQ only handles failures.

**Exam triggers:**
- *"run code without managing servers"* → Lambda
- *"process takes longer than 15 minutes"* → NOT Lambda (use ECS/Fargate, Step Functions, or Batch)
- *"eliminate cold starts"* → Provisioned Concurrency
- *"one Lambda function is starving others of concurrency"* → Reserved Concurrency
- *"canary deployment for a Lambda function"* → Aliases with traffic splitting
- *"share dependencies across multiple Lambda functions"* → Lambda Layers

### DynamoDB

Fully managed **NoSQL** database — serverless, single-digit millisecond latency at any scale.

**Key concepts:**

- **Table** — a collection of items (like rows)
- **Item** — a single record (like a row), max 400 KB
- **Primary key** — uniquely identifies each item. Two types:
  - **Partition key** — single attribute (e.g. `user_id`)
  - **Partition key + Sort key** — composite (e.g. `user_id` + `timestamp`) — allows range queries

**Flexible attributes (schema-less) — why items can have different fields:**

Unlike SQL where every row has the same columns, DynamoDB items can have different attributes. In practice, 90% of items often look similar — the flexibility is most useful in three scenarios:

Single-table design (the DynamoDB best practice) — different entity types in one table:

```
PK          | SK        | name    | price | email        | orderDate
PRODUCT#123 | METADATA  | Widget  | 9.99  |              |
USER#456    | PROFILE   |         |       | bob@test.com |
USER#456    | ORDER#789 |         |       |              | 2024-01-15
```

Products have `name`/`price`. Users have `email`. Orders have `orderDate`. Same table, different shapes. In SQL you'd need separate tables with joins.

Optional fields that vary — a product catalog where a t-shirt has `colour`/`size`, a light bulb has `wattage`, a book has `author`. Attributes simply don't exist on items that don't need them — no NULLs, no wasted storage.

Evolving schema — add a new feature with a `loyalty_tier` attribute. New items include it, old items don't. No `ALTER TABLE`, no backfill needed.

**Capacity modes:**

| | Provisioned | On-Demand |
| - | ----------- | --------- |
| Throughput | You specify RCU/WCU | Auto-scales |
| Cost | Cheaper at steady load | More expensive, but no planning |
| Scaling | Auto-scaling available (but you set min/max) | Instant |
| Use case | Predictable traffic | Unpredictable, spiky traffic |

Food business analogy:
- **Provisioned** = a restaurant with a fixed number of tables. You know the dinner rush needs 50 tables. Cheaper per meal, but you pay for empty tables on quiet nights.
- **On-Demand** = a food truck. Some days 10 customers, some days 1,000. You don't predict — DynamoDB scales instantly. More expensive per request but you never pay for idle capacity.

Use Provisioned when traffic is predictable (steady web app). Use On-Demand for spiky or new workloads where you can't forecast traffic. You can switch between modes once every 24 hours.

**Provisioned + Auto Scaling — the middle ground:**

With Provisioned mode, you can enable Auto Scaling on RCU and WCU independently. Set a target utilisation (e.g. 70%) and min/max values:

```
Read:  min 5 RCU, max 100 RCU, target 70% utilisation
Write: min 10 WCU, max 500 WCU, target 70% utilisation
```

Cost benefit of Provisioned (cheaper per unit) with some flexibility (scales up during spikes, down when quiet). The catch: Auto Scaling reacts via CloudWatch alarms — **few minutes delay** before it kicks in. A sudden spike can throttle before scaling catches up.

| | Provisioned (fixed) | Provisioned + Auto Scaling | On-Demand |
| - | ------------------- | -------------------------- | --------- |
| Cost | Cheapest (if you guess right) | Cheap | Most expensive |
| Spike handling | Throttled if over-capacity | Few min delay, then scales | Instant |
| Planning | You set exact RCU/WCU | You set min/max/target | None |

RCU = Read Capacity Unit (4 KB strongly consistent read/s). WCU = Write Capacity Unit (1 KB write/s).

**Indexes:**

| | Global Secondary Index (GSI) | Local Secondary Index (LSI) |
| - | ---------------------------- | --------------------------- |
| When to create | Any time | At table creation only |
| Key | Different partition key + sort key | Same partition key, different sort key |
| Reads | Eventually consistent only | Strongly or eventually consistent |
| Use case | Query by a completely different attribute | Query same partition key with a different sort |

**DynamoDB Streams:**

Captures a time-ordered sequence of item-level changes (insert, update, delete) in a table. Feed changes to Lambda for real-time reactions:

```
DynamoDB table → Stream → Lambda → send welcome email when new user is created
                                 → update search index when product is modified
                                 → replicate data to another table/region
```

Streams is not unique to DynamoDB — the "database change triggers an action" pattern exists everywhere:

| Service | Change capture mechanism |
| ------- | ----------------------- |
| DynamoDB | DynamoDB Streams |
| Aurora/RDS | Invoke Lambda from DB trigger (Aurora only) |
| Kinesis | Kinesis Data Streams |
| S3 | S3 Event Notifications |
| MongoDB | Change Streams |
| PostgreSQL | Logical replication / WAL |
| Kafka | Topics |

DynamoDB Streams' advantage on AWS: tight Lambda integration — change in the table automatically invokes Lambda with the old and new item image. Zero polling code.

**DynamoDB Accelerator (DAX):**

In-memory cache **specifically for DynamoDB** — sits in front of your table, caches reads. Microsecond response times vs milliseconds.

```
Without DAX: App → DynamoDB (5ms)
With DAX:    App → DAX (0.1ms, cache hit) or → DynamoDB (5ms, cache miss)
```

**DAX vs ElastiCache:** DAX is for DynamoDB only, no code changes needed (same API). ElastiCache is general-purpose caching for any data source but requires code changes.

**DynamoDB Global Tables:**

Multi-region, multi-active replication. Write to any region, changes replicate to all others. Requires DynamoDB Streams enabled.

- Use case: global app where users in any region need low-latency reads AND writes
- Different from Aurora Global Database — Aurora is active-passive (one writer), DynamoDB Global Tables is active-active (write anywhere)

**WCU and RCU calculations (exam favourite):**

| Unit | What it means |
| ---- | ------------- |
| 1 WCU | 1 write/second for an item up to 1 KB |
| 1 RCU | 1 strongly consistent read/second for an item up to 4 KB |
| 1 RCU | 2 eventually consistent reads/second for an item up to 4 KB |

Examples:
- Write 10 items/second, each 2 KB → 10 × 2 = **20 WCU** (each item rounds up to 2 KB)
- Write 6 items/second, each 4.5 KB → 6 × 5 = **30 WCU** (4.5 rounds up to 5 KB)
- Read 10 items/second, each 4 KB, strongly consistent → 10 × 1 = **10 RCU**
- Read 10 items/second, each 4 KB, eventually consistent → 10 × 0.5 = **5 RCU** (half the cost)

**The formula:**

```
WCU = (items/sec) × CEILING(item_size_KB / 1)
RCU (strong)     = (items/sec) × CEILING(item_size_KB / 4)
RCU (eventually) = (items/sec) × CEILING(item_size_KB / 4) / 2
```

Eventually consistent reads are **half the cost** — use them unless your app needs the latest data.

**Partition key design — hot partitions:**

Same problem as Kinesis hot shards. DynamoDB distributes data across partitions by hashing the partition key. If one key gets disproportionate traffic, that partition is overwhelmed.

```
partition_key = "date" → every item today hits the same partition → throttled ❌
partition_key = "user_id" → millions of unique values → even distribution ✅
```

Fix: choose a partition key with **high cardinality** (many unique values). If you must use a low-cardinality key (e.g. date), add a random suffix: `2024-01-15#3` to spread writes across partitions.

**DynamoDB TTL (Time to Live):**

Automatically delete expired items at no cost — no WCU consumed for TTL deletions.

You define a TTL attribute (e.g. `expires_at`) with a Unix epoch timestamp. DynamoDB deletes items after the timestamp passes (usually within 48 hours — not instant).

Real-world examples:
- Session tokens — expire after 24 hours, auto-deleted
- Shopping carts — abandon after 7 days, auto-cleaned
- Temporary tokens (OTP, password reset) — expire after 15 minutes

Deleted items can be captured by DynamoDB Streams → Lambda for post-deletion actions (audit log, cleanup).

**DynamoDB Transactions:**

All-or-nothing operations across multiple items/tables. Either everything succeeds or everything rolls back.

```
Transfer money:
  1. Debit account A: -$100  ┐
  2. Credit account B: +$100 ┘ → both succeed or both fail (transaction)
```

- **TransactWriteItems** — up to 100 write actions in one transaction
- **TransactGetItems** — up to 100 read actions (consistent snapshot)
- Costs **2x WCU/RCU** — DynamoDB does a prepare + commit under the hood

Use case: financial transactions, inventory management, anything where partial writes corrupt data.

**Conditional Writes:**

Write only if a condition is met — prevents race conditions without transactions.

```
Update item SET stock = stock - 1 WHERE stock > 0
```

If stock is already 0, the write is rejected. No read-then-write race condition. Cheaper than transactions when you only need to protect a single item.

**DynamoDB Export to S3:**

Export your entire table to S3 as JSON or Apache Ion format — without consuming any RCU. Runs against the continuous backups (Point-in-Time Recovery must be enabled).

Use case: run analytics on DynamoDB data without impacting the live table. Export to S3 → query with Athena or load into Redshift.

**Exam triggers:**
- *"serverless NoSQL database"* → DynamoDB
- *"single-digit millisecond latency at any scale"* → DynamoDB
- *"microsecond read latency for DynamoDB"* → DAX
- *"react to changes in a DynamoDB table"* → DynamoDB Streams + Lambda
- *"multi-region active-active database"* → DynamoDB Global Tables
- *"unpredictable traffic on a NoSQL database"* → DynamoDB On-Demand
- *"schema-less, flexible data model"* → DynamoDB
- *"need complex joins and relationships"* → NOT DynamoDB, use RDS
- *"automatically delete expired data"* → DynamoDB TTL
- *"all-or-nothing writes across multiple items"* → DynamoDB Transactions
- *"prevent overselling inventory"* → Conditional Writes
- *"analyse DynamoDB data without impacting the table"* → Export to S3 + Athena
- *"calculate RCU/WCU"* → remember: eventually consistent reads are half the cost

### API Gateway

Managed service for creating, publishing, and securing REST/HTTP APIs. The front door for your serverless backend.

```
Client → API Gateway → Lambda → DynamoDB
                     → any HTTP endpoint
                     → any AWS service
```

**Two types:**

| | REST API | HTTP API |
| - | -------- | -------- |
| Features | Full-featured — caching, request validation, WAF, API keys, usage plans | Simpler — fewer features |
| Cost | More expensive | 70% cheaper |
| Latency | Higher | Lower |
| Use case | Enterprise APIs needing all features | Simple APIs, Lambda proxies |

**Key features:**

- **Stages** — deploy different versions (dev, staging, prod) with separate URLs
- **Throttling** — rate limiting per API or per client (API keys + usage plans)
- **Caching** — cache responses at the API Gateway level to reduce Lambda invocations
- **Request/response transformation** — modify payloads without changing Lambda code
- **CORS** — configure cross-origin access
- **Authorisation** — IAM, Lambda authoriser (custom auth logic), or Cognito

**API Gateway + Lambda — the serverless pattern:**

API Gateway handles routing, throttling, auth, and caching. Lambda handles business logic. Neither requires servers.

**Exam triggers:**
- *"create a serverless REST API"* → API Gateway + Lambda
- *"throttle API requests per client"* → API Gateway usage plans + API keys
- *"reduce Lambda invocations for repeated requests"* → API Gateway caching
- *"cheapest API for a simple Lambda proxy"* → HTTP API (not REST API)
- *"custom authentication logic for an API"* → Lambda authoriser

### Step Functions

Visual **workflow orchestrator** — coordinate multiple Lambda functions (and other AWS services) into a sequence with branching, retries, error handling, and parallelism.

**The problem it solves:** a Lambda function has a 15-minute timeout. Complex workflows (order processing, ETL pipelines, ML training) need multiple steps that together take much longer.

```
Step Functions workflow:
  Start → Validate order (Lambda, 5s)
        → Process payment (Lambda, 10s)
        → Reserve inventory (Lambda, 3s)
        ├── Success → Ship order (Lambda, 5s) → Notify customer (SNS)
        └── Failure → Refund payment (Lambda, 10s) → Notify support (SNS)
```

**Key features:**

- **Visual workflow** — see the execution flow in the AWS console
- **Built-in error handling** — retry, catch, timeout per step
- **Parallel execution** — run steps concurrently
- **Wait states** — pause for a specified time or until a signal
- **Human approval** — pause workflow until someone approves
- **Max execution time:** 1 year (Standard) or 5 minutes (Express)

**Two workflow types:**

| | Standard | Express |
| - | -------- | ------- |
| Duration | Up to 1 year | Up to 5 minutes |
| Execution model | Exactly-once | At-least-once |
| Cost | Per state transition | Per execution + duration |
| Use case | Long-running workflows, human approval | High-volume event processing (IoT, streaming) |

**Exam triggers:**
- *"orchestrate multiple Lambda functions"* → Step Functions
- *"workflow needs error handling and retries"* → Step Functions
- *"process takes longer than 15 minutes"* → Step Functions (or ECS/Batch)
- *"workflow requires human approval"* → Step Functions with wait for callback
- *"visual workflow designer"* → Step Functions

### Amazon Cognito

Managed **user authentication** — add sign-up, sign-in, and access control to your web/mobile app without building an auth system.

**Two components:**

**User Pools — authentication (who are you?):**

- Managed user directory — sign-up, sign-in, password reset, MFA
- Supports social login (Google, Facebook, Apple) and SAML/OIDC (corporate identity providers)
- Returns a **JWT token** after login — your API verifies this token
- Integrates with API Gateway as an authoriser

```
User → sign in → Cognito User Pool → JWT token → API Gateway (verifies token) → Lambda
```

**Identity Pools (Federated Identities) — authorisation (what can you access?):**

- Exchanges a token (from User Pool, Google, Facebook, etc.) for **temporary AWS credentials**
- Gives users direct access to AWS services (S3, DynamoDB) without going through an API
- Use case: mobile app uploads photos directly to S3 with temporary credentials

```
User → Cognito User Pool (JWT) → Identity Pool → temporary AWS credentials → S3 direct upload
```

**User Pool vs Identity Pool:**

| | User Pool | Identity Pool |
| - | --------- | ------------- |
| Purpose | Authentication (sign in) | Authorisation (AWS access) |
| Returns | JWT token | Temporary AWS credentials (STS) |
| Use case | "Log in to my app" | "Upload directly to S3 from the browser" |

Often used together: User Pool handles login, Identity Pool grants AWS access.

**Exam triggers:**
- *"add authentication to a web/mobile app"* → Cognito User Pool
- *"social login (Google, Facebook)"* → Cognito User Pool
- *"give users temporary AWS credentials"* → Cognito Identity Pool
- *"mobile app needs to upload directly to S3"* → Cognito Identity Pool
- *"authorise API Gateway requests with user tokens"* → Cognito User Pool as API Gateway authoriser

### Serverless Quick Reference

| Service | What it does |
| ------- | ------------ |
| Lambda | Run code on demand, pay per invocation |
| DynamoDB | NoSQL database, single-digit ms latency |
| API Gateway | Managed REST/HTTP APIs |
| S3 | Object storage |
| SNS/SQS | Messaging |
| Kinesis Data Firehose | Streaming delivery to S3/Redshift |
| Step Functions | Workflow orchestration |
| Cognito | User authentication and authorisation |
| Aurora Serverless | Relational DB that scales to zero |
| Fargate | Serverless containers |

All of these are serverless — no instances to manage, pay for what you use, auto-scale.
