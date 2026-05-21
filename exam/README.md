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
- [VPC and Networking](#vpc-and-networking)
  - [VPC Fundamentals](#vpc-fundamentals)
  - [Subnets](#subnets)
  - [Internet Gateway (IGW)](#internet-gateway-igw)
  - [NAT Gateway vs NAT Instance](#nat-gateway-vs-nat-instance)
  - [Route Tables](#route-tables)
  - [Security Groups](#security-groups)
  - [NACLs (Network ACLs)](#nacls-network-acls)
  - [Security Groups vs NACLs](#security-groups-vs-nacls)
  - [VPC Endpoints](#vpc-endpoints)
  - [ENI-backed vs Public Endpoint Services](#eni-backed-vs-public-endpoint-services)
  - [VPC Peering](#vpc-peering)
  - [Transit Gateway](#transit-gateway)
  - [PrivateLink](#privatelink)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [Direct Connect and Site-to-Site VPN](#direct-connect-and-site-to-site-vpn)
  - [VPC Anti-patterns (exam wrong answers)](#vpc-anti-patterns-exam-wrong-answers)
  - [VPC Exam Triggers](#vpc-exam-triggers)
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
  - [Caching Strategies](#caching-strategies)
  - [Redis vs DynamoDB](#redis-vs-dynamodb)
- [DocumentDB and Neptune](#documentdb-and-neptune)
  - [DocumentDB — anchored in Redis](#documentdb--anchored-in-redis)
  - [Neptune — anchored in Redis](#neptune--anchored-in-redis)
  - [Comparison — Redis vs DocumentDB vs Neptune](#comparison--redis-vs-documentdb-vs-neptune)
  - [Picking between RDS, Aurora, DynamoDB, DocumentDB, Neptune](#picking-between-rds-aurora-dynamodb-documentdb-neptune)
  - [Common anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers)
  - [Exam triggers](#exam-triggers)
- [Other Managed Databases](#other-managed-databases)
  - [Amazon Keyspaces (Cassandra-compatible)](#amazon-keyspaces-cassandra-compatible)
  - [Amazon MemoryDB for Redis](#amazon-memorydb-for-redis)
  - [Amazon Timestream](#amazon-timestream)
- [AWS Database Migration Service (DMS) and Schema Conversion Tool (SCT)](#aws-database-migration-service-dms-and-schema-conversion-tool-sct)
  - [What DMS Does](#what-dms-does)
  - [Homogeneous vs Heterogeneous Migrations](#homogeneous-vs-heterogeneous-migrations)
  - [AWS Schema Conversion Tool (SCT)](#aws-schema-conversion-tool-sct)
  - [Replication Instance Sizing](#replication-instance-sizing)
  - [When DMS Is Not the Answer](#when-dms-is-not-the-answer)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers)
  - [Exam Triggers](#exam-triggers)
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
  - [When Not to Use S3](#when-not-to-use-s3)
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
  - [When People Reach for Redshift](#when-people-reach-for-redshift)
  - [OLTP vs OLAP](#oltp-vs-olap)
  - [Why Not RDS for Analytics?](#why-not-rds-for-analytics)
  - [Why Load into Redshift Instead of Querying S3?](#why-load-into-redshift-instead-of-querying-s3)
  - [Redshift Key Properties](#redshift-key-properties)
  - [Loading Data into Redshift](#loading-data-into-redshift)
  - [Redshift vs Athena](#redshift-vs-athena)
  - [Redshift Snapshots](#redshift-snapshots)
- [Amazon Athena](#amazon-athena)
  - [Key Properties](#key-properties)
  - [The Cost Model — Why File Format Matters](#the-cost-model--why-file-format-matters)
  - [Athena vs Redshift Spectrum (close cousins)](#athena-vs-redshift-spectrum-close-cousins)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-1)
  - [Exam Triggers](#exam-triggers-1)
- [Amazon OpenSearch Service](#amazon-opensearch-service)
  - [When OpenSearch, Anchored in What You Know](#when-opensearch-anchored-in-what-you-know)
  - [Key Properties](#key-properties-1)
  - [Classic Use Cases](#classic-use-cases)
  - [OpenSearch vs CloudWatch Logs Insights](#opensearch-vs-cloudwatch-logs-insights)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-2)
  - [Exam Triggers](#exam-triggers-2)
- [Serverless](#serverless-1)
  - [AWS Lambda](#aws-lambda)
  - [DynamoDB](#dynamodb)
  - [API Gateway](#api-gateway)
  - [Step Functions](#step-functions)
  - [Amazon Cognito](#amazon-cognito)
  - [Microservices](#microservices)
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

## VPC and Networking

A **VPC (Virtual Private Cloud)** is your own isolated network inside an AWS region. You define the IP address range, carve it into subnets, control routing, and decide what can talk to what. Almost every AWS service either lives **inside** a VPC (EC2, RDS, ALB) or is a **public API** you call from a VPC (S3, DynamoDB, SQS, SNS).

Understanding which is which is the single biggest source of "why doesn't this work?" on the exam.

### VPC Fundamentals

- **Regional** — a VPC lives in one AWS region. To span regions, peer VPCs together or use Transit Gateway.
- **CIDR block** — define the IP range (e.g. `10.0.0.0/16`). Allowed sizes: `/16` (65k IPs) down to `/28` (16 IPs).
- **Default VPC** — every region has one pre-created, with public subnets in each AZ. Fine for experiments, not for production.
- **AWS reserves 5 IPs per subnet** — `.0` (network), `.1` (VPC router), `.2` (DNS), `.3` (future use), `.255` (broadcast). A `/28` subnet has 16 IPs but only 11 are usable.

### Subnets

A subnet is a slice of the VPC's CIDR, **scoped to one Availability Zone**.

```
VPC: 10.0.0.0/16 (region: eu-west-1)
├── 10.0.1.0/24 → eu-west-1a (public)
├── 10.0.2.0/24 → eu-west-1b (public)
├── 10.0.10.0/24 → eu-west-1a (private)
└── 10.0.11.0/24 → eu-west-1b (private)
```

**Public vs private is defined by the route table, not by name:**

| | Public subnet | Private subnet |
| - | ------------- | -------------- |
| Route table has `0.0.0.0/0 → IGW` | ✅ | ❌ |
| Resources can have public IPs | ✅ | ❌ (mostly) |
| Can reach internet | ✅ (directly) | Only via NAT Gateway |
| Internet can reach in | ✅ (if SG allows) | ❌ |
| Use for | ALB, NAT Gateway, bastion | RDS, ElastiCache, app servers |

A subnet with **no `0.0.0.0/0` route at all** is **isolated** — no internet in or out. Used for highly sensitive workloads (e.g. databases that should never reach the internet).

### Internet Gateway (IGW)

The IGW is the door between your VPC and the internet. Exactly **one per VPC**, attached to the VPC itself (not a subnet).

```
Public subnet route table:
  10.0.0.0/16  → local      (intra-VPC, always present)
  0.0.0.0/0    → igw-abc123 (this makes it "public")
```

An instance also needs a **public IP** or **Elastic IP** to be reachable from the internet — the IGW alone isn't enough.

### NAT Gateway vs NAT Instance

Private subnets need a way to reach the internet for outbound traffic (package updates, third-party APIs) **without** being reachable inbound. A NAT does the translation.

| | NAT Gateway | NAT Instance |
| - | ----------- | ------------ |
| What it is | Managed AWS service | Regular EC2 instance you manage |
| Scaling | Up to 45 Gbps, automatic | Limited by instance size, manual |
| Patching/HA | AWS handles it | You handle it |
| Cost | ~$0.045/hour + ~$0.045/GB processed | EC2 hourly + data |
| AZ scope | Single AZ — needs one per AZ for HA | Single AZ |
| Use | Default choice | Legacy, cost-optimisation in dev |

**The HA trap:** a NAT Gateway lives in **one AZ**. If you put all private subnets through a single NAT Gateway in `eu-west-1a` and that AZ fails, private subnets in `eu-west-1b` also lose internet (they were routing through the dead NAT). **Fix:** one NAT Gateway per AZ, each private subnet routes to its own AZ's NAT.

```
Multi-AZ NAT setup:
  Private subnet in 1a → NAT GW in 1a → IGW
  Private subnet in 1b → NAT GW in 1b → IGW   ← independent failure domains
```

### Route Tables

Each subnet is associated with **one route table**. Routes are evaluated **most-specific first**.

```
Destination       Target
10.0.0.0/16    →  local        ← automatic, can't remove (intra-VPC traffic)
172.16.0.0/16  →  pcx-abc      ← VPC peering
0.0.0.0/0      →  nat-xyz      ← default route to NAT (private subnet)
```

The `local` route to the VPC CIDR is automatic and immutable — that's why subnets in the same VPC can always reach each other.

### Security Groups

- **Stateful** — if you allow inbound, the return traffic is **automatically allowed** out (and vice versa). You don't need a matching outbound rule.
- **Attached to ENIs** — so to EC2 instances, RDS, ElastiCache, ALB/NLB, Lambda-in-VPC, ECS tasks, EFS mount targets, VPC interface endpoints. Anything with a network interface in your VPC.
- **Allow rules only** — there's no "deny" rule. If no rule matches, traffic is dropped.
- **Can reference other SGs by ID** — `allow inbound 3306 from sg-app` means "from anything wearing the app SG", regardless of IP. Cleaner than maintaining IP lists.
- **Default behaviour** — new SGs deny all inbound, allow all outbound.
- **Limits** — up to 5 SGs per ENI; up to 60 inbound + 60 outbound rules per SG (soft).

### NACLs (Network ACLs)

- **Stateless** — you must allow inbound **and** outbound separately. If you only allow inbound on port 443, the response packet (on an ephemeral port) is dropped on the way out unless you also allow that.
- **Attached to subnets** (not ENIs) — every resource in the subnet shares the NACL.
- **Allow AND deny rules** — useful for explicit blocks (e.g. block a known-bad IP range).
- **Rules evaluated in order** — lowest rule number first; first match wins.
- **Default NACL** allows all traffic. **Custom NACLs** start denying everything.

### Security Groups vs NACLs

| | Security Group | NACL |
| - | -------------- | ---- |
| Attached to | ENI (instance) | Subnet |
| Stateful? | Yes — return traffic auto-allowed | No — must allow both directions |
| Rule types | Allow only | Allow + Deny |
| Rule evaluation | All rules evaluated (any allow → permitted) | Ordered, first match wins |
| Reference other SGs | Yes (by SG ID) | No (CIDR only) |
| Default for new | Deny all inbound, allow all outbound | Custom: deny all. Default: allow all |
| Use case | Day-to-day "who can talk to this resource" | Subnet-wide block/allow, deny lists |

**The exam shortcut:** SG is the default tool. NACL is for when you specifically need a **deny** (e.g. block a malicious IP range) or a subnet-wide rule that's independent of per-instance config.

### VPC Endpoints

A VPC Endpoint lets resources in your VPC reach AWS services **without going over the public internet** (no NAT Gateway, no IGW). Two types:

| | Gateway Endpoint | Interface Endpoint |
| - | ---------------- | ------------------ |
| Services | **S3 and DynamoDB only** | Almost every other AWS service (SQS, SNS, Kinesis, Secrets Manager, KMS, etc.) |
| How | Adds a route to your route table | Creates an ENI in your subnet with a private IP |
| Cost | **Free** | ~$0.01/hour per endpoint per AZ + per-GB data |
| DNS | Service uses public DNS, traffic stays private | Endpoint gets a regional DNS name (or enables private DNS to override the public one) |
| Security control | Endpoint policy | Endpoint policy + **security group** (on the ENI) |
| Powered by | Custom routing | PrivateLink |

**Exam shortcut:** "S3 or DynamoDB without going through NAT" → **Gateway endpoint** (free). Anything else → **Interface endpoint**.

### ENI-backed vs Public Endpoint Services

This is the concept that explains "why can't I attach a security group to SQS?" — and the source of many exam traps.

| Service category | Examples | Has ENI in your VPC? | Controlled by |
| ---------------- | -------- | -------------------- | ------------- |
| **ENI-backed** | EC2, RDS, ElastiCache, ALB/NLB, EFS, Lambda-in-VPC, ECS task, VPC interface endpoint | ✅ | **Security groups** + IAM |
| **Public AWS API** | S3, DynamoDB, SQS, SNS, Lambda (default), Kinesis, EventBridge, Step Functions, API Gateway, CloudWatch | ❌ | **IAM + resource policy** — no security groups |

To control network access to a public-API service from your VPC, you don't use a security group on the service — you use a **VPC endpoint** in your VPC, and the SG attaches to the **endpoint**, not the service.

**Anti-patterns:**

- *"Attach a security group to my SQS queue / S3 bucket / SNS topic"* — not possible. These have no ENI. Use IAM + resource policy.
- *"Public IP + tight security group = secure"* — partly true, but the public IP still attracts internet noise (scanners, port-knocking). Putting the resource in a private subnet behind an ALB is stronger.
- *"Use a security group to block a malicious IP"* — SGs are allow-only. Use a NACL or AWS WAF for explicit denies.

### VPC Peering

A 1:1 connection between two VPCs — they can route to each other as if they were one network.

- **CIDRs must not overlap** (no NAT in peering)
- **Cross-region and cross-account** allowed
- **No transitive routing** — if A peered with B, and B peered with C, A **cannot** reach C through B. You'd need a direct A↔C peering.
- Both VPCs must update their **route tables** to point at the peering connection for the other's CIDR.

The transitive routing limit is why peering doesn't scale past a handful of VPCs — N VPCs need N² peerings.

### Transit Gateway

A hub-and-spoke router for many VPCs (and on-prem networks). Solves the N² peering problem.

```
        VPC A ─┐
        VPC B ─┼─→ Transit Gateway ←─→ on-prem (via DX or VPN)
        VPC C ─┘
```

- **Transitive routing** — any spoke can reach any other spoke (if route tables allow).
- **Centralised** — one place to manage routes, security, attachments.
- **Cross-region** peering supported (between two Transit Gateways).
- **Cost** — per-hour attachment fee + per-GB data processed. Expensive at scale, but cheaper than maintaining dozens of peerings.

**Exam shortcut:** "connect many VPCs and on-prem" → Transit Gateway. "Two VPCs" → VPC Peering (cheaper).

### PrivateLink

Expose a service running in **your** VPC to **other** VPCs (or accounts) without peering, without overlapping CIDR concerns, without internet.

```
Provider VPC:    [Your service behind an NLB] → "VPC Endpoint Service"
                                                       ↓
Consumer VPC:    [Interface Endpoint] → reaches your service via private IPs
```

- Provider puts an **NLB** in front of their service and creates a **VPC Endpoint Service**.
- Consumer creates an **Interface Endpoint** that targets the provider's service.
- Traffic stays on the AWS backbone — never traverses the public internet.
- The two VPCs **can have overlapping CIDRs** — PrivateLink doesn't route between them, it just exposes the service.

Use case: SaaS providers exposing their product to customers' VPCs (Snowflake, Datadog, etc. all use PrivateLink).

### VPC Flow Logs

Capture metadata about IP traffic in your VPC. Useful for security forensics, troubleshooting connectivity ("why is this blocked?"), and traffic analysis.

- **Granularity:** VPC, subnet, or ENI
- **Captures:** source/dest IP and port, protocol, bytes, ACCEPT/REJECT
- **Does NOT capture:** packet contents (use a packet mirror for that)
- **Destinations:** CloudWatch Logs, S3, or Kinesis Data Firehose
- **Cost-conscious tip:** ship to S3 with Parquet format and query with Athena — much cheaper than CloudWatch Logs for large volumes.

**Exam triggers:**
- *"why is traffic being blocked between two instances"* → enable VPC Flow Logs, look for REJECT entries
- *"audit which IPs accessed our database"* → VPC Flow Logs on the RDS ENI

### Direct Connect and Site-to-Site VPN

Two ways to connect on-prem to AWS:

| | Site-to-Site VPN | Direct Connect |
| - | ---------------- | -------------- |
| Path | Encrypted tunnel over the **public internet** | **Dedicated physical line** from your data centre to an AWS Direct Connect location |
| Setup time | Minutes | Weeks to months (physical install) |
| Bandwidth | 1.25 Gbps per tunnel | 1, 10, 100 Gbps options |
| Latency | Variable (internet) | Low and consistent |
| Cost | Cheap | Expensive (port fee + data) |
| Encryption | Built in (IPsec) | None by default — add VPN over DX or MACsec for encryption |

**Hybrid pattern:** Direct Connect for production traffic, VPN as a backup if the DX link fails.

### VPC Anti-patterns (exam wrong answers)

- **Attaching security groups to SQS/SNS/S3/DynamoDB** — these don't have ENIs. Use IAM + resource policy, plus VPC endpoints if you need the traffic to stay private.
- **Single NAT Gateway for multi-AZ private subnets** — if that AZ dies, all private subnets lose internet. One NAT per AZ.
- **Interface endpoint for S3** — works but Gateway endpoint is free. Prefer Gateway unless you specifically need PrivateLink behaviour (e.g. on-prem reaching S3 through DX).
- **VPC Peering for 10+ VPCs** — N² problem. Use Transit Gateway.
- **Relying on a tight SG with a public IP** — public IPs still attract noise; private subnet + ALB is stronger.
- **Trying to use NACL deny rules for application-level access control** — too brittle and far from the app. Use SG + IAM + WAF closer to the resource.
- **Putting Lambda in a VPC by default** — only do it if Lambda needs to reach private resources (RDS, ElastiCache). VPC attachment loses internet access (unless NAT) and adds cold-start cost.

### VPC Exam Triggers

- *"keep S3 traffic off the public internet"* → S3 Gateway VPC endpoint (free)
- *"keep traffic to other AWS services off the public internet"* → Interface VPC endpoint
- *"why can't I attach a security group to SQS / SNS / S3"* → no ENI; use IAM + resource policy
- *"private subnet instances need internet for package updates"* → NAT Gateway
- *"NAT Gateway is a single point of failure"* → one NAT per AZ
- *"connect 20 VPCs and on-prem"* → Transit Gateway
- *"connect two VPCs with non-overlapping CIDRs"* → VPC Peering
- *"why is traffic blocked between two instances"* → VPC Flow Logs (look for REJECT)
- *"on-prem to AWS with consistent low latency"* → Direct Connect
- *"on-prem to AWS, fast to set up, encrypted"* → Site-to-Site VPN
- *"expose my VPC-hosted SaaS to customer VPCs"* → PrivateLink (NLB + VPC Endpoint Service)
- *"block a malicious IP range across the whole subnet"* → NACL deny rule (SGs are allow-only)

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

**The complete ECS on EC2 scaling chain:**

```
1. CloudWatch detects high CPU across tasks → fires alarm
2. ECS Service Auto Scaling reacts → "add more tasks"
3. ECS tries to place new tasks on existing instances
4. No room → Capacity Provider instructs ASG to add instances
5. ASG launches new EC2 instances → join ECS cluster
6. New tasks placed on new instances ✅
```

Important: CPUs don't trigger task scaling directly — **CloudWatch** watches CPU, fires an alarm, and the scaling policy reacts. And the ASG doesn't decide to scale on its own — it receives instructions from the **Capacity Provider**.

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

**IAM database authentication — the details:**

Instead of storing a database password, the application asks AWS STS for a **short-lived token** and uses it as the password.

```
App (IAM role)  ──→  aws rds generate-db-auth-token ──→  token (valid 15 min)
                ──→  connect to RDS using user + token as password
```

- Token is **valid for 15 minutes** — rotates automatically every call
- Auth uses **AWS Signature V4** under the hood (your IAM credentials sign the request)
- **TLS is enforced** — IAM auth cannot be used over an unencrypted connection
- Throughput limit: ~200 connections/sec per instance with IAM auth — fine for Lambda spawning many short connections, can be a bottleneck for heavy concurrent connection workloads (use RDS Proxy in front to pool connections)

**Use cases:**
- **Lambda → RDS** — Lambda's IAM role generates the token; no secret to ship in the code
- **Apps running on EC2/ECS** with an instance/task role
- **Anywhere you'd rather not store a database password**

**Anti-pattern:** generating a fresh token on every query → throttling. Cache the token for its 15-minute lifetime.

**Secrets Manager rotation for RDS / Aurora:**

Store the database credentials in **AWS Secrets Manager**, and have it **automatically rotate** them on a schedule (e.g. every 30 days). Rotation is performed by an AWS-managed Lambda function for RDS/Aurora — you don't write the rotation code.

```
App  →  GetSecretValue (Secrets Manager)  →  current password
        Secrets Manager (every 30 days)   →  triggers Lambda
                                          →  Lambda generates new password
                                          →  updates RDS user
                                          →  updates the secret
                                          →  app picks up the new value next call
```

**Two rotation strategies (the exam-relevant nuance):**

| Strategy | How | Use when |
| -------- | --- | -------- |
| **Single-user rotation** | One DB user; rotation changes its password. Brief moment where old/new password coexist | Simple, default |
| **Alternating users rotation** (recommended for production) | Two DB users (`app_user` + `app_user_clone`); each rotation flips between them. Old password remains valid until next rotation — zero connection breakage | Production where any password-change race must be avoided |

| | Parameter Store (SSM) | Secrets Manager |
| - | --------------------- | --------------- |
| Stores secrets | Yes (SecureString) | Yes |
| Automatic rotation | No (you build it) | **Yes — built-in for RDS/Aurora/Redshift/DocumentDB** |
| Cost | Cheaper (free for Standard) | More expensive (~$0.40/secret/month) |
| Use case | Static config, infrequently rotated secrets | RDS credentials, anything needing scheduled rotation |

**Anti-patterns:**

- **Storing the DB password in env vars or code** — use Secrets Manager (or IAM auth for short-lived apps).
- **Storing RDS credentials in Parameter Store and expecting auto-rotation** — Parameter Store doesn't rotate. Use Secrets Manager for credentials, Parameter Store for static config.
- **Using IAM auth for a long-lived high-concurrency connection workload without RDS Proxy** — token generation rate limit can bite. Put Proxy in front.

**Exam triggers:**
- *"automatically rotate RDS credentials every N days"* → **Secrets Manager** (built-in rotation Lambda)
- *"rotate the database password without any downtime"* → Secrets Manager with **alternating users** strategy
- *"app should authenticate to RDS without a stored password"* → **IAM database authentication**
- *"Lambda connecting to RDS, want short-lived credentials"* → IAM database authentication
- *"cheaper way to store database connection string that doesn't need rotation"* → Parameter Store
- *"credential rotation breaking app connections"* → switch from single-user to alternating-users rotation

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

**Aurora Serverless v1 vs v2:**

Aurora Serverless auto-scales compute (ACU = Aurora Capacity Unit ≈ 2 GB RAM + matching CPU). Two generations exist; **v1 is deprecated** (end of life announced) — assume **v2** unless a question specifically references v1.

| | Aurora Provisioned | Aurora Serverless v1 (deprecated) | **Aurora Serverless v2** |
| - | ------------------ | --------------------------------- | ------------------------ |
| Compute | Fixed instance size | Auto-scales in big steps | Auto-scales in **0.5 ACU increments**, sub-second |
| Scale to zero | No | Yes — fully pauses | Scales to a configurable minimum (0.5 ACU); can scale to zero on supported engines |
| Cold-start latency on resume | N/A | Seconds — measurable cold start | Near-instant (always-on minimum) |
| Mixing with provisioned in same cluster | No | No | **Yes** — v2 readers alongside provisioned writers |
| Read replicas | Limited | Limited | Up to 15 |
| Global Database support | No | No | **Yes** |
| Cost model | Pay for instance 24/7 | Pay per ACU-second + per-request | Pay per ACU-second |
| Use case | Steady, predictable workloads | Legacy only | **Default for variable workloads** |

**Exam triggers:**
- *"Aurora with auto-scaling compute for unpredictable workloads"* → Aurora Serverless v2
- *"Aurora Serverless that supports Global Database"* → v2 only (v1 doesn't)
- *"sub-second scaling response, no cold starts"* → Aurora Serverless v2
- *"dev/test database that should pause when idle"* → Aurora Serverless v2 (or v1 for full pause)

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

**Aurora Backtrack (Aurora MySQL only):**

**Rewind the database in-place** to a point in the past — no restore from snapshot, no new instance. Aurora keeps a change log of writes; Backtrack replays the log backward.

```
12:00  Application is healthy
12:30  Engineer runs UPDATE without a WHERE clause — corrupts table
12:35  Run Backtrack to 12:29 → table is restored, cluster keeps running
```

| | Snapshot restore | Aurora Clone | **Backtrack** |
| - | ---------------- | ------------ | ------------- |
| What happens | New instance created from snapshot | New live instance, copy-on-write | **Same instance**, rewound in place |
| Speed | Minutes to hours | Seconds | Seconds |
| Loses data after the target time | No (snapshot is older) | No | **Yes** — all writes after the target are gone |
| Available on | All RDS engines | Aurora MySQL + PostgreSQL | **Aurora MySQL only** |
| Use case | Disaster recovery, cross-region | Dev/test copy | Undo a recent operator mistake |

**Window:** up to **72 hours** of backtrack history (configurable). Storage cost scales with the change-log size.

**Exam triggers:**
- *"undo a recent destructive operation without creating a new instance"* → Aurora Backtrack
- *"rewind the database to a point in time, same instance"* → Aurora Backtrack
- *"point-in-time recovery, Aurora PostgreSQL"* → restore from snapshot (Backtrack is MySQL only)

**Babelfish for Aurora PostgreSQL:**

A translation layer that lets **SQL Server clients (T-SQL, TDS wire protocol)** talk to Aurora PostgreSQL **without changing application code**. The app thinks it's connecting to SQL Server; Babelfish translates T-SQL to PostgreSQL and SQL Server tabular results back.

```
Existing SQL Server app  ─── T-SQL + TDS ──→  Babelfish  ─── PostgreSQL ──→  Aurora Postgres
(unchanged)                                    (translator)                   (real engine)
```

Use case: migrating SQL Server workloads off expensive licenses without rewriting application code. Caveat: not 100% T-SQL compatible — some advanced SQL Server features (CLR procedures, certain XML functions, MERGE quirks) don't translate.

**Exam triggers:**
- *"migrate SQL Server workload to Aurora without rewriting the application"* → Babelfish for Aurora PostgreSQL
- *"reduce SQL Server licensing costs while keeping the app unchanged"* → Babelfish
- *"open-source database that speaks the SQL Server wire protocol"* → Babelfish

**Aurora I/O-Optimized storage:**

Aurora bills I/O **per request** by default — fine for low-traffic apps, expensive for I/O-heavy workloads. **I/O-Optimized** is a storage class where you pay more per GB but **I/O is free**.

| | Aurora Standard (default) | Aurora I/O-Optimized |
| - | ------------------------- | -------------------- |
| Storage cost | Lower per GB | ~125% higher per GB |
| I/O cost | Per request | **Free** |
| Break-even | I/O bill is < 25% of total | I/O bill is > 25% of total |
| Use case | Most workloads | I/O-heavy, predictable cost |

Switch with one setting. AWS recommends I/O-Optimized when I/O accounts for more than 25% of your Aurora bill — typical for write-heavy or large-scan workloads.

**Exam trigger:** *"reduce Aurora costs for an I/O-heavy workload with predictable monthly billing"* → Aurora I/O-Optimized.

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

### Caching Strategies

Picking *the right cache* is only half the problem — picking *the right strategy for talking to it* determines whether you actually get faster, cheaper, or staler results. Four patterns show up on the exam.

**Lazy Loading (Cache-Aside) — the default:**

The app talks to both the cache and the database. On miss, it populates the cache.

```
Read:
  1. App → Cache: GET user:42
  2. Cache miss → App → DB: SELECT * FROM users WHERE id=42
  3. App → Cache: SET user:42 = {...} with TTL
  4. Return to caller
Write:
  App → DB only. Cache is not updated on write.
```

- **Pros:** only cache what's actually requested (cheap); cache failure doesn't break writes; survives stale data via TTL
- **Cons:** **3 round trips on a miss**; stale data is possible if you write to the DB without invalidating
- **Use when:** read-heavy, miss rate acceptable, stale data tolerable for the TTL window

**Write-Through — write goes to cache + DB together:**

Every write updates the cache and the database in the same operation.

```
Write:
  1. App → Cache: SET user:42 = {...}
  2. App → DB:    UPDATE users SET ... WHERE id=42
Read:
  1. App → Cache: GET user:42 (always populated)
```

- **Pros:** cache is always fresh; reads are always a hit (for keys that have been written)
- **Cons:** **writes are slower** (two writes); cache holds data that may never be read (wasted memory); on cache cold-start, no data unless you pre-warm
- **Use when:** writes are infrequent vs reads, freshness matters, you can afford the write latency

**Write-Behind / Write-Back — async DB write:**

The app writes only to the cache; the cache asynchronously batches writes to the database.

```
Write:
  1. App → Cache: SET order:abc = {...}
  2. Cache → DB (later, in batches): INSERT INTO orders ...
```

- **Pros:** very fast writes; DB sees batched, smoothed traffic
- **Cons:** **risk of data loss** if the cache fails before flushing; consistency window between cache and DB; complex to implement
- **Use when:** ingest spikes where DB can't keep up *and* losing some recent writes is acceptable; rarely the right exam answer

**Read-Through — cache handles the miss for you:**

The application only ever talks to the cache. The cache itself fetches from the DB on a miss. (Conceptually similar to lazy loading but the cache, not the app, does the DB call.)

```
App → Cache: GET user:42
  ├── hit  → return value
  └── miss → cache calls DB, stores result, returns to app
```

- **Pros:** simpler app code (one client); cache loader is centralised
- **Cons:** initial miss still slow; needs a cache that supports it (e.g. DAX is read-through for DynamoDB; Redis isn't natively read-through but libraries can add it)
- **DAX is the canonical AWS read-through cache** — drop-in for the DynamoDB SDK

**Side-by-side:**

| | Lazy Loading | Write-Through | Write-Behind | Read-Through |
| - | ------------ | ------------- | ------------ | ------------ |
| Cache miss path | App → DB → cache | N/A (always populated) | N/A | Cache → DB → cache |
| Write path | DB only | Cache + DB synchronously | Cache only (DB async) | DB only |
| Freshness | Stale until TTL | Always fresh | Eventually consistent | Stale until TTL |
| Risk of data loss | None | None | **Yes** (cache fails before flush) | None |
| Write latency | Fast (DB only) | Slow (cache + DB) | Fastest | Fast |
| Wasted cache memory | Low (demand-driven) | High (writes-rarely-read) | Moderate | Low |
| Typical exam answer | "default cache pattern" | "data must always be fresh in cache" | rarely correct | "DynamoDB cache with no code changes" → DAX |

**TTL strategy — the often-missed trade-off:**

- **Short TTL** (seconds–minutes) — fresh data but more cache misses, more DB load
- **Long TTL** (hours–days) — fewer misses but staler data
- **No TTL** — only safe with explicit invalidation on writes (write-through pattern)
- **Per-key TTL** — different freshness for different data: user profile (1h), product price (5min), session (30min)

**Cache invalidation patterns:**

- **TTL-based** — simplest, accept staleness up to TTL
- **Write-through** — cache is updated on every write, never stale
- **Explicit invalidation** — on write, `DEL` the cache key (lazy loading + explicit invalidation is a common middle ground)
- **Event-driven invalidation** — DynamoDB Stream / RDS event → Lambda → invalidate Redis key

**Common anti-patterns (exam wrong answers):**

- **Lazy loading with no TTL or invalidation** — data drifts stale forever. Always set a TTL.
- **Write-through with a cache that doesn't survive failures** — if the cache loses data, the DB still has it (write-through doesn't lose data) but cold start is brutal. Use Redis with replicas, or accept the cold-start cost.
- **Write-behind for critical writes** — order placements, payments, audit logs. If the cache fails mid-flush, data is gone. Use write-through or write directly to DB with cache invalidation.
- **Picking Redis when the question describes "no code changes to cache DynamoDB"** → DAX (read-through, drop-in).
- **Caching for write-heavy workloads** — caches accelerate reads, not writes. If writes dominate, focus on database write capacity (Aurora write throughput, DynamoDB on-demand) instead.

**Exam triggers:**

- *"default caching pattern, app reads from cache, falls back to DB"* → **Lazy loading**
- *"cache must always reflect the latest data"* → **Write-through**
- *"cache fresh writes without slowing the write path, can lose data"* → **Write-behind**
- *"cache for DynamoDB with no code changes"* → **DAX** (read-through)
- *"prevent stale data with minimal effort"* → short TTL
- *"reduce DB load for repeated reads"* → lazy loading with reasonable TTL

### Redis vs DynamoDB

Both are key/value-ish, both single-digit ms latency, both managed by AWS — but they solve fundamentally different problems. Redis is a **cache** (with extras); DynamoDB is a **durable system of record**.

| | ElastiCache Redis | DynamoDB |
| - | ----------------- | -------- |
| What it is | In-memory data store | Disk-backed (SSD) NoSQL database |
| Primary role | Cache + specialised data structures | Durable storage |
| Latency | Sub-millisecond | 1–10 ms (sub-ms with DAX) |
| Durability | Optional (RDB snapshots, AOF) — treat as volatile by default | Durable by default, 3-AZ replication |
| Capacity | Limited by **RAM** | Effectively unlimited storage |
| Scaling | Vertical + sharding via cluster mode | Horizontal, auto-sharded, invisible |
| Serverless? | Provisioned by default (Redis Serverless exists) | Serverless by default (on-demand or provisioned) |
| Data model | Strings, lists, sets, **sorted sets**, hashes, streams, geo, pub/sub | Key/value or document items up to 400 KB |
| Multi-region | Global Datastore (one-way, primary region) | Global Tables (active-active) |
| Auth | AUTH token, Redis ACLs, security groups | **IAM only** (no SGs — public API) |
| Pricing | Per node-hour | Per RCU/WCU or per request + storage |

**Use Redis when:**

- **Caching** — read-through / write-through in front of RDS or DynamoDB
- **Session store** — fast, losing a session is acceptable
- **Leaderboards / top-N** — sorted sets do this in O(log N); DynamoDB can't
- **Real-time counters** — atomic `INCR` is built in
- **Rate limiting** — counter + TTL per user/IP
- **Distributed locks** — Redlock pattern
- **Pub/sub** between app processes (for AWS-native fan-out use SNS)
- Working set comfortably fits in RAM

**Use DynamoDB when:**

- **System of record** — durable storage for orders, users, events
- **Massive scale** — terabytes+ with no capacity planning
- **Serverless app** — pay-per-request, no nodes to size
- **Multi-region active-active** — Global Tables
- **Predictable single-digit-ms latency at any scale**
- **Streams + Lambda** for change capture
- **TTL auto-expiry** of items

**Use both together — the common pattern:**

```
Read path:  App → Redis (hit? return)
                → DynamoDB (miss → query → write to Redis → return)
Write path: App → DynamoDB (always) → optionally invalidate Redis key
```

If you're caching DynamoDB *specifically*, **DAX** is usually a better fit than Redis — microsecond reads, no client code changes, write-through automatic. Redis is more flexible (any data structure, any data source) but you manage cache invalidation.

**DAX vs Redis as a DynamoDB cache:**

| | DAX | ElastiCache Redis |
| - | --- | ----------------- |
| What it caches | DynamoDB only | Anything (you control it) |
| Code changes | None — DAX client drops in for the DynamoDB SDK | Yes — explicit GET/SET around DDB calls |
| Cache invalidation | Automatic on write | You manage it |
| Data structures | Item cache + query cache | Sorted sets, lists, pub/sub, etc. |
| Use when | Caching DynamoDB reads with minimal effort | Need sorted sets, multi-source cache, or pub/sub |

**Common anti-patterns (exam wrong answers):**

- **Redis as the durable system of record for critical data** — it's a cache. If the node fails before a snapshot, data is gone. Use DynamoDB or RDS for durability.
- **DynamoDB for real-time top-N leaderboards** — Scan/Query won't give you O(log N) ranking. Redis sorted sets do.
- **Redis with persistence disabled, then surprised when data is missing after a restart** — Redis is volatile by default. Enable RDB/AOF if you need recovery, or accept the loss.
- **Caching DynamoDB with Redis when DAX would do** — DAX is no-code, write-through. Pick Redis only if you need more than DAX provides.
- **Attaching a security group to DynamoDB** — public API, no ENI. Use IAM + VPC interface endpoint.
- **Using DynamoDB as a queue** — possible (TTL + Streams) but SQS is the right answer. Same anti-pattern with Redis lists — use SQS.

**Exam triggers:**

- *"sub-millisecond latency"* → Redis
- *"real-time leaderboard / top-N"* → Redis sorted sets
- *"session store, fast"* → ElastiCache Redis
- *"durable serverless NoSQL with predictable latency"* → DynamoDB
- *"unlimited storage, single-digit ms"* → DynamoDB
- *"global active-active database"* → DynamoDB Global Tables
- *"cache for DynamoDB with minimal code changes"* → DAX
- *"distributed lock"* → Redis (Redlock)
- *"pub/sub between app processes"* → Redis pub/sub (or SNS for AWS-native fan-out)
- *"key/value store, pay-per-use"* → DynamoDB on-demand

## DocumentDB and Neptune

Two AWS-managed databases that are not RDS, not DynamoDB, and not Redis — each built for a specific data shape that the others handle badly.

The easiest way in is to **anchor both in Redis**, which you already know as an in-memory key/value store with a few clever data structures (lists, sorted sets, hashes, pub/sub). Redis is great at sub-ms lookups by key, but the moment you want to *query* by attribute or follow *relationships*, it falls over. DocumentDB and Neptune are what you reach for in those two cases.

### DocumentDB — anchored in Redis

Imagine you store a user profile in Redis as a hash:

```
HSET user:42 name "Alice" age 30 city "London"
HGET user:42 name        ← works
HGETALL user:42           ← works
"give me all users in London aged 25–35"  ← Redis can't do this
```

To answer the third query in Redis you'd hand-roll secondary indexes (`SADD city:London 42`), maintain them on every write, intersect sets in your app code, and accept that nothing is queryable except via your hand-built indexes.

**DocumentDB is what you'd want if Redis hashes had:**

- A **query language** (`find({city: "London", age: {$gte: 25, $lte: 35}})`)
- **Indexes** on any field
- **Durable disk storage** (not limited by RAM)
- **Replicas + automatic failover** built in
- **MongoDB driver compatibility** — existing Mongo app code works unchanged

It's AWS's managed Mongo-compatible service: same wire protocol, same APIs (within a supported version), but AWS handles the cluster, replication, backups, and patching.

**Key properties:**

- **Data model:** JSON documents (BSON), flexible schema
- **Query API:** MongoDB API — `find`, `aggregate`, indexes on any field
- **Storage:** durable, 6 copies across 3 AZs, scales automatically up to 64 TB
- **Cluster:** one writer instance + up to 15 read replicas (Aurora-style storage layer)
- **Failover:** automatic, typically under 30 seconds
- **Latency:** single-digit ms
- **Auth:** native MongoDB auth + IAM database authentication; security groups (ENI-backed, lives in your VPC)
- **Multi-region:** Global Clusters — one writer region, others are read-only
- **Pricing:** per instance-hour + I/O + storage; Elastic Clusters offer a more serverless-style model

**Trade-off vs Redis:** latency goes from sub-ms → ms, and per-GB cost is higher. You get a real database in exchange.

**⚠ "Is DocumentDB really MongoDB?" — no, and this matters:**

There are three flavours of "MongoDB on AWS" and the distinction shows up in exam wrong-answer choices:

| Option | Who runs it | Is it the real MongoDB engine? |
| ------ | ----------- | ------------------------------ |
| **Amazon DocumentDB (MongoDB compatibility)** | AWS | **No** — AWS-built reimplementation that speaks the MongoDB wire protocol. Existing MongoDB drivers work unchanged |
| **MongoDB Atlas on AWS** | MongoDB Inc. (the company), available via AWS Marketplace | **Yes** — the real MongoDB engine, sold as SaaS, deployed onto AWS infrastructure |
| **Self-managed MongoDB on EC2** | You | Yes — but you own all the maintenance pain |

**Why DocumentDB is the default AWS exam answer:**

Questions phrased *"which AWS service"* are looking for an AWS-native service. Atlas is third-party SaaS — it runs *on* AWS, but it isn't *an* AWS service. So:

- *"AWS service for managed MongoDB"* → **DocumentDB**
- *"any way to run MongoDB on AWS"* → DocumentDB *or* Atlas *or* self-hosted

**Compatibility gaps (occasional exam trap):**

DocumentDB emulates MongoDB API versions 3.6, 4.0, and 5.0 but is **not 100% compatible**. Some features don't work:

- Certain aggregation operators
- Some index types (text search, parts of geospatial)
- Cross-document transactions have constraints
- Change streams behave differently from MongoDB's

If a question says *"team relies on MongoDB feature X that DocumentDB doesn't support"*, the answer is **MongoDB Atlas on AWS Marketplace** or self-managed on EC2 — not DocumentDB.

**Mnemonic:**

- "AWS service" + "MongoDB" + "no code changes" → **DocumentDB**
- "Real MongoDB" + "feature parity" + "AWS infrastructure" → **MongoDB Atlas (Marketplace)**

### Neptune — anchored in Redis

What if your data is **relationships**? Who follows whom on a social network. Which accounts touched which transactions in a fraud graph. Which products were co-bought by users similar to me.

In Redis you can model edges as sets:

```
SADD friends:alice bob carol dave
SADD friends:bob   alice eve frank
"who are friends of friends of Alice?"  ← N round-trips + app-side joining
"shortest path from Alice to Zach?"     ← essentially impossible
```

Every hop is another `SMEMBERS` call and another set intersection in your app. At two hops it's painful. At three or four it's broken.

**Neptune is what you reach for when graph traversal is the question.** One query, optimised by a graph engine:

```gremlin
g.V().has('user','id','alice')
     .out('friend').out('friend')           # friends of friends
     .where(out('bought').has('id','X'))    # who also bought X
```

**Key properties:**

- **Two graph models** in one engine:
  - **Property graph** — nodes + edges with properties. Query with **Gremlin** or **openCypher**
  - **RDF triples** — knowledge-graph style. Query with **SPARQL**
- **Storage:** durable, 6 copies across 3 AZs, scales automatically up to 64 TB (Aurora-style)
- **Cluster:** one writer + up to 15 read replicas
- **Latency:** single-digit ms for typical traversals
- **Auth:** IAM, security groups (lives in your VPC)
- **Multi-region:** Global Database — one writer region, others read-only
- **Serverless:** Neptune Serverless option scales capacity up and down automatically
- **Pricing:** per instance-hour + I/O + storage

**Classic use cases:**

- **Social networks** — followers, friends-of-friends, mutual connections
- **Fraud detection** — "is this new account connected to any known-bad accounts within 3 hops?"
- **Recommendation engines** — "users who bought X also bought Y" expressed as graph traversal
- **Knowledge graphs** — Wikidata-style entity relationships
- **Identity resolution** — linking accounts/devices/sessions that belong to the same person

**⚠ OLTP trap — do not pick Neptune for an OLTP question:**

Neptune uses the **same Aurora-style storage layer**: 6 copies across 3 AZs, auto-scaling storage, up to 15 read replicas. That's tempting when an exam question says *"OLTP database with built-in auto-scaling and the maximum number of replicas for its underlying storage."* Two qualifiers match Neptune — but the answer is **Aurora**.

The decisive word is **OLTP**:

| Term | What it means | The right database |
| ---- | ------------- | ------------------ |
| **OLTP** — Online *Transaction* Processing | Frequent short atomic relational operations: insert order, update balance | **Aurora** (or RDS) |
| **OLAP** — analytical queries | Aggregations across millions of rows | **Redshift** |
| **Graph workload** | Traversal: friends-of-friends, fraud paths | **Neptune** |

"Transactions" in OLTP is industry shorthand for **relational** workload (banking, ordering, inventory). Fraud detection in a graph DB is *not* OLTP, despite involving ACID transactions and "transactional data" in plain English. If a question says OLTP, eliminate Neptune, DynamoDB, DocumentDB, and Redshift before picking the storage-replicas winner from the relational survivors → Aurora.

### Comparison — Redis vs DocumentDB vs Neptune

| | Redis | DocumentDB | Neptune |
| - | ----- | ---------- | ------- |
| What it is | In-memory key/value + data structures | Managed MongoDB-compatible document DB | Managed graph database |
| Data shape | Strings, lists, sets, sorted sets, hashes | JSON documents, flexible schema | Nodes + edges (or RDF triples) |
| Query | Redis commands (no general query) | MongoDB API (`find`, `aggregate`) | Gremlin / openCypher / SPARQL |
| Durability | Volatile by default | Durable, 3-AZ | Durable, 3-AZ |
| Latency | Sub-ms | Single-digit ms | Single-digit ms |
| Capacity | Limited by RAM | Up to 64 TB | Up to 64 TB |
| Best at | Caching, leaderboards, counters, pub/sub | Queryable durable JSON at scale | Graph traversal, "friends of friends" |
| Anchor for the exam | "the cache" | "Redis hashes with queries and durability" | "what Redis edges *can't* do" |

### Picking between RDS, Aurora, DynamoDB, DocumentDB, Neptune

| Question | Use |
| -------- | --- |
| Relational tables, joins, transactions, SQL | **RDS** or **Aurora** |
| Same as above but cloud-native, auto-scale, multi-region read scale | **Aurora** |
| Key/value or document, serverless, predictable ms latency, massive scale | **DynamoDB** |
| JSON documents with rich queries, Mongo compatibility | **DocumentDB** |
| Graph: relationships, traversals, paths | **Neptune** |
| Sub-ms cache or specialised structures (sorted sets, pub/sub, locks) | **ElastiCache Redis** |
| Analytics over petabytes of columnar data | **Redshift** |

### Common anti-patterns (exam wrong answers)

- **Using Redis for graph queries** — possible to store edges in sets, but multi-hop traversal becomes N round-trips + app-side joining. Use Neptune.
- **Using Redis as a primary document store** — fetch by key only, no `find`-style queries. Use DocumentDB if you need querying + durability.
- **Using DocumentDB as a cache** — durable disk, ms latency, expensive per GB. If volatile + sub-ms is what you want, use Redis.
- **Using Neptune for tabular data** — wrong shape entirely. Use RDS or Redshift.
- **Using DocumentDB for relational joins** — Mongo-style document DBs don't do joins well. Use RDS / Aurora.
- **Using RDS for deep relationship queries with recursive CTEs** — fine for 2 hops, falls over beyond 3–4. Use Neptune.
- **Picking DocumentDB just because it's "NoSQL"** — DynamoDB is usually a better choice for new AWS-native apps. DocumentDB shines when you have existing Mongo code or need Mongo-style ad-hoc queries on documents.
- **Picking DocumentDB when the team relies on a MongoDB feature DocumentDB doesn't support** — DocumentDB is API-compatible, not feature-complete. Some aggregation operators, index types, transactions, and change streams differ. If the question hints at a specific Mongo feature, the answer might be **MongoDB Atlas on AWS Marketplace** or self-hosted on EC2.
- **Picking Neptune just because the data "feels relational"** — Neptune wins only when traversal is the access pattern. A normal foreign-key model belongs in RDS.
- **Picking Neptune on an OLTP question because it mentions "6 copies across 3 AZs" or "auto-scaling storage"** — Neptune shares the Aurora storage layer, so those qualifiers match, but **OLTP** means relational. The answer is Aurora. Eliminate Neptune the moment you see "OLTP".

### Exam triggers

- *"managed MongoDB-compatible database"* → **DocumentDB**
- *"migrate an existing MongoDB workload to AWS"* → **DocumentDB**
- *"JSON document database with flexible schema and queries"* → **DocumentDB**
- *"graph database"* → **Neptune**
- *"social network / recommendation engine / fraud detection / identity resolution"* → **Neptune**
- *"friends-of-friends / shortest path / multi-hop traversal"* → **Neptune**
- *"knowledge graph / SPARQL / RDF"* → **Neptune**
- *"Gremlin / openCypher / Cypher"* → **Neptune**
- *"AWS-managed graph database that supports multiple query languages"* → **Neptune**
- *"AWS-managed alternative to self-hosting MongoDB on EC2"* → **DocumentDB**
- *"OLTP database with auto-scaling and the maximum storage replicas"* → **Aurora** (not Neptune — OLTP means relational, eliminate graph DBs first)
- *"team needs a specific MongoDB feature DocumentDB doesn't support"* → **MongoDB Atlas (AWS Marketplace)** or self-hosted on EC2 (DocumentDB is API-compatible, not feature-complete)

## Other Managed Databases

Three more AWS-managed databases that show up in exam scenarios, each built for a workload the mainstream services handle badly. The pattern is the same as DocumentDB/Neptune: anchor each one in a service you already know, then describe the delta.

### Amazon Keyspaces (Cassandra-compatible)

**Anchored in DynamoDB.** Both are AWS-managed, serverless, wide-column-ish, and target massive scale with single-digit ms latency. The differences:

- **CQL (Cassandra Query Language)** — looks SQL-ish, same as open-source Apache Cassandra. If your team already speaks CQL or your application uses a Cassandra driver, Keyspaces is a near-drop-in.
- **Clustering columns** — Cassandra's first-class concept for ordered rows within a partition. DynamoDB approximates this with a sort key but the semantics differ.
- **No native streams + Lambda trigger** — DynamoDB Streams has no direct equivalent. You can use change data capture via integrations but it's not as seamless.

```
DynamoDB item:    PK=user#42, SK=order#2024-01-15, attrs={...}
Keyspaces row:    partition_key=user#42, clustering=(order_date), columns=...
                  (SELECT * FROM orders WHERE user_id = '42' ORDER BY order_date DESC)
```

**Key properties:**

- Serverless or provisioned (same model as DynamoDB)
- Multi-AZ by default, durable
- Single-digit ms reads/writes
- IAM authentication, KMS encryption, VPC endpoints
- Multi-Region replication (active-active)
- Same "public API, no security group" model as DynamoDB

**One-line decision rule:**

| Situation | Pick |
| --------- | ---- |
| New AWS-native application | **DynamoDB** (better-integrated, streams, broader feature set) |
| Migrating an existing Apache Cassandra workload | **Keyspaces** (keep your CQL queries and drivers) |
| Team already fluent in CQL | **Keyspaces** |
| Need DynamoDB Streams → Lambda triggers | **DynamoDB** |

**Common anti-patterns (exam wrong answers):**

- **Picking Keyspaces for a greenfield AWS-native app** — DynamoDB is better integrated, has Streams, has DAX, has TTL. Keyspaces shines on migration, not new builds.
- **Expecting DynamoDB Streams behaviour on Keyspaces** — no native equivalent. If event-driven processing matters, DynamoDB is the answer.
- **Trying to attach a security group to Keyspaces** — public API, no ENI. IAM + VPC endpoint, same as DynamoDB.

**Exam triggers:**

- *"managed Cassandra-compatible database"* → **Keyspaces**
- *"migrate existing Cassandra workload to AWS without rewriting CQL"* → **Keyspaces**
- *"serverless wide-column database with CQL"* → **Keyspaces**

### Amazon MemoryDB for Redis

**Anchored in ElastiCache Redis.** Same Redis API, same data structures. The critical difference: **MemoryDB is durable** — it's a primary database, not a cache.

```
ElastiCache Redis:  in-memory, optional RDB snapshots, treat as volatile (lose data on failure)
MemoryDB for Redis: in-memory + Multi-AZ transaction log → durable, survives node failure
```

The transaction log gives MemoryDB:

- **Microsecond reads, single-digit ms writes**
- **Durable across multi-AZ failures** — no data loss on node failure
- **Strong consistency** for reads from the primary

Think of it as "Redis you can trust as a system of record." Same API as ElastiCache Redis (you can use the same client libraries), but you don't need a separate durable database underneath.

**ElastiCache vs MemoryDB:**

| | ElastiCache Redis | MemoryDB for Redis |
| - | ----------------- | ------------------ |
| Role | Cache (in front of a real DB) | Primary database |
| Durability | Volatile by default | Durable (multi-AZ transaction log) |
| Read latency | Sub-ms | Microseconds |
| Write latency | Sub-ms | Single-digit ms (transaction log write) |
| Use when | You have a separate durable store | You want Redis API as the source of truth |
| Cost | Cheaper | More expensive (durability isn't free) |

**Common anti-patterns:**

- **Using ElastiCache Redis as a primary store for critical data** — volatile by default. If you need Redis API + durability, use MemoryDB.
- **Using MemoryDB as a cache** — durability costs money. If you have a real database underneath, ElastiCache is cheaper.
- **Picking MemoryDB when DynamoDB would do** — DynamoDB is cheaper at scale unless you specifically need Redis data structures (sorted sets, streams, pub/sub) as the primary access pattern.

**Exam triggers:**

- *"Redis-compatible database I can use as the primary data store"* → **MemoryDB for Redis**
- *"durable in-memory database with Redis API"* → **MemoryDB for Redis**
- *"need Redis sorted sets / streams as a system of record, not a cache"* → **MemoryDB**
- *"cache in front of RDS / DynamoDB"* → **ElastiCache Redis** (cheaper, durability not needed)

### Amazon Timestream

**Anchored in DynamoDB and CloudWatch.** Time-series data — IoT sensor readings, application metrics, DevOps telemetry — has a specific shape that general-purpose databases handle badly:

```
Time-series characteristics:
- Append-only (you don't update past readings)
- Indexed primarily by timestamp + dimension (sensor_id, region, etc.)
- Recent data queried often, old data queried rarely (or aggregated)
- Massive write volume (millions of points per second)
- Queries are aggregations over time windows ("avg temperature per hour")
```

Storing this in DynamoDB works for ingestion but kills you on cost and query: aggregations require scans or pre-aggregation jobs. RDS dies on the write volume. CloudWatch metrics is too coarse and storage-limited.

**Timestream solves the shape:**

- **Two storage tiers**, automatic:
  - **Memory store** — recent data, fast reads, expensive per GB
  - **Magnetic store** — older data, cheaper, slightly slower reads
- **Built-in time-series functions** — interpolation, smoothing, derivatives, rate-of-change
- **SQL-compatible query language**
- **Scales to trillions of events per day**
- **Pay per write + storage tier + per query (data scanned)**

```
SELECT bin(time, 1m) AS minute,
       avg(temperature) AS avg_temp
FROM "iot"."readings"
WHERE sensor_id = 'sensor-42'
  AND time > ago(1h)
GROUP BY bin(time, 1m)
```

**Timestream vs alternatives:**

| Workload | Better than Timestream? |
| -------- | ----------------------- |
| AWS infrastructure metrics | **CloudWatch Metrics** — built-in, free for AWS-emitted metrics |
| Custom app metrics, low volume | **CloudWatch Metrics** custom metrics |
| Massive IoT or app telemetry, query-heavy | **Timestream** |
| Time-series + need full SQL joins with other tables | RDS with time-series extensions (TimescaleDB-style), but Timestream's purpose-built tiers will usually win |
| Time-series at petabyte analytical scale | **Redshift** or **OpenSearch** depending on access pattern |

**Common anti-patterns:**

- **Storing IoT readings in DynamoDB** — works, but aggregations are painful and storage cost scales linearly with no tiering. Timestream tiers data automatically and has time-series functions.
- **Storing metrics in RDS** — write volume kills it.
- **Using CloudWatch Metrics for high-cardinality custom dimensions** — expensive at scale ($0.30 per custom metric per month adds up fast). Timestream is cheaper per dimension at high cardinality.
- **Using Timestream for transactional data that isn't time-series** — wrong shape; use DynamoDB / RDS.

**Exam triggers:**

- *"store and analyse IoT sensor data at scale"* → **Timestream**
- *"time-series database"* → **Timestream**
- *"trillions of events per day with time-window aggregations"* → **Timestream**
- *"application metrics from AWS services"* → **CloudWatch Metrics** (not Timestream)
- *"queries like average temperature over the last hour grouped by minute"* → **Timestream** (built-in time-series functions)

## AWS Database Migration Service (DMS) and Schema Conversion Tool (SCT)

The single most likely topic to be missing from a database study list. Almost every "migrate from on-prem X to AWS Y" exam question is answered by DMS, sometimes with SCT.

### What DMS Does

A managed service that **replicates data from a source database to a target database**, with the source typically remaining online during the migration. AWS spins up a **replication instance** (an EC2 under the hood, fully managed) that reads from the source and writes to the target.

```
On-prem Oracle  ──→  Replication Instance (DMS)  ──→  Amazon Aurora PostgreSQL
                         │
                         ├── Full load: copy existing rows
                         └── CDC: stream ongoing changes (zero or near-zero downtime)
```

**Two migration modes:**

| Mode | What it does |
| ---- | ------------ |
| **Full load** | One-time copy of all data from source to target. Downtime = duration of the load |
| **CDC (Change Data Capture)** | Continuous stream of source changes (inserts/updates/deletes) to the target. Cuts over with minimal downtime |
| **Full load + CDC** (most common) | Initial copy + ongoing replication. Switch the app to the target when CDC has caught up |

**Sources DMS supports:** Oracle, SQL Server, MySQL, PostgreSQL, MariaDB, MongoDB, Db2, SAP ASE, Azure SQL, S3, plus on-prem self-managed installations of the same.

**Targets DMS supports:** all the above (as RDS or self-managed), plus Aurora, Redshift, DynamoDB, OpenSearch, Kinesis, Kafka, S3, DocumentDB, Neptune.

### Homogeneous vs Heterogeneous Migrations

```
Homogeneous:    Oracle on-prem  →  RDS for Oracle      (same engine on both sides)
                MySQL on-prem   →  Aurora MySQL        (compatible engines)

Heterogeneous:  Oracle on-prem  →  Aurora PostgreSQL   (different engines)
                SQL Server      →  RDS for MySQL       (different engines)
```

- **Homogeneous** — DMS alone is enough. Schema and SQL syntax are compatible.
- **Heterogeneous** — DMS moves the **data**; **schema and stored procedures need conversion first**. That's where SCT comes in.

### AWS Schema Conversion Tool (SCT)

A free downloadable tool (runs on your laptop) that **converts schema, stored procedures, views, and code** from one database engine to another.

```
Source (Oracle PL/SQL)  ──→  SCT  ──→  Target (PostgreSQL PL/pgSQL)
                              │
                              ├── Tables, indexes, constraints → auto-converted
                              ├── Stored procs / functions     → auto-converted where possible
                              └── Non-convertible items        → flagged for manual rewrite + effort estimate
```

**Workflow for a heterogeneous migration:**

1. **SCT** converts the schema and code → apply to the target database
2. **DMS** loads the data + replicates ongoing changes
3. Cut over the application to the target

**SCT also helps:** migrating data warehouses (Teradata, Netezza, Greenplum, Vertica) to **Redshift** — schema conversion is essential because warehouse DDL/SQL differs significantly.

### Replication Instance Sizing

DMS performance depends on the replication instance size. Right-sizing matters:

- **Small instances** (t3.medium): fine for low-volume migrations, dev/test
- **Large instances** (c5/r5.xlarge+): high-volume production, parallel table loads
- **Multi-AZ** option for the replication instance during long-running CDC migrations — survives AZ failures without restarting the migration

### When DMS Is Not the Answer

Common confusions on the exam:

- **Lift-and-shift VM (the whole server, not just the DB)** → **AWS Application Migration Service (MGN)** or **VM Import**, not DMS
- **Migrate Hadoop / S3 data lake content** → **AWS DataSync** or **Snowball** depending on volume, not DMS
- **Migrate the OS + database on EC2** → MGN, then point DMS at the new instance if you want to move the DB engine afterward
- **Continuous data integration between cloud systems forever** → DMS *can* do this but a streaming service (Kinesis, MSK) or change data capture pipeline is often a better long-term answer

### Common Anti-patterns (exam wrong answers)

- **Picking DMS for a homogeneous migration but forgetting CDC** → full-load-only forces downtime equal to the load time. Production cutovers almost always need full load + CDC.
- **Picking DMS without SCT for heterogeneous migrations** → DMS moves data but doesn't convert schema or stored procedures. Without SCT the target won't have the tables/code to receive the data.
- **Using DMS for huge initial loads when bandwidth is the bottleneck** → **Snowball Edge** can be the initial-load mechanism, with DMS doing CDC catch-up afterward.
- **Picking DataSync for database migration** → DataSync is for file storage (S3, EFS, FSx), not databases.
- **Picking DMS to migrate a VMware VM** → that's MGN's job.

### Exam Triggers

- *"migrate an on-prem database to AWS with minimal downtime"* → **DMS** (full load + CDC)
- *"migrate Oracle to Aurora PostgreSQL"* → **SCT** (schema conversion) + **DMS** (data)
- *"migrate SQL Server to RDS for MySQL"* → **SCT** + **DMS**
- *"migrate Teradata / Netezza data warehouse to Redshift"* → **SCT** + **DMS**
- *"migrate MongoDB on-prem to DocumentDB"* → **DMS** (DocumentDB is a valid target)
- *"continuously replicate from production database to analytics database"* → **DMS** with ongoing CDC
- *"replicate a database across AWS regions"* → Aurora Global Database or DMS CDC
- *"convert database schema from one engine to another"* → **SCT**
- *"initial load is too big to stream over the internet"* → **Snowball Edge** for bulk + **DMS** CDC for catch-up
- *"migrate VMs, not just the database"* → **MGN** (AWS Application Migration Service), not DMS

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

**Full-stack serverless architecture:**

Everything serverless — frontend, auth, API, database, caching, file storage:

```
┌─────────────────────────────────────────────────────────────────┐
│  Frontend                                                       │
│  S3 (static React/Vue app) → CloudFront (CDN, HTTPS)           │
│  Route 53 (app.example.com → CloudFront Alias)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS API calls
┌──────────────────────────▼──────────────────────────────────────┐
│  Auth                                                           │
│  Cognito User Pool (sign-up, sign-in, JWT)                     │
│  Cognito Identity Pool (direct S3 uploads from browser)        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ JWT token
┌──────────────────────────▼──────────────────────────────────────┐
│  API                                                            │
│  API Gateway (validates JWT, throttling, caching)               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  Business Logic                                                 │
│  Lambda functions                                               │
└───────┬──────────────┬──────────────┬───────────────────────────┘
        │              │              │
┌───────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐
│  DynamoDB    │ │  DAX       │ │  S3       │
│  (database)  │ │  (cache)   │ │  (files)  │
└──────────────┘ └────────────┘ └───────────┘
```

**How the pieces fit:**

| Layer | Service | What it does |
| ----- | ------- | ------------ |
| Frontend | S3 + CloudFront | Static app served globally, HTTPS |
| DNS | Route 53 | `app.example.com` → CloudFront, `api.example.com` → API Gateway |
| Auth | Cognito User Pool | Sign-up, sign-in, JWT tokens, social login |
| Direct upload | Cognito Identity Pool | Browser uploads photos directly to S3 (no Lambda) |
| API | API Gateway | Validates JWT, throttles, caches responses |
| Logic | Lambda | Business logic, scales per request |
| Database | DynamoDB | NoSQL, auto-scales |
| Cache | DAX | Microsecond reads, same DynamoDB API |
| Files | S3 | User uploads, generated files |

**Cost at zero traffic: ~$0.** Everything scales to zero. You only pay when users arrive. This is why serverless is popular for startups and side projects.

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

### When Not to Use S3

S3 is the right answer for *most* storage questions on the exam — but the trap questions are the ones where S3 looks plausible and is actually wrong. Here's where it breaks down.

| Anti-use case | Why S3 hurts | Better fit |
| ------------- | ------------ | ---------- |
| **Millions of tiny objects** (< few KB each) | Per-request charges dominate: PUT ~$5/million, GET ~$0.40/million. List operations slow down. Latency overhead per object | Aggregate into Parquet/ORC/tar/zip; or EFS/FSx for file workloads |
| **Tiny objects in Glacier / Deep Archive** | Minimum **40 KB** charged per object + ~32 KB metadata overhead. A 1 KB file costs the same as 40 KB | Aggregate before archiving |
| **Tiny objects in Intelligent-Tiering** | Per-object **monitoring fee** dominates for sub-128 KB objects (which aren't tiered anyway) | S3 Standard, or aggregate |
| **POSIX filesystem semantics** — locking, partial writes, symlinks, atomic rename | S3 is whole-object PUT, no locks, no append | EFS (Linux) or FSx (Windows / Lustre) |
| **Append-mostly workloads** (per-event logging) | No append — every event is a new PUT + per-request cost | Kinesis Firehose to batch into S3, or CloudWatch Logs |
| **Sub-ms or low-latency reads** | First-byte latency typically 100–200 ms | DynamoDB, ElastiCache, EBS |
| **Random byte-range writes** | S3 PUT is whole-object only (byte-range *GET* is fine) | EBS, EFS |
| **Concurrent edits to the same object** | Last writer wins, no merge | DynamoDB with conditional writes, or RDS |
| **High write rate to one prefix** | S3 partitions by prefix; ~3,500 PUT/s and 5,500 GET/s per partitioned prefix | Spread across more prefixes, or use a database |
| **Primary database** — querying by attributes, joins, transactions | No query engine. Athena/S3 Select read whole objects | DynamoDB / RDS / Redshift |
| **Strong multi-object transactions** | No cross-object atomicity | DynamoDB `TransactWriteItems` |

**The small-object cost problem made concrete:**

```
1 GB stored as:
  1,000,000 × 1 KB objects → $5 to upload + listing overhead + per-request fees on every operation
                            + Glacier/Intelligent-Tiering economics break completely
  1 × 1 GB object          → $0.000005 to upload + one cheap GET + clean archive economics
```

Same storage volume, same storage cost. Every other dimension (upload cost, list cost, request rate, latency, archive economics) is dramatically worse for the tiny-object version.

**Mitigations when you're stuck with small objects:**

- **Aggregate before writing** — Kinesis Firehose buffers events and writes 1–128 MB Parquet files instead of N tiny JSONs
- **S3 Inventory** to discover the small-object problem in existing buckets
- **Manifest pattern** — one larger index file pointing at related small ones, when small files must remain separate
- **S3 Express One Zone** — newer **single-AZ** storage class designed for high-frequency small-object workloads. Much lower per-request cost, ms-scale latency. Trade-off: one AZ (no cross-AZ durability), more expensive per-GB storage. **Exam answer for: "millions of small objects accessed at high rate, low latency, AZ-local is OK"**

**Common anti-patterns (exam wrong answers):**

- **S3 as a database** — pick DynamoDB for key/value, RDS for relational
- **S3 as a queue / event log** — pick SQS for queueing, Kinesis for streams
- **S3 as a shared filesystem for EC2** — pick EFS (Linux multi-attach) or FSx (Windows / Lustre)
- **Millions of small PUTs per day with no aggregation** — pre-batch with Firehose
- **Glacier for tiny objects** — 40 KB minimum + metadata makes per-byte cost terrible

**Exam triggers:**

- *"millions of small files, cost is high"* → aggregate before writing (Firehose, batch jobs)
- *"need POSIX filesystem semantics"* → not S3 — EFS / FSx
- *"need sub-ms latency for a key/value lookup"* → not S3 — DynamoDB
- *"need to append to a log file in S3"* → not directly — buffer with Firehose
- *"high write rate to a single S3 prefix is being throttled"* → spread writes across more prefixes
- *"high-frequency reads of millions of small files in one AZ, low latency"* → **S3 Express One Zone**
- *"tiny files in Glacier costing more than expected"* → 40 KB per-object minimum + 32 KB metadata
- *"concurrent edits to the same file"* → not S3 — DynamoDB / RDS

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

**SQS access control:**

SQS is a public AWS API — it has **no ENI in your VPC**, so you **cannot attach a security group to a queue**. (See the [VPC and Networking](#vpc-and-networking) section on ENI-backed vs public-endpoint services.) Control access through these layers instead:

| Layer | Purpose |
| ----- | ------- |
| **IAM identity policy** | Which principal can call SQS APIs at all (`sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`) |
| **Queue policy** (resource-based) | Who can act on this specific queue. Used for **cross-account** access — name the external principal directly |
| **KMS key policy** | If the queue uses SSE-KMS, the producer/consumer also needs `kms:GenerateDataKey` / `kms:Decrypt` on the key |
| **VPC interface endpoint** | Keeps SQS traffic off the public internet. SG attaches to the **endpoint**, not the queue |
| **VPC endpoint policy** | On the endpoint, restrict which queues are reachable through it |
| **Encryption** | TLS in transit (enforced); SSE-SQS or SSE-KMS at rest |

**Common access-control gotcha:** consumer has `sqs:ReceiveMessage` but gets `AccessDenied` anyway → it's missing `kms:Decrypt` on the queue's KMS key. The IAM permission to *read the queue* is separate from the permission to *decrypt the message*.

**Anti-patterns:**

- *"Attach a security group to the queue to restrict access"* — impossible. IAM + queue policy is the answer.
- *"Use the queue policy alone for everything"* — works, but for AWS principals in the same account, IAM is usually cleaner and more auditable. Save queue policy for cross-account.
- *"Forgot the KMS key policy"* — most common cause of AccessDenied on SSE-KMS queues.

**Exam triggers:**
- *"decouple application components"* → SQS
- *"buffer writes to a database"* → SQS (see below)
- *"messages processed out of order"* → switch to SQS FIFO
- *"messages being processed twice"* → increase visibility timeout or switch to FIFO
- *"scale consumers based on workload"* → SQS + CloudWatch Alarm + ASG
- *"debug failed messages"* → Dead Letter Queue
- *"restrict cross-account access to a queue"* → queue policy (resource-based)
- *"keep SQS traffic off the public internet"* → VPC interface endpoint for SQS
- *"consumer has SQS IAM permission but still gets AccessDenied"* → missing `kms:Decrypt` on the KMS key
- *"attach a security group to an SQS queue"* → not possible; SQS has no ENI

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

### When People Reach for Redshift

You move data **out** of operational systems (RDS, DynamoDB, application logs, third-party feeds) **into** Redshift specifically for analytics. The trigger is one of these three:

1. **BI dashboards on big data** — Tableau / QuickSight / PowerBI hitting the same dataset many times per minute. Always-on cluster + result cache + materialised views = fast repeated queries.
2. **Petabyte-scale analytical queries** — complex joins and aggregations across billions of rows that would crush RDS.
3. **Central data warehouse** — consolidate data from many sources into one place so analysts can query without touching production.

**Concrete real-world scenarios:**

- *"5 years of order history, want to slice by region/product/time for the exec dashboard"*
- *"Daily ETL job pulls yesterday's orders from production RDS into Redshift so analysts don't hit the OLTP DB"*
- *"Marketing wants to combine web clickstream (S3), CRM (RDS), and ad spend (third-party) — one warehouse, one SQL"*
- *"Finance runs monthly close reports across the entire transaction history"*

**Rule of thumb:**

- Live transactional workload → **RDS / Aurora / DynamoDB**
- Ad-hoc, infrequent SQL on S3 → **Athena**
- **Repeated, complex analytics on big data feeding dashboards** → **Redshift**

If you wouldn't use the word *"warehouse"* or *"BI"* to describe the workload, Redshift is probably the wrong answer.

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

### Why Load into Redshift Instead of Querying S3?

Given Athena and Redshift Spectrum can query S3 in place, why pay to load? The short answer: **speed, predictable cost, and warehouse features**.

| Reason | Why loading into Redshift wins |
| ------ | ------------------------------ |
| **Performance** | Loaded data is distributed across cluster nodes using **distribution keys** + sorted using **sort keys**. A star-schema join on a 10-billion-row fact table is sub-second in Redshift, minutes in Athena |
| **Cost flips at volume** | Athena = $5 per TB **scanned, per query**. A dashboard scanning 100 GB hit 1,000 times/day = $500/day. A Redshift cluster running 24/7 for the same workload might be $50/day |
| **Result cache + warm cluster** | Repeated queries hit Redshift's cache in milliseconds. Athena has seconds of startup overhead per query |
| **Materialised views** | Pre-compute aggregations (`SELECT region, SUM(sales) GROUP BY region`) and refresh on a schedule. Athena can't do this — every query re-aggregates from raw data |
| **Concurrency** | Concurrency Scaling spins up extra clusters for spikes. Athena has lower default concurrency limits |
| **Workload management (WLM)** | Queue management — give finance queries priority over marketing, prevent runaway queries from starving everyone else |
| **Joins across big fact + dimension tables** | Co-locating joined rows via the distribution key is **Redshift's superpower**. Athena moves data across nodes during the join — slow |
| **ELT pipeline** | `COPY` from S3 into a staging table, transform with SQL, load into a fact table |

**The mental model:**

```
Raw events  →  S3 (cheap, durable, source of truth for raw data)
                  │
                  ├── Ad-hoc / infrequent query  →  Athena (query in place)
                  │
                  └── ETL/ELT into Redshift      →  fast repeated queries, BI dashboards,
                                                    materialised views, complex joins
```

S3 stays the **source of truth for raw data**. Redshift becomes the **source of truth for analytical queries**. Both coexist in most architectures.

**When NOT to copy in:**

- Queries run rarely (weekly report, ad-hoc exploration) → **Athena**
- Petabyte-scale data with only a small slice queried at a time → **Redshift Spectrum** (cluster for hot data, S3 for cold)
- Cost-sensitive project, slower queries acceptable → **Athena**

**The simple rule:**

- *"Will I run this query many times per day?"* → **load into Redshift**
- *"Will I run this query a few times per month?"* → **leave in S3, use Athena**
- *"Some of both?"* → **Redshift Spectrum** (hot data loaded, cold data in S3)

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

## Amazon Athena

**Anchored in Redshift.** Both run SQL over large datasets. The difference: Redshift loads data into a cluster you provision; **Athena queries data directly in S3, no cluster, no loading**.

```
Redshift:  Load CSV/Parquet from S3 → into Redshift cluster → SQL queries
Athena:    Leave files in S3 → point Athena at them → SQL queries
```

Built on **Presto/Trino** under the hood. Schema is defined in the **AWS Glue Data Catalog** (or Athena's own catalog), which is metadata only — Athena reads the underlying objects on each query.

**Glue Crawler + Glue Data Catalog (exam pairing with Athena):**

- **Glue Crawler** scans S3 paths, infers schema, and writes the table definition to the **Glue Data Catalog** — no manual `CREATE TABLE` needed.
- **Glue Data Catalog** is a central metadata store shared by Athena, Redshift Spectrum, and EMR. One table definition, multiple query engines.
- Typical exam pattern: *"new S3 data lands daily, want to query it with Athena without manually maintaining schema"* → Glue Crawler on a schedule → Glue Data Catalog → Athena.

### Key Properties

- **Serverless** — no infrastructure to manage, no cluster to size
- **Pay per query** — billed by **bytes scanned from S3** ($5 per TB scanned at standard rate)
- **Standard SQL** (ANSI), JOINs, window functions, CTEs
- **Reads many formats** — CSV, JSON, Parquet, ORC, Avro
- **Federated queries** — query RDS, DynamoDB, on-prem databases via connectors (no need to copy data into S3 first)
- **Athena for Apache Spark** — same service, Spark notebooks for non-SQL workloads
- **Integrates with QuickSight** for BI dashboards directly on S3 data

### The Cost Model — Why File Format Matters

```
Same data, three formats, scanning to answer the same query:
  CSV (raw):     scan all 100 GB           → $0.50 per query
  JSON:          scan all 100 GB           → $0.50 per query
  Parquet:       scan only relevant columns (~5 GB) → $0.025 per query (20× cheaper)
```

**Athena cost optimisations (exam-tested):**

| Technique | Effect |
| --------- | ------ |
| **Convert to Parquet/ORC** (columnar) | Athena reads only the columns you select — 10–100× less data scanned |
| **Compress** (Snappy, gzip) | Smaller files, less data scanned, same bytes-billed reduction |
| **Partition** by common filter (date, region) | Athena skips partitions outside the `WHERE` clause |
| **Larger files** (128 MB – 1 GB) | Fewer S3 GET requests, faster query |
| **Use `LIMIT` carefully** — *doesn't* reduce scanned bytes for most queries | Don't rely on it as a cost control |

**Partitioning example:**

```
s3://logs/year=2026/month=05/day=20/events.parquet
                                                   ↑
SELECT * FROM logs WHERE year=2026 AND month=05    ← scans only that month
```

### Athena vs Redshift Spectrum (close cousins)

Both let you SQL-query S3. The difference is **where the query engine lives**:

| | Athena | Redshift Spectrum |
| - | ------ | ----------------- |
| Engine | Serverless (Presto-based) | Part of a Redshift cluster |
| Need a cluster? | No | Yes — Spectrum requires a Redshift cluster |
| Best for | Ad-hoc queries, infrequent use | Extending an existing Redshift workload to query S3 data without loading |
| Cost | Per query (bytes scanned) | Cluster cost + Spectrum charges |

If you already have Redshift → Spectrum is the natural fit. If you don't and only need occasional SQL on S3 → Athena.

### Federated Queries

Standard Athena queries S3. **Federated queries** extend Athena to query *non-S3* sources — RDS, DynamoDB, Redshift, DocumentDB, ElastiCache, Neptune, Timestream, CloudWatch Logs, on-prem databases — and **join across sources** in one SQL statement.

```
Athena query
   ├── SELECT from s3.logs          (native S3 scan)
   ├── JOIN  rds.orders ON ...      (Lambda connector → RDS → results back)
   └── JOIN  dynamodb.users ON ...  (Lambda connector → DynamoDB → results back)
```

**How it works:**

- Each non-S3 source has a **Lambda connector** that runs in your account and talks to the source on Athena's behalf
- AWS provides connectors for ~25 sources (RDS, DynamoDB, Redshift, DocumentDB, Neptune, ElastiCache, Timestream, CloudWatch, Snowflake, SAP HANA, on-prem MySQL/Postgres via JDBC…)
- Build custom connectors with the **Athena Query Federation SDK**
- Connectors live in your account — they reach private sources (RDS in a VPC) using Lambda VPC config

**Key properties:**

- Cost = **Lambda execution** (connector) **+ Athena bytes-scanned**
- **Pushdown depends on the connector** — good ones push filters/projections to the source; poor ones fetch everything and let Athena filter (expensive)
- One AWS region per query — federated query doesn't cross regions
- Source credentials stored in **Secrets Manager**, referenced by the connector

**Use cases:**

- Ad-hoc reporting that touches multiple stores without building a warehouse
- One-off audits joining live RDS with S3 archives
- Investigation across logs (S3), state (DynamoDB), and metadata (RDS)
- Avoiding ETL for queries that run rarely

**Common anti-patterns:**

- **Federated queries for high-volume production reporting** — Lambda cost + per-query latency add up. Use **DMS** to replicate into Redshift, or **Glue ETL** to land everything in S3 as Parquet.
- **Federated query with a non-pushdown connector on a huge table** — the connector pulls every row and Athena filters in memory. Pre-aggregate at source or copy first.
- **Federated query for a single source you'll use heavily** — if you only need DynamoDB, use **PartiQL** on DynamoDB directly. If you only need RDS, just query RDS.

**Exam triggers:**

- *"ad-hoc SQL across multiple data sources without ETL"* → **Athena federated queries**
- *"join S3 data with live RDS data without copying it"* → **Athena federated queries**
- *"query a non-S3 source with Athena"* → **federated query + Lambda connector**
- *"build a custom data source for Athena"* → **Athena Query Federation SDK**
- *"production high-volume reporting across sources"* → **NOT federated** — replicate to a warehouse via DMS or Glue ETL

**Mental model:** federated queries are **ad-hoc cross-source SQL**, not a substitute for a warehouse. Cheap and convenient for occasional use; wrong answer when the query runs every minute.

### Common Anti-patterns (exam wrong answers)

- **Storing data as raw CSV/JSON in S3 and querying it with Athena daily** — high recurring scan cost. Convert to Parquet + partition. AWS Glue ETL can automate this.
- **Athena for sub-second OLTP-style queries** — Athena has query startup overhead (seconds). For low-latency lookups use DynamoDB or RDS.
- **Using `SELECT *` on a partitioned columnar table** — defeats the columnar benefit; reads every column. Select only the columns you need.
- **Forgetting that scanned bytes are billed even on failed queries** — bad SQL still costs money.
- **Using Athena when the data is constantly being updated row-by-row** — S3 isn't designed for that; the small-object problem will hit you. Use a real database.

### Exam Triggers

- *"query S3 with SQL, no infrastructure"* → **Athena**
- *"ad-hoc SQL queries, infrequent, low cost when idle"* → **Athena**
- *"query CloudTrail / VPC Flow Logs / ALB logs / S3 access logs"* → **Athena** (all S3-resident log formats)
- *"reduce Athena cost"* → **Parquet + partition + compress**
- *"already have Redshift, want S3 data without loading"* → **Redshift Spectrum**
- *"discover schema of S3 data automatically"* → **Glue Crawler → Glue Data Catalog → Athena**
- *"connect QuickSight to S3 data"* → **Athena** (or Spectrum if Redshift is already in play)
- *"federated SQL across S3 + RDS + DynamoDB"* → **Athena federated queries**

**The 80/20:** *serverless SQL on S3 + cost = bytes scanned + Parquet/partitioning fixes cost + Spectrum is the Redshift-resident version*. Remember those four pieces and most Athena questions fall out.

## Amazon OpenSearch Service

**Anchored in DynamoDB and RDS.** Both serve point lookups by ID well. Neither is good at **full-text search** ("find every product description containing 'waterproof hiking boots'") or **log analytics at scale** ("how many 5xx errors did our ALB return per minute over the last 7 days, broken down by URL path?").

OpenSearch (the AWS-managed fork of Elasticsearch + Kibana, rebranded as OpenSearch + OpenSearch Dashboards in 2021) is the right tool for those two access patterns.

### When OpenSearch, Anchored in What You Know

If your data and queries look like:

```
"find me orders where the customer notes field contains 'urgent' AND order_date is in the last 7 days"
"top 10 most-searched product names in the last hour"
"all log lines from service X with status_code=500 in a specific time window"
```

…then a key/value store (DynamoDB) can't help — there's no key to look up — and a relational DB (RDS) can do it but slowly (full-text search via `LIKE '%urgent%'` is unindexed and brutal at scale).

OpenSearch indexes documents on **every field**, builds an **inverted index** for full-text search, and adds aggregations on top. Results come back in tens of milliseconds even over billions of documents.

### Key Properties

- **Document store** — JSON documents, schema-flexible (with mapping types)
- **Full-text search** — tokenisation, stemming, relevance scoring (BM25), fuzzy match
- **Aggregations** — counts, histograms, percentiles, time-bucketed series
- **OpenSearch Dashboards** — built-in visualisation tool (the fork of Kibana)
- **Cluster-based** — master + data nodes + (optional) ingest nodes, scaled by node count and storage
- **OpenSearch Serverless** — pay-per-OCU (OpenSearch Compute Unit), no cluster management
- **Auth:** Cognito, IAM, fine-grained access control, security groups (lives in VPC)
- **Cross-cluster replication** for multi-region

### Classic Use Cases

| Use case | Why OpenSearch wins |
| -------- | ------------------- |
| **Application logs / centralised logging** | "ELK / EFK stack" — apps ship logs to Kinesis Firehose → OpenSearch; engineers search and visualise in Dashboards |
| **Full-text search** for an e-commerce / SaaS product | Search-as-you-type, typo tolerance, relevance ranking — way beyond `LIKE` queries |
| **Real-time observability dashboards** | Time-series aggregations on operational data (latency P95, error rate per endpoint) |
| **Security analytics / SIEM** | OpenSearch has a security analytics module; correlate VPC Flow Logs + CloudTrail + WAF logs |
| **Clickstream / behavioural analytics** | Aggregate millions of events per second, query in seconds |

### OpenSearch vs CloudWatch Logs Insights

Both can search logs in AWS. The trade-off:

| | CloudWatch Logs Insights | OpenSearch Service |
| - | ------------------------ | ------------------ |
| Setup | Zero — already where AWS logs go | Provision cluster, ship logs in |
| Cost | Pay per query (GB scanned) | Cluster running cost + storage |
| Query language | Insights query (custom) | Lucene / OpenSearch query DSL / SQL |
| Visualisation | Basic CloudWatch dashboards | OpenSearch Dashboards (richer) |
| Best for | Occasional searches over CloudWatch-collected logs | Heavy day-to-day log analytics, full-text search, dashboards |

### Common Anti-patterns (exam wrong answers)

- **Using OpenSearch as a primary system of record** — it's a search index, not a durable source-of-truth database. Source data should live in DynamoDB / RDS / S3; OpenSearch holds an *index* of it.
- **Using OpenSearch for transactional workloads** — no ACID transactions, no joins. Wrong tool.
- **Building search with RDS `LIKE '%term%'`** — works for tiny datasets, falls over at scale. OpenSearch is the right answer when search relevance and speed matter.
- **Using OpenSearch when CloudWatch Logs Insights suffices** — OpenSearch has cluster running costs even when idle; CloudWatch Logs Insights is pay-per-query.
- **Trying to attach a security group directly to "OpenSearch Serverless"** — OpenSearch Serverless uses VPC endpoints; attach the SG to the endpoint, not the service. (Domain-mode OpenSearch *does* live in your VPC with its own ENIs and SGs.)

### Exam Triggers

- *"full-text search across product descriptions / documents"* → **OpenSearch**
- *"centralised log analytics with rich querying and dashboards"* → **OpenSearch**
- *"ELK stack / Kibana on AWS"* → **OpenSearch Service** (Dashboards is the Kibana fork)
- *"search-as-you-type, typo tolerance, relevance ranking"* → **OpenSearch**
- *"real-time observability dashboards beyond what CloudWatch provides"* → **OpenSearch**
- *"ingest logs from many sources for search and analytics"* → **Kinesis Firehose → OpenSearch**
- *"occasional log search, minimise cost"* → **CloudWatch Logs Insights** (not OpenSearch)
- *"OpenSearch without managing a cluster"* → **OpenSearch Serverless**

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

**Indexes — GSI vs LSI:**

By default DynamoDB only lets you query by the **table's** partition key (+ sort key). Want to query by a different attribute? You need a secondary index.

| | Global Secondary Index (GSI) | Local Secondary Index (LSI) |
| - | ---------------------------- | --------------------------- |
| When to create | Any time, after table creation | **At table creation only** — can't add later |
| Limit | 20 GSIs per table (soft limit) | 5 LSIs per table (hard limit) |
| Partition key | **Different** from the table's | **Same** as the table's |
| Sort key | Anything (or none) | Different from the table's |
| Reads | **Eventually consistent only** | Strongly or eventually consistent |
| Throughput | **Own RCU/WCU**, separate from the table | Shares the table's RCU/WCU |
| Storage | Separate physical storage | Stored alongside table partitions |
| Use case | Query by a totally different attribute | Different sort order within the same partition |

**Worked example — orders table:**

```
Table primary key: PK = customer_id, SK = order_date
Default queries:   "all orders for customer X" / "customer X's orders in Jan 2026"
```

- *Want: "find an order by order_id"* → **GSI** with PK = `order_id` (different partition key)
- *Want: "customer X's orders sorted by total_amount"* → **LSI** with PK = `customer_id`, SK = `total_amount`
- *Want: "all orders with status PENDING"* → **GSI** with PK = `status` (different partition key)

**Common GSI/LSI gotchas (exam favourites):**

- **GSI reads are eventually consistent only** — if a question says *"strongly consistent reads on a secondary attribute"*, the answer is LSI, not GSI.
- **LSI must be defined at table creation** — once the table exists you can't add an LSI. GSIs can be added/dropped any time.
- **GSI has its own throughput** — a GSI can be **throttled independently** of the base table. If the GSI WCU is too low, writes to the base table fail (because DynamoDB has to update the GSI synchronously and runs out of WCU).
- **Attribute projection** — choose what to copy into the index: `KEYS_ONLY`, `INCLUDE` (specific attributes), or `ALL`. Smaller projection = cheaper but more requests need a follow-up `GetItem` on the base table.
- **LSI shares the partition** with the base table — a "hot partition" on the base also hits the LSI; a GSI uses separate partitioning and can dodge that.

**Decision rule:**

| Need | Pick |
| ---- | ---- |
| Same partition key, different sort order, strongly consistent reads | **LSI** |
| Different partition key | **GSI** |
| Added after table already exists | **GSI** (LSI is impossible) |
| Independent throughput from the base table | **GSI** |

**DynamoDB Transactions (`TransactWriteItems` / `TransactGetItems`):**

Up to **100 items across multiple tables** in one all-or-nothing operation. If any item fails (conditional check, capacity, validation), the whole transaction rolls back.

```
TransactWriteItems:
  ├── Put     order:abc into Orders table
  ├── Update  user:42 in Users table (decrement balance)
  └── Update  inventory:widget in Stock table (decrement count)
  All succeed, or none do.
```

- **2× the WCU/RCU cost** of normal operations (transactions are billed double)
- **One AWS region only** — no cross-region transactions
- **Up to 4 MB total** for the whole transaction
- Supports **idempotency tokens** to safely retry

| | Conditional write | TransactWriteItems |
| - | ----------------- | ------------------ |
| Scope | One item | Up to 100 items, multiple tables |
| Atomicity | Single item | All-or-nothing across all items |
| Cost | Normal | 2× |
| Use case | "Update only if version = N" optimistic locking | Banking-style multi-record updates |

**Conditional writes:**

Every `PutItem`, `UpdateItem`, and `DeleteItem` can carry a `ConditionExpression` that must be true for the write to succeed. The check + write is **atomic at the item level**.

```
UpdateItem on user:42
  SET balance = balance - 100
  ConditionExpression: balance >= 100
  → Succeeds only if the current balance is ≥ 100; otherwise fails with no change
```

Common patterns:
- **Optimistic locking** — `attribute_not_exists(id)` to prevent overwrite of an existing item
- **Compare-and-swap** — `version = :expected_version` to detect concurrent updates
- **Conditional delete** — only delete if the item is in a specific state

**Exam triggers:**
- *"all-or-nothing update across multiple DynamoDB items"* → `TransactWriteItems`
- *"strongly consistent reads on a non-key attribute"* → LSI, not GSI
- *"add an index on an existing table"* → GSI (LSI can't be added after creation)
- *"GSI is throttling writes to the base table"* → increase the GSI's WCU
- *"prevent overwriting an existing item"* → conditional write with `attribute_not_exists`
- *"optimistic locking on DynamoDB"* → conditional write with a version attribute

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

A read cache that sits in front of DynamoDB and uses the **exact same API**. Your app doesn't change a single line of code — just change the endpoint.

The problem: your app reads the same item 1,000 times per second. Each read costs RCU and takes ~5ms. With DAX, the first read goes to DynamoDB. The next 999 come from DAX's in-memory cache at 0.1ms. You save 999 RCUs.

```
Without DAX: App → DynamoDB (5ms, costs RCU every time)
With DAX:    App → DAX (0.1ms, cache hit) → only cache misses hit DynamoDB
```

**DAX vs ElastiCache:**

| | DAX | ElastiCache |
| - | --- | ----------- |
| Code changes | None — same DynamoDB API | Yes — you write cache logic |
| Works with | DynamoDB only | Anything (RDS, APIs, any data) |
| Cache logic | Automatic (read-through/write-through) | You build it (lazy loading, TTL) |

DAX is the lazy option — drop it in, change the endpoint, done. ElastiCache gives more control but you write the caching logic yourself.

**When DAX helps:** read-heavy workloads where the same items are read repeatedly (leaderboards, product catalogs, user profiles).

**When DAX doesn't help:** write-heavy workloads (DAX caches reads, not writes), queries that always return different results (cache misses every time), or caching data from multiple sources (use ElastiCache).

**DynamoDB Global Tables:**

Multi-region, **active-active** replication. Write to any region, changes replicate to all others in typically under a second. A "global table" is really N identical tables (same name, same schema) in different regions, glued together by replication.

```
Write in eu-west-1 → local table → eu-west-1 stream
                                       ↓
                  replication service reads the stream
                                       ↓
                  applies the change to us-east-1, ap-south-1, ...
```

**Requirements (and why):**

| Requirement | Why |
| ----------- | --- |
| **DynamoDB Streams enabled** with view type `NEW_AND_OLD_IMAGES` | The stream **is** the replication transport. DynamoDB doesn't have a separate replication daemon — without streams, there's nothing to replicate from. `OLD_IMAGES` is needed for conflict detection, `NEW_IMAGES` for applying the change. |
| **Same table name in every region** | The replicator matches by name. Different names = different tables, not a global table. |
| **Same capacity mode in every region** | On-Demand everywhere, or Provisioned + auto-scaling everywhere. Can't mix — replication rates would diverge. |
| **Service-linked IAM role** | `AWSServiceRoleForDynamoDBReplication` lets the replication service write into peer regions on your behalf. |
| **v1 only: empty table when adding a region** | v2 (`2019.11.21`, the current version) lets you promote an existing table to global. Assume v2 on the exam unless v1 is specified. |

**Conflict resolution — last-writer-wins:**

If two regions write the same item at nearly the same moment, the one with the later timestamp wins. The loser's write is **silently dropped**, not merged. Design partition keys so a given item is usually written from one region (e.g. shard users by home region).

**Consistency model:**

- **Within a region** — strongly consistent reads work as normal.
- **Across regions** — eventually consistent only. Replication is fast (<1s typical) but you cannot read-after-write across regions and assume freshness.

**Cost — replicated Write Capacity Units (rWCU):**

A write is billed in every region it lands in. A 1 KB write replicated to 3 regions ≈ 3 rWCU. Reads are billed normally in whichever region serves them — Global Tables make reads *cheaper* (closer to users) but writes *more expensive* (multiplied by region count).

**Global Tables vs Aurora Global Database (exam trap):**

| | DynamoDB Global Tables | Aurora Global Database |
| - | ---------------------- | ---------------------- |
| Topology | Active-active — write in any region | Active-passive — one primary, others read-only |
| Conflict handling | Last-writer-wins | No conflicts possible (single writer) |
| Failover | None needed — every region is already writable | Promote a secondary region (~1 min RTO) |
| Use case | Global write-heavy apps (gaming, IoT, social) | Global read scale + DR for a relational app |

**Common anti-patterns (exam wrong answers):**

- **Using Global Tables for read-only DR** — overkill and expensive (you pay rWCU for writes you don't need replicated). A single-region table + cross-region backup or on-demand replication is cheaper.
- **Assuming strong consistency across regions** — only eventual. Cross-region read-after-write will see stale data.
- **Two regions writing the same item, expecting a merge** — last-writer-wins drops one. If you need merge semantics, use conditional writes + version numbers in application code.
- **Picking Global Tables when only reads need to be global** — DynamoDB DAX or CloudFront-cached reads may be cheaper. Global Tables shine when *writes* must be low-latency from multiple regions.

**Exam triggers:**

- *"multi-region active-active database with low-latency writes everywhere"* → DynamoDB Global Tables
- *"global table replication isn't working"* → DynamoDB Streams not enabled (or wrong view type)
- *"global database with one writer and read replicas in other regions"* → Aurora Global Database, **not** DynamoDB Global Tables
- *"two regions wrote the same item, one update disappeared"* → last-writer-wins, by design
- *"replication latency across regions"* → typically under 1 second, eventually consistent

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

The problem without conditional writes — race condition:

```
User A reads stock = 1
User B reads stock = 1
User A writes stock = 0 (bought last item)
User B writes stock = -1 ❌ (oversold — B didn't know A already bought it)
```

With conditional writes:

```
User A: Update stock = stock - 1 WHERE stock > 0 → succeeds (stock was 1, now 0) ✅
User B: Update stock = stock - 1 WHERE stock > 0 → rejected (stock is 0) ✅ no oversell
```

The condition is evaluated **atomically** on the server — no gap between read and write. DynamoDB checks and writes in one operation.

Real-world examples:
- **Inventory:** decrement stock only if stock > 0 (prevent overselling)
- **Booking:** assign a seat only if `booked = false` (prevent double booking)
- **Idempotency:** create an order only if `order_id` doesn't already exist (prevent duplicate processing)
- **Optimistic locking:** update only if `version = 3` (prevent stale writes from overwriting newer data)

Cheaper than transactions when you only need to protect a **single item**. Transactions are for multi-item all-or-nothing operations.

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

**DynamoDB vs RDS — feature differentiators:**

What makes DynamoDB special compared to RDS — the exam tests these:

| DynamoDB feature | RDS equivalent | Why DynamoDB wins |
| ---------------- | -------------- | ----------------- |
| TTL | No native equivalent — you write a cron job | Auto-delete at zero cost, no WCU consumed |
| Export to S3 | `mysqldump` or DMS — consumes DB resources | Zero RCU impact, runs against backups |
| DAX | ElastiCache (separate service, code changes) | Same API, drop-in cache, no code changes |
| Global Tables | Aurora Global DB (one writer, active-passive) | Active-active, write in any region |
| On-Demand | No equivalent — you provision instance size | Instant scaling, zero capacity planning |
| Streams | Aurora triggers Lambda (limited engines) | Built-in CDC on every table |
| Conditional writes | SQL `UPDATE WHERE` (needs transaction isolation) | Native atomic check-and-write |

### API Gateway

Managed service for creating, publishing, and securing REST/HTTP APIs. The front door for your serverless backend.

```
Client → API Gateway → Lambda → DynamoDB
                     → any HTTP endpoint
                     → any AWS service
```

**Three API types:**

| | REST API | HTTP API | WebSocket API |
| - | -------- | -------- | ------------- |
| Protocol | HTTP (request/response) | HTTP (request/response) | WebSocket (persistent two-way connection) |
| Features | Full — caching, WAF, API keys, usage plans, request validation | Simpler — fewer features | Real-time two-way messaging |
| Cost | Most expensive | 70% cheaper than REST | Pay per message + connection minutes |
| Latency | Higher | Lower | Persistent connection |
| Use case | Enterprise APIs needing all features | Simple APIs, Lambda proxies | Chat, gaming, live dashboards, IoT |

**WebSocket API** maintains a persistent connection — the server can push data to the client without the client asking. Use case: chat apps, live sports scores, real-time dashboards. REST/HTTP APIs are request-response only (client must poll for updates).

**Endpoint types:**

| Type | How it works | Use case |
| ---- | ------------ | -------- |
| Edge-optimised (default) | Requests routed through CloudFront edge locations | Global clients |
| Regional | No CloudFront, clients in the same region | Same-region clients, or you manage your own CloudFront |
| Private | Only accessible from within your VPC via VPC Endpoint | Internal microservice APIs |

**Exam trap — Edge-Optimised does NOT distribute your API globally:**

Your API Gateway still lives in **one region**. Edge-Optimised just puts CloudFront in front of it for faster routing. The edge locations don't run your API — they provide a faster network path to the single-region API Gateway.

```
Edge-Optimised:
User in Tokyo → CloudFront edge (Tokyo) → routes to API Gateway (us-east-1)
                                          (API Gateway is still in one region)

Regional:
User in Tokyo → directly to API Gateway (us-east-1)
                (no CloudFront in between)
```

Your Lambda functions, authorisers, and integrations all run in the one region. Only the CloudFront routing layer is distributed globally.

**Stages and canary deployments:**

Stages are named deployments (dev, staging, prod) — each gets its own URL. Within a stage, you can run a **canary deployment** — route a percentage of traffic to a new version:

```
prod stage:
├── 90% traffic → current version (stable)
└── 10% traffic → canary (new version being tested)
```

If the canary is healthy, promote it to 100%. If it fails, roll back — only 10% of users were affected.

**Usage plans + API keys — rate limiting per client:**

API keys identify the client. Usage plans define limits per key:

```
API Key: "partner-acme"  → Usage Plan: 1,000 requests/day, 10 requests/second
API Key: "partner-corp"  → Usage Plan: 10,000 requests/day, 50 requests/second
API Key: "internal-app"  → Usage Plan: unlimited
```

Use case: monetise your API (free tier vs paid tier), or limit third-party partners to prevent abuse. REST API only — HTTP API doesn't support usage plans.

**Throttling:**

- **Account-level:** 10,000 requests/second across all APIs (soft limit)
- **Stage/method-level:** configure per stage or per endpoint
- Exceeded → **429 Too Many Requests** returned to the client

**Caching:**

Cache responses at the API Gateway level — subsequent identical requests return the cached response without invoking Lambda:

```
First request:  Client → API Gateway → Lambda → response → cached
Next request:   Client → API Gateway → cached response (Lambda not invoked) ✅
```

- **Cache TTL:** 0–3600 seconds (default 300s). 0 effectively disables.
- **Cache size:** 0.5 GB to 237 GB, per stage
- **Per-stage** setting (dev vs prod) with **per-method overrides** (cache `GET /products` but not `POST /orders`)
- **REST API only** — HTTP API does not support caching
- **Encryption at rest** is optional

**Cache key — what makes two requests "the same":**

By default the cache key is the **full path + query string**. You can promote specific query params or headers to be part of the key so different values cache separately:

```
Default key:  GET /products?category=shoes
              GET /products?category=hats     ← cached separately if `category` is in the key

If `category` is NOT in the key, both share one cache entry → second request returns the wrong response ❌
```

Rule of thumb: anything that changes the response **must** be part of the cache key (user ID header, locale, currency, query params).

**Cache invalidation:**

Clients can force a cache bypass by sending `Cache-Control: max-age=0` on the request:

- Caller needs the `InvalidateCache` IAM permission, otherwise API Gateway returns **403** (or silently ignores, depending on stage setting)
- Useful for "refresh now" actions after a write
- You can also flush the entire stage cache from the console/API — disruptive, all keys cleared

**Cost trap (exam favourite):**

API Gateway cache is **not free** — you pay per hour for the provisioned cache size, whether it's hit or idle. Halving Lambda invocations does not automatically save money once the cache bill is added in.

| Scenario | Cache helps? |
| -------- | ------------ |
| High-traffic read endpoint, slow/expensive backend | ✅ Yes — fewer Lambda invocations + lower latency |
| Low-traffic API | ❌ No — cache idle cost outweighs Lambda savings |
| Per-user personalised responses with no repetition | ❌ No — every request is a miss |
| Mostly writes (POST/PUT) | ❌ No — writes aren't cached |

**Don't confuse with the Lambda authoriser cache:**

Two unrelated caches live in API Gateway — knowing the difference is an exam trap:

| | Response cache | Lambda authoriser cache |
| - | -------------- | ----------------------- |
| Caches | The backend response body | The *authorisation decision* (allow/deny + policy) |
| Keyed by | URL path + query + configured params/headers | The token (or token + identity sources) |
| Default TTL | 300s | 300s |
| Saves on | Backend Lambda invocations | Authoriser Lambda invocations |
| API types | REST only | REST and HTTP |

**Edge caching is different again** — API Gateway's cache is **regional**. For true edge caching, put **CloudFront** in front of a regional API. Edge-optimised API Gateway uses CloudFront for TLS termination but does **not** cache responses at the edge.

**Common anti-patterns (exam wrong answers):**

- **Caching POST responses** — POST/PUT/DELETE are not cached. If "reduce backend load on writes" is the goal, the answer is a queue (SQS), not a cache.
- **Cache key missing the variable that changes the response** — e.g. caching `/profile` without including the `Authorization` header → every user sees the first user's profile. Add the identifying header/param to the cache key.
- **Caching a low-traffic API to save money** — the hourly cache fee will exceed the Lambda savings. Either remove the cache or move it to CloudFront (only pays when cached).
- **Using API Gateway response cache when you actually want edge caching** — regional cache doesn't help users on the other side of the world. CloudFront in front is the right answer.

**Request/response mapping templates:**

Transform the payload between client and backend without changing Lambda code. Written in Velocity Template Language (VTL):

- Rename fields (`userName` → `user_name`)
- Add/remove fields
- Change data format (XML → JSON)
- REST API only

**Authorisation — three options:**

| Method | How it works | Use case |
| ------ | ------------ | -------- |
| IAM | Caller signs request with AWS credentials (SigV4) | AWS-to-AWS calls, internal services |
| Cognito User Pool | Client sends JWT, API Gateway validates it | Web/mobile app users |
| Lambda authoriser | Custom Lambda checks token/headers, returns an IAM policy | Third-party tokens, custom auth logic |

**Cognito integration flow:**

```
User → sign in → Cognito User Pool → JWT token
User → API request with JWT → API Gateway → validates token with Cognito
                             → authorised → Lambda → response
```

No custom code needed — API Gateway validates the JWT natively.

**Lambda authoriser flow:**

```
User → API request with token → API Gateway → Lambda authoriser
                               → authoriser checks token (against your DB, third-party, etc.)
                               → returns IAM policy (allow/deny)
                               → authorised → Lambda → response
```

The authoriser result is **cached** (default 300s) — subsequent requests with the same token skip the authoriser Lambda.

**Exam triggers:**
- *"create a serverless REST API"* → API Gateway + Lambda
- *"throttle API requests per client"* → API Gateway usage plans + API keys
- *"reduce Lambda invocations for repeated requests"* → API Gateway caching
- *"different users seeing each other's cached responses"* → cache key missing the user identifier (header/query param)
- *"force-refresh a cached API response"* → `Cache-Control: max-age=0` header + `InvalidateCache` IAM permission
- *"edge cache for an API serving global users"* → CloudFront in front of API Gateway (regional cache isn't edge)
- *"cheapest API for a simple Lambda proxy"* → HTTP API (not REST API)
- *"custom authentication logic for an API"* → Lambda authoriser
- *"real-time two-way communication"* → WebSocket API
- *"API accessible only from within the VPC"* → Private endpoint type
- *"test a new API version with a small % of traffic"* → canary deployment
- *"monetise an API with different rate limits per customer"* → usage plans + API keys
- *"authenticate API with Cognito user tokens"* → Cognito User Pool authoriser

**Do you always need API Gateway with Lambda? No.**

API Gateway is specifically for when you need an HTTP endpoint. Most Lambda triggers don't need it:

| Trigger | API Gateway needed? |
| ------- | ------------------- |
| S3 event (file uploaded) | No — S3 invokes Lambda directly |
| SQS message | No — Lambda polls the queue |
| DynamoDB Stream | No — Lambda polls the stream |
| CloudWatch / EventBridge schedule | No — invokes Lambda directly |
| SNS notification | No — SNS invokes Lambda directly |
| Another Lambda | No — invoke via SDK |
| ALB | No — ALB can invoke Lambda as a target |

**ALB vs API Gateway for HTTP endpoints:**

| | API Gateway | ALB |
| - | ----------- | --- |
| Cost | Per request ($3.50/million) | Per hour + per LCU (~$16/month min) |
| Features | Throttling, caching, API keys, usage plans, WebSocket | Basic routing, health checks |
| Best for | Feature-rich APIs, low/spiky traffic | High-volume, simple routing, already have an ALB |

**Exam shortcut:** "invoke Lambda on a schedule" or "invoke Lambda from S3" → no API Gateway. "REST API" or "HTTP endpoint" → API Gateway (or ALB for simpler cases).

### Step Functions

Visual **workflow orchestrator** — coordinate multiple Lambda functions (and other AWS services) into a sequence with branching, retries, error handling, and parallelism.

**The problem it solves — why not just chain Lambdas?**

Without Step Functions, you'd have Lambda A invoke Lambda B invoke Lambda C directly:

```
Without Step Functions (Lambda chaining — bad):
Lambda A → invokes Lambda B → invokes Lambda C → invokes Lambda D
  ├── If B fails? A doesn't know. No retry. No visibility.
  ├── If C times out? B is stuck waiting. You pay for idle time.
  └── Where did it fail? Check CloudWatch logs for each Lambda individually.
```

This is messy — no central visibility, no built-in retries, hard to debug, tightly coupled. Each Lambda needs to know about the next one.

```
With Step Functions (orchestration — good):
Step Functions manages the flow:
  A → B → C → D
  ├── B fails? Step Functions retries it 3 times automatically
  ├── C times out? Step Functions catches the error, runs a fallback
  └── Visual console shows exactly where it failed, with input/output at each step
```

Step Functions decouples the workflow from the functions. Each Lambda does one thing and doesn't know about the others. Step Functions handles the flow, retries, branching, and error handling.

A Lambda function also has a 15-minute timeout. Complex workflows (order processing, ETL pipelines, ML training) need multiple steps that together take much longer.

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

**Real-world examples:**

- **Order processing** — validate → charge payment → reserve stock → ship → notify customer. If payment fails, skip to refund. Each step is a separate Lambda.
- **ETL pipeline** — extract CSV from S3 → Lambda transforms data → load into Redshift → on failure, send to DLQ and notify ops
- **ML workflow** — prepare data → train model → evaluate accuracy → if accuracy > 90% deploy model, else retrain with different parameters
- **Human approval** — employee submits expense → Step Functions pauses → manager gets email → approves/rejects → payment processed or denied
- **Video processing** — upload triggers workflow → extract audio (Lambda) → transcribe (Amazon Transcribe) → translate (Amazon Translate) → generate subtitles → all in parallel where possible

**Not just Lambda — Step Functions integrates with 200+ AWS services directly:** S3, DynamoDB, SQS, SNS, ECS, Batch, Glue, SageMaker, and more. Many steps don't even need a Lambda function — Step Functions can call the AWS API directly (e.g. put an item in DynamoDB without a Lambda wrapper).

**Exam triggers:**
- *"orchestrate multiple Lambda functions"* → Step Functions
- *"workflow needs error handling and retries"* → Step Functions
- *"process takes longer than 15 minutes"* → Step Functions (or ECS/Batch)
- *"workflow requires human approval"* → Step Functions with wait for callback
- *"visual workflow designer"* → Step Functions
- *"chaining Lambda functions is getting complex"* → Step Functions (decouple the orchestration)

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

**Why Identity Pools exist — the photo upload example:**

Without Identity Pool: every photo goes through your backend. You pay for API Gateway + Lambda. At scale (millions of photos), your backend is a bottleneck and expensive.

```
Without: Mobile app → API Gateway → Lambda → uploads to S3 (slow, expensive at scale)
With:    Mobile app → Identity Pool → temporary credentials → uploads directly to S3 (fast, cheap)
```

**Why temporary credentials, not permanent API keys?** You can't embed permanent AWS access keys in a mobile app — anyone can decompile and steal them. Identity Pool gives temporary credentials (expire in 1 hour) scoped to exactly what that user can do:

```
User "bob" gets temporary credentials that ONLY allow:
  s3:PutObject to s3://my-bucket/users/bob/*

Bob can upload to his own folder. Can't read other users' files.
Credentials expire in 1 hour. If stolen, limited damage.
```

Other examples: mobile app reads user-specific DynamoDB data directly, IoT device writes sensor data to Kinesis, browser downloads private S3 files.

**When NOT to use:** when your backend should control all access. Most web apps go through API Gateway → Lambda → S3. Identity Pool is for cutting out the middleman (mobile, IoT, high-volume uploads).

**User Pool vs Identity Pool:**

| | User Pool | Identity Pool |
| - | --------- | ------------- |
| Purpose | Authentication (sign in) | Authorisation (AWS access) |
| Returns | JWT token | Temporary AWS credentials (STS) |
| Use case | "Log in to my app" | "Upload directly to S3 from the browser" |

Often used together: User Pool handles login, Identity Pool grants AWS access.

**Why Cognito User Pool instead of building your own auth?**

Rolling your own means: user database, password hashing, email verification, password reset flow, MFA, JWT signing/validation, social login OAuth flows, brute-force protection, compliance (GDPR). Cognito gives you all of this out of the box.

| | Build your own | Cognito User Pool |
| - | -------------- | ----------------- |
| User database | You manage (RDS/DynamoDB) | Managed by Cognito |
| Password hashing | You implement (bcrypt, argon2) | Built-in |
| MFA | You integrate (Authy, SMS API) | Built-in (SMS, TOTP) |
| Social login | You implement each OAuth flow | Toggle on Google/Facebook/Apple |
| Email verification | You build (SES + Lambda) | Built-in |
| Brute-force protection | You build rate limiting | Built-in (adaptive auth) |
| Hosted login page | You build from scratch | Built-in (customisable) |

**Hosted UI:**

Cognito provides a pre-built login/sign-up page you can use immediately. Customise the logo, CSS, and domain. Your app redirects to the Hosted UI, user logs in, Cognito redirects back with a JWT. No login page code to write or maintain.

```
Your app → redirect to Cognito Hosted UI → user signs in → redirect back with JWT
```

Use case: you want auth working in minutes, not days. Customise later.

**CUP + ALB — authenticate at the load balancer:**

Cognito User Pool can authenticate directly at the ALB — not just API Gateway. The ALB verifies the JWT before the request reaches your backend:

```
User → ALB (verifies Cognito JWT) → EC2/ECS/Lambda
       ├── Valid token → forward request ✅
       └── Invalid/missing → redirect to Cognito Hosted UI for login
```

This means your backend code **never handles authentication** — the ALB rejects unauthenticated requests before they arrive. Works with EC2, ECS, and Lambda targets.

**CUP Lambda Triggers — customise the auth flow:**

Lambda functions that run at specific points during sign-up and sign-in:

| Trigger | When it runs | Use case |
| ------- | ------------ | -------- |
| Pre sign-up | Before creating user | Validate email domain (only allow @company.com) |
| Post confirmation | After email verification | Send welcome email, create user profile in DynamoDB |
| Pre authentication | Before sign-in | Check if user is banned, log sign-in attempt |
| Post authentication | After successful sign-in | Add custom claims to token, sync user data |
| Pre token generation | Before JWT is issued | Add custom attributes to the JWT (role, permissions) |
| Custom message | When sending verification/MFA code | Customise email/SMS template |
| User migration | When user signs in for first time | Migrate users from old auth system on-demand |

Real-world example — migrating from an old auth system:

```
User signs in → Cognito: "user not found"
             → User Migration trigger → Lambda checks old database
             → User exists in old DB? → create in Cognito, return success
             → User doesn't exist? → reject sign-in
```

Users are migrated one-by-one as they sign in — no big-bang migration needed.

**Exam triggers:**
- *"add authentication to a web/mobile app"* → Cognito User Pool
- *"social login (Google, Facebook)"* → Cognito User Pool
- *"give users temporary AWS credentials"* → Cognito Identity Pool
- *"mobile app needs to upload directly to S3"* → Cognito Identity Pool
- *"authorise API Gateway requests with user tokens"* → Cognito User Pool as API Gateway authoriser
- *"authenticate users at the ALB"* → Cognito User Pool + ALB integration
- *"pre-built login page with minimal effort"* → Cognito Hosted UI
- *"run custom logic during sign-up (validate email domain)"* → CUP Lambda trigger (Pre sign-up)
- *"migrate users from an existing auth system"* → CUP User Migration Lambda trigger

### Microservices

A microservices architecture splits an application into small, independently deployable services that each own one capability (orders, payments, inventory, notifications). Each service has its own database, its own scaling, and its own deploy pipeline.

On AWS, a microservice is usually one of: a Lambda function, an ECS/Fargate service, or an EKS pod — fronted by API Gateway or an ALB. The hard part isn't the compute, it's **how services talk to each other**.

**Synchronous vs Asynchronous — the core decision:**

| | Synchronous | Asynchronous |
| - | ----------- | ------------ |
| Pattern | Service A calls Service B and waits for the response | Service A drops a message, B processes it later |
| Coupling | Tight — A is broken if B is down | Loose — A doesn't care if B is down |
| Latency | Caller pays B's full latency | Caller returns immediately (fire-and-forget) |
| Failure mode | Cascading — B down → A times out → A's caller times out | Isolated — messages queue up until B recovers |
| AWS services | API Gateway → Lambda, ALB → ECS, service-to-service HTTP | SQS, SNS, EventBridge, Kinesis, Step Functions |
| Use when | Caller needs the result *now* (checkout total, login) | Work can happen later (send email, resize image, update search index) |

**Synchronous example — order checkout:**

```
Browser → API Gateway → Order Service (Lambda)
                          ├── calls Payment Service (sync) — must succeed before order is confirmed
                          └── calls Inventory Service (sync) — must reserve stock before order is confirmed
                        ← returns 200 with order ID
```

Every hop adds latency, and any failure breaks the whole chain. Right pattern here — the user is waiting for a yes/no on their order.

**Asynchronous example — order fulfilment:**

```
Order Service → publishes "OrderPlaced" event to SNS
                ├── SQS → Email Service (send confirmation)
                ├── SQS → Warehouse Service (pick & pack)
                ├── SQS → Analytics Service (update dashboards)
                └── SQS → Loyalty Service (award points)
```

Order Service doesn't know or care who consumes the event. Add a new subscriber tomorrow without touching the Order Service. If the Email Service is down, messages queue up in SQS — nothing is lost.

**Choosing the right AWS integration pattern:**

| Pattern | Service | When |
| ------- | ------- | ---- |
| Point-to-point queue (one consumer) | **SQS** | Decouple producer from one consumer, smooth out spikes, retry on failure |
| Fan-out (many consumers, all get the message) | **SNS + SQS** | One event, multiple independent reactions (the order example above) |
| Event bus with filtering/routing | **EventBridge** | Many event sources and destinations, route by content, integrate with SaaS |
| Streaming (ordered, replayable) | **Kinesis** | Process the same stream multiple ways, replay history, analytics |
| Workflow orchestration | **Step Functions** | Long multi-step business process with retries, branching, human approval |
| Sync HTTP API | **API Gateway / ALB** | Browser or mobile client needs a response |
| Sync service-to-service | **Service Discovery + ALB** or **App Mesh** | Internal HTTP calls between containers |

**SNS vs EventBridge** — both are pub/sub but with different sweet spots. SNS is simpler and faster (sub-100ms), best for fan-out to SQS/Lambda. EventBridge supports **content-based filtering**, schema registry, and 100+ SaaS sources (Datadog, Zendesk, etc.) — use it when routing logic is non-trivial or events come from outside AWS.

**Orchestration vs Choreography:**

```
Orchestration (Step Functions):       Choreography (SNS/EventBridge):
  Workflow ─→ Service A                  Service A ──event──→ Service B
           ─→ Service B                                   ──→ Service C
           ─→ Service C                  No central controller — each service
  Central controller knows the steps     reacts to events from others
```

- **Orchestration** — easier to reason about, visualise, and debug. Central point of failure (mitigated by Step Functions being managed). Use for ordered multi-step workflows where you care about the overall outcome.
- **Choreography** — looser coupling, easier to add new services. Harder to trace end-to-end ("why didn't the email send?"). Use for event-driven flows where each service independently reacts.

**The Saga pattern** — for distributed transactions across microservices (no 2-phase commit available). Each step has a compensating action. Implement with Step Functions: if step 3 fails, run compensating actions for steps 1 and 2.

```
Book flight → Book hotel → Charge card
   ↓ fails              ↓ fails           ↓ fails
   nothing to undo      cancel flight     cancel flight + cancel hotel
```

**Sync wrapped around async — Request/Reply over a queue:**

If the caller really needs a response but you still want queue-based decoupling, use a reply queue with a correlation ID. Rare on the exam — sync HTTP is almost always the right answer when you need a response.

**Common microservices anti-patterns (exam wrong answers):**

- **Shared database** — two microservices reading/writing the same RDS table. Defeats the point — they're now coupled at the schema. Each service owns its own data store.
- **Distributed monolith** — services that must be deployed together because they call each other synchronously in a chain. Hides monolith complexity behind a network. Async events break the coupling.
- **Sync chain for non-blocking work** — calling an email service synchronously during checkout. Email failure shouldn't fail the order — publish an event instead.

**Exam triggers:**

- *"decouple microservices"* → **SQS** (one consumer) or **SNS** (fan-out)
- *"one event, multiple services need to react independently"* → **SNS + SQS fan-out** or **EventBridge**
- *"route events based on content / from SaaS sources"* → **EventBridge**
- *"orchestrate a multi-step workflow with retries and branching"* → **Step Functions**
- *"distributed transaction across microservices"* → **Saga pattern with Step Functions**
- *"service A is failing because service B is down"* → tight sync coupling → introduce a queue (async)
- *"need response immediately"* → synchronous (API Gateway/ALB)
- *"work can happen later, smooth out traffic spikes"* → asynchronous (SQS)
- *"two microservices share an RDS table"* → anti-pattern, each service should own its data

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
