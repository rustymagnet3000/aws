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

**Exam scenario: "shared storage dynamically loaded on hundreds of instances"**

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

**Exam triggers:**
- *"Lambda functions timing out connecting to RDS"* → RDS Proxy
- *"too many database connections"* → RDS Proxy
- *"reduce database failover time for the application"* → RDS Proxy
- *"serverless application with a relational database"* → RDS Proxy

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

**Exam trap: "which does NOT help with stateless design?"**

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
