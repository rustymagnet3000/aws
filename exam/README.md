# AWS Exam

<!-- TOC depthfrom:2 depthto:2 withlinks:true updateonsave:true orderedlist:false -->

- [AWS Exam](#aws-exam)
  - [Useful links](#useful-links)
  - [EC2](#ec2)
    - [Elastic IP versus Standard Public IP](#elastic-ip-versus-standard-public-ip)
    - [EC2 SSH Troubleshooting](#ec2-ssh-troubleshooting)
    - [1. Security Group — open port 22](#1-security-group--open-port-22)
    - [2. IPv6 vs IPv4](#2-ipv6-vs-ipv4)
    - [3. Permission denied (publickey)](#3-permission-denied-publickey)
    - [4. Accessing instance without the correct key](#4-accessing-instance-without-the-correct-key)
    - [Placement Groups](#placement-groups)
    - [AMI](#ami)
  - [EFS](#efs)
  - [Scaling and ELB](#scaling-and-elb)

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

**Target Group** — the collection of targets (EC2 instances, IPs, Lambda functions) that a load balancer routes traffic to. The ALB forwards a request to a Target Group based on listener rules; the Target Group then picks a healthy target and sends the request there. Health checks are configured per Target Group. The path-based routing example above (`/api` → one group, `/images` → another) means each path maps to a different Target Group.

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

If an instance fails a health check, ASG terminates it and launches a replacement automatically.

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

### Exam triggers

- *"run containers without managing servers"* → ECS on Fargate
- *"migrate a containerised app with minimal infrastructure overhead"* → Fargate
- *"need GPU instances or a custom AMI for containers"* → ECS on EC2
- *"keep a container running and replace it if it crashes"* → ECS Service
- *"scale containers based on load"* → ECS Service + ALB + target tracking policy
