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
  - [Centralised NAT (Egress VPC Pattern)](#centralised-nat-egress-vpc-pattern)
  - [Route Tables](#route-tables)
  - [Security Groups](#security-groups)
  - [NACLs (Network ACLs)](#nacls-network-acls)
  - [Security Groups vs NACLs](#security-groups-vs-nacls)
  - [VPC Endpoints](#vpc-endpoints)
  - [ENI-backed vs Public Endpoint Services](#eni-backed-vs-public-endpoint-services)
  - [VPC Peering](#vpc-peering)
  - [Transit Gateway](#transit-gateway)
  - [PrivateLink](#privatelink)
  - [DNS in a VPC](#dns-in-a-vpc)
  - [VPC Sharing via AWS RAM](#vpc-sharing-via-aws-ram)
  - [Amazon VPC Lattice](#amazon-vpc-lattice)
  - [AWS Cloud WAN](#aws-cloud-wan)
  - [AWS VPC IP Address Manager (IPAM)](#aws-vpc-ip-address-manager-ipam)
  - [IPv6 in a VPC](#ipv6-in-a-vpc)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [Reachability Analyzer and Network Access Analyzer](#reachability-analyzer-and-network-access-analyzer)
  - [Direct Connect and Site-to-Site VPN](#direct-connect-and-site-to-site-vpn)
  - [AWS Client VPN](#aws-client-vpn)
  - [Gateway Load Balancer (GWLB)](#gateway-load-balancer-gwlb)
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
- [Amazon CloudWatch](#amazon-cloudwatch)
  - [The Five Core Concepts](#the-five-core-concepts)
  - [The Monitoring Granularity Trap (exam favourite)](#the-monitoring-granularity-trap-exam-favourite)
  - [The CloudWatch Agent — the OS-level fact most miss](#the-cloudwatch-agent--the-os-level-fact-most-miss)
  - [Alarms + Auto Scaling — the classic pattern](#alarms--auto-scaling--the-classic-pattern)
  - [CloudWatch Alarms vs Datadog Monitors (mental anchor)](#cloudwatch-alarms-vs-datadog-monitors-mental-anchor)
  - [Composite Alarms (deep dive)](#composite-alarms-deep-dive)
  - [Testing Alarms](#testing-alarms)
  - [CloudWatch Synthetics (deep dive)](#cloudwatch-synthetics-deep-dive)
  - [CloudWatch Logs — the cost trap](#cloudwatch-logs--the-cost-trap)
  - [Logs Insights vs OpenSearch](#logs-insights-vs-opensearch)
  - [Specialised Variants (exam-relevant names)](#specialised-variants-exam-relevant-names)
  - [CloudWatch Contributor Insights (short deep dive)](#cloudwatch-contributor-insights-short-deep-dive)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-9)
  - [Exam Triggers](#exam-triggers-9)
- [AWS CloudTrail](#aws-cloudtrail)
  - [What CloudTrail is NOT](#what-cloudtrail-is-not)
  - [Main Part vs the Extras](#main-part-vs-the-extras)
  - [What CloudTrail Records](#what-cloudtrail-records)
  - [Three Event Types (each tested)](#three-event-types-each-tested)
  - [Event History vs Trails](#event-history-vs-trails)
  - [Standard Architecture (the exam-favourite pattern)](#standard-architecture-the-exam-favourite-pattern)
  - [Key Features (each shows up on the exam)](#key-features-each-shows-up-on-the-exam)
  - [CloudTrail + CloudWatch + EventBridge (the trio in action)](#cloudtrail--cloudwatch--eventbridge-the-trio-in-action)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-10)
  - [Exam Triggers](#exam-triggers-10)
- [AWS Config](#aws-config)
  - [What AWS Config is NOT](#what-aws-config-is-not)
  - [Core Concepts](#core-concepts)
  - [Worked Example: "No S3 bucket should ever be public"](#worked-example-no-s3-bucket-should-ever-be-public)
  - [Standard Architecture](#standard-architecture)
  - [Config + CloudTrail (the audit pair)](#config--cloudtrail-the-audit-pair)
  - [Pricing — Why It Matters on the Exam](#pricing--why-it-matters-on-the-exam)
  - [Privileges — Who Needs What](#privileges--who-needs-what)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-11)
  - [Exam Triggers](#exam-triggers-11)
- [AWS Organizations](#aws-organizations)
  - [What AWS Organizations is NOT](#what-aws-organizations-is-not)
  - [Core Concepts](#core-concepts-1)
  - [Standard Multi-Account Topology](#standard-multi-account-topology)
  - [Consolidated Billing — the Money Bit](#consolidated-billing--the-money-bit)
  - [SCPs (Service Control Policies) — Deep Dive](#scps-service-control-policies--deep-dive)
  - [Three Policy Layers: Identity Policy vs SCP vs Permissions Boundary](#three-policy-layers-identity-policy-vs-scp-vs-permissions-boundary)
  - [AWS Control Tower — the layer above Organizations](#aws-control-tower--the-layer-above-organizations)
  - [IAM Identity Center (formerly AWS SSO)](#iam-identity-center-formerly-aws-sso)
  - [Organization-Aware Services](#organization-aware-services)
  - [Pricing](#pricing)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-12)
  - [Common Exam Question Patterns](#common-exam-question-patterns)
  - [Exam Triggers](#exam-triggers-12)
- [AWS Control Tower & Landing Zones](#aws-control-tower--landing-zones)
  - ["Landing Zone" — the term is overloaded](#landing-zone--the-term-is-overloaded)
  - [What Control Tower is NOT](#what-control-tower-is-not)
  - [Core Concepts](#core-concepts-2)
  - [What Control Tower Sets Up on Day 1](#what-control-tower-sets-up-on-day-1)
  - [How Control Tower Account Provisioning Actually Flows](#how-control-tower-account-provisioning-actually-flows)
  - [Guardrails — Where the Governance Lives](#guardrails--where-the-governance-lives)
  - [Drift Detection](#drift-detection)
  - [CfCT and AFT — Customising Beyond the Defaults](#cfct-and-aft--customising-beyond-the-defaults)
  - [Control Tower vs Landing Zone Accelerator (LZA)](#control-tower-vs-landing-zone-accelerator-lza)
  - [Enrolling Existing Accounts](#enrolling-existing-accounts)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-13)
  - [Exam Triggers](#exam-triggers-13)
  - [Pricing](#pricing-1)
- [AWS Directory Service (Active Directory on AWS)](#aws-directory-service-active-directory-on-aws)
  - [The Three Flavours (this is the whole exam)](#the-three-flavours-this-is-the-whole-exam)
  - [What AWS Directory Service is NOT](#what-aws-directory-service-is-not)
  - [The Decision Tree](#the-decision-tree)
  - [How Domain-Joining an EC2 Instance Actually Flows](#how-domain-joining-an-ec2-instance-actually-flows)
  - [Trust Relationships (Managed AD Only)](#trust-relationships-managed-ad-only)
  - [Integration with IAM Identity Center](#integration-with-iam-identity-center)
  - [Common Use Cases](#common-use-cases)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-13)
  - [Exam Triggers](#exam-triggers-13)
  - [Pricing Notes](#pricing-notes)
- [AWS STS (Security Token Service)](#aws-sts-security-token-service)
  - [What STS is NOT](#what-sts-is-not)
  - [Core Concepts](#core-concepts-3)
  - [How AssumeRole Actually Flows](#how-assumerole-actually-flows)
  - [The External ID Pattern (Cross-Account from Third Parties)](#the-external-id-pattern-cross-account-from-third-parties)
  - [Role Chaining Limits](#role-chaining-limits)
  - [ABAC with Session Tags](#abac-with-session-tags)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-14)
  - [Exam Triggers](#exam-triggers-14)
- [Amazon Cognito](#amazon-cognito)
  - [What Cognito is NOT](#what-cognito-is-not)
  - [The Two Cognito Products (Constantly Confused)](#the-two-cognito-products-constantly-confused)
  - [User Pool Deep Dive](#user-pool-deep-dive)
  - [Identity Pool Deep Dive](#identity-pool-deep-dive)
  - [When to Use Cognito vs Alternatives](#when-to-use-cognito-vs-alternatives)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-15)
  - [Exam Triggers](#exam-triggers-15)
- [AWS KMS (Key Management Service)](#aws-kms-key-management-service)
  - [What KMS is NOT](#what-kms-is-not)
  - [Core Concepts](#core-concepts-4)
  - [Envelope Encryption — How It Actually Flows](#envelope-encryption--how-it-actually-flows)
  - [Common Use Cases (where KMS hides underneath)](#common-use-cases-where-kms-hides-underneath)
  - [Key Policies vs IAM Policies — the Gotcha](#key-policies-vs-iam-policies--the-gotcha)
  - [Worked Example: S3 Cross-Bucket Replication with SSE-KMS](#worked-example-s3-cross-bucket-replication-with-sse-kms)
  - [When to Use CloudHSM Instead](#when-to-use-cloudhsm-instead)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-16)
  - [Exam Triggers](#exam-triggers-16)
- [AWS Certificate Manager (ACM)](#aws-certificate-manager-acm)
  - [What ACM is NOT](#what-acm-is-not)
  - [Core Concepts](#core-concepts-5)
  - [How DNS Validation Actually Flows](#how-dns-validation-actually-flows)
  - [Where You Can Attach an ACM Cert](#where-you-can-attach-an-acm-cert)
  - [ACM Private CA (PCA) — the Internal mTLS Story](#acm-private-ca-pca--the-internal-mtls-story)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-17)
  - [Exam Triggers](#exam-triggers-17)
- [AWS Secrets Manager](#aws-secrets-manager)
  - [What Secrets Manager is NOT](#what-secrets-manager-is-not)
  - [Core Concepts](#core-concepts-6)
  - [How Rotation Actually Flows (numbered)](#how-rotation-actually-flows-numbered)
  - [Single-User vs Alternating-User Rotation](#single-user-vs-alternating-user-rotation)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-18)
  - [Exam Triggers](#exam-triggers-18)
- [AWS Systems Manager Parameter Store](#aws-systems-manager-parameter-store)
  - [What Parameter Store is NOT](#what-parameter-store-is-not)
  - [Core Concepts](#core-concepts-7)
  - [Standard vs Advanced Tier — When to Upgrade](#standard-vs-advanced-tier--when-to-upgrade)
  - [Common Patterns](#common-patterns)
  - [Secrets Manager vs Parameter Store — the Comparison](#secrets-manager-vs-parameter-store--the-comparison)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-19)
  - [Exam Triggers](#exam-triggers-19)
- [Amazon GuardDuty](#amazon-guardduty)
  - [What GuardDuty is NOT](#what-guardduty-is-not)
  - [Core Concepts](#core-concepts-8)
  - [How GuardDuty Actually Detects Things](#how-guardduty-actually-detects-things)
  - [Common Finding Types (worth recognising on the exam)](#common-finding-types-worth-recognising-on-the-exam)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-20)
  - [Exam Triggers](#exam-triggers-20)
- [Amazon Inspector](#amazon-inspector)
  - [What Inspector is NOT](#what-inspector-is-not)
  - [Resource Types and Scan Modes](#resource-types-and-scan-modes)
  - [Inspector v1 vs v2 — the historical context](#inspector-v1-vs-v2--the-historical-context)
  - [How EC2 Scanning Actually Flows](#how-ec2-scanning-actually-flows)
  - [ECR and Lambda — fully agentless (no choice to make)](#ecr-and-lambda--fully-agentless-no-choice-to-make)
  - [Inspector vs GuardDuty (the comparison the exam loves)](#inspector-vs-guardduty-the-comparison-the-exam-loves)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-21)
  - [Exam Triggers](#exam-triggers-21)
- [Amazon Macie](#amazon-macie)
  - [What Macie is NOT](#what-macie-is-not)
  - [The Two Layers of Macie](#the-two-layers-of-macie)
  - [What Macie Can Detect (Managed Data Identifiers)](#what-macie-can-detect-managed-data-identifiers)
  - [How a Macie Scan Actually Flows](#how-a-macie-scan-actually-flows)
  - [Why "Just S3"?](#why-just-s3)
  - [Multi-account: Same Delegated Admin Pattern](#multi-account-same-delegated-admin-pattern)
  - [The Trio Together](#the-trio-together)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-22)
  - [Exam Triggers](#exam-triggers-22)
- [AWS Security Hub](#aws-security-hub)
  - [What Security Hub is NOT](#what-security-hub-is-not)
  - [Core Concepts](#core-concepts-9)
  - [How Security Hub Pulls It All Together](#how-security-hub-pulls-it-all-together)
  - [Compliance Standards — the "what controls am I passing?" angle](#compliance-standards--the-what-controls-am-i-passing-angle)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-23)
  - [Exam Triggers](#exam-triggers-23)
- [AWS WAF (Web Application Firewall)](#aws-waf-web-application-firewall)
  - [What WAF is NOT](#what-waf-is-not)
  - [Core Concepts](#core-concepts-10)
  - [How a WAF Request Actually Flows](#how-a-waf-request-actually-flows)
  - [Where to Attach a Web ACL (and Why It Matters)](#where-to-attach-a-web-acl-and-why-it-matters)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-24)
  - [Exam Triggers](#exam-triggers-24)
- [AWS Shield + DDoS Resiliency (BP1–BP7)](#aws-shield--ddos-resiliency-bp1bp7)
  - [The BP1–BP7 Framework](#the-bp1bp7-framework)
  - [How the BPs Stack — Layered Defence Picture](#how-the-bps-stack--layered-defence-picture)
  - [Shield Standard vs Shield Advanced](#shield-standard-vs-shield-advanced)
  - [The EDoS Problem: Why DDoS Causes Cost Explosions](#the-edos-problem-why-ddos-causes-cost-explosions)
  - [How Shield Advanced Solves EDoS — Cost Protection](#how-shield-advanced-solves-edos--cost-protection)
  - [Architectural Mitigations (without Shield Advanced)](#architectural-mitigations-without-shield-advanced)
  - [When to Pay for Shield Advanced](#when-to-pay-for-shield-advanced)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-25)
  - [Exam Triggers](#exam-triggers-25)
  - [The Mental Model](#the-mental-model)
- [AWS Network Firewall + Firewall Manager](#aws-network-firewall--firewall-manager)
  - [AWS Network Firewall](#aws-network-firewall)
  - [AWS Firewall Manager](#aws-firewall-manager)
  - [The Combined Mental Model](#the-combined-mental-model)
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
  - [Amazon MQ](#amazon-mq)
  - [Amazon MSK (Managed Streaming for Apache Kafka)](#amazon-msk-managed-streaming-for-apache-kafka)
  - [Amazon Managed Service for Apache Flink](#amazon-managed-service-for-apache-flink)
  - [How MSK and Flink Fit Together](#how-msk-and-flink-fit-together)
  - [Kafka vs SNS vs Redis pub/sub](#kafka-vs-sns-vs-redis-pubsub)
  - [Amazon EventBridge](#amazon-eventbridge)
- [Amazon Redshift](#amazon-redshift)
  - [When People Reach for Redshift](#when-people-reach-for-redshift)
  - [OLTP vs OLAP](#oltp-vs-olap)
  - [Why Not RDS for Analytics?](#why-not-rds-for-analytics)
  - [Why Load into Redshift Instead of Querying S3?](#why-load-into-redshift-instead-of-querying-s3)
  - [Redshift Key Properties](#redshift-key-properties)
  - [Loading Data into Redshift](#loading-data-into-redshift)
  - [Redshift vs Athena](#redshift-vs-athena)
  - [Redshift Snapshots and Disaster Recovery](#redshift-snapshots-and-disaster-recovery)
- [AWS Glue](#aws-glue)
  - [The Five Pieces of Glue](#the-five-pieces-of-glue)
  - [Where Glue Sits in the Analytics Stack](#where-glue-sits-in-the-analytics-stack)
  - [Glue vs EMR — the Key Decision](#glue-vs-emr--the-key-decision)
  - [Job Bookmarks (exam favourite)](#job-bookmarks-exam-favourite)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-5)
  - [Exam Triggers](#exam-triggers-5)
- [AWS Lake Formation](#aws-lake-formation)
  - [What Lake Formation Adds](#what-lake-formation-adds)
  - [Who Honours Lake Formation Permissions](#who-honours-lake-formation-permissions)
  - [The Mental Model](#the-mental-model)
  - [Classic Use Cases](#classic-use-cases-1)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-6)
  - [Exam Triggers](#exam-triggers-6)
- [Amazon Athena](#amazon-athena)
  - [Key Properties](#key-properties)
  - [The Cost Model — Why File Format Matters](#the-cost-model--why-file-format-matters)
  - [Athena vs Redshift Spectrum (close cousins)](#athena-vs-redshift-spectrum-close-cousins)
  - [Athena vs DynamoDB (the "both are serverless" trap)](#athena-vs-dynamodb-the-both-are-serverless-trap)
  - [Federated Queries](#federated-queries)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-1)
  - [Exam Triggers](#exam-triggers-1)
- [Amazon OpenSearch Service](#amazon-opensearch-service)
  - [When OpenSearch, Anchored in What You Know](#when-opensearch-anchored-in-what-you-know)
  - [Key Properties](#key-properties-1)
  - [Where Does OpenSearch Actually Store the Data?](#where-does-opensearch-actually-store-the-data)
  - [Three Storage Tiers (cost optimisation)](#three-storage-tiers-cost-optimisation)
  - [Is OpenSearch a Database?](#is-opensearch-a-database)
  - [The Canonical Architecture](#the-canonical-architecture)
  - [Classic Use Cases](#classic-use-cases)
  - [OpenSearch vs CloudWatch Logs Insights](#opensearch-vs-cloudwatch-logs-insights)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-2)
  - [Exam Triggers](#exam-triggers-2)
- [Amazon EMR](#amazon-emr)
  - [Three Deployment Modes](#three-deployment-modes)
  - [When EMR Is the Right Answer](#when-emr-is-the-right-answer)
  - [When EMR Is the WRONG Answer](#when-emr-is-the-wrong-answer)
  - [The Decision Tree](#the-decision-tree)
  - [Real-World Scenarios Where EMR Wins](#real-world-scenarios-where-emr-wins)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-3)
  - [Exam Triggers](#exam-triggers-3)
- [Amazon QuickSight](#amazon-quicksight)
  - [The Real AWS-Native Datadog Competitor](#the-real-aws-native-datadog-competitor)
  - [QuickSight Key Properties](#quicksight-key-properties)
  - [When You'd Reach for QuickSight](#when-youd-reach-for-quicksight)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-4)
  - [Exam Triggers](#exam-triggers-4)
- [Big Data Ingestion Pipelines](#big-data-ingestion-pipelines)
  - [The Universal Pipeline Skeleton](#the-universal-pipeline-skeleton)
  - [Five Canonical Pipelines](#five-canonical-pipelines)
  - [Which Service at Each Stage](#which-service-at-each-stage)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-7)
  - [Exam Triggers](#exam-triggers-7)
- [AWS AI/ML Services](#aws-aiml-services)
  - [The Family at a Glance](#the-family-at-a-glance)
  - [Amazon Rekognition (the headliner for computer vision)](#amazon-rekognition-the-headliner-for-computer-vision)
  - [Amazon Transcribe (the headliner for speech-to-text)](#amazon-transcribe-the-headliner-for-speech-to-text)
  - [Amazon Polly (the headliner for text-to-speech)](#amazon-polly-the-headliner-for-text-to-speech)
  - [Amazon Translate (the headliner for machine translation)](#amazon-translate-the-headliner-for-machine-translation)
  - [Amazon Lex and Amazon Connect (chatbot brain + contact center)](#amazon-lex-and-amazon-connect-chatbot-brain--contact-center)
  - [Amazon Bedrock (the headliner for generative AI / foundation models)](#amazon-bedrock-the-headliner-for-generative-ai--foundation-models)
  - [Amazon Comprehend (the headliner for general NLP)](#amazon-comprehend-the-headliner-for-general-nlp)
  - [Amazon Comprehend Medical (HIPAA-eligible clinical NLP)](#amazon-comprehend-medical-hipaa-eligible-clinical-nlp)
  - [Amazon Kendra](#amazon-kendra)
  - [Amazon Personalize](#amazon-personalize)
  - [Amazon Textract](#amazon-textract)
  - [Amazon Forecast](#amazon-forecast)
  - [Amazon Fraud Detector](#amazon-fraud-detector)
  - [Amazon Augmented AI (A2I)](#amazon-augmented-ai-a2i)
  - [When to Pick SageMaker Over Pre-trained Services](#when-to-pick-sagemaker-over-pre-trained-services)
  - [Amazon SageMaker — Deep Dive](#amazon-sagemaker--deep-dive)
  - [Common Anti-patterns (exam wrong answers)](#common-anti-patterns-exam-wrong-answers-8)
  - [Exam Triggers](#exam-triggers-8)
  - [AI/ML Cheat Sheet](#aiml-cheat-sheet)
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

#### Egress-Only Internet Gateway (vs NAT Gateway)

The IGW handles **bidirectional** internet traffic (the source of most VPC internet connectivity). For "outbound only" patterns there are two parallel tools — one for each IP version. Knowing which goes with which is the most-tested IPv6 question.

**The fundamental difference:**

| | **NAT Gateway** | **Egress-Only IGW** |
| - | --------------- | ------------------- |
| IP version | **IPv4 only** | **IPv6 only** |
| Job | Translate private IPv4 → public IPv4 **AND** block inbound | Block unsolicited inbound IPv6 (no translation needed) |
| Cost | ~$33/month per AZ + $0.045/GB | **Free** — no hourly, no per-GB |
| Multi-AZ | One per AZ for HA | One per VPC (covers all AZs) |
| 55k connection limit per destination | Yes | **No** |
| Source IP preserved at destination | ❌ No — destination sees NAT's public IP | ✅ Yes — original IPv6 preserved |
| Route table entry | `0.0.0.0/0 → nat-xxx` | `::/0 → eigw-xxx` |

They're **not alternatives** — they're parallel constructs for the two IP families. Dual-stack VPCs use **both**, with separate route-table entries.

**Why both exist — the conceptual reason:**

NAT Gateway does **two jobs at once** in IPv4:

```
NAT Gateway in IPv4:
  1. Translate private IP → public IP   ← REQUIRED because RFC 1918 IPs
                                          can't route on the internet
  2. Block unsolicited inbound          ← side effect of NAT (no translation
                                          entry = nowhere to send inbound)
```

IPv6 addresses are **globally routable by design**. There are no "private" IPv6 addresses in the same sense — every IPv6 address you get from AWS *is* a public, internet-routable address. So **job #1 isn't needed**. You don't translate anything.

But you still want *"private subnet, no inbound from internet."* That's where Egress-Only IGW comes in — it's specifically the **"block inbound, allow outbound"** gateway, without any translation overhead:

```
Egress-Only IGW in IPv6:
  1. (no translation needed)
  2. Block unsolicited inbound          ← the only job

Just job #2. That's why it's free — no translation infrastructure to run.
```

**How a request flows through Egress-Only IGW:**

```
IPv6 instance in private subnet (2001:db8:1:1::10)
  │
  │ HTTPS request to api.example.com (2606:4700::1)
  ▼
Subnet route table:  ::/0 → eigw-xxx
  │
  ▼
Egress-Only IGW: stateful — records the outbound flow
  │
  ▼
AWS backbone → internet → api.example.com
                            (sees the request from 2001:db8:1:1::10 — the
                             ACTUAL instance address, not a translated one)

Reply (api.example.com → 2001:db8:1:1::10):
  Egress-Only IGW: "I have state for this flow → allow"  → reaches instance

Unsolicited inbound from internet to 2001:db8:1:1::10:
  Egress-Only IGW: "no state — this wasn't initiated from inside"  → blocked
```

The stateful behaviour is identical to NAT Gateway's "outbound creates state, inbound matched against state." Just no IP translation step.

**Benefits beyond cost:**

1. **No 55k connection limit per destination** — the NAT Gateway gotcha doesn't apply (no port translation table)
2. **Source IP preserved at destination** — 1,000 instances calling the same external API show up as 1,000 distinct IPv6 addresses (vs all appearing as the single NAT IP). Better debugging, better third-party allowlisting, better forensics
3. **Simpler HA** — one Egress-Only IGW per VPC covers all AZs (vs NAT needing one per AZ + asymmetric routing risk)
4. **No data-processing charge** — at 10 TB/month outbound, NAT's $0.045/GB = ~$450/month of pure overhead. Egress-Only IGW = $0

**When you'd use each:**

| Scenario | Use |
| -------- | --- |
| **IPv4-only VPC** (most VPCs today) | **NAT Gateway** for IPv4 outbound; no Egress-Only IGW |
| **IPv6-only VPC** (e.g. EKS at scale) | **Egress-Only IGW** for IPv6 outbound; no NAT Gateway |
| **Dual-stack VPC** (IPv4 + IPv6) | **Both** — NAT for IPv4 traffic, Egress-Only IGW for IPv6 traffic |

**The catch (why everyone isn't using it):**

- **Destination must be IPv6-reachable.** Most modern public services are dual-stack (AWS, Google, Cloudflare, GitHub, npm, PyPI, Docker Hub). Legacy/niche IPv4-only destinations still need NAT
- **App stack must speak IPv6.** Older runtimes/libraries sometimes default to IPv4 and need configuration
- **On-prem might not be IPv6-ready** — peered / VPN / DX traffic to on-prem is typically IPv4 and needs NAT

**Mental model:**

> *NAT Gateway does **two jobs**: translate private→public AND block inbound (the second is a side effect of the first). Egress-Only IGW does **only the second job** because IPv6 addresses are already globally routable. That's why Egress-Only IGW is free: there's no translation infrastructure to run. They're not alternatives — they're parallel constructs for the two IP families. Dual-stack = use both.*

**Exam triggers:**

- *"IPv6 instances need outbound internet but not inbound"* → **Egress-Only IGW**
- *"Save NAT Gateway costs for high-volume outbound at scale"* → **dual-stack + Egress-Only IGW** for the IPv6 traffic
- *"Preserve source IP at the destination for thousands of instances"* → **Egress-Only IGW** (NAT hides them all behind one public IP)
- *"NAT Gateway connection-limit exhaustion (55k per destination)"* → IPv6 + **Egress-Only IGW** sidesteps it
- *"My IPv4 instance needs internet but not inbound"* → **NAT Gateway**, not Egress-Only IGW (this is the trap)
- *"Why does my IPv6 instance still not reach the internet despite Egress-Only IGW?"* → either the destination is IPv4-only, or the route table is missing `::/0 → eigw-xxx`

### NAT Gateway vs NAT Instance

Private subnets need a way to reach the internet for outbound traffic (package updates, third-party APIs) **without** being reachable inbound. A NAT does the translation.

**Status note:** AWS's official NAT instance AMI (`amzn-ami-vpc-nat`) was **deprecated in December 2020** — AWS no longer patches or updates it. The *capability* isn't removed: you can still run a NAT instance on any Linux AMI with `iptables` MASQUERADE configured. The popular modern community AMI is **[fck-nat](https://fck-nat.dev)** — drop-in NAT instance on a `t4g.nano` for ~$3/month. Most exam questions assume NAT Gateway as the default; NAT Instance still appears as the **cost-optimisation answer** for low-traffic / dev environments.

| | NAT Gateway | NAT Instance (e.g. fck-nat) |
| - | ----------- | --------------------------- |
| What it is | Managed AWS service | EC2 instance you manage (AWS AMI deprecated 2020; use fck-nat or your own) |
| Scaling | Up to 100 Gbps, automatic | Instance-size-limited (5 Gbps on `t4g.nano`, more on bigger) |
| Patching / HA | AWS handles it | You patch the OS; you set up Auto Scaling for HA |
| Cost (idle) | ~$0.045/hour × 730h ≈ **~$33/month per AZ** | `t4g.nano` ≈ **~$3/month per AZ** |
| Cost (data) | + ~$0.045/GB processed | Just normal EC2 data transfer |
| Cost — typical multi-AZ dev VPC | ~$99/month (3 AZs idle) before data | ~$9/month for 3 × t4g.nano |
| AZ scope | Single AZ — one per AZ for HA | Single AZ — one per AZ for HA |
| Security group on the NAT | ❌ NAT Gateway has no SG | ✅ NAT Instance is just an EC2 — full SG control |
| Port forwarding (inbound DNAT) | ❌ | ✅ |
| Bastion + NAT combined | ❌ | ✅ (the box can do both jobs) |
| Connection limit | 55k per unique destination IP+port | Limited by ephemeral port range + instance memory |
| Use | **Default choice for production** | **Cost-optimisation for dev / low-traffic**; specialised needs (port forward, custom iptables, bastion combo) |

**The HA trap:** a NAT Gateway lives in **one AZ**. If you put all private subnets through a single NAT Gateway in `eu-west-1a` and that AZ fails, private subnets in `eu-west-1b` also lose internet (they were routing through the dead NAT). **Fix:** one NAT Gateway per AZ, each private subnet routes to its own AZ's NAT.

```
Multi-AZ NAT setup:
  Private subnet in 1a → NAT GW in 1a → IGW
  Private subnet in 1b → NAT GW in 1b → IGW   ← independent failure domains
```

**The 55,000 connection limit gotcha:** a single NAT Gateway supports up to **55,000 simultaneous connections per unique destination (IP + port)**. If hundreds of EC2 instances all hammer the same external endpoint (e.g. a popular SaaS API on the same hostname:port), you can exhaust this and see intermittent connection failures — but only to *that* destination. Calls to other destinations work fine. **Fix:** distribute traffic across multiple destinations / endpoints, deploy multiple NAT Gateways in the same AZ + split subnets across them, or use **VPC Endpoints** for AWS services to bypass NAT entirely. Exam trigger: *"hundreds of EC2 instances seeing intermittent connection drops to a single external API but other traffic works"* → **NAT Gateway 55k connection limit per destination**.

**NAT exam triggers:**

- *"Default NAT for production"* → **NAT Gateway**
- *"Most cost-effective NAT for low-traffic dev environment"* → **NAT Instance** (10× cheaper than NAT GW)
- *"NAT with port forwarding (inbound DNAT)"* → **NAT Instance** — NAT GW doesn't support it
- *"Attach a security group to my NAT"* → **NAT Instance** — NAT GW has no SG
- *"Highly available, scalable, managed NAT"* → **NAT Gateway one-per-AZ**
- *"AWS-provided NAT instance AMI"* → **deprecated since 2020** — use community AMIs (fck-nat) or NAT GW
- *"Combine bastion + NAT on a single instance"* → **NAT Instance** (one EC2 doing both jobs)

### Centralised NAT (Egress VPC Pattern)

The default is "NAT Gateway in every VPC." At scale this gets expensive fast — 20 VPCs × 3 AZs = **60 NAT Gateways × ~$33/month idle = ~$2,000/month** before any data charges. The fix is **centralised NAT**: deploy NAT Gateways in **one shared egress VPC** and route every other VPC's outbound traffic through it via Transit Gateway.

```
                    Internet
                        │
                        ▼
              ┌───────────────────────────┐
              │  CENTRAL EGRESS VPC       │
              │    NAT GW (per AZ)        │
              │    + optional Network     │
              │      Firewall / WAF       │
              └─────────────┬─────────────┘
                            │
                    Transit Gateway
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
            VPC A         VPC B         VPC C
        (no NAT GW)   (no NAT GW)   (no NAT GW)
        Route table:  Route table:  Route table:
        0.0.0.0/0     0.0.0.0/0     0.0.0.0/0
            → TGW         → TGW         → TGW
```

Spoke VPCs send `0.0.0.0/0` to the TGW; TGW forwards to the egress VPC; the egress VPC's NAT Gateway handles the SNAT; response returns the same path.

#### Why centralised NAT wins

| Driver | Impact |
| ------ | ------ |
| **Cost** | 60 NAT Gateways → 3 NAT Gateways = **~$2,000/month → ~$99/month** before data. By far the most common reason orgs adopt it |
| **Centralised egress filtering** | One place to attach **AWS Network Firewall** for egress inspection, one place to monitor Flow Logs |
| **Consistent egress IPs** | All VPCs egress from the same handful of public IPs — useful when **whitelisting at third parties** (SaaS APIs, customer firewalls) |
| **Simpler management** | Central networking team owns NAT + firewall; spoke teams don't manage networking primitives |
| **Easier compliance** | All outbound traffic auditable in one place |

#### The trade-offs

| Trade-off | Detail |
| --------- | ------ |
| **TGW data processing charges** | Every cross-VPC packet incurs TGW data charges (~$0.02/GB). At very high volume this can eat the NAT savings — do the maths |
| **Asymmetric routing risk** | If response packets come back via a different path, sessions break. Careful TGW route-table design needed |
| **Single egress VPC = blast radius** | Mitigate with multi-AZ NAT Gateways in the egress VPC (you'd do this anyway) |
| **Cross-region complexity** | Multi-region setups need TGW peering or per-region egress VPCs |
| **Doesn't help VPC Endpoint traffic** | Traffic to S3/DynamoDB via Gateway endpoints bypasses NAT entirely anyway — that's still the right pattern for AWS-service traffic |

#### Exam triggers

- *"Reduce NAT Gateway costs across many VPCs"* → **Centralised egress VPC**
- *"30 VPCs, want to consolidate NAT"* → **Centralised egress VPC + TGW**
- *"Consistent public egress IPs across all our AWS accounts"* → **Centralised NAT in egress VPC**
- *"Centrally inspect all outbound traffic from our VPCs"* → **Centralised egress + AWS Network Firewall**
- *"Simpler management of NAT across the org"* → **Centralised egress VPC pattern**

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

A NACL is a **stateless, subnet-level firewall** with both Allow and Deny rules. Most teams set it up once and forget it — but when it bites, it's usually because of the **stateless + ephemeral ports** combination. That's the part the exam loves.

#### Core properties

- **Stateless** — you must allow inbound **and** outbound separately. The return traffic is **not** auto-allowed (unlike Security Groups). This is the source of most NACL incidents
- **Attached to subnets** — every resource in the subnet shares the NACL
- **One subnet → one NACL** — but one NACL can be associated with many subnets
- **Allow AND Deny rules** — unlike SGs which are allow-only. Useful for explicit IP blocks
- **Rules evaluated in order** — lowest rule number first; **first match wins** (then evaluation stops)
- **Implicit final `*` deny** — every NACL ends with an invisible `* → DENY ALL` that you can't remove
- **Default NACL** allows all inbound + outbound. **Custom NACLs** start denying everything
- **Per-VPC** — can't share NACLs across VPCs
- **Filters traffic *crossing* subnet boundaries only** — traffic *within* a subnet is not inspected by the NACL

#### The ephemeral port trap (most-tested NACL gotcha)

> *"I allowed port 443 inbound. Why are my HTTPS connections still failing?"*

Because the **response** goes out on the **client's ephemeral port**, not on port 443. With a stateless NACL, you need a rule for that too.

```
   Client (1.2.3.4, ephemeral port 51234)
         │
         │ SYN  src=1.2.3.4:51234  dst=10.0.1.10:443
         ▼
   ┌───────────────────────┐
   │ Subnet NACL — inbound │
   │ Rule: ALLOW 443       │  ✅ accept
   └─────────┬─────────────┘
             ▼
         Your server processes the request
             │
             │ SYN+ACK  src=10.0.1.10:443  dst=1.2.3.4:51234
             ▼
   ┌────────────────────────┐
   │ Subnet NACL — outbound │
   │ Rule: ALLOW 443?       │  ❌ no — destination port is 51234, not 443
   │ Implicit * DENY        │  → packet dropped
   └────────────────────────┘
```

**The fix:** outbound NACL rules must allow the **ephemeral port range** as destination, because that's where the response is heading (the client's ephemeral port). For typical clients:

| Client OS / runtime | Ephemeral port range |
| -------------------- | -------------------- |
| **Linux** (default) | 32768 – 60999 |
| **Windows** | 49152 – 65535 |
| **AWS Lambda / NAT Gateway** | 1024 – 65535 |
| **Safe blanket rule** | **1024 – 65535** (covers all clients) |

Most outbound NACL rules look like `ALLOW TCP 1024-65535` — that's the response channel for inbound services.

**Mental model:** *Stateless NACLs need a rule for the response port — and the response port is the **client's** ephemeral port, not your service port. The outbound NACL rule isn't for your service speaking outbound; it's for sending responses back to clients on their ephemeral ports.*

#### Rule numbering convention

Rules are evaluated lowest-number first. **Leave gaps between rule numbers** so you can insert new rules later without renumbering:

```
100   ALLOW  TCP   443       0.0.0.0/0        (HTTPS)
200   ALLOW  TCP   80        0.0.0.0/0        (HTTP)
300   DENY   ALL   ALL       1.2.3.4/32       (block specific bad IP)
*     DENY   ALL   ALL       0.0.0.0/0        (implicit, can't remove)
```

If a new rule needs to come between rules 100 and 200, you can number it 150 without renumbering anything. Gap-based numbering (100, 200, 300…) is the convention.

**First match wins:** if rule 100 allows the traffic, rule 200 is never evaluated. **Order your DENY rules before broader ALLOW rules** if you want them to win.

#### NACLs only filter subnet-boundary traffic

Traffic *between* two instances **in the same subnet** is not inspected by the NACL — only traffic that **enters or leaves** the subnet hits the NACL. This catches people out:

```
Subnet 10.0.1.0/24, NACL denies inbound on port 22:

  Instance A (10.0.1.10) → Instance B (10.0.1.20) on port 22 → ✅ ALLOWED
    (traffic stays within the subnet, never crosses NACL boundary)

  External (1.2.3.4) → Instance B (10.0.1.20) on port 22 → ❌ BLOCKED
    (crosses into the subnet, NACL evaluates)
```

If you want to block intra-subnet traffic, that's a **Security Group** job — NACLs can't.

#### ICMP handling (ping)

ICMP doesn't use ports — it uses **types and codes**:

| ICMP message | Type | Code |
| ------------ | ---- | ---- |
| Echo Request (ping out) | 8 | 0 |
| Echo Reply (ping response) | 0 | 0 |
| Destination Unreachable | 3 | 0–15 |

For ping to work through a NACL, you need:
- Inbound: `ALLOW ICMP, type 8, code 0` (the echo request arriving)
- Outbound: `ALLOW ICMP, type 0, code 0` (the echo reply going back)

Or — if your instance is initiating the ping outbound:
- Outbound: `ALLOW ICMP, type 8, code 0`
- Inbound: `ALLOW ICMP, type 0, code 0`

Exam trigger: *"ping fails from outside the VPC even though SG allows ICMP"* → NACL is missing the echo reply rule.

#### When NACLs are actually the right tool

NACLs aren't just "block malicious IPs." Real use cases:

| Use case | Why NACL not SG |
| -------- | --------------- |
| **Block a known-bad IP range** | SGs are allow-only — can't deny |
| **PCI / regulatory subnet segregation** | Auditor wants a subnet-level firewall rule that's independent of per-instance config |
| **Defence in depth** — second layer after SG | Two independent filtering layers reduce blast radius of a misconfigured SG |
| **Compliance — audit trail of denies** | NACL deny rules show explicit policy. Combine with VPC Flow Logs `REJECT` entries for forensics |
| **Subnet-wide allow lists** for sensitive subnets | "Only this CIDR range can reach the DB subnet" — applies regardless of which instance is there |

#### Exam triggers

- *"Block a specific IP range from reaching the whole subnet"* → **NACL deny rule** (SGs are allow-only)
- *"I allowed port 443 inbound but HTTPS still fails"* → **NACL outbound missing ephemeral port range** (1024-65535)
- *"Why does ping fail through my NACL?"* → **Missing ICMP echo reply rule** (type 0)
- *"Two instances in the same subnet can talk despite the NACL deny"* → **NACLs don't filter intra-subnet traffic**; use Security Groups
- *"Why is rule 200 not taking effect?"* → **Rule 100 already matched** (first-match-wins; reorder)
- *"Default NACL behaviour vs new custom NACL"* → Default allows all; custom starts deny-all
- *"Defence in depth at the subnet layer for PCI"* → **NACL** (auditor wants subnet-level rules)

### Security Groups vs NACLs

| | Security Group | NACL |
| - | -------------- | ---- |
| Attached to | ENI (instance) | Subnet |
| Granularity | **Per-resource** (granular) | **Per-subnet** (blanket) |
| Stateful? | ✅ Yes — return traffic auto-allowed | ❌ No — must allow both directions |
| Ephemeral port handling | **Automatic** (stateful) | **You must allow the response port range yourself** (e.g. 1024-65535 outbound) |
| Rule types | **Allow only** | **Allow + Deny** |
| Rule evaluation | All rules evaluated; any allow → permitted | **Ordered**, first match wins |
| Implicit final deny? | No — unmatched is just denied | ✅ Yes — visible `*` rule you can't remove |
| Filters intra-subnet traffic? | ✅ Yes (each ENI evaluated) | ❌ No — only filters traffic *crossing* subnet boundary |
| Reference other SGs by ID | ✅ Yes (`sg-xxx` as source/dest) | ❌ No — CIDR only |
| Reference other accounts' SGs | ✅ Yes (cross-account peering) | ❌ No |
| Max rules | 60 inbound + 60 outbound per SG, 5 SGs per ENI | 20 rules per direction (soft limit, raisable) |
| Default for new | Deny all inbound, allow all outbound | Custom: deny all. Default: allow all |
| Use case | Day-to-day "who can talk to this resource" | Subnet-wide block/allow, deny lists, defence-in-depth |

**The exam shortcut:** SG is the default tool. NACL is for when you specifically need a **deny** (e.g. block a malicious IP range) or a subnet-wide rule that's independent of per-instance config.

**Quick mental model:** *Security Group is a stateful per-instance firewall (think `iptables` on the host). NACL is a stateless per-subnet ACL (think router ACL). They stack: traffic must pass both. SGs do the heavy lifting; NACLs handle blanket bans and defence in depth.*

### VPC Endpoints

A VPC Endpoint lets resources in your VPC reach AWS services **without going over the public internet** (no NAT Gateway, no IGW). Two completely different mechanisms under the same name — knowing which is which is the most-tested VPC topic on the SAA exam.

#### The Two Flavours — Full Comparison

| | **Gateway Endpoint** | **Interface Endpoint** |
| - | -------------------- | ----------------------- |
| Services supported | **S3 and DynamoDB only** (just these two) | Almost every other AWS service: SQS, SNS, Kinesis, KMS, Secrets Manager, EC2 API, ECR, CloudWatch Logs, Step Functions, API Gateway, Systems Manager, Athena, Glue, etc. |
| Underlying mechanism | **Custom routing entry** in your VPC route table pointing at the endpoint | **ENI created in each chosen subnet** with a private IP |
| Cost | **Free** (no hourly charge, no data charge) | **~$0.01/hour per endpoint per AZ** + **~$0.01/GB processed** |
| DNS | Public DNS unchanged; **routing decides** what's private | Endpoint gets a **regional DNS name**; **Private DNS option** rewrites the public DNS to resolve to the endpoint's private IPs |
| Security control | **Endpoint policy** (resource policy on the endpoint) | **Endpoint policy + Security Group** (on the ENI) |
| Reachable from on-prem (via DX / VPN) | ❌ **No** — Gateway endpoints work only from inside the VPC's route table | ✅ **Yes** — on-prem can reach the ENI's private IP via DX/VPN |
| Reachable from peered VPC | ❌ **No** (edge-to-edge routing limitation) | ❌ Not directly (PrivateLink limitation) — needs its own endpoint in each VPC |
| Powered by | Custom routing | **PrivateLink** (Interface endpoints ARE PrivateLink under the hood) |
| HA / multi-AZ | Inherently HA — route entry applies to all subnets in the VPC | **You** decide which AZs to deploy ENIs in — pay per AZ |
| Max per VPC | 255 per service | No hard cap; cost-bound |

**The 90% shortcut:** *"S3 or DynamoDB privately"* → **Gateway endpoint** (free). *"Any other AWS service privately"* → **Interface endpoint** (paid).

#### How Each Endpoint Actually Routes a Request

```
GATEWAY ENDPOINT (S3 / DynamoDB):

  EC2 in private subnet
       │
       │ aws s3 ls s3://bucket
       ▼
  Public DNS: s3.eu-west-1.amazonaws.com → 52.x.y.z (PUBLIC IP)
       │
       │ but route table for this subnet contains:
       │   pl-6da54004 (S3 prefix list) → vpce-xxx (Gateway Endpoint)
       │
       ▼
  Traffic routes via Gateway Endpoint → S3 (over AWS backbone)
  Never touches the internet, never hits NAT.
```

The clever bit: Gateway endpoints use **prefix lists** (`pl-xxx`) that contain all current S3 / DynamoDB IPs in the region. The route table sends those prefixes to the endpoint, not to NAT/IGW.

```
INTERFACE ENDPOINT (e.g. KMS, Secrets Manager, ECR):

  EC2 in private subnet
       │
       │ aws kms decrypt ...
       ▼
  Without Private DNS:
    Public DNS: kms.eu-west-1.amazonaws.com → public IP → blocked (no NAT)
    Must use:   vpce-xxx-yyy.kms.eu-west-1.vpce.amazonaws.com → ENI's private IP
    → app code change needed

  With Private DNS enabled (the default for AWS services):
    Public DNS: kms.eu-west-1.amazonaws.com → **rewritten to private IP**
    → app code stays the same; transparently routes via ENI
       ↓
  Traffic enters the ENI in the AZ → AWS backbone → service
```

**Private DNS magic:** when enabled, the VPC's resolver returns the endpoint's private IP for the *public* service hostname. Apps using the standard SDK / hostname keep working with no code changes.

#### Endpoint Policies — IAM for the Endpoint

Every endpoint has its own resource-based policy that controls **what API calls can pass through this endpoint** (independent of the caller's IAM). Default is "allow all" — tighten when you need to.

**Example: Gateway endpoint restricted to a specific bucket:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::my-app-data",
      "arn:aws:s3:::my-app-data/*"
    ]
  }]
}
```

Any request through this endpoint can only touch `my-app-data`. Calls to other S3 buckets via this endpoint fail — even if IAM allows.

**Use cases for endpoint policies:**
- **Data exfiltration control** — endpoint can only reach approved S3 buckets in your org. Stops attackers from `aws s3 cp` to their own bucket via your endpoint
- **Allow-list of approved AWS services** — restrict an Interface endpoint to specific API actions
- **Cross-account governance** — limit which accounts' resources a VPC can reach

#### S3 Has THREE Access Patterns Now

S3 is special — it's the only service with both endpoint types **plus** a third "direct via internet" option:

| Pattern | When |
| ------- | ---- |
| **Gateway Endpoint** | Default choice from VPC. Free. Works only from inside the VPC's route table |
| **Interface Endpoint (PrivateLink for S3)** | When you need access **from on-prem** (via DX/VPN), or **cross-region**, or applying Security Groups. Paid |
| **Direct via NAT + IGW** | Treating S3 as a public service. Standard internet egress costs apply. Almost never the right answer for VPC workloads |

The S3 Interface endpoint is newer (2021). Why it matters:
- **From on-prem:** an Interface endpoint's ENI has a private IP reachable over DX/VPN. The Gateway endpoint can't do this — its routing only works from inside the VPC
- **Security Groups on S3 traffic:** Interface endpoint = ENI = SG. Gateway endpoint has no SG, only endpoint policy
- **Cost:** Interface endpoint is paid; Gateway is free. Use Interface only when you need its specific capabilities

#### Multi-AZ Deployment for Interface Endpoints

Interface endpoints create one ENI per subnet you deploy them into. For HA:

```
VPC: eu-west-1
  ├── Private subnet in 1a → Interface endpoint ENI (10.0.1.50)
  ├── Private subnet in 1b → Interface endpoint ENI (10.0.2.50)
  └── Private subnet in 1c → Interface endpoint ENI (10.0.3.50)

Cost: 3 AZs × ~$0.01/hour × 730h = ~$22/month per endpoint
```

If you only deploy to one AZ and that AZ fails, the endpoint is unreachable for everyone — even instances in other AZs (their DNS resolves to the dead ENI). **Always deploy multi-AZ for production endpoints**, accepting the cost.

#### Endpoints from On-Prem (the DX / VPN gotcha)

A common multi-cloud / hybrid question:

| Endpoint type | Reachable from on-prem (via DX or VPN)? |
| ------------- | ---------------------------------------- |
| **Gateway endpoint** | ❌ **No** — Gateway endpoints work only via VPC route tables. On-prem traffic enters the VPC but can't use the Gateway endpoint route |
| **Interface endpoint** | ✅ **Yes** — the ENI has a private IP reachable over DX/VPN |

**Exam trigger:** *"On-prem needs to reach S3 privately via Direct Connect"* → **S3 Interface endpoint** (Gateway won't work from on-prem).

#### Cost Economics — When Endpoints Pay Off

The accounting question: when does an endpoint save money vs just using NAT?

```
NAT Gateway costs:
  $0.045/hour idle (per AZ) + $0.045/GB processed

Interface Endpoint costs:
  $0.01/hour (per AZ) + $0.01/GB processed

Gateway Endpoint costs:
  Free
```

**Break-even for a single Interface endpoint vs NAT:**
- Hourly: $0.01/hour < $0.045/hour → endpoint is cheaper at idle
- Per GB: $0.01/GB < $0.045/GB → endpoint is cheaper per byte

**But the gotcha:** you typically have **NAT anyway** for other internet egress. Adding an Interface endpoint *adds* hourly cost on top of NAT — only worth it if you process enough GB to offset.

**Rule of thumb:** Interface endpoint pays off vs NAT at roughly **20+ GB/month** of traffic to that specific service. Below that, NAT alone is cheaper. Above, endpoint wins (especially at scale).

**Gateway endpoints** (S3 / DynamoDB): always enable them. They're free, and any S3/DynamoDB traffic that would otherwise traverse NAT now bypasses it — pure savings.

#### Common Services and Which Endpoint They Use

| Service | Endpoint type |
| ------- | ------------- |
| **S3** | Gateway (default) or Interface (for on-prem / SG / cross-region) |
| **DynamoDB** | **Gateway only** — no Interface endpoint available |
| **KMS, Secrets Manager, SSM, Lambda, ECR, CloudWatch Logs, SQS, SNS, Kinesis, Step Functions** | Interface |
| **EC2 API, EBS API, Auto Scaling** | Interface |
| **Athena, Glue, EMR, Redshift, RDS API** | Interface |
| **API Gateway** (PrivateLink for execute-api) | Interface |
| **Bedrock, SageMaker, Comprehend** | Interface |
| **STS, IAM** | Interface (STS regional endpoints) |
| **Anything else with a public API** | Almost always Interface |

#### Common Anti-patterns and Gotchas

- *"Use Interface endpoint for S3 by default"* → wasteful unless you specifically need it; **Gateway endpoint is free**
- *"DynamoDB Interface endpoint"* → doesn't exist; **Gateway only**
- *"Single-AZ Interface endpoint in production"* → single point of failure; deploy across all AZs your workloads live in
- *"Endpoint policies are optional"* → for exfiltration-sensitive workloads, **always** scope endpoints to approved resources only
- *"Disable Private DNS"* → then your app code must use the verbose `vpce-xxx.s3.region.vpce.amazonaws.com` hostname instead of the standard one. Almost always leave Private DNS enabled
- *"Gateway endpoint reachable from on-prem"* → no; **Interface endpoint** is required for hybrid access
- *"Interface endpoint without Security Group"* → SG defaults to "allow all in the same SG" — usually you want to tighten this
- *"Endpoint replaces NAT Gateway for AWS services"* → partially. If your workload ONLY talks to AWS services + you have endpoints for all of them, you can remove NAT. Common in regulated environments

#### Expanded Exam Triggers

- *"S3 access from VPC, free, no internet"* → **Gateway endpoint**
- *"DynamoDB access from VPC, no internet"* → **Gateway endpoint** (only option for DynamoDB)
- *"KMS / Secrets Manager / SSM access from VPC privately"* → **Interface endpoint**
- *"S3 access from on-prem via Direct Connect privately"* → **S3 Interface endpoint** (Gateway won't work from on-prem)
- *"Restrict VPC endpoint to specific S3 buckets only"* → **Endpoint policy** with `Resource` restriction
- *"Apply security group to S3 traffic"* → **S3 Interface endpoint** (Gateway has no SG)
- *"Eliminate NAT Gateway costs for VPC workloads"* → **Gateway endpoints for S3/DynamoDB + Interface endpoints for all needed AWS services**
- *"App code expects public AWS hostname"* → **Enable Private DNS** on Interface endpoint
- *"Endpoint HA in production"* → **Deploy Interface endpoint ENIs in every AZ** the workload uses
- *"Why does my Lambda in VPC fail to call Secrets Manager?"* → no Interface endpoint + no NAT route (Lambda-in-VPC loses default internet)
- *"Prevent data exfiltration to attacker's S3 bucket"* → **Endpoint policy** scoping `Resource` to approved bucket ARNs
- *"Cross-region S3 access privately"* → **S3 Interface endpoint** (Gateway endpoint is region-local)

#### The Mental Model

> *VPC Endpoint = "VPC outbound to AWS APIs over the AWS backbone." It's a back door from your private network to AWS service control planes — never an inbound public-facing thing. Security groups on Interface endpoints control which VPC resources can use the endpoint, not anything external.*

**Constantly confused with:**

| Confused with | Actually is |
| ------------- | ----------- |
| ALB / API Gateway (public inbound to your app) | **VPC Endpoint is outbound from VPC to AWS APIs** |
| CloudFront / WAF (edge security for incoming users) | **VPC Endpoint is for the app itself talking to AWS** |
| PrivateLink endpoint service (you exposing your service to others) | **VPC Endpoint consumes someone's service (AWS's, in this case)** |

The 10-second recall: **"AWS-API access from inside the VPC, never customer-facing."**

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

#### Acceptance Workflow (the cross-account handshake)

Peering uses a request/accept model:

```
1. VPC A's owner: CreateVpcPeeringConnection (RequesterVpc=A, AccepterVpc=B)
       ↓
2. Connection enters `pending-acceptance` state
       ↓
3. VPC B's owner: AcceptVpcPeeringConnection
       ↓
4. State transitions to `active`
       ↓
5. NOW both sides update route tables to point the peer's CIDR at the connection
```

**Cross-account gotcha:** request expires after **7 days** if not accepted. *"Why isn't my cross-account peering working?"* — common answer: accepter never accepted.

**Cross-region cross-account** combines both: requester picks the accepter's region + account ID; accepter sees the request in their console / via the API in that region.

#### Routing — Both Directions Required

Peering creates the *capability* to route. **Both VPCs must update their route tables** for actual traffic flow. Single-side updates fix nothing.

```
VPC A (10.0.0.0/16) peered with VPC B (10.1.0.0/16) via pcx-abc123:

VPC A route table:                  VPC B route table:
  10.0.0.0/16 → local                 10.1.0.0/16 → local
  10.1.0.0/16 → pcx-abc123  ← add!    10.0.0.0/16 → pcx-abc123  ← add!
  0.0.0.0/0   → igw-xxx               0.0.0.0/0   → nat-yyy
```

If only VPC A has the peering route, A sends packets to B, but B's response goes to its default route (e.g. NAT or `local`) and never makes it back. Asymmetric routing kills the session.

#### Security Group References Across Peering

You **can** reference a Security Group ID in a peered VPC — but only for **intra-region peering**:

| | Intra-region peering | Cross-region peering |
| - | -------------------- | --------------------- |
| Reference peer's SG by ID (`sg-xxx`) | ✅ Yes | ❌ No — CIDR only |
| Reference peer's CIDR | ✅ Yes | ✅ Yes |

So `sg-app-tier` in VPC A can have an inbound rule allowing `sg-db-tier` from VPC B (if same region). Cross-region peering forces you back to IP-based rules.

#### DNS Resolution Across Peering

By default, instances in VPC A can't resolve VPC B's private DNS hostnames. Two flags control this — set on **each side**:

```
VPC A: enableDnsResolutionFromRemoteVpc = true (allows A to resolve B's hostnames)
VPC B: enableDnsResolutionFromRemoteVpc = true (allows B to resolve A's hostnames)
```

**Route 53 private hosted zones** don't auto-cross peering either. You must **explicitly associate** the private hosted zone with the peered VPC for it to resolve there.

**Exam trigger:** *"VPC A can reach VPC B by IP but DNS lookups fail"* → **DNS resolution across peering not enabled**, or **private hosted zone not associated with the peer**.

#### Edge-to-Edge Routing Limitation (the killer gotcha)

A peered VPC **cannot use** the other VPC's **IGW, NAT Gateway, VPN, or Direct Connect**. Peering only routes between the two VPCs — never beyond.

```
        Internet
            │
            ▼
   ┌────────────────────┐
   │ VPC B              │
   │   NAT Gateway      │
   │   IGW              │
   └────────┬───────────┘
            │ peering
            ▼
   ┌────────────────────┐
   │ VPC A (no NAT/IGW) │  ← Can A reach the internet via B's NAT?
   │                    │  ❌ NO. Edge-to-edge routing not allowed
   └────────────────────┘
```

You **cannot** use peering to create a "hub" VPC that handles internet egress for many spokes. That's exactly the problem **Transit Gateway** (with a centralised egress VPC) solves.

Other things you can't do across peering:
- Spoke VPC sends `0.0.0.0/0` traffic via hub VPC's IGW → blocked
- Spoke VPC uses hub VPC's NAT Gateway → blocked
- Spoke VPC reaches on-prem via hub VPC's VPN / Direct Connect → blocked
- Spoke VPC reaches a service exposed via PrivateLink in hub VPC → blocked (the endpoint ENI is reachable, but it's a VPC-private service)

The list of "can't cross peering" is essentially: **anything that exits the peered VPC to somewhere else**.

#### Cross-Region Peering Specifics

| Property | Detail |
| -------- | ------ |
| **Encryption** | Encrypted by default since 2018 — uses AES-256 over the AWS backbone |
| **MTU** | 1500 only — **no jumbo frames** (intra-region peering supports 9001) |
| **Data charges** | ~$0.02/GB each direction (cheaper than Transit Gateway cross-region for low volume) |
| **SG references** | ❌ Not supported — CIDR only |
| **Setup** | Same request/accept flow; requester specifies the accepter's region |

#### VPC Peering vs Transit Gateway vs PrivateLink — when to use which

| Need | Choose | Why |
| ---- | ------ | --- |
| **2–3 VPCs, all-to-all connectivity** | **VPC Peering** | Cheaper; no TGW attachment fees; direct routing |
| **Many VPCs (5+) needing transitive connectivity** | **Transit Gateway** | Peering N² problem becomes painful past a handful |
| **Cross-region with just 2 VPCs** | **VPC Peering** (cross-region) | TGW cross-region peering adds ~$0.05/hour per attachment + data charges |
| **Spoke VPCs need hub VPC's NAT / VPN / Direct Connect** | **Transit Gateway** | Peering's edge-to-edge limitation blocks this |
| **Expose a single service to many consumers, possibly with overlapping CIDRs** | **PrivateLink** | Peering needs non-overlapping CIDRs; PrivateLink doesn't care |
| **Cross-account, single service exposure** | **PrivateLink** | Don't expose the whole VPC; expose only the NLB-fronted service |
| **Many accounts share one team's VPC** | **VPC Sharing via RAM** | Participants deploy directly into shared subnets — no peering at all |

#### Updated exam triggers

- *"Connect 2 VPCs, simplest pattern"* → **VPC Peering**
- *"Cross-account peering not working after creation"* → **Accepter hasn't accepted** the request (expires after 7 days)
- *"DNS resolution failing across peering"* → **enable `enableDnsResolutionFromRemoteVpc`** on both sides, **associate private hosted zone** with peer VPC
- *"Can a peered VPC use the other VPC's NAT Gateway?"* → **No** — edge-to-edge routing not supported. Use **Transit Gateway** with centralised egress
- *"Can a peered VPC reach on-prem via the other VPC's Direct Connect?"* → **No** — same limitation
- *"Cross-region peering — is it encrypted?"* → **Yes**, by default since 2018
- *"Reference peer's SG by ID"* → **Intra-region peering only**; cross-region forces CIDR
- *"Why is traffic not flowing despite active peering?"* → **Route tables not updated** on both sides
- *"3 VPCs need full connectivity"* → **3 peering connections** (A↔B, B↔C, A↔C) or **TGW**
- *"30 VPCs need full connectivity"* → **Transit Gateway** (don't do 435 peerings)

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

#### Transit Gateway Deeper Bits

**Attachment types** — what you can plug into a TGW:

| Attachment | What it connects |
| ---------- | ---------------- |
| **VPC** | A VPC in the same region |
| **VPN** | Site-to-Site VPN tunnel |
| **Direct Connect Gateway** | Direct Connect physical connection (multi-region) |
| **Transit Gateway Peering** | Another TGW (same or cross-region) |
| **Connect** | SD-WAN / third-party appliance integration (GRE + BGP) |

**TGW route tables** — each TGW has multiple route tables, and each attachment is associated with one. This lets you create **segmented network topologies**:

```
Default TGW route table → all spokes route to each other
                  ↓ OR ↓
Segmented setup:
  - "Prod" route table: only prod VPCs route to each other + shared services
  - "Dev" route table: only dev VPCs route to each other + shared services
  - "Shared services" route table: visible to everyone

Result: full isolation between Prod and Dev without separate TGWs.
```

This is how large orgs implement **network segmentation** for compliance (PCI workloads in one segment, dev in another, both able to reach shared services like DNS / monitoring).

**TGW sharing via RAM** — A central networking account owns the TGW; other accounts attach their VPCs to it via **AWS Resource Access Manager**. Standard multi-account hub-and-spoke pattern.

**TGW Network Manager** — Visualises your TGW topology across regions on a global map. Useful for hybrid network operations + troubleshooting.

**Inter-region TGW peering** — Connect TGWs in different regions; traffic stays on the AWS backbone. The standard "global private network" pattern uses one TGW per region, peered together.

#### Appliance Mode — the "sticky sessions for firewall fleets" feature

Without this, centralised stateful inspection (Network Firewall, Palo Alto, Check Point, Fortinet, Snort, etc. running behind a TGW) silently breaks for half of all flows. It's an opt-in setting on a TGW attachment and the exam loves it.

**The bouncer analogy:** Imagine a club with bouncers at multiple doors. You enter through Door A and bouncer A checks your ID and **remembers you**. If you try to leave through Door C, bouncer C has no memory of you arriving — they don't know if you should be there. **Appliance Mode = "always exit through the same door you entered."**

**The AWS version:** A stateful firewall is a bouncer with a memory. It builds a **connection table** on the outbound SYN ("alice → api.example.com:443 allowed") and uses that to recognise the SYN-ACK reply. If the reply hits a *different* firewall instance, that firewall has no record of the connection, looks at it as an unsolicited inbound packet, and **drops it**.

**Default TGW behaviour (without Appliance Mode):**

```
Outbound  (alice → api.example.com):
   Spoke VPC A ──→ TGW ──→ Inspection VPC, AZ-a, firewall #1
                                              ↑
                                              creates state for the flow

Inbound reply (api.example.com → alice):
   Spoke VPC A ←── TGW ←── Inspection VPC, AZ-b, firewall #2
                                              ↑
                                              has NO state for this flow
                                              → drops the packet
                                              → alice's connection times out
```

TGW load-balances across AZs by default. The forward and reverse paths can land on different appliances. Stateless appliances don't care; stateful ones break.

**With Appliance Mode enabled on the inspection VPC attachment:**

```
Spoke VPC A ──→ TGW(AZ-a) ──→ firewall #1 (state created)
Spoke VPC A ←── TGW(AZ-a) ←── firewall #1 (same instance recognises the flow)

Same TGW endpoint = same firewall = stateful inspection works.
```

**Why it's opt-in, not always-on:** stateless appliances (pure routers, simple L4 forwarders) don't need flow affinity, and forcing it would unnecessarily constrain TGW's load-balancing. So Appliance Mode is **per-attachment** — turn it on for the inspection VPC attachment, leave it off everywhere else.

**Adjacent analogies that may also click:**

| Analogy | What it captures |
| ------- | ---------------- |
| **Sticky sessions on a load balancer** | User stuck to same backend server because session data lives there. Same principle for firewall connection tables |
| **Same operator on a phone call** | The operator listening to both halves knows the context. Switching mid-call to a different operator means the new one has no idea what was said earlier |
| **Customs at one airport vs two** | If you went through customs to enter, your declaration is at that office. Leaving through a different customs office that didn't see you arrive → they flag you |

**Mental model:** *Appliance Mode = "sticky sessions for stateful firewall fleets behind Transit Gateway." Turn it on whenever you have stateful inspection appliances (Network Firewall, Palo Alto, Check Point, Fortinet, Snort/Suricata) running behind a TGW in a centralised inspection VPC. Leave it off for everything else.*

**Exam triggers:**
- *"Segment prod and dev networks in a hub-and-spoke topology"* → **TGW with multiple route tables**
- *"Share a TGW across 50 accounts"* → **TGW + AWS RAM**
- *"Connect TGWs in different regions"* → **TGW peering attachments**
- *"Integrate SD-WAN appliances with TGW"* → **TGW Connect attachment** (GRE + BGP)
- *"Visualise multi-region TGW topology"* → **TGW Network Manager**
- *"Centralised firewall fleet behind TGW silently dropping return traffic"* → **enable Appliance Mode** on the inspection VPC's TGW attachment
- *"Why do my stateful firewall sessions break intermittently when load-balanced across AZs?"* → **Appliance Mode** keeps both directions on the same TGW endpoint
- *"Asymmetric routing through inspection VPC"* → **Appliance Mode** is the fix

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

### DNS in a VPC

DNS is one of the most under-explained parts of AWS networking — but it's tested heavily in hybrid scenarios. Two layers to understand:

#### Amazon-provided DNS (the always-on default)

Every VPC has an Amazon-provided DNS resolver at **`VPC CIDR + 2`** (e.g. for `10.0.0.0/16`, the resolver lives at `10.0.0.2`). It handles:

- **Public DNS** — any internet domain (`amazon.com`, `github.com`)
- **VPC-internal DNS** — EC2 instance hostnames (`ip-10-0-1-23.eu-west-1.compute.internal`)
- **AWS service endpoints** — `s3.amazonaws.com`, etc.

It's enabled by the VPC attributes `enableDnsSupport` (provides the resolver) and `enableDnsHostnames` (instances get DNS names).

#### Private Hosted Zones (Route 53)

A Route 53 hosted zone that resolves **only inside specified VPCs**. Used for internal service discovery without exposing names publicly.

```
Private hosted zone: corp.internal
  api.corp.internal     → 10.0.1.50
  db.corp.internal      → 10.0.2.30
  
Resolves only from VPCs explicitly associated with this zone.
External resolvers (8.8.8.8, etc.) return NXDOMAIN.
```

#### Route 53 Resolver Endpoints — Hybrid DNS

This is where exam questions live. When you connect on-prem to AWS, **DNS doesn't automatically work both ways** — Amazon's resolver isn't reachable from on-prem, and your on-prem DNS isn't reachable from VPCs. Route 53 Resolver bridges this:

| Endpoint type | Direction | Use case |
| ------------- | --------- | -------- |
| **Inbound resolver endpoint** | **On-prem → AWS** | On-prem servers can resolve AWS private hosted zones (e.g. `api.corp.internal`). ENIs in the VPC get IPs that on-prem points DNS at |
| **Outbound resolver endpoint** | **AWS → on-prem** | EC2 instances can resolve on-prem-only names (e.g. `legacy-app.internal.corp.com`). Uses **forwarding rules** to send specific domains to on-prem DNS |

```
Hybrid DNS architecture:

  On-prem corporate DNS                  AWS VPC
  ─────────────────────                  ───────────────
                                         
  Resolves *.corp.com           ┌─→ Inbound Resolver Endpoint
                                │   (ENIs in VPC; on-prem DNS forwards
  ─── 8.8.8.8 for public ───────┤    *.aws.corp.com queries here)
                                │
                                │
   Outbound Resolver Endpoint ──┤
   (forwarding rules:           │
    *.internal.corp.com   ──────┴─→ corporate DNS over VPN/DX
    routes to on-prem DNS)
```

**Exam triggers:**
- *"On-prem servers need to resolve AWS private hosted zone names"* → **Inbound Resolver Endpoint**
- *"EC2 instances need to resolve on-prem internal domains"* → **Outbound Resolver Endpoint + forwarding rules**
- *"Bidirectional DNS between AWS and on-prem"* → **Inbound + Outbound + Forwarding Rules**
- *"Block resolution of malicious domains from a VPC"* → **Route 53 Resolver DNS Firewall**

#### DHCP Option Sets

You can override what DNS / NTP servers a VPC's instances get via **DHCP option sets**. Common use: point instances at custom DNS (on-prem corporate DNS) instead of the Amazon-provided resolver.

| Setting | Use |
| ------- | --- |
| `domain-name-servers` | List of DNS server IPs (e.g. `10.1.1.10, 10.1.1.11` for on-prem DNS) |
| `domain-name` | Default search domain (`corp.example.com`) |
| `ntp-servers` | NTP server IPs |
| `netbios-name-servers` | Legacy Windows naming |

Exam trigger: *"All EC2 instances in our VPC must use our on-prem DNS servers"* → **custom DHCP option set with `domain-name-servers` set to on-prem IPs**.

### VPC Sharing via AWS RAM

A pattern for multi-account networks: **one account owns the VPC; other accounts deploy resources into shared subnets**.

```
Network account (owner)
  └── VPC: 10.0.0.0/16
        ├── Subnet A (shared with App Team 1's account)
        ├── Subnet B (shared with App Team 2's account)
        └── Subnet C (shared with Data Team's account)
              ↓
        Each participant account deploys EC2 / RDS / ALB into its
        designated subnets — without owning the VPC itself
```

#### Why use VPC Sharing?

- **Centralised network governance** — one team owns CIDRs, route tables, peering, IGW/NAT, security baselines
- **No duplicate NAT Gateways** — participants share the owner's NAT, saving $$
- **Simpler hybrid connectivity** — DX / VPN attaches once to the owner's VPC, all participants benefit
- **Cleaner security** — Security Groups in participant accounts can reference each other across the shared VPC

#### What participants CAN and CANNOT do

| Action | Owner | Participant |
| ------ | ----- | ----------- |
| Create / delete the VPC | ✅ | ❌ |
| Manage CIDRs, route tables, IGW, NAT | ✅ | ❌ |
| Manage VPN, peering, Transit Gateway attachments | ✅ | ❌ |
| Create subnets | ✅ | ❌ |
| Deploy EC2 / RDS / ALB into shared subnets | ✅ | ✅ |
| Create Security Groups + reference them across accounts | ✅ | ✅ |

#### VPC Sharing vs VPC Peering vs Transit Gateway

| Pattern | When |
| ------- | ---- |
| **VPC Sharing (RAM)** | Many teams / accounts that should appear to share one network. **Owner pays NAT/data** |
| **VPC Peering** | A few VPCs (typically own by separate teams) that need to talk to each other. **Each VPC pays its own NAT/etc.** |
| **Transit Gateway** | Many VPCs that need transitive connectivity + hybrid; each VPC is independent |

**Exam triggers:**
- *"Centralised networking team manages one VPC; app teams deploy into shared subnets"* → **VPC Sharing via RAM**
- *"Avoid paying for NAT Gateway in every account"* → **VPC Sharing** (one NAT, all participants use it)
- *"Multi-account architecture with shared DX / VPN"* → **VPC Sharing** (or TGW with shared attachments)

### Amazon VPC Lattice

**Anchored as a managed service mesh for AWS.** A newer (2023) **application-layer connectivity layer** for service-to-service communication — across VPCs, accounts, and on-prem. Handles auth, routing, observability, traffic management for HTTP/HTTPS calls *without* peering or PrivateLink complexity.

#### Core concepts

| Concept | What it is |
| ------- | ---------- |
| **Service network** | Logical grouping that contains services and clients. The "fabric" |
| **Service** | A discoverable endpoint (Lambda, ECS service, ALB target, K8s pod, IP target) |
| **Listener** | The protocol (HTTP / HTTPS) + port + routing rules |
| **Target group** | Where requests land (similar to ELB target groups) |
| **Authentication** | None / IAM auth (uses SigV4 — like the AWS API) |

#### Why VPC Lattice exists

Without Lattice, service-to-service across VPCs / accounts means **PrivateLink, peering, or TGW** — each with its own setup overhead. Lattice replaces that with:

- **No peering, no NAT** — services discoverable by friendly DNS names regardless of underlying VPC
- **IAM-native auth** — caller's IAM identity authorises the call (no API keys to manage)
- **Built-in observability** — CloudWatch metrics, access logs out of the box
- **Multi-target-type** — same listener can route to ALB, NLB, Lambda, ECS, K8s, IP, by weight or path

#### When VPC Lattice vs Other Patterns

| Question | Use |
| -------- | --- |
| *"East-west service-to-service across VPCs / accounts, HTTP-based"* | **VPC Lattice** |
| *"Expose a SaaS to many customer VPCs"* | **PrivateLink** (Lattice is for *internal* connectivity) |
| *"Cross-VPC routing for arbitrary protocols (not just HTTP)"* | **Transit Gateway** |
| *"Public internet-facing app"* | **CloudFront + ALB / API Gateway** |

**Exam triggers:**
- *"Connect microservices across multiple VPCs without managing peering"* → **VPC Lattice**
- *"IAM-based service-to-service auth across accounts"* → **VPC Lattice with SigV4 auth**
- *"Friendly DNS for cross-VPC service calls"* → **VPC Lattice**

### AWS Cloud WAN

**Anchored as Transit Gateway's bigger sibling for multi-region networks.** Cloud WAN gives you a **global network policy in JSON**; AWS provisions the underlying TGWs, peerings, and attachments to match. Think of it as Terraform-for-network-architecture.

#### Core concepts

| Concept | What it is |
| ------- | ---------- |
| **Global network** | The top-level Cloud WAN resource — one per organisation |
| **Core network policy** | JSON document declaring your desired network topology (segments, regions, routing) |
| **Core Network Edges** (CNEs) | AWS-provisioned regional networking nodes (effectively TGWs under the hood) |
| **Segments** | Network-level isolation (like TGW route tables, but declarative) |
| **Attachments** | VPCs, VPNs, Direct Connect, TGWs all attach to CNEs |

#### Cloud WAN vs Transit Gateway

| | **Transit Gateway** | **AWS Cloud WAN** |
| - | ------------------- | ----------------- |
| Setup | Manual: create TGW per region + peerings + route tables | **Declarative policy in JSON** — AWS builds it |
| Multi-region | Manual TGW peering | **Native multi-region** |
| Segmentation | TGW route tables | **First-class segments** |
| Visibility | TGW Network Manager (optional add-on) | **Built-in global dashboard** |
| Maturity | Mature, widely used | Newer (2022+); enterprise pattern |
| Cost | Per-attachment + data | Higher overhead — only worth it at multi-region scale |

**Decision:** small / single-region → **TGW**. 5+ regions, declarative IaC for network → **Cloud WAN**.

**Exam triggers:**
- *"Declarative multi-region network policy"* → **AWS Cloud WAN**
- *"Manage a global network of 8+ regions as code"* → **AWS Cloud WAN**
- *"Single-region or two-region setup"* → **Transit Gateway** is sufficient

### AWS VPC IP Address Manager (IPAM)

**Anchored as IP-CIDR-planning-as-code.** IPAM is AWS's tool for **centrally planning, tracking, and auto-allocating IP CIDRs** across your org's VPCs. Useful once you outgrow "we'll assign CIDRs by hand in a spreadsheet."

#### Core concepts

| Concept | What it is |
| ------- | ---------- |
| **IPAM pool** | A hierarchical CIDR space you've reserved (e.g. `10.0.0.0/8` at the top) |
| **Sub-pools** | Carve top pool into regional / per-account / per-environment sub-pools |
| **Auto-allocation** | New VPCs get CIDRs auto-assigned from the appropriate pool — no conflicts, no overlaps |
| **Public IPAM** | Manage BYOIP (Bring-Your-Own-IP) address space too |
| **Monitoring** | Track utilisation; alert when a pool nears exhaustion |

#### When IPAM is worth it

- 50+ VPCs across many accounts
- Risk of accidentally allocating overlapping CIDRs (which would break peering / TGW)
- Compliance — need an audit trail of who got which CIDR when
- BYOIP address space management

For small orgs, IPAM is overkill — just track CIDRs in a spreadsheet or Terraform variables.

**Exam triggers:**
- *"Centrally plan and prevent overlapping CIDRs across many accounts"* → **AWS IPAM**
- *"Auto-allocate CIDRs to new VPCs from a reserved pool"* → **IPAM with auto-allocation**
- *"Manage BYOIP across the org"* → **IPAM public pool**

### IPv6 in a VPC

For most workloads IPv6 is overkill. There's **one big reason** orgs adopt it inside a VPC and a few smaller ones — knowing which scenarios trigger an IPv6 answer is what the exam tests.

#### The headline reason — RFC 1918 exhaustion at scale

People assume the private IPv4 space (`10.0.0.0/8` = ~16.7M addresses, plus `172.16/12` and `192.168/16`) is infinite. **It isn't, at enterprise scale.** Three pressures eat it:

| Pressure | What chews through IP space |
| -------- | --------------------------- |
| **EKS / Kubernetes** | AWS VPC CNI gives **every pod a real VPC IP**. 1,000 nodes × 50 pods/node = **50,000 IPs in one cluster**. A `/16` (65k IPs) exhausted by a single cluster. **This is the #1 reason** orgs flip EKS to IPv6 mode |
| **`awsvpc` mode for ECS / Fargate** | Each task = ENI = VPC IP. Less severe than EKS (1 IP per task vs many pods per node) but the same shape of problem at scale. Bridge mode on ECS-on-EC2 sidesteps it |
| **Non-overlapping CIDR requirement** | VPC Peering / TGW / DX require non-overlapping CIDRs. Hundreds of VPCs + M&A = perpetual IP planning headaches |

IPv6 has **3.4 × 10³⁸ addresses**. AWS gives every VPC a `/56` IPv6 CIDR automatically (~4.7 × 10²² per VPC). You **cannot run out**.

#### The "no NAT Gateway needed" angle

IPv6 is globally routable — **no NAT in IPv6**. With an **Egress-Only Internet Gateway** (the IPv6 equivalent of NAT), IPv6 instances get outbound internet access without NAT translation:

| | IPv4 outbound | IPv6 outbound |
| - | ------------- | ------------- |
| Inbound-blocking outbound gateway | **NAT Gateway** (~$33/month per AZ + $0.045/GB) | **Egress-Only IGW** (free, no per-GB charge) |
| 55k connection limit per destination | Yes (the NAT Gateway gotcha) | **No** — IPv6 sidesteps it |
| Source IP rewriting | Yes (NAT translation) | **No** — original IP preserved |
| Cost at scale | Significant | Negligible |

The cost angle alone justifies IPv6 dual-stack for high-traffic workloads. Plus the **55k connection limit gotcha** that bites large NAT-fronted fleets is just **not a problem** for IPv6 traffic.

#### Other reasons people use IPv6 internally

| Reason | Why |
| ------ | --- |
| **M&A / VPC merging** | Acquiring a company with overlapping `10.x` CIDRs → IPv6 gives clean parallel address space without renumbering |
| **Compliance mandates** | US Federal IPv6 mandate, India, EU pushes. Government-facing workloads increasingly require IPv6 readiness |
| **Reach IPv6-only public services** | Growing number of public services + mobile carriers prefer IPv6 |
| **Flow Log simplicity** | No NAT means no `pkt-srcaddr` vs `srcaddr` confusion |
| **Future-proofing** | Like SSL was "optional" in 2010, expected by 2020 |

#### When IPv6 is genuinely **not** worth it

| Case | Stay with IPv4 |
| ---- | -------------- |
| **Small / medium VPC** (< few thousand resources) | IPv4 plenty; IPv6 adds operational complexity for no gain |
| **Traditional 3-tier app on EC2 + RDS** | Will never exhaust IPs |
| **No EKS / no extreme scale** | The biggest reason doesn't apply |
| **Workloads talking to on-prem IPv4 systems** | Adds dual-stack translation complexity |
| **Most enterprises starting fresh** | IPv4 + good IPAM hygiene handles you for years |

For a "normal" VPC with EC2 + ALB + RDS + S3 endpoints — IPv6 is solving a problem you don't have.

#### Exam framing

If a question mentions any of these → IPv6 might be the answer:

| Trigger | Answer |
| ------- | ------ |
| *"Pod / container exhaustion of IP addresses in EKS"* | **EKS with IPv6 mode** |
| *"Run a Kubernetes cluster with 50,000+ pods"* | **IPv6 mode** |
| *"Merge two companies' VPCs with overlapping CIDRs without renumbering"* | Consider **IPv6** |
| *"Federal compliance requires IPv6 readiness"* | **IPv6 dual-stack** |
| *"Outbound from IPv6 instances without exposing inbound"* | **Egress-Only Internet Gateway** |
| *"NAT Gateway connection-limit exhaustion at scale (55k per destination)"* | Move to **IPv6** sidesteps it entirely |
| *"Avoid NAT Gateway cost for high-volume outbound traffic"* | **IPv6 + Egress-Only IGW** is free vs NAT Gateway's per-GB charge |
| *"ECS / Fargate hitting subnet IP exhaustion"* | **`awsvpc` + dual-stack subnet + IPv6**, or secondary CIDRs |

If a question is just *"my app needs to talk to the internet"* with no scale or compliance trigger → it's **NOT** an IPv6 question. Stay IPv4.

#### Mental model

> *IPv6 in a VPC is mostly about **dodging the RFC 1918 exhaustion problem** at extreme scale — and the place it shows up is almost always **EKS pod IPs**. The secondary win is **no NAT Gateway** (use Egress-Only IGW instead) — cheaper, no 55k connection limit. For traditional workloads on a normal-sized VPC, IPv6 is solving a problem you don't have. The exam tests it because EKS at scale + the cost angle have made it real for a slice of customers, not because every VPC needs it.*

### VPC Flow Logs

Capture metadata about IP traffic in your VPC. Used for security forensics, connectivity troubleshooting, traffic analysis, compliance, and feeding SIEMs.

#### Core properties

- **Granularity:** VPC, subnet, or ENI (finest)
- **Captures:** source/dest IP+port, protocol, bytes, packets, ACCEPT/REJECT, plus optional newer fields
- **Does NOT capture:** packet contents (use **VPC Traffic Mirroring** for that)
- **Destinations:** CloudWatch Logs, S3, **Kinesis Data Firehose**, **Amazon Data Firehose to OpenSearch**
- **Aggregation interval:** **1-minute (default)** or **10-minute** (cheaper, ~10× less log volume, but laggier — useful when you don't need fine-grained timing)

#### Three Granularity Levels — Pick Carefully

| Level | Captures | Use |
| ----- | -------- | --- |
| **VPC** | Every ENI in the VPC | Broad audit, compliance, centralised security analytics |
| **Subnet** | Every ENI in that subnet | Subnet-level forensics — e.g. "what hit my DB subnet?" |
| **ENI** | Just that one network interface | **Finest granularity** — single instance / endpoint forensics |

A single ENI can have multiple Flow Logs (one per granularity level) — they all log the same traffic independently. **Cost stacks** if you enable multiple levels for the same traffic.

#### What's NOT Captured (the classic trap question)

Flow Logs **silently skip** several traffic categories. Memorise these — they're popular exam wrong-answer traps:

- **Instance metadata service** — `169.254.169.254` (IMDS)
- **Amazon-provided DNS** — VPC CIDR + 2 (e.g. `10.0.0.2`)
- **Amazon Time Sync** — `169.254.169.123` (NTP)
- **Windows license activation** — traffic to Microsoft KMS servers
- **VPC router IP** — `.1` of the subnet
- **DHCP traffic**
- **Traffic to/from a load balancer's link-local addresses**
- **Mirrored traffic**

**Exam trap:** *"Why don't I see IMDS calls in Flow Logs?"* → because IMDS isn't logged. Use **CloudTrail** + **Instance Metadata Service v2** session tokens for IMDS audit.

#### ACCEPT vs REJECT — The Subtlety

Common misreading: "ACCEPT = the connection worked." **Not necessarily.**

| Status | Means | Doesn't mean |
| ------ | ----- | ------------ |
| **ACCEPT** | Security Group + NACL both **allowed** the packet | The destination app actually received / responded |
| **REJECT** | **NACL denied** the packet (NACLs are stateless so they generate REJECT entries). Security Group denies show up too in some cases | The connection failed (might have been intentional!) |

**Why this matters:**
- A packet can be ACCEPTed but still fail downstream (app crashed, port not listening, application-layer reject)
- REJECT specifically tells you a network-layer firewall blocked it
- For app-layer failures, Flow Logs are *useless* — you need application logs / X-Ray traces

#### NODATA and SKIPDATA Log Statuses

Sometimes a flow log record's `log-status` field isn't `OK`:

| log-status | Meaning |
| ---------- | ------- |
| **OK** | Normal record with traffic data |
| **NODATA** | The ENI had no traffic during the aggregation interval |
| **SKIPDATA** | Records were dropped during the interval (throttling, internal capacity) — **data was lost** |

**Exam trap:** *"Some traffic isn't showing up in Flow Logs"* — could be:
- The traffic is on the excluded list above
- A SKIPDATA event dropped records
- The aggregation interval hasn't elapsed yet
- Wrong destination / filter

#### Custom Log Formats (cost saver)

Default Flow Log format = ~14 fields per record. You can define **custom formats** with only the fields you actually need — reduces log volume and storage cost.

Newer fields worth knowing (not in default):
- `vpc-id`, `subnet-id`, `instance-id` — useful for centralised querying without joins
- `tcp-flags` — SYN, ACK, FIN etc. for connection analysis
- `pkt-srcaddr`, `pkt-dstaddr` — the **original** addresses before NAT translation (vs `srcaddr`/`dstaddr` after NAT). Critical for understanding NAT Gateway behaviour
- `traffic-path` — which AWS network component the traffic took (IGW / NAT / TGW / VPC peering / Gateway Load Balancer / etc.)
- `flow-direction` — `ingress` / `egress`

**`pkt-srcaddr` vs `srcaddr` gotcha:** when traffic goes through NAT Gateway, the original source IP gets rewritten. Default Flow Log shows the NAT'd IP. To see the **original instance's IP** behind a NAT, you need `pkt-srcaddr` in a custom format. Useful for *"which instance actually made this call?"* through a centralised NAT.

#### Flow Logs Are NOT Real-Time

Don't build alerting that assumes immediate Flow Log visibility:

| Destination | Typical delivery delay |
| ----------- | ---------------------- |
| **CloudWatch Logs** | ~5 minutes |
| **S3** | ~10 minutes |
| **Kinesis Data Firehose** | Near real-time (seconds, depending on Firehose buffer config) |

For real-time, ship to Firehose → OpenSearch / Splunk.

#### GuardDuty Doesn't Need You to Enable Flow Logs

A widespread misconception: *"to use GuardDuty I need to turn on VPC Flow Logs first."* **Wrong.** GuardDuty has its own internal stream that consumes Flow Log data directly from AWS infrastructure — independent of whether you've enabled VPC Flow Logs for your own logging.

You can disable VPC Flow Logs entirely and GuardDuty still works.

**Why this matters:** an exam question about "GuardDuty prerequisites" should not include "enable Flow Logs." If an answer says that, it's wrong.

#### Transit Gateway Flow Logs (separate from VPC Flow Logs)

A completely separate Flow Log type for **Transit Gateway attachments** — captures traffic flowing between VPCs / VPN / DX through a TGW. Same destinations (S3 / CloudWatch / Firehose), similar fields, but a different resource type.

**Exam trigger:** *"Audit traffic flowing through our Transit Gateway"* → **Transit Gateway Flow Logs**, not VPC Flow Logs.

#### The Standard Multi-Account Architecture

Every regulated org uses some version of this:

```
VPC in Account A ─┐
VPC in Account B ─┼─→ Flow Logs (per-VPC) → S3 bucket in central
VPC in Account C ─┘                          security/audit account
                                              ↓ Parquet format, partitioned by
                                                date / account / region
                                              ↓
                                      Athena queries
                                              ↓
                                      QuickSight dashboards / GuardDuty
                                      / Security Hub / SIEM
```

**Why this pattern:**
- Single audit-trail location across the org
- S3 + Parquet + Athena is **orders of magnitude cheaper** than CloudWatch Logs at scale
- Cross-account delivery uses S3 bucket policy granting log delivery from source accounts
- Lake Formation can govern access to the centralised logs

#### Cost Reality

Flow Logs aren't free — they bill on **delivery + storage**:

- **CloudWatch Logs**: ~$0.50/GB ingested + retention
- **S3**: standard storage + per-GB Athena query costs
- **Firehose**: per-GB ingested + downstream destination

**Rule of thumb at scale:** S3 + Parquet wins by ~10× vs CloudWatch Logs. The cost-conscious default is *"ship to S3, query with Athena, ship critical events to CloudWatch Logs subscription filters or Firehose."*

#### Expanded Exam Triggers

- *"Why is traffic blocked between two instances?"* → enable Flow Logs, look for **REJECT**
- *"Audit which IPs accessed our database"* → Flow Logs on the **RDS ENI**
- *"Cheap long-term Flow Log storage with ad-hoc querying"* → **S3 + Parquet + Athena**
- *"Real-time security analytics on Flow Logs"* → **Firehose → OpenSearch / Splunk**
- *"Why don't I see calls to the metadata service in Flow Logs?"* → **IMDS isn't captured** (also DNS, NTP, Windows activation, VPC router)
- *"ACCEPT in Flow Logs means the connection succeeded"* → **No** — means firewall allowed; app-layer success requires app logs
- *"Some Flow Log records have no data"* → **NODATA** (no traffic) or **SKIPDATA** (records dropped during interval)
- *"See original source IP before NAT rewrote it"* → **Custom format with `pkt-srcaddr`**
- *"Which network path did this traffic take (IGW / NAT / TGW)?"* → **Custom format with `traffic-path`**
- *"Do I need to enable Flow Logs for GuardDuty to work?"* → **No** — GuardDuty has its own internal Flow Logs stream
- *"Audit traffic through our Transit Gateway"* → **Transit Gateway Flow Logs** (separate feature)
- *"Reduce Flow Logs cost in a busy account"* → **10-minute aggregation + custom format + S3 + Parquet**
- *"Centralise Flow Logs across 50 accounts"* → **Each VPC ships to S3 in security account** via cross-account bucket policy

#### The Mental Model

> *VPC Flow Logs = "after-the-fact metadata about every IP packet that the network layer saw." It's a **logbook**, not a wire tap (no payload) and not a real-time alarm (5-10 min lag for S3/CW). ACCEPT means firewall allowed, **not** that the app succeeded. Several traffic categories are silently excluded (IMDS, DNS, NTP, etc.). For payload analysis use **Traffic Mirroring**; for real-time use **Firehose**; for AWS-API audit use **CloudTrail**.*

### Reachability Analyzer and Network Access Analyzer

Two complementary troubleshooting / governance tools for VPC connectivity. Often confused — they answer different questions.

| | **Reachability Analyzer** | **Network Access Analyzer** |
| - | ------------------------- | ---------------------------- |
| Answers | *"Can host A reach host B right now?"* (point-to-point test) | *"What network access exists across the org?"* (continuous posture analysis) |
| Scope | One source + one destination | Whole VPC / org |
| Output | Detailed path showing every hop, every SG/NACL/route/IGW rule it passes through (or where it fails) | List of resources that match a "Network Access Scope" you define |
| Use case | *"Why can't my Lambda reach RDS?"* — gives you the exact rule blocking | *"Find every VPC with an internet path to RDS"* — catches misconfigurations org-wide |
| Pricing | $0.10 per analysis | Per Network Access Scope analysed |

#### Reachability Analyzer — the path debugger

```
Source: EC2 instance i-aaa  (10.0.1.10, eu-west-1a)
Destination: RDS instance db-xxx  (10.0.10.20, eu-west-1a)

Result: NOT REACHABLE

Path:
  1. ENI eni-source              → ✓ allowed
  2. Subnet route table          → ✓ local route to 10.0.0.0/16
  3. Security Group (source)     → ✓ outbound allows 0.0.0.0/0:3306
  4. NACL (source subnet)        → ✓ allows outbound
  5. Subnet route table (dest)   → ✓ local route
  6. NACL (dest subnet)          → ✓ allows inbound
  7. Security Group (dest)       → ❌ DENIED — no inbound rule for 10.0.1.10:3306
                                    (RDS SG only allows from sg-app, not direct CIDRs)

→ Fix: either add the source CIDR to the RDS SG, or attach sg-app to the source EC2
```

This is the level of detail it gives you — every layer of the AWS networking stack inspected, with the exact rule that blocks (or allows) clearly identified.

#### Network Access Analyzer — the posture analyser

You define a **Network Access Scope** (e.g. *"any internet-facing resource that can reach a database subnet"*), and the analyser finds every match across your VPCs and accounts.

Built-in scopes include:
- *Resources with direct internet connectivity*
- *Internet-facing resources reaching sensitive subnets*
- *Cross-VPC connectivity through peering*

**Exam triggers:**
- *"Why can't host A reach host B?"* → **Reachability Analyzer**
- *"Find every VPC with internet-reachable databases"* → **Network Access Analyzer**
- *"Show the exact rule blocking traffic"* → **Reachability Analyzer**
- *"Audit network exposure across the org"* → **Network Access Analyzer**

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

#### Why Use Direct Connect (and Who Does)

The exam treats DX as "private dedicated line — expensive but fast." The real-world drivers are more specific. Useful context for understanding which scenarios the exam *expects* DX as the right answer.

**The drivers:**

| Driver | Why it justifies the cost + setup time |
| ------ | -------------------------------------- |
| **Compliance — traffic must never traverse public internet** | Banks, healthcare, government. Auditors want documented proof PHI / PCI data flows over a private circuit |
| **Predictable performance** (low jitter, consistent latency) | Real-time trading (latency arbitrage), telephony, VoIP, financial market data, video production |
| **Cost at terabyte / petabyte scale** | Internet egress ≈ **$0.09/GB**. DX egress ≈ **$0.02/GB**. At 100 TB/month outbound: internet = $9k, DX = $2k — port pays for itself in months |
| **Reduce internet circuit dependency** | If your office ISP dies, AWS-hosted apps stay reachable. Separating "internet" from "AWS connectivity" is operationally valuable |
| **Large recurring data flows** | Daily multi-TB DB backups to S3, cross-DC replication, video archival, scientific data pipelines |
| **Hybrid app latency** | App tier in AWS, database tier on-prem (or vice versa). Internet jitter ruins user experience when every request crosses the boundary |
| **Real-time control systems** | Industrial / SCADA workloads where milliseconds matter |

**Who actually pays for DX:**

| Industry | Why |
| -------- | --- |
| **Banks & financial services** | Compliance (PCI-DSS, FFIEC), trading latency, data sovereignty, massive risk-modelling data |
| **Insurance** | Actuarial / claims data volumes; compliance |
| **Healthcare / pharma** | HIPAA (PHI mustn't traverse public internet without controls), medical imaging (terabytes of MRI/CT), drug discovery compute |
| **Government / public sector** | FedRAMP / IRAP / G-Cloud often mandate private connectivity for sensitive workloads |
| **Telecoms** | Interconnect with AWS to offer cloud-on-net services to enterprise customers |
| **Media & broadcasting** | Multi-TB raw video footage between studios and cloud editing/rendering |
| **Manufacturing / energy** | IoT / SCADA data from factories or wind farms; latency-sensitive control |
| **Gaming** | Low-latency anti-cheat / matchmaking |
| **Large retail** | POS / inventory spanning on-prem stores + cloud; PCI compliance |
| **Enterprise SaaS providers** (Snowflake, Databricks, Salesforce) | DX-based customer connectivity so customers don't traverse internet to use the SaaS — often combined with PrivateLink |

**The hidden driver — internet egress costs:**

This rarely comes up explicitly but matters most at scale:

- 1 TB/month: internet = $92, DX = $20
- 100 TB/month: internet = $9,200/month, DX = $2,000/month — **DX saves $7k/month** after port fees
- 1 PB/month (large enterprise): internet = $92,000/month, DX = $20,000/month

The DX port itself is **~$216/month** for 1 Gbps dedicated. Break-even on egress savings alone happens fast at scale.

**Who does NOT need DX:**

| Situation | Why not |
| --------- | ------- |
| **Pure cloud-native startup** | No on-prem; VPC + internet is enough |
| **Hybrid with < 1 Gbps usage** | Site-to-Site VPN at ~$0.05/hour does the job; DX overkill |
| **No compliance pressure** | Internet + TLS is enough for most workloads |
| **Don't push enough data** | At < 10 TB/month outbound, internet egress doesn't justify a DX port |
| **Want speed-of-setup** | DX install = **weeks to months**. VPN = **minutes** |

**Architectural tells that signal DX is in use:**

- "Hybrid Active Directory across on-prem and AWS"
- "Direct Connect Gateway" in the diagram
- "Equinix" / "CoreSite" or another colocation facility mentioned
- BGP ASN exchange with AWS
- Multi-region DR with on-prem as part of the topology
- "FedRAMP High" or other strict compliance label
- VMware Cloud on AWS (almost always paired with DX)
- AWS Outposts (uses DX for management plane)

**The "is DX worth it?" decision:**

```
Do you have an on-prem data centre that needs to integrate with AWS?
  ├── NO → skip DX, use VPN if you need any hybrid
  └── YES → 
        Are you transferring > ~10 TB/month sustained?
          ├── YES → DX pays for itself on egress savings alone
          └── NO →
                Do you have compliance requirements demanding private circuits?
                  ├── YES → DX (or your auditors fail you)
                  └── NO →
                        Do you need consistent low-latency for real-time apps?
                          ├── YES → DX
                          └── NO → VPN is probably fine
```

**Mental model:** *Direct Connect isn't really about "fast network" — it's about **predictable cost** (per-GB egress vs internet), **predictable performance** (no jitter), and **compliance documentation** (auditor wants a private circuit on paper). Big enough on-prem footprint + regulated enough to need private paths + moving enough data that egress savings matter → DX. Startups and pure-cloud orgs don't need it.*

#### Direct Connect Deeper Bits

**Virtual Interfaces (VIFs)** — the logical channel on top of the physical DX line. Three types, each tested:

| VIF type | Connects to | Use |
| -------- | ----------- | --- |
| **Private VIF** | A single VPC (via Virtual Private Gateway) | Reach private resources in one VPC |
| **Transit VIF** | A **Direct Connect Gateway** which attaches to a **Transit Gateway** | Reach many VPCs (often multi-region) via TGW |
| **Public VIF** | AWS **public endpoints** (S3, DynamoDB, etc.) — but **not the public internet** | Avoid the public internet for AWS public-service access |

**Direct Connect Gateway** — multi-region glue. One DX physical connection can reach VPCs in **multiple regions** by attaching the DX Gateway to a Virtual Private Gateway (per region) or a Transit Gateway.

**Hosted vs Dedicated connections:**

| | **Dedicated** | **Hosted** |
| - | ------------- | ---------- |
| Provided by | AWS directly | An AWS Partner |
| Bandwidth options | 1, 10, 100 Gbps (fixed) | 50 Mbps up to 10 Gbps (flexible) |
| Setup time | Weeks (physical install) | Days (partner provisions a slice of their existing port) |
| Cost | Higher (whole port for you) | Lower (sharing physical infrastructure) |

**Link Aggregation Group (LAG)** — bundle multiple DX connections into one logical link for higher bandwidth + redundancy.

**Encryption options on DX:**

By default, **DX traffic is NOT encrypted** (it's a private line, but plaintext). For encryption:

| Option | How |
| ------ | --- |
| **MACsec** | Hardware-level Layer 2 encryption on the DX port. Requires supported hardware + the 10/100 Gbps tiers |
| **Site-to-Site VPN over DX** | Run a VPN tunnel inside the DX connection — gets you IPsec encryption with DX's low/consistent latency |
| **Application-layer TLS** | Just use TLS for the actual traffic (web apps); DX adds privacy + consistency, app provides encryption |

**Exam trap:** *"DX connection is private so it's encrypted"* → **wrong**. DX is private but not encrypted by default. Use **MACsec** or **VPN over DX** if encryption is required.

#### Site-to-Site VPN Deeper Bits

**Dual-tunnel HA** — every Site-to-Site VPN automatically gets **two tunnels** to different AWS endpoints. Your customer gateway should be configured to use both (active/active or active/standby).

**Static vs dynamic (BGP) routing:**

| | **Static routing** | **BGP routing** |
| - | ------------------ | --------------- |
| Setup | Manually configure routes on both sides | Use BGP to exchange routes dynamically |
| Failover | Manual | Automatic — BGP detects tunnel down + reroutes |
| When | Small, stable network | Recommended for production / scale |

**Accelerated Site-to-Site VPN** — uses **AWS Global Accelerator** under the hood to route VPN traffic over the AWS backbone from the nearest edge location. Lower + more consistent latency. ~10% extra cost.

**VPN CloudHub** — a hub-and-spoke topology using a single Virtual Private Gateway to connect **multiple on-prem sites** via VPN. Each site terminates its VPN at the VGW; the VGW routes between them. *Cheap multi-site hybrid pattern* without needing a TGW.

**Exam triggers:**
- *"Connect AWS to multiple remote offices, cheap and simple"* → **VPN CloudHub** (single VGW, multiple customer gateways)
- *"Direct Connect failover to VPN"* → **VPN as backup with BGP for automatic failover**
- *"Lower-latency VPN over the public internet"* → **Accelerated Site-to-Site VPN** (uses Global Accelerator)
- *"Encrypt traffic over Direct Connect"* → **MACsec** or **VPN over DX**

#### Is Site-to-Site VPN "Old School"?

Honest answer: **mostly yes** — but that's not a criticism. Site-to-Site VPN is the cloud-managed version of IPsec tunnels enterprises have been running since the late 1990s. The protocol (IPsec, IKEv2), the configuration concepts (BGP over the tunnel, pre-shared keys, dual-tunnel HA), and the customer-side hardware (Cisco, Fortinet, Juniper, Palo Alto, even pfSense) all predate "the cloud" by decades.

It's **not deprecated** — it's still the default answer for "connect my office network to my VPC" because (a) every enterprise already owns VPN-capable hardware and (b) IPsec is universally understood by network teams.

**What's actually modern about it (the AWS-side bits):**

| Modern bit | How it differs from old-school |
| ---------- | ------------------------------- |
| **AWS-side endpoint is managed** | No VPN appliance to run in AWS; VGW / TGW is a service |
| **ECMP across multiple tunnels** (with TGW) | Aggregate bandwidth beyond the 1.25 Gbps per-tunnel cap |
| **Accelerated VPN** | Routes via AWS Global Accelerator edge network |
| **Hub-and-spoke with TGW** | One VPN to TGW reaches many VPCs |
| **Cross-region via TGW peering** | Multi-region hybrid bridged through AWS backbone |
| **CloudWatch metrics + Flow Logs** | Cloud-native observability |
| **Pay-as-you-go** | $0.05/hour per tunnel vs depreciating VPN appliances |

#### When Modern Alternatives Beat Site-to-Site VPN

For the *"connect my office network to my VPC"* use case, Site-to-Site VPN is still the right answer. For **adjacent** use cases people sometimes try to solve with VPN, there are better options:

| Modern alternative | When it beats Site-to-Site VPN |
| ------------------ | ------------------------------ |
| **AWS Direct Connect** | Higher bandwidth needs, compliance demanding private circuit, large egress data volumes — covered in the DX section above |
| **AWS Client VPN** | Individual user laptops (not whole networks) — TLS-based, modern auth (SAML, IAM Identity Center, AD) |
| **AWS Verified Access** | Workforce access to **HTTP/HTTPS apps** — zero-trust model, **no VPN client needed**. Replaces VPN for *"engineer wants to access internal web app from a laptop"* |
| **Amazon VPC Lattice** | Service-to-service mesh — replaces VPN-or-peering patterns for *internal* service connectivity (HTTP) |
| **AWS Cloud WAN** | Managing multi-region networks declaratively — replaces hand-built multi-VPN/TGW setups |
| **AWS PrivateLink** | Exposing a single service privately — replaces VPN-for-one-service patterns |

#### Exam framing

When a scenario describes a **traditional enterprise hybrid pattern** (on-prem DC, VPN device, BGP, etc.) → **Site-to-Site VPN** is in play.

When it describes **modern cloud-native patterns** (individual users accessing HTTPS apps from anywhere, microservices, mesh) → think **Verified Access / Client VPN / Lattice**.

| Question phrasing | Likely answer |
| ----------------- | ------------- |
| *"Connect our office network of 200 users to AWS"* | **Site-to-Site VPN** (or DX if bandwidth/compliance demands) |
| *"Individual remote employees need access to a private RDS"* | **AWS Client VPN** |
| *"Workforce needs zero-trust access to internal HTTPS apps without a VPN client"* | **AWS Verified Access** |
| *"Microservices across many VPCs need to talk to each other"* | **VPC Lattice** |
| *"Expose one service privately to many consumer VPCs"* | **PrivateLink** |
| *"Multi-region network policy as code"* | **AWS Cloud WAN** |

The mental model: *Site-to-Site VPN = "old school but still right" for office-to-VPC. The newer services are for specific cases the older protocol doesn't fit elegantly.*

#### Site-to-Site VPN vs Virtual Private Gateway — the Layer Confusion

A perennial source of exam confusion: people treat *Site-to-Site VPN* and *Virtual Private Gateway* as alternatives. They're **not** — they're different layers of the same setup.

- **Site-to-Site VPN** is the **service** (the encrypted IPsec tunnel pair)
- **Virtual Private Gateway (VGW)** is one option for the **AWS-side endpoint** the tunnel terminates at
- **Transit Gateway (TGW)** is the other AWS-side endpoint option
- **Customer Gateway (CGW)** is just AWS's metadata record of your **on-prem VPN device** (its public IP + BGP ASN — not a real device AWS runs)

So the real choice isn't *"Site-to-Site VPN vs VGW"* — it's **VGW vs TGW for terminating the VPN on the AWS side**:

| | **VGW** | **TGW** |
| - | ------- | ------- |
| Attaches to | **One VPC** | **Many VPCs + VPNs + DX + peerings** |
| Transitive routing | ❌ | ✅ (the whole point) |
| ECMP for multiple VPN tunnels | ❌ | ✅ — aggregate higher bandwidth |
| Cross-region | ❌ | ✅ via TGW peering |
| VPN connections supported | 10 | 5000 |
| Use when | Single VPC, simple hybrid | Multi-VPC hybrid, hub-and-spoke |

Even for "just one VPC today" scenarios, **TGW is often chosen** for future-proofing — adding a second VPC is one attachment vs another VPN.

**Exam triggers for VPN termination choice:**

| Question | Answer |
| -------- | ------ |
| *"Where does Site-to-Site VPN terminate on the AWS side?"* | **VGW** (one VPC) or **TGW** (many VPCs) |
| *"On-prem needs access to 10 VPCs via VPN"* | **TGW + Site-to-Site VPN** (one VPN to TGW, transitive to all VPCs) |
| *"Single VPC, cheapest VPN setup"* | **VGW + Site-to-Site VPN** |
| *"Increase VPN aggregate bandwidth beyond 1.25 Gbps per tunnel"* | **TGW + multiple VPN connections + ECMP** |
| *"Failover between DX and VPN"* | Both terminate at the same **TGW**; BGP handles failover |
| *"Multi-region hybrid network"* | **TGW + TGW peering** (or **DX Gateway + multiple VGWs in different regions**) |
| *"Customer Gateway is..."* | An AWS resource **representing your on-prem VPN device** (its public IP + BGP ASN) — metadata, not a device AWS runs |
| *"Connect to a single VPC via Direct Connect"* | **DX → Private VIF → VGW** |
| *"Connect to many VPCs via Direct Connect"* | **DX → Transit VIF → DX Gateway → TGW** |

**The mental model:** *Site-to-Site VPN = the encrypted IPsec service. **VGW vs TGW** = the actual choice on the AWS side. VGW = "this one VPC only." TGW = "this VPC and any others I want, plus future hybrid connectivity." Customer Gateway = AWS's name for your on-prem router.*

### AWS Client VPN

**Anchored as workforce VPN: laptops → AWS.** Site-to-Site VPN connects entire networks; **Client VPN connects individual users**. The exam constantly tests the distinction.

#### Client VPN vs Site-to-Site VPN

| | **Site-to-Site VPN** | **AWS Client VPN** |
| - | --------------------- | ------------------- |
| What it connects | **Whole on-prem network** to VPC | **Individual user laptops / devices** to VPC |
| Protocol | IPsec (industry standard) | TLS (OpenVPN-compatible) |
| Client software | None — uses customer gateway (hardware/router) | **AWS Client VPN client** (or any OpenVPN client) |
| Auth | Pre-shared key / certificate | **Active Directory**, **SAML / Identity Center**, or **mutual TLS** (certs) |
| Use case | Office / data centre to AWS | Remote employees / contractors accessing AWS private resources |
| Pricing | Per-tunnel-hour | Per-endpoint-hour + per-connected-user-hour |

#### Core Client VPN concepts

| Concept | What it is |
| ------- | ---------- |
| **Client VPN endpoint** | The VPN entry point you create; users connect to it |
| **Target network associations** | Which subnets the endpoint can reach (you associate ≥1 subnets) |
| **Authorisation rules** | Per-CIDR / per-group rules controlling who can reach what |
| **Connection log** | CloudWatch Logs of who connected when (audit trail) |
| **Split-tunnel** | Only traffic to AWS goes through the VPN; everything else uses the user's local internet — better UX, less load on the endpoint |
| **Full-tunnel** | ALL user traffic routed through AWS — useful for centralised inspection, less private for users |

#### Typical flow

```
1. User opens AWS VPN Client on their laptop
       ↓
2. Authenticates (e.g. SAML via Okta / IAM Identity Center)
       ↓
3. TLS tunnel established to the Client VPN endpoint
       ↓
4. User assigned an IP from the endpoint's CIDR pool
       ↓
5. Authorisation rules evaluate: "is this user/group allowed to reach 10.0.10.0/24?"
       ↓
6. If allowed, user can reach private resources (RDS, internal apps) as if on the VPC
```

**Exam triggers:**
- *"Remote employees need to access private RDS / internal apps in VPC"* → **AWS Client VPN**
- *"Connect a remote office to AWS"* → **Site-to-Site VPN** (not Client VPN)
- *"Federate Client VPN with Active Directory or Okta"* → **Client VPN with AD / SAML auth**
- *"Only AWS-bound traffic should go through the VPN"* → **Split-tunnel mode**
- *"Audit who connected when"* → **Client VPN connection logs to CloudWatch**

### Gateway Load Balancer (GWLB)

**Anchored as: a transparent L3 load balancer for inline traffic appliances.** GWLB lets you deploy fleets of **third-party security/network appliances** (Palo Alto, Check Point, Fortinet firewalls, IDS/IPS like Snort/Suricata) and have ALL VPC traffic transparently flow through them for inspection — without any changes to the source/destination of the traffic.

#### What problem GWLB solves

Before GWLB: deploying inline 3rd-party appliances in AWS meant:
- Routing traffic to an EC2 instance running the appliance
- Single instance = SPoF + bandwidth bottleneck
- No native load balancing of the appliances themselves
- Appliances had to do their own NAT / source-IP-rewriting

GWLB makes appliance fleets:
- **Transparent** (preserve original source IP)
- **Horizontally scalable** (just add more appliances)
- **Highly available** (auto-replaces unhealthy ones)
- **Inline in the data path** (no DNS tricks needed)

#### Core concepts

| Concept | What it is |
| ------- | ---------- |
| **Gateway Load Balancer** | The actual load balancer — sits in a "security VPC" |
| **GENEVE encapsulation** | The protocol GWLB uses to forward traffic to appliances (UDP/6081). Wraps the original IP packet so the appliance sees true source/dest |
| **Target group** | The appliances behind the GWLB (EC2 instances running firewall/IDS software) |
| **Gateway Load Balancer Endpoint (GWLBE)** | An ENI in your *service VPC* that traffic routes to — acts as the "front door" |
| **Service consumer model** | Like PrivateLink: security team runs the GWLB; app teams' VPCs connect via GWLBEs |

#### The architectural pattern

```
       Internet
           │
           ▼
   ┌──────────────────┐
   │ Public Subnet    │
   │ (route table:    │
   │  default route   │
   │  to GWLBE)       │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐               ┌────────────────────────┐
   │ GWLBE (in your   │ ←──GENEVE──→  │ Security VPC           │
   │ VPC)             │               │   Gateway Load         │
   └────────┬─────────┘               │   Balancer             │
            │                          │       │                │
            │ (after inspection,       │       ▼                │
            │  traffic returns)        │   Appliance fleet      │
            ▼                          │   (Palo Alto / etc.)   │
   ┌──────────────────┐               └────────────────────────┘
   │ Private Subnet   │
   │ (app instances)  │
   └──────────────────┘
```

Traffic flows: **app VPC → GWLBE → GENEVE-tunnelled to Security VPC → through appliance fleet → returned to app VPC**. The app sees no change.

#### GWLB vs AWS Network Firewall

| | **AWS Network Firewall** | **Gateway Load Balancer** |
| - | ------------------------ | -------------------------- |
| What it is | A fully managed firewall (AWS provides the engine) | A load balancer for **3rd-party** appliances you bring |
| Engine | AWS-managed Suricata + custom rules | Whatever appliance you deploy (Palo Alto, Check Point, Fortinet, Snort, custom) |
| Use when | You want AWS-managed firewall, no licence to buy | You already have a 3rd-party security vendor + their cloud offering |
| Maintenance | AWS patches | You patch (or AMI vendor) |

**Decision:** new build, no existing vendor preference → **Network Firewall**. Existing relationship with Palo Alto / Check Point / Fortinet and want their cloud edition → **GWLB + their appliance**.

#### Common Anti-patterns

- *"Use ALB for inline firewall inspection"* — ALB is L7 HTTP, not transparent. Use GWLB
- *"Single appliance EC2 with route table pointing to it"* — no HA, no scaling. Use GWLB-fronted fleet
- *"GWLB for L7 HTTP routing"* — wrong tool. GWLB is transparent L3; use ALB for L7

**Exam triggers:**
- *"Deploy a fleet of 3rd-party firewalls / IDS that scales horizontally"* → **GWLB**
- *"Transparent inline traffic inspection without changing source/dest IPs"* → **GWLB** (uses GENEVE)
- *"Centralised security appliance inspection across many VPCs"* → **GWLB in security VPC + GWLBEs in app VPCs**
- *"My existing Palo Alto / Check Point / Fortinet team wants to run their cloud appliance in AWS"* → **GWLB + vendor's AMI**

### VPC Anti-patterns (exam wrong answers)

- **Attaching security groups to SQS/SNS/S3/DynamoDB** — these don't have ENIs. Use IAM + resource policy, plus VPC endpoints if you need the traffic to stay private.
- **Single NAT Gateway for multi-AZ private subnets** — if that AZ dies, all private subnets lose internet. One NAT per AZ.
- **Interface endpoint for S3** — works but Gateway endpoint is free. Prefer Gateway unless you specifically need PrivateLink behaviour (e.g. on-prem reaching S3 through DX).
- **VPC Peering for 10+ VPCs** — N² problem. Use Transit Gateway.
- **Relying on a tight SG with a public IP** — public IPs still attract noise; private subnet + ALB is stronger.
- **Trying to use NACL deny rules for application-level access control** — too brittle and far from the app. Use SG + IAM + WAF closer to the resource.
- **Putting Lambda in a VPC by default** — only do it if Lambda needs to reach private resources (RDS, ElastiCache). VPC attachment loses internet access (unless NAT) and adds cold-start cost.
- **Hundreds of EC2 instances calling the same external API through one NAT Gateway** — hits the **55k connection limit per destination**. Use VPC Endpoints (for AWS services) or distribute traffic.
- **Site-to-Site VPN for individual remote employees** — wrong tool; that's **AWS Client VPN**.
- **Trusting DX is encrypted by default** — it's not. Use **MACsec** or **VPN over DX**.
- **Manually managing CIDRs across 50+ accounts in a spreadsheet** — error-prone; use **IPAM**.
- **Spinning up appliances on standalone EC2 for inline inspection** — no HA, no scaling. Use **GWLB**.
- **Single TGW route table for prod + dev** — no segmentation. Use **multiple TGW route tables**.
- **Hand-managed multi-region TGW peerings + attachments** — at scale, consider **AWS Cloud WAN** declarative policy.
- **Cross-VPC service-to-service via PrivateLink for HTTP microservices** — works but heavy. Consider **VPC Lattice** for HTTP service mesh.
- **On-prem servers can't resolve AWS private hosted zone names** — need an **Inbound Resolver Endpoint**.
- **EC2 instances can't resolve on-prem internal domains** — need an **Outbound Resolver Endpoint + forwarding rules**.

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
- *"private IPv6 instances need outbound internet only"* → **Egress-Only Internet Gateway**
- *"hundreds of EC2 instances dropping connections to the same API endpoint"* → NAT Gateway **55k connection limit per destination**
- *"on-prem servers need to resolve AWS private hosted zone names"* → **Route 53 Resolver Inbound endpoint**
- *"EC2 needs to resolve on-prem internal domains"* → **Route 53 Resolver Outbound endpoint + forwarding rules**
- *"central networking team manages one VPC; app teams deploy resources into shared subnets"* → **VPC Sharing via AWS RAM**
- *"avoid duplicate NAT Gateways across many accounts"* → **VPC Sharing** (participants use the owner's NAT)
- *"east-west microservice connectivity across VPCs with IAM auth"* → **VPC Lattice**
- *"declarative multi-region network policy"* → **AWS Cloud WAN**
- *"centrally manage CIDRs across many accounts, prevent overlap"* → **AWS IPAM**
- *"point all VPC instances at on-prem DNS servers"* → **custom DHCP option set**
- *"segment prod and dev networks via TGW"* → **TGW with multiple route tables**
- *"connect TGWs across regions"* → **TGW peering attachments**
- *"why can't host A reach host B? show me the exact rule blocking"* → **Reachability Analyzer**
- *"audit network exposure across the org continuously"* → **Network Access Analyzer**
- *"Direct Connect needs to reach VPCs in multiple regions"* → **Direct Connect Gateway**
- *"reach AWS public services (S3) over Direct Connect, avoiding the internet"* → **Public VIF**
- *"DX with TGW for many-VPC hybrid"* → **Transit VIF + Direct Connect Gateway + TGW**
- *"encrypt traffic over Direct Connect"* → **MACsec** (hardware-level) or **VPN over DX** (IPsec)
- *"connect multiple remote offices to AWS via VPN cheaply"* → **VPN CloudHub** (one VGW, multiple customer gateways)
- *"automatic failover for Site-to-Site VPN"* → **BGP dynamic routing**
- *"lower-latency VPN by using AWS backbone"* → **Accelerated Site-to-Site VPN**
- *"remote employees / laptops need access to private resources in VPC"* → **AWS Client VPN**
- *"only AWS-bound traffic goes through the Client VPN"* → **split-tunnel mode**
- *"Client VPN auth via Okta / Identity Center / Active Directory"* → **SAML / AD auth**
- *"deploy a fleet of 3rd-party firewalls / IDS that scales"* → **Gateway Load Balancer (GWLB)**
- *"transparent L3 inline inspection without changing source/dest IPs"* → **GWLB with GENEVE**
- *"centralised security appliance VPC inspecting traffic from many app VPCs"* → **GWLB + GWLBEs**

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

## Amazon CloudWatch

**Anchored against services you know.** CloudWatch is AWS's observability layer (metrics + logs + alarms + dashboards) — the AWS-native answer to what Datadog does in one product. Most other AWS services emit metrics/logs *into* CloudWatch automatically; you query, alarm, visualise, and react from there.

### The Five Core Concepts

| Component | What it does |
| --------- | ------------ |
| **Metrics** | Time-series numeric data (CPU, request count, custom values). Per-AWS-service metrics are free; **custom metrics** cost per metric per month |
| **Alarms** | Threshold-based triggers on metrics (or composite of multiple) — states: `OK` / `INSUFFICIENT_DATA` / `ALARM` |
| **Logs** | Application + service logs collected into log groups / log streams. **Retention is per-log-group** (default = never expire → cost trap) |
| **Logs Insights** | Query language for searching/aggregating logs — pay per GB scanned |
| **Dashboards** | Visualisations across metrics + logs |

### The Monitoring Granularity Trap (exam favourite)

| | **Basic monitoring** | **Detailed monitoring** |
| - | -------------------- | ----------------------- |
| Granularity | **5-minute** | **1-minute** |
| EC2 cost | Free | Paid (per instance) |
| Default? | Yes for EC2 | No — opt-in |

**Custom metrics** can be even finer — down to **1-second** (high-resolution custom metrics).

Exam phrasing: *"need faster autoscaling response than 5 minutes"* → **enable Detailed Monitoring** (1-minute) or **publish a custom metric**.

### The CloudWatch Agent — the OS-level fact most miss

By default, EC2 metrics include **CPU, network, disk I/O**, but **NOT memory** or **disk usage**. To get those, install the **CloudWatch Agent** on the instance — it pushes OS-level metrics (RAM, disk free, custom application metrics) into CloudWatch as custom metrics.

Exam triggers:
- *"can't alarm on EC2 memory usage"* → **install the CloudWatch Agent** (memory is not a default metric)
- *"can't alarm on disk free space"* → **CloudWatch Agent**

### Alarms + Auto Scaling — the classic pattern

```
EC2 CPU > 70% for 5 min → CloudWatch Alarm → Auto Scaling Group → add instances
SQS queue depth > 1000  → CloudWatch Alarm → Auto Scaling Group → add consumers
RDS connections > 80%   → CloudWatch Alarm → SNS → email/page ops
```

**Composite alarms** combine multiple alarms with AND/OR logic — reduce noise (only alarm if "high CPU AND high error rate").

### CloudWatch Alarms vs Datadog Monitors (mental anchor)

If you use Datadog at work, a **Datadog "monitor" ≈ CloudWatch Alarm**. Same idea: watch a condition, evaluate continuously, notify on breach. The vocabulary differs but the model is identical.

| Datadog | CloudWatch equivalent |
| ------- | --------------------- |
| Monitor (metric) | **CloudWatch Alarm** on a metric |
| Anomaly monitor | **CloudWatch Alarm** with **Anomaly Detection** |
| Log monitor (count matches) | **Metric Filter** → **CloudWatch Alarm** |
| Composite monitor (AND/OR) | **Composite Alarm** |
| Notification channels (Slack, PagerDuty, email) | **SNS topic** → AWS Chatbot / Lambda / email subscribers |

**Worked example — "alert Slack when more than 10 errors in 5 minutes":**

```
Datadog:    Log query: status:error → Monitor: count > 10 over 5 min → #ops-alerts Slack

CloudWatch: Logs → Metric Filter (pattern { status = "error" }) → custom metric ErrorCount
                  → CloudWatch Alarm (ErrorCount > 10 over 5 min)
                  → SNS topic
                  → AWS Chatbot → Slack channel
```

Two things that trip people up when translating from Datadog mental model:

1. **AWS Chatbot is the bridge to Slack / MS Teams.** SNS can't post to Slack directly. **AWS Chatbot** subscribes to an SNS topic and posts to a channel — no Lambda needed. Exam phrasing: *"send CloudWatch alarms to a Slack channel"* → **SNS + AWS Chatbot**.

2. **Log-based alerts need the Metric Filter step.** Datadog lets you alarm directly on a log query. In CloudWatch you first turn the log pattern into a metric (the **Metric Filter**), then alarm on that metric. Exam phrasing: *"alert when more than N errors appear in logs"* → **Metric Filter + CloudWatch Alarm**.

**Alarm states** also differ:

| Datadog | CloudWatch |
| ------- | ---------- |
| OK / Warn / Alert / No Data | **OK / INSUFFICIENT_DATA / ALARM** (3 states only) |

**Exam triggers:**

- *"send CloudWatch alarm to a Slack channel"* → **SNS topic + AWS Chatbot**
- *"alert when log pattern X appears more than N times"* → **Metric Filter → CloudWatch Alarm → SNS**
- *"reduce alarm noise by combining conditions (AND/OR)"* → **Composite Alarm**
- *"alarm on unusual behaviour rather than a fixed threshold"* → **CloudWatch Anomaly Detection**

### Composite Alarms (deep dive)

A **composite alarm** has no metric of its own — its state is computed from a boolean **rule expression** over other alarms. Two reasons to use them: **reduce noise** (combine conditions) and **suppress flood** (silence children when a parent is in alarm).

**Rule expression syntax:**

The expression uses three state functions over the child alarms:

```
ALARM("alarm-name")              ← true when that alarm is in ALARM state
OK("alarm-name")                 ← true when that alarm is in OK state
INSUFFICIENT_DATA("alarm-name")  ← true when that alarm has no data
```

Combine with `AND`, `OR`, `NOT` and parentheses.

**Worked examples:**

```
# Page only if BOTH high CPU and high error rate
ALARM("high-cpu") AND ALARM("high-error-rate")

# Alert on either symptom
ALARM("p99-latency") OR ALARM("5xx-rate")

# High CPU, but only if the underlying disk isn't full (different root cause)
ALARM("high-cpu") AND NOT ALARM("disk-full")

# Treat missing data as healthy, not as a problem
(ALARM("api-error-rate")) AND (NOT INSUFFICIENT_DATA("api-error-rate"))
```

**Suppressor alarms — the noise-flood killer:**

A composite alarm can designate another alarm as a **suppressor**. While the suppressor is in ALARM, the composite alarm **does not publish state-change notifications** for its children — preventing alert storms when one root cause triggers many downstream effects.

Classic scenario:

```
                    ┌──────────────────────────────────────────────┐
                    │ Region-wide outage = page once, not 50 times │
                    └──────────────────────────────────────────────┘

Region-Down alarm (suppressor)  ──→  composite alarm tracking 50 service-level alarms
                                     suppresses notifications while Region-Down is ALARM
```

Without the suppressor: a region-wide outage triggers 50 downstream service alarms → 50 pages → on-call overload.
With the suppressor: only the region-down page fires; the 50 noisy children are gagged for the duration.

You can configure how long the suppression lasts and what happens on edge timing (suppressor extension period, wait period).

**Cost:**

Composite alarms are billed **per alarm-month**, same model as regular alarms. They're cheap, but each child also counts as its own alarm — composite ≠ free.

**Anti-patterns (exam wrong answers):**

- **Composite alarm with a metric expression** — composite alarms don't observe metrics directly; that's what *metric math* + regular alarms are for. Composites operate on alarm *states*, not metric values.
- **Trying to suppress with `OK("parent-alarm")`** — suppressor logic uses the dedicated **ActionsSuppressor** field, not an OR/AND clause. Use the suppressor mechanism, not the rule expression, for flood-killing.
- **Using composite to chain alarms with no logic gain** — if you just want "fire if A OR B", a Composite makes sense. If you have *one* condition, just use a regular alarm.
- **Forgetting that children still publish independently** — composite suppression only silences the *composite's* actions. Child alarms still fire their own actions unless reconfigured. Disable child actions if the composite is meant to be the sole notifier.

**Exam triggers:**

- *"alarm only when high CPU AND high error rate occur together"* → **Composite Alarm with AND**
- *"alert on either of two symptoms"* → **Composite Alarm with OR**
- *"prevent alert flood when a parent infrastructure failure triggers many downstream alarms"* → **Composite Alarm with a suppressor**
- *"reduce noise from chatty monitoring without disabling alerts entirely"* → **Composite Alarm**
- *"alarm logic that depends on the state of other alarms, not raw metrics"* → **Composite Alarm**

### Testing Alarms

Three CLI tools for testing and operating alarms without waiting for real conditions to trigger.

**`set-alarm-state` — manually flip alarm state to test downstream actions:**

```bash
aws cloudwatch set-alarm-state \
  --alarm-name "high-error-rate" \
  --state-value ALARM \
  --state-reason "Testing Slack integration"
```

- Flips state to `ALARM` / `OK` / `INSUFFICIENT_DATA` immediately
- **Triggers every configured action** — SNS notifications, Auto Scaling, Lambda — as if the threshold was breached
- **State auto-reverts** at the next evaluation period when CloudWatch reads the real metric (no manual cleanup)
- Doesn't touch underlying metric data
- Requires `cloudwatch:SetAlarmState` IAM permission

**`put-metric-data` — drive the real evaluation logic with a fake value:**

```bash
aws cloudwatch put-metric-data \
  --namespace "MyApp" \
  --metric-name "ErrorCount" \
  --value 999
```

- Publishes a real metric value — alarm evaluates as it normally would
- More realistic than `set-alarm-state` (exercises the threshold logic, datapoints-to-alarm, etc.)
- Useful for testing **anomaly detection** alarms where the logic depends on the metric distribution

**`disable-alarm-actions` — mute during maintenance without deleting:**

```bash
aws cloudwatch disable-alarm-actions --alarm-names "high-cpu" "high-errors"
# ... do disruptive maintenance ...
aws cloudwatch enable-alarm-actions --alarm-names "high-cpu" "high-errors"
```

- Alarm state still updates (you can see it in the console) but **no actions fire**
- Use during planned maintenance windows to silence false pages without losing the alarm config

**Side-by-side:**

| Tool | What it does | Real metric data? | Triggers actions? | Use for |
| ---- | ------------ | ----------------- | ----------------- | ------- |
| `set-alarm-state` | Manually flip state | No | Yes | Quick end-to-end test of SNS / Chatbot / autoscaling wiring |
| `put-metric-data` | Push a fake metric value | Yes | Yes (if threshold exceeded) | Realistic testing including evaluation logic |
| `disable-alarm-actions` | Mute actions | Yes | **No** | Maintenance windows — keep alarm logic, silence pages |

**Gotchas:**

- **`set-alarm-state` notifies for real** — if you run it in prod, ops will get paged. Test in non-prod, or warn the team / mute Slack first.
- **State reverts on next evaluation** — useful auto-cleanup, but you can't pin a state with this command.
- **`set-alarm-state` doesn't bypass disabled actions** — flips state but actions stay silent if you've disabled them.
- **No `set-alarm-state` on a composite alarm directly** — composite state is *computed* from children. Drive it by setting child alarm states.

**Exam triggers:**

- *"verify a CloudWatch alarm triggers the right SNS notification end-to-end"* → `set-alarm-state`
- *"test autoscaling policy without waiting for real load"* → `set-alarm-state` (quick) or `put-metric-data` (realistic)
- *"silence alarms during planned maintenance without losing them"* → `disable-alarm-actions`
- *"test a composite alarm's logic"* → set the *child* alarm states (composite has no direct setter)

### CloudWatch Synthetics (deep dive)

**Scripted probes that run on a schedule from AWS-managed infrastructure**, hitting your endpoints (or full user flows) and recording success / failure / latency. The AWS-native equivalent of the synthetic monitoring you'd build with Datadog Synthetics, Pingdom, or New Relic.

```
Every 1 min: AWS Synthetics → HTTP GET https://api.example.com/health
             → check status 200, response body contains "ok"
             → record success / latency to CloudWatch metrics
             → screenshot + HAR file on failure → S3
             → trigger CloudWatch Alarm if 3 consecutive failures
```

**Five canary blueprints (you don't write all of them from scratch):**

| Blueprint | What it does |
| --------- | ------------ |
| **Heartbeat monitor** | Single URL probe — quick health check |
| **API canary** | Multi-step REST API workflow with assertions on response |
| **Broken link checker** | Crawl a page, follow all links, report 404s |
| **Visual monitoring** | Pixel-diff a page against a baseline — detect visual regressions |
| **GUI workflow builder / canary recorder** | Record a real user flow (login → add to cart → checkout), replay it on schedule |

Under the hood: **Node.js or Python running headless Chromium** (Puppeteer/Selenium). You can write fully custom scripts when blueprints don't fit.

**What gets recorded:**

- **Metrics** in CloudWatch — `SuccessPercent`, `Duration`, `Failed`, per canary
- **Screenshots + HAR files** on failure → stored in S3
- **CloudWatch Logs** with detailed step-by-step output
- **X-Ray traces** (optional)

You then **alarm** on those metrics — *"if `SuccessPercent < 90` over 5 min → SNS → Slack"*.

**Where it sits in the observability stack:**

| Probe type | Service |
| ---------- | ------- |
| **Synthetic** — AWS-run scripted probe of your endpoint | **CloudWatch Synthetics** |
| **Real User Monitoring** — actual browsers in the wild reporting back | **CloudWatch RUM** |
| **Distributed tracing** — follow a request across services | **X-Ray** |
| **Metrics + Alarms** | **CloudWatch** core |
| **Logs** | **CloudWatch Logs** |

Synthetics + RUM are **complementary**: Synthetics tells you *"is the site up from AWS's vantage?"*, RUM tells you *"are real users actually having a good experience?"*

**When to reach for it:**

- **Public API / website uptime monitoring** — the most common use
- **SLA verification** — measurable proof that endpoints meet uptime targets
- **Multi-step flow validation** — login + key action + logout, end-to-end
- **Catch issues before users do** — failures alarm before customer reports
- **Detect SSL cert expiry / TLS errors** — Synthetics fails on cert problems

**Synthetics vs Route 53 health checks (exam trap):**

| | CloudWatch Synthetics | Route 53 health checks |
| - | --------------------- | ---------------------- |
| What it tests | Full HTTP behaviour, multi-step flows, browser flows, content assertions | Simple "is the endpoint responding?" |
| Granularity | 1-min to once-per-hour, scripted | Every 10s or 30s |
| Failure trigger | Alarm + SNS + screenshot + HAR | DNS failover, alarm |
| Cost | Per canary run | Per health check per month |
| Use for | Behavioural / SLA / flow monitoring | DNS failover, simple uptime |

If the question says *"DNS failover when an endpoint is unhealthy"* → **Route 53 health check**. If it says *"alert when login flow breaks"* or *"check API returns expected JSON"* → **Synthetics**.

**Common anti-patterns (exam wrong answers):**

- **Synthetics for real-user performance** → wrong tool; use **RUM** for real-user data
- **Synthetics from a public endpoint to monitor internal-only VPC endpoints** → canaries run on AWS infra; configure **VPC-attached canaries** to reach internal endpoints
- **Route 53 health checks for multi-step flows** → too simple. Synthetics is the right tool for "login → click → assert".

**Exam triggers:**

- *"periodically probe a public API endpoint and alarm on failures"* → **CloudWatch Synthetics** (heartbeat / API canary)
- *"test a multi-step user workflow (login → action → logout) on a schedule"* → **Synthetics** (GUI workflow blueprint)
- *"detect broken links across a website"* → **Synthetics** (broken link checker blueprint)
- *"visual regression testing — alert when a page's appearance changes"* → **Synthetics** (visual monitoring blueprint)
- *"real user performance from actual browsers"* → **CloudWatch RUM** (NOT Synthetics)
- *"simple uptime probe with DNS failover"* → **Route 53 health check** (lighter than Synthetics)

**The 80/20:** *Synthetics = AWS-managed scripted probes (Node/Python + headless Chromium). Five blueprints: heartbeat, API, broken-link, visual, GUI workflow. Use it for public API liveness, SLA verification, multi-step flow validation. Pairs with RUM (real-user data) and X-Ray (tracing). For simple "is the IP responding" use Route 53 health checks; for "is the user journey working" use Synthetics.*

### CloudWatch Logs — the cost trap

- Default retention: **never expire** — your logs grow forever and bill forever
- Fix: set retention per log group (1 day → 10 years) or use **subscription filters** to ship to S3 (cheaper) and trim CloudWatch
- **Subscription filters** stream log events in real time to **Kinesis / Lambda / OpenSearch / Firehose**

### Logs Insights vs OpenSearch

| | Logs Insights | OpenSearch |
| - | ------------- | ---------- |
| Setup | Zero — logs already in CloudWatch | Provision cluster |
| Cost | Pay per GB scanned per query | Cluster running cost |
| Query language | CloudWatch Insights syntax | Lucene / OpenSearch query DSL |
| Best for | Occasional log search | Heavy day-to-day log analytics + dashboards |

### Specialised Variants (exam-relevant names)

| Service | What it does |
| ------- | ------------ |
| **CloudWatch Synthetics** | **Canary** scripts that periodically hit your endpoints; alarm on failure |
| **CloudWatch RUM** | Real User Monitoring — frontend performance from real browsers |
| **CloudWatch Container Insights** | Auto-collected ECS / EKS / Fargate metrics + logs |
| **CloudWatch Lambda Insights** | Per-function metrics with cold start, memory, init time |
| **CloudWatch Application Insights** | Automated detection of problems in apps (.NET / SQL / Java) |
| **CloudWatch Anomaly Detection** | ML-based dynamic thresholds — alarm on "unusual" not just "above X" |
| **CloudWatch ServiceLens** | Combine metrics + X-Ray traces for service map view |
| **CloudWatch Contributor Insights** | Top-N analyses (top users, top IPs, top errors) |

### CloudWatch Contributor Insights (short deep dive)

**Mental model:** a continuous *"GROUP BY field ORDER BY count DESC LIMIT 10"* running over a CloudWatch Logs stream. Point a rule at a log group, tell it which field to group by, and it builds a live time-series of the top-N values.

```
CloudWatch Logs (e.g. ALB access logs)
       ↓
Contributor Insights rule:
  match-pattern: status >= 500
  group-by:      clientIP
       ↓
Live time-series: "Top 10 IPs by 5xx count, last 15 min"
       ↓ graph on dashboard / alarm on the leader / spot anomalies
```

**Common use cases:**

| Question | Group-by field |
| -------- | -------------- |
| *"Which IPs are hammering my API?"* | `clientIP` (ALB / CloudFront access logs) |
| *"Which URLs throw the most 5xx?"* | `request.url` |
| *"Which users make the most API calls?"* | `userIdentity.arn` (CloudTrail logs) |
| *"What error code dominates right now?"* | `errorCode` |
| *"Which DynamoDB tables throttle most?"* | `tableName` |
| *"Which Lambda functions time out?"* | `function.name` |

**Bot / scraper detection pattern (the auto-response loop):**

Contributor Insights gives you *visibility*; pair it with WAF for *blocking*. The full layered defence:

```
Internet
   ↓
CloudFront (edge cache + rate limiting)
   ↓
AWS WAF (Bot Control + rate-based rules)   ← inline blocking
   ↓
ALB → app
   ↓ access logs
CloudWatch Logs
   ↓
Contributor Insights rule (top IPs / User-Agents) ← visibility + alerting
   ↓ alarm when top contributor > N req/min
SNS → Lambda → WAF UpdateIPSet (add the IP to a block list) ← automated response
```

CI alone doesn't block — it observes and alerts. **WAF Bot Control + rate-based rules** are the primary inline defence; CI surfaces the slow-burn cases Bot Control might not flag and feeds an automated WAF block via Lambda.

**Two rule types:**

- **Built-in (managed) rules** — pre-built for VPC Flow Logs, DNS query logs, etc. Zero config
- **Custom rules** — you specify log group + match pattern + group-by keys

**Cost note:** billed per rule per month + per million log events analysed. Don't run rules on log groups you don't care about.

**When NOT to use it:**

- **Inline blocking** — too slow; use **WAF rate-based rules** for sub-second blocking
- **One-off forensic queries on historical logs** — use **CloudWatch Logs Insights** (ad-hoc SQL) instead; CI is for *continuous* top-N
- **Low-cardinality fields** (HTTP status with only ~5 values) — create regular per-value metrics instead
- **Sophisticated bot signatures** (rotating IPs, headless-browser tells, JS fingerprints) — **WAF Bot Control** is purpose-built

**Exam triggers:**

- *"identify the top IPs / users / URLs / resources causing X"* → **Contributor Insights**
- *"DDoS investigation — which IP sent the most requests last hour?"* → **Contributor Insights** on access logs
- *"find the heaviest API consumer in CloudTrail"* → **Contributor Insights** on CloudTrail log group
- *"top contributors to a metric in real time"* → **Contributor Insights**
- *"detect and **block** bots / scrapers inline"* → **WAF Bot Control + rate-based rules** (NOT Contributor Insights alone)
- *"detect-and-auto-block pipeline"* → **CI alarm → Lambda → WAF UpdateIPSet**

### Common Anti-patterns (exam wrong answers)

- **"Can't alarm on memory"** → install **CloudWatch Agent** (memory isn't a default EC2 metric)
- **Default-monitoring then asking why autoscaling is slow** → enable **Detailed Monitoring** for 1-min granularity
- **No log retention set** — logs grow forever; cost balloons
- **Logs Insights for daily dashboards on TBs of logs** → use **OpenSearch** instead (cluster pays off at that volume)
- **CloudWatch Events** when the question says "EventBridge" — same service, EventBridge is the rebrand + adds SaaS integrations
- **Picking QuickSight to "monitor latency"** — QuickSight is BI, not monitoring. Use CloudWatch (or third-party Datadog).

### Exam Triggers

- *"monitor AWS resources / alarm on metrics"* → **CloudWatch**
- *"alarm on EC2 CPU > X for autoscaling"* → **CloudWatch Alarm + ASG**
- *"alarm on memory or disk usage"* → **CloudWatch Agent** (default metrics don't include these)
- *"need 1-minute autoscaling granularity"* → **Detailed Monitoring**
- *"sub-minute custom metrics"* → **High-resolution custom metrics**
- *"query logs with SQL-like syntax, occasionally"* → **Logs Insights**
- *"ship logs to a SIEM / analytics destination"* → **Subscription filter → Kinesis / Lambda / OpenSearch / Firehose**
- *"periodically test that our API endpoint is up"* → **CloudWatch Synthetics canaries**
- *"frontend performance monitoring from real users"* → **CloudWatch RUM**
- *"ML-based anomaly detection on a metric"* → **CloudWatch Anomaly Detection**
- *"combine multiple alarms with AND/OR to reduce noise"* → **Composite Alarms**
- *"auto-collect ECS/EKS container metrics"* → **Container Insights**
- *"single dashboard combining metrics + traces"* → **ServiceLens**
- *"top-N contributors (top users / IPs / errors)"* → **Contributor Insights**

**The 80/20:** *CloudWatch = metrics + logs + alarms + dashboards. Three exam traps: (1) **memory/disk need the CloudWatch Agent**; (2) **basic monitoring is 5-min** — enable Detailed for 1-min; (3) **logs never expire by default** — set retention. Logs Insights for ad-hoc log queries; OpenSearch when log analytics is constant. Alarms drive ASG, SNS, Lambda. CloudWatch Synthetics for endpoint canaries, RUM for frontend, ServiceLens for traces.*

## AWS CloudTrail

**Anchored against CloudWatch.** CloudWatch tells you *"how is my system performing?"* (metrics, logs, alarms). **CloudTrail tells you *"who did what to my AWS account?"*** — every AWS API call across every service, recorded with caller identity, source IP, timestamp, and parameters. Foundational for audit, compliance, and security forensics. Enabled by default for the last 90 days (Event History), with optional Trails for long-term + advanced features.

Mental model: CloudTrail is the `access.log` of the AWS **control plane** — instead of HTTP requests, it records API calls against AWS itself. Source of truth for *"who did this?"* — security forensics, compliance (SOC2, PCI, HIPAA), change tracking.

### What CloudTrail is NOT

The exam loves to swap CloudTrail in where a different observability service belongs. The vocabulary ("logs", "monitoring", "audit") overlaps but the services don't.

| Question | Service | Not CloudTrail because... |
| -------- | ------- | ------------------------- |
| *"My app threw a 500 — what did it log?"* | **CloudWatch Logs** | App stdout/stderr is not an AWS API call |
| *"Is CPU above 80%?"* | **CloudWatch Metrics + Alarms** | Performance telemetry, not API audit |
| *"What does this resource look like now, and how has its config changed over time?"* | **AWS Config** | Config tracks *resource state*; CloudTrail tracks *the API call that changed it* |
| *"Trace a request across microservices"* | **X-Ray** | Distributed tracing of app calls, not AWS API calls |
| *"Who accessed this S3 object?"* | **S3 server access logs** OR **CloudTrail data events** | CloudTrail only logs S3 object access if **data events are explicitly enabled** (off by default) |

**Three-way split worth memorising:**

| Question | Service |
| -------- | ------- |
| Who did what to AWS? | **CloudTrail** |
| How is it performing? | **CloudWatch** |
| What is the current/historical resource config? | **AWS Config** |

### Main Part vs the Extras

CloudTrail's surface area is wide, but the **core is small**. Most "CloudTrail" exam questions are really about management events; everything else is opt-in. Use this hierarchy to triage what the question is actually asking.

| Tier | Feature | What it is | Default? | Cost |
| ---- | ------- | ---------- | -------- | ---- |
| **🟢 The core** | **Management events** | Every control-plane API call (CreateInstance, AttachPolicy, ConsoleLogin, DeleteBucket). **This *is* CloudTrail.** | ✅ Always on — 90 days free in Event History | Free for first trail |
| **🟡 The audit setup** | **A Trail to S3** | What you create when you want real audit: long-term retention, multi-region, organization-wide, log file integrity validation, delivery to a dedicated log-archive account | ❌ You configure | S3 storage |
| **🔵 Opt-in extras** | **Data events** | High-volume data-plane events: S3 GetObject/PutObject, Lambda Invoke, DynamoDB item ops | ❌ Off | ~$0.10 per 100k events |
| **🔵 Opt-in extras** | **Insights events** | ML anomaly detection on API call *rates* (e.g. burst of TerminateInstances at 3am) | ❌ Off | Premium per-event |
| **🔵 Opt-in extras** | **CloudTrail Lake** | Managed event data store, query with SQL. Alternative to "Trail → S3 → Athena". 7+ year retention | ❌ Separate offering | Per ingested event + retention |

**Mnemonic:** *"CloudTrail" = management events. Everything else is optional.*

If a question doesn't mention "data events", "Insights", or "Lake", it's about the core: **management-event recording delivered to a trail.**

**Where Insights fits — and where it doesn't.** Insights is the smallest tier by real-world usage. Most production setups don't enable it because:
- It costs extra per analysed event
- It generates false positives (legitimate batch jobs look anomalous)
- Many orgs use **GuardDuty** for threat/anomaly detection instead (GuardDuty itself consumes CloudTrail under the hood)

So if an exam question asks about *detecting unusual API patterns specifically using CloudTrail*, the answer is Insights. If the question is more general ("detect suspicious activity"), **GuardDuty** is often the better answer.

### What CloudTrail Records

Every interaction with AWS APIs — whether through:
- AWS Console (rendered as the underlying API call)
- AWS CLI / SDK calls
- Other AWS services calling each other
- IAM role assumptions

```
Example event:
{
  "eventTime":     "2026-05-26T10:23:14Z",
  "eventName":     "DeleteBucket",
  "eventSource":   "s3.amazonaws.com",
  "userIdentity":  { "userName": "alice", "accountId": "...", "arn": "..." },
  "sourceIPAddress": "203.0.113.42",
  "requestParameters": { "bucketName": "prod-data" },
  "responseElements":  { ... }
}
```

### Three Event Types (each tested)

| Event type | What it captures | Default? | Cost |
| ---------- | ---------------- | -------- | ---- |
| **Management events** | Control-plane operations — CreateInstance, AttachPolicy, ConsoleLogin, DeleteBucket | **On by default** in Event History (90 days) | First trail's management events free; additional trails charged |
| **Data events** | High-volume data-plane — **S3 GetObject / PutObject**, **Lambda Invoke**, DynamoDB item-level | **Off by default** — opt in per resource | Charged per event (~$0.10 per 100k events) |
| **Insights events** | ML-detected unusual API patterns (e.g. burst of TerminateInstances) | Opt-in | Per analysed event |

**Exam trap:** the default trail captures management events only. *"Why didn't CloudTrail log S3 GetObject?"* → **data events weren't enabled**.

### Event History vs Trails

| | Event History (default) | Trail (you create) |
| - | ----------------------- | ------------------ |
| Always on | ✅ — every account, automatically | ❌ — you configure |
| Retention | **90 days** | Indefinite (S3) |
| Cost | Free | S3 storage + per-event |
| Search | Web console + CLI lookup | S3 + Athena / CloudWatch Logs / CloudTrail Lake |
| Data events | ❌ Management only | ✅ If enabled |
| Multi-region | View only | ✅ Single trail across all regions |
| Multi-account | ❌ | ✅ **Organization trail** captures all accounts |

For real audit + compliance you always create a **Trail** (with logs delivered to S3); Event History is just the "what just happened?" web view.

### Standard Architecture (the exam-favourite pattern)

```
All AWS API calls (every region, every account)
       ↓
CloudTrail (multi-region, organization-wide)
       ↓
  ┌────┴────┐
  ▼         ▼
  S3 bucket            CloudWatch Logs (optional)
  (centralised audit         ↓
   log archive in a    Metric Filter on suspicious patterns
   dedicated security  (e.g. RootAccountUsage, DeleteBucket)
   account)                  ↓
  + S3 Object Lock      CloudWatch Alarm → SNS → Slack/PagerDuty
  + Log File Integrity
    Validation
       ↓
  Athena queries       EventBridge rule on CloudTrail event
  (audit on demand)    (e.g. AssumeRole from unexpected IP)
                            ↓
                       Lambda for automated response
```

### Key Features (each shows up on the exam)

**Multi-region trail** — one trail covers events from all regions. Without this, a global account would need a trail per region.

**Organization trail** — created in the AWS Organizations management account; **captures events from every member account** in a single trail. Member accounts cannot disable or modify it. The standard answer for centralised audit in multi-account architectures.

**Log file integrity validation** — CloudTrail can produce a **digest file** signed with SHA-256 every hour, listing the hashes of log files delivered. Lets you prove logs haven't been tampered with — required for many compliance regimes.

**Cross-account log delivery** — deliver trails from many accounts into a **dedicated security/log archive account's S3 bucket**. Combine with **S3 Object Lock** and bucket policy restrictions to prevent even admins in the source account from tampering.

**CloudTrail Lake** — a fully managed event data store you can **query with SQL** (no S3 + Athena setup). Retention up to 7+ years. Replacement for "trail to S3 → Glue Crawler → Athena" if you want it pre-built.

**CloudTrail Insights** — automatically detect unusual API call patterns. *"Why did `TerminateInstances` spike 10x at 3am?"* → Insights fires an event you can react to via EventBridge.

### CloudTrail + CloudWatch + EventBridge (the trio in action)

These three services compose into AWS's audit-and-react foundation:

```
CloudTrail records the API call
  ↓
delivered to CloudWatch Logs (optional)
  ↓ Metric Filter on suspicious patterns
CloudWatch Alarm → SNS → Slack/PagerDuty (slow path — minutes)

OR

CloudTrail event → EventBridge rule (real-time — seconds)
  ↓
Lambda / Step Functions / SSM Automation (auto-response)
```

**Examples:**
- *"Alert when root account is used"* → CloudTrail → CloudWatch Logs Metric Filter on `userIdentity.type = "Root"` → Alarm → SNS
- *"Auto-revoke access keys when leaked detection fires"* → CloudTrail Insights event → EventBridge → Lambda calls `DeleteAccessKey`
- *"Detect IAM policy attachments to a privileged role"* → EventBridge rule on `AttachRolePolicy` to that role → Lambda audits and pages security

### Common Anti-patterns (exam wrong answers)

- **"Why didn't CloudTrail log S3 GetObject?"** → S3 data events were not enabled (management-only by default)
- **Single-region trail in a global account** → enable **multi-region trail** (one trail, all regions)
- **Each account has its own trail, audit is fragmented** → create an **organization trail** in the management account; all members reported into one trail
- **Trail logs sit in the source account, where bad actors could delete them** → deliver to a **dedicated log-archive account** with S3 Object Lock + restrictive bucket policy
- **No log file integrity validation enabled** → can't prove logs weren't tampered with; compliance requires it
- **Hunting for events by ad-hoc S3 + Athena every time** → consider **CloudTrail Lake** for native SQL on events
- **Using CloudTrail for application logs** — wrong layer. CloudTrail is for AWS API calls; app logs go to **CloudWatch Logs**
- **Using CloudWatch Logs to audit "who did what in AWS"** — wrong direction. **CloudTrail** is the audit source

### Exam Triggers

- *"audit who made which AWS API calls"* → **CloudTrail**
- *"who deleted this resource?"* → **CloudTrail Event History** (last 90 days) or Trail in S3 (longer)
- *"log every S3 GetObject for compliance"* → **CloudTrail data events** (must opt in)
- *"detect unusual API patterns (TerminateInstances spike)"* → **CloudTrail Insights**
- *"centralise audit logs from all AWS Organizations accounts into one place"* → **Organization trail** delivered to a security account's S3
- *"tamper-proof audit logs"* → **CloudTrail log file integrity validation** + **S3 Object Lock**
- *"query CloudTrail events with SQL natively"* → **CloudTrail Lake** (no S3 + Athena setup)
- *"real-time reaction to a suspicious API call"* → **CloudTrail event → EventBridge → Lambda**
- *"alarm on root account usage"* → **CloudTrail → CloudWatch Logs → Metric Filter → Alarm**
- *"prevent member accounts from disabling audit logging"* → **Organization trail** (members can't modify it)
- *"retain audit logs for 7 years"* → **CloudTrail Lake** (built-in long retention) or **Trail to S3 with Glacier lifecycle**

**The 80/20:** *CloudTrail = audit log of every AWS API call. Three event types: **management** (free, default-on), **data** (opt-in, S3/Lambda/DynamoDB high-volume), **Insights** (anomaly detection). For real audit always create a **multi-region organization trail** delivered to a **dedicated log-archive account's S3 bucket** with **log file integrity validation**. Pairs with CloudWatch (alarm via Metric Filter on log patterns) and EventBridge (real-time reaction to specific events). For SQL-native event queries, use **CloudTrail Lake** instead of S3 + Athena.*

## AWS Config

**Anchored against CloudTrail.** CloudTrail records *the API call* (who, when, what was invoked). **AWS Config records *the resource state* that resulted** — and tracks how that state changes over time. If CloudTrail is the `access.log`, Config is `git log` for your AWS resources: every change produces a new versioned snapshot you can diff.

Foundational for **compliance, configuration drift detection, and "what did this resource look like last Tuesday?"** questions.

### What AWS Config is NOT

| Question | Service | Not Config because... |
| -------- | ------- | --------------------- |
| *"Who deleted the bucket?"* | **CloudTrail** | Config sees the state change, not the API caller's identity (though it links to the CloudTrail event) |
| *"Is CPU above 80%?"* | **CloudWatch** | Performance telemetry, not resource configuration |
| *"Prevent non-compliant resources from being created in the first place"* | **SCPs / IAM / permissions boundaries / CloudFormation Guard** | Standard Config Rules are **detective** (flag after the fact); for prevention use policies. (Config does now have proactive rules for some resource types via CFN hooks.) |
| *"Detect a public S3 bucket"* — one-off | **IAM Access Analyzer** | Access Analyzer is purpose-built for resource-policy exposure; Config Rules are the general-purpose compliance engine |
| *"Inventory of all my EC2 instances"* | **AWS Systems Manager Inventory** OR **Config** | Both work; SSM goes deeper into OS-level inventory (installed packages); Config is broader across all AWS resource types |

**Three-way split (carried over from CloudTrail section):**

| Question | Service |
| -------- | ------- |
| Who did what to AWS? | **CloudTrail** |
| How is it performing? | **CloudWatch** |
| What is the current/historical resource config? | **AWS Config** |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Configuration Item (CI)** | A point-in-time JSON snapshot of a single resource (e.g. an EC2 instance, an S3 bucket, a security group). Created every time the resource changes. |
| **Configuration history** | The timeline of CIs for a resource — *"how has this security group changed over the last 6 months?"* |
| **Configuration snapshot** | Point-in-time export of all recorded resources in the account — delivered to S3 on a schedule |
| **Config Rule** | A desired-state check evaluated against CIs. Returns **compliant** or **non-compliant**. AWS-managed (200+ pre-built) or custom (Lambda / CloudFormation Guard) |
| **Conformance pack** | A bundle of rules + remediation, deployable as one unit (e.g. PCI-DSS pack, HIPAA pack, Operational Best Practices pack) |
| **Remediation action** | An **SSM Automation document** that runs when a rule fires — manual or automatic. E.g. *"if an EBS volume is unencrypted, snapshot + recreate encrypted"* |
| **Aggregator** | Multi-account, multi-region view. One central account sees compliance state across the whole org |

### Worked Example: "No S3 bucket should ever be public"

The simplest end-to-end Config story — one rule, one violation, one auto-fix.

**The goal:** never let a public S3 bucket appear in your account. (The thing behind every "company X leaks 10M records via misconfigured S3 bucket" headline.)

**Step 1 — Enable the rule (one click).** AWS ships a managed rule called **`s3-bucket-public-read-prohibited`**. You enable it. No code.

**Step 2 — Someone screws up.** A developer debugging a new bucket runs:

```bash
aws s3api put-bucket-acl --bucket marketing-assets --acl public-read
```

**Step 3 — Config catches it automatically.** Within minutes:

1. Config records a new **CI** (Configuration Item — a JSON snapshot of the bucket's state) showing the public ACL
2. The rule re-evaluates the new CI → **`NON_COMPLIANT`**
3. The Config dashboard flags `marketing-assets` red
4. An **EventBridge event** fires because compliance state flipped

**Step 4 — React (two options):**

```
Option A — just alert:
EventBridge → SNS → Slack #security
"🚨 marketing-assets is publicly readable. Compliance failed at 14:07."

Option B — auto-fix:
EventBridge → SSM Automation → aws s3api put-bucket-acl --acl private
"Auto-remediated: marketing-assets ACL reverted to private at 14:07."
```

**Why this is useful — what you'd have to build without Config:**
- A Lambda that scans every bucket on a schedule (every minute? hour? expensive either way)
- Pagination, error handling, IAM permissions, retries
- Your own dashboard for compliance status
- Your own history tracking

**With Config:** one checkbox enables the rule, it evaluates the moment a bucket changes (not on a poll), and dashboard + history + EventBridge come free.

**The pattern, generalised:**

```
1. Pick a rule (managed or custom): "X must be true of resource Y"
2. Enable it
3. Wait for a violation
4. Either alert (SNS) or fix (SSM Automation)
```

Repeat for every guardrail you care about: *no unencrypted EBS, no SG open to 0.0.0.0/0 on port 22, every resource must have an `Owner` tag, no IAM user without MFA.* Config has managed rules for all of these out of the box.

### Standard Architecture

```
Resource change (e.g. SG ingress rule modified)
       ↓
AWS Config records a Configuration Item (CI)
       ↓
  ┌────┴────────────────────────┐
  ▼                             ▼
Configuration history       Config Rules evaluated
(S3 + queryable via         (AWS-managed or custom Lambda)
 Config Advanced Query)             ↓
                            Compliant / Non-compliant
                                    ↓
                          ┌─────────┴─────────┐
                          ▼                   ▼
                  EventBridge event     Auto-remediation
                  (compliance change)   (SSM Automation doc)
                          ↓
                  Lambda / SNS / Slack
                  (alert security team)

Across many accounts → Config Aggregator (single dashboard)
```

### Config + CloudTrail (the audit pair)

These two are almost always tested together because they answer different halves of the same question:

```
"Why is this security group suddenly open to 0.0.0.0/0?"

CloudTrail → AuthorizeSecurityGroupIngress called at 14:03 by user "bob"
                                  ↓
AWS Config → SG configuration changed at 14:03; new CI shows 0.0.0.0/0 rule
                                  ↓
        Config Rule "restricted-ssh" flips to NON_COMPLIANT
                                  ↓
        Auto-remediation: SSM Automation removes the rule
```

**Mnemonic:** *CloudTrail = the action. Config = the consequence.*

### Pricing — Why It Matters on the Exam

Config bills **per Configuration Item recorded** and **per rule evaluation**. Two traps:

1. **Recording all resource types in all regions** — expensive in a busy account. The fix: scope recording to the resource types you actually care about, or to the regions you use.
2. **Continuous recording vs daily recording** — Config now offers a cheaper daily-recording mode for resources that don't need real-time tracking.

### Privileges — Who Needs What

Config's IAM story has three distinct layers. Conflating them is a common exam trap (and a real-world security mistake).

| Layer | Who/what | Privilege | Why |
| ----- | -------- | --------- | --- |
| **Enabling Config** | Cloud/platform admin (one-time) | **High** — `config:PutConfigurationRecorder`, `iam:PassRole`, create service-linked role | Setup is a privileged action; not an app-team job |
| **Config service-linked role** (`AWSServiceRoleForConfig`) | The Config service itself | **Very broad read** — `Describe*`/`Get*`/`List*` across nearly every resource type | Read-only, but sees everything — required to record CIs. Cannot modify resources |
| **Viewing compliance** (consumer) | Auditors, engineers, dashboards | **Low** — `config:Get*`, `config:Describe*`, `config:Select*` | Safe to grant widely; common pattern for `SecurityAuditor` roles via an **Aggregator** |
| **Custom Config Rule author** | Engineer writing a rule | **Medium** — `lambda:CreateFunction` + `iam:PassRole` for the rule's Lambda execution role | Rule's Lambda only needs read on the resource type it evaluates |
| **Remediation actions** ← *the dangerous one* | SSM Automation execution role | **HIGH WRITE** — e.g. `s3:PutBucketPolicy`, `ec2:RevokeSecurityGroupIngress`, `kms:CreateKey` | This is where blast radius lives. Auto-remediation must write to AWS. Scope tightly to exact resource ARNs / conditions |

**Mental model:**

```
Setup        →  high privilege  (admin, one-time)
Recording    →  broad read      (service-linked role; safe)
Viewing      →  low privilege   (grant widely)
Remediation  →  HIGH WRITE      ← scrutinise this
```

**Exam framing:** *least privilege* in AWS Config usually means **locking down the remediation role**, not the recording role (which is intentionally broad and read-only).

### Common Anti-patterns (exam wrong answers)

- *"Who deleted this resource?"* → **CloudTrail**, not Config. Config shows the resource disappeared; CloudTrail shows who called the delete API
- *"Prevent the creation of unencrypted EBS volumes"* → **SCP / permission boundary / proactive control**, not a standard Config Rule (which is detective — fires after creation)
- *"Real-time performance dashboards"* → **CloudWatch**, not Config (Config tracks configuration, not performance)
- *"Use Config to inventory installed OS packages"* → **SSM Inventory** is the right tool; Config is AWS-resource-level
- *"Centralised compliance dashboard across 200 accounts"* → **Config Aggregator** in a security/audit account (don't try to log in to each account)
- *"Bundle of HIPAA / PCI / NIST rules"* → **Conformance pack**, not "write 40 individual Config Rules"
- *"Auto-fix the violation"* → **Config Rule + Remediation action (SSM Automation)**, not a hand-rolled Lambda triggered ad-hoc
- *"Detect S3 bucket made public"* — both **Config Rule** (`s3-bucket-public-read-prohibited`) and **IAM Access Analyzer** are valid; the exam often prefers the more specific Access Analyzer answer for resource-policy exposure

### Exam Triggers

- *"Track how a resource's configuration changed over time"* → **AWS Config — configuration history**
- *"Ensure all EBS volumes are encrypted (detect-and-flag)"* → **Config Rule** (e.g. `encrypted-volumes`)
- *"Auto-remediate non-compliant resources"* → **Config Rule + SSM Automation document**
- *"Bundle of pre-built compliance rules for HIPAA / PCI / NIST"* → **Conformance pack**
- *"Compliance dashboard across all AWS Organizations accounts"* → **Config Aggregator**
- *"Custom compliance check not covered by managed rules"* → **Custom Config Rule** backed by Lambda or CloudFormation Guard
- *"Detect configuration drift from a baseline"* → **AWS Config** (its core use case)
- *"React in real time when a resource becomes non-compliant"* → **Config compliance-change event → EventBridge → Lambda / SNS**
- *"Combine 'who did it' with 'what changed'"* → **CloudTrail + Config together**
- *"Reduce Config cost in a noisy account"* → scope recorded resource types, exclude unused regions, switch to **daily recording** for low-churn resources

**The 80/20:** *AWS Config = `git log` for AWS resource state. Records a **Configuration Item** every time a resource changes, evaluates **Config Rules** (managed or custom) for compliance, and can **auto-remediate** via SSM Automation. Pairs with CloudTrail (CloudTrail = "who called the API"; Config = "how the resource state changed"). For multi-account compliance use an **Aggregator**; for compliance bundles use a **Conformance pack**. Watch for the detective-vs-preventive distinction — Config flags violations, **SCPs / IAM / permission boundaries** prevent them.*

## AWS Organizations

**Anchored against GitHub Organizations / Active Directory OUs.** One company → many AWS accounts (prod, dev, sandbox, security, log-archive) grouped into a hierarchy with central governance and one consolidated bill. Above ~5 accounts, managing them individually breaks down — Organizations is how you scale.

Two killer features: **consolidated billing** (one invoice, volume discounts pooled, RIs/Savings Plans shared) and **Service Control Policies (SCPs)** — deny-only guardrails that bound what IAM in member accounts can do, even for the root user.

### What AWS Organizations is NOT

| Question | Service | Not Organizations because... |
| -------- | ------- | ---------------------------- |
| *"Grant a user permissions to do X"* | **IAM** | SCPs don't grant — only restrict the *ceiling* of what IAM grants |
| *"Single sign-on across accounts"* | **IAM Identity Center** (formerly AWS SSO) | Organizations is the substrate; Identity Center sits on top for federated login |
| *"Set up a multi-account landing zone with best practices"* | **AWS Control Tower** | Control Tower is the opinionated wizard built *on top of* Organizations |
| *"Active Directory for AWS"* | **AWS Managed Microsoft AD** | Directory service for Windows / domain-joined resources; different layer entirely |
| *"Group IAM users together"* | **IAM Groups** | IAM Groups live inside *one* account; Organizations groups *accounts* themselves |
| *"Cross-account resource sharing"* | **AWS Resource Access Manager (RAM)** | RAM shares specific resources (subnets, TGWs, Resolver rules) across accounts |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Management account** (was "master") | The root account that creates the org. **Pays the bill.** Cannot have SCPs applied to it (it's intentionally outside guardrails) |
| **Member account** | Any AWS account that's part of the org |
| **Root** | The top of the OU hierarchy — *one per org*. Don't confuse with the "root user" of an account |
| **Organizational Unit (OU)** | A folder of accounts; can nest up to 5 levels deep. Apply policies at OU level for inheritance |
| **Service Control Policy (SCP)** | A **deny-only** policy that bounds what IAM can do in member accounts. Attached to root, OUs, or individual accounts |
| **Delegated administrator** | A member account given admin rights for a specific service (GuardDuty, Security Hub, Config) without granting it management-account power |

### Standard Multi-Account Topology

```
Root
├── Security OU
│   ├── log-archive account     (centralised CloudTrail/Config logs, write-once, Object Lock)
│   └── audit account           (read-only across the org for security team)
├── Infrastructure OU
│   └── shared-services account (DNS, networking, AMIs, build pipelines)
├── Workloads OU
│   ├── Prod OU
│   │   ├── prod-app-1
│   │   └── prod-app-2
│   └── Non-prod OU
│       ├── staging
│       └── dev
└── Sandbox OU
    └── sandbox-* (one per engineer)
```

Each leaf is its own AWS account. SCPs at the OU level enforce *"prod accounts can't disable CloudTrail"*, *"sandbox accounts can't use anything outside `eu-west-1`"*, *"only the security account can write to the log-archive bucket"*, etc.

### Consolidated Billing — the Money Bit

- One invoice for the whole org
- **Volume discounts pool** across accounts — tier-based pricing on S3, data transfer, etc. (you cross volume tiers faster by aggregating usage)
- **Reserved Instances + Savings Plans share** across accounts by default (a sandbox account benefits from a prod-account RI's unused capacity)
- Per-account or per-tag cost allocation reports via **AWS Cost Explorer**
- The management account is the payer; member accounts see usage but not the consolidated invoice

**Exam trap:** *"How do I get the volume discount across all my accounts without managing them centrally?"* — you can't. Consolidated billing requires Organizations.

### SCPs (Service Control Policies) — Deep Dive

SCPs are the governance hammer. They define the **maximum** permissions for an account, regardless of what IAM policies grant. Key properties:

| Property | Detail |
| -------- | ------ |
| **Effect** | Can only **Deny** in practice — they bound the ceiling. (Technically you can use `Allow` in allow-list mode but the default is deny-list.) |
| **Applies to** | Root, OUs, or individual accounts. **Inherited down** the OU tree (an account is bounded by every SCP from root → its OU → itself) |
| **Affects** | **All IAM principals** (users, roles, federated identities) AND the **root user** of member accounts |
| **Does NOT affect** | The management account (excluded by design — don't even try) |
| **Cannot grant** | Only restrict. Without an IAM policy granting the action, the user still can't do it |

#### Deny-list vs Allow-list strategies

Two competing patterns — the exam loves this distinction:

| Strategy | How it works | When to use |
| -------- | ------------ | ----------- |
| **Deny-list** (default) | Default `FullAWSAccess` policy is attached at root; you add SCPs that *deny* specific actions | Start permissive, lock down the dangerous stuff. Easier; what most orgs run |
| **Allow-list** | Remove `FullAWSAccess`; explicitly `Allow` only certain services/actions | Maximum lockdown — e.g. a regulated workload OU that only needs S3 + Lambda + DynamoDB. Brittle: any new service is blocked until you add it |

#### Classic SCP example — region lockdown

```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:RequestedRegion": ["eu-west-1", "us-east-1"] }
  }
}
```

Now nothing in those accounts — IAM user, role, or root — can spin up resources outside those two regions. The bluntest instrument in AWS governance.

#### Worked Example: "Only audited services in prod, freely experiment in dev"

A classic regulated-industry scenario (fintech, healthcare, public sector). The audit team has approved a specific list of AWS services for production use. New services can only be used in prod once they clear audit. Meanwhile, developers should be free to experiment with anything in dev.

**The pattern:**

```
Prod OU      →  allow-list SCP (remove FullAWSAccess, allow only audited services)
                + companion deny-list SCP (block dangerous actions within allowed services)
                + region lockdown SCP
Dev OU       →  default FullAWSAccess (no restrictions — experimentation encouraged)
```

When a new service like Bedrock launches, prod accounts cannot use it until the security team audits it and adds it to the prod SCP allow-list. Dev accounts can use it immediately.

**SCP 1 — the audited-services allow-list (attached to Prod OU, with `FullAWSAccess` removed):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowAuditedServicesOnly",
    "Effect": "Allow",
    "Resource": "*",
    "Action": [
      "ec2:*", "autoscaling:*", "elasticloadbalancing:*",
      "ecs:*", "ecr:*", "eks:*",
      "lambda:*",
      "s3:*", "ebs:*", "efs:*",
      "rds:*", "dynamodb:*", "elasticache:*",
      "vpc:*", "route53:*", "cloudfront:*", "apigateway:*",
      "iam:*", "sts:*", "kms:*", "secretsmanager:*", "acm:*",
      "cloudwatch:*", "logs:*", "cloudtrail:*", "xray:*", "events:*",
      "sqs:*", "sns:*", "kinesis:*", "firehose:*",
      "cloudformation:*", "ssm:*",
      "codebuild:*", "codepipeline:*", "codedeploy:*",
      "backup:*", "config:*",
      "support:*", "tag:*", "resource-groups:*"
    ]
  }]
}
```

Anything not on the list — Bedrock, QLDB, Managed Blockchain, GameLift, IoT services, brand-new previews — is implicitly denied at the SCP layer. Even an account admin can't bypass it.

**SCP 2 — companion deny-list for dangerous actions within allowed services:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyTamperingWithAuditLogs",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
        "config:DeleteConfigurationRecorder", "config:StopConfigurationRecorder",
        "config:DeleteDeliveryChannel"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDangerousKMS",
      "Effect": "Deny",
      "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
      "Resource": "*"
    },
    {
      "Sid": "DenyLeavingTheOrg",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "EnforceRegionLockdown",
      "Effect": "Deny",
      "NotAction": [
        "iam:*", "sts:*", "support:*", "organizations:*",
        "route53:*", "cloudfront:*", "waf:*", "globalaccelerator:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": { "aws:RequestedRegion": ["eu-west-1", "eu-west-2"] }
      }
    }
  ]
}
```

The region lockdown uses `NotAction` to exempt **global services** (IAM, STS, CloudFront, Route 53) — these don't have a region and would otherwise be blocked.

**Walking through scenarios — `bob` in a prod account vs `bob` in a dev account:**

| Action | Prod account | Dev account |
| ------ | ------------ | ----------- |
| `s3:PutObject` | ✅ Allowed (S3 in allow-list) | ✅ Allowed |
| `bedrock:InvokeModel` (not audited yet) | ❌ Blocked — Bedrock not in allow-list | ✅ Allowed |
| `cloudtrail:StopLogging` | ❌ Blocked by deny-list SCP | ✅ Allowed (no SCP restriction) |
| `s3:PutObject` in `us-east-1` | ❌ Blocked by region lockdown | ✅ Allowed (no region SCP in dev) |
| `iam:CreateUser` in `us-east-1` | ✅ Allowed — IAM is in `NotAction` exemption | ✅ Allowed |

**The practical workflow when a new service needs to go to prod:**

```
1. New service launches (e.g. Bedrock) OR team requests exception
       ↓
2. Compliance/security team reviews:
   - Data residency (where does data go?)
   - Encryption (at rest, in transit, customer-managed keys?)
   - Logging (CloudTrail data events available?)
   - Provider/sub-processor risk (Bedrock models from third parties)
       ↓
3. Decision recorded; ticket raised against the SCP repo
       ↓
4. PR adds the service to SCP 1's allow-list
       ↓
5. Code review, approval, merged
       ↓
6. Terraform / CloudFormation pipeline deploys updated SCP
       ↓
7. Prod accounts can now use the service immediately
```

**The SCP is the audit gate** — services literally cannot be used in prod until they pass through this repo's PR review.

**Why this works where IAM doesn't:**

1. **Defence against escalation** — a developer with `iam:*` could grant themselves more permissions, but SCPs cap what IAM can grant
2. **Defence against the root user** — root ignores IAM but is bound by SCPs
3. **Applies to every principal** in every account in the OU — set once, applies to all
4. **Cannot be modified from the member account** — only the org management account can change SCPs, so a compromised prod account can't lift restrictions

**SCP gotchas to know:**

- **Size limit:** 5,120 characters per SCP, max 5 SCPs per entity. Real orgs hit this — they split into multiple SCPs (allow-list, deny-list, region lockdown)
- **`FullAWSAccess` must be removed** from the OU for allow-list mode to work; otherwise the SCP layer remains open
- **Test SCPs in a dev OU first** — a misconfigured allow-list can lock everyone out of prod
- **Don't forget global services** in region lockdown — use `NotAction` for IAM, STS, CloudFront, Route 53, etc.

#### How real orgs maintain the allow-list

**There is no AWS-provided file that maps service-name → "audited / approved".** It's a per-company decision. But AWS ships two artifacts that feed into the process:

| AWS resource | What it gives you | What it's NOT |
| ------------ | ----------------- | ------------- |
| **AWS Services in Scope by Compliance Program** (`aws.amazon.com/compliance/services-in-scope/`) | Published page mapping each AWS service to compliance programs it's certified under: SOC 1/2/3, PCI-DSS, HIPAA, FedRAMP, ISO 27001, IRAP, etc. **The starting point for any allow-list.** | Not a policy file — you read it and decide |
| **AWS Artifact** | The AWS service where you download the actual SOC / PCI / ISO audit reports for use in your own audits | Not a service-allow-list either |
| **AWS Config conformance packs** | Pre-built bundles of compliance rules (HIPAA, PCI, NIST). Detective, not preventive. | Doesn't gate service usage; flags non-compliant resources |
| **AWS Service Catalog** | Vend approved *products* (e.g. "the only RDS pattern you can deploy") — complements SCPs | Higher-level than SCPs; doesn't replace them |

**The typical workflow:**

```
1. Compliance team reads "Services in Scope" page
       ↓
2. Cross-references against your org's required certifications
   (e.g. PCI-DSS + HIPAA for healthtech)
       ↓
3. Maintains an internal manifest of "services we've reviewed + approved for prod"
       ↓
4. That manifest drives the SCP allow-list (often via codegen)
```

**Repo structure most orgs use:**

```
scp-policies/
├── audited-services.yaml          ← source-of-truth manifest
├── policies/
│   ├── prod-allow-list.json       ← generated from manifest
│   ├── prod-deny-list.json
│   ├── prod-region-lockdown.json
│   └── dev-permissive.json
├── terraform/
│   └── attach-scps.tf
└── docs/
    └── service-approval-process.md
```

**Example `audited-services.yaml`** — captures *why* a service is approved, not just *that* it is:

```yaml
services:
  - service: s3
    actions: ["s3:*"]
    approved_date: 2024-03-15
    approved_by: compliance@example.com
    audit_ticket: SEC-1247
    compliance_certifications: [SOC2, PCI-DSS, HIPAA, ISO27001]
    conditions: |
      Must enable bucket encryption (KMS).
      Must enable Block Public Access at account level.
      Data-event logging required for buckets containing PHI.

  - service: bedrock
    actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    approved_date: 2026-04-02
    approved_by: compliance@example.com
    audit_ticket: SEC-2103
    compliance_certifications: [SOC2, HIPAA]
    conditions: |
      Only approved foundation models: Claude (Anthropic), Titan (AWS).
      Region restricted to us-east-1, eu-west-1 (data residency).
      No PHI in prompts without HIPAA BAA review.
    excluded_actions: ["bedrock:CreateModelCustomizationJob"]

  - service: qldb
    status: NOT_APPROVED
    reason: "Compliance burden vs benefit not justified"
```

A pipeline reads the manifest → generates the SCP JSON → applies via Terraform/CloudFormation.

**Why a YAML manifest instead of editing the SCP JSON directly:**

1. **Auditor-friendly** — the YAML has reasoning, dates, approvers, conditions. The generated JSON is just `Allow: [...]` with no context
2. **Git history is the audit trail** — every change shows who approved what, when, with what justification
3. **One source feeds multiple outputs** — same manifest can generate SCP, Config rules, IAM permissions boundaries, Service Catalog products
4. **Conditions are documented** — *"S3 approved but requires bucket encryption"* lives next to the service, so deployers know the constraints

**The three layers most regulated orgs run:**

```
Layer 1 — Manifest (YAML)
   "Here are the services we've reviewed + approved, with conditions"
        ↓ (codegen)
Layer 2 — SCPs
   "Hard gate at the AWS API layer — services not in the list cannot be called"
        ↓ (parallel control)
Layer 3 — Service Catalog products
   "Pre-built blessed deployments — one-click launch with required
    encryption/tagging/networking already configured"
```

SCPs are the *deny-by-default* outer wall. **Service Catalog is the paved road inside it** that makes the right thing easy for developers.

**Exam framing:** if a question asks *"how do you ensure only audited services are used in production?"* → **SCP allow-list at the OU level**. If it asks *"how do you give developers a self-service way to deploy approved patterns?"* → **AWS Service Catalog**. Both together = the complete answer for regulated orgs.

#### Other SCPs every multi-account org runs

- *"Member accounts can't disable CloudTrail / Config / GuardDuty"* — deny `cloudtrail:Stop*`, `cloudtrail:Delete*`, `config:Delete*`
- *"No one can leave the organization"* — deny `organizations:LeaveOrganization`
- *"Prod accounts can't create IAM users with console access"* — deny `iam:CreateLoginProfile`
- *"Sandbox accounts can only run small EC2 instances"* — deny `ec2:RunInstances` unless `ec2:InstanceType` matches an allow-list

### Three Policy Layers: Identity Policy vs SCP vs Permissions Boundary

Three layers that get confused constantly. **Identity policy grants. SCP and boundary restrict. SCPs are organisation-wide; boundaries are per-principal.**

| | **Identity-based policy** | **SCP** | **Permissions Boundary** |
| - | ------------------------- | ------- | ------------------------ |
| **Purpose** | **Grants** permissions | Caps what an account can do | Caps what one principal can do |
| **Grants?** | ✅ Yes (the only one that grants) | ❌ No — restricts only | ❌ No — restricts only |
| **Attaches to** | IAM user, group, role | Root, OU, or account | A single IAM user or role |
| **Scope** | The principal it's attached to | **Every** principal in the account(s) it covers | Just that one principal |
| **Affects root user?** | ❌ Root has implicit `*` | ✅ Yes — even root | ❌ No — only IAM users/roles |
| **Set by** | Account admin / developer | Org management account | Account admin |
| **Without it** | Principal can do nothing (deny-by-default at IAM) | Default `FullAWSAccess` SCP allows everything | Boundary is optional |

#### What each is for, in one line

- **Identity-based policy:** *"What CAN this user do?"* (the grant)
- **SCP:** *"What is the maximum any user — including root — in this account is allowed to do?"* (the org-level ceiling)
- **Permissions boundary:** *"What is the maximum THIS specific role is allowed to do, even if its IAM policy says more?"* (the per-principal ceiling)

#### Evaluation order when all three exist

```
Can this user do action X on resource Y?
        ↓
1. Is there an explicit Deny anywhere?                → ❌ BLOCKED
        ↓ (no)
2. Does the SCP allow X?                              → if no, ❌ BLOCKED
        ↓ (yes)
3. Does the Permissions Boundary allow X?             → if no, ❌ BLOCKED
        ↓ (yes)
4. Does the Identity policy (or resource policy)      → if no, ❌ BLOCKED
   explicitly Allow X?                                   (implicit deny)
        ↓ (yes)
                                                      → ✅ ALLOWED
```

**All three must say yes.** Any one saying no blocks the action. SCP and Boundary cap; Identity policy grants.

#### Worked example — developer `bob` who needs admin most of the time

```
Org SCP (attached to the developer's OU)
└── "Deny everything outside eu-west-1"           ← org-wide guardrail

Permissions Boundary (attached to bob's IAM user)
└── "Allow only s3:*, ec2:*, lambda:*, iam:Get*   ← bob-specific ceiling
     — deny anything tagged Environment=Production"

Identity policy (attached to bob's IAM user)
└── "AdministratorAccess"                         ← grants the actual permissions
```

`bob` tries to:

| Action | SCP | Boundary | Identity | Result |
| ------ | --- | -------- | -------- | ------ |
| Create EC2 in eu-west-1 (non-prod) | ✅ | ✅ | ✅ | ✅ Allowed |
| Create EC2 in us-east-1 | ❌ wrong region | ✅ | ✅ | ❌ **Blocked by SCP** |
| Delete an RDS instance | ✅ | ❌ not in boundary | ✅ | ❌ **Blocked by boundary** |
| Read a prod-tagged S3 bucket | ✅ | ❌ prod tag denied | ✅ | ❌ **Blocked by boundary** |
| Create an IAM user | ✅ | ❌ only `iam:Get*` | ✅ | ❌ **Blocked by boundary** |

The identity policy says "anything" — but the SCP and boundary together filter it down to a safe subset. Defence in depth.

#### Why three layers, not one

Each layer answers a different "who's in charge?" question:

| Layer | Owned by | Answers |
| ----- | -------- | ------- |
| **SCP** | Org admin (security team) | *"What can NO account in our org ever do?"* |
| **Permissions Boundary** | Account admin / platform team | *"This developer can manage their own IAM — but never escalate beyond this ceiling."* |
| **Identity policy** | Account admin / developer | *"Here are the permissions to actually do the job."* |

Boundaries shine in **delegated IAM** scenarios: *"I'll let developers create their own roles for their apps, but the roles can never be more powerful than this boundary."* Without boundaries, a developer with `iam:*` could create themselves an admin role and bypass everything.

#### Exam traps for the three layers

| Question setup | Trap | Right answer |
| -------------- | ---- | ------------ |
| "Limit a specific developer's max permissions, but they need to be admin sometimes" | "Use an SCP" | **Permissions boundary** — SCPs apply to *all* principals in the account |
| "Limit ALL users in an account, including root" | "Use a permissions boundary" | **SCP** — boundaries don't apply to root and only attach to one principal |
| "Developer has `iam:*` and shouldn't escalate privileges" | "Restrict their IAM policy" | **Permissions boundary** + condition requiring all roles they create attach the same boundary |
| "Why isn't the SCP affecting the management account?" | "Misconfigured" | Management account is **excluded** from SCPs by design |
| "User has admin identity policy but action denied" | "Re-add admin to IAM" | The cause is an SCP, boundary, or resource policy denying — IAM is fine |

### AWS Control Tower — the layer above Organizations

Organizations gives you the primitives (accounts, OUs, SCPs). **Control Tower** is the opinionated landing-zone builder on top. See the dedicated **[AWS Control Tower & Landing Zones](#aws-control-tower--landing-zones)** section below for the deep dive — including the overloaded "Landing Zone" terminology, guardrails, Account Factory flow, CfCT/AFT, and Landing Zone Accelerator (LZA).

### IAM Identity Center (formerly AWS SSO)

**Anchored against Okta or Azure AD's SSO portal — but AWS-native and free.** Sits on top of AWS Organizations and gives humans a single browser portal where they sign in once, pick which AWS account + role to assume, and get temporary STS credentials. No IAM users anywhere.

Was called **AWS SSO** until 2022. Exam questions still use both names interchangeably.

#### What it is NOT

| Question | Service | Not Identity Center because... |
| -------- | ------- | ------------------------------ |
| *"Manage app users (people signing up for our SaaS)"* | **Amazon Cognito** | Identity Center is for *workforce identity*; Cognito is for *customer identity* in your own apps |
| *"Active Directory for AWS workloads"* | **AWS Managed Microsoft AD** | Identity Center can *use* AD as an identity source, but isn't a directory service itself |
| *"Grant permissions"* | **IAM** (via permission sets that materialise as IAM roles) | Identity Center orchestrates; IAM still does the actual permission evaluation |
| *"Federated login for a single AWS account"* | **IAM Identity Provider** (SAML or OIDC) | Single-account federation works via IAM; Identity Center is the *multi-account* answer |
| *"Service-to-service auth"* | **IAM roles** | Identity Center is for human users, not services |

#### Core concepts

| Concept | What it is |
| ------- | ---------- |
| **Identity source** | Where users live: built-in Identity Center directory, external IdP (Okta / Entra ID / Google / Ping / OneLogin via SAML 2.0), or AWS Managed Microsoft AD / on-prem AD via AD Connector |
| **Users + Groups** | Managed in Identity Center, or synced from external IdP via **SCIM 2.0** (auto provision / deprovision) |
| **Permission Set** | Reusable bundle of policies (AWS-managed + customer-managed + inline + optional permissions boundary). E.g. `ReadOnlyAccess`, `BillingAdmin`, `DataScientist` |
| **Assignment** | Three-way join: *(user-or-group) × (permission set) × (account)*. "Alice gets BillingAdmin in finance account; dev-team group gets ReadOnly in all prod accounts" |
| **Application assignment** | The portal can also launch external SaaS apps (Salesforce, Slack, etc.) via SAML — Identity Center doubles as an enterprise SSO portal |
| **Start URL** | Unique URL of your Identity Center portal (e.g. `https://d-xxx.awsapps.com/start`) |

#### How a login actually flows

```
1. Alice opens https://d-xxx.awsapps.com/start
       ↓
2. Identity Center authenticates her
   (either against its own directory, or redirects to Okta/Entra ID)
       ↓
3. Alice sees a list of accounts she's assigned to,
   each with the permission sets she can use
       ↓
4. Alice clicks "prod-account" → "BillingAdmin"
       ↓
5. Identity Center calls STS to assume the corresponding IAM role
   (Identity Center auto-creates a role per permission set per account,
    named like `AWSReservedSSO_BillingAdmin_xxx`)
       ↓
6. Alice gets temporary STS credentials (1–12h, configurable)
       ↓
7. Console session opens in that account with those permissions
```

For CLI use: `aws configure sso` walks Alice through setup; `aws sso login` opens the browser, she authenticates, the CLI caches her temporary creds locally.

#### Permission Sets — the workhorse

- **Reusable across accounts** — define `DataScientist` once; assign to 12 accounts
- **Compose multiple policy types** — AWS-managed + customer-managed + inline + permissions boundary, all in one set
- **Materialised as IAM roles** in each target account when first assigned. Identity Center owns these roles (prefixed `AWSReservedSSO_`); don't edit them directly — your changes will be clobbered on next provisioning
- **Session duration** configurable per set (default 1h, max 12h)
- **MFA enforcement** configured at the Identity Center level — applies to every login

Common patterns:

```
ReadOnly                  → AWS managed: ReadOnlyAccess
BillingAdmin              → AWS managed: AWSBillingReadOnlyAccess + custom budget actions
PowerUser                 → AWS managed: PowerUserAccess (no IAM)
Admin-with-Boundary       → AdministratorAccess + permissions boundary
                            that denies prod-tagged resources
SecurityAuditor           → ReadOnlyAccess + SecurityAudit + IAMReadOnlyAccess
```

#### Identity source choices

| Source | When to use |
| ------ | ----------- |
| **Identity Center directory** (default) | Small org, no existing IdP, simplest setup |
| **External IdP via SAML 2.0 + SCIM 2.0** | You already use Okta / Entra ID / Google Workspace — **the normal enterprise answer** |
| **AWS Managed Microsoft AD or on-prem AD** | You're an AD shop and want AWS to follow AD group membership |

**Exam trigger:** *"users are in Okta — give them AWS console access"* → **Identity Center with Okta as SAML identity source + SCIM for sync**.

#### Replacing IAM users — the migration pattern

```
Before:
  account-1: IAM user "alice", "bob", "charlie"...
  account-2: IAM user "alice", "bob"...
  account-3: ...
  (30 accounts × N users = chaos. Access keys everywhere.)

After:
  IAM Identity Center (in management account)
  ├── Identity source: Okta (via SAML 2.0 + SCIM)
  ├── Permission sets: ReadOnly, PowerUser, Admin-with-Boundary
  └── Assignments:
        engineering group → PowerUser → all dev accounts
        sre group         → Admin-with-Boundary → prod accounts
        finance group     → BillingAdmin → finance account

  No IAM users. No access keys (CLI uses `aws sso login`).
  Offboarding = remove from Okta group; access disappears instantly.
```

#### Anti-patterns

- *"Use Cognito for AWS console access"* — wrong service; Cognito is for app users
- *"Have IAM users in each account because permissions are simpler that way"* — this is the legacy pattern Identity Center exists to replace
- *"Federate each account separately via IAM SAML provider"* — works but doesn't scale; Identity Center is multi-account-aware
- *"Create one giant `AdministratorAccess` permission set for everyone"* — defeats the purpose; combine with **permissions boundaries** or use scoped sets per role
- *"Edit the `AWSReservedSSO_*` roles directly in each account"* — Identity Center owns these; your edits get clobbered

#### Exam triggers

- *"Federated SSO across all AWS accounts in an org"* → **IAM Identity Center**
- *"Users currently have IAM users in 30 accounts, want to consolidate"* → **migrate to IAM Identity Center**
- *"Users live in Okta / Entra ID — give them AWS access"* → **Identity Center + that IdP as SAML source + SCIM 2.0 for auto-sync**
- *"Single sign-on for AWS Console AND third-party SaaS"* → **Identity Center application assignments**
- *"Replace static access keys for engineers using the CLI"* → **`aws configure sso` + `aws sso login`** (temporary STS creds)
- *"Auto-deprovision a leaver from all AWS accounts when they leave"* → **Identity Center + SCIM** (removal from IdP cascades)
- *"Centrally manage which permissions are available in each account"* → **permission sets**
- *"Different MFA / session durations per role"* → **per-permission-set configuration**

**Pricing:** Free from AWS's side. (Your IdP may charge per SAML app — that's an Okta/Entra ID concern.)

### Organization-Aware Services

| Service | What "organization-aware" enables |
| ------- | --------------------------------- |
| **CloudTrail** | **Organization trail** captures events across all member accounts (members can't disable it) |
| **AWS Config** | **Aggregator** pulls compliance state from every account into one dashboard |
| **GuardDuty** | Org-wide threat detection from a **delegated admin account** |
| **Security Hub** | Org-wide findings aggregation |
| **IAM Access Analyzer** | Org-scoped zone of trust — flags resources accessible from outside the org |
| **AWS Backup** | Centralised backup policies applied at OU level |
| **Resource Access Manager (RAM)** | Share subnets / TGWs / Resolver rules across accounts within the org |
| **Service Catalog** | Vend approved products across the org |
| **Cost & Billing** | Consolidated reports, per-account or per-tag breakdowns |

### Pricing

**AWS Organizations itself is free.** You pay for the underlying AWS usage in each member account. Control Tower is also free; you pay for the resources it creates (Config recorders, CloudTrail, etc.).

The cost reality: **Config + CloudTrail running across many accounts is where the bill grows** — see the Config pricing notes for how to scope.

### Common Anti-patterns (exam wrong answers)

- *"Apply an SCP to the management account to lock it down"* → **doesn't work** — management account is excluded from SCPs by design. Use IAM policies + permissions boundaries there
- *"Use SCPs to grant permissions"* → SCPs are **deny-only in practice** (they set the ceiling). You still need IAM policies to grant
- *"IAM users per account"* in a 30-account org → **IAM Identity Center** with permission sets
- *"Run CloudTrail individually in each account"* → **organization trail** in the management account (or via Control Tower)
- *"Mix prod and non-prod accounts in the same OU"* → split into Prod / Non-prod OUs so SCPs can differ
- *"Set up multi-account from scratch by manually creating accounts"* → **Control Tower Account Factory**
- *"Create a new account by calling `CreateAccount` then forgetting baseline setup"* → use **Control Tower** or wrap in IaC so baseline (CloudTrail, Config, tags, IAM roles) is applied
- *"SCPs can lock the root user out of a member account"* — **true and intended**, but if a question presents this as "unintended consequence", the answer is usually "create a break-glass IAM role exempted via SCP condition"

### Common Exam Question Patterns

The exam loves Organizations / SCP scenarios because they expose whether you actually understand AWS's layered policy model. Here are the recurring patterns and the trap answers each one is designed to lure you toward.

#### Pattern 1 — "Why can't user X do Y despite having admin?"

A user has `AdministratorAccess` in IAM but an action gets blocked. You need to spot which layer is denying.

| Scenario | The actual cause | Trap answer |
| -------- | ---------------- | ----------- |
| Admin user can't terminate EC2 instances | **SCP** at OU level denies `ec2:TerminateInstances` | "the IAM policy is wrong" |
| Admin user can't access an S3 bucket | **Resource policy** (bucket policy) denies — or doesn't include the role's account | "add `s3:*` to IAM policy" (already there) |
| Admin user can't use a KMS key in another account | KMS **key policy** doesn't trust the role | "grant `kms:Decrypt` in IAM" |
| Admin user can't assume a role | **Permissions boundary** blocks it, or the role's **trust policy** doesn't include them | "the role's permission policy is wrong" |

**Rule:** *"User has admin but still can't do X"* → look for **SCP, resource policy, permissions boundary, or trust policy**. The IAM policy isn't the culprit.

#### Pattern 2 — "How do we enforce X across all accounts?"

| The ask | The answer | Why |
| ------- | ---------- | --- |
| "Prevent any account from using regions other than EU" | **SCP with `aws:RequestedRegion` condition** | Only mechanism that enforces across all accounts and overrides root |
| "Prevent member accounts from disabling CloudTrail" | **SCP denying `cloudtrail:Stop*`, `cloudtrail:Delete*`** | Org trail alone isn't enough — members could still try; SCP makes it impossible |
| "Block creation of public S3 buckets" | **SCP denying `s3:PutBucketAcl`** with public-read condition + S3 Block Public Access | Defence in depth |
| "Sandbox accounts can only run small EC2 instances" | **SCP with `ec2:InstanceType` condition** on `ec2:RunInstances` | Per-OU policy enforcement |
| "Prevent root user of any member account from creating access keys" | **SCP** | The *only* way to restrict the root user — IAM can't |

**Rule:** *"Enforce X across many accounts"* or *"prevent users including root from doing X"* → **SCP**. If the answer says "IAM policy", it's the trap.

#### Pattern 3 — Management account traps

| Question | Correct answer | Trap |
| -------- | -------------- | ---- |
| "Apply an SCP to the management account to lock it down" | **Doesn't work** — management account is excluded from SCPs | "yes, just attach the SCP" |
| "Why is the management account still able to terminate instances despite the deny SCP?" | Management account ignores SCPs | "the SCP must be misconfigured" |
| "How do we restrict the management account?" | **IAM + permissions boundaries** in the management account; better: **don't put workloads there** | "another SCP" |

**Rule:** if a question mentions "management account" + "SCP", the answer is almost always *"SCPs don't apply to the management account"*. Best practice: management account should have **no workloads** — only Organizations + billing.

#### Pattern 4 — Allow-list vs deny-list strategy

| Question wording | Answer |
| ---------------- | ------ |
| "This OU should only be able to use S3, Lambda, and DynamoDB — nothing else" | **Allow-list SCP**: remove default `FullAWSAccess`, attach SCP allowing only those services |
| "Block usage of EC2 P-series instances across all accounts" | **Deny-list SCP**: keep `FullAWSAccess`, attach SCP denying `ec2:RunInstances` with instance-type condition |
| "Highly regulated workload, lock down to minimum surface area" | **Allow-list** |
| "Most accounts run normally, but a few high-risk actions need blocking" | **Deny-list** |

**Rule:** *"only X, Y, Z allowed"* → allow-list. *"block A, B, C"* → deny-list.

#### Pattern 5 — Cross-account access

Cross-account requires **both sides to agree**:

```
Account A: alice                  Account B: prod-data S3 bucket
─────────────────                 ──────────────────────────────
Identity policy on alice:         Bucket policy on prod-data:
"Allow s3:GetObject               "Allow Principal arn:…alice
 on prod-data/*"                   s3:GetObject on prod-data/*"

      Both must Allow → access granted
      Either missing → denied
```

| Question | Answer |
| -------- | ------ |
| "User in Account A can't read S3 bucket in Account B" | Need **both** IAM allow on alice AND bucket policy granting account A |
| "We added the IAM policy but it still doesn't work" | The **resource policy** (bucket policy) is missing the grant |
| "We added the bucket policy but it still doesn't work" | The **IAM policy** on the user is missing the grant |
| "How does cross-account role assumption work?" | Role's **trust policy** in Account B trusts Account A; user in A has IAM permission to call `sts:AssumeRole` |

**Rule:** cross-account = **both** identity policy AND resource policy must allow. The exam tests whether you know one side alone isn't enough.

#### Pattern 6 — SCP vs Permissions Boundary

A perennial source of confusion:

| | SCP | Permissions Boundary |
| - | --- | -------------------- |
| Attaches to | Account, OU, root | Individual IAM user or role |
| Scope | All principals in that account | Just that one principal |
| Affects root user? | ✅ Yes | ❌ No (only IAM users/roles) |
| Effect | Caps what IAM can grant | Caps what IAM can grant for that principal |
| Set by | Org management account | Account admin |

**Rule:** "all principals in an account" → **SCP**. "specific role for a developer who's also an admin" → **permissions boundary**.

#### Pattern 7 — Account creation / landing zone

| Question | Answer | Trap |
| -------- | ------ | ---- |
| "Set up a new multi-account environment from scratch with best practices" | **AWS Control Tower** | "Use Organizations directly" |
| "Programmatically create 50 new sandbox accounts" | **Control Tower Account Factory** or `organizations:CreateAccount` API | "manually via console" |
| "We have 30 existing accounts and want centralised governance" | **AWS Organizations** (add Control Tower later) | "rebuild everything in Control Tower" |
| "Standardised baseline for every new account (CloudTrail, Config, IAM roles)" | **Control Tower guardrails + Account Factory** | "CloudFormation StackSets alone" |

**Rule:** "from scratch + best practices + landing zone" → Control Tower. "already have many accounts" → Organizations.

#### Pattern 8 — Federated SSO

| Question | Answer |
| -------- | ------ |
| "Users currently have IAM users in 30 accounts — what should we move to?" | **IAM Identity Center** (formerly AWS SSO) |
| "Federate with Okta / Azure AD for AWS access" | **IAM Identity Center** with the IdP as identity source |
| "One login → access multiple accounts" | **IAM Identity Center** with permission sets |
| "Allow temporary credentials instead of access keys" | IAM Identity Center, or **roles + STS** |

**Rule:** "IAM users everywhere" + "federated login" + "many accounts" → **IAM Identity Center**.

#### Pattern 9 — Organization-wide security tooling

| Question | Answer |
| -------- | ------ |
| "Centralise CloudTrail across all accounts" | **Organization trail** |
| "Centralised compliance dashboard across all accounts" | **AWS Config Aggregator** |
| "Centralise GuardDuty findings, but security team isn't in the management account" | **Delegated administrator** for GuardDuty |
| "Aggregate Security Hub findings org-wide" | **Delegated admin + cross-account Security Hub integration** |
| "Centralised backup policies for all accounts" | **AWS Backup + Organizations** |
| "Share VPC subnets across accounts" | **AWS Resource Access Manager (RAM)** — not Organizations directly |

**Rule:** "org-wide X from non-management account" → **delegated administrator** pattern.

#### Pattern 10 — Order of evaluation gotchas

The most punishing questions because the answer hinges on the precedence rules.

| Scenario | Result | Why |
| -------- | ------ | --- |
| SCP Allows, IAM doesn't grant | ❌ Blocked | IAM must explicitly Allow — SCPs never grant |
| SCP Denies, IAM Allows | ❌ Blocked | Explicit Deny wins everywhere |
| SCP Allows, IAM Allows, Permissions Boundary Denies | ❌ Blocked | Every layer must pass |
| Resource policy Allows, IAM Denies (same account) | ❌ Blocked | Both layers must Allow |
| Resource policy Allows (cross-account), IAM Allows (cross-account), SCP in *either* account Denies | ❌ Blocked | SCP in either account can block |

**Rule:** *Explicit Deny anywhere = blocked. Every layer must Allow. SCPs never grant.*

#### Vocabulary the exam uses to telegraph the answer

| Phrase in question | What it's pointing at |
| ------------------ | --------------------- |
| "across all accounts" | Organizations / SCP / org trail / Aggregator |
| "even if a user is an administrator" | SCP or permissions boundary |
| "prevent the root user from..." | **Only** SCP can do this |
| "minimum necessary permissions for a developer who needs admin sometimes" | Permissions boundary |
| "from scratch with best practices" | Control Tower |
| "federated single sign-on" | IAM Identity Center |
| "delegate administration of [GuardDuty/Config/etc.] to a non-management account" | Delegated administrator |
| "consolidated billing" / "pooled volume discounts" | Organizations (consolidated billing) |
| "tamper-proof audit logs across accounts" | Organization trail + S3 Object Lock |

### Exam Triggers

- *"Centralised billing across multiple AWS accounts"* → **AWS Organizations consolidated billing**
- *"Block use of certain regions across all accounts"* → **SCP at the root or OU level with `aws:RequestedRegion` condition**
- *"Prevent member accounts from disabling CloudTrail / Config"* → **SCP denying `cloudtrail:Stop*`, `config:Delete*`**
- *"Programmatically create new AWS accounts"* → **`organizations:CreateAccount`** API or **Control Tower Account Factory**
- *"Standardised landing zone for a new multi-account setup"* → **AWS Control Tower**
- *"Federated SSO across all member accounts"* → **IAM Identity Center**
- *"Centralised CloudTrail across the org"* → **organization trail**
- *"Centralised compliance dashboard across the org"* → **AWS Config Aggregator**
- *"Allow only specific EC2 instance types in sandbox accounts"* → **SCP with `ec2:InstanceType` condition**
- *"Share VPC subnets across accounts"* → **AWS Resource Access Manager (RAM)**, not Organizations directly
- *"Delegate GuardDuty admin to a security account"* → **delegated administrator** feature
- *"Pool Reserved Instance discounts across accounts"* → **Consolidated billing** (default behaviour)
- *"Restrict the root user of a member account from doing X"* → **SCP** (the *only* way to restrict the root user)

**The 80/20:** *AWS Organizations = central management of many AWS accounts grouped into OUs under a root. Two killer features: **consolidated billing** (pooled discounts, shared RIs, one invoice) and **SCPs** (deny-only guardrails that cap what IAM can do — even for the root user). The management account is excluded from SCPs by design. **AWS Control Tower** is the opinionated landing-zone builder on top; **IAM Identity Center** provides federated SSO across accounts. Org-aware services (CloudTrail, Config, GuardDuty, Security Hub) all support a "delegated admin" + cross-account aggregation pattern.*

## AWS Control Tower & Landing Zones

**Anchored against opinionated infrastructure templates (Terraform blueprints, GitHub starter repos) — but AWS-managed and continuously enforced.** Control Tower isn't a service in the traditional sense; it's a **wizard + ongoing supervisor** that builds a standardised multi-account "landing zone" on top of AWS Organizations and keeps it from drifting.

### "Landing Zone" — the term is overloaded

When someone says *"do you have a landing zone?"* they could mean any of these:

| What they mean | What it actually is | Status |
| -------------- | ------------------- | ------ |
| **The concept** | A pre-configured, secure, multi-account AWS environment with baseline governance (CloudTrail, Config, IAM, networking, audit) ready to go — the *thing* you've built | Generic industry term, not a service |
| **AWS Control Tower** | AWS's *managed wizard* that builds a landing zone for you in ~30 mins | Active, recommended for most |
| **AWS Landing Zone Accelerator (LZA)** | AWS's open-source CloudFormation/Terraform solution for enterprise/regulated landing zones — more powerful, more setup | Active, for advanced cases |
| **AWS Landing Zone (the old service)** | The legacy CloudFormation solution AWS used to ship — pre-dates Control Tower | **Deprecated.** Migrated customers to Control Tower |

**One-line answer:** *A landing zone is a pre-built, governed, multi-account AWS foundation. **AWS Control Tower** is how most companies build one. **Landing Zone Accelerator (LZA)** is the heavier-duty alternative for regulated enterprise environments.*

### What Control Tower is NOT

| Question | Service | Not Control Tower because... |
| -------- | ------- | ---------------------------- |
| *"Group AWS accounts and apply SCPs"* | **AWS Organizations** | Control Tower *uses* Organizations under the hood; Organizations is the primitive |
| *"Provision infrastructure as code"* | **CloudFormation / Terraform** | Control Tower deploys *accounts*, not arbitrary infra (though it uses StackSets to apply baselines) |
| *"Enterprise-grade landing zone with deep customisation"* | **AWS Landing Zone Accelerator (LZA)** | LZA is the more powerful, more complex enterprise alternative — Control Tower is the opinionated, lower-ceiling option |
| *"Multi-account billing"* | **Organizations consolidated billing** | Comes free with Organizations; Control Tower doesn't add billing features |
| *"User authentication / SSO"* | **IAM Identity Center** | Control Tower *enables* Identity Center as part of setup, but doesn't manage users itself |
| *"Workload deployment across accounts"* | **CloudFormation StackSets / Terraform** | Control Tower bootstraps the accounts; you still need IaC to deploy workloads into them |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Landing Zone** | The full multi-account environment Control Tower builds and maintains — OUs, accounts, baselines, guardrails, log/audit pipelines |
| **Home region** | The single region where Control Tower itself runs. **Cannot be changed** after setup — pick carefully |
| **Governed regions** | Regions Control Tower extends its guardrails into. Guardrails only enforce in these regions; everything else is unmanaged |
| **Account Factory** | Vended template (in Service Catalog) for provisioning new accounts with the standard baseline auto-applied |
| **Guardrails** | Pre-built **SCPs** (preventive) and **Config Rules** (detective) bundled into mandatory / strongly recommended / elective tiers |
| **Drift detection** | Alerts when someone modifies the landing zone outside Control Tower (e.g. manually edits an SCP, moves an account between OUs) |
| **Customizations for Control Tower (CfCT)** | CloudFormation templates that auto-run when a new account is provisioned — your customisation layer |
| **Account Factory for Terraform (AFT)** | Terraform-based alternative to Account Factory for IaC-heavy orgs — runs in a CodePipeline |

### What Control Tower Sets Up on Day 1

When you click "Enable Control Tower" in a fresh org, it creates:

```
Management account (your existing account, becomes the org root)
        │
        ├── Security OU
        │     ├── Log Archive account     (centralised CloudTrail + Config logs)
        │     │                             - S3 bucket with versioning + Object Lock
        │     │                             - Cross-account write from all member accounts
        │     │
        │     └── Audit account            (read-only across the org for security team)
        │                                    - Aggregates Config compliance
        │                                    - SNS topics for compliance alerts
        │
        └── Sandbox OU                    (empty initially; place for test accounts)

Plus, in the management account:
  - AWS Organizations enabled with all features
  - IAM Identity Center enabled
  - CloudTrail organization trail → Log Archive bucket
  - AWS Config aggregator → Audit account
  - Service Catalog with Account Factory product available
  - CloudFormation StackSets deploying baseline IAM roles into every account
```

You go from "blank AWS account" to "production-ready 3-account landing zone" in ~30 minutes. Doing this manually is a multi-week project.

### How Control Tower Account Provisioning Actually Flows

```
1. Admin opens Service Catalog → "AWS Control Tower Account Factory" product
       ↓
2. Fills in: account email, account name, target OU, SSO user details
       ↓
3. Submits — Service Catalog kicks off a CloudFormation stack
       ↓
4. Stack calls organizations:CreateAccount to vend a new AWS account
       ↓
5. Once created, Control Tower automatically:
   - Moves the account into the chosen OU
   - Applies all mandatory + strongly recommended guardrails (SCPs)
   - Deploys baseline CloudFormation StackSets:
       • AWSControlTowerExecution role (cross-account admin for CT)
       • CloudTrail log forwarding to Log Archive
       • AWS Config recorder + delivery to Audit account
       • IAM Identity Center permission set assignments
   - Runs any Customizations for Control Tower (CfCT) templates
       ↓
6. Creates an IAM Identity Center user (the new account's "admin")
       ↓
7. Sends an invitation email to the admin's address
       ↓
8. Admin logs into Identity Center → sees new account → can start working
```

What took ~2 weeks of manual setup is now ~20 minutes.

### Guardrails — Where the Governance Lives

Two implementations under the same name:

| Mechanism | What it does | Example |
| --------- | ------------ | ------- |
| **Preventive guardrails** | **SCPs** that block actions before they happen | "Disallow changes to CloudTrail config" — denies `cloudtrail:Stop*`, `cloudtrail:Delete*` |
| **Detective guardrails** | **AWS Config Rules** that flag non-compliant resources after the fact | "Detect S3 buckets without versioning" |

Three tiers of enforcement:

| Tier | Behaviour | Example |
| ---- | --------- | ------- |
| **Mandatory** | Always on, **cannot disable** | "Disallow public read on log archive S3 bucket"; "disallow deletion of log archive bucket" |
| **Strongly recommended** | On by default, can disable per OU | "Require MFA for root user"; "disallow internet access from EC2 in Security OU" |
| **Elective** | Opt-in only | "Disallow EC2 instances larger than `m5.large`"; "deny use of specific regions" |

The mandatory ones are the killer feature — they make it *impossible* for any account in the org to compromise the audit trail.

### Drift Detection

Control Tower continuously checks that the landing zone matches its expected state. Drifts get flagged:

| Common drift cause | What happens |
| ------------------ | ------------ |
| Someone manually edits an SCP that Control Tower owns | Drift event in dashboard |
| Account moved between OUs outside Control Tower | Drift detected |
| Log archive bucket policy modified | Drift detected (this one's serious — affects audit integrity) |
| Mandatory guardrail somehow disabled | Drift detected |

**Remediation:** "Reset landing zone" from the console reverts changes to the expected state. Or manually fix the offending change.

### CfCT and AFT — Customising Beyond the Defaults

| | Customizations for Control Tower (CfCT) | Account Factory for Terraform (AFT) |
| - | -------------------------------------- | ------------------------------------ |
| Language | CloudFormation | Terraform |
| Trigger | Runs when accounts are provisioned via Account Factory | Replaces Account Factory with a Terraform-driven pipeline |
| Use when | You want to apply standard CFN templates to every new account (baseline VPC, IAM roles, alarms) | You're a Terraform shop and want GitOps account vending |
| Complexity | Lower | Higher (CodeCommit + CodePipeline + Terraform state per account) |

**Exam trigger:** *"customise account baseline beyond what Control Tower provides"* → **CfCT** (CloudFormation) or **AFT** (Terraform).

### Control Tower vs Landing Zone Accelerator (LZA)

| | Control Tower | Landing Zone Accelerator (LZA) |
| - | ------------- | ------------------------------ |
| Setup | Click through a wizard | Deploy a CloudFormation stack + extensive config files |
| Customisation | Limited (via CfCT) | Almost unlimited |
| Target | Most orgs, small-to-medium complexity | Heavily regulated industries (finance, gov, healthcare), 100+ accounts |
| Maintenance | AWS keeps it updated | You maintain the LZA codebase |
| Cost (effort) | Low | High |
| Cost ($) | Free | Free (but more AWS resources spun up) |

**Decision:** Control Tower until you outgrow it. Then either migrate to LZA, or layer LZA-style customisations on top using CfCT.

### Enrolling Existing Accounts

Originally Control Tower was greenfield-only. Now you can:
- **Enrol existing accounts** into an existing Control Tower org — they get the baseline applied retroactively
- **Enrol an existing OU** to bring all its accounts in at once
- Some constraints: the account must not have conflicting resources (e.g. its own non-CT CloudTrail config in conflicting regions)

**Exam framing:** the older "Control Tower only works for new orgs" answer is **out of date**. If a question implies that, it's the trap.

### Common Anti-patterns (exam wrong answers)

- *"Manually edit SCPs that Control Tower manages"* → causes drift; let Control Tower own its SCPs and add your *own* SCPs alongside
- *"Manually create accounts via `organizations:CreateAccount`"* in a Control Tower org → bypasses Account Factory baseline → drift
- *"Put workloads in the management account"* → bad practice; management account should be Organizations + billing only
- *"Disable mandatory guardrails"* → can't anyway, but if a question implies you can, it's the trap
- *"Use Control Tower for a 500-account heavily regulated environment"* → consider **LZA** instead
- *"Skip Account Factory and provision baseline manually"* → no — that's exactly what Control Tower automates

### Exam Triggers

- *"Set up a new multi-account environment with AWS best practices"* → **AWS Control Tower**
- *"What is a landing zone?"* → pre-built, governed, multi-account AWS foundation (built by Control Tower or LZA)
- *"Auto-provision accounts with standard CloudTrail / Config / IAM baseline"* → **Control Tower Account Factory**
- *"Pre-built compliance rules across all accounts"* → **Control Tower guardrails** (mandatory / recommended / elective)
- *"Detect when someone modifies our landing zone"* → **Control Tower drift detection**
- *"Terraform-based account vending"* → **Account Factory for Terraform (AFT)**
- *"Run additional CloudFormation in every new account"* → **Customizations for Control Tower (CfCT)**
- *"Enterprise landing zone, 200+ accounts, deep customisation"* → **AWS Landing Zone Accelerator (LZA)**
- *"Enrol our existing 30 accounts into Control Tower"* → **Enrol existing accounts/OUs feature** (no longer greenfield-only)
- *"Tamper-proof audit log shared across all accounts"* → **Control Tower's Log Archive account** (with mandatory guardrails preventing modification)
- *"Why can't I disable this CloudTrail in a Control Tower account?"* → **Mandatory guardrail blocks it via SCP**

### Pricing

**Control Tower itself is free.** You pay for the underlying resources it spins up: CloudTrail (org trail is free for management events; data events cost), Config recorders + rules, S3 storage in Log Archive, IAM Identity Center (free), CloudWatch alarms in Audit account.

**The cost reality:** Config across many accounts is where the bill grows — same trap as in the AWS Config notes.

**The 80/20:** *AWS Control Tower = the opinionated wizard that builds a production-ready multi-account **landing zone** on top of Organizations in ~30 minutes. Creates Security OU (Log Archive + Audit accounts), enables CloudTrail org trail, Config aggregator, IAM Identity Center, and applies preventive (SCP) + detective (Config Rule) **guardrails** in three tiers (mandatory/strongly recommended/elective). **Account Factory** vends new accounts with the baseline auto-applied; **CfCT** or **AFT** lets you customise further. **Drift detection** alerts when someone modifies the landing zone outside Control Tower. Pick Control Tower when starting fresh or up to ~100 accounts; pick **Landing Zone Accelerator (LZA)** for enterprise / heavily regulated environments. Management account is Organizations + billing — don't put workloads there.*

## AWS Directory Service (Active Directory on AWS)

**Anchored against on-prem Active Directory.** If you've ever run AD in a data centre (domain controllers, OUs, Group Policy, Kerberos, LDAP), AWS Directory Service is the managed version — three flavours depending on how much "real AD" you need.

### The Three Flavours (this is the whole exam)

| Service | What it actually is | When to pick it | Cost |
| ------- | ------------------- | --------------- | ---- |
| **AWS Managed Microsoft AD** | **Real Microsoft AD** on AWS-managed Domain Controllers in a VPC. Full schema, Group Policy, Kerberos, LDAP, MFA, trusts | Need *actual* AD features: SQL Server Windows Auth, SharePoint, .NET apps, schema extensions, forest trusts with on-prem AD | $$$ (most expensive — managed DCs) |
| **AD Connector** | A **proxy / redirector** to your *existing* on-prem AD. No directory data stored in AWS — every auth call is forwarded back to on-prem | You already have on-prem AD and want AWS workloads (EC2 domain-join, WorkSpaces, IAM Identity Center) to authenticate against it without replicating | $ (cheap — it's just a proxy) |
| **Simple AD** | A **Samba-based** AD-compatible directory. LDAP, basic user/group management, joining Linux/Windows EC2 | Lightweight, low cost, no Microsoft-specific features needed (no trusts, no schema extensions, no MFA, no PowerShell, no Group Policy) | $ |

**The umbrella name** for all three is **AWS Directory Service**.

### What AWS Directory Service is NOT

| Question | Service | Not Directory Service because... |
| -------- | ------- | -------------------------------- |
| *"SSO into AWS Console across many accounts"* | **IAM Identity Center** | Identity Center *uses* AD as one possible identity source; AD itself doesn't talk to the AWS console |
| *"Manage IAM users / roles"* | **IAM** | Different identity layer — IAM is for AWS API/console; AD is for Windows/LDAP workloads |
| *"Authenticate end customers signing into our SaaS"* | **Amazon Cognito** | AD is workforce identity, not customer identity |
| *"Replace IAM users in each AWS account"* | **IAM Identity Center** (which can sit on top of Managed AD) | AD alone doesn't federate to AWS console |
| *"Sync Google Workspace users to AWS"* | **IAM Identity Center with Google as SAML source** | AD is Microsoft-flavoured; Google syncs to Identity Center directly |
| *"DNS for VPC resources"* | **Route 53 (private hosted zones) or Route 53 Resolver** | AD provides DNS *for the domain*, but isn't your general-purpose DNS service |

### The Decision Tree

```
Do you need full Microsoft AD features (Group Policy, schema, trusts, MFA, LDAPS)?
  └── YES → AWS Managed Microsoft AD
  └── NO → Do you already have on-prem AD and want to keep it as the source of truth?
            └── YES → AD Connector (proxy to on-prem)
            └── NO → Do you just need basic LDAP / small user count, no Microsoft-specific bits?
                      └── YES → Simple AD
                      └── NO → You probably don't need a directory at all
                                  → use IAM Identity Center's built-in directory
```

### How Domain-Joining an EC2 Instance Actually Flows

```
1. Launch a Windows EC2 in a VPC subnet that can reach the AD DCs
       ↓
2. EC2 has an IAM role with permission to read directory join info from SSM
   (and AmazonSSMManagedInstanceCore for the SSM agent)
       ↓
3. Either:
   - At launch: pass the directory ID via the "Domain join directory" option
   - At runtime: SSM Run Command "AWS-JoinDirectoryServiceDomain"
       ↓
4. SSM agent on the instance retrieves domain credentials from a managed secret
       ↓
5. The instance contacts the AD DCs (Managed AD, or via AD Connector → on-prem)
   using Kerberos/LDAP over the standard ports (UDP/TCP 88, 389, 445, 636…)
       ↓
6. AD creates a computer account; the instance trusts the domain controllers
       ↓
7. AD users can now RDP into the box; Group Policy applies
```

The IAM role + SSM glue is what makes this seamless — without it you'd be manually joining with `Add-Computer`.

### Trust Relationships (Managed AD Only)

Trusts let users in one domain authenticate to resources in another. Three flavours, all tested:

| Trust type | Direction | Use case |
| ---------- | --------- | -------- |
| **One-way outgoing trust** | AWS Managed AD trusts on-prem AD | On-prem users access AWS resources, but not vice versa |
| **One-way incoming trust** | On-prem AD trusts AWS Managed AD | AWS-managed accounts access on-prem resources |
| **Two-way (bidirectional) forest trust** | Both ways | Full integration — the classic answer for hybrid AD |

**Exam trigger:** *"hybrid AD, users in either domain access resources in the other"* → **two-way forest trust between AWS Managed Microsoft AD and on-prem AD**.

You **cannot** create trusts with Simple AD or AD Connector — trusts are a Managed Microsoft AD–only feature.

### Integration with IAM Identity Center

This is where Directory Service ties back to everything in the Organizations section:

```
On-prem AD (or AWS Managed Microsoft AD)
         ↓ (identity source)
IAM Identity Center
         ↓ (assigns permission sets to user/group + account)
AWS Console / CLI in member accounts
```

User identity lives in AD. Identity Center reads group membership from AD. Permission sets in Identity Center map AD groups → AWS roles. AD users get federated AWS console access without ever creating IAM users.

**Exam trigger:** *"company uses AD on-prem and wants AWS console SSO that respects AD group membership"* → **IAM Identity Center with Managed AD (with trust to on-prem) OR AD Connector as the identity source**.

### Common Use Cases

| Use case | Service |
| -------- | ------- |
| SQL Server Windows Authentication on RDS / EC2 | **Managed Microsoft AD** (RDS for SQL Server integrates directly) |
| .NET apps using AD authentication | **Managed Microsoft AD** or **AD Connector** |
| Joining Windows EC2 fleet to a domain | Any of the three (Managed AD if you want trusts/Group Policy) |
| Amazon WorkSpaces / AppStream user directory | **Managed Microsoft AD** or **AD Connector** (or Simple AD for basic) |
| FSx for Windows File Server (SMB shares with AD ACLs) | **Managed Microsoft AD** or **AD Connector** |
| LDAP-backed Linux app, no Microsoft features | **Simple AD** |
| SSO into AWS Console for AD users | **AD source + IAM Identity Center** |

### Common Anti-patterns (exam wrong answers)

- *"Use Simple AD because it's cheap"* — fine until you need trusts, Group Policy, MFA, schema extensions, or PowerShell management — none of which Simple AD supports
- *"Use AD Connector when on-prem is unreachable"* — AD Connector requires live network to on-prem DCs; an outage there breaks all AWS auth
- *"Use Managed Microsoft AD for a simple LDAP directory of 20 users"* — overkill and expensive; use Simple AD or Identity Center directory
- *"Use AD to authenticate customers of your SaaS"* — wrong layer; that's **Cognito**
- *"Replicate on-prem AD into AWS by standing up DCs on EC2"* — works but you're managing DCs yourself; the whole point of Managed AD is AWS does that for you
- *"Use AD for AWS Console SSO directly"* — AD doesn't talk to the AWS console; you need **IAM Identity Center** on top

### Exam Triggers

- *"Run SQL Server with Windows Authentication"* → **AWS Managed Microsoft AD** (or AD Connector to on-prem)
- *"Domain-join EC2 instances to existing on-prem AD"* → **AD Connector** (or Managed AD with trust)
- *"Two-way trust with on-prem AD"* → **Managed Microsoft AD** (Simple AD + AD Connector can't do trusts)
- *"Cheap AD-compatible directory for small Linux workload"* → **Simple AD**
- *"Hybrid AD with seamless user experience in both directions"* → **Managed Microsoft AD + two-way forest trust**
- *"AWS Console SSO for AD users across many accounts"* → **IAM Identity Center with AD as identity source**
- *"Group Policy, MFA, LDAPS, schema extensions"* → **Managed Microsoft AD** only
- *"WorkSpaces / FSx need a directory"* → **Managed AD or AD Connector** (Simple AD for low-end WorkSpaces)
- *"Manage the directory in AWS but users authenticate against on-prem"* → contradictory — pick: Managed AD (AWS-resident) or AD Connector (on-prem-resident)
- *"No AD admin team, no Microsoft licences, but we need an LDAP directory"* → **Simple AD** or skip AD entirely

### Pricing Notes

- **Managed Microsoft AD**: per-hour per DC (you get 2 DCs by default; can scale up). Most expensive of the three.
- **AD Connector**: per-hour, much cheaper — it's just a proxy.
- **Simple AD**: per-hour, cheapest. Two sizes (Small for ≤500 users, Large for ≤5000).

**The 80/20:** *AWS Directory Service umbrella covers three flavours: **Managed Microsoft AD** (real MS AD on AWS DCs, supports trusts/Group Policy/schema), **AD Connector** (proxy to existing on-prem AD), **Simple AD** (Samba-based, cheap, no Microsoft-specific features). For hybrid AD with trust → Managed AD. For "on-prem AD is the source of truth" → AD Connector. For "I just need a basic LDAP" → Simple AD. Combine any of these with **IAM Identity Center** to give AD users SSO into the AWS console across all org accounts. Trusts are Managed AD only. Watch out: AD ≠ IAM ≠ Cognito ≠ Identity Center — different identity layers.*

## AWS STS (Security Token Service)

**Anchored as the universal "give me temporary AWS credentials" service.** Every cross-account access, every federated login, every role assumption in AWS goes through STS underneath. Most AWS services don't expose it directly — they call it on your behalf — but understanding STS is what lets you reason about *who is allowed to do what, when, and for how long*.

### What STS is NOT

| Question | Service | Not STS because... |
| -------- | ------- | ------------------ |
| *"Manage IAM users / roles / policies"* | **IAM** | IAM defines the rules; STS *issues credentials* based on them |
| *"Workforce SSO into the AWS Console"* | **IAM Identity Center** | Identity Center uses STS underneath; you don't call STS directly |
| *"Authenticate end users of my app"* | **Amazon Cognito** | Cognito for app users; STS for AWS principals (though Cognito identity pools use STS) |
| *"Store and rotate secrets"* | **AWS Secrets Manager** | Secrets are *long-lived secrets*; STS issues *short-lived AWS credentials* |
| *"Active Directory authentication"* | **AWS Managed Microsoft AD** | Different identity layer entirely |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Temporary credentials** | A bundle: `AccessKeyId` + `SecretAccessKey` + `SessionToken` + `Expiration`. The session token is what marks it as STS-issued (vs long-lived IAM user keys) |
| **`AssumeRole`** | The workhorse. A principal (user or role) assumes an IAM role; STS issues temporary credentials for that role |
| **`AssumeRoleWithSAML`** | SAML 2.0 federation — corporate IdP (Okta, ADFS, Entra ID) → STS → AWS console / API |
| **`AssumeRoleWithWebIdentity`** | OIDC federation — Google, Facebook, Cognito, Kubernetes service accounts (IRSA) → STS |
| **`GetSessionToken`** | Short-lived credentials for an IAM user (typically used to enforce MFA before sensitive actions) |
| **`GetFederationToken`** | Older federation pattern; mostly replaced by `AssumeRoleWith*` variants |
| **Session policies** | Inline policy passed *at AssumeRole time* that further restricts the role's permissions for that session only |
| **External ID** | Cross-account assume-role guard — prevents the "confused deputy" attack |
| **Source identity** | Propagates the original caller's identity across role chains (audit visibility) |
| **Session tags** | Key/value pairs attached at AssumeRole time — used for **ABAC** (attribute-based access control) |
| **Role chaining** | Assume role A → from A, assume role B. Limited to **1 hop** and **1-hour** max session |
| **Session duration** | Default 1 hour; configurable per role via `MaxSessionDuration` (up to 12 hours) |

### How AssumeRole Actually Flows

```
1. Principal calls sts:AssumeRole(
     RoleArn="arn:aws:iam::ACCT-B:role/CrossAccountAdmin",
     RoleSessionName="alice-session",
     ExternalId="...",          ← if cross-account third-party
     SerialNumber + TokenCode,  ← if MFA required
     DurationSeconds=3600       ← up to role's MaxSessionDuration
   )
       ↓
2. STS validates the caller has sts:AssumeRole permission on the target role
       ↓
3. STS validates the role's TRUST POLICY allows this caller:
     "Principal": { "AWS": "arn:aws:iam::ACCT-A:user/alice" }
     "Condition": { "StringEquals": { "sts:ExternalId": "..." } }
     "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
       ↓
4. STS returns temporary credentials:
     {
       "AccessKeyId":     "ASIA...",     ← note ASIA prefix = temporary
       "SecretAccessKey": "...",
       "SessionToken":    "FQoG...",     ← signs every request
       "Expiration":      "2026-06-02T15:30:00Z"
     }
       ↓
5. Caller uses temp creds for subsequent AWS API calls
   (session token must be sent on EVERY request)
       ↓
6. When credentials expire → caller must AssumeRole again (refresh)
```

**Spot the temporary creds:** access key starts with `ASIA` (not `AKIA` for long-lived IAM user keys). Useful when debugging — you can tell at a glance which credentials a request used.

### The External ID Pattern (Cross-Account from Third Parties)

The **confused deputy problem**: a third-party SaaS (e.g. Datadog, Wiz) has many customers. If their assume-role permissions to *your* account aren't tied to a unique identifier, an attacker who's also their customer could trick the SaaS into doing things in your account.

**The fix — external ID:**

```json
// In your account, the role's trust policy:
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::THIRD-PARTY-ACCT:root" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "sts:ExternalId": "unique-string-generated-for-you" }
  }
}
```

The third party must pass the matching `ExternalId` on every `AssumeRole` call. Without it, no access — even with valid AWS credentials.

**Exam trigger:** *"Cross-account assume role for a third-party service"* → **always use external ID**.

### Role Chaining Limits

A common gotcha:

```
User in Account A
     ↓ AssumeRole
Role 1 in Account A (session: 8 hours)
     ↓ AssumeRole
Role 2 in Account B (session: capped at 1 hour, regardless of role's MaxSessionDuration)
     ↓ AssumeRole
Role 3 in Account C → ❌ BLOCKED — role chain limit reached (max 1 hop after initial assumption)
```

**Rules:**
- Max **1 hop** in a chain (counting from the first assumed role)
- Chained sessions max out at **1 hour** (overrides MaxSessionDuration)

If you see a question about *"the role chain failed after 1 hour"* — that's why.

### ABAC with Session Tags

Session tags let you implement **attribute-based access control** dynamically:

```
1. IdP / federation issues identity with attributes: dept=engineering
       ↓
2. AssumeRoleWithSAML passes session tag: PrincipalTag/dept=engineering
       ↓
3. IAM policy on resources:
     "Condition": {
       "StringEquals": { "aws:ResourceTag/dept": "${aws:PrincipalTag/dept}" }
     }
       ↓
4. Principal can only access resources tagged with the same dept value
```

One policy serves N departments — instead of N separate policies per dept. Big win at scale.

### Common Anti-patterns (exam wrong answers)

- *"Long-lived access keys for cross-account access"* → use **AssumeRole + temp creds**
- *"IAM user in every account"* → use **AssumeRole + cross-account IAM role** (or migrate to IAM Identity Center)
- *"Share access keys with third party"* → use **AssumeRole + external ID**
- *"Hard-code access keys in code"* → use **IAM role for EC2 / Lambda / ECS task** — STS issues credentials automatically via the metadata service
- *"Allow `Principal: *` in a role trust policy"* → catastrophic; anyone can assume the role. Always scope to specific accounts/principals
- *"Try to chain through 3 roles for cross-org access"* → fails at hop 2 due to chaining limit
- *"Use `GetFederationToken` for new SAML integrations"* → legacy; use `AssumeRoleWithSAML`

### Exam Triggers

- *"Cross-account access"* → **`AssumeRole`** with cross-account trust policy
- *"Federate corporate users (Okta, ADFS, Entra ID) to AWS"* → **`AssumeRoleWithSAML`** (or IAM Identity Center for multi-account)
- *"Federate mobile/web app users to AWS"* → **`AssumeRoleWithWebIdentity`** or **Cognito identity pool**
- *"Third-party tool needs AWS access"* → **`AssumeRole` + External ID**
- *"Temporary credentials with MFA enforcement"* → **`GetSessionToken`** with MFA token
- *"Propagate user identity across role chains for audit"* → **session tags + source identity**
- *"Why did my chained role session only last 1 hour?"* → **role chaining limit** (caps at 1h regardless of MaxSessionDuration)
- *"Dynamic permissions based on user attributes"* → **session tags + ABAC**
- *"How do EC2 / Lambda / ECS get credentials without keys?"* → **IAM role + STS issues temp creds via instance / container metadata service**
- *"How do I tell if credentials are temporary?"* → **access key starts with `ASIA`** (vs `AKIA` for IAM user)

**The 80/20:** *STS = the credential factory for everything in AWS. Every cross-account `AssumeRole`, every federated login (SAML / OIDC), every temporary credential goes through STS. Key APIs: **`AssumeRole`** (general), **`AssumeRoleWithSAML`** (corporate IdP), **`AssumeRoleWithWebIdentity`** (OIDC / Cognito), **`GetSessionToken`** (MFA-protected user creds). Always use **External ID** for cross-account third-party access. **Role chaining** is limited to 1 hop, 1-hour sessions. **Session tags** enable ABAC. Temporary access keys start with `ASIA` (long-lived IAM user keys start with `AKIA`). Most AWS services call STS for you (EC2 instance profile, Lambda execution role, ECS task role) — you rarely call it directly.*

## Amazon Cognito

**Anchored against Auth0 / Okta Customer Identity — but AWS-native, cheaper at scale, less polished.** Cognito handles **end-user identity for your app**: signup, login, MFA, password reset, social federation, and optionally hands those users **temporary AWS credentials** so they can call AWS APIs directly. Constantly confused with IAM Identity Center — keep this straight: **Identity Center is for your employees logging into AWS Console; Cognito is for your app's customers**.

### What Cognito is NOT

| Question | Service | Not Cognito because... |
| -------- | ------- | ---------------------- |
| *"Workforce SSO into the AWS Console"* | **IAM Identity Center** | Identity Center is for *your employees* accessing AWS; Cognito is for *your app's customers* |
| *"Active Directory for Windows workloads"* | **AWS Managed Microsoft AD** | Different identity layer |
| *"Manage IAM users / roles in AWS"* | **IAM** | IAM is for AWS principals; Cognito is for app principals |
| *"Store passwords for service accounts"* | **AWS Secrets Manager** | Secrets Manager = secrets storage; Cognito = user identity |
| *"Cross-account access to AWS"* | **STS `AssumeRole`** | Cognito identity pools use STS underneath, but cross-account AWS access is STS's domain |

### The Two Cognito Products (Constantly Confused)

This is the most-tested distinction in the entire service. Get this right and you've nailed Cognito.

| | **Cognito User Pool** | **Cognito Identity Pool** |
| - | --------------------- | -------------------------- |
| Purpose | **Authenticate your app's users** (signup, login, MFA) | **Give authenticated users temporary AWS credentials** |
| Output | **JWT tokens** (ID token + access token + refresh token) | **Temporary AWS credentials** (via STS) |
| Use to call | Your application's APIs (API Gateway with Cognito authoriser) | AWS services directly (S3, DynamoDB, etc.) |
| Federates with | Social IdPs (Google, Facebook, Apple) + SAML/OIDC IdPs + User Pool itself | User Pool tokens, social IdPs, SAML, OIDC, developer-authenticated |
| Replaces | Building your own auth system (Auth0, Firebase Auth) | Building your own STS exchange |
| Lambda triggers | ✅ (pre-signup, post-confirmation, custom auth challenge, etc.) | ❌ |
| Hosted UI | ✅ (drop-in login pages) | ❌ |

**The flow that uses both:**

```
1. User opens your mobile app
       ↓
2. App calls Cognito User Pool → user signs up / logs in
       ↓
3. User Pool returns JWT (ID token containing user attributes + access token)
       ↓
   ─── now app needs to upload a profile photo to S3 ───
       ↓
4. App passes the JWT to Cognito Identity Pool
       ↓
5. Identity Pool calls STS AssumeRoleWithWebIdentity using the JWT
       ↓
6. STS returns temporary AWS credentials (mapped to either:
     - "authenticated role" if the user signed in
     - "unauthenticated role" if guest access is enabled)
       ↓
7. App uses those credentials to call S3 directly (PutObject on profile-photos/userId)
```

### User Pool Deep Dive

| Feature | What it does |
| ------- | ------------ |
| **Hosted UI** | AWS-hosted signup / login / MFA pages (your-domain.auth.region.amazoncognito.com). Customisable CSS/logo |
| **Custom UI** | Build your own UI; call Cognito APIs directly |
| **MFA** | SMS, TOTP (authenticator apps), or adaptive (risk-based — flag suspicious logins for MFA) |
| **Lambda triggers** | Custom logic at lifecycle stages: PreSignUp, PostConfirmation, PreAuthentication, PostAuthentication, CustomMessage, DefineAuthChallenge, etc. Use these for: blocking signups from disposable email domains, custom welcome emails, anti-abuse checks |
| **Social federation** | Sign in with Google / Facebook / Apple / Amazon. User Pool stores a federated identity record |
| **SAML/OIDC federation** | Enterprise customers — sign in with their corporate IdP |
| **App clients** | Per-application credentials (web, mobile, server) with different scopes |
| **OAuth 2.0 + OIDC flows** | Standard auth flows — Authorization Code, Implicit (legacy), Client Credentials |
| **Adaptive authentication** | Detects risky sign-ins (new device, anomalous location) and triggers MFA dynamically |

### Identity Pool Deep Dive

| Feature | What it does |
| ------- | ------------ |
| **Identity providers** | Cognito User Pool, Google, Facebook, Apple, Amazon, OIDC, SAML, developer-authenticated identities (DAI), guest |
| **Authenticated role** | IAM role assumed for signed-in users — scoped permissions to AWS resources they're allowed to touch |
| **Unauthenticated role** | IAM role for guest / anonymous users (if you enable guest access) |
| **Role mapping** | Conditional role selection based on user attributes (e.g. paid-tier users → role with more permissions) |
| **Variable substitution** | IAM policies can reference `${cognito-identity.amazonaws.com:sub}` so each user only accesses their own S3 prefix / DynamoDB items |

**Per-user prefix pattern (the classic):**

```json
// Authenticated role's policy
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::user-uploads/${cognito-identity.amazonaws.com:sub}/*"
}
```

Each user can only read/write their own folder. One role, N users, no IAM users created.

### When to Use Cognito vs Alternatives

| Need | Use |
| ---- | --- |
| Quick auth for a new SaaS app | **Cognito User Pool** (or Auth0/Firebase if you want a polished alternative) |
| Mobile app users need to upload to S3 | **User Pool + Identity Pool** |
| Enterprise customers sign in via their corporate SAML | **User Pool with SAML IdP** |
| Workforce SSO into AWS Console | **IAM Identity Center**, not Cognito |
| Active Directory authentication | **AWS Directory Service**, not Cognito |
| Programmatic AWS access from EC2 / Lambda | **IAM role + STS**, not Cognito |

### Common Anti-patterns (exam wrong answers)

- *"Use Cognito for AWS Console access for employees"* → wrong service; that's **IAM Identity Center**
- *"Confuse User Pool with Identity Pool"* → User Pool = authn for your app; Identity Pool = AWS credentials for app users
- *"Store passwords in IAM users for app sign-up"* → IAM is for AWS, not app users; use **Cognito User Pool**
- *"Build your own JWT issuer + AWS STS exchange"* → reinvent the wheel; **Cognito does both**
- *"Use the user's same IAM access keys for app access"* → catastrophic; use **Cognito Identity Pool** to issue scoped temp creds per user
- *"Per-user IAM user for each customer"* → doesn't scale; use **Identity Pool with `${cognito-identity.amazonaws.com:sub}` variable substitution**
- *"Use Cognito for service-to-service auth"* → use **IAM roles + STS**

### Exam Triggers

- *"Sign up / log in / MFA for our app's users"* → **Cognito User Pool**
- *"App users need to upload directly to S3 / read DynamoDB"* → **Cognito Identity Pool** (after authenticating against User Pool)
- *"Social login (Google / Facebook / Apple)"* → **Cognito User Pool with social IdP**
- *"Enterprise SAML federation for app users"* → **User Pool with SAML IdP**
- *"Customise the signup flow with validation logic"* → **Lambda triggers** (PreSignUp / PostConfirmation)
- *"App users get temporary AWS credentials"* → **Identity Pool**
- *"Each user can only access their own S3 prefix"* → **Identity Pool authenticated role + `${cognito-identity.amazonaws.com:sub}` variable**
- *"Hosted login page (no UI work)"* → **User Pool Hosted UI**
- *"Risk-based MFA"* → **User Pool adaptive authentication**

**The 80/20:** *Cognito = AWS-native customer identity service. **User Pool** = authn for your app (signup, login, MFA, federation, JWTs). **Identity Pool** = STS-backed exchange that gives authenticated users temporary AWS credentials (so the mobile app can upload to S3 directly without backend code). The two are independent products that pair together. **Use Cognito for app users; use IAM Identity Center for workforce / AWS Console access.** Lambda triggers customise signup/login flows. Variable substitution like `${cognito-identity.amazonaws.com:sub}` in IAM policies gives each user their own scoped slice of an S3 bucket / DynamoDB table.*

## AWS KMS (Key Management Service)

**Anchored against HashiCorp Vault or a managed HSM.** KMS is the centralised, managed cryptographic key service that virtually every AWS service uses for encryption at rest. You don't usually call KMS directly — services like S3, EBS, RDS, Secrets Manager call it on your behalf.

### What KMS is NOT

| Question | Service | Not KMS because... |
| -------- | ------- | ------------------ |
| *"Store and rotate database passwords / API keys"* | **AWS Secrets Manager** | Secrets Manager *uses* KMS to encrypt secrets — but it stores/rotates them; KMS just encrypts |
| *"Single-tenant dedicated hardware HSM for FIPS 140-2 Level 3"* | **AWS CloudHSM** | KMS is multi-tenant managed (FIPS 140-2 Level 3 too, but shared HW). CloudHSM is your own dedicated HSM cluster |
| *"Manage TLS certificates"* | **AWS Certificate Manager (ACM)** | ACM provisions/renews certs; ACM uses KMS for private CA keys but isn't KMS |
| *"Encrypted string parameters"* | **SSM Parameter Store SecureString** (which uses KMS) | Different storage layer; KMS is the encryption backend |
| *"Encrypt my data with my own algorithm offline"* | **AWS Encryption SDK / S2N** | Client-side libraries; can use KMS-supplied data keys but aren't KMS |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **KMS Key** (formerly "CMK" — Customer Master Key) | The logical key resource. Three flavours: **AWS-managed** (free, used automatically by services like `aws/s3`), **customer-managed** ($1/mo + API calls, you control rotation/policy), **AWS-owned** (invisible, used by some services) |
| **Symmetric vs Asymmetric** | Symmetric (256-bit AES-GCM) = single key encrypts + decrypts; most common. Asymmetric (RSA/ECC) = public/private pairs; for signing, verification, or encryption where caller can't have the private key |
| **Envelope encryption** | The killer pattern: KMS encrypts a **data key**, the data key encrypts your actual data. Lets you encrypt huge files with one KMS API call |
| **Key policy** | Resource-based policy *on the key itself*. Combined with IAM policies via the standard AND/OR rules. **Required** — even root user needs an explicit grant in the key policy |
| **Grant** | Temporary, programmatic delegation of key permissions — used by services like RDS that need to use your key on your behalf |
| **Alias** | Friendly name pointing at a key (e.g. `alias/prod-database`). Use these in code, not raw key IDs |
| **Multi-region key** | One logical key replicated across regions — same key material, same key ID. Required for cross-region snapshot copies and global apps |
| **Imported key material (BYOK)** | You generate key material elsewhere and import into KMS — KMS stores it but didn't create it. Lets you keep an offline master key |
| **KMS Custom Key Store** | Back a KMS key with a CloudHSM cluster you own — best of both worlds for high-compliance workloads |

### Envelope Encryption — How It Actually Flows

The single most important KMS pattern. Without it, every encrypt/decrypt would need a KMS API call, hitting rate limits and 4 KB payload caps.

```
1. App calls KMS GenerateDataKey(KeyId=alias/my-key)
       ↓
2. KMS returns BOTH:
     - Plaintext data key (use this NOW, then throw away)
     - Encrypted data key (store this with your data)
       ↓
3. App uses the plaintext data key to encrypt local data with AES-GCM
       ↓
4. App writes to disk/S3:
     [ encrypted data | encrypted data key ]
       ↓
5. App wipes the plaintext data key from memory
       ↓
   ─── later, to decrypt ───
       ↓
6. App reads [ encrypted data | encrypted data key ] from storage
       ↓
7. App calls KMS Decrypt(CiphertextBlob=encrypted data key)
       ↓
8. KMS returns the plaintext data key
       ↓
9. App decrypts data locally, then wipes the data key again
```

**Why this pattern wins:** one KMS API call lets you encrypt arbitrarily large data. The KMS master key never leaves AWS. Even AWS staff can't see your plaintext data keys — they only exist in your app's memory.

### Common Use Cases (where KMS hides underneath)

| Service | How it uses KMS |
| ------- | --------------- |
| **S3 SSE-KMS** | Each object encrypted with a data key wrapped by your KMS key |
| **EBS volume encryption** | Volume encrypted with a KMS-derived data key |
| **RDS / Aurora encryption** | Storage layer encrypted via KMS |
| **Secrets Manager** | Secret values stored encrypted with KMS |
| **Parameter Store SecureString** | Same — KMS-encrypted parameter values |
| **Lambda environment variables** | Optional KMS encryption for env vars at rest |
| **CloudTrail log file encryption** | KMS encrypts log files in S3 |

### Key Policies vs IAM Policies — the Gotcha

Unlike most resource policies in AWS, a KMS **key policy is required** and acts as the **primary** authorisation source. IAM policies alone cannot grant access to a key — the key policy must explicitly allow it (typically by saying "allow IAM to be used", which then defers to IAM policies).

```json
// Minimal key policy — must include something like this
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": "kms:*",
  "Resource": "*"
}
```

That `Principal: root` doesn't mean "the root user" — it means "any IAM principal in this account, subject to IAM policies". Without it, IAM policies granting KMS permissions don't work.

**Exam trap:** *"Why can't this IAM user use the key despite having `kms:Decrypt` in their IAM policy?"* → **Key policy doesn't include them or doesn't defer to IAM**.

### Worked Example: S3 Cross-Bucket Replication with SSE-KMS

The classic exam scenario that ties KMS + IAM + S3 + key policies together. Setup:

> *Source bucket encrypted with SSE-KMS (Key A). Target bucket encrypted with SSE-KMS (Key B). You configure S3 replication, both buckets, both KMS keys exist. **Replication is still not working.** What's missing?*

The answer hinges on **three commonly-missed pieces**, in order of how often they trip people up:

#### 1. The opt-in flag (most commonly missed)

By default, S3 replication **silently skips** SSE-KMS encrypted objects. You have to explicitly opt in via `SseKmsEncryptedObjects.Status = Enabled` in the replication rule:

```json
{
  "Rules": [{
    "SourceSelectionCriteria": {
      "SseKmsEncryptedObjects": {
        "Status": "Enabled"          ← THE OPT-IN
      }
    },
    "Destination": {
      "Bucket": "arn:aws:s3:::target-bucket",
      "EncryptionConfiguration": {
        "ReplicaKmsKeyID": "arn:aws:kms:region:acct:key/TARGET-KEY-ID"
      }
    }
  }]
}
```

Without this flag, replication appears to "work" — unencrypted objects flow through, metrics look healthy — but every KMS-encrypted object is silently absent at the target. Brutal to debug.

#### 2. The replication IAM role's KMS permissions

S3 replication runs as an IAM role that S3 assumes. To replicate a KMS-encrypted object, the role must be able to **decrypt** with the source key and **encrypt** with the target key:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Decrypt"],
  "Resource": "arn:aws:kms:region:acct:key/SOURCE-KEY-ID"
},
{
  "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:GenerateDataKey"],
  "Resource": "arn:aws:kms:region:acct:key/TARGET-KEY-ID"
}
```

Without this, the replication role can replicate **unencrypted** objects fine — but every SSE-KMS object fails.

#### 3. The KMS key policies on BOTH keys

Remember the double-gate from the previous subsection: **key policies are required; IAM alone doesn't grant access**. So both keys' key policies must also allow the replication role:

- **Source key policy:** allow the replication role to `kms:Decrypt`
- **Target key policy:** allow the replication role to `kms:Encrypt` + `kms:GenerateDataKey`

Missing either key policy entry → replication still fails, even with perfect IAM policy.

#### The full checklist (in order of "most commonly missing")

```
1. ✅ SseKmsEncryptedObjects.Status = Enabled in the replication rule
2. ✅ Replication IAM role has KMS perms (Decrypt on source, Encrypt + GenerateDataKey on target)
3. ✅ Source KMS key policy grants the replication role kms:Decrypt
4. ✅ Target KMS key policy grants the replication role kms:Encrypt + kms:GenerateDataKey
5. ✅ Destination config specifies ReplicaKmsKeyID
6. ✅ Source bucket has versioning enabled (replication requires it)
7. ✅ Target bucket has versioning enabled
8. ✅ Replication role trust policy allows s3.amazonaws.com to assume it
```

#### Why this trips people up

The console UI buries the opt-in. You click through "create replication rule," select source / destination / role, and the rule appears "configured" — nothing flags that KMS-encrypted objects need a separate opt-in. People often only discover this when an audit finds half the data missing at the target.

#### The Mental Model

> *S3 replication is "S3 service acting as a courier." It can deliver an unencrypted parcel just by knowing where to take it. But if the parcel is locked (KMS-encrypted), the courier needs the key to open it AND the key to lock the new parcel at the destination. The courier's keychain = the IAM role's KMS permissions. The lockmaker's permission slip = the KMS key policy. The shipping order has to specifically say "yes, also deliver locked parcels" — that's the SseKmsEncryptedObjects opt-in.*

#### Exam framing variants

| Question phrasing | Most likely answer |
| ----------------- | ------------------ |
| *"Replication configured, KMS keys exist, KMS-encrypted objects aren't replicating"* | **Opt-in: `SseKmsEncryptedObjects: Enabled` in the rule** |
| *"Replication role exists, KMS keys exist, replication fails for encrypted objects"* | **Role needs `kms:Decrypt` on source + `kms:Encrypt`/`kms:GenerateDataKey` on target; both key policies must also allow the role** |
| *"Cross-region replication with KMS"* | Plus **multi-region key** OR re-encryption with target-region key during copy |
| *"Cross-account replication with KMS"* | Plus **target bucket policy** allowing source account's replication role to write |

### When to Use CloudHSM Instead

CloudHSM is the **dedicated single-tenant hardware HSM** alternative to KMS. Same crypto operations, very different operational model.

| | **AWS KMS** | **AWS CloudHSM** |
| - | ----------- | ----------------- |
| Tenancy | **Multi-tenant** (shared HSM, AWS-managed) | **Single-tenant** (you get your own HSM cluster) |
| FIPS 140-2 level | **Level 3** for HSM module (overall service Level 2) | **Level 3** end-to-end |
| Who controls keys | AWS manages HSMs; you control key policies + usage | **You** control the HSM, the keys, and the access |
| Who can see keys | AWS staff can't access plaintext, but operationally AWS runs the HSMs | **Only you** — AWS has no access to the HSM cluster |
| Cost | $1/key/month + API call charges | **~$1.45/hour per HSM** (~$1,050/month per HSM, typically 2+ for HA) |
| Setup complexity | One click — instantly available | Provision cluster + manage client config + cross-account setup |
| Use case | 95% of workloads | Compliance demanding HSM ownership; offload TLS termination from EC2; SQL Server TDE with own HSM; PKI root CA |
| Integration with AWS services (S3, RDS, etc.) | ✅ Native | ⚠️ Indirect (via **KMS Custom Key Store** backed by CloudHSM) |

**The bridge: KMS Custom Key Store** — back a KMS key with a CloudHSM cluster. KMS API surface stays the same (so S3, RDS, etc. work normally), but the underlying key material lives in *your* HSM. Best of both worlds for high-compliance workloads that still want AWS-service integration.

**Exam triggers (CloudHSM-specific):**
- *"FIPS 140-2 Level 3 single-tenant dedicated hardware"* → **CloudHSM**
- *"Regulation requires AWS to have no access to our keys"* → **CloudHSM** (not KMS)
- *"Offload SSL termination from EC2 to a dedicated HSM"* → **CloudHSM**
- *"Run a private CA root key in dedicated hardware"* → **CloudHSM**
- *"Get KMS-style integration but with my own HSM hardware"* → **KMS Custom Key Store + CloudHSM**

For everything else (S3 encryption, EBS encryption, RDS encryption, Secrets Manager) → **KMS** is the right answer.

### Common Anti-patterns (exam wrong answers)

- *"Use a customer-managed key when an AWS-managed key would suffice"* → wasted $1/mo + API costs per key; only go custom when you need control over rotation/policy
- *"Hard-code key IDs in code"* → use **aliases** so key rotation/migration doesn't break code
- *"Disable key rotation to save money"* → annual rotation is free and zero-config; just turn it on
- *"Single-region key for cross-region snapshot copy"* → fails. Use a **multi-region key** for cross-region replication
- *"Call KMS Encrypt for every record"* → hits API rate limits; use **envelope encryption** with locally-cached data keys
- *"IAM policy alone grants key access"* → no, key policy must allow it too
- *"Use KMS to store database passwords"* → wrong service; **Secrets Manager** stores+rotates, KMS just encrypts

### Exam Triggers

- *"Centrally managed encryption keys with rotation"* → **AWS KMS**
- *"Bring your own key material"* → **KMS imported key material**
- *"Dedicated single-tenant hardware HSM, FIPS 140-2 Level 3"* → **AWS CloudHSM** (not KMS)
- *"Encrypt across regions"* → **KMS multi-region keys**
- *"Temporary access for a service to use a key"* → **KMS Grant**
- *"Encrypt huge files without API call per record"* → **Envelope encryption**
- *"Automated annual key rotation, zero app changes"* → **KMS automatic rotation** (customer-managed keys)
- *"Cross-region EBS snapshot copy fails to decrypt"* → snapshot encrypted with **single-region key**; need multi-region
- *"Encrypt secret database password"* → **Secrets Manager** (which uses KMS underneath)

**The 80/20:** *KMS = managed crypto key service that almost every AWS service uses for encryption at rest. Three key flavours: **AWS-managed** (free, automatic), **customer-managed** ($1/mo, you control), **AWS-owned** (invisible). **Envelope encryption** is the foundational pattern — KMS encrypts data keys, data keys encrypt your data. Keys are protected by **key policies** (required) + IAM policies + grants. **Multi-region keys** for cross-region scenarios. **CloudHSM** for dedicated single-tenant; KMS for everything else.*

## AWS Certificate Manager (ACM)

**Anchored as KMS's sibling.** *KMS = encryption at rest. **ACM = TLS / encryption in transit.*** ACM provisions, manages, and **auto-renews** public + private TLS/SSL certificates and deploys them directly into AWS services that terminate TLS (CloudFront, ALB, NLB, API Gateway, etc.). Public certificates are **free**. The catch: ACM keeps the private key inside AWS — you can't export it.

### What ACM is NOT

| Question | Service | Not ACM because... |
| -------- | ------- | ------------------ |
| *"Encrypt data at rest"* | **AWS KMS** | KMS handles encryption-at-rest keys; ACM handles TLS certs (encryption in transit) |
| *"Store arbitrary secrets"* | **AWS Secrets Manager** | Secrets Manager stores generic secrets; ACM is purpose-built for X.509 certs |
| *"Manage DNS records"* | **Route 53** | Route 53 is DNS; ACM *uses* Route 53 records for domain validation but isn't DNS |
| *"Code signing certificates"* | **AWS Signer** | Different lifecycle and trust model |
| *"Deploy a TLS cert onto an EC2 nginx web server"* | Buy/manage cert externally (Let's Encrypt, etc.) | ACM **won't let you export the private key** — only AWS services with native ACM integration can use it |
| *"Issue internal mTLS certs for microservices"* | **AWS Certificate Manager Private CA** (ACM PCA) | Public ACM issues *publicly trusted* certs only — for internal trust you need a private CA |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Public certificate** | Publicly trusted X.509 cert issued by **Amazon Trust Services**. Free. Must validate domain ownership |
| **Private certificate** | Issued by your **ACM Private CA** — trusted only by clients you've given the CA's root to. For internal mTLS, service-to-service auth |
| **Imported certificate** | A cert you bought from a third party (DigiCert, Let's Encrypt, etc.) that you import into ACM. **No auto-renewal** — you manage rotation |
| **Domain validation** | Two flavours: **DNS validation** (preferred — add a CNAME, ACM checks it, auto-renewable forever) or **email validation** (manual click on email; doesn't auto-renew well) |
| **Wildcard cert** | One cert covering `*.example.com` (any single-level subdomain). Free in ACM |
| **Multi-SAN cert** | One cert covering multiple domains: `example.com`, `www.example.com`, `api.example.com`. Subject Alternative Names list |
| **Auto-renewal** | ACM-issued certs with DNS validation renew automatically before expiry — zero touch. Imported certs do NOT auto-renew |
| **Region scope** | Most ACM certs are **regional**. **CloudFront certs must be in `us-east-1`** (CloudFront is global but its config layer is anchored there) |

### How DNS Validation Actually Flows

```
1. Request a public certificate via ACM:
     aws acm request-certificate --domain-name example.com \
                                 --validation-method DNS
       ↓
2. ACM returns a unique CNAME record name + value, e.g.:
     _abc123.example.com  CNAME  _xyz789.acm-validations.aws
       ↓
3. You add that CNAME to your DNS provider
   (If using Route 53: one-click "Create record in Route 53" from console)
       ↓
4. ACM polls DNS for the CNAME — typically resolves within 5 minutes
       ↓
5. Validation succeeds → certificate ISSUED status; ready to attach
       ↓
6. Attach cert to CloudFront / ALB / API Gateway (via console / IaC)
       ↓
7. ACM continues monitoring the CNAME forever
       ↓
8. ~60 days before expiry: ACM auto-renews — if CNAME still present,
   new cert issued and silently rotated under the same ARN. Zero downtime
```

**Why DNS validation beats email validation:** auto-renewable. As long as the CNAME stays in place, the cert renews forever without human intervention. Email validation requires someone to click a link every renewal — fine for one cert, painful for fifty.

### Where You Can Attach an ACM Cert

| Service | Notes |
| ------- | ----- |
| **CloudFront distribution** | Cert **must be in `us-east-1`** regardless of where the rest of your infra lives |
| **Application Load Balancer (ALB)** | Cert in **the same region as the ALB** |
| **Network Load Balancer (NLB)** | TLS termination at NLB — cert in same region |
| **API Gateway** | REST + HTTP APIs (custom domains) |
| **Cognito user pool custom domain** | Cert must be in `us-east-1` (Cognito uses CloudFront under the hood) |
| **AWS App Runner** | Custom domain certs |
| **Elastic Beanstalk** | Via the underlying ALB/CLB |
| **AWS Nitro Enclaves** | Specific use case |
| **EC2 / your own web server (nginx, Apache)** | ❌ **Not directly** — private key can't be exported |

**Exam trap:** *"Cert deployed to ALB but the CloudFront in front of it can't use the same cert"* → cert is in the wrong region (CloudFront needs `us-east-1`; ALB cert is wherever the ALB lives). Solution: **issue a second cert in `us-east-1`** for CloudFront, or use the same cert if you happen to be in `us-east-1` already.

### ACM Private CA (PCA) — the Internal mTLS Story

When you need certs trusted only inside your org (service-to-service mTLS, internal admin tools, IoT devices):

| Feature | Detail |
| ------- | ------ |
| **CA hierarchy** | Root CA → Subordinate CAs → leaf certificates. Mirrors traditional PKI |
| **Cost** | **$400/month per CA** + per-certificate issuance fee. Expensive — only pay for it when you actually need internal PKI |
| **Use cases** | Kubernetes service mesh mTLS (Istio/Linkerd), microservice authentication, IoT device identity, internal HTTPS that you don't want public CAs to issue for |
| **Integrates with** | ACM (PCA-issued certs can be deployed via ACM into ALB/CloudFront/etc. as internal-trust certs), Kubernetes cert-manager via AWS Privateca Issuer |
| **vs Public ACM** | Public ACM issues certs trusted by every browser. PCA issues certs trusted only by clients that have your CA root |

**Exam trigger:** *"internal mTLS between microservices in a private VPC"* → **ACM Private CA**, not public ACM.

### Common Anti-patterns (exam wrong answers)

- *"Buy TLS certs from a third party for an ALB"* → use **ACM public certs** (free + auto-renew)
- *"Deploy ACM cert to nginx on EC2"* → can't — private key isn't exportable. Use Let's Encrypt + certbot, or a CloudFront/ALB in front
- *"Use the ALB's regional cert for CloudFront"* → CloudFront needs the cert in **`us-east-1`**
- *"Email-validate certs in an automated pipeline"* → use **DNS validation** so it's auto-renewable
- *"Import a third-party cert and forget about it"* → **imported certs don't auto-renew**; set a CloudWatch alarm on expiry
- *"Use public ACM for internal service-to-service mTLS"* → public CAs won't issue for internal hostnames; use **ACM Private CA**
- *"Single cert covering example.com and api.example.com via wildcard `*.example.com`"* → wildcard only covers **one level** (`api.example.com`, but not `v1.api.example.com`); use a **multi-SAN cert**

### Exam Triggers

- *"Free TLS certs for an ALB / CloudFront / API Gateway"* → **AWS Certificate Manager (public)**
- *"Automatic cert renewal, no manual steps"* → **ACM-issued cert + DNS validation**
- *"Cert for CloudFront distribution"* → **ACM cert in `us-east-1`**
- *"Internal mTLS between microservices"* → **ACM Private CA**
- *"Migrated cert from another provider, want to keep using it"* → **Import into ACM** (no auto-renewal though)
- *"Cover multiple subdomains with one cert"* → **wildcard `*.example.com`** or **multi-SAN cert**
- *"Deploy cert to EC2 web server"* → ACM **can't export the private key** — use a CloudFront/ALB front, or use a non-ACM cert
- *"Why did renewal fail?"* → DNS CNAME was removed, or email validation wasn't re-done
- *"Issue private certs for VPN clients / IoT devices"* → **ACM Private CA** with a custom root distributed to those clients
- *"Set a CloudWatch alarm on cert expiry"* → use **`DaysToExpiry` metric** (especially for imported certs that don't auto-renew)

**The 80/20:** *ACM = managed TLS cert service. **Public certs are free + auto-renew** when issued by ACM with DNS validation. Attaches to **CloudFront (`us-east-1` only) / ALB / NLB / API Gateway / Cognito / App Runner** — not raw EC2 (no exportable private key). **Imported certs don't auto-renew.** For internal mTLS / service-to-service, use **ACM Private CA** ($400/month per CA, paid). Wildcards cover one subdomain level; multi-SAN covers multiple explicit domains. **ACM is to TLS in transit what KMS is to encryption at rest.***

## AWS Secrets Manager

**Anchored against HashiCorp Vault, but managed.** Secrets Manager stores, retrieves, and **automatically rotates** secrets (database credentials, API keys, OAuth tokens). Every secret is KMS-encrypted at rest. The headline feature is **native rotation** for AWS databases — no Lambda code required.

### What Secrets Manager is NOT

| Question | Service | Not Secrets Manager because... |
| -------- | ------- | ------------------------------ |
| *"Store cheap config values for my app"* | **SSM Parameter Store (Standard)** | Free up to 10,000 — Secrets Manager charges $0.40 per secret per month |
| *"Encrypt arbitrary data"* | **AWS KMS** | KMS does the encryption; Secrets Manager stores secret lifecycle on top of KMS |
| *"Manage TLS certificates"* | **AWS Certificate Manager (ACM)** | ACM provisions/renews certs — different lifecycle |
| *"Human-facing password manager"* | **1Password / Bitwarden / Vault UI** | Secrets Manager is for *applications* fetching secrets, not humans browsing them |
| *"Store binary blobs"* | **S3 + KMS** | Secrets Manager caps at 64 KB per secret |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Secret** | Name + value (string up to 64 KB, usually JSON) + metadata + KMS encryption. Value can be any string, often a JSON blob like `{"username": "alice", "password": "..."}` |
| **Staging labels** | Version pointers: **`AWSCURRENT`** (the live version), **`AWSPENDING`** (version being rotated to, mid-rotation), **`AWSPREVIOUS`** (last version, for rollback) |
| **Automatic rotation** | Schedule-driven re-issuing of the secret. **Native** for RDS / Aurora / DocumentDB / Redshift. **Custom Lambda** for everything else (third-party APIs, SaaS, etc.) |
| **Rotation strategies** | **Single-user** (one DB user whose password gets rotated — brief outage window) vs **Alternating-user** (two users, one always live — zero-downtime) |
| **Resource policy** | Resource-based policy on the secret — used for **cross-account access** (which Parameter Store can't do) |
| **Multi-region replication** | Native: pick a primary region + N replica regions. Updates to the primary propagate. Used for DR and globally distributed apps |
| **GetRandomPassword API** | Generates cryptographically strong random passwords (with configurable length, character set) — you don't have to write the entropy code |
| **Caching client library** | Official SDK for Java/Python/Node that caches secrets in memory to avoid the $0.05-per-10k-calls API cost |

### How Rotation Actually Flows (numbered)

Secrets Manager's rotation Lambda follows a strict four-step lifecycle. Whether AWS-managed (native) or your custom Lambda, all four steps must succeed for rotation to finish.

```
1. createSecret
       ↓ Lambda generates a new secret value (or fetches from RDS, etc.)
       ↓ Stores it under the AWSPENDING staging label
       ↓ (AWSCURRENT still points to the old value at this stage)
       ↓
2. setSecret
       ↓ Lambda updates the TARGET system with the new value
       ↓ e.g. for RDS: ALTER USER appuser IDENTIFIED BY 'new-password'
       ↓ The DB now accepts both old + new (during the transition)
       ↓
3. testSecret
       ↓ Lambda verifies the new value works against the target
       ↓ e.g. opens a new DB connection with the new credentials
       ↓ If fails → rotation aborts, AWSPENDING discarded
       ↓
4. finishSecret
       ↓ Lambda moves the AWSCURRENT label from old version → new version
       ↓ Old version becomes AWSPREVIOUS
       ↓ New value is now live for all consumers
```

**Why staging labels matter:** apps fetch via `AWSCURRENT`. The label move is atomic, so consumers either get the old value or the new value, never both. Rollback is just moving the label back to AWSPREVIOUS.

### Single-User vs Alternating-User Rotation

| | Single-user | Alternating-user |
| - | ----------- | ---------------- |
| Approach | One DB user; rotate its password | Two DB users (e.g. `app_user_1`, `app_user_2`) — one active, one being rotated |
| Brief outage during rotation? | ✅ Yes (window between setSecret and finishSecret) | ❌ No — the inactive user is being rotated while the active one serves traffic |
| Setup complexity | Lower | Higher (need to provision the second user, both granted same permissions) |
| Use when | OK with occasional sub-second rotation hiccup | Zero-downtime required |

**Exam trigger:** *"rotate RDS credentials with zero downtime"* → **alternating-user rotation strategy**.

### Common Anti-patterns (exam wrong answers)

- *"Store every config value in Secrets Manager"* → expensive; use **Parameter Store** for non-rotating config
- *"Rotate credentials by manually editing the secret"* → defeats the purpose; configure **automatic rotation**
- *"Use Secrets Manager for files > 64 KB"* → wrong tool; use S3 + KMS
- *"Single-user rotation for a high-traffic production database"* → consider **alternating-user** to avoid the rotation outage window
- *"App fetches the secret on every request"* → use the **caching client library** or Lambda extension; API calls add up
- *"Share secrets between accounts by copying"* → use **resource policy** for cross-account access

### Exam Triggers

- *"Automatically rotate RDS / Aurora / DocumentDB credentials"* → **Secrets Manager native rotation**
- *"Rotate credentials with zero downtime"* → **alternating-user rotation**
- *"Cross-account access to a secret via resource policy"* → **Secrets Manager**
- *"Replicate a secret across regions for DR"* → **Secrets Manager multi-region replication**
- *"Generate cryptographically strong passwords via API"* → **`GetRandomPassword`**
- *"Test rotation before going live"* → **AWSPENDING staging label**
- *"Roll back to previous secret version"* → move **AWSCURRENT** back to **AWSPREVIOUS**
- *"Rotate third-party API key (not an AWS database)"* → **custom Lambda rotation function**
- *"Reduce Secrets Manager API costs"* → **caching client library** or **Lambda Secrets Manager extension**

**The 80/20:** *Secrets Manager = managed secret lifecycle service. **Stores + retrieves + rotates** secrets, KMS-encrypted, $0.40/secret/month. **Native rotation** for RDS/Aurora/DocumentDB/Redshift; **custom Lambda** for everything else. **AWSCURRENT/AWSPENDING/AWSPREVIOUS** staging labels manage atomic version transitions. **Alternating-user** rotation = zero downtime. **Resource policy** enables cross-account sharing; **multi-region replication** for DR. **64 KB cap** per secret. Pairs with Parameter Store: hierarchical config in Parameter Store, rotating secrets in Secrets Manager, referenced from Parameter Store via `/aws/reference/secretsmanager/...`.*

## AWS Systems Manager Parameter Store

**Anchored against etcd or Consul KV — but free for most use cases and part of AWS Systems Manager.** Parameter Store is a managed key-value store for application **configuration** (and SecureString secrets too if you want). Standard tier is free up to 10,000 parameters per account per region — which is why most companies use it for config alongside Secrets Manager for true rotating secrets.

### What Parameter Store is NOT

| Question | Service | Not Parameter Store because... |
| -------- | ------- | ------------------------------ |
| *"Automatically rotate RDS credentials"* | **Secrets Manager** | Parameter Store has no built-in rotation — you'd build it with EventBridge + Lambda |
| *"Cross-account secret sharing via resource policy"* | **Secrets Manager** | Parameter Store doesn't support resource policies — IAM only |
| *"Multi-region replication of a value"* | **Secrets Manager** (or build with EventBridge + Lambda) | Parameter Store is per-region; no native replication |
| *"Encrypt arbitrary data"* | **AWS KMS** | KMS does the encryption; Parameter Store SecureString uses KMS under the hood |
| *"Database for app state"* | **DynamoDB / RDS** | Parameter Store has rate limits and is for *config*, not runtime data |
| *"Store files / binary blobs"* | **S3** | 4 KB (Standard) / 8 KB (Advanced) cap per parameter |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Parameter** | Name + value + type. The name is a **path** like `/myapp/prod/db/host` |
| **Types** | **String** (plain text), **StringList** (comma-separated), **SecureString** (KMS-encrypted) |
| **Tiers** | **Standard** — free, ≤10,000 params per account/region, 4 KB max value, no policies. **Advanced** — $0.05/param/month, ≤100,000 params, 8 KB max, supports parameter policies + change notifications |
| **Hierarchical paths** | `/<app>/<env>/<service>/<key>` — fetch a whole tree with `GetParametersByPath` |
| **Versioning** | Up to 100 versions per parameter. Reference a specific version via `:<n>` suffix |
| **Public parameters** | AWS-published parameters (e.g. `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64`) — read-only, free, auto-updated by AWS |
| **Parameter policies** (Advanced only) | Expiration (auto-delete after date), expiration notification, no-change notification |
| **References to Secrets Manager** | `/aws/reference/secretsmanager/<secret-name>` — Parameter Store transparently resolves to the secret. Lets your app read everything from one API |
| **Integrations** | ECS task definitions (`valueFrom`), Lambda env vars, CodeBuild, CloudFormation dynamic references (`{{resolve:ssm:...}}`), EC2 user data |

### Standard vs Advanced Tier — When to Upgrade

| | Standard (free) | Advanced ($0.05/param/month) |
| - | --------------- | ---------------------------- |
| Max parameters per account/region | 10,000 | 100,000 |
| Max value size | 4 KB | 8 KB |
| Parameter policies | ❌ | ✅ (expiration, notification) |
| Change notifications via EventBridge | ❌ | ✅ |

**Decision rule:** Standard for almost everything. Only go Advanced if you need (a) > 10,000 params, (b) > 4 KB values, or (c) auto-expiration / change notifications.

### Common Patterns

#### Hierarchical configuration with `GetParametersByPath`

```
/myapp/prod/db/host        → "db.example.com"
/myapp/prod/db/port        → "5432"
/myapp/prod/db/username    → "appuser"
/myapp/prod/feature-flags/dark-mode → "enabled"
/myapp/prod/api/timeout-ms → "5000"
```

App calls `ssm:GetParametersByPath(Path="/myapp/prod/")` once at startup and gets the whole tree — cheap, fast, structured.

#### The hybrid pattern (config in Parameter Store, secrets in Secrets Manager)

```
Parameter Store (free, hierarchical)
├── /myapp/prod/db/host       → "db.example.com"
├── /myapp/prod/db/port       → "5432"
├── /myapp/prod/db/username   → "appuser"
└── /myapp/prod/db/password   → /aws/reference/secretsmanager/myapp-prod-db-pwd

Secrets Manager (paid, rotating)
└── myapp-prod-db-pwd          → actual rotating password, auto-rotated every 30 days
```

The app reads everything from Parameter Store; rotating secrets are transparently resolved from Secrets Manager.

#### Latest AMI lookup (public parameter)

```bash
aws ssm get-parameter \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 \
  --query 'Parameter.Value' --output text
```

Used in CloudFormation / Terraform / launch templates so you don't hard-code stale AMI IDs.

### Secrets Manager vs Parameter Store — the Comparison

The exam decision most people get wrong:

| Feature | Parameter Store | Secrets Manager |
| ------- | --------------- | --------------- |
| **Pricing** | Standard: **free** (≤10,000). Advanced: $0.05/param/month | **$0.40/secret/month** + API call charges |
| **Max value size** | 4 KB (Standard) / 8 KB (Advanced) | **64 KB** |
| **Built-in rotation** | ❌ DIY with EventBridge + Lambda | ✅ **Native** for RDS / Aurora / DocumentDB / Redshift |
| **Cross-account resource policy** | ❌ IAM only | ✅ Native |
| **Multi-region replication** | ❌ DIY | ✅ Native |
| **Hierarchical paths** | ✅ `/prod/db/password` | ❌ Flat namespace |
| **Versioning** | ✅ up to 100 versions | ✅ with staging labels |
| **Generated random passwords** | ❌ | ✅ `GetRandomPassword` |
| **Stores arbitrary config + secrets** | ✅ Mix freely | ❌ Secrets only |
| **Public parameters** (AWS-published) | ✅ | ❌ |

#### The decision rule

```
Does the value need automatic rotation managed by AWS?
  ├── YES → Secrets Manager
  └── NO  → Does it need cross-account resource policies, multi-region replication,
            or > 8 KB values?
              ├── YES → Secrets Manager
              └── NO  → Parameter Store Standard (free)
```

### Common Anti-patterns (exam wrong answers)

- *"Use Secrets Manager for every config value"* → expensive at scale; **Parameter Store** is free for config
- *"Store rotating DB credentials in Parameter Store"* → no native rotation; use **Secrets Manager**, or reference from Parameter Store
- *"Hit Parameter Store on every Lambda invocation"* → rate limits + cold-start latency; cache locally or use Lambda extensions
- *"Use Advanced tier for everything"* → unnecessary cost; Standard is enough for most params
- *"Hard-code AMI IDs"* → use **public Parameter Store parameters** for latest-AMI lookup
- *"Flat parameter names like `prod_db_host`"* → use hierarchical paths so `GetParametersByPath` works

### Exam Triggers

- *"Cheapest way to store 500 config values"* → **Parameter Store Standard** (free)
- *"Fetch a whole tree of app config in one call"* → **`GetParametersByPath`**
- *"Store latest Amazon Linux AMI by name"* → **Parameter Store public parameter** (`/aws/service/ami-amazon-linux-latest/...`)
- *"Reference a Secrets Manager secret from Parameter Store"* → **`/aws/reference/secretsmanager/<name>`** syntax
- *"Auto-expire a parameter after a date"* → **Parameter Store Advanced tier policy**
- *"Notify on parameter change"* → **Advanced tier + EventBridge**
- *"Inject config into ECS task definition without code changes"* → **`valueFrom` referencing Parameter Store** (or Secrets Manager)
- *"App needs both config and rotating DB password"* → **Hybrid: Parameter Store for config + reference to Secrets Manager**

**The 80/20:** *Parameter Store = part of SSM, **free up to 10,000 params** on Standard tier, hierarchical paths (`/app/env/key`), three types (String / StringList / SecureString-KMS). Use for **config + non-rotating secrets**. Pair with Secrets Manager via `/aws/reference/secretsmanager/...` reference syntax so apps read everything from one API but rotating secrets are managed by Secrets Manager. **Advanced tier** ($0.05/param/month) only when you need >10,000 params, >4 KB values, expiration policies, or change notifications. Public parameters give you AWS-published values like latest AMIs.*

## Amazon GuardDuty

**Anchored against Datadog Security Monitoring or Splunk SIEM detection rules — but AWS-native and agentless.** GuardDuty continuously analyses CloudTrail, VPC Flow Logs, and DNS query logs using ML and threat intelligence, then emits **findings** for suspicious behaviour. Zero agents, zero infrastructure to manage. Enable it and findings start appearing within minutes.

### What GuardDuty is NOT

| Question | Service | Not GuardDuty because... |
| -------- | ------- | ------------------------ |
| *"Aggregate findings from many sources into one dashboard"* | **AWS Security Hub** | Security Hub *consumes* GuardDuty findings; GuardDuty is one source among many |
| *"Scan EC2 / Lambda / container images for software vulnerabilities (CVEs)"* | **Amazon Inspector** | Inspector = static vulnerability scanning; GuardDuty = behavioural threat detection |
| *"Classify sensitive data in S3 (PII, PHI)"* | **Amazon Macie** | Macie inspects *data*; GuardDuty inspects *behaviour* |
| *"Deep-dive investigation of an incident across logs"* | **Amazon Detective** | Detective is the forensic analysis tool that complements GuardDuty findings |
| *"Full SIEM with custom queries on raw logs"* | **Amazon OpenSearch / Splunk** | GuardDuty doesn't store raw logs — pipe findings into a SIEM if you need that |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Finding** | A detection event with severity (Low / Medium / High), affected resource, evidence (which API call, source IP, threat intel match), and a finding type like `Backdoor:EC2/C&CActivity.B` |
| **Always-on data sources** | CloudTrail management events + VPC Flow Logs + Route 53 DNS query logs. No setup — GuardDuty reads them directly via a service-linked role |
| **Optional protection plans** (paid) | **S3 Protection** (CloudTrail data events for S3), **EKS Protection** (Kubernetes audit logs), **Malware Protection** (snapshot-scan EBS on suspicious EC2), **RDS Protection** (login activity), **Lambda Protection** (network activity), **Runtime Monitoring** (EKS/ECS/EC2 agent-based runtime threats) |
| **Trusted IP / threat lists** | Custom IP allow-lists or block-lists (your own threat intel) |
| **Multi-account** | Delegated administrator in Organizations — one security account sees findings org-wide |
| **EventBridge integration** | Every finding auto-emits an EventBridge event — feeds Security Hub, Lambda auto-remediation, SNS alerting, Slack |

### How GuardDuty Actually Detects Things

```
1. GuardDuty's service-linked role consumes (no setup needed):
     - CloudTrail management events from every region
     - VPC Flow Logs from every ENI
     - Route 53 Resolver DNS query logs
   (Plus optional sources if enabled)
       ↓
2. AWS-managed ML models + threat-intel feeds + behavioural baselines
   analyse the combined stream in near-real-time
       ↓
3. If a pattern matches a finding type → finding emitted
   Example: an EC2 instance making DNS queries to a known botnet C2 domain
   AND VPC Flow Logs show outbound traffic to its IP → Backdoor:EC2/C&CActivity.B
       ↓
4. Finding appears in GuardDuty console (and propagates to Security Hub if enabled)
       ↓
5. EventBridge automatically receives the finding event
       ↓
6. EventBridge rule routes to:
     - SNS topic → PagerDuty / Slack
     - Lambda → auto-quarantine instance (revoke SG, isolate)
     - Step Functions → human-in-the-loop incident response
     - Security Hub → centralised finding management
```

**Why the agentless angle matters:** GuardDuty reads existing AWS log streams. It can't be disabled by a compromised instance (the instance never knew it was being watched). Compare to host-based agents which an attacker can kill once they're on the box.

### Common Finding Types (worth recognising on the exam)

| Finding | Meaning |
| ------- | ------- |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | IAM access key used from a known malicious IP |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from anomalous location |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | EC2 querying a known crypto mining pool DNS |
| `Backdoor:EC2/C&CActivity.B` | EC2 communicating with a known command-and-control server |
| `Recon:EC2/PortProbeUnprotectedPort` | EC2 being port-scanned from outside |
| `Exfiltration:S3/AnomalousBehavior` | S3 access pattern (volume / source IP) deviates from baseline |
| `Trojan:EC2/DNSDataExfiltration` | DNS tunneling exfiltration suspected |
| `Policy:IAMUser/RootCredentialUsage` | Root user API activity (always Medium severity) |

### Common Anti-patterns (exam wrong answers)

- *"Disable GuardDuty in some accounts to save money"* → blind spots in those accounts; cost is small relative to detection value
- *"Use GuardDuty to scan for software vulnerabilities"* → wrong service; **Inspector** does that
- *"Use GuardDuty to find sensitive data in S3"* → wrong service; **Macie** does that
- *"Treat GuardDuty as a SIEM"* → it's a detector; pipe findings into **Security Hub** or a real SIEM (Splunk, OpenSearch) for long-term storage / cross-correlation
- *"Each account manages its own GuardDuty findings"* in a multi-account org → use **delegated administrator** for org-wide central management
- *"Install GuardDuty agents on EC2"* → no agents; it's agentless (Runtime Monitoring is the only agent-based feature)

### Exam Triggers

- *"Detect compromised EC2 instance making unusual API calls / connecting to C2 server"* → **GuardDuty**
- *"Detect cryptocurrency mining on EC2"* → **GuardDuty** (specific finding type)
- *"Anomalous S3 download patterns / exfiltration"* → **GuardDuty S3 Protection**
- *"Malware on EC2 without installing agents"* → **GuardDuty Malware Protection** (snapshot-based EBS scan)
- *"EKS / Kubernetes API anomalies"* → **GuardDuty EKS Protection**
- *"Detect unauthorised IAM API activity"* → **GuardDuty** (paired with CloudTrail under the hood)
- *"Org-wide threat detection from a dedicated security account"* → **GuardDuty + delegated admin**
- *"Auto-quarantine compromised instance on finding"* → **GuardDuty finding → EventBridge → Lambda**

**The 80/20:** *GuardDuty = AWS-native, agentless, ML-driven threat detection. Always-on sources: CloudTrail + VPC Flow + DNS. Optional add-ons: S3 / EKS / Malware / RDS / Lambda Protection + Runtime Monitoring. Emits **findings** (severity Low/Medium/High, with finding-type strings like `Backdoor:EC2/C&CActivity.B`). Every finding hits EventBridge → automate response (SNS, Lambda, Security Hub). For multi-account: **delegated administrator** in Organizations. Pairs with Security Hub (aggregation) and Detective (investigation).*

## Amazon Inspector

**Anchored as GuardDuty's sibling — but for software, not behaviour.**

> *Inspector = "is this **software** dangerous?" (vulnerability scanner — mostly agentless).*
> *GuardDuty = "is this **behaviour** dangerous?" (threat detector — mostly agentless).*

Both lean agentless for the convenience win. Inspector needs an "agent" only on EC2, and even there it piggybacks on **SSM Agent** (already on AWS AMIs) rather than asking you to install something new.

### What Inspector is NOT

| Question | Service | Not Inspector because... |
| -------- | ------- | ------------------------ |
| *"Detect threats / suspicious behaviour"* | **Amazon GuardDuty** | GuardDuty = behavioural; Inspector = static analysis for known CVEs |
| *"Classify sensitive data (PII / PHI) in S3"* | **Amazon Macie** | Macie inspects *data content*; Inspector inspects *software vulnerabilities* |
| *"Investigate an incident across logs"* | **Amazon Detective** | Detective is forensic deep-dive; Inspector tells you what's vulnerable |
| *"Compliance configuration evaluation"* | **AWS Config + Conformance Packs** | Config = is this resource configured correctly. Inspector = does this resource have known CVEs |
| *"Aggregate findings org-wide"* | **AWS Security Hub** | Security Hub *consumes* Inspector findings; Inspector is one source |
| *"Scan source code for vulnerabilities (SAST)"* | **CodeGuru Security / Amazon Q Developer** | Inspector scans *built artefacts and runtime images*, not source code |

### Resource Types and Scan Modes

Inspector v2 covers **three resource types**, with different scan mechanisms per type:

| Resource | Scan mode | Agent? |
| -------- | --------- | ------ |
| **EC2 instances** | **Hybrid** — agent-based via SSM Agent by default, **falls back to agentless EBS snapshot scanning** when SSM isn't available | SSM Agent (piggybacked, not dedicated) |
| **ECR container images** | **Fully agentless** server-side scan at push time + continuous re-scan when new CVEs are published | None |
| **AWS Lambda functions** | **Fully agentless** scan of function code + layers + dependencies | None |

So Inspector v2 is **mostly agentless**, with EC2 being the only exception — and even that doesn't need a dedicated Inspector agent.

### Inspector v1 vs v2 — the historical context

If a question mentions "Amazon Inspector" without a version, it's **v2**. v1 (Classic) is largely deprecated.

| | **Inspector v1 (Classic)** | **Inspector v2 (current)** |
| - | -------------------------- | --------------------------- |
| Status | Deprecated — AWS pushed everyone to v2 | The exam answer |
| Coverage | **EC2 only** | EC2 + ECR + Lambda |
| Scanning model | **Point-in-time assessment runs** (you scheduled them) | **Continuous** scanning |
| Agent | **Required dedicated Inspector Agent** on every EC2 | SSM Agent (already there); ECR + Lambda agentless |
| Rules | Picked "rules packages" (CIS, OS Best Practices) | Built-in vulnerability database (CVEs) + network reachability |

**Exam trap:** if a question says *"install the Inspector Agent on each EC2"* → that's v1, and the right answer is *"migrate to Inspector v2 which uses SSM"*.

### How EC2 Scanning Actually Flows

The dual-mode behaviour is the most testable Inspector detail:

```
┌───────────────────────────────────────────────────────────────┐
│  Mode 1: Agent-based (default when SSM is healthy)            │
│                                                                │
│  1. EC2 instance has SSM Agent (AWS AMIs include it)          │
│         ↓                                                      │
│  2. Inspector uses SSM to pull:                                │
│       - Installed packages + versions                          │
│       - Network configuration                                  │
│         ↓                                                      │
│  3. Inspector matches against CVE database                     │
│         ↓                                                      │
│  4. Findings emitted (continuous — re-evaluated on new CVEs)   │
│                                                                │
│  Pros: deep package-level visibility, real-time                │
│  Cons: requires SSM Agent working + IAM role for SSM           │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│  Mode 2: Agentless (newer, 2023+)                              │
│                                                                │
│  1. Inspector takes an EBS snapshot of the instance's volume   │
│         ↓                                                      │
│  2. Snapshot mounted in Inspector's analysis environment       │
│         ↓                                                      │
│  3. File system + package metadata scanned offline             │
│         ↓                                                      │
│  4. Snapshot deleted; findings emitted                         │
│                                                                │
│  Pros: works without SSM, works on stopped instances,          │
│        works on instances you can't modify (third-party AMIs)  │
│  Cons: less rich (no runtime info), snapshot cost              │
└───────────────────────────────────────────────────────────────┘
```

**Hybrid mode (default in v2):** Inspector uses agent-based when SSM is reachable, automatically falls back to agentless EBS snapshot scanning when it isn't. The "set and forget" answer.

### ECR and Lambda — fully agentless (no choice to make)

**ECR enhanced scanning:**
- Image pushed to ECR → Inspector pulls metadata + scans for CVEs in OS packages + application dependencies (Python, Node, Java, Go, .NET, Ruby)
- **Re-scans existing images** when new CVEs are published — older images become "newly vulnerable" without anyone re-pushing
- No agent, no SSM, nothing to install

**Lambda standard scanning:**
- Inspector analyses the function's code + layers + dependencies
- Identifies CVEs in third-party libraries
- Lambda is fully managed — there's no instance to put an agent on

### Inspector vs GuardDuty (the comparison the exam loves)

| | **Amazon Inspector** | **Amazon GuardDuty** |
| - | -------------------- | -------------------- |
| **What it answers** | *"Do I have any known vulnerabilities?"* (CVEs, misconfigs) | *"Is something behaving maliciously?"* (threat detection) |
| **Method** | Static analysis of installed software | Behavioural analysis of audit / network / DNS traffic |
| **EC2** | Agent (SSM-based) **or** agentless (EBS snapshot) | Agentless via VPC Flow / CloudTrail / DNS. Optional Runtime Monitoring is agent-based |
| **ECR** | Fully agentless image scan | N/A |
| **Lambda** | Fully agentless code scan | Agentless (Lambda Protection — network activity) |
| **Continuous?** | Continuous re-evaluation against latest CVE DB | Continuous behavioural analysis |
| **Multi-account** | Delegated admin in Organizations | Delegated admin in Organizations |
| **Output** | Findings → Security Hub | Findings → Security Hub |

### Common Anti-patterns (exam wrong answers)

- *"Install the Inspector Agent on each EC2"* → v1 thinking; v2 uses **SSM Agent** (already there)
- *"Use Inspector to detect compromised instances making C2 calls"* → wrong service; that's **GuardDuty**
- *"Use Inspector to scan S3 for sensitive data"* → wrong service; that's **Macie**
- *"Scan container images only at push time"* → enable **continuous re-scan** so newly-disclosed CVEs flag older images
- *"Run Inspector v1 assessment runs every month"* → v1 is point-in-time and deprecated; v2 is continuous
- *"Inspector for Lambda needs an agent / layer"* → Lambda scanning is **fully agentless** — Inspector reads the code from the Lambda service
- *"Skip SSM Agent on EC2 to save cost"* → you lose the rich agent-based scan; agentless EBS scan still works as fallback but with less detail

### Exam Triggers

- *"Continuous CVE scanning for EC2 / container images / Lambda"* → **Amazon Inspector v2**
- *"Scan EC2 for OS package vulnerabilities without installing a new agent"* → **Inspector v2** uses **SSM Agent**
- *"Scan EC2 instances you can't put SSM on (third-party AMI)"* → **Inspector v2 agentless EBS snapshot scanning**
- *"Continuous CVE scanning for container images"* → **Inspector v2 ECR enhanced scanning** (agentless)
- *"Find vulnerable dependencies in Lambda function code"* → **Inspector v2 Lambda standard scanning** (agentless)
- *"Aggregate Inspector findings org-wide"* → **Security Hub + Inspector delegated admin**
- *"Migrating from Inspector Classic — what changes?"* → no more dedicated agent (uses SSM), continuous instead of point-in-time, adds ECR + Lambda
- *"Why is this old container image suddenly showing a finding?"* → **Inspector re-scans existing ECR images when new CVEs are disclosed**

**The Mental Model:**

> *Inspector = "is this **software** dangerous?" (vulnerability scanner — mostly agentless).*
> *GuardDuty = "is this **behaviour** dangerous?" (threat detector — mostly agentless).*
> *Both lean agentless. Inspector needs an "agent" only on EC2, and even there it piggybacks on SSM Agent rather than asking you to install anything new.*

**The 80/20:** *Inspector v2 = continuous vulnerability scanner for **EC2 + ECR + Lambda**. ECR and Lambda are fully agentless. EC2 uses **SSM Agent** by default and falls back to **agentless EBS snapshot scanning** when SSM isn't available — no dedicated Inspector agent like the deprecated v1 had. Findings flow into **Security Hub** alongside GuardDuty's. The exam frames Inspector vs GuardDuty as "vulnerabilities (software) vs threats (behaviour)" — both important, both delegated-admin compatible.*

## Amazon Macie

**Anchored as the third sibling — but for S3 data, not behaviour or software.**

> *GuardDuty = "is this **behaviour** dangerous?" (threat detector).*
> *Inspector = "is this **software** dangerous?" (vulnerability scanner).*
> *Macie = "is there **sensitive data** at risk in our S3 buckets?" (data classifier).*

**Macie's one job: find and classify sensitive data in S3, and flag exposed buckets.** It doesn't scan EBS, EFS, RDS, DynamoDB, or anything else — **S3 only**. That's deliberate: S3 is where the *"company leaks 10M records"* breaches happen, so Macie targets the highest-blast-radius surface.

### What Macie is NOT

| Question | Service | Not Macie because... |
| -------- | ------- | -------------------- |
| *"Detect threats / malicious behaviour"* | **Amazon GuardDuty** | Macie classifies *data*; GuardDuty detects *behaviour* |
| *"Find software vulnerabilities (CVEs)"* | **Amazon Inspector** | Inspector scans software; Macie scans data content |
| *"Encrypt the data"* | **AWS KMS** | Macie finds where sensitive data lives; KMS encrypts it |
| *"Block public S3 access at account level"* | **S3 Block Public Access** | Macie *reports* on it; BPA *enforces* it |
| *"Scan PII in a database (RDS / DynamoDB)"* | **No native AWS service** | Export to S3, then Macie — or use a third-party DSPM tool |
| *"Real-time DLP (block sensitive data uploads inline)"* | **No native AWS** | Macie is periodic discovery, not inline DLP |
| *"Aggregate findings org-wide"* | **AWS Security Hub** | Security Hub *consumes* Macie findings as one source |

### The Two Layers of Macie

| Layer | What it does | Cost |
| ----- | ------------ | ---- |
| **Bucket-level posture monitoring** | Continuously evaluates every S3 bucket for: public accessibility, unencrypted, externally shared, missing Block Public Access | **Free** |
| **Sensitive data discovery jobs** | Scans buckets/prefixes you target. Uses ML + regex + managed identifiers to find PII, PHI, credentials, financial data | **$1 per GB scanned** (1 GB/month free per account) |

The pricing is the gotcha — bucket monitoring is virtually free, but **actually scanning content is expensive**. Most orgs target Macie at specific high-risk buckets, not the entire data lake.

### What Macie Can Detect (Managed Data Identifiers)

Macie ships with **150+ pre-built identifiers**:

| Category | Examples |
| -------- | -------- |
| **Personal** | Names, addresses, dates of birth, phone numbers, email addresses |
| **National IDs** | US SSN, UK National Insurance, French INSEE, German BSN, Canadian SIN |
| **Financial** | Credit card numbers (with Luhn validation), IBAN, SWIFT codes, US bank routing |
| **Health** | Medical record numbers, NHS numbers, HIPAA-relevant identifiers |
| **Credentials** | AWS access keys, secret keys, SSH private keys, OAuth tokens, JWTs |
| **Code** | API keys, database connection strings |

Plus **custom data identifiers** with regex + keyword proximity (e.g. *"a 9-digit number within 50 characters of the word 'customer ID'"*).

### How a Macie Scan Actually Flows

```
1. Enable Macie in the account / via Organizations delegated admin
       ↓
2. Macie immediately starts free bucket-level posture monitoring
   (public buckets, unencrypted, externally shared → findings emitted)
       ↓
3. You configure a "sensitive data discovery job":
     - Target: specific buckets, or all buckets matching a tag
     - Schedule: one-time or recurring (daily/weekly)
     - Identifiers: which built-in + custom rules to apply
       ↓
4. Macie reads objects from target buckets (sample or full scan)
       ↓
5. ML + regex + identifiers classify each object's contents
       ↓
6. Findings emitted with severity + sample of matched content:
     - "Bucket X contains 1,200 objects with credit card numbers"
     - "Object Y in bucket Z contains AWS access keys"
       ↓
7. Findings → EventBridge → Security Hub / SNS / Lambda for automation
```

### Why "Just S3"?

Historically, the biggest data leak headlines come from S3 misconfigurations — public buckets, forgotten data dumps, dev environments containing prod data. Macie targets the surface with the worst track record.

For other data stores there's **no native AWS PII scanner**:
- **RDS / Aurora** — no Macie equivalent; export to S3 and scan, or use third-party DSPM tools (Cyera, BigID, Theom)
- **DynamoDB** — same; export + scan
- **EBS** — no equivalent; snapshot, mount, scan manually
- **EFS / FSx** — no equivalent

This is a known gap in AWS's data security story. Third-party DSPM (Data Security Posture Management) tools fill it.

### Multi-account: Same Delegated Admin Pattern

Like GuardDuty / Inspector / Security Hub, Macie supports a **delegated administrator** in Organizations. One security account sees Macie findings across all org accounts.

### The Trio Together

| Service | "Is this ___ dangerous?" | What it scans | Output |
| ------- | ------------------------ | ------------- | ------ |
| **GuardDuty** | Is this **behaviour** dangerous? | CloudTrail + VPC Flow + DNS (+ optional sources) | Behavioural findings → Security Hub |
| **Inspector** | Is this **software** dangerous? | EC2 + ECR + Lambda | CVE findings → Security Hub |
| **Macie** | Is there **sensitive data** at risk? | S3 buckets + objects | Data-classification findings → Security Hub |

All three are AWS-native, mostly agentless, multi-account-aware via delegated admin, and feed Security Hub. Together they cover threats, vulnerabilities, and data exposure for an AWS environment.

### Common Anti-patterns (exam wrong answers)

- *"Use Macie to scan RDS for PII"* → Macie is **S3-only**; export to S3 first, or use a third-party DSPM tool
- *"Run a full Macie scan across the entire data lake monthly"* → at $1/GB, this can cost more than the data is worth; **target specific high-risk buckets**
- *"Use Macie to detect threats"* → wrong service; that's **GuardDuty**
- *"Use Macie to find vulnerable packages"* → wrong service; that's **Inspector**
- *"Use Macie as a real-time DLP to block sensitive uploads"* → Macie is **periodic discovery**, not inline. For inline blocking, you'd need an API Gateway / Lambda layer with custom logic, or a third-party DLP product
- *"Skip Macie bucket monitoring"* → bucket-level posture monitoring is **free** and gives you "which buckets are public/unencrypted" — always-on value

### Exam Triggers

- *"Find PII / credit card numbers / SSNs in S3"* → **Amazon Macie**
- *"Detect AWS access keys accidentally committed to S3"* → **Macie** (built-in identifier for AWS keys)
- *"Identify publicly exposed S3 buckets cheaply"* → **Macie bucket posture monitoring** (free)
- *"HIPAA compliance — find PHI in our data lake"* → **Macie with health identifiers**
- *"Continuously classify sensitive data across all org accounts"* → **Macie + Organizations delegated admin**
- *"Scan PII in RDS / DynamoDB"* → **Not native AWS** — export to S3, then Macie (or third-party DSPM)
- *"Custom detection for our internal customer-ID format"* → **Macie custom data identifier** (regex + keyword proximity)
- *"Why is Macie so expensive in our data lake?"* → $1/GB scanned; target specific buckets, not everything

**The 80/20:** *Macie = sensitive-data classifier for **S3 only**. Two layers: **free bucket-level posture monitoring** (public/unencrypted/exposed buckets) + **paid sensitive data discovery jobs** ($1/GB scanned) using **150+ built-in identifiers** (PII, PHI, credentials, financial) plus custom regex+keyword rules. Findings flow into **Security Hub** alongside GuardDuty and Inspector. Multi-account via **delegated admin**. The trio: **GuardDuty (behaviour) + Inspector (software) + Macie (data)** = AWS's native detection coverage.*

## AWS Security Hub

**Anchored against a SIEM-lite dashboard for AWS.** Security Hub doesn't *detect* anything itself — it **aggregates findings** from GuardDuty, Inspector, Macie, Config, IAM Access Analyzer, Firewall Manager, Health, plus third-party tools (Wiz, Lacework, Splunk, etc.) into one normalised view, then scores you against compliance standards.

### What Security Hub is NOT

| Question | Service | Not Security Hub because... |
| -------- | ------- | --------------------------- |
| *"Detect threats"* | **Amazon GuardDuty** | Security Hub aggregates GuardDuty findings, not produces them |
| *"Vulnerability scanning"* | **Amazon Inspector** | Inspector is a *source* into Security Hub |
| *"Classify sensitive data"* | **Amazon Macie** | Macie is a *source* into Security Hub |
| *"Compliance-as-code evaluation"* | **AWS Config + Conformance packs** | Security Hub *consumes* Config findings; Config does the evaluation |
| *"Full SIEM with raw log retention + custom queries"* | **OpenSearch / Splunk** | Security Hub holds findings only — no raw logs, no custom queries on logs |
| *"Investigation tool"* | **Amazon Detective** | Detective is the deep-dive; Security Hub is the overview |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **AWS Security Finding Format (ASFF)** | The normalised JSON schema every finding gets converted to before entering Security Hub. Lets one dashboard handle GuardDuty + Inspector + third-party findings uniformly |
| **Native sources** | GuardDuty, Inspector, Macie, Config (compliance findings), IAM Access Analyzer, Firewall Manager, Health, Audit Manager |
| **Third-party sources** | Wiz, Lacework, Splunk, CrowdStrike, Tenable, Palo Alto, etc. — integrate via partner connectors |
| **Compliance Standards** | Pre-built control sets you can enable: **AWS Foundational Security Best Practices (FSBP)**, **CIS AWS Foundations Benchmark** (v1.2, v1.4, v3.0), **PCI-DSS**, **NIST 800-53 Rev. 5**, **Service-Managed Standard: AWS Control Tower** |
| **Security Score** | Percentage of enabled controls passing. Per-account or aggregated across org |
| **Automation Rules** | Auto-update / suppress / re-route findings without code (e.g. "if finding from sandbox OU, set severity to Low") |
| **Custom Actions** | User-triggered routing of findings to EventBridge for custom handling (e.g. open a Jira ticket) |
| **Cross-region aggregation** | Pick a home region; findings from all enabled regions aggregate there |
| **Delegated administrator** | One member account becomes the org-wide Security Hub admin |

### How Security Hub Pulls It All Together

```
        ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
        │   GuardDuty     │    │   Inspector     │    │     Macie       │
        │  (threats)      │    │  (CVEs)         │    │  (data class.)  │
        └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
                 │                      │                      │
                 │  findings in ASFF format                    │
                 ▼                      ▼                      ▼
         ┌──────────────────────────────────────────────────────────┐
         │                  AWS Security Hub                         │
         │  - Normalises into ASFF                                   │
         │  - Aggregates cross-account, cross-region                 │
         │  - Maps findings to compliance standards (FSBP/CIS/etc.)  │
         │  - Computes security score                                │
         │  - Runs Automation Rules (auto-update/suppress/escalate)  │
         └──────────────────────────────┬───────────────────────────┘
                                        │
                       ┌────────────────┼────────────────┐
                       ▼                ▼                ▼
              ┌────────────────┐  ┌──────────┐  ┌──────────────────┐
              │  EventBridge   │  │  Console │  │  Third-party SIEM │
              │  (Custom       │  │  dash    │  │  (Splunk, etc.)   │
              │   Actions)     │  │          │  │                   │
              └────────────────┘  └──────────┘  └──────────────────┘
```

### Compliance Standards — the "what controls am I passing?" angle

Each standard is a list of **controls** (e.g. *"S3 buckets should have versioning enabled"*, *"IAM users should not have access keys older than 90 days"*). Security Hub evaluates these continuously via Config rules under the hood. Your security score = passing controls ÷ enabled controls.

**Exam-favourite standards:**
- **AWS Foundational Security Best Practices (FSBP)** — AWS's curated baseline; turn this on first
- **CIS AWS Foundations Benchmark v1.4 / v3.0** — industry-standard checklist
- **PCI-DSS** — for payment workloads
- **NIST 800-53 Rev. 5** — US federal compliance
- **Service-Managed Standard: AWS Control Tower** — auto-managed by Control Tower (mandatory guardrails appear here)

### Common Anti-patterns (exam wrong answers)

- *"Use Security Hub to detect threats"* → it aggregates, doesn't detect; **GuardDuty** detects
- *"Ingest custom application logs into Security Hub"* → it holds findings only, not logs; use OpenSearch / Splunk for logs
- *"Game the security score by suppressing low-severity findings"* → score becomes meaningless; fix root causes
- *"Skip cross-region aggregation"* in a multi-region org → findings scattered across regions are hard to triage
- *"Treat Security Hub as the final SIEM"* — export to a real SIEM if you need cross-correlation, long retention, custom queries
- *"Each account manages its own Security Hub"* → use **delegated administrator** in Organizations

### Exam Triggers

- *"Aggregate findings from GuardDuty / Inspector / Macie across all accounts and regions"* → **AWS Security Hub**
- *"AWS-native security compliance dashboard with CIS / PCI / NIST"* → **Security Hub standards**
- *"Auto-suppress findings from sandbox accounts"* → **Security Hub Automation Rules**
- *"Pipe critical findings to PagerDuty / Slack"* → **Security Hub → EventBridge → SNS/Lambda**
- *"Single security score across the org"* → **Security Hub + delegated admin**
- *"Normalise findings from third-party security tools (Wiz, Lacework)"* → **Security Hub** via ASFF partner integrations
- *"Centrally view 'do my accounts pass the CIS benchmark?'"* → **Security Hub CIS standard**

**The 80/20:** *Security Hub = the AWS-native aggregator + compliance scorer. **Not a detector** — it consumes findings from GuardDuty, Inspector, Macie, Config, Access Analyzer, third-party tools in **ASFF format**. Adds **compliance standards** (FSBP / CIS / PCI / NIST) and continuous security scores. Cross-account / cross-region aggregation via **delegated administrator**. Routes findings to EventBridge for automation. Pairs with GuardDuty (detection) and Detective (investigation). Not a full SIEM — export findings to one if you need raw-log retention.*

## AWS WAF (Web Application Firewall)

**Anchored against nginx + ModSecurity or Cloudflare WAF — but as a managed AWS service.** WAF is the **Layer-7** firewall: it inspects HTTP/HTTPS requests and decides Allow / Block / Count / CAPTCHA / Challenge based on headers, URI, body, source IP, geo, rate, signatures. Sits in front of CloudFront, ALB, API Gateway, AppSync, App Runner, Cognito, or Verified Access.

### What WAF is NOT

| Question | Service | Not WAF because... |
| -------- | ------- | ------------------ |
| *"Protect against large volumetric DDoS attacks"* | **AWS Shield** (Standard is free; Advanced is paid) | WAF filters HTTP; Shield handles L3/L4 volumetric attacks |
| *"Filter TCP/UDP at instance/subnet level"* | **Security Groups** (L4 stateful) / **NACLs** (L4 stateless) | WAF is L7 HTTP only |
| *"Network firewall for VPC east-west / L3-L7 traffic"* | **AWS Network Firewall** | WAF doesn't sit in the VPC data path |
| *"Centrally manage WAF rules across many accounts"* | **AWS Firewall Manager** | Firewall Manager applies WAF rule groups + Shield + Network Firewall configs across the org |
| *"Filter non-HTTP traffic"* | **Network Firewall / Security Groups** | WAF is HTTP/HTTPS only |
| *"Protect API behind WebSocket / gRPC"* | Mixed | WAF works on HTTP-based protocols; raw WebSocket is limited |

### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Web ACL** (Web Access Control List) | A bundle of rules attached to a protected resource (CloudFront distribution, ALB, etc.) |
| **Rule** | A single check: condition + action. Can be **AWS managed** (curated by AWS), **Marketplace managed** (vendor), or **custom** (you write) |
| **Rule action** | What happens on match: **Allow**, **Block**, **Count** (test mode — log but don't block), **CAPTCHA**, **Challenge** (silent JS challenge to weed out bots) |
| **Conditions** | What to match on: **IP set**, **geo-match** (country), **rate-based** (per-IP rate limit), **regex pattern**, **size constraint**, **SQL injection**, **XSS**, **byte match** (string in URI/header/body), **label match** (chain rules) |
| **Managed Rule Groups** | Pre-built bundles. AWS-managed includes **Core Rule Set (CRS / OWASP)**, **Known Bad Inputs**, **SQL Database**, **Linux/Unix/Windows-specific**, **Bot Control**, **Account Takeover Prevention** |
| **WCU (Web ACL Capacity Units)** | Each rule "costs" WCUs; total cap per Web ACL (1,500 default). Complex rules (regex/body inspection) cost more |
| **Logging** | Send inspected request logs to S3, CloudWatch Logs, or Kinesis Firehose |

### Specialised (paid) features

- **Bot Control** — distinguishes verified bots (Google, Bing) from scrapers and credential-stuffers
- **Account Takeover Prevention (ATP)** — credential-stuffing detection on login endpoints
- **Account Creation Fraud Prevention (ACFP)** — detects fake account signups
- **Fraud Control** — umbrella term covering the above

### How a WAF Request Actually Flows

```
1. Client sends HTTPS request to CloudFront / ALB / API Gateway
       ↓
2. The associated Web ACL evaluates its rules in PRIORITY order
       ↓
3. For each rule:
     - Check conditions (IP set match? URI regex? body contains SQLi pattern?)
     - If matched → apply rule action (Allow / Block / Count / CAPTCHA / Challenge)
     - If terminating action (Allow/Block) → STOP evaluation
     - If non-terminating (Count) → continue to next rule
       ↓
4. If no rule matched → DEFAULT action applies (usually Allow, sometimes Block)
       ↓
5. If Block → 403 returned to client
   If Allow → request proxied to the origin
   If CAPTCHA → client served a CAPTCHA challenge first
       ↓
6. Inspected request metadata logged to S3 / CW Logs / Firehose (if enabled)
```

**Priority matters:** put broad allow-list rules early (e.g. allow your monitoring vendor's IP set), then the broad managed rule groups, then narrow custom blocks.

### Where to Attach a Web ACL (and Why It Matters)

WAF isn't a service you "deploy" — it's a **filter you clip onto a layer of your stack**. The choice of which layer has real architectural consequences.

#### The attachment points

| Resource | Scope | Typical use |
| -------- | ----- | ----------- |
| **CloudFront distribution** | **Global** Web ACL (must live in `us-east-1`) | Internet-facing apps — filter at the edge |
| **Application Load Balancer (ALB)** | Regional | Regional apps without CloudFront, or as defence-in-depth |
| **API Gateway (REST/HTTP API)** | Regional | Serverless APIs without CloudFront |
| **AppSync GraphQL API** | Regional | GraphQL endpoint protection |
| **App Runner service** | Regional | App Runner custom domain |
| **Cognito user pool** | Regional | Auth endpoint protection (combine with ATP for credential stuffing) |
| **Verified Access** | Regional | Workforce zero-trust endpoint |

#### What the choice actually means

```
                       ┌─────────────────────────────────┐
                       │     Attacker / legitimate user  │
                       └──────────────┬──────────────────┘
                                      │ HTTPS request
            ┌─────────────────────────▼──────────────────────────┐
            │ ① CloudFront edge location (one of 400+ globally)  │
            │    ← WAF "Global" Web ACL filters HERE             │
            │    ✓ Earliest possible block                       │
            │    ✓ No bandwidth into your region for blocked req │
            │    ✓ Latency for blocked req = tens of ms          │
            └─────────────────────────┬──────────────────────────┘
                                      │ (allowed requests only)
                                      ▼
                       ┌──────────────────────────────────┐
                       │   Your AWS region (eu-west-1)    │
                       │                                  │
                       │   ② Application Load Balancer    │
                       │   ← WAF "Regional" Web ACL HERE  │
                       │      ✓ Inside your VPC           │
                       │      ✓ Sees decrypted requests   │
                       │                                  │
                       │   OR ② API Gateway / AppSync /   │
                       │      App Runner / Cognito        │
                       │   ← Regional Web ACL HERE        │
                       │                                  │
                       │            ↓ origin (ECS/Lambda/EC2) │
                       └──────────────────────────────────┘
```

#### Why earlier is almost always better

| Concern | CloudFront (edge) | ALB / API Gateway (region) |
| ------- | ----------------- | -------------------------- |
| **Where is the malicious request blocked?** | Nearest edge to the attacker | After traversing the internet to your region |
| **Bandwidth into your region for blocked req** | None | Full request + TLS termination cost |
| **Origin resource consumption** | Origin never sees blocked req | Origin handles TLS, sees the connection |
| **Volumetric attack absorption** | CloudFront's globally distributed capacity | Single region's capacity |
| **Latency for blocked requests** | Low (closest edge) | Higher (must reach region) |
| **TLS body inspection** | Yes (CloudFront terminates TLS) | Yes |

**Principle:** filter as early as possible. WAF on CloudFront is the gold standard for any internet-facing app.

#### The Global vs Regional Web ACL distinction

There are **two flavours** of Web ACL — they look identical but live in different services:

| | Global Web ACL | Regional Web ACL |
| - | -------------- | ---------------- |
| Can attach to | **CloudFront only** | ALB, API Gateway, AppSync, App Runner, Cognito, Verified Access |
| Region it lives in | **`us-east-1` always** (even if CloudFront serves globally) | Same region as the resource |
| Same rules / managed rule groups available? | Yes | Yes |
| Pricing | Same per-WCU model | Same |

**Exam trap:** *"I have CloudFront in front of an ALB in eu-west-1; can I share one Web ACL?"* → **No.** CloudFront needs a Global Web ACL in `us-east-1`; ALB needs a Regional Web ACL in eu-west-1. Same rules, two ACL resources.

#### The bypass risk if you only WAF at ALB (or only at CloudFront)

The gotcha the exam loves:

```
Setup: CloudFront (NO WAF) → ALB (NO WAF)

Attacker discovers the ALB's direct DNS name (DNS history,
certificate transparency logs, accidentally-public Terraform state):
  myapp-alb-1234567890.eu-west-1.elb.amazonaws.com
       ↓
Request hits ALB directly, bypassing CloudFront entirely
       ↓
No WAF inspection → ❌ malicious request reaches origin
```

**The proper defence — CloudFront + WAF + restricted ALB:**

```
Setup: CloudFront (WAF) → ALB (restricted to only accept CloudFront)

  - WAF on CloudFront blocks bad requests at the edge
  - ALB security group only allows traffic from CloudFront's managed
    prefix list (com.amazonaws.global.cloudfront.origin-facing)
  - PLUS a custom X-Origin-Verify header (CloudFront sets it; ALB
    requires it) — defeats prefix-list spoofing
       ↓
  Direct ALB attack: blocked by SG + header check
  Normal traffic: hits CloudFront → WAF inspected → forwarded to ALB
```

Without restricting the ALB, **WAF on CloudFront alone is bypassable**. Always pair edge WAF with origin lockdown.

#### Multi-layer WAF (defence in depth)

Higher-security workloads attach WAF at **both** CloudFront and ALB:

```
CloudFront WAF
  - Block: known bad IPs, geo restrictions, bulk volumetric patterns
  - Block: OWASP managed rules (broad, edge-relevant)
  - Rate limit: per-IP global limits
       ↓
ALB WAF
  - Block: more specific business-logic rules
  - Block: API-specific patterns (path-based, body-based)
  - Rate limit: per-endpoint regional limits
```

Common in fintech / healthtech / government where regulations demand layered controls. Overkill for most apps — CloudFront alone is enough.

#### How the choice maps to common architectures

| Architecture | Where WAF goes | Why |
| ------------ | -------------- | --- |
| **Global SPA + REST API** (CloudFront + ALB / API Gateway) | **WAF on CloudFront** | Filter at edge; restrict origin to only accept CloudFront traffic |
| **Regional API only** (ALB → ECS / EC2) | **WAF on ALB** | No CloudFront in the picture |
| **Serverless REST API** (API Gateway + Lambda) | **WAF on API Gateway** | No CloudFront, no ALB |
| **GraphQL** (AppSync) | **WAF on AppSync** | Direct integration |
| **High-security / regulated** | **WAF on CloudFront AND on ALB/API Gateway** | Layered controls |
| **Cognito user pool** (login / signup endpoints) | **WAF on Cognito user pool** | ATP for credential stuffing; ACFP for fake signups |

#### Attachment-point exam triggers

| Question | Answer |
| -------- | ------ |
| *"Global app — where to attach WAF?"* | **CloudFront** (Global Web ACL in `us-east-1`) |
| *"Regional API, no CloudFront — where?"* | **ALB or API Gateway** (Regional Web ACL, same region) |
| *"Attacker bypassed CloudFront and hit ALB directly"* | Either put WAF on ALB too, **or** restrict ALB to only accept CloudFront (prefix list + header check) |
| *"Why doesn't my regional Web ACL work on CloudFront?"* | CloudFront needs **Global** Web ACL in `us-east-1` |
| *"Protect login endpoint from credential stuffing"* | **WAF on Cognito user pool** with **Account Takeover Prevention** |
| *"Defence-in-depth — multiple layers of WAF"* | **WAF on CloudFront + WAF on ALB** with different rule sets |

### Common Anti-patterns (exam wrong answers)

- *"Use WAF for DDoS protection"* → wrong layer; use **AWS Shield** (Advanced for serious DDoS) — WAF supplements Shield, doesn't replace it
- *"Use WAF for L3/L4 filtering"* → wrong layer; use **Security Groups / NACLs**
- *"WAF on ALB for a globally distributed app"* → adds latency for distant users; put WAF on **CloudFront** for global apps
- *"Enable all managed rule groups in Block mode without testing"* → false positives will break legitimate traffic; use **Count** mode first to observe
- *"Single Web ACL across all environments"* → can't tune per environment; use separate Web ACLs
- *"Manage WAF rules separately in each account"* in a multi-account org → use **AWS Firewall Manager** for centralised rule deployment
- *"Forget rate-based rules"* → critical for slowing brute-force and scraping

### Exam Triggers

- *"Block SQL injection / XSS at the edge"* → **AWS WAF Managed Core Rule Set**
- *"Rate-limit per source IP"* → **WAF rate-based rule**
- *"Block traffic from specific country"* → **WAF geo-match rule**
- *"OWASP Top 10 protection"* → **WAF AWS Managed Rules**
- *"Bot mitigation / scraping prevention"* → **WAF Bot Control**
- *"Credential stuffing on login"* → **WAF Account Takeover Prevention (ATP)**
- *"Fake account signups"* → **WAF Account Creation Fraud Prevention (ACFP)**
- *"Centrally manage WAF across many accounts"* → **AWS Firewall Manager**
- *"DDoS protection beyond WAF"* → **AWS Shield Advanced**
- *"Test a new WAF rule without affecting traffic"* → **Count action mode**
- *"Global app — filter at the edge"* → **WAF on CloudFront** (not ALB)

**The 80/20:** *WAF = Layer-7 HTTP firewall as a managed service. Attaches to CloudFront (global), ALB / API Gateway / AppSync / App Runner / Cognito (regional). **Rules** with conditions (IP, geo, rate, regex, SQLi, XSS, body inspection) → actions (Allow / Block / Count / CAPTCHA / Challenge). **AWS Managed Rule Groups** cover OWASP Top 10, SQLi, bot control. **Web ACL Capacity Units (WCU)** cap rule complexity. Paid features: **Bot Control**, **ATP** (credential stuffing), **ACFP** (fake signups). Multi-account → **AWS Firewall Manager**. WAF ≠ Shield (DDoS) ≠ Security Groups (L3/L4) ≠ Network Firewall (VPC-level).*

## AWS Shield + DDoS Resiliency (BP1–BP7)

**Anchored against Cloudflare DDoS protection.** AWS Shield is the **DDoS protection service** — Standard is free and automatic; Advanced is the paid tier with cost protection and DRT (DDoS Response Team) access. But Shield isn't a standalone story — it's part of a wider framework AWS calls the **DDoS Resiliency Best Practices (BP1–BP7)**, which the exam references by name.

### The BP1–BP7 Framework

AWS's *DDoS Resiliency Best Practices* whitepaper organises mitigations into numbered Best Practices. The exam (especially Security Specialty) phrases questions like *"Which AWS service maps to BP3?"* — so the labels are worth memorising.

| Code | Best Practice | What it maps to | Defends against |
| ---- | ------------- | --------------- | --------------- |
| **BP1** | **Edge location mitigation** | **CloudFront** | Absorbs volumetric L3/L4 attacks at AWS's 400+ POPs; only HTTP/S reaches your origin |
| **BP2** | **DDoS-resilient reference architecture** | **Global Accelerator + Route 53** | Anycast IPs (Global Accelerator) and DNS-level resilience absorb attacks |
| **BP3** | **Web application layer defence** | **AWS WAF** | Layer 7 attacks: SQL injection, XSS, HTTP floods, slowloris, scraping, rate-based |
| **BP4** | **Attack surface reduction** | Security Groups + NACLs + private subnets + bastion design | Don't expose what doesn't need to be public |
| **BP5** | **Scale to absorb attacks** | **ELB + Auto Scaling** | Horizontal scaling soaks up volumetric attacks; ELB itself is highly resilient |
| **BP6** | **Operational visibility** | **CloudWatch + GuardDuty + Shield Advanced metrics** | See attacks happening — detect them before users complain |
| **BP7** | **Engage AWS DDoS Response Team (DRT)** | **Shield Advanced subscription** | 24/7 access to AWS's DDoS specialists during attacks |

(Numbering shifts slightly across whitepaper versions — BP4 and BP5 sometimes swap — but **BP1 = CloudFront** and **BP3 = WAF** are stable references.)

### How the BPs Stack — Layered Defence Picture

```
                       Internet — attack traffic
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │  ROUTE 53 / GLOBAL ACCELERATOR  (BP2)                  │
       │  ✓ Anycast — attack absorbed across regions             │
       │  ✓ Always-on Shield Standard for L3/L4 here             │
       └────────────────────────┬───────────────────────────────┘
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │  CLOUDFRONT  (BP1)                                     │
       │  ✓ Volumetric L3/L4 absorbed at edge                    │
       │  ✓ Only HTTP/HTTPS reaches your region                  │
       │  ✓ Shield Standard auto-protects                        │
       └────────────────────────┬───────────────────────────────┘
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │  AWS WAF on CloudFront  (BP3)                          │
       │  ✓ Layer 7 attacks blocked                              │
       │  ✓ Rate-based rules, OWASP managed rules                │
       │  ✓ Bot Control / ATP for app-layer attacks              │
       └────────────────────────┬───────────────────────────────┘
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │  ALB + Auto Scaling + private subnets  (BP4 + BP5)     │
       │  ✓ Origin not directly exposed                          │
       │  ✓ Scales horizontally during attack                    │
       └────────────────────────┬───────────────────────────────┘
                                ▼
                        Your origin (ECS / Lambda / EC2)

       Throughout: CloudWatch + GuardDuty + Shield Advanced metrics  (BP6)
       During attack: AWS DRT engagement via Shield Advanced  (BP7)
```

### Shield Standard vs Shield Advanced

| | **Shield Standard** | **Shield Advanced** |
| - | ------------------- | -------------------- |
| Cost | **Free** — automatic for all AWS customers | **$3,000/month per organization** + data transfer fees |
| Scope | L3/L4 attacks on CloudFront, Route 53, Global Accelerator, ELB | Everything in Standard, plus L7, EC2, sophisticated/large attacks |
| WAF included? | ❌ (WAF charged separately) | ✅ AWS WAF included free |
| DRT (DDoS Response Team) access | ❌ | ✅ 24/7 via Support |
| **Cost protection** (refunds for scaling during attack) | ❌ | ✅ **The killer feature** |
| Advanced attack metrics | ❌ | ✅ via CloudWatch |
| Health-based detection | ❌ | ✅ (integrates with Route 53 health checks) |
| Real-time attack visibility | Basic | Detailed |
| Protects EC2 directly (Elastic IPs) | ❌ | ✅ |

### The EDoS Problem: Why DDoS Causes Cost Explosions

The naive interpretation of "scale to absorb attacks" (BP5) misses a critical risk. **Economic Denial of Service (EDoS)** is when the attack's goal isn't downtime — it's bankrupting you:

```
Attacker fires 100k req/s at your ALB
       ↓
ALB scales (no problem — AWS absorbs ALB itself)
       ↓
Origin EC2/ECS hits CPU/request thresholds
       ↓
Auto Scaling spins up MORE instances to handle the load
       ↓
Attack continues, MORE instances spin up
       ↓
You wake up to:
  - 200 EC2 instances running ($$$/hour)
  - Massive ELB data transfer bill
  - Massive CloudFront data-out bill
  - Massive Route 53 query bill
  - Plus WAF inspected-request charges
       ↓
Bill arrives. Site stayed up, but the cost might be six figures.
```

Even a *successful* DDoS defence can cost tens-to-hundreds of thousands in scaling charges.

### How Shield Advanced Solves EDoS — Cost Protection

The single most important feature of Shield Advanced. AWS refunds the scaling charges incurred during a **verified DDoS event**:

| Service | Costs refunded |
| ------- | -------------- |
| **EC2** (Auto Scaling spin-ups) | ✅ |
| **Elastic Load Balancing** (data transfer + LCU charges) | ✅ |
| **CloudFront** (data out) | ✅ |
| **Route 53** (additional queries) | ✅ |
| **Global Accelerator** (data transfer) | ✅ |

**The catch:** must be verified as a DDoS by AWS (open a case with DRT). Genuine traffic spikes that aren't attacks → not refunded.

**The economics:** $3,000/month is **DDoS insurance**. One serious attack might cost $50k–$500k in scaling charges. Cost protection refunds that. Shield Advanced pays for itself many times over in a single attack.

### Architectural Mitigations (without Shield Advanced)

If you can't justify $36k/year, engineer your way around the cost risk:

#### 1. Heavy CloudFront caching

```
Attacker fires 100k req/s
       ↓
CloudFront serves cached responses from edge for 99% of requests
       ↓
Origin only sees ~1k req/s (cache misses only)
       ↓
No Auto Scaling triggered. Cost bounded.
```

A well-cached site is **mostly immune to volumetric L7 attacks**. CloudFront's per-request cost is tiny ($0.0075 per 10k requests) vs scaling an entire fleet.

#### 2. WAF rate-based rules

```
Web ACL rule:
  rate_based_rule(limit=2000 req per IP per 5 min) → Block

Attacker's botnet exceeds rate from each IP
       ↓
Requests blocked at WAF ($0.60 per million inspected)
       ↓
Never reach the origin → no scaling trigger
```

WAF rate-based rules are the **single most cost-effective** L7 DDoS mitigation.

#### 3. Auto Scaling maximum limits

Set a **hard maximum** on your Auto Scaling group (e.g. `max = 50`). Under attack, the group caps at 50 instances. Site degrades (some users get errors) but cost is bounded.

Trade-off: availability vs cost. Most teams pick a max that's 2–3× normal peak — enough headroom for legitimate spikes, ceiling on attack-driven scaling.

#### 4. AWS Budgets + Budget Actions

```
Budget: $5,000 / day
  → Alert at 80%
  → Action at 100%: apply restrictive IAM, stop specific services
```

AWS Budgets can take **automated actions** when thresholds are breached. Risky if misconfigured — most teams configure alarms first, manual actions second.

#### 5. CloudWatch Composite Alarms

```
Composite alarm:
  IF (RequestCount > 10× baseline)
  AND (4xx/5xx errors elevated)
  AND (estimated cost rate > $500/hour)
  THEN page on-call + Lambda to scale-cap or rate-limit
```

Detect the *combination* that signals "attack, not legitimate traffic". Rate limits alone fire on legitimate spikes (Black Friday).

### When to Pay for Shield Advanced

| Workload | Shield Advanced? | Why |
| -------- | ---------------- | --- |
| Small SaaS, marketing site, blog | ❌ | $36k/year too much; caching + rate limits are enough |
| Mid-size e-commerce | 🟡 | Depends on revenue-at-risk. If one-hour outage costs >$10k, consider it |
| Fintech / banking / payments | ✅ | Cost protection alone justifies it; plus DRT access |
| Online gaming with real-time servers | ✅ | Hard to cache; high attack surface |
| Government / public sector | ✅ | Compliance + uptime requirements |
| Streaming / media | ✅ | Heavily attacked; CloudFront-heavy already so cost protection compounds |

### Common Anti-patterns (exam wrong answers)

- *"Use Shield Standard for full DDoS protection"* → Shield Standard is L3/L4 only on specific services; for full coverage including L7, you need WAF + Shield Standard, or Shield Advanced
- *"WAF alone is enough for DDoS"* → WAF handles L7; volumetric L3/L4 needs CloudFront + Shield Standard
- *"Scale to absorb without cost guardrails"* → leads to EDoS bills; use Auto Scaling max limits + WAF rate-based rules at minimum
- *"Pay for Shield Advanced for a small marketing site"* → wasteful; architectural defences suffice
- *"Skip CloudFront for a 'simple' app"* → missing BP1; you're exposing the origin directly
- *"Restrict Auto Scaling max to current peak"* → first legitimate spike (sale, viral post) will cause outage
- *"Rely on Shield to refund without enabling Shield Advanced"* → cost protection is **Advanced-only**

### Exam Triggers

- *"Free, automatic DDoS protection on CloudFront / Route 53 / ELB"* → **AWS Shield Standard**
- *"DDoS protection with DRT access and cost protection"* → **AWS Shield Advanced** ($3k/month)
- *"Mitigate volumetric attack before it reaches origin"* → **CloudFront (BP1)** + Shield
- *"Block HTTP flood / Layer 7 attack"* → **AWS WAF (BP3)** + rate-based rule
- *"Scale during attack to absorb load"* → **ALB + Auto Scaling (BP5)**
- *"Refund EC2 / ALB / Route 53 scaling costs incurred during DDoS"* → **Shield Advanced cost protection**
- *"Prevent runaway Auto Scaling cost during attack"* → **WAF rate-based rules + Auto Scaling max + CloudFront caching**
- *"24/7 DDoS response team engagement"* → **Shield Advanced (BP7)**
- *"What is an Economic Denial of Service (EDoS) attack?"* → Attack aiming to **inflate AWS bill** via uncontrolled scaling; Shield Advanced cost protection mitigates
- *"Why is BP5 (scale to absorb) safe?"* → Combined with **cost protection + CloudFront caching + WAF rate limits**
- *"Which BP maps to AWS WAF?"* → **BP3** (web application layer defence)
- *"Which BP maps to CloudFront?"* → **BP1** (edge location mitigation)
- *"Protect on-prem origin from DDoS"* → **CloudFront + Shield + WAF**, accelerated via Global Accelerator

### The Mental Model

> *Shield Standard keeps your site up during volumetric attacks. **Shield Advanced keeps your bank account up too.** Architectural defences (CloudFront caching, WAF rate limits, max-scale caps) reduce how much the attack costs in the first place; Shield Advanced cost protection refunds whatever leaks through.*

**The 80/20:** *AWS Shield = DDoS protection. **Standard** = free + automatic, L3/L4 on CloudFront/Route 53/ELB. **Advanced** = $3k/month, adds L7 protection, **cost protection** (refunds for Auto Scaling / ELB / data transfer charges during verified attacks), **DRT** (DDoS Response Team) access, and EC2 Elastic IP protection. AWS's **BP1–BP7** DDoS Resiliency Best Practices map to specific services: BP1=CloudFront, BP2=Global Accelerator/Route 53, BP3=WAF, BP4=attack surface reduction, BP5=Auto Scaling, BP6=visibility (CloudWatch/GuardDuty), BP7=DRT. The exam references these labels directly. **Economic Denial of Service (EDoS)** is the cost-bankruptcy variant — Shield Advanced's cost protection is the answer.*

## AWS Network Firewall + Firewall Manager

Two services covered together because they're complementary and often confused. **Network Firewall** is a VPC-level firewall (the thing in the data path). **Firewall Manager** is org-wide central management of WAF + Shield + Network Firewall + Security Groups (the thing that *deploys* them consistently across all accounts).

### AWS Network Firewall

**Anchored against Palo Alto / Cisco ASA — but managed by AWS.** A true **VPC-level firewall** that sits in the data path and inspects every packet flowing in / out / through your VPCs. Layer 3 to Layer 7, stateful, supports Suricata rules.

#### What Network Firewall is NOT

| Question | Service | Not Network Firewall because... |
| -------- | ------- | ------------------------------- |
| *"L7 HTTP filtering at the edge"* | **AWS WAF** | WAF is HTTP/HTTPS only; Network Firewall handles all protocols |
| *"Per-instance L4 stateful firewall"* | **Security Groups** | SGs attach to ENIs; Network Firewall sits in a subnet on the routing path |
| *"Stateless subnet ACL"* | **NACLs** | NACLs are simple L4 allow/deny per subnet; Network Firewall is L3-L7 stateful |
| *"DDoS protection"* | **AWS Shield** | Different concern; Network Firewall is for traffic filtering, not volumetric attacks |
| *"Centrally manage firewall rules across the org"* | **AWS Firewall Manager** | Firewall Manager deploys Network Firewall configs; it's not the firewall itself |

#### Core Concepts

| Concept | What it is |
| ------- | ---------- |
| **Firewall** | The Network Firewall resource you create; attached to a VPC |
| **Firewall endpoint** | The actual inspection point — one per AZ, placed in a **dedicated firewall subnet** |
| **Firewall policy** | A collection of stateless + stateful rule groups; can be reused across firewalls |
| **Stateless rules** | Standard 5-tuple match (src/dst IP/port + protocol) → pass / drop / forward to stateful engine |
| **Stateful rules** | Full session tracking. Two rule formats: **standard 5-tuple** or **Suricata-compatible IDS/IPS rules** |
| **Domain list rules** | Block / allow based on **HTTP Host header** or **TLS SNI** (e.g. *"block all egress except `*.amazonaws.com`"*) |
| **Suricata rules** | Open-source IDS/IPS rule format — gives you access to rich community + commercial rule sets (Proofpoint ET, etc.) |

#### Where Network Firewall Sits (the architecture pattern)

```
        Internet                                On-prem (via VPN/DX)
            │                                          │
            ▼                                          ▼
       ┌────────────────────────────────────────────────────┐
       │  Inspection VPC                                     │
       │    ┌──────────────────────────────────────────┐    │
       │    │  Network Firewall endpoints              │    │
       │    │  (one per AZ in firewall subnet)         │    │
       │    └──────────────────┬───────────────────────┘    │
       └───────────────────────┼────────────────────────────┘
                               │
                  Transit Gateway routes ALL traffic through here
                               │
        ┌──────────────────────┼─────────────────────┐
        ▼                      ▼                     ▼
  ┌──────────┐         ┌──────────┐          ┌──────────┐
  │ Prod VPC │         │ Dev VPC  │          │Shared VPC│
  └──────────┘         └──────────┘          └──────────┘
```

**Classic pattern:** centralised inspection VPC with Network Firewall; Transit Gateway routes all spoke-VPC traffic through it. Every cross-VPC and east-west / north-south packet inspected.

#### Use Cases

- **Egress filtering** — *"VPC can only talk to specific external domains"* (e.g. only `*.amazonaws.com`, `github.com`)
- **East-west inspection** — *"all traffic between VPCs must pass through inspection"* (PCI / FedRAMP requirement)
- **IDS/IPS via Suricata rules** — signature-based detection of known exploits
- **DNS filtering** — block resolution of malicious / unapproved domains
- **Compliance** — required by many regulated frameworks for "deep packet inspection"

#### Pricing (the gotcha)

- **$0.395/hour per firewall endpoint** (one per AZ → $0.395 × N × 730 hours/month ≈ $290/month per AZ)
- **$0.065/GB processed** — expensive at scale
- Plus underlying Transit Gateway charges if using centralised inspection

A multi-AZ deployment processing meaningful traffic easily runs **thousands of dollars per month**. Only deploy when you actually need it.

#### Common Anti-patterns

- *"Use Network Firewall instead of Security Groups"* → SGs are free + per-resource; use both
- *"Network Firewall for L7 HTTP filtering of public sites"* → use **WAF** at CloudFront / ALB
- *"Single-AZ Network Firewall"* → no HA; deploy one endpoint per AZ
- *"Skip the dedicated firewall subnet"* → it's required architecturally
- *"Deploy without Transit Gateway in a multi-VPC setup"* → ends up with one firewall per VPC, expensive; use centralised inspection VPC

#### Exam Triggers

- *"Inspect all VPC east-west traffic with deep packet inspection"* → **AWS Network Firewall**
- *"Egress filter — VPC can only call specific external domains"* → **Network Firewall domain list rules**
- *"IDS/IPS for VPC traffic using Suricata rules"* → **Network Firewall stateful rule groups**
- *"Centralised inspection point for multiple VPCs"* → **Network Firewall in inspection VPC + Transit Gateway**
- *"Block resolution of malicious domains at the network layer"* → **Network Firewall DNS / domain filtering** (or Route 53 Resolver DNS Firewall — both valid; see distinction below)

**Note on Route 53 Resolver DNS Firewall:** related but different — Route 53 Resolver DNS Firewall filters DNS queries from your VPC. Network Firewall can do this too via domain list rules. Difference: DNS Firewall is cheaper and DNS-only; Network Firewall is broader (TLS SNI, protocols, deep inspection). For *"just block DNS resolution of bad domains"* → **Route 53 Resolver DNS Firewall** is the cheaper answer.

### AWS Firewall Manager

**Anchored as: Organizations meets security policies.** Centrally manage **WAF rule groups + Shield Advanced + Network Firewall configs + Security Groups + Route 53 Resolver DNS Firewall** across **all accounts** in your AWS Organization. Apply consistent rules to existing AND new resources automatically.

#### What Firewall Manager is NOT

| Question | Service | Not Firewall Manager because... |
| -------- | ------- | ------------------------------- |
| *"A firewall itself"* | **WAF / Network Firewall / Security Groups** | Firewall Manager *manages* other firewalls; it doesn't filter traffic itself |
| *"Replace WAF / Shield / Network Firewall"* | Each underlying service | You still need (and pay for) the underlying services |
| *"Centrally manage IAM"* | **AWS Organizations + SCPs / IAM Identity Center** | Different layer — those govern identity, Firewall Manager governs network/app security |
| *"For a single account"* | Manage each firewall directly | Firewall Manager is overkill for one account; it's an **org-wide** tool |

#### Requirements

- **AWS Organizations** with all features enabled
- **Firewall Manager delegated administrator** in a member account (typical security account)
- **AWS Config enabled** in every account (Firewall Manager uses Config to detect non-compliant resources)

#### What You Can Manage Through Firewall Manager

| Resource type | Centrally managed |
| ------------- | ----------------- |
| **WAF rule groups** | Apply same WAF rules to all CloudFront / ALB / API Gateway across the org |
| **Shield Advanced** | Onboard accounts to Shield Advanced; protect specified resources |
| **AWS Network Firewall** | Deploy Network Firewall in every VPC; central rule sets |
| **Security Groups** | Audit / enforce SG policies (e.g. *"no SG allowing 0.0.0.0/0 on port 22"*); also create "common" SGs accounts can reference |
| **Route 53 Resolver DNS Firewall** | Deploy DNS Firewall rule groups across all VPCs |
| **Palo Alto Networks Cloud NGFW** | Third-party integration |
| **Fortigate Cloud Native Firewall** | Third-party integration |

#### Use Cases

- *"Apply this OWASP managed rule group to every ALB in every account"*
- *"Ensure every VPC has a Network Firewall deployed with our standard rules"*
- *"Audit all Security Groups across the org and flag any allowing SSH from the internet"*
- *"Auto-onboard new accounts to Shield Advanced protection"*
- *"Maintain a baseline of acceptable Security Groups, with auto-remediation for drift"*

#### Cost

**$100/month per policy per region.** Adds up — if you have 5 policies across 3 regions, that's $1,500/month just for Firewall Manager (plus the underlying WAF / Shield / Network Firewall costs).

#### Common Anti-patterns

- *"Use Firewall Manager for a single account"* → overkill; manage WAF / SGs directly
- *"Skip AWS Config setup"* → Firewall Manager *requires* Config to detect non-compliance
- *"Treat Firewall Manager as a firewall"* → it's a policy manager; it doesn't filter packets itself
- *"Run Firewall Manager from the management account"* → use a **delegated administrator** (security/audit account)

#### Exam Triggers

- *"Centrally enforce WAF rules across all org accounts"* → **AWS Firewall Manager**
- *"Audit Security Groups across all accounts for risky rules"* → **Firewall Manager SG audit policy**
- *"Auto-onboard new accounts to Shield Advanced"* → **Firewall Manager Shield policy**
- *"Apply consistent Network Firewall config to every VPC across the org"* → **Firewall Manager + Network Firewall**
- *"Detect SGs allowing 0.0.0.0/0 on dangerous ports across the org"* → **Firewall Manager content audit policy**

### The Combined Mental Model

| Layer | Service | Scope |
| ----- | ------- | ----- |
| **L3/L4 stateful, per-resource** | **Security Group** | One ENI / resource |
| **L4 stateless, per-subnet** | **NACL** | One subnet |
| **L3-L7 stateful + IDS/IPS, per-VPC** | **Network Firewall** | VPC (often centralised in inspection VPC) |
| **L7 HTTP/HTTPS** | **WAF** | CloudFront / ALB / API Gateway etc. |
| **DNS query filtering** | **Route 53 Resolver DNS Firewall** | VPC |
| **Volumetric DDoS L3/L4** | **AWS Shield (Standard/Advanced)** | CloudFront / Route 53 / ELB / Global Accelerator (Standard) + EC2 (Advanced) |
| **Central management of all the above across an Org** | **AWS Firewall Manager** | Organization-wide |

**The 80/20:** *Network Firewall = AWS-managed L3-L7 stateful firewall for VPCs. Sits in a dedicated firewall subnet; typical deployment is a centralised inspection VPC with all spoke VPCs routing through it via Transit Gateway. Supports Suricata IDS/IPS rules + domain list filtering. Expensive ($290+/month per AZ + $0.065/GB). Firewall Manager = central management of WAF + Shield + Network Firewall + Security Groups + Route 53 DNS Firewall across all org accounts. Requires AWS Organizations + Config + delegated admin. $100/policy/region/month. Use Firewall Manager when you have 10+ accounts and want consistent security policies; skip it for single-account or small setups.*

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

### Amazon MSK (Managed Streaming for Apache Kafka)

**Anchored against Kinesis Data Streams.** Both are AWS-managed streaming services. The split:

- **MSK runs real Apache Kafka** — wire-compatible, existing Kafka producers/consumers/tools (Kafka Connect, Schema Registry, MirrorMaker, kafkactl) work unchanged
- **Kinesis is AWS-proprietary** — simpler API, deeper AWS integration, no Kafka ecosystem

| | Amazon MSK | Kinesis Data Streams |
| - | ---------- | -------------------- |
| Engine | Real Apache Kafka | AWS proprietary |
| Wire-compatible with | Open-source Kafka | Kinesis SDK only |
| Lives in VPC? | **Yes** — brokers have ENIs + **security groups** | No — public API endpoint |
| Deployment | MSK Provisioned (size brokers) or **MSK Serverless** | Always serverless |
| Retention | Configurable, default 7 days, **unlimited** with tiered storage | 24h default, max 365 days |
| Best for | Lift-and-shift Kafka, Kafka ecosystem (Connect, KSQL, Streams API) | Greenfield AWS-native streaming |
| Auth | IAM, SASL/SCRAM, mTLS, ACLs | IAM only |

**When MSK wins:**
- Existing Apache Kafka workload, want managed
- Need Kafka Connect, Schema Registry, Streams API ecosystem
- Multi-cloud / portability concerns — Kafka runs anywhere

**When Kinesis wins:**
- Greenfield streaming on AWS, no Kafka commitment
- Tight AWS integration (Kinesis Firehose → S3/Redshift/OpenSearch with no code)
- Don't want to think about brokers at all

**Exam triggers:**
- *"managed Apache Kafka on AWS"* → **MSK**
- *"lift-and-shift Kafka cluster to AWS"* → **MSK**
- *"Kafka without managing brokers"* → **MSK Serverless**
- *"existing tools use the Kafka protocol"* → **MSK**

### Amazon Managed Service for Apache Flink

**Anchored against Lambda + Kinesis event source.** Both consume streams. The difference is *state*:

- **Lambda is stateless per-message** — process one record, forget it. State has to live elsewhere (DynamoDB, S3)
- **Flink is stateful with built-in windowing** — "count events per minute by user", "join two streams within a 10-minute window", "detect a pattern across the last 100 events" — all native, in-memory state with checkpoints to S3

**Formerly known as:** Kinesis Data Analytics for Apache Flink. The older SQL-only "Kinesis Data Analytics" product was deprecated; this is the current Flink offering. Can also run on **EMR with Flink** if cluster control matters.

**What Flink is for:**

| Use case | Why Flink wins |
| -------- | -------------- |
| **Windowed aggregations** | "P95 latency per service per minute" — tumbling / sliding / session windows built in |
| **Stream-to-stream joins** | Join two streams within a time window (clicks + impressions on the same user) |
| **Complex event processing (CEP)** | "3 failed logins followed by a successful one in 5 minutes" |
| **Stateful ML feature engineering** | Real-time feature pipelines updating model inputs as events stream |
| **Exactly-once processing** | Flink checkpointing gives strong guarantees Lambda + Kinesis can't easily match |

**The canonical pipeline:**

```
Producers (apps, IoT) ──→ MSK or Kinesis Data Streams
                              │
                              ▼
                       Managed Service for Apache Flink
                       (windows, joins, CEP, stateful)
                              │
                              ├──→ OpenSearch (search/dashboards)
                              ├──→ S3 (data lake)
                              ├──→ RDS / DynamoDB (aggregated state)
                              └──→ another Kafka/Kinesis stream
```

**When to pick Flink vs alternatives:**

| Workload | Pick |
| -------- | ---- |
| Per-message transformation, no state needed | **Lambda** (cheaper, simpler) |
| Buffer + batch-write to S3 | **Kinesis Firehose** |
| Stateful windowed aggregations / joins / CEP | **Managed Flink** |
| Spark on streams (existing Spark code) | **EMR with Spark Streaming** |

**Common anti-patterns (exam wrong answers):**

- **Lambda for stateful windowing** — possible but painful; you'd build state in DynamoDB. Flink does it natively.
- **Kinesis Data Streams alone for analytics** — Streams is the transport; you still need a processor (Flink, Lambda, Spark).
- **MSK when Kinesis would do** — Kafka complexity for no gain on greenfield AWS apps.
- **Flink for simple filter/transform** — Lambda is simpler and cheaper.
- **Confusing "Kinesis Data Analytics SQL" with Flink** — the SQL-only product is gone; **Managed Service for Apache Flink** is the current Flink offering.

**Exam triggers:**

- *"stateful stream processing with windowing"* → **Managed Service for Apache Flink**
- *"real-time aggregation over sliding / tumbling / session windows"* → **Flink**
- *"join two streams in real time"* → **Flink**
- *"complex event processing / pattern detection across events"* → **Flink** (CEP)
- *"exactly-once stream processing"* → **Flink** with checkpointing

### How MSK and Flink Fit Together

```
            ┌───────────────────────────────────────────────────┐
            │                  Producers                         │
            └───────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌─────────────────────┐
            Choose: │  MSK    or  Kinesis │      (transport)
                    └─────────────────────┘
                                │
                                ▼
            ┌───────────────────────────────────────────────────┐
            │  Lambda  (stateless, per-event)                    │
            │  Firehose  (batch to S3/Redshift/OpenSearch)       │
            │  Managed Flink  (stateful, windows, joins, CEP)    │
            │  EMR Spark Streaming  (Spark on streams)           │
            └───────────────────────────────────────────────────┘
                                │
                                ▼
                       Sinks (S3, RDS, OpenSearch, another stream)
```

**The 80/20:**
- *"managed Kafka"* → **MSK**
- *"managed Kafka with no brokers to size"* → **MSK Serverless**
- *"stateful stream processing with windows/joins"* → **Managed Service for Apache Flink**
- *"simple per-event transform"* → **Lambda** (not Flink)
- *"buffer stream to S3"* → **Kinesis Firehose** (not Flink)

### Kafka vs SNS vs Redis pub/sub

All three "broadcast a message to multiple consumers" — but they are fundamentally different *shapes*. The cleanest mental model:

| | SNS | Redis pub/sub | Kafka (MSK) |
| - | --- | ------------- | ----------- |
| Analogy | **Telegraph** — delivered or lost, no record | **Walkie-talkie** — only people listening *right now* hear it | **Tape recorder** — everything stored, anyone can rewind and replay |
| Storage | None (transient) | None (transient) | **Durable, retention configurable** (days → forever with tiered storage) |
| Consumers | Push to subscribers (Lambda, SQS, email, SMS, HTTP) | Only currently-connected subscribers | **Pull-based**; each consumer tracks its own offset |
| Replay | No | No | **Yes** — rewind, reprocess any time |
| Multiple independent reader groups | All subscribers share the broadcast; no per-subscriber position | No — one-shot | **Yes** — N consumer groups, each at their own position on the same topic |
| Ordering | None (Standard); FIFO for one consumer | Best-effort | **Strict within a partition** |
| Throughput | High, but per-message billed | Limited by single Redis node for pub/sub | **Millions msg/sec** sustained |
| Schema management | None | None | **Schema Registry** (Glue or Confluent) |
| Auth / VPC | Public API, IAM (no SGs) | Inside VPC, SGs, AUTH token | Inside VPC, IAM/SASL/mTLS |

**Why Kafka exists alongside SNS / Redis pub/sub — the five reasons:**

1. **Durability + replay** — the headline. Kafka is an **append-only log**, not a message broker. Consumers are independent and can rewind.

   ```
   SNS:    Publisher → SNS → if a subscriber is down, message is lost
                            (pair with SQS to durably buffer per subscriber)
   Redis:  Publisher → Redis → only currently-connected subs receive it
   Kafka:  Publisher → message persists for days/weeks
                       → Service B reads now
                       → Service C reads tomorrow
                       → Service D (new consumer) replays from offset 0
   ```

2. **Multiple independent consumer groups on the same stream** — you publish "order events" once; fulfilment, analytics, audit, and search each read at their own pace with their own offset. SNS fans out but each subscriber gets only "now."

3. **Throughput at scale** — Redis pub/sub is capped by a single node. SNS scales but at per-request pricing. Kafka was built for LinkedIn-scale event volumes (millions of messages/sec) and stays cheap per message.

4. **Streaming pipeline backbone** — stateful stream processors (Flink, Spark Streaming, Kafka Streams) need a durable log to checkpoint against. You don't run Flink on top of SNS or Redis pub/sub.

5. **Cross-cloud / portable** — Kafka runs anywhere. SNS and Redis pub/sub (in AWS form) lock you in.

**Direct comparison — Kafka vs SNS fan-out:**

```
SNS fan-out:
  Publisher → SNS → SQS (Service A queue) → Service A
                  → SQS (Service B queue) → Service B
                  → SQS (Service C queue) → Service C
  Each subscriber gets a separate queue; no replay; messages drop off after consumption.

Kafka:
  Publisher → Kafka topic ─→ Service A consumer group (own offset)
                          ─→ Service B consumer group (own offset)
                          ─→ Service C consumer group (own offset)
  All three read the same persistent log. Any can reset offset and replay.
```

Looks similar from above. Behaves very differently when you need replay, late-joining consumers, or rewind for debugging.

**Pick which:**

| Pattern | Pick |
| ------- | ---- |
| Notification fan-out — email user, send SMS, ping a Lambda | **SNS** (with SQS where durability matters) |
| Real-time UI updates between websocket clients on the same app | **Redis pub/sub** (or AppSync subscriptions) |
| Ephemeral signalling between app instances (cache invalidation, leader election) | **Redis pub/sub** |
| Durable event log, multiple downstream consumers, replay, stream processing | **Kafka (MSK)** or **Kinesis Data Streams** |
| AWS-native event bus with routing/filtering and 100+ SaaS integrations | **EventBridge** |

**Common anti-patterns (exam wrong answers):**

- **Picking SNS for an event log that needs replay or late-joining consumers** — SNS doesn't store. Use Kafka or Kinesis.
- **Picking Redis pub/sub for anything durable** — volatile, no replay, single-node throughput cap. Use Kafka.
- **Picking Kafka for a notification scenario** — operational overhead and complexity for no gain. SNS is right.
- **Picking Kafka greenfield on AWS when Kinesis would do** — same log shape, less ops. Pick MSK only when the Kafka *ecosystem* (Connect, Schema Registry, Streams API) or portability matters.
- **Using SNS + Lambda for "stream processing"** — fine for per-event reactions, breaks down for windowed/joined/stateful processing. Use Kafka or Kinesis + Flink.

**Exam triggers:**

- *"durable, replayable event log with multiple independent consumers"* → **Kafka (MSK)** or **Kinesis Data Streams**
- *"broadcast a notification to email/SMS/Lambda subscribers"* → **SNS**
- *"real-time pub/sub between app processes, ephemeral"* → **Redis pub/sub**
- *"existing on-prem Kafka workload, migrate to AWS"* → **MSK**
- *"event-driven architecture with content-based routing and SaaS sources"* → **EventBridge**
- *"stateful stream processing on top of a Kafka topic"* → **Managed Service for Apache Flink** consuming from **MSK**
- *"late-joining consumer needs to replay all historical events"* → **Kafka / Kinesis** (not SNS)

**The 80/20:** *SNS is a telegraph (delivered or lost), Redis pub/sub is a walkie-talkie (only people listening now hear it), Kafka is a tape recorder (everything stored, anyone can rewind). Pick Kafka when you need a durable replayable log with multiple independent consumer groups — typical of event-driven architectures and stream-processing pipelines.*

### Amazon EventBridge

**Anchored against SNS + CloudWatch Events.** EventBridge is the **AWS-native event bus**: routes JSON events from many sources to many targets, with content-based filtering. It's the **rebrand of CloudWatch Events**, with two big additions:

1. **Custom and Partner event buses** — not just AWS-emitted events; bring in your own + 100+ SaaS sources (Datadog, Zendesk, Shopify, MongoDB Atlas, PagerDuty, etc.)
2. **Schema registry**, **Archive + Replay**, **Pipes**, and **Scheduler** — features that don't exist in plain SNS or CloudWatch Events

**Two-word mental model:** *content-routed event bus*.

#### The Role of an Event Bus

The **event bus is the routing channel** that events land on. **Rules** attached to the bus evaluate every event that arrives and forward matching ones to **targets**. The bus itself doesn't *do* anything — it's just the channel. The behaviour comes from the rules attached to it.

```
[Source] → PutEvents → [Event Bus] ─→ Rule A (pattern match) ─→ Target(s)
                                  ─→ Rule B (pattern match) ─→ Target(s)
                                  ─→ Rule C (no match)         (event discarded
                                                                unless archived)
```

**Why multiple buses, not one shared:**

1. **Separation of concerns** — production events on a `prod` bus, dev events on a `dev` bus. Different rules, different targets, different IAM
2. **Access control** — IAM policies attach *per bus*. Team A can `PutEvents` to their bus but not yours
3. **Cross-account routing** — Account A's bus can be a *target* of Account B's rule. Standard pattern: each app account publishes locally, routes to a central audit account's bus
4. **Multi-tenancy** — each customer / tenant has their own bus with their own rules

**Anchored against what you know:**

```
SNS topic:       Publishers → topic → fan-out to all subscribers (basic filtering)
Kafka topic:     Publishers → topic → consumers read independently, replay any time
EventBridge bus: Publishers → bus → rules filter on content → routed to matching targets only
                                    (no consumer offset / replay unless Archive is configured)
```

**Concrete walk-through:**

```
Custom bus "orders-bus" (you create it)
    │
    ├── Rule "high-value-orders": pattern { detail.amount > 1000 }
    │       → Target: SNS topic "vip-alerts"
    │       → Target: Lambda "fraud-check"
    │
    ├── Rule "all-orders-to-warehouse": pattern { detail-type: "OrderPlaced" }
    │       → Target: SQS queue "warehouse-queue"
    │
    └── Rule "eu-orders-only": pattern { detail.region: "EU" }
            → Target: cross-account bus in eu-compliance-account

App publishes:
  events:PutEvents({ source: "orders.app", detail: { amount: 1500, region: "US" } })

→ Matches Rule 1 AND Rule 2 → SNS, Lambda, SQS all get the event
→ Doesn't match Rule 3 (region:"US" not "EU") → that target isn't notified
```

**Exam-relevant facts about buses specifically:**

- **One event can match multiple rules** — fanned out independently to each rule's targets
- **Targets per rule: up to 5** — for more, chain rules
- **Cross-account / cross-region**: an event bus in one account can be a **target** of another account's rule (event federation across an Org)
- **Default bus is special** — only it receives AWS-service-emitted events automatically; you can't change that
- **Archive is configured on the bus, not the rule** — retains events on that bus for replay
- **IAM: `events:PutEvents` is checked against the bus's resource policy**, not the publisher's identity policy alone — critical for cross-account publishing

#### Four Event-Bus Types

| Bus type | What it receives | Use for |
| -------- | ---------------- | ------- |
| **Default bus** | AWS service events (EC2 state change, S3 PutObject, RDS failover, etc.) | React to anything AWS does |
| **Custom bus** | Your own application events | Decouple microservices internally |
| **Partner bus** | Events from SaaS (Datadog, Zendesk, Shopify, Auth0, etc.) | React to events from outside AWS |
| **Scheduler** (separate service, but family) | Cron / one-time schedules | Replaces scheduled CloudWatch Events rules |

#### Rules + Targets + Filtering (the core mechanic)

```
Source emits event → matches against rules (JSON pattern) → routed to target(s)
```

A **rule** has:
- An **event pattern** — JSON filter on event fields. *Only* matching events trigger targets
- One or more **targets** — Lambda, SQS, SNS, Step Functions, Kinesis Firehose, ECS task, API Gateway, another event bus, etc. (**18+ supported target types**)
- Optional **input transformer** — reshape the event before delivery to a target

```json
{
  "source": ["aws.s3"],
  "detail-type": ["Object Created"],
  "detail": {
    "bucket": { "name": ["prod-uploads"] },
    "object": { "size": [{ "numeric": [">", 1048576] }] }
  }
}
```

That rule fires only on **S3 object creations in `prod-uploads` larger than 1 MB**. Content-based filtering is the headline differentiator from SNS (SNS does filter-by-attribute but is less expressive).

#### Target Permissions: Resource-based Policy vs IAM Role

A perennial exam confusion: *"How does EventBridge get permission to invoke its target?"* There are **two patterns** and which one you use depends on the target type.

| Target | Permission mechanism |
| ------ | -------------------- |
| **Lambda** | **Resource-based policy** on the function (a "Lambda permission" granting `events.amazonaws.com` to `lambda:InvokeFunction`) |
| **SNS** | **Resource-based policy** on the topic |
| **SQS** | **Resource-based policy** on the queue |
| **CloudWatch Logs** | **Resource-based policy** on the log group |
| **Kinesis Data Streams** | **IAM role** (EventBridge assumes a role with `kinesis:PutRecord` permission) |
| **Kinesis Data Firehose** | **IAM role** |
| **Step Functions** | **IAM role** |
| **ECS / Fargate task** | **IAM role** (with `ecs:RunTask`) |
| **API destinations** | **IAM role** |
| **Systems Manager Run Command** | **IAM role** |
| **CodeBuild / CodePipeline / Batch / Glue / SageMaker** | **IAM role** |

**The underlying rule:** *"Does the target service support resource-based policies that allow another AWS service to invoke it?"*

- **Yes** (Lambda, SNS, SQS, CloudWatch Logs) → grant via resource-based policy *on the target*
- **No** (everything else) → EventBridge needs an **IAM role** to assume, and the role has permission to call the target

#### Why the historical split

It comes down to how each service was designed:

```
Resource-based pattern (Lambda):
  EventBridge ──invoke──► Lambda function
                          ↑
                          │ checks its own resource policy:
                          │ "Is events.amazonaws.com on the allow list?"
                          │ ✅ yes → execute

IAM-role pattern (Kinesis):
  EventBridge ──assume-role──► IAM Role
                               ↓ (with temp credentials)
                               kinesis:PutRecord on stream
```

**Mental model:** *Lambda/SNS/SQS/Logs are "the doors with a doorman list posted on them." Everything else has no doorman, so the caller must wear a badge (role) to get in.*

#### What the console auto-creates

When you set up an EventBridge rule with a target via the console, AWS auto-creates the right thing:

- **Lambda target** → adds a `Lambda permission` to the function (visible in *Configuration → Permissions → Resource-based policy*)
- **Kinesis target** → creates an IAM role named like `Amazon_EventBridge_Invoke_Kinesis_xxx` with the trust policy + invocation permissions

You can verify by inspecting the target after creation.

#### The rule generalises beyond EventBridge

Same pattern applies any time *service A invokes service B* in AWS:

| Integration | Mechanism |
| ----------- | --------- |
| S3 event notification → Lambda | **Resource-based policy** on the Lambda |
| API Gateway → Lambda backend | **Resource-based policy** on the Lambda |
| SNS subscription → Lambda | **Resource-based policy** on the Lambda |
| CloudWatch Logs subscription filter → Lambda | **Resource-based policy** on the Lambda |
| CloudWatch Events / EventBridge → Lambda | **Resource-based policy** on the Lambda |
| CloudWatch Events / EventBridge → Kinesis | **IAM role** |
| Step Functions → Lambda | **IAM role** (Step Functions assumes a role with `lambda:InvokeFunction`) — note Lambda *also* accepts resource policies, but Step Functions uses the role pattern |
| Cross-account access to any resource | **Both** — resource policy on the target AND IAM policy on the principal |

#### Exam-pattern mnemonic

> *"Lambda, SNS, SQS, CloudWatch Logs — the four targets with a doorman. Everything else needs the caller to wear a badge."*

If a question phrases the answer choices as *"add an IAM role"* vs *"add a resource-based policy"*, ask: **what type of target?** Lambda/SNS/SQS/Logs → resource policy. Anything else → IAM role.

#### Archive + Replay (unique feature)

EventBridge can **archive every event** that lands on a bus (with optional filtering on what to keep). Later you can **replay** archived events back through the bus — useful for:

- **Disaster recovery** — replay events lost during a downstream outage
- **Bug fix replay** — replay a window of events after fixing a buggy consumer
- **Testing** — replay production events into a staging bus

Neither SNS nor CloudWatch Events can do this — replay is an EventBridge-only superpower.

**The replay gotcha (exam trap): replays use *current* rules → *current* targets.** A replayed event lands on the bus and is matched against **today's** rules, not the rules that existed when it was archived. So:

- A rule you've added since the archive will fire on replay (even though it didn't exist when the event happened)
- A rule you've deleted won't fire — those targets get nothing
- Consumers **must be idempotent** — replay re-invokes every target that matches today

If a question asks *"why did the replay trigger a target that didn't exist before?"* — that's the answer.

**Replay targets a time range, not specific events.** You pick start-time → end-time; you can't replay "just these 12 events". Idempotency on consumers is non-negotiable.

**Archive-time filtering = the cost knob.** You don't have to archive everything. Set an event pattern at archive creation (e.g. only `source: "aws.iam"`) to drop the storage bill. Multiple archives per bus are allowed — each with its own filter + retention. Common "reduce archive cost without losing required events" exam answer.

**Retention + encryption:**
- Retention: **1 day → indefinite**, configurable per archive
- Encrypted at rest by default with an AWS-managed key; customer-managed KMS key supported
- Archives are **per-bus, per-region** — not replicated cross-region

**Replay throughput is bursty.** Delivery happens "as fast as the bus can accept" — replaying millions of events can cause a thundering herd at consumers. Mention if a question is about scale.

#### What Archive is NOT

| Question | Service | Not Archive because... |
| -------- | ------- | ---------------------- |
| *"Long-term queryable audit store of events"* | **CloudTrail Lake** or S3 + Athena | Archive can't be queried with SQL — only filtered by time range for replay |
| *"Dead-letter queue for failed event delivery"* | **EventBridge target DLQ** (an SQS queue per target) | DLQ catches per-target delivery failures; Archive is a passive copy of *everything* on the bus |
| *"Stream replay with position seeks"* | **Kinesis Data Streams** | Kinesis lets consumers seek to a sequence number; Archive only replays by time window through current rules |
| *"Cross-region disaster recovery for events"* | **Cross-region bus replication** | Archives are per-bus, per-region — not replicated across regions |
| *"Long-term audit of who did what in AWS"* | **CloudTrail** | Archive captures bus events (which may include CloudTrail events) but is not the audit source of truth |

#### Schema Registry

Discover the schema of events flowing through a bus (auto-discovered or registered manually), version them, and **code-generate typed bindings** in Java / Python / TypeScript so consumers get autocomplete + compile-time safety on event payloads.

Pairs nicely with **EventBridge Pipes** — typed event handlers across microservices.

#### EventBridge Pipes (newer feature)

A **point-to-point** integration between an event source and a target — with optional filtering and enrichment — **without writing Lambda glue**.

```
Source ──→ Filter ──→ Enrichment ──→ Target
(SQS, Kinesis,        (Lambda /        (Lambda, SQS,
 DynamoDB Streams,    Step Functions,  EventBridge bus,
 MSK, MQ, etc.)       API destination) Step Functions, etc.)
```

Use case: *"every change in DynamoDB Streams → enrich with user profile via API → write to EventBridge bus → fan out to 5 consumers"*. Without Pipes you'd build a Lambda for the glue. With Pipes it's configuration.

| | EventBridge Rules | EventBridge Pipes |
| - | ----------------- | ----------------- |
| Pattern | One source bus → N targets | One source → one target (with optional enrichment) |
| Sources | EventBridge bus events | SQS, Kinesis, DynamoDB Streams, MSK, MQ, SelfManaged Kafka |
| Use for | Event bus fan-out | Replacing the "Lambda as glue" pattern |

#### EventBridge Scheduler (the cron service)

Originally scheduled tasks lived inside CloudWatch Events (rate / cron expressions). EventBridge Scheduler is the **dedicated cron service** — supports **millions of schedules**, **one-time** schedules, time-zone awareness, flexible time windows, and direct invocation of **270+ AWS API actions** (no Lambda glue).

| Old way | New way |
| ------- | ------- |
| CloudWatch Events scheduled rule → Lambda → action | **EventBridge Scheduler** → action directly |

Exam phrasing: *"schedule a one-time invocation of a Lambda 3 hours from now"* → **EventBridge Scheduler** (CloudWatch Events scheduled rules only support recurring patterns).

#### EventBridge vs SNS (the exam decision)

| | SNS | EventBridge |
| - | --- | ----------- |
| Pattern | Pub/sub topic — fan-out to N subscribers | Event bus — content-routed to many targets |
| Filtering | Attribute-based filter policies (limited) | **Content-based** JSON pattern matching (rich) |
| SaaS sources | No | **100+ partner integrations** |
| AWS-emitted events | No (you publish manually) | **Yes** — default bus auto-receives from many services |
| Archive + replay | No | **Yes** |
| Schema registry | No | **Yes** |
| Latency | Sub-100ms (faster) | Slightly higher (~ hundreds of ms) |
| Target types | SQS, Lambda, HTTP/S, SMS, email, mobile push | 18+ AWS targets, API destinations (HTTP), cross-account buses |
| Throughput | Massive | High but with per-rule and per-target limits |
| Best for | Simple, fast fan-out | Complex routing, SaaS events, replay, schemas |

**The shortcut:** simple fan-out, lowest latency, AWS-only → **SNS**. Routing logic, SaaS sources, replay, schemas → **EventBridge**.

#### Common Anti-patterns (exam wrong answers)

- **"CloudWatch Events"** in a current question → recognise it as **EventBridge** (same service, rebrand). Same exam answer.
- **EventBridge for simple ultra-low-latency fan-out** — SNS is faster and cheaper for pure fan-out.
- **Writing a Lambda just to ferry events from SQS / Kinesis to EventBridge** — use **EventBridge Pipes** instead.
- **CloudWatch Events scheduled rule for a one-time future invocation** — only supports recurring patterns. Use **EventBridge Scheduler** for one-off / cron-at-scale.
- **Custom database table to log every event for replay** — EventBridge **Archive + Replay** does this natively.
- **SNS for events that originate at a SaaS vendor** — SaaS partners deliver into EventBridge **partner event buses**, not SNS.

#### Exam Triggers

- *"AWS-native event bus with content-based routing"* → **EventBridge**
- *"react to events from Datadog / Zendesk / Shopify / Auth0 / etc."* → **EventBridge partner event bus**
- *"replay events from last week through the same pipeline"* → **EventBridge Archive + Replay**
- *"point-to-point integration from SQS/Kinesis/DynamoDB Streams to a target without writing Lambda glue"* → **EventBridge Pipes**
- *"schedule a one-time future invocation"* → **EventBridge Scheduler** (NOT CloudWatch Events scheduled rules)
- *"cron at massive scale (millions of schedules)"* → **EventBridge Scheduler**
- *"version + auto-discover event schemas, code-gen bindings"* → **EventBridge Schema Registry**
- *"route events differently based on JSON payload content"* → **EventBridge event patterns** (richer than SNS filter policies)
- *"cross-account / cross-region event routing"* → **EventBridge cross-account / cross-region buses**
- *"the service formerly known as CloudWatch Events"* → **EventBridge**

**The 80/20:** *EventBridge = content-routed event bus = CloudWatch Events rebrand + custom + partner buses + Archive/Replay + Pipes + Scheduler + Schema Registry. Pick EventBridge over SNS when you need content-based filtering, SaaS sources, or replay. Pick SNS when you need simple, fastest fan-out. The exam tests the rebrand trap ("CloudWatch Events" → EventBridge), the SaaS-source angle, Archive+Replay uniqueness, and Pipes for "no Lambda glue".*

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

### Redshift Snapshots and Disaster Recovery

Snapshots are the **cornerstone of Redshift's DR story**. Yes — Redshift supports snapshots (common confusion: people sometimes think of Redshift like Athena where there's nothing to back up). Redshift's cluster storage is real and the snapshot system is how you protect it.

**Two types of snapshots:**

| | Automated | Manual |
| - | --------- | ------ |
| Frequency | Every **8 hours** OR every **5 GB** of data change, whichever first | On-demand, when you trigger |
| Retention | **1–35 days** (configurable) | **Indefinite** — until you delete |
| What it captures | Incremental — only blocks changed since last snapshot | Same incremental mechanism |
| Use case | Day-to-day recovery (last few weeks) | Long-term retention, pre-upgrade safety, end-of-project archive |
| Cost | Storage of changed blocks | Same |

**Snapshots are stored in S3 internally** (AWS-managed) — that's why they're incremental and cheap. Restoring a snapshot creates a **new cluster** (you can't restore in-place).

### The Standard Redshift DR Plan

```
Primary region (eu-west-1)                          DR region (us-east-1)
──────────────────────────                          ────────────────────
Redshift cluster
   ↓ automated snapshots (every 8h / 5GB)
S3 (internal, AWS-managed)
   ↓ cross-region snapshot copy (configurable)
                            ─────────────────→     Snapshot stored in DR region
                                                       ↓ on disaster
                                                   Restore → new Redshift cluster
                                                       ↓
                                                   Update DNS / app config to point at new cluster
```

**Steps to implement:**

1. **Automated snapshots are on by default** — verify retention is set to enough days for your RPO (default is 1 day; bump to e.g. 7–14 days for production).
2. **Configure cross-region snapshot copy** — pick the destination region and the retention for copied snapshots (can differ from primary).
3. **Take manual snapshots** for milestones (pre-upgrade, end of fiscal quarter, before risky migration) — these persist beyond the 35-day automated cap.
4. **In the DR region, periodically test restore** — confirm a snapshot actually restores cleanly to a new cluster.

### Additional Resilience Features

**Multi-AZ for Redshift (RA3 nodes only):**

Newer feature — deploy a single Redshift cluster across **two AZs in the same region**. Synchronous replication, automatic failover if one AZ fails, no manual recovery. Reduces RTO from "restore from snapshot" to near-zero for AZ failures.

- Multi-AZ does NOT protect against **region** failure — still need cross-region snapshot copy for true DR
- Only available on RA3 node types

**AWS Backup integration:**

Redshift snapshots can be managed via **AWS Backup** for centralised policy-based backup across all your AWS resources (RDS, DynamoDB, EFS, EBS, etc.) — one backup vault, one retention policy, cross-region copy, cross-account copy, audit reports.

| Approach | When |
| -------- | ---- |
| Direct Redshift snapshot management | Single cluster, simple needs |
| **AWS Backup** | Multiple AWS resources, centralised policy, compliance/audit requirements |

**Cross-account snapshot sharing:**

Share a snapshot with another AWS account — useful for giving the security/audit team access to a frozen copy, or recovering into a separate "DR account."

### Common Anti-patterns (exam wrong answers)

- **"Redshift doesn't support snapshots"** — yes it does. They're the primary DR mechanism. (Common knowledge gap.)
- **Relying only on automated snapshots for long-term backup** — they max at 35 days. Use **manual snapshots** for longer retention, or AWS Backup with a long-retention policy.
- **Multi-AZ alone as your DR strategy** — Multi-AZ protects against AZ failure within a region, not region failure. You still need **cross-region snapshot copy** for true DR.
- **Copying snapshots manually as a DR strategy** — error-prone. Use the built-in **cross-region snapshot copy** feature; it runs automatically on every new snapshot.
- **Forgetting the new cluster cost on restore** — restoring creates a new cluster with its own compute cost. Build the DR cost into your plan.

### Exam Triggers

- *"data warehouse for analytics and reporting"* → **Redshift**
- *"run complex SQL across petabytes of data"* → **Redshift**
- *"connect BI tools like Tableau to AWS"* → **Redshift**
- *"query S3 data with SQL, no infrastructure"* → **Athena**
- *"query S3 data from within Redshift"* → **Redshift Spectrum**
- *"OLAP workload"* → **Redshift**
- *"OLTP workload"* → **RDS / Aurora**
- *"Redshift disaster recovery plan"* → **enable cross-region snapshot copy**
- *"Redshift backup retention beyond 35 days"* → **manual snapshots** (or AWS Backup with long retention)
- *"recover Redshift cluster in another region after disaster"* → **restore from cross-region copied snapshot**
- *"centralised backup policy across Redshift + other AWS resources"* → **AWS Backup**
- *"protect Redshift cluster against single-AZ failure with automatic failover"* → **Multi-AZ for RA3** (no manual recovery needed)
- *"share Redshift snapshot with another AWS account"* → **cross-account snapshot sharing**

**The 80/20:** *Redshift HAS snapshots (don't doubt this). Automated = up to 35 days; manual = forever. DR = cross-region snapshot copy → restore in the DR region creates a new cluster. Multi-AZ (RA3 only) handles AZ failures; cross-region snapshot copy handles region failures. AWS Backup is the centralised alternative.*

## AWS Glue

Glue is **five things sharing a name**, and the exam tests them as if they're separate services. Anchored in what you know: **Athena uses the Glue Data Catalog** for schema. **EMR is the alternative when you need cluster control**. Glue itself is the serverless ETL + metadata stack.

### The Five Pieces of Glue

| Component | What it is | Why it matters |
| --------- | ---------- | -------------- |
| **Glue Data Catalog** | Central metadata repository — table names, columns, types, S3 locations. **Used by Athena, Redshift Spectrum, EMR, Lake Formation** | AWS's central schema registry — one definition, many query engines |
| **Glue Crawler** | Scans data sources (S3, RDS, DynamoDB, JDBC), **infers schema**, writes table definitions to the Data Catalog | Exam-favourite pairing with Athena: *"new S3 data lands daily, query with Athena without manual schema"* |
| **Glue ETL Jobs** | Serverless Apache Spark (or Python shell) for transformations. Pay per **DPU-hour** (Data Processing Unit) | Glue = serverless EMR-for-ETL |
| **Glue Studio** | Visual drag-and-drop ETL builder — generates Spark/PySpark under the hood | "No-code ETL" for engineers |
| **Glue DataBrew** | Visual **no-code** data prep for analysts; 250+ built-in transformations | "No-code data prep" for non-engineers |
| **Glue Schema Registry** | Versioned schemas for streaming data (Kafka, Kinesis); producers/consumers validate against it | "Schema validation for streaming" |

### Where Glue Sits in the Analytics Stack

```
Raw data in S3 / RDS / JDBC sources
       │
       ▼
Glue Crawler ──→ Glue Data Catalog (schema metadata, no actual data)
       │
       ▼
Glue ETL Job (serverless Spark) ──→ transforms, writes Parquet to S3 / Redshift
       │
       ▼
Athena / Redshift Spectrum / EMR / QuickSight all read using the Catalog's schema
```

### Glue vs EMR — the Key Decision

| | AWS Glue | EMR |
| - | -------- | --- |
| Model | **Serverless** — no cluster | You manage the cluster (or use EMR Serverless) |
| Frameworks | **Spark + Python shell only** | Spark, Hadoop, Hive, HBase, Flink, Presto, etc. |
| Best for | Standard ETL feeding Athena/Redshift | Frameworks Glue doesn't ship, or cluster control |
| Built-in | Job bookmarks, workflows, Data Catalog | Frameworks; you wire the rest |
| Cost | Pay per DPU-hour, no idle cost | Cluster running cost (or EMR Serverless workers) |

**Rule of thumb:** *"Serverless Spark ETL with auto schema discovery feeding Athena/Redshift"* → **Glue**. *"Need Hadoop / Hive / HBase / Flink / Presto, or want cluster control"* → **EMR**.

### Job Bookmarks (exam favourite)

State that Glue maintains *between* runs of an ETL job, recording which data has already been processed. The next run picks up only the new data.

```
Run 1, Monday:    Process orders_2026-05-19.csv, orders_2026-05-20.csv
                  Bookmark: "processed up to 2026-05-20"
Run 2, Tuesday:   Bookmark exists → read only orders_2026-05-21.csv
                  Bookmark advances to "2026-05-21"
Run 3, Wednesday: Read only orders_2026-05-22.csv
```

**Three modes:**

| Mode | What it does | When to pick |
| ---- | ------------ | ------------ |
| **Enable** | Track processed data, skip it next run | Default for incremental ETL (daily/hourly batches) |
| **Disable** | Reprocess everything on every run | Full reload, dev/test, when you want every run to be from scratch |
| **Pause** | Track but don't apply | One-off reprocessing without losing the existing bookmark state |

**Source support:**

| Source | Bookmark tracking |
| ------ | ----------------- |
| **S3** | By file timestamp / key — new files since last run |
| **JDBC** (RDS, on-prem DBs) | By a monotonically increasing column (e.g. `id`, `last_updated`) — you specify which column |
| **Streaming sources** (Kinesis, Kafka) | Different mechanism (checkpoints), **not** bookmarks |
| **DynamoDB** | Not supported via bookmarks |

**Anti-pattern trap (exam):**

- **Source data is updated in place** (rows modified rather than new rows added) → bookmarks **don't help**; they only track *additions*. Use **DMS CDC** to capture updates, or do a full reload.
- **Filenames keep getting rewritten with the same name** → bookmarks may miss changes; pick a partition scheme that makes new data appear as new keys.

**Exam triggers:**

- *"avoid reprocessing data already handled by a previous Glue run"* → **Job Bookmarks**
- *"incremental ETL from S3 to Redshift via Glue"* → enable **Job Bookmarks**
- *"track data already processed during a previous run of a Glue ETL job"* → **Job Bookmarks** (this is the exam's literal phrasing)
- *"Glue is reprocessing the same files every night"* → enable **Job Bookmarks**
- *"one-off full reload without losing the existing bookmark state"* → set bookmarks to **Pause**

### Common Anti-patterns (exam wrong answers)

- **Glue for non-Spark frameworks** — Glue only runs Spark + Python shell. Hive / HBase / Flink → EMR.
- **Glue when Lambda + Step Functions would do** — for small per-event transformations, Lambda is cheaper. Glue is for batch Spark scale.
- **Crawler when schema is stable** — define the table manually; avoid Crawler costs + risk of schema drift surprises.
- **DataBrew for engineers** — they want ETL Jobs (more flexible). DataBrew is for analysts.
- **Glue Studio for highly custom code** — once logic gets complex, write PySpark directly; Studio's generated code becomes unwieldy.

### Exam Triggers

- *"serverless ETL with Apache Spark"* → **AWS Glue** (ETL job)
- *"central metadata catalog used by Athena / Spectrum / EMR"* → **Glue Data Catalog**
- *"automatically discover schema of S3 data"* → **Glue Crawler → Glue Data Catalog → Athena**
- *"no-code data prep for business analysts"* → **Glue DataBrew**
- *"managed schema registry for Kafka / Kinesis"* → **Glue Schema Registry**
- *"avoid reprocessing the same data on every Glue job run"* → **Job bookmarks**
- *"convert raw CSV/JSON in S3 to Parquet for cheaper Athena queries"* → **Glue ETL Job**
- *"orchestrate multiple Glue jobs with dependencies"* → **Glue Workflows** (or Step Functions)
- *"need Hadoop/Hive/HBase/Flink instead of Spark"* → **EMR**, NOT Glue

**The 80/20:** *Glue is five things sharing a name — **Data Catalog** (used by Athena/Spectrum/EMR), **Crawler** (auto schema discovery), **ETL Jobs** (serverless Spark), **Studio** (visual ETL for engineers), **DataBrew** (no-code for analysts), **Schema Registry** (streaming validation). Catalog + Crawler + ETL Jobs are the exam-critical trio. Glue is to ETL what Athena is to SQL: serverless. Use EMR when you need frameworks Glue doesn't ship.*

## AWS Lake Formation

**Anchored in Glue + S3 + IAM.** S3 holds the bytes. The **Glue Data Catalog** holds the schema. **IAM and S3 bucket policies** control access — but only at bucket/prefix/table granularity. Lake Formation is the **fine-grained access-control and governance layer** that sits on top, so you can say "user X can read columns A and B but **not** column SSN, and only rows where region = 'EU'."

```
Without Lake Formation:  "Can user X read the orders table?"  (table-level only)
With Lake Formation:     "Can user X read columns A, B, C but NOT SSN,
                          only for rows where region = 'EU'?"  (cell-level)
```

The headline is security and governance — yes.

### What Lake Formation Adds

| Capability | What it adds |
| ---------- | ------------ |
| **Centralised permissions** | Grant/revoke at database, table, column, row, or cell level — *once*, applied across all consumers |
| **LF-Tags** (Lake Formation tags) | Tag-based access control: tag a column `PII=true`, then grant "no access to anything tagged PII" to a role |
| **Row-level filters** | `WHERE region = 'EU'` baked into the permission; users see only their slice |
| **Cross-account sharing** | Share a table from account A to account B **without copying data**; consumer's queries see it natively (uses AWS RAM under the hood) |
| **Data-lake setup helpers** | Register S3 locations, blueprint workflows to ingest from RDS/Aurora into the lake |
| **Centralised audit** | Track who queried which columns; pairs with CloudTrail |

### Who Honours Lake Formation Permissions

Lake Formation policies are enforced by the analytics services that integrate with it:

- **Athena**, **Redshift Spectrum**, **EMR**, **Glue**, **QuickSight**

A custom client that hits S3 directly (e.g. a Spark job using S3 URIs without going through Glue Catalog) **bypasses** Lake Formation. The catalog-aware services are the choke point.

### The Mental Model

```
S3              → where the bytes live
Glue Catalog    → where the schema (table definitions) live
Lake Formation  → who can see what — at column/row/cell granularity
```

### Classic Use Cases

- *"Analysts can query the customer table but must NOT see SSN / email columns"* → Lake Formation **column-level permissions**
- *"EU team can only see rows where `region = 'EU'`"* → **row-level filters**
- *"Share a production table with the data science account without copying data"* → **cross-account sharing**
- *"Centralised data lake governance across many AWS accounts"* → Lake Formation
- *"GDPR / HIPAA compliance for the data lake"* → column/row controls + centralised audit

### Common Anti-patterns (exam wrong answers)

- **Using S3 bucket policies for column-level data-lake permissions** — impossible at that granularity. Lake Formation is the answer.
- **Using Lake Formation when simple IAM + table-level access is enough** — overkill for single-account, table-level needs.
- **Expecting Lake Formation to control tools it doesn't integrate with** — only catalog-aware services (Athena, Spectrum, EMR, Glue, QuickSight) enforce it. Direct S3 readers bypass it.
- **Confusing Lake Formation with Macie** — **Macie** *discovers* sensitive data (PII detection in S3). Lake Formation *controls access* to known data. They're complementary, not interchangeable.

### Exam Triggers

- *"fine-grained access control on a data lake"* → **Lake Formation**
- *"column-level / row-level / cell-level permissions on S3 data"* → **Lake Formation**
- *"share tables across AWS accounts without copying data"* → **Lake Formation cross-account sharing**
- *"centralised data lake governance"* → **Lake Formation**
- *"GDPR / PII compliance — hide columns from certain users"* → **Lake Formation column permissions**
- *"discover and classify sensitive data in S3"* → **Macie** (NOT Lake Formation)
- *"build and secure a data lake quickly"* → **Lake Formation**

**The 80/20:** *Lake Formation is the access-control + governance layer on top of S3 + Glue Data Catalog. It exists because IAM and S3 bucket policies can't do column/row/cell-level permissions on data lakes. If a question mentions fine-grained data-lake permissions, cross-account table sharing, or column/row-level access, Lake Formation is the answer. Macie discovers; Lake Formation controls.*

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

### Athena vs DynamoDB (the "both are serverless" trap)

Exam questions often pair Athena with DynamoDB because both are serverless. But they solve completely different problems — picking DynamoDB when Athena is right (or vice versa) is one of the most common exam traps. Match the constraints in the question, not just the "serverless" tag.

**Example question pattern:** *"Log files in S3, perform quick analysis, serverless, find users who attempted unauthorised actions."*

| Constraint | Athena | DynamoDB |
| ---------- | ------ | -------- |
| **Data already in S3 — no loading** | ✅ Queries S3 in place | ❌ Doesn't read S3; you'd ETL every log into DynamoDB items first |
| **"Quick analysis"** | ✅ Point + SQL query → done | ❌ Plan keys/GSIs, load data, then query |
| **Filter by an arbitrary attribute** (e.g. `action = 'unauthorized'`) | ✅ Standard SQL | ❌ No general filter — Query needs the partition key; Scan reads the entire table |
| **Serverless** | ✅ | ✅ (the only box DynamoDB ticks — and not enough on its own) |

**Why DynamoDB falls apart for "query logs in S3":**

1. **Wrong data location** — DynamoDB is a database (put data in, look it up by key). The logs are already in S3. Loading them in is itself a project, not a "quick analysis."
2. **Wrong query shape** — DynamoDB is built for *"give me item with ID=X"*. The question wants *"find all items where `action='unauthorized'`"* — that's a filter, not a key lookup. Efficient filter on DynamoDB requires a pre-designed GSI on the filter attribute. You don't design infrastructure for ad-hoc forensic queries.
3. **Even with data loaded, you'd Scan** — querying without the partition key forces a full Scan: expensive and slow.

**The mental model:**

```
Athena    = "I have data sitting in S3 and want to query it ad-hoc"
DynamoDB  = "I'm building an app that needs key-based lookups in milliseconds"
```

Different services, different problems. The exam question's "S3 + quick analysis + filter" framing fits Athena cleanly.

**The "serverless" trap — general lesson:**

"Serverless" alone is **never** the discriminator in an exam question. Lambda, S3, SNS, SQS, EventBridge, DynamoDB, Athena, Step Functions, Aurora Serverless v2, Fargate, OpenSearch Serverless — all qualify. You always need a second constraint (data location, query shape, latency, durability, access pattern) to pick between them. If two options are both serverless, ignore that word and compare them on the *other* criteria the question lists.

**Vocabulary mapping (the question pattern → the right answer):**

| Phrase in the question | Service |
| ---------------------- | ------- |
| *"log files in S3, query with SQL, serverless"* | **Athena** |
| *"CloudTrail / VPC Flow Logs / ALB logs / S3 access logs"* | **Athena** (these are all S3-resident log formats) |
| *"key-based lookup with single-digit ms latency"* | **DynamoDB** |
| *"search across text fields in logs, dashboards"* | **OpenSearch** |
| *"occasional log query, minimise idle cost"* | **CloudWatch Logs Insights** |

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

### Where Does OpenSearch Actually Store the Data?

A genuine source of confusion. Two clear answers:

1. **Yes, OpenSearch stores the logs itself.** Each data node has **EBS volumes** holding the indexed documents.
2. **But don't treat it as a primary database.** The production pattern is: **raw logs land in S3 (source of truth), and OpenSearch holds the indexed copy for search**. If the cluster dies, you rebuild from S3.

**How it stores each document:**

```
Document: {"timestamp":"...","user":"alice","action":"login_failed","ip":"1.2.3.4"}
       ↓
OpenSearch stores:
  - The raw JSON document (on disk via EBS)
  - An inverted index alongside:
        "login_failed" → [doc-id-1, doc-id-7, doc-id-22, ...]
        "alice"        → [doc-id-1, doc-id-9, ...]
        "1.2.3.4"      → [doc-id-1, doc-id-3, ...]
  - Distributed across shards, replicated for resilience
```

Search is fast because looking up "login_failed" gives you doc IDs immediately — no scanning every document.

### Three Storage Tiers (cost optimisation)

OpenSearch has built-in tiering so you don't keep everything on expensive hot nodes:

| Tier | Where data lives | Performance | Cost | Use for |
| ---- | ---------------- | ----------- | ---- | ------- |
| **Hot** | EBS on data nodes | Fast (ms) | $$$ | Recent logs queried daily |
| **UltraWarm** | Backed by **S3** under the hood | Slower (seconds) | ~10% of hot | Older logs queried occasionally |
| **Cold** | Also backed by S3; must "attach" indices before querying | Slowest | Cheapest | Compliance retention, rarely queried |

Typical pattern: **hot for last 30 days, UltraWarm for last 90 days, cold for everything older**.

### Is OpenSearch a Database?

**Technically yes** — it persists data, indexes it, replicates it. But categorise it as a **search engine / analytics store**, not a traditional database:

| | OpenSearch | DynamoDB / RDS (true primary DBs) |
| - | ---------- | --------------------------------- |
| Persistent storage | Yes | Yes |
| ACID transactions | ❌ No | ✅ Yes |
| Joins | ❌ Limited / not at scale | ✅ Yes (RDS) |
| Source of truth | **No — typically not** | **Yes** |
| Built for | Search + analytics over documents | Operational reads/writes by key/query |
| Loses data if cluster dies | Possible — treat as rebuildable | No — durable by design |

### The Canonical Architecture

```
Apps  ──→  Kinesis Firehose  ──┬──→  S3 (raw logs, cheap, durable, source of truth)
                                │         retention: months / years for compliance
                                │
                                └──→  OpenSearch (indexed copy for search + dashboards)
                                          retention: days / weeks — short, hot
```

**Why both:**
- **S3** — effectively infinite, ~$0.023/GB/month, durable. The perfect cold archive.
- **OpenSearch** — expensive per GB, but searches in milliseconds. Terrible as a cold archive, unbeatable for live querying.

If OpenSearch fails or you blow away the cluster, **S3 still has every log**. Rebuild OpenSearch from S3 via Firehose, Logstash, or OpenSearch Ingestion.

**Anti-patterns (exam wrong answers):**

- *"Store 7 years of logs in OpenSearch for compliance"* — wildly expensive. Use S3 for long retention; OpenSearch for short hot retention only.
- *"OpenSearch as our single source of truth for orders / users / payments"* — wrong shape; no ACID, no joins. Use RDS / DynamoDB; index them in OpenSearch for search.
- *"Skip S3, ship logs straight to OpenSearch only"* — cluster failure or misconfigured index lifecycle = logs gone. Always keep S3 in the pipeline.

**Exam triggers:**

- *"long-term log retention for compliance"* → **S3** (paired with OpenSearch for the hot portion)
- *"reduce OpenSearch cost for older log data"* → **UltraWarm / Cold storage tiers**
- *"rebuild OpenSearch index from raw logs"* → **replay from S3** via Firehose / OpenSearch Ingestion

### Classic Use Cases

| Use case | Why OpenSearch wins |
| -------- | ------------------- |
| **Application logs / centralised logging** | "ELK / EFK stack" — apps ship logs to Kinesis Firehose → OpenSearch; engineers search and visualise in Dashboards |
| **Full-text search** for an e-commerce / SaaS product | Search-as-you-type, typo tolerance, relevance ranking — way beyond `LIKE` queries |
| **Real-time observability dashboards** | Time-series aggregations on operational data (latency P95, error rate per endpoint) |
| **Security analytics / SIEM** | OpenSearch has a security analytics module; correlate VPC Flow Logs + CloudTrail + WAF logs |
| **Clickstream / behavioural analytics** | Aggregate millions of events per second, query in seconds |

**The canonical OpenSearch logging pipeline (memorise this — exam-favourite):**

```
App logs / CloudWatch Logs / VPC Flow Logs
       │
       ▼
Kinesis Data Firehose
       │
       ├── (optional) Lambda transform (parse, enrich, redact PII)
       │
       ▼
OpenSearch Service
       │
       ▼
OpenSearch Dashboards (the Kibana fork — search + visualise)
```

If a question describes "stream logs from many sources into a searchable analytics store with rich dashboards," this is the architecture.

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

**The 80/20:** *managed Elasticsearch + Kibana fork; two superpowers — full-text search and log analytics with dashboards; the pipeline is Firehose → OpenSearch; it's an **index**, not a database; CloudWatch Logs Insights is the cheap alternative for infrequent log search.*

## Amazon EMR

**Anchored in services you know.** Athena runs interactive SQL on S3. Glue runs serverless Spark for ETL. Redshift is the warehouse. **EMR is the managed cluster running the full big-data ecosystem** — Hadoop, Spark, Hive, HBase, Presto/Trino, Flink, Pig. You get more frameworks, more control, more flexibility — at the cost of running a cluster.

```
Athena    → just SQL, on S3, interactive, serverless, no code
Glue      → ETL pipelines, Spark, serverless, integrated with Data Catalog
Redshift  → data warehouse, columnar storage, BI dashboards
EMR       → run any big-data framework on a cluster you control (or serverless)
```

### Three Deployment Modes

| Mode | What it is |
| ---- | ---------- |
| **EMR on EC2** | Classic — you size the cluster, install frameworks, pay for instances. Use **transient clusters** that spin up for a job and tear down to save cost |
| **EMR on EKS** | Run EMR workloads on an existing Kubernetes cluster |
| **EMR Serverless** | No cluster — pay per task/runtime. Sweet spot for Spark/Hive without ops overhead |

### When EMR Is the Right Answer

| Workload | Why EMR over the alternatives |
| -------- | ----------------------------- |
| **Petabyte-scale ETL with Spark/Hive** | Glue can do this too — pick EMR if you need version control, custom libraries, long-running jobs, or already have on-prem Spark code |
| **Lift-and-shift Hadoop/Spark from on-prem** | EMR is the natural home — same Apache stack, just managed |
| **Machine learning training data prep at scale** | Spark MLlib, distributed feature engineering across TB+ data |
| **Streaming with Flink or Spark Streaming** | EMR runs these; Kinesis Data Analytics is more limited |
| **HBase / Hudi / Iceberg / Delta Lake workloads** | EMR ships these frameworks; nothing else does as cleanly |
| **Interactive Presto/Trino with cluster control** | Same engine as Athena but with sizing/tuning control |

### When EMR Is the WRONG Answer

| If you only need… | Use instead |
| ----------------- | ----------- |
| Interactive SQL on S3 | **Athena** (no cluster, pay per query) |
| Managed ETL pipeline | **AWS Glue** (serverless Spark, less ops) |
| BI dashboards on big data | **Redshift** |
| Short-running event processing | **Lambda** (+ Kinesis if streaming) |
| Real-time alerting on streams | **Kinesis Data Analytics** (Flink-based, managed) |
| Search / log analytics | **OpenSearch** |

### The Decision Tree

```
Need to process big data?
├── Just SQL on S3 occasionally?            → Athena
├── BI dashboards, frequent complex SQL?    → Redshift
├── Simple ETL pipeline, want serverless?   → Glue
├── Need Hadoop / Spark / Hive / HBase /
│   Flink / Presto with cluster control?    → EMR
└── Want EMR features but no cluster ops?   → EMR Serverless
```

### Real-World Scenarios Where EMR Wins

- *"Lift-and-shift our on-prem Spark/Hadoop pipeline to AWS"* — same code, EMR runs it.
- *"Train ML models on 50 TB of clickstream data"* — Spark MLlib on EMR.
- *"Process Delta Lake / Hudi / Iceberg tables"* — EMR ships these; Glue is catching up but EMR is still the default.
- *"Run a custom Hive UDF written by our data team"* — full control over the cluster + libraries.
- *"Stream-process Kinesis events with Flink"* — EMR + Flink, or Kinesis Data Analytics if you want managed.

### Common Anti-patterns (exam wrong answers)

- **EMR for occasional SQL on S3** — overkill; cluster cost dominates. Use Athena.
- **EMR when AWS Glue would do** — Glue is cheaper, simpler, serverless. Pick EMR only when you need a framework Glue doesn't have or need cluster control.
- **EMR for short-running event processing** — Lambda or Kinesis is the right answer.
- **EMR for BI dashboards** — Redshift is built for it.
- **EMR cluster running 24/7 for nightly batch jobs** — use **EMR Serverless** or transient clusters that start/stop per job.

### Exam Triggers

- *"managed Hadoop / Spark / Hive / HBase / Flink / Presto cluster"* → **EMR**
- *"lift and shift existing Hadoop/Spark workload to AWS"* → **EMR**
- *"petabyte-scale ETL with Apache Spark, need cluster control"* → **EMR** (or **Glue** if you want serverless and don't need control)
- *"train ML model on terabytes of data with Spark MLlib"* → **EMR**
- *"Delta Lake / Hudi / Iceberg processing"* → **EMR**
- *"Spark jobs without managing a cluster"* → **EMR Serverless** or **Glue**
- *"transient cluster that spins up for a job and tears down after"* → **EMR** transient cluster pattern
- *"interactive Presto with cluster sizing control"* → **EMR with Presto** (or Athena if you want serverless)

**The 80/20:** *EMR is the managed home for the full Apache big-data stack (Spark, Hadoop, Hive, HBase, Flink, Presto). Pick it when you need a framework Athena/Glue/Redshift don't offer, or you're lifting on-prem Hadoop/Spark to AWS. For interactive SQL → Athena; serverless ETL → Glue; warehouse → Redshift; everything else big-data → EMR (or EMR Serverless).*

## Amazon QuickSight

**Anchored against Datadog** — because the instinct to call this "AWS Datadog" is wrong, and the exam exploits that confusion.

QuickSight is AWS's **BI / Business Intelligence** tool. Its competitors are **Tableau, Looker, Power BI** — not Datadog. Both show data on dashboards, but they live in different worlds:

| | Amazon QuickSight | Datadog |
| - | ----------------- | ------- |
| Category | **BI / Business Intelligence** | **Observability / APM / Monitoring** |
| Data source | Data warehouses + databases — **Redshift, Athena, RDS, S3 (via Athena), Snowflake**, SaaS connectors | **Live operational telemetry** — metrics, traces, logs from servers/apps via agents |
| Typical user | Analysts, finance, marketing, execs | SREs, DevOps, on-call engineers |
| Typical question | *"Revenue by region by quarter"*, *"customer cohort retention"* | *"P99 latency on the checkout API right now"*, *"5xx error spike at 14:32"* |
| Data freshness | Minutes-to-hours-old (warehouse refresh) | Seconds-old (live telemetry) |
| Closest competitors | **Tableau, Looker, Power BI** | **New Relic, Dynatrace, Splunk Observability, Grafana Cloud** |

### The Real AWS-Native Datadog Competitor

If a question describes Datadog-shaped work — *"monitor application latency, error rates, infrastructure metrics, traces, logs in one place"* — the AWS answer is the **observability bundle**, not QuickSight:

```
Datadog (one product) ≈ CloudWatch (metrics + logs + alarms + dashboards)
                       + CloudWatch Logs Insights (log queries)
                       + X-Ray (distributed tracing)
                       + OpenSearch + Dashboards (richer log analytics)
```

Datadog rolls all of those into one slick UI. AWS sells each piece separately.

### QuickSight Key Properties

- **Serverless** — no infrastructure to manage
- **SPICE** — in-memory cache that accelerates dashboards (terabyte-scale, columnar). Data is ingested into SPICE on a schedule; dashboards query SPICE, not the source
- **Direct query mode** — alternative to SPICE; runs every query live against the source (Redshift, Athena, RDS). Good for always-fresh data, slower per query
- **QuickSight Q** — ML-powered natural-language queries (*"show me sales by region last quarter"* in plain English)
- **Embed in apps** — Embedded Analytics SDK; build QuickSight dashboards into your own product
- **Pricing** — per-user authors + per-reader pay-per-session

### When You'd Reach for QuickSight

- *"Executive sales dashboard backed by Redshift"*
- *"Show analysts a self-service way to slice the data warehouse"*
- *"Embed a billing dashboard into our SaaS product"*
- *"Customer wants a Tableau-style tool, AWS-native"*
- *"Connect natural-language queries to our data warehouse"* (QuickSight Q)

### Common Anti-patterns (exam wrong answers)

- **Using QuickSight as a monitoring / observability tool** — wrong product. CloudWatch + Logs Insights + X-Ray + OpenSearch is the AWS observability stack.
- **QuickSight on real-time streaming data with sub-second freshness** — QuickSight refreshes on schedule (SPICE) or per query (Direct Query). Real-time live ops dashboards belong in CloudWatch / OpenSearch / Grafana.
- **Using QuickSight as the data store** — it's a visualisation layer; data lives in Redshift / Athena / RDS / S3.
- **Picking QuickSight when the team needs trace analysis** — that's X-Ray (or a third-party APM).

### Exam Triggers

- *"BI dashboard on top of Redshift / Athena / RDS"* → **QuickSight**
- *"AWS-native alternative to Tableau / Looker / Power BI"* → **QuickSight**
- *"natural-language queries against the data warehouse"* → **QuickSight Q**
- *"embed analytics dashboards into a SaaS product"* → **QuickSight Embedded Analytics**
- *"in-memory cache to accelerate dashboard queries"* → **SPICE**
- *"monitor latency / error rates / traces"* → **CloudWatch + X-Ray** (NOT QuickSight)
- *"AWS equivalent of Datadog"* → **CloudWatch + Logs Insights + X-Ray + OpenSearch** (NOT QuickSight)

**The 80/20:** *QuickSight is AWS Tableau, not AWS Datadog. It visualises data in warehouses/databases for business users; it does not monitor running systems. The Datadog-equivalent on AWS is the CloudWatch + Logs Insights + X-Ray + OpenSearch bundle.*

## Big Data Ingestion Pipelines

The reason exam questions on data pipelines are hard isn't the individual services — you know those — it's choosing *which combination* solves the scenario. This section ties the messaging + analytics services together into the canonical pipelines.

### The Universal Pipeline Skeleton

Every big-data ingestion scenario maps to this five-stage shape:

```
Source → Buffer/Transport → Process → Store → Query/Consume
```

Identify the right service at each stage and the answer falls out. The decision table at the end of this section is the cheat sheet.

### Five Canonical Pipelines

#### 1. Real-time Log Analytics

```
App logs / VPC Flow Logs / CloudTrail
       ↓
Kinesis Firehose  ──── (optional Lambda transform: parse, enrich, redact PII)
       ↓                                  ↓
OpenSearch Service              S3 (Parquet, partitioned)
       ↓                                  ↓
OpenSearch Dashboards         Athena (ad-hoc) + Glue Catalog
```

**When:** centralised logging, observability, ELK-style search.

#### 2. Clickstream / Event Streaming for Real-time Reactions

```
Web/Mobile apps ──→ Kinesis Data Streams
                          ↓                        ↓
                  Lambda (stateless              Managed Flink (stateful:
                  per-event reactions)            windows, joins, CEP)
                          ↓                        ↓
              DynamoDB (counters) + S3        OpenSearch (live dashboards)
```

**When:** real-time fraud detection, leaderboards, personalisation, abuse signals.

#### 3. Operational DB → Analytics Warehouse (CDC pattern)

```
RDS / Aurora production
       ↓
DMS with full load + CDC (continuous change capture)
       ↓
S3 (raw landing zone) ─→ Glue ETL (clean, convert to Parquet)
                              ↓
                  Glue Data Catalog (schema)
                              ↓
                  ┌───────────────────────────────┐
                  ▼                               ▼
         Redshift COPY               Athena (ad-hoc)
         (warehouse for BI)                ↓
                  ↓                  Federated joins
            QuickSight dashboards
```

**When:** "move data out of production OLTP for analytics" — classic exam scenario.

#### 4. File Upload → Analytics-Ready

```
Customer uploads CSV/JSON → S3 (raw bucket)
                                  ↓
                          S3 Event Notification
                                  ↓
              ┌──────────────────┴──────────────────┐
              ▼                                     ▼
      Lambda (lightweight)                Glue ETL (heavyweight Spark)
       quick validation                   convert CSV → Parquet,
              ↓                                  partition, dedupe
      S3 (cleaned bucket)                          ↓
              ↓                            Glue Data Catalog
        Glue Crawler                               ↓
              ↓                              Athena + QuickSight
       Glue Data Catalog
              ↓
     Athena + QuickSight
```

**When:** "customers / partners upload files for analysis," self-service data lake ingestion.

#### 5. IoT at Massive Scale (Lambda Architecture — Real-time + Batch)

```
Millions of devices ──→ AWS IoT Core (MQTT)
                              ↓
                    Kinesis Data Streams
                              ↓
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
         Kinesis        Managed Flink    Lambda
         Firehose       (windowed         (device state
            ↓            aggregations)      → DynamoDB)
        S3 (raw)              ↓
            ↓           Timestream
       Glue ETL         (time-series
            ↓            live dashboards)
       Athena
       (historical)
```

**When:** IoT, telemetry at huge scale, with both live dashboards and historical querying.

### Which Service at Each Stage

| Stage | Need | Pick |
| ----- | ---- | ---- |
| **Source** | Servers / apps | SDK push to Kinesis / MSK / Firehose |
| | IoT devices | **AWS IoT Core** |
| | Operational DB | **DMS** (full load + CDC) |
| | File drops | **S3 + Event Notification** |
| **Buffer/Transport** | Just land in S3 | **Kinesis Firehose** |
| | Replay + multiple consumers | **Kinesis Data Streams** or **MSK** |
| | Kafka-compatible / existing Kafka workload | **MSK** |
| **Process** | Per-event, stateless | **Lambda** |
| | Stateful, windowed, joins | **Managed Apache Flink** |
| | Heavy ETL, Spark | **Glue ETL** (serverless) or **EMR** (more control) |
| | No-code analyst prep | **Glue DataBrew** |
| **Store** | Data lake | **S3 + Glue Data Catalog** |
| | Warehouse for BI | **Redshift** |
| | Search / log analytics | **OpenSearch** |
| | Time-series | **Timestream** |
| | Operational lookups | **DynamoDB / RDS** |
| **Query/Consume** | Ad-hoc SQL on S3 | **Athena** |
| | BI dashboards | **QuickSight** (or third-party via Redshift) |
| | Search UI | **OpenSearch Dashboards** |
| | Programmatic | SDK to the underlying store |

### Common Anti-patterns (exam wrong answers)

- **Picking Kinesis Data Streams when Firehose would do** — if all you need is "buffer events and write to S3/Redshift/OpenSearch with no code," Firehose is the answer. Data Streams is for when you need replay + multiple consumers.
- **Lambda for stateful windowed aggregations** — use Flink.
- **Writing raw CSV/JSON to S3 forever** — Athena scan costs balloon. Convert to Parquet + partition via Glue ETL.
- **One-million-tiny-files pattern from per-event PUTs to S3** — buffer with Firehose first (1–128 MB output files).
- **Loading directly into Redshift from production OLTP via JDBC** — kills the OLTP DB. Use **DMS + CDC** through S3.
- **DataSync for a database** — DataSync is for files (S3/EFS/FSx). DMS is for databases.
- **Picking Athena for queries that run every minute on the same data** — load into Redshift instead; cost flips at volume.

### Exam Triggers

- *"centralised log analytics with dashboards"* → **Firehose → OpenSearch + S3**
- *"clickstream into a data lake"* → **Kinesis Data Streams → Firehose → S3**
- *"migrate production DB to a warehouse with minimal downtime"* → **DMS (full load + CDC) → S3 → Glue → Redshift**
- *"customer uploads CSV, want it queryable with SQL"* → **S3 event → Glue ETL → Parquet → Athena**
- *"IoT telemetry at millions of devices, both live and historical"* → **IoT Core → Kinesis → Firehose (S3) + Flink (Timestream)**
- *"convert raw S3 data to columnar for cheap Athena queries"* → **Glue ETL → Parquet + partitioning**
- *"replay an event stream from yesterday"* → **Kinesis Data Streams / MSK** (NOT Firehose, NOT SNS)
- *"fraud detection in real time on a stream"* → **Kinesis → Flink** (or Lambda for stateless rules)

**The 80/20 — the universal skeleton:**

```
Source → Buffer/Transport → Process → Store → Query/Consume
   ?            ?              ?         ?         ?
```

Five questions, one per stage. Identify each from the exam scenario and the answer falls out. The three most common pipelines: **logs → Firehose → OpenSearch**, **events → Kinesis → Lambda/Flink → S3 + DynamoDB**, and **operational DB → DMS → S3 → Glue → Redshift**.

## AWS AI/ML Services

AWS splits AI/ML into two layers:

1. **Pre-trained services** — call an API, get an answer. You don't train anything. Each service targets one input type (images, text, speech, video, documents).
2. **Build-your-own platform** — **SageMaker** for the full ML lifecycle when no pre-trained service fits.

The exam shortcut: **pick the pre-built service that matches your input type before reaching for SageMaker.**

### The Family at a Glance

| Service | Input | What it does | Anchor |
| ------- | ----- | ------------ | ------ |
| **Rekognition** | Images & video | Computer vision — detect objects, faces, text, content moderation, PPE | "AWS for image/video AI" |
| **Comprehend** | Text | NLP — sentiment, entities, key phrases, language detection, PII detection | "Rekognition for text" |
| **Translate** | Text | Language translation | "Google Translate API" |
| **Transcribe** | Audio | Speech-to-text | "audio → text" |
| **Polly** | Text | Text-to-speech (lifelike voices) | "text → audio" |
| **Textract** | Documents (PDFs, scans) | Extract text **+ structure** from forms, tables, receipts | "OCR with layout" |
| **Lex** | Text/voice | Build chatbots (powers Alexa) | "build a chatbot" |
| **Personalize** | User events | Recommendation engine | "Netflix-style recommendations" |
| **Forecast** | Time-series data | Demand / metric forecasting | "predict future numbers" |
| **Bedrock** | Anything (LLMs) | Foundation models / GenAI — call Claude, Llama, Titan via one API | "AWS gateway to LLMs" |
| **SageMaker** | Anything | Build/train/deploy **your own** ML models — end-to-end platform | "DIY ML" |

### Amazon Rekognition (the headliner for computer vision)

**Capabilities:**

| Capability | What you get back |
| ---------- | ----------------- |
| **Object & scene detection** | "cat (98%)", "beach (94%)" with bounding boxes |
| **Facial analysis** | Age range, emotion, gender, glasses/beard, smile, eyes-open |
| **Face comparison** | Similarity score between two faces |
| **Face search** in a face collection | "Does this face match anyone in our DB of 100k stored faces?" |
| **Celebrity recognition** | Identify well-known people |
| **Content moderation** | Flag explicit / suggestive / violent imagery |
| **Text detection** | OCR-lite — signs, license plates, screenshots (use **Textract** for documents) |
| **PPE detection** | Helmets, masks, gloves — safety/compliance use |
| **Custom Labels** | Train your own image classifier with ~10–100 images per class |
| **Video analysis** | Stored video (S3) or live video (Kinesis Video Streams) — async output to SNS |

**Classic Rekognition pipelines:**

```
User uploads photo → S3 → S3 event → Lambda → Rekognition.DetectLabels()
                                              → store JSON tags in DynamoDB
                                              → moderation flag? → SNS alert
```

- **Content moderation** — S3 upload → Lambda → `DetectModerationLabels` → block or quarantine
- **User photo tagging** — auto-tag uploaded photos for search
- **Identity verification (KYC)** — selfie + ID photo → `CompareFaces` → match score
- **Smart camera** — Kinesis Video Streams → Rekognition Video → real-time person detection
- **Safety compliance** — factory camera → `DetectProtectiveEquipment` → flag missing helmet

### Amazon Transcribe (the headliner for speech-to-text)

**Anchored against Rekognition.** Rekognition is "what's in this image/video?"; Transcribe is "what was said in this audio/video?" — both pre-trained APIs, you call them and get JSON back.

**Two execution modes:**

| Mode | How it works | Use case |
| ---- | ------------ | -------- |
| **Batch** | Audio file in S3 → start a job → output transcript JSON to S3 | Podcasts, recorded meetings, call recordings, archived video |
| **Streaming** | Open a websocket / HTTP/2 stream → push audio chunks → receive partial transcripts in real time | Live captions, voice assistants, real-time call monitoring |

**Key features (exam-relevant):**

| Feature | What it does |
| ------- | ------------ |
| **Speaker diarization** | Identifies who said what — `"Speaker 1: ...", "Speaker 2: ..."`. Up to 10 speakers |
| **Channel identification** | For stereo audio (call recordings), left = caller, right = agent — separate transcripts per channel |
| **Custom vocabulary** | Teach Transcribe your brand names, product names, jargon — *"Magnetar"* instead of *"magnet are"* |
| **Custom language models** | Train on domain-specific corpora for higher accuracy on niche vocabulary |
| **PII redaction** | Built-in: redact SSN, credit-card numbers, names, addresses from transcripts |
| **Vocabulary filtering** | Block profanity or sensitive terms |
| **Subtitle output** | Generate **WebVTT** or **SubRip (SRT)** subtitle files directly |
| **Automatic language identification** | Detect the spoken language when you don't know in advance |
| **Call Analytics** | Special mode for call centers — sentiment, talk time, interruptions, issue categorisation |

**Specialised variants:**

- **Transcribe Medical** — trained on medical terminology (clinical notes, doctor-patient dialogue). HIPAA-eligible.
- **Transcribe Call Analytics** — call-center-specific output (sentiment per channel, talk-time ratio, non-talk time)

**Common pipelines:**

```
Call center recording → S3 → Lambda → Transcribe (Call Analytics + PII redaction)
                                          → Comprehend (sentiment / topics)
                                          → QuickSight (dashboards)

Live meeting audio → Transcribe Streaming → real-time captions in the UI

Video uploaded → S3 → Transcribe → SRT/WebVTT subtitles → CloudFront delivers video + subs
```

**Common anti-patterns (exam wrong answers):**

- **Polly for transcription** — Polly is text → audio (the opposite direction). Transcribe is audio → text.
- **Using a generic transcriber for medical dictation** — accuracy is poor on clinical vocab; use **Transcribe Medical**.
- **Trying to find sentiment with Transcribe alone** — Transcribe outputs text. Pair with **Comprehend** for sentiment (or use **Transcribe Call Analytics** which has sentiment built in).
- **Building real-time captions with batch Transcribe** — batch is async, latency in minutes. Use **Transcribe Streaming** for live captions.
- **Hoping Transcribe will magically know brand/product names** — use **Custom Vocabulary** for known proper nouns.

**Exam triggers:**

- *"transcribe a podcast / meeting / call recording"* → **Transcribe** (batch)
- *"real-time captions for a live event / stream"* → **Transcribe Streaming**
- *"identify which speaker said what in a recording"* → **Transcribe** with **speaker diarization**
- *"call-center recording with caller on left channel, agent on right"* → **Transcribe** with **channel identification** (or **Call Analytics**)
- *"redact credit-card numbers / PII from transcripts"* → **Transcribe PII redaction**
- *"generate subtitles for a video library"* → **Transcribe** with WebVTT/SRT output
- *"transcribe a doctor's dictation accurately"* → **Transcribe Medical**
- *"sentiment + talk-time analytics from call recordings"* → **Transcribe Call Analytics** (+ optionally Comprehend)
- *"my transcripts misspell our product name"* → **Custom Vocabulary**

### Amazon Polly (the headliner for text-to-speech)

**Anchored against Transcribe.** Transcribe is audio → text (recognition). **Polly is text → audio** (synthesis). Same pre-trained API pattern; opposite direction. They often pair for voice apps.

```
"Hello, Bobby. Your delivery has arrived." → Polly → audio bytes (MP3/OGG/PCM)
```

**Voice engine tiers (matters for cost + quality):**

| Engine | Quality | Cost | Use for |
| ------ | ------- | ---- | ------- |
| **Standard** | Concatenative; "fine" — robotic in places | Cheapest | Quick prototypes, IVR menus where naturalness isn't critical |
| **Neural (NTTS)** | Neural-network synthesis — much more natural | Higher | Production apps, customer-facing voice |
| **Long-form** | Tuned for long content (articles, books) — natural pacing over paragraphs | Higher | Article narration, audiobooks |
| **Generative** | Newest tier; most natural, conversational, emotionally expressive | Highest | Premium experiences, lifelike chatbots |

**Key features:**

| Feature | What it does |
| ------- | ------------ |
| **30+ languages, many voices per language** | Male/female, regional accents, age ranges |
| **SSML** (Speech Synthesis Markup Language) | XML markup to control pronunciation, emphasis, pauses, whispering, breathing, speed |
| **Pronunciation lexicons** | Define custom pronunciation for industry terms / brand names / proper nouns |
| **Speech marks** | Word/sentence/viseme timing metadata — for **lip-syncing**, karaoke, subtitle alignment |
| **Brand Voice** | Custom voice trained on a brand's recordings (enterprise; long lead time) |
| **Real-time streaming** | Synthesise + stream audio chunks as produced (low-latency voice) |
| **Save to S3** | Async synthesis for long inputs — output stored as an S3 object |

**Canonical pipelines:**

```
Chatbot voice:     User text/voice → Lex (or Bedrock) → response text → Polly → audio reply

Article narration: Article text → Polly (Long-form voice) → S3 → CloudFront → mobile app
                                                            (synthesise once, replay forever)

IVR / call center: Caller → Amazon Connect → Lex understands intent
                                           → Polly speaks the response

Accessibility:     Page text → Polly streaming → audio playback for visually impaired users
```

**Common anti-patterns (exam wrong answers):**

- **Polly for transcription** — Polly does TTS, not STT. **Transcribe** is the right service for audio → text.
- **Standard voices for production customer-facing audio** — sounds robotic. Use **Neural** (or **Generative** for premium).
- **Synthesising the same content on every request** — for static text (articles, menus, FAQ), synthesise once and cache in **S3** behind CloudFront. Don't pay per request when output never changes.
- **Trying to fix awkward pronunciation by misspelling the input text** — use **SSML** (`<phoneme>` tag) or a **pronunciation lexicon** for proper nouns and brand names.
- **Using Polly for on-demand voice cloning** — that's **Brand Voice** (enterprise, long lead time); not a self-service feature.

**Exam triggers:**

- *"text-to-speech with natural-sounding voices"* → **Polly**
- *"convert articles / news / books into audio"* → **Polly** (Long-form voice)
- *"voice responses for a chatbot"* → **Lex + Polly** (or **Bedrock + Polly**)
- *"build an IVR / interactive voice response system"* → **Connect + Lex + Polly**
- *"screen reader / accessibility audio for a website"* → **Polly**
- *"control pronunciation, emphasis, pauses programmatically"* → **Polly with SSML**
- *"fix the way Polly says our brand name"* → **pronunciation lexicon** (or SSML `<phoneme>`)
- *"lip-sync animated character with Polly's audio"* → **Polly speech marks** (visemes)
- *"low-latency conversational voice for an AI assistant"* → **Polly Neural / Generative** with real-time streaming
- *"transcribe audio"* → **Transcribe** (NOT Polly — opposite direction)

### Amazon Translate (the headliner for machine translation)

**Anchored against Polly / Transcribe.** Another single-purpose pre-trained API: Polly synthesises speech, Transcribe recognises speech, **Translate converts text between languages**. Text in language A → text in language B.

```
"The package will arrive tomorrow" (en)
            ↓ Translate
"Le colis arrivera demain" (fr)
"El paquete llegará mañana" (es)
"パッケージは明日届きます" (ja)
```

- **75+ languages** supported
- **Pay per character** translated
- **Auto language detection** if source unknown (uses Comprehend under the hood)
- **Real-time** API + **batch / async** for large S3 jobs
- **Document translation** preserves formatting for PDF / DOCX / HTML

**Key features:**

| Feature | What it does |
| ------- | ------------ |
| **Custom Terminology** | Define exact translations for terms — *"Magnetar always translates as Magnetar"*, not "magnet are". Brand names, product names, jargon |
| **Active Custom Translation (ACT)** | Provide parallel data (your own translation pairs) to influence the model's style/word choice for your domain |
| **Profanity masking** | Mask profanity in the output |
| **Formality setting** | For pairs that distinguish (German `du`/`Sie`, Spanish `tú`/`usted`) — choose formal or informal |
| **Document translation** | Submit a PDF/DOCX/HTML, get translated output with formatting preserved |
| **Real-time API + Batch jobs** | Sync call for chat; async batch for thousands of S3 documents |

**Canonical pipelines:**

```
Multilingual customer support:
  Customer writes in any language → Translate to agent's language
                                  → Agent replies → Translate to customer's language

User-generated content:
  User posts in their language → store original + Translate to viewer's language on read

Website localisation (batch):
  Source content in S3 → Translate (batch) → translated content in S3 per locale

Mixed-language analytics:
  Unknown-language input → Comprehend (detect language)
                         → Translate to English
                         → Comprehend (sentiment / entities)
                         → store

Document translation:
  Contract.pdf → Translate document API → Contract_fr.pdf (formatting intact)
```

**Common anti-patterns (exam wrong answers):**

- **Translate for content *generation*** — Translate converts between languages, it doesn't write new content. Use **Bedrock** for generation.
- **Not using Custom Terminology when you have brand names / proper nouns** — outputs get weird. Define a glossary once.
- **Calling Translate without detecting source language first** when the source is unknown — pair with **Comprehend** for language detection.
- **Using Translate on code or structured data** — it's for natural language. Translating JSON keys or code identifiers breaks things.
- **Confusing Translate with Comprehend** — Comprehend *understands* text (sentiment, entities, language detection). Translate *converts* text between languages.

**Exam triggers:**

- *"translate text between languages, real-time"* → **Translate**
- *"localise a website / mobile app into multiple languages"* → **Translate** (batch jobs from S3)
- *"customer support across languages"* → **Translate** (often paired with Lex/Connect)
- *"translate PDF / DOCX preserving formatting"* → **Translate document translation**
- *"brand names must translate consistently"* → **Translate Custom Terminology**
- *"adapt translation style to our domain with our own parallel data"* → **Active Custom Translation (ACT)**
- *"formal vs informal tone in target language"* → **Translate formality setting**
- *"detect language then translate"* → **Comprehend + Translate**
- *"translate user-generated reviews into the viewer's language"* → **Translate**
- *"redact / mask profanity in translated output"* → **Translate profanity masking**

### Amazon Lex and Amazon Connect (chatbot brain + contact center)

Often paired but solving different parts of the problem. **Lex is the NLU engine** (same one that powers Alexa). **Connect is the cloud call center.** They're not alternatives — Connect *calls* Lex for the natural-language understanding inside an IVR.

#### Amazon Lex — the chatbot brain

Build conversational interfaces (voice **or** text). You define:

| Concept | What it is |
| ------- | ---------- |
| **Intent** | What the user wants — "BookHotel", "CheckBalance", "TrackOrder" |
| **Utterances** | Example phrases for each intent — "I want to book a room", "Reserve a hotel" |
| **Slots** | Parameters the intent needs — `date`, `city`, `room_type` |
| **Prompts** | What Lex asks to fill missing slots — *"Which city?"* |
| **Fulfillment** | A **Lambda** function that executes the intent once slots are filled |

```
User: "Book me a hotel in Paris for Friday"
Lex picks: Intent=BookHotel, slots={city:"Paris", date:"Friday"}
            ↓
        Lambda fulfillment → reservation system → confirmation
            ↓
Lex/Polly: "Your hotel in Paris is booked for Friday, confirmation ABC123."
```

- **Multi-language**, voice **or** text — same definition works for both
- **Lex v2** is current (v1 is legacy)
- Integrates with **Lambda**, **Connect**, mobile/web SDKs

#### Amazon Connect — the cloud contact center

Pay-per-use cloud call center. Replaces traditional on-prem PBX / contact-center systems. No per-seat licensing, no hardware.

| Capability | What it does |
| ---------- | ------------ |
| **Phone numbers** (toll-free, local) | Inbound and outbound calls |
| **Contact flows** | Visual designer for routing, IVR, branching logic |
| **Queues + routing** | Skills-based routing, priority queues |
| **Agent workspace** | Browser-based UI — no software install for agents |
| **Call recording** | Stored in your S3 |
| **Real-time + historical metrics** | Dashboards for ops |
| **Outbound campaigns** | Predictive / preview / progressive dialers |

**Contact Lens for Amazon Connect** — the built-in analytics layer:

- Real-time and post-call **sentiment analysis**
- **Transcription** with PII redaction
- **Issue / category detection** ("customer mentioned cancellation 3 times")
- **Talk-time ratios**, silence detection
- **Agent screen alerts** when sentiment turns negative

#### The Canonical Pipeline (exam-favourite architecture)

```
Caller dials phone number
       ↓
Amazon Connect (cloud contact center)
       ↓
Contact Flow (visual routing logic)
       ↓
Amazon Lex (NLU — "what does the caller want?")
       ↓
AWS Lambda fulfillment (look up account in DynamoDB / RDS, place order, etc.)
       ↓
Amazon Polly (synthesise the spoken response)
       ↓
Caller hears the answer
       ↓ if escalation needed
Route to human agent → Connect agent workspace shows full context
       ↓ after call
Contact Lens (sentiment, issues, transcription)
       ↓
S3 (recording) + Comprehend / QuickSight (analytics dashboards)
```

This stack — **Connect + Lex + Polly + Lambda + Contact Lens** — is the AWS answer to "modernise a call center" and appears constantly in exam questions.

#### Where Each Service Fits

| Layer | Service |
| ----- | ------- |
| **Phone system / call routing / agents** | **Connect** |
| **Understand what the caller wants** (NLU) | **Lex** |
| **Speak responses naturally** | **Polly** |
| **Execute business logic** (lookup, transact) | **Lambda** + databases |
| **Transcribe + analyse calls** | **Contact Lens** (or **Transcribe Call Analytics** outside Connect) |
| **Free-form generative conversation** (LLM-style) | **Bedrock** (Lex is intent/slot-based) |

#### Common Anti-patterns (exam wrong answers)

- **Lex for free-form open-ended conversation** — Lex is built around intents + slots. For true natural conversational AI, **Bedrock + Claude/Llama** is the right answer.
- **Building a traditional rigid menu IVR ("press 1 for sales")** when Lex could understand natural language — Lex elevates IVR from menus to "tell me what you need".
- **Connect for non-phone scenarios** — Connect is contact-center / telephony. For internal video meetings → **Chime SDK**. For chat-only support → **Lex + a web widget**, not Connect.
- **Skipping Contact Lens** when the question mentions sentiment / analytics / transcription inside a call center — Contact Lens is the in-Connect answer.
- **Picking Transcribe alone** when the question is about a *call center* — inside Connect, **Contact Lens** is the integrated path.
- **Confusing Lex with Polly** — Lex understands input; Polly speaks output. They pair, not interchange.

#### Exam Triggers

- *"build a chatbot"* → **Lex**
- *"voice chatbot / voice assistant"* → **Lex + Polly**
- *"natural-language chatbot with intents and slots"* → **Lex**
- *"cloud contact center / call center on AWS"* → **Connect**
- *"replace on-prem PBX / call center"* → **Connect**
- *"intelligent IVR that understands natural language"* → **Connect + Lex + Polly**
- *"call center with agent assistance and screen pops"* → **Connect** with Lambda integration
- *"real-time call sentiment / agent alerts"* → **Contact Lens for Amazon Connect**
- *"transcribe + analyse customer calls inside the call center"* → **Contact Lens**
- *"store call recordings"* → **Connect → S3**
- *"chatbot that holds free-form conversation, no rigid intents"* → **Bedrock** (NOT Lex)
- *"Alexa-like skill / the engine that powers Alexa"* → **Lex** (same NLU engine)
- *"chatbot for a website with text + voice"* → **Lex** (web/mobile SDKs)

**The 80/20:** *Lex = chatbot brain (intents + slots + NLU; powers Alexa). Connect = cloud call center (phone numbers, routing, agents). They pair: Connect handles the call, Lex understands the caller, Polly speaks back, Lambda executes business logic, Contact Lens analyses sentiment + transcribes. For free-form conversational AI use Bedrock instead of Lex.*

### Amazon Bedrock (the headliner for generative AI / foundation models)

**Anchored against Lex.** Lex is intent/slot-based — rigid conversation flows you design in advance. **Bedrock is the opposite end** — call a foundation model (LLM) and get free-form generation, summarisation, Q&A, or chat. One API across many models from Anthropic, Meta, Mistral, AI21, Cohere, Stability AI, and AWS Titan.

```
You: "Summarise this 50-page contract in 5 bullet points"
   ↓
Bedrock (InvokeModel) — pick the model (Claude / Llama / Titan / etc.)
   ↓
LLM response — bullets generated on the fly, no intents, no slots
```

**Why Bedrock matters on the exam:**

- **Fully managed**, no infrastructure — call an API, get a response
- **Multi-model marketplace**: Anthropic Claude, Meta Llama, Mistral, Cohere Command, AI21 Jurassic, Stability Diffusion (images), AWS Titan
- **Serverless inference** — no endpoint to provision (unlike SageMaker)
- **Data stays in your account** — Bedrock doesn't train on your prompts
- **VPC endpoints** — keep traffic off the internet

**Key Bedrock features (each is a likely exam trigger):**

| Feature | What it does |
| ------- | ------------ |
| **InvokeModel / Converse APIs** | Call any supported foundation model |
| **Knowledge Bases** | **RAG (Retrieval-Augmented Generation)** — point Bedrock at your S3 docs, vector store (OpenSearch / Aurora pgvector / Pinecone), and the model answers using *your* data |
| **Agents** | LLM that can call APIs / Lambda functions to take actions, not just generate text |
| **Guardrails** | Policy layer — block sensitive topics, redact PII, enforce safety rules |
| **Prompt management + flows** | Versioned prompts, reusable prompt templates, visual prompt-chaining |
| **Model evaluation** | Compare models side-by-side on your task |
| **Provisioned Throughput** | Reserved capacity for predictable workloads at lower per-token cost |
| **Custom Models** | Fine-tune a foundation model on your data (continued pre-training or fine-tuning) |

**Canonical Bedrock pipelines:**

```
Document Q&A (RAG):
  S3 (your PDFs) → Knowledge Base (vector embeddings) → Bedrock model → answer with citations

Chatbot with actions:
  User → Bedrock Agent → calls Lambda → updates DynamoDB → returns confirmation

Content generation:
  Lambda → Bedrock InvokeModel → generated copy / summaries / translations → S3

Image generation:
  API call → Bedrock (Stable Diffusion / Titan Image) → image → S3 → CloudFront
```

**Common anti-patterns (exam wrong answers):**

- **Lex for free-form conversational AI** — Lex is rigid intents/slots. Use **Bedrock** for natural chat.
- **SageMaker JumpStart when Bedrock would do** — Bedrock is fully managed, no endpoints. JumpStart is for when you need to host the model yourself or fine-tune deeply.
- **Asking Bedrock to "search our docs" without Knowledge Bases** — without RAG, the model has no access to your private data. Use **Bedrock Knowledge Bases**.
- **Skipping Guardrails for customer-facing GenAI** — PII leaks, off-topic responses, jailbreaks. Bedrock Guardrails block them centrally.
- **Provisioning a SageMaker endpoint for a foundation model when Bedrock supports it** — Bedrock is cheaper and managed; reach for SageMaker JumpStart only for models Bedrock doesn't host.

**Exam triggers:**

- *"call a foundation model (Claude / Llama / Titan / Stable Diffusion) via one API"* → **Bedrock**
- *"build a chatbot with free-form conversation, no rigid intents"* → **Bedrock** (NOT Lex)
- *"summarise / generate / translate text with an LLM"* → **Bedrock**
- *"generate images from text prompts"* → **Bedrock** (Stable Diffusion / Titan Image)
- *"build a Q&A bot over our private documents in S3"* → **Bedrock Knowledge Bases** (RAG)
- *"LLM that can take actions / call APIs"* → **Bedrock Agents**
- *"block PII / off-topic / unsafe responses in a GenAI app"* → **Bedrock Guardrails**
- *"fine-tune a foundation model on our domain data"* → **Bedrock Custom Models**
- *"reserved capacity for predictable LLM workloads"* → **Bedrock Provisioned Throughput**
- *"compare multiple foundation models on our task"* → **Bedrock Model Evaluation**

**The 80/20:** *Bedrock = managed API to foundation models (Claude/Llama/Titan/Stable Diffusion etc.). Five named features: **Knowledge Bases** (RAG over your data), **Agents** (LLM that takes actions), **Guardrails** (safety/PII), **Custom Models** (fine-tuning), **Provisioned Throughput** (reserved capacity). For free-form GenAI use Bedrock; for rigid intents/slots use Lex; for self-hosting a model use SageMaker JumpStart.*

### Amazon Comprehend (the headliner for general NLP)

**Anchored against Comprehend Medical.** Same API pattern, but tuned for **general text** — customer reviews, social media, support tickets, emails — not clinical content. Comprehend Medical is anchored against *this* service; here's the parent.

**What it extracts:**

| Capability | Output |
| ---------- | ------ |
| **Sentiment** | Positive / negative / neutral / mixed + confidence scores |
| **Targeted Sentiment** | Sentiment toward a *specific entity* in a paragraph |
| **Entity recognition** | People, places, organisations, dates, quantities, commercial items |
| **Key phrases** | The noun phrases that matter in the text |
| **Language detection** | 100+ languages with confidence |
| **Syntax** | Parts of speech, tokenisation |
| **Topic modelling** | Discover themes across a corpus of documents |
| **PII detection** | Identify + redact names, addresses, SSN, credit cards, etc. |
| **Events detection** | Find structured events (e.g. mergers, IPOs from financial text) |

**Customisation:**
- **Comprehend Custom Classification** — train a text classifier on your labelled data (support ticket → category)
- **Comprehend Custom Entity Recognition** — recognise your domain entities (product SKUs, internal codenames)

**Canonical pipelines:**

```
Customer reviews  → Comprehend (sentiment + entities) → DynamoDB / Redshift → QuickSight
Support tickets   → Comprehend Custom Classification → route to the right team
User uploads      → Comprehend PII detection → redact before storing in S3
Multilingual text → Comprehend (language detect) → Translate → store / process
```

**Common anti-patterns (exam wrong answers):**

- **Comprehend on clinical text** → use **Comprehend Medical** (knows drugs, conditions, ICD-10/RxNorm/SNOMED)
- **Building a sentiment classifier from scratch in SageMaker** when Comprehend solves it → use the pre-trained service
- **Comprehend for translation** → Comprehend *detects* language; **Translate** converts it
- **Comprehend for full-text search** → use **OpenSearch** (inverted index) or **Kendra** (Q&A)

**Exam triggers:**

- *"sentiment of customer reviews / social media"* → **Comprehend**
- *"detect language of incoming text"* → **Comprehend**
- *"extract entities (names, places, organisations) from text"* → **Comprehend**
- *"find key phrases / topics across a document corpus"* → **Comprehend** (topic modelling)
- *"detect and redact PII from text before storing"* → **Comprehend PII detection**
- *"train a custom text classifier on our own labels"* → **Comprehend Custom Classification**
- *"recognise our domain-specific entities (product names, codenames)"* → **Comprehend Custom Entity Recognition**
- *"sentiment toward a specific product mentioned in a paragraph"* → **Targeted Sentiment**
- *"detect events like mergers/IPOs in financial text"* → **Comprehend Events detection**
- *"clinical text"* → **Comprehend Medical** (NOT Comprehend)

### Amazon Comprehend Medical (HIPAA-eligible clinical NLP)

**Anchored against regular Comprehend.** Same API pattern, but the model understands **medical vocabulary** and links entities to **standard medical ontologies** (ICD-10, RxNorm, SNOMED). Regular Comprehend on a clinical note won't recognise "metoprolol" as a drug or "T2DM" as type-2 diabetes — Comprehend Medical does.

**What it extracts:**

| Category | Examples |
| -------- | -------- |
| **Medical conditions** | "diabetes", "hypertension", "T2DM" |
| **Medications** | Drug name + dosage + frequency + route ("metoprolol 50mg twice daily orally") |
| **Anatomy** | Body parts, systems ("left ventricle", "cervical spine") |
| **Tests, treatments, procedures** | "MRI", "appendectomy", "blood glucose test" |
| **Time expressions** | When things happened ("admitted on 2026-05-10", "post-op day 3") |
| **Protected Health Information (PHI)** | Names, ages, addresses, IDs, dates — for **de-identification** |

**Ontology linking — the differentiator:**

Comprehend Medical doesn't just extract — it **links to standard codes**:

| Linker | Codes returned | What for |
| ------ | -------------- | -------- |
| **ICD-10-CM** | International Classification of Diseases | Billing and diagnoses |
| **RxNorm** | Standard drug identifiers | Medication reconciliation |
| **SNOMED CT** | Comprehensive clinical terminology | EHR interoperability |

Extracting "diabetes" returns `E11.9` (ICD-10); "metoprolol" returns the RxNorm code linking to every system using it.

**Canonical pipelines:**

```
Spoken doctor dictation:
  Audio → Transcribe Medical → text → Comprehend Medical → structured EHR fields
                                                          → ICD-10 / RxNorm codes

Scanned clinical document:
  PDF → Textract → text → Comprehend Medical → structured fields + ontology codes

De-identification for research:
  Clinical notes → Comprehend Medical → detect PHI → redact → S3 (research-safe corpus)

Clinical trial matching:
  Patient records → Comprehend Medical → conditions + medications
                                       → match against trial inclusion criteria
```

**HIPAA + compliance:**

- **HIPAA-eligible** — covered under AWS's BAA (Business Associate Addendum)
- Data isn't used to train AWS models
- Standard AWS encryption (in transit + at rest with KMS)

**Common anti-patterns (exam wrong answers):**

- **Using regular Comprehend on clinical text** — won't recognise medical entities or link to ontologies. Use **Comprehend Medical**.
- **Using Comprehend Medical for general text** — overkill, tuned for clinical vocab. Use regular **Comprehend** for sentiment / entities in customer reviews etc.
- **Using Textract alone for clinical documents** — Textract extracts text + form structure; it doesn't understand medical meaning. Pipeline: **Textract → Comprehend Medical**.
- **Forgetting Transcribe Medical for spoken input** — for dictated notes the pipeline is **Transcribe Medical → Comprehend Medical**, not generic Transcribe.
- **Storing PHI in plaintext after extraction** — use Comprehend Medical's PHI detection to **de-identify** before research storage.

**Exam triggers:**

- *"extract medical entities from clinical notes / EHR / discharge summaries"* → **Comprehend Medical**
- *"HIPAA-compliant NLP"* → **Comprehend Medical**
- *"de-identify / redact PHI in medical text"* → **Comprehend Medical** (PHI detection)
- *"link medications to RxNorm"* → **Comprehend Medical**
- *"link conditions to ICD-10 codes for billing"* → **Comprehend Medical**
- *"link to SNOMED CT for EHR interoperability"* → **Comprehend Medical**
- *"transcribe a doctor's dictation and extract structured data"* → **Transcribe Medical → Comprehend Medical**
- *"scanned medical document → structured medical fields"* → **Textract → Comprehend Medical**
- *"clinical trial patient matching"* → **Comprehend Medical**
- *"medical coding automation"* → **Comprehend Medical** (ICD-10 linking)

**The 80/20:** *Comprehend Medical = HIPAA-eligible NLP for clinical text. Extracts conditions, medications, anatomy, tests, PHI — and links to ICD-10, RxNorm, SNOMED. Pairs: **Transcribe Medical → Comprehend Medical** (dictation pipeline), **Textract → Comprehend Medical** (scanned docs). Regular Comprehend won't recognise medical vocabulary; Comprehend Medical is overkill for non-clinical text.*

### Amazon Kendra

Enterprise search powered by ML. Natural-language search across documents (PDFs, Word, Confluence, SharePoint, Salesforce, S3, ServiceNow…). Different from **OpenSearch** which is for log analytics + Lucene queries — **Kendra is for "ask a question, get a precise answer"** from enterprise content.

**Exam triggers:**
- *"natural-language search across internal documents / knowledge base"* → **Kendra**
- *"build an enterprise search for SharePoint / Confluence / S3 content"* → **Kendra** (pre-built connectors)
- *"return a precise answer to an employee's natural-language question"* → **Kendra**
- *"chatbot answering questions from internal docs"* → **Kendra** (often paired with Lex or Bedrock)
- *"FAQ / customer self-service"* → **Kendra**
- *"full-text search on logs / dashboards"* → **OpenSearch** (NOT Kendra)

### Amazon Personalize

Real-time recommendation engine — the same ML used internally by Amazon.com for product recs. Feed it user-interaction data (clicks, views, purchases); get back personalised recommendations, ranked results, or trending items.

**Exam triggers:**
- *"personalised product / content recommendations"* → **Personalize**
- *"users who bought X also bought Y"* → **Personalize**
- *"Netflix-style recommendation engine"* → **Personalize**
- *"personalised email campaigns"* → **Personalize**
- *"rank a search result list for a specific user"* → **Personalize** (Personalized Ranking)
- *"recommendation engine but we have **no** historical interaction data"* → not Personalize alone — it needs interaction data to learn from

### Amazon Textract

Extract text **and structure** from documents — forms, tables, receipts, invoices. Beyond OCR: recognises form fields, table cells, key-value pairs, signatures. HIPAA-eligible. Anchored against **Rekognition**: Rekognition's text detection is OCR-lite for signs/license plates; **Textract is for documents with layout**.

**Exam triggers:**
- *"extract text and structured fields from PDFs / forms / invoices / receipts"* → **Textract**
- *"OCR that preserves table structure and key-value pairs"* → **Textract**
- *"automate invoice / mortgage application / ID document processing"* → **Textract** (specialised APIs: AnalyzeExpense, AnalyzeID, AnalyzeLending)
- *"extract signatures from scanned documents"* → **Textract**
- *"scanned medical document → structured fields"* → **Textract → Comprehend Medical**
- *"read text from a photo of a license plate / sign"* → **Rekognition** (NOT Textract — that's OCR-lite, not document layout)

### Amazon Forecast

Time-series forecasting service — feed it historical numeric data (sales, demand, web traffic, energy usage); get back probabilistic forecasts. Uses ML behind the scenes — you don't pick the algorithm. Different from **Timestream** (which *stores* time-series data) — Forecast *predicts* future values from it.

**Exam triggers:**
- *"forecast future demand / sales / metrics from historical time-series"* → **Forecast**
- *"capacity planning, predict next quarter's sales"* → **Forecast**
- *"predict web traffic / energy usage / inventory needs"* → **Forecast**
- *"need probabilistic forecasts with confidence intervals"* → **Forecast**
- *"store time-series data"* → **Timestream** (NOT Forecast)

### Amazon Fraud Detector

Pre-trained fraud detection — feed it event data (account signups, online payments) and your historical fraud labels; it builds a model that scores incoming events for fraud risk in real time. Built on the same ML Amazon.com uses internally.

**Exam triggers:**
- *"detect fraudulent account signups / online payments / promo abuse"* → **Fraud Detector**
- *"real-time fraud scoring without building an ML model from scratch"* → **Fraud Detector**
- *"identify suspicious transactions as they happen"* → **Fraud Detector**
- *"build a custom fraud model in SageMaker"* — possible, but **Fraud Detector** is the managed pre-built answer when one exists

### Amazon Augmented AI (A2I)

**Human review of low-confidence ML predictions.** Wraps Rekognition / Textract / Comprehend (or your own SageMaker model) so that when the model's confidence is low, the output is routed to a **human reviewer** (your private workforce, vendors, or Mechanical Turk) before being trusted. Closes the "ML is 95% accurate but I need 100% for compliance" loop.

**Exam triggers:**
- *"human-in-the-loop review for low-confidence ML predictions"* → **Augmented AI (A2I)**
- *"route uncertain Textract / Rekognition / Comprehend results to a human"* → **A2I**
- *"compliance requires manual review of any prediction below X% confidence"* → **A2I**
- *"send low-confidence model outputs to Mechanical Turk for verification"* → **A2I**

### When to Pick SageMaker Over Pre-trained Services

| Scenario | Pick |
| -------- | ---- |
| "Detect objects in user photos" | **Rekognition** (don't train your own) |
| "Detect *very specific* defects in our widgets that Rekognition doesn't know" | **Rekognition Custom Labels** if ~100 images is enough; **SageMaker** for full control |
| "Analyse medical X-rays / satellite imagery" | **SageMaker** — fundamentally different domain than Rekognition's training data |
| "Sentiment of customer reviews" | **Comprehend** |
| "Custom domain-specific NLP classifier" | **Comprehend Custom** or **SageMaker** |
| "Forecast next quarter's sales" | **Forecast** (pre-trained) — or **SageMaker** for bespoke models |
| "Build a chatbot for our website" | **Lex** (or **Bedrock** for LLM-powered) |
| "End-to-end ML platform — training, hyperparameter tuning, deployment, monitoring" | **SageMaker** |

### Amazon SageMaker — Deep Dive

SageMaker isn't one service — it's a **family of components** covering every stage of building ML. Anchored against the pre-trained AI/ML services: those are *call-an-API*, AWS owns the model. **SageMaker is what you reach for when no pre-trained service fits** — you bring training data, choose / write the algorithm, own the model lifecycle.

#### The ML Lifecycle SageMaker Covers

```
1. PREPARE DATA      → Data Wrangler, Feature Store, Ground Truth
2. BUILD             → Studio (IDE), Notebooks, JumpStart (pre-built models)
3. TRAIN             → Training Jobs, Autopilot (AutoML), HPO tuning
4. DEPLOY            → Endpoints (real-time / serverless / async), Batch Transform, Edge
5. MONITOR + GOVERN  → Model Monitor (drift), Clarify (bias/explainability), Pipelines (CI/CD)
```

#### Components to Know

| Component | What it does |
| --------- | ------------ |
| **SageMaker Studio** | Browser-based IDE for ML (Jupyter + ML-specific tooling) |
| **SageMaker Notebooks** | Managed Jupyter on EC2 — no infra setup |
| **SageMaker Canvas** | **No-code** ML for business analysts (point-and-click) |
| **SageMaker Data Wrangler** | Visual data prep — 300+ transformations, generates code |
| **SageMaker Ground Truth** | **Data labelling** — humans label, models learn. Auto-labelling reduces cost over time |
| **SageMaker Feature Store** | Central store for engineered features, shared across teams and models |
| **SageMaker Training Jobs** | Managed training on EC2/GPU — bring your own code or use built-in algorithms |
| **SageMaker Autopilot** | **AutoML** — picks algorithm + hyperparameters automatically from a tabular CSV |
| **Hyperparameter Tuning (HPO)** | Search hyperparameter space to maximise a metric |
| **SageMaker JumpStart** | One-click deploy of pre-built / foundation models (Hugging Face, Stable Diffusion, Llama, etc.) |
| **SageMaker Endpoints (real-time)** | Always-on hosted model for low-latency inference |
| **SageMaker Serverless Inference** | Auto-scaling, scale-to-zero endpoint — pay per request |
| **SageMaker Async Inference** | Queue-based for **long-running** or **large-payload** inferences |
| **SageMaker Batch Transform** | One-off / scheduled batch inference — no endpoint needed |
| **Multi-model endpoints** | Host many models on **one endpoint** — load on demand from S3 |
| **SageMaker Model Monitor** | Detect **drift** in production (data, model quality, bias) |
| **SageMaker Clarify** | **Bias detection** + explainability (SHAP values) |
| **SageMaker Debugger** | Profile + debug training jobs |
| **SageMaker Pipelines** | **CI/CD for ML** — orchestrated training/deploy workflows |
| **SageMaker Model Registry** | Versioning + approval workflow for models before deployment |
| **SageMaker Neo** | **Compile models** for specific hardware (edge devices, custom CPUs) |
| **SageMaker Edge Manager** | Deploy + monitor models on **edge devices** (IoT, factory equipment) |

#### Endpoint Types — Pick the Right One (exam favourite)

| Type | When |
| ---- | ---- |
| **Real-time endpoint** | Sub-second predictions, steady traffic, latency-critical (default) |
| **Serverless Inference** | Spiky / unpredictable traffic, OK with cold starts, scale-to-zero needed |
| **Async Inference** | **Large payloads** (>6 MB), **long inference times** (>60s), queue-based |
| **Batch Transform** | One-off or scheduled batch — no endpoint to keep alive |
| **Multi-model endpoint** | Host many models cheaply — load on demand from S3 |

```
"Predict in real time at scale"             → Real-time endpoint
"Sporadic predictions, pay only when used"  → Serverless Inference
"Process 100 MB image with a 5-min model"   → Async Inference
"Predict for 10M rows nightly"              → Batch Transform
"Host 500 small per-customer models"        → Multi-model endpoint
```

#### Training Cost Optimisation

- **Managed Spot Training** — save up to 90% on training compute (with checkpointing in case Spot is reclaimed)
- **Distributed training** — data parallel (split data across GPUs) or model parallel (split model across GPUs) for large models
- **Built-in algorithms** — pre-optimised (XGBoost, K-Means, Linear Learner, Image Classification, BlazingText, etc.) — cheaper than custom containers
- **Warm pools** — keep training instances warm between back-to-back jobs

#### Canonical Architecture

```
S3 (training data)
   ↓
SageMaker Data Wrangler (clean, transform, engineer features)
   ↓
SageMaker Ground Truth (label data if supervised)
   ↓
SageMaker Feature Store (share features; offline + online sync)
   ↓
SageMaker Training Job (with Spot for cost; or Autopilot for AutoML)
   ↓
SageMaker Model Registry (version + approve)
   ↓
SageMaker Pipelines (orchestrate the whole flow as CI/CD)
   ↓
SageMaker Endpoint (real-time) / Batch Transform / Async / Serverless
   ↓
SageMaker Model Monitor (drift) + Clarify (bias) + CloudWatch (metrics)
```

#### SageMaker Anti-patterns (exam wrong answers)

- **SageMaker when a pre-trained service would solve it** — building a sentiment classifier from scratch when Comprehend exists. Always check the pre-trained family first.
- **Real-time endpoint for nightly batch predictions** — wasteful. Use **Batch Transform**.
- **Real-time endpoint for spiky / sporadic traffic** — pays for idle. Use **Serverless Inference**.
- **Real-time endpoint for 5-minute inferences or 100 MB payloads** — endpoints have payload and timeout limits. Use **Async Inference**.
- **Hosting 100 small models on 100 separate endpoints** — wildly expensive. Use **multi-model endpoints**.
- **Manual data labelling at scale** — use **Ground Truth** (auto-labelling reduces human effort over time).
- **Picking Canvas for engineers** — Canvas is no-code for analysts; engineers want Studio + Notebooks.
- **Forgetting Model Monitor** when the question mentions *drift* / *retrain* / *model accuracy degrading in production*.
- **Deploying a model to a Raspberry Pi without optimisation** — use **SageMaker Neo** to compile for the target hardware.
- **Skipping Spot training** for non-critical training jobs — leaves 90% savings on the table.

#### SageMaker Exam Triggers

**Service-specific:**

- *"build, train, deploy ML model end-to-end"* → **SageMaker**
- *"AutoML — pick model + hyperparameters automatically"* → **SageMaker Autopilot**
- *"data labelling for supervised learning"* → **SageMaker Ground Truth**
- *"detect drift in a production model"* → **SageMaker Model Monitor**
- *"bias detection / explainability / SHAP values"* → **SageMaker Clarify**
- *"no-code ML for business analysts"* → **SageMaker Canvas**
- *"CI/CD pipeline for ML"* → **SageMaker Pipelines**
- *"pre-built foundation models / Hugging Face / Llama / Stable Diffusion"* → **SageMaker JumpStart**
- *"share engineered features across multiple models / teams"* → **SageMaker Feature Store**
- *"visual data prep with 300+ transformations"* → **SageMaker Data Wrangler**
- *"version + approve models before deployment"* → **SageMaker Model Registry**
- *"compile model for an IoT / edge device"* → **SageMaker Neo** + **Edge Manager**
- *"reduce training cost"* → **Managed Spot Training**
- *"distributed training across multiple GPUs"* → **SageMaker distributed training**

**Endpoint-type:**

- *"low-latency real-time predictions"* → **Real-time endpoint**
- *"sporadic traffic, scale-to-zero, pay only when used"* → **Serverless Inference**
- *"large payload (>6 MB) or long inference time (>60s)"* → **Async Inference**
- *"score millions of rows nightly, no endpoint needed"* → **Batch Transform**
- *"host hundreds of per-customer models cost-efficiently"* → **Multi-model endpoint**

**The SageMaker 80/20:** *Five lifecycle stages (Prepare → Build → Train → Deploy → Monitor) with named components for each. The exam tests two things hardest: (1) **picking the right endpoint type** (real-time / serverless / async / batch / multi-model) — match payload, latency, traffic pattern; (2) **knowing the named components** — Autopilot for AutoML, Ground Truth for labelling, Model Monitor for drift, Clarify for bias, Pipelines for CI/CD, JumpStart for pre-built models. Always check pre-trained services first — only reach for SageMaker when they don't fit.*

### Common Anti-patterns (exam wrong answers)

- **Rekognition for documents with structured fields (forms, tables, receipts)** → **Textract** (designed for documents with layout). Rekognition's text detection is just OCR-lite.
- **SageMaker when a pre-trained service would do** — building a sentiment classifier from scratch when Comprehend solves it.
- **Comprehend for translation** → Comprehend detects language, **Translate** translates it.
- **Calling Rekognition synchronously on a 2-hour video** → use the async video API; output goes to SNS.
- **Personalize for "what to show next" without user-event history** → Personalize needs interaction data to learn from.
- **Lex without thinking about LLM alternatives** → for natural conversational AI, **Bedrock + Claude / Llama** is often a better fit than rigid intent/slot Lex flows.

### Exam Triggers

**Input type → service:**

- *"detect objects / faces / text / inappropriate content in images or video"* → **Rekognition**
- *"extract structured data from invoices / forms / receipts / PDFs"* → **Textract**
- *"sentiment / entities / key phrases / language detection in text"* → **Comprehend**
- *"detect PII in text and redact it"* → **Comprehend** (PII detection)
- *"translate text between languages"* → **Translate**
- *"transcribe a podcast / meeting / call recording"* → **Transcribe**
- *"convert text to natural-sounding speech"* → **Polly**
- *"build a chatbot with intents and slots"* → **Lex**
- *"chatbot using a foundation model (Claude / Llama / Titan)"* → **Bedrock**
- *"product recommendations based on user behaviour"* → **Personalize**
- *"forecast future demand / metrics from historical time-series"* → **Forecast**
- *"build/train/deploy a custom ML model end-to-end"* → **SageMaker**

**Service-specific giveaways:**

- *"compare two faces / face match against a collection"* → **Rekognition** (`CompareFaces`, face collections)
- *"detect helmets / masks / PPE in images"* → **Rekognition** PPE detection
- *"identify celebrities in a photo"* → **Rekognition** celebrity recognition
- *"train a custom image classifier with a small labelled dataset"* → **Rekognition Custom Labels** (low effort) or **SageMaker** (more control)
- *"OCR on a complex form keeping the table/field structure"* → **Textract** (NOT Rekognition's text detection)

**The 80/20:** *Pre-trained services pick by input type — Rekognition (images/video), Textract (documents), Comprehend (text NLP), Transcribe/Polly (speech), Translate (translation), Lex/Bedrock (chatbots), Personalize (recommendations), Forecast (time-series). SageMaker only when nothing pre-trained fits. The exam exploits Rekognition vs Textract confusion — Rekognition is "what's in this picture?", Textract is "extract the form fields and table cells from this PDF".*

### AI/ML Cheat Sheet

The whole AI/ML map on one card. Two layers, two decisions, eight pairings.

**The two-tier mental model:**

```
Layer 1: PRE-TRAINED API services    ← pick by input type, call an API, done
Layer 2: SAGEMAKER                    ← only when no pre-trained service fits
```

**Layer 1 — pick by input type:**

| Input | Service | Headline use |
| ----- | ------- | ------------ |
| **Images / video** | **Rekognition** | Objects, faces, content moderation, PPE, celebrities |
| **Documents (PDFs/forms/receipts)** | **Textract** | OCR with layout — keys, values, table cells |
| **Text (general)** | **Comprehend** | Sentiment, entities, key phrases, language detection, PII |
| **Text (clinical)** | **Comprehend Medical** | Medical entities + ICD-10 / RxNorm / SNOMED linking |
| **Text → audio** | **Polly** | Text-to-speech (natural voices) |
| **Audio → text** | **Transcribe** | Speech-to-text (general or Medical) |
| **Translate text between languages** | **Translate** | 75+ languages, formality, custom terminology |
| **Build a chatbot** | **Lex** | Intents + slots (rigid) / **Bedrock** (free-form LLM) |
| **Cloud call center** | **Connect** (+ Lex + Polly + Contact Lens) | Phone system, IVR, sentiment analytics |
| **Recommend products / content** | **Personalize** | Real-time personalisation |
| **Forecast time-series** | **Forecast** | Demand / metric forecasting |
| **Enterprise document search** | **Kendra** | Natural-language Q&A across docs (NOT log analytics — that's OpenSearch) |
| **Call a foundation model (LLM)** | **Bedrock** | Claude / Llama / Titan / Stable Diffusion via one API |

**Layer 2 — reach for SageMaker when:**

- No pre-trained service matches your domain (medical imagery, satellite, defects, fraud, custom NLP)
- You need to **train, tune, deploy, monitor** your own model end-to-end
- You need CI/CD for ML (Pipelines), bias detection (Clarify), drift monitoring (Model Monitor)

**SageMaker lifecycle in one glance:**

```
1. PREPARE  → Data Wrangler · Feature Store · Ground Truth (labelling)
2. BUILD    → Studio · Notebooks · JumpStart (pre-built models)
3. TRAIN    → Training Jobs · Autopilot (AutoML) · HPO · Spot training (-90%)
4. DEPLOY   → Real-time / Serverless / Async / Batch / Multi-model endpoints · Neo (edge)
5. GOVERN   → Model Monitor (drift) · Clarify (bias) · Pipelines (CI/CD) · Model Registry
```

**SageMaker endpoint type — the most-tested decision:**

| Workload | Endpoint |
| -------- | -------- |
| Sub-second predictions, steady traffic | **Real-time** |
| Sporadic / spiky traffic, OK with cold starts | **Serverless Inference** |
| Large payload (>6 MB) or long inference (>60s) | **Async Inference** |
| Score millions of rows nightly | **Batch Transform** |
| Host hundreds of small models cheaply | **Multi-model endpoint** |

**Common pairings — memorise (they appear together constantly):**

```
Connect + Lex + Polly + Lambda + Contact Lens   = intelligent IVR / cloud call center
Lex + Polly                                      = voice chatbot
Transcribe + Comprehend                          = analyse call recordings
Transcribe Medical + Comprehend Medical          = clinical dictation pipeline
Textract + Comprehend                            = extract + understand documents
Textract + Comprehend Medical                    = scanned clinical docs → structured EHR
Kendra + Lex (or Bedrock)                        = chatbot answering from internal docs
Personalize + Pinpoint/SES                       = personalised email campaigns
```

**Top anti-pattern traps:**

- **SageMaker for something pre-trained solves** — always check Layer 1 first
- **Rekognition for documents** — use **Textract** (OCR with layout)
- **Comprehend on clinical text** — use **Comprehend Medical**
- **Lex for free-form conversation** — use **Bedrock** (LLM)
- **Kendra for log analytics** — use **OpenSearch**
- **Polly vs Transcribe** confusion — Polly = text→audio; Transcribe = audio→text
- **Comprehend vs Translate** — Comprehend *understands* text; Translate *converts* between languages
- **Real-time endpoint for batch / spiky / large-payload** workloads — pick **Batch Transform / Serverless / Async** instead

**The two decisions that crack most exam questions:**

1. **What's the input?** → identify the pre-trained service. Done if one fits.
2. **If no pre-trained service fits → SageMaker.** Then pick the **endpoint type** by latency / payload / traffic shape.

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
