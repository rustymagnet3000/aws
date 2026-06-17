# AWS

<!-- TOC depthfrom:2 depthto:2 withlinks:true updateonsave:true orderedlist:false -->

- [whoami](#whoami)
- [SNS](#sns)
- [s3](#s3)
- [dynamodb](#dynamodb)
- [Cloudtrail](#cloudtrail)
- [Elasticache  Redis](#elasticache--redis)
- [Cloudwatch](#cloudwatch)
- [Databases](#databases)
- [Inspector](#inspector)
- [ec2](#ec2)
- [Athena](#athena)
- [Tips](#tips)
- [CLI](#cli)
- [aws-sso](#aws-sso)
- [saml2aws](#saml2aws)
- [IAM](#iam)
- [lambda](#lambda)
- [Invoke Lambda](#invoke-lambda)
- [Keys](#keys)
- [ECR](#ecr)
- [Proxy AWS CLI traffic](#proxy-aws-cli-traffic)
- [Secrets Manager](#secrets-manager)
- [Elastic Container Service  ECS](#elastic-container-service--ecs)
- [SSM Sessions](#ssm-sessions)
- [SSM Parameter Store](#ssm-parameter-store)

<!-- /TOC -->

## whoami

```bash
# Get ARN, UserId and Account
aws sts get-caller-identity

# Get account info
aws organizations describe-account --account-id < ACCOUNT ID >

# Get ARN, UserId, Account + Account Aliases
{ aws sts get-caller-identity & aws iam list-account-aliases; } | jq -s ".|add"

# Get username
aws iam get-user
```

## SNS

```bash
# list Topics
aws sns list-topics

# list details of a Topic
aws sns get-topic-attributes --topic-arn ${TOPIC_ARN}

# list subscriptions for a topic
aws sns list-subscriptions-by-topic --topic-arn ${TOPIC_ARN}

# create a topic
aws sns create-topic --name my-topic

# subscribe an endpoint (email / SQS / Lambda / HTTPS)
aws sns subscribe --topic-arn ${TOPIC_ARN} --protocol email --notification-endpoint me@example.com
aws sns subscribe --topic-arn ${TOPIC_ARN} --protocol sqs   --notification-endpoint ${QUEUE_ARN}
aws sns subscribe --topic-arn ${TOPIC_ARN} --protocol lambda --notification-endpoint ${LAMBDA_ARN}

# unsubscribe
aws sns unsubscribe --subscription-arn ${SUBSCRIPTION_ARN}

# publish a message
aws sns publish \
    --topic-arn ${TOPIC_ARN} \
    --message file://message.txt

# publish with subject + attributes (filter policies)
aws sns publish \
    --topic-arn ${TOPIC_ARN} \
    --subject "Alert" \
    --message "Disk usage high" \
    --message-attributes '{"severity":{"DataType":"String","StringValue":"high"}}'

# delete a topic
aws sns delete-topic --topic-arn ${TOPIC_ARN}
```

## s3

```bash
# check if bucket exists
aws s3api head-bucket --bucket your-bucket-name
```

`head-bucket` result codes:

| Result  | Meaning                                         |
| ------- | ----------------------------------------------- |
| **200** | Bucket exists **and you have access**           |
| **301** | Bucket exists but **in a different region**     |
| **403** | Bucket exists but **you don't have permission** |
| **404** | Bucket **does not exist**                       |

```bash
export BUCKET_NAME=mybucket
export BUCKET_URI=s3://mybucket
export BUCKET=s3://mybucket
export BUCKET_HTTP=https://mybucket.eu-west-2.amazonaws.com

# list
aws s3 ls ${BUCKET_NAME}

# list without credentials / owning that bucket
aws s3 --endpoint-url ${BUCKET_HTTP} ls

# list with subfolders
aws s3 ls ${BUCKET_URI} --recursive
aws s3 ls ${BUCKET_URI} --recursive --human-readable --summarize

# list storage state of file in bucket
aws s3api get-object-attributes \
    --bucket ${BUCKET_NAME} \
    --key foobar.txt \
    --object-attributes "StorageClass" "ETag" "ObjectSize"

{
    "LastModified": "2022-01-07T10:39:23+00:00",
    "ETag": "xxxxxxx",
    "StorageClass": "GLACIER",
    "ObjectSize": 199
}

# Enter MFA code for arn:aws:iam::________
aws s3 ls --profile mfa

# copy everything in bucket
aws s3 cp ${BUCKET} ./ --recursive

# check if bucket is public
aws s3api get-bucket-policy-status --bucket ${BUCKET}

# bucket location
aws s3api get-bucket-location --bucket ${BUCKET}

# check if I can pull a file from sub-folder
aws s3 cp ${BUCKET} /images/boo.jpg

# Copy to bucket
aws s3 cp test.txt ${BUCKET}

# Copy to local
aws s3 cp ${BUCKET_URI} poc

# Copy to local with server side encryption (SSE) it is handled by the aws
# ensure any Role has enough permissions to obtain the Server Side encryption key

aws s3 cp ${BUCKET_URI}/404.html/index.html .


# Copy and print to stdout
aws s3 cp ${BUCKET}/file.txt /dev/stdout

# Delete from bucket
aws s3 rm ${BUCKET}/test2.txt

# Delete bucket
aws s3 rb ${BUCKET}

# Find owner of Object
aws s3api get-object-acl --bucket ${BUCKET_NAME} --key service-worker.js
aws s3api get-bucket-acl --bucket ${BUCKET_NAME}

# Add directory remotely
aws s3api put-object --bucket ${BUCKET_NAME} --key foo/ --region "eu-west-1"
# add directory and file remotely
aws s3api put-object --bucket ${BUCKET_NAME} --key foo/foo.js --body foo.js

# Get Bucket Policy
aws s3api get-bucket-policy --bucket ${BUCKET} --expected-bucket-owner 111122223333

# Get Bucket Ownership controls
aws s3api get-bucket-ownership-controls --bucket ${BUCKET_NAME}

# Sync (more flexible than cp — only transfers files that changed)
aws s3 sync ./local-dir ${BUCKET_URI}/remote-dir
aws s3 sync ${BUCKET_URI}/remote-dir ./local-dir --delete   # mirror, remove local files not in bucket

# Get / set / remove default bucket encryption (SSE-KMS)
aws s3api get-bucket-encryption --bucket ${BUCKET_NAME}
aws s3api put-bucket-encryption \
    --bucket ${BUCKET_NAME} \
    --server-side-encryption-configuration '{
      "Rules": [{
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "alias/my-key"
        }
      }]
    }'
aws s3api delete-bucket-encryption --bucket ${BUCKET_NAME}

# Block Public Access (account or bucket level)
aws s3api put-public-access-block --bucket ${BUCKET_NAME} \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Versioning
aws s3api get-bucket-versioning --bucket ${BUCKET_NAME}
aws s3api put-bucket-versioning --bucket ${BUCKET_NAME} --versioning-configuration Status=Enabled

# Lifecycle (e.g. transition to Glacier after 30 days)
aws s3api get-bucket-lifecycle-configuration --bucket ${BUCKET_NAME}
aws s3api put-bucket-lifecycle-configuration \
    --bucket ${BUCKET_NAME} \
    --lifecycle-configuration file://lifecycle.json
```

### Read compressed json file from s3

`cat compressed.ndjson| zcat`

## dynamodb

### Set up locally

```bash
# get Docker image
docker pull amazon/dynamodb-local

# create the container in detached mode. This is a one-off step.
docker run \
	-p 8000:8000 \
	--name dynamodb \
	-d amazon/dynamodb-local \
	-jar DynamoDBLocal.jar \
    -sharedDb

# start container
docker start dynamodb
```

The `-sharedDb` flag is essential to avoid `“Cannot do operations on a non-existent table”`. See [here](https://stackoverflow.com/questions/29558948/dynamo-local-from-node-aws-all-operations-fail-cannot-do-operations-on-a-non-e).

### Verify local database

`aws dynamodb describe-table --table-name DELETEme --endpoint-url http://localhost:8000`

### Add local data

```bash
aws dynamodb put-item \
	--table-name DELETEme \
    	--item '{
        		"Name": {"S": "Alice"},
        		"Age": {"N": "99"}
      		}' \
	--endpoint-url http://localhost:8000 \
    	--return-consumed-capacity TOTAL

docker pull amazon/dynamodb-local
docker run -p 8000:8000 amazon/dynamodb-local
```

### Delete local table

```bash
aws dynamodb delete-table \
    --table-name DELETEme \
    --endpoint-url http://localhost:8000
```

### Query and list locally

```bash
# create empty Profile
aws configure --profile rm_local_db

# list Tables
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

### List table and fields

```bash
# list Tables
aws dynamodb list-tables

# Describe endpoints using DynamoDB
aws ec2 describe-vpc-endpoint-services | grep -i dynamo

# Describe table
aws dynamodb describe-table   --table-name footable

# Read table
aws dynamodb scan --table-name footable

# Create table
aws dynamodb create-table \
    --table-name DELETEme \
    --attribute-definitions \
        AttributeName=Name,AttributeType=S \
        AttributeName=Age,AttributeType=N \
    --key-schema \
        AttributeName=Name,KeyType=HASH \
        AttributeName=Age,KeyType=RANGE \
    --provisioned-throughput \
        ReadCapacityUnits=1,WriteCapacityUnits=1 \
    --endpoint-url http://localhost:8000

# delete table
aws dynamodb delete-table --table-name DELETEme
```

### Replicate a DynamoDB table locally

Original [article](https://medium.com/@balint_sera/replicate-a-dynamodb-table-409641215e8).

```bash
# describe table
aws dynamodb describe-table --table-name foo_table > foo_table.txt
```

Copy the JSON into files. Example: `key-schema.json`:

```json
[
    {
        "AttributeName": "partition",
        "KeyType": "HASH"
    }
]
```

Don't copy Attribution Definitions that are not part of the KeySchema, if you hit the error:

> Number of attributes in key schema must match the number of attributes defined in attribute definitions

[Reference](https://stackoverflow.com/questions/30866030/number-of-attributes-in-key-schema-must-match-the-number-of-attributes-defined-i)

```bash
aws dynamodb create-table \
    --table-name DELETEme \
    --attribute-definitions file://attribute-definitions.json \
    --key-schema file://key-schema.json  \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --endpoint-url http://localhost:8000
```

### Put item

```bash
aws dynamodb put-item \
    --table-name DELETEme \
    --item '{
        "Name": {"S": "Alice"},
        "Age": {"N": "99"}
      }' \
    --return-consumed-capacity TOTAL
```

### Query item

<https://www.bmc.com/blogs/dynamodb-queries/>

Works even for a Reserved Word like `Name`:

```bash
aws dynamodb query \
	--table-name DELETEme \
	--key-condition-expression "#nm = :name" \
	--expression-attribute-name '{"#nm": "Name"}' \
	--expression-attribute-values  '{ ":name":{"S":"Bob"}}'
```

```bash
 aws dynamodb get-item \
        --table-name DELETEme \
        --key file://key.json \
        --return-consumed-capacity TOTAL
# key.json
```

```json
{
    "Name": {"S": "Alice"},
    "Age": {"N": "99"}
}
```

### Query individual items with Projection Expression

Only attributes of the desired item:

```bash
aws dynamodb get-item \
    --table-name DELETEme \
    --key '{"Name": {"S": "Bob"},"Age": {"N": "77"}}' \
    --projection-expression "#A, #N" \
    --expression-attribute-names file://names.json
# names.json
```

```json
{
    "#N": "Name",
    "#A": "Age"
}
```

If the Primary Key as `Hash` = Name and `Sort Key` = Age you need to search with both. [Reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html).

>For the primary key, you must provide all of the attributes. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide values for both the partition key and the sort key.

### Query item with file

```bash
aws dynamodb query --table-name footable \
	--key-condition-expression "email=:email" \
	--expression-attribute-values file://expression_attributes.json
```

Inside of the `expression_attributes.json` file:

```json
{
   ":email": {"S": "alice.bob@example.com"}
}
```

### Query with Python Boto3

##### Boto3 get a single Item

```python
        response = table.query(
            KeyConditionExpression=Key('partition').eq('xxxxxxxx')
        )
```

##### Boto3 get all columns where email matches

```python
from boto3.dynamodb.conditions import Key, And, Attr
    response = table.scan(
        FilterExpression=Attr("email").eq(entered_email)
    )
```

##### Boto3 get email, name, age column where email matches

```python
response = table.scan(
    FilterExpression=Attr("email").eq(email),
    ProjectionExpression="email, name, age"
)
```

### DynamoDB reserved words

[reserved words](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html).

## Cloudtrail

```bash
aws cloudtrail lookup-events help

# Set a max-items
aws cloudtrail lookup-events --max-items 10

# Events in 1 hour time period
## Keep the space between date and time!
aws cloudtrail lookup-events --start-time "08-23-2021, 01:16PM" --end-time "08-23-2021, 02:16PM" --max-items 10

# Filter by user
aws cloudtrail \
	lookup-events \
		--start-time "08-23-2021, 01:16PM" \
		--end-time "08-23-2021, 02:16PM" \
		--max-items 10 \
	--lookup-attributes AttributeKey=Username,AttributeValue=foo.bar@foobar.com

# Filter by s3 bucket
aws cloudtrail \
	lookup-events \
	--lookup-attributes \
		AttributeKey=ResourceName,AttributeValue=foo-bucket \
	--start-time "08-23-2021, 01:16PM" \
	--end-time "08-23-2021, 04:36PM" \
	--max-items 10 \
	--query 'Events[].{username:Username,time:EventTime,event:EventName,eventid:EventId,accesskey:AccessKeyId,resource:(Resources[0].ResourceName)}' \
	--output table \
	--region ${AWS_REGION}


aws cloudtrail put-event-selectors --trail-name TrailName --region ${AWS_REGION} \
--advanced-event-selectors \
'[
    {
            "Name": "S3EventSelector",
            "FieldSelectors": [
                { "Field": "eventCategory", "Equals": ["Data"] },
                { "Field": "resources.type", "Equals": ["AWS::S3::Object"] },
                { "Field": "resources.ARN", "Equals":  ["arn:aws:s3:::foo-bucket"] }
            ]
        }
]'

```

## Elasticache ( Redis )

```bash
# get Redis versions
aws elasticache describe-cache-engine-versions \
    --engine "Redis"

# get 5 clusters
aws elasticache describe-cache-clusters --max-items 5

# list topics
aws elasticache describe-cache-clusters --cache-cluster-id ${CLUSTER_ID}

# list replication groups (cluster-mode / Multi-AZ Redis) as a table
aws elasticache describe-replication-groups --region eu-west-1 \
  --query 'ReplicationGroups[*].{id:ReplicationGroupId,status:Status,nodes:NumNodeGroups,desc:Description}' \
  --output table 2>&1 | head -30
```

## Cloudwatch

```bash
# set Group Name
export GROUP_NAME=/aws/lambda/foo

# Get log-stream names that start with 2022
aws logs describe-log-streams --log-group-name ${GROUP_NAME} --log-stream-name-prefix 2022

# Get all Log Streams most recent first
aws logs describe-log-streams --log-group-name ${GROUP_NAME} --log-stream-name-prefix 2022 --descending

# Get latest Log Stream
aws logs describe-log-streams --log-group-name ${GROUP_NAME} --log-stream-name-prefix 2022 --descending --max-items 1

# Get Logs
aws logs get-log-events --log-group-name ${GROUP_NAME} --log-stream-name "2022/03/17/xxxxx"

# real-time watch logs
aws logs tail /aws/lambda/foolambda --follow

# Tail.  More readable, filtered and only last three hours
aws logs \
    tail ${GROUP_NAME} \
    --follow \
    --format short \
    --filter-pattern "Security" \
    --since 3h

# AWS web interface go to: CloudWatch/Log groups
/aws/lambda/foobar
```

### Filter log events (one-shot query, not tail)

```bash
# search across all streams in a log group
aws logs filter-log-events \
    --log-group-name ${GROUP_NAME} \
    --filter-pattern "ERROR" \
    --start-time $(date -u -v-1H +%s)000 \
    --limit 50

# JSON query (when log lines are JSON)
aws logs filter-log-events \
    --log-group-name ${GROUP_NAME} \
    --filter-pattern '{ $.level = "error" }'
```

### Alarms

```bash
# list alarms
aws cloudwatch describe-alarms
aws cloudwatch describe-alarms --state-value ALARM   # currently firing

# create a metric alarm (CPU > 80% for 5 mins)
aws cloudwatch put-metric-alarm \
    --alarm-name HighCPU-i-xxx \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 60 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 5 \
    --dimensions Name=InstanceId,Value=i-xxx \
    --alarm-actions ${SNS_TOPIC_ARN}

# delete alarms
aws cloudwatch delete-alarms --alarm-names HighCPU-i-xxx

# get raw metric data
aws cloudwatch get-metric-statistics \
    --namespace AWS/EC2 \
    --metric-name CPUUtilization \
    --dimensions Name=InstanceId,Value=i-xxx \
    --start-time $(date -u -v-1H +%FT%TZ) \
    --end-time $(date -u +%FT%TZ) \
    --period 300 \
    --statistics Average Maximum
```

## Databases

### Describe

```bash
aws rds describe-db-clusters | jq '.DBClusters[] | select(.EngineVersion | contains("9.6")) | { name: .DBClusterIdentifier, version: .EngineVersion }'

# list DB clusters (Aurora / RDS multi-instance) as a table
aws rds describe-db-clusters --region eu-west-1 \
  --query 'DBClusters[*].{id:DBClusterIdentifier,engine:Engine,status:Status,endpoint:Endpoint}' \
  --output table 2>&1 | head -30

aws rds describe-db-engine-versions --engine postgres | grep -A 1 AutoUpgrade| grep -A 2 true |grep PostgreSQL | sort --unique | sed -e 's/"Description": "//g'

aws rds download-db-log-file-portion \
	--db-instance-identifier foobar-db \
	--log-file-name error/postgresql.log.2021-01-01 \
	--output text > tail.txt
```

## Inspector

### Tips

`https://awsclibuilder.com/home/services/inspector`

### List ( with a max )

```bash
aws inspector list-findings --max-items 10
aws inspector list-findings --max-items 10 --region eu-west-1 --output table
aws inspector list-findings --max-items 10 --region eu-west-1 --output json | jq .
```

### List Assessment Runs

```bash
aws inspector list-assessment-runs --max-items=10
```

### Describe finding

`aws inspector describe-findings --finding-arns arn:aws:inspector:eu-west-2:......./finding/0-6xxxxxxx`

## ec2

```bash
# Allocate Public IP address
aws ec2 allocate-address

# List Static, Public IP addresses
aws ec2 describe-addresses

# Release Public IP address
aws ec2 release-address --allocation-id eipallocXXXXXXXXX

# Describe VPC endpoint services
aws ec2 describe-vpc-endpoint-services

# Describe all instances (compact)
aws ec2 describe-instances \
    --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name,IP:PrivateIpAddress,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

# Describe instances filtered by tag
aws ec2 describe-instances --filters "Name=tag:Name,Values=my-app"
aws ec2 describe-instances --filters "Name=tag:Environment,Values=prod" "Name=instance-state-name,Values=running"

# Describe instances filtered by state
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"

# AMI search (regex / wildcard)
aws ec2 describe-images --filters 'Name=name,Values=amzn2-ami-hvm-*' --owners amazon

# Get latest Amazon Linux 2023 AMI ID (via SSM public parameter)
aws ssm get-parameter \
    --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 \
    --query 'Parameter.Value' --output text

# Security Groups
aws ec2 describe-security-groups
aws ec2 describe-security-groups --group-ids sg-xxxxx
aws ec2 describe-security-groups --filters "Name=group-name,Values=my-sg"

# Show SG rules in a flat readable form
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=sg-xxxxx"

# Authorize / revoke SG rules
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxx \
    --protocol tcp --port 443 --cidr 10.0.0.0/16
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxxxx \
    --protocol tcp --port 443 --cidr 10.0.0.0/16

# Start / stop / reboot / terminate
aws ec2 start-instances --instance-ids i-xxxxx
aws ec2 stop-instances --instance-ids i-xxxxx
aws ec2 reboot-instances --instance-ids i-xxxxx
aws ec2 terminate-instances --instance-ids i-xxxxx
```

## Athena

### List table and fields

```bash
aws athena list-table-metadata \
    --catalog-name AwsDataCatalog \
    --database-name sampledb \
    --max-items 2 \
    --region=us-east-2

SELECT *
FROM "foobar_logs_test_env"
WHERE dt < '2021/9/13'
 AND dt > '2021/9/12'
 AND zoneid = 'ffffff'
 AND originip = '120.120.120.120'
LIMIT 10


```

## Tips

- [aws-in-plain-english](https://expeditedsecurity.com/aws-in-plain-english/)
- [gcp-in-plain-english](https://cloudblog.withgoogle.com/topics/developers-practitioners/back-popular-demand-google-cloud-products-4-words-or-less-2021-edition/amp/)

## CLI

### Starting

#### Version

`aws --version`

#### Upgrade ( macOS )

```bash
brew upgrade awscli
# if errors due to Python version: xcode-select --install
# if you installed via other methods and want to clean up:
pip3 uninstall awscli
brew link awscli
```

#### Persisted config and credentials

```bash
ls -1 ~/.aws
cat ~/.aws/config
cat ~/.aws/credentials
```

#### Remove credentials / profiles

`vi ~/.aws/config`

### List

```bash
> aws configure list

      Name                    Value             Type    Location
      ----                    -----             ----    --------
   profile                <not set>             None    None
access_key     ****************DYXW shared-credentials-file
secret_key     ****************zO0/ shared-credentials-file
    region                eu-west-1      config-file    ~/.aws/config


> aws configure list-profiles
default
rm_lambda_demo
saml
```

#### Region

```bash
aws configure get region
aws configure set region eu-west-2 --profile foobar
aws configure get region --profile foobar
```

#### Configure profile

```bash
aws configure --profile rm_lambda_demo
AWS Access Key ID [None]: ....XW
AWS Secret Access Key [None]: ...zO0
Default region name [None]: eu-west-2
Default output format [None]: json
```

## aws-sso

### Set up

```bash
# install
brew install aws-sso-cli

# start up
aws-sso completions -I

# set the cli to point toward aws set up
https://<appID>.awsapps.com/

# download credentials profiles from aws
aws-sso config-profiles

# verify Profiles installed locally
cat ~/.aws/config

# tell aws cli tool which Profile to use
export AWS_PROFILE=1234567890:ReadOnly \
 && export AWS_REGION=us-east-1

# verify it all worked
aws sts get-caller-identity

# native AWS CLI v2 SSO commands (alternative to aws-sso-cli)
aws configure sso       # interactive SSO setup → writes a profile to ~/.aws/config
aws sso login           # opens browser, refreshes credentials
aws sso login --profile my-prod-profile
aws sso logout          # clears cached SSO credentials
```

### Day-2-day usage

```bash
# kick start the download of credentials after SSO completes
aws-sso config-profiles

# check it worked
export AWS_PROFILE="1234567890:ReadOnly" \
  && AWS_REGION="eu-north-1" \
  && aws sts get-caller-identity

# if it failed, check other profiles are not taking over
unset AWS_ENDPOINT_URL_S3 \
  && unset AWS_ACCESS_KEY_ID \
  && unset AWS_SECRET_ACCESS_KEY
```

## saml2aws

> CLI tool which enables you to login and retrieve AWS temporary credentials via a SAML identity provider (Google Workspace, Okta, ADFS, etc.).

### Set up

```bash
brew install awscli
brew install saml2aws
saml2aws --version

saml2aws configure
# Select provider (like Google)
# URL: enter URL of Identity Provider
# Username: email known to Identity Provider
# Password: Password associated to email
```

### Day-2-Day use

```bash
# Normal login
saml2aws login

# check if logged in
eval $(saml2aws script)

# Debugging info
saml2aws login --verbose

# Kick off previous session
saml2aws login --force

# skip prompts for username and password
saml2aws login --skip-prompt

# Reset configuration with 2 hour expiry
saml2aws configure --session-duration 7200
```

## IAM

### Assume Roles

Great [AWS article](https://aws-blog.de/2021/08/iam-what-happens-when-you-assume-a-role.html)

> authentication (principals) and authorization (policies)

### IAM account summary

```bash
aws organizations list-accounts
aws iam get-account-summary
aws iam list-roles
```

### Roles and Policies

```bash
# List Roles with certain Prefix
# only useful if roles created with Paths
aws iam list-roles --path-prefix /aws-service-role/

# Role policies attached to a single role ( not inline policies )
aws iam list-attached-role-policies --role-name $ROLE_NAME

# List customer line policies
aws iam list-role-policies --role-name $ROLE_NAME

# Get inline policy permission list
aws iam get-role-policy --role-name $ROLE_NAME --policy-name $POLICY_NAME

# Group policies attached to roles
aws iam list-attached-group-policies --group-name Admins

# Test which policy allows an action
aws iam simulate-principal-policy --action-names "sqs:Receivemessage" --policy-source-arn ${ROLE_ARN}

# Test multiple actions
aws iam simulate-principal-policy \
    --action-names \
        "sqs:Receivemessage" \
        "ssm:GetSecretValue" \
        "iam:CreateUser" \
        "lambda:InvokeFunction" \
    --policy-source-arn ${ROLE_ARN}

aws iam simulate-principal-policy \
    --action-names \
        "aws-portal:ViewBilling" \
    --policy-source-arn ${ROLE_ARN}



# List overview of Policy
aws iam get-policy  --policy-arn ${POLICY_ARN}

# List versions of Policy
aws iam list-policy-versions --policy-arn ${POLICY_ARN}

# List Permissions of a specific Policy version
aws iam get-policy-version  --policy-arn ${POLICY_ARN} --version-id=v4

# List Policies that might impact organization
# might require the Root org
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# list IAM Groups
aws iam list-groups

```

### Create role / policy / user (lifecycle)

```bash
# Create a managed policy from a JSON file
aws iam create-policy \
    --policy-name MyAppReadOnly \
    --policy-document file://policy.json
# → returns the policy ARN

# Create a role with a trust policy (who can assume it)
aws iam create-role \
    --role-name MyAppRole \
    --assume-role-policy-document file://trust-policy.json

# Attach a managed policy to a role
aws iam attach-role-policy \
    --role-name MyAppRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Attach a managed policy to a user / group
aws iam attach-user-policy --user-name alice --policy-arn ${POLICY_ARN}
aws iam attach-group-policy --group-name Devs --policy-arn ${POLICY_ARN}

# Put an inline policy on a role (less reusable, fine for one-offs)
aws iam put-role-policy \
    --role-name MyAppRole \
    --policy-name InlineExtra \
    --policy-document file://inline.json

# Detach + delete (cleanup order matters: detach first, then delete)
aws iam detach-role-policy --role-name MyAppRole --policy-arn ${POLICY_ARN}
aws iam delete-role-policy --role-name MyAppRole --policy-name InlineExtra
aws iam delete-role --role-name MyAppRole
aws iam delete-policy --policy-arn ${POLICY_ARN}

# Create a user + access key (use sparingly — prefer SSO/roles)
aws iam create-user --user-name alice
aws iam create-access-key --user-name alice
aws iam delete-access-key --user-name alice --access-key-id AKIAxxxx
aws iam delete-user --user-name alice
```

### Example trust policy (`trust-policy.json`)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

For cross-account, replace the Principal with `{ "AWS": "arn:aws:iam::OTHER-ACCT:root" }` and add an `sts:ExternalId` condition for third-party access (the confused-deputy fix).

### Assume a role (STS) — worked example

```bash
# 1. Assume the role and capture credentials
CREDS=$(aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/CrossAccountAdmin \
    --role-session-name alice-session \
    --duration-seconds 3600 \
    --query Credentials --output json)

# 2. Export the temporary credentials into the environment
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .SessionToken)

# 3. Verify (note the ASIA prefix on AccessKeyId = temporary creds)
aws sts get-caller-identity

# 4. When done, unset to return to your normal identity
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

For cross-account third-party access, add `--external-id <unique-string>` — required by the role's trust policy `sts:ExternalId` condition.

### Best practices

- [AWS best practice guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Best practices for managing AWS access keys](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
- [Good tips on Access Keys](https://ashishrajan.medium.com/aws-security-best-practices-access-keys-cloudsecurity-facb20aa0db6)

### Temporary credentials trump Access Keys

>Use IAM roles instead of long-term access keys  In many scenarios, you don't need long-term access keys that never expire (as you have with an IAM user). Instead, you can create IAM roles and generate temporary security credentials. Temporary security credentials consist of an access key ID and a secret access key, but they also include a security token that indicates when the credentials expire.

### Retire long-term AWS keys for 2FA and temp credentials

General [reference](https://mklein.io/2021/02/09/temporary-credentials-cli-console/) and [aws reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html) or [Terraform reference](https://klaviyo.tech/implementing-mfa-for-aws-cd9aab246103).  I found an article that got me over the "assign a MFA device to a IAM User" was [this excellent article](https://www.vlent.nl/weblog/2019/02/24/using-mfa-with-aws-cli/):

```bash
# Create PowerUserRole IAM role
aws iam create-role --role-name PowerUserRole --assume-role-policy-document file://role-policy.json

# Attach PowerUserAccess policy
aws iam attach-role-policy --role-name PowerUserRole --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

If you look inside this role, it has restrictions:

            "NotAction": [
                "iam:*",
                "organizations:*",
                "account:*"
            ]

# Create policy
aws iam create-policy --policy-name AllowAssumeRolePolicy --policy-document file://assume-role-policy.json

# Attach policy to user
aws iam attach-user-policy --user-name rm_lite --policy-arn arn:aws:iam::400000000000:policy/AllowAssumeRolePolicy
```

### Add new 2FA device in AWS IAM Console

```bash
# Go into AWS Console
Add Google Authenticator in the IAM section of the AWS Console next to the username

# Get a SessionToken Token
aws sts get-session-token \
    --serial-number arn:aws:iam::400907146110:mfa/rm_lite \
    --token-code < enter 6 digit code from Google Authenticator >

{
    "Credentials": {
        "AccessKeyId": "....",
        "SecretAccessKey": ".....",
        "SessionToken": "IQoJb3JpZ....j",
        "Expiration": "2021-05-17T22:26:57+00:00"
    }
}
```

### Up to 12 hours CLI access via Temp Credentials

[Set up 12 hours CLI access](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/)

### Set new, temp profile

```bash
aws configure --profile mfa set source_profile default
aws configure --profile mfa set role_arn arn:aws:iam::400000000000:user/rm_lite
aws configure --profile mfa set duration_seconds 3600
aws configure --profile mfa set mfa_serial arn:aws:iam::400000000000:mfa/rm_lite
aws configure set aws_session_token dd --profile jd

aws iam list-users --profile mfa
# Enter MFA code for arn:aws:iam::________

```

```json
# role-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::400000000:user/rm_lite"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
# assume-role-policy.json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": [
      "arn:aws:iam::400000000000:role/PowerUserRole"
    ]
  }
}
```

### Get csv file of all accounts

```bash
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content  | base64 -D > aws_cred_report.csv
```

### Dormant accounts manually

```bash
aws iam list-access-keys          // ListAccessKeys
aws iam get-access-key-last-used --access-key-id FFFFFFFFFFFFFFFF
```

### List users

```bash
aws iam list-users --output json
aws iam list-users --output text | awk '{print $NF}'        // just username
aws iam list-users --output text > users.txt | wc -l        // count users
```

### List Access Keys by User

```bash
aws iam list-access-keys --user-name 'foobar'
aws iam list-access-keys --user-name 'foobar_with_multiple_keys' --max-items 5
```

### List all Access Key IDs

List all [Key IDs](https://stackoverflow.com/questions/24028610/find-the-owner-of-an-aws-access-key).

```bash
for user in $(aws iam list-users --output text | awk '{print $NF}'); do
    aws iam list-access-keys --user $user --output text
done
```

### Best practice

[IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

## lambda

### Info

```bash
# list 10 lambdas available in region and account, if any
aws lambda list-functions --max-items 10

# get all env variables and settings ( memory, timeouts, ARNs )
aws lambda get-function-configuration --function-name ${FUNCTION_NAME}

# same as configuration + info on where the code is located and Tags
aws lambda get-function --function-name ${FUNCTION_NAME}

```

### Create role

The `file://` is required:

`aws iam create-role --role-name rm-lambda-demo-role --assume-role-policy-document file://trust-policy.json`

### whoami

`aws sts get-caller-identity`

### Get role ARN

`aws iam get-role --role-name rm-lambda-demo-role`

### Python upload code

Ensure the python function can inject parameters:

```python
def rm_handler(event, context):
    send_cake_recipe()
```

### Zip up code and dependencies

```bash
 pip3 install -r requirements.txt --target ./package
cd package
zip -r ../my-deployment-package.zip .
cd ..
zip -g my-deployment-package.zip demo_lambda.py
```

### Create

```bash
aws lambda create-function \
    --function-name MyPyLambdaFunction \
    --runtime python3.7 \
    --zip-file fileb://my-deployment-package.zip \
    --handler demo_lambda.rm_handler \
    --role arn:aws:iam::400907146110:role/rm-lambda-demo-role
```

### Update code

Code change:

`zip -g my-deployment-package.zip demo_lambda.py`

Then push:

```bash
aws lambda update-function-code \
    --function-name MyPyLambdaFunction \
    --zip-file fileb://my-deployment-package.zip
```

Or push a container image:

```bash
aws lambda update-function-code \
    --function-name MyPyLambdaFunction \
    --image-uri ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/my-image:latest
```

### Update configuration (env vars, memory, timeout, layers)

```bash
# environment variables (use update-function-configuration, NOT update-function-code)
aws lambda update-function-configuration \
    --function-name MyPyLambdaFunction \
    --environment Variables={LD_LIBRARY_PATH=/usr/bin/test/lib64,LOG_LEVEL=DEBUG}

# memory and timeout
aws lambda update-function-configuration \
    --function-name MyPyLambdaFunction \
    --memory-size 1024 \
    --timeout 30

# attach layers
aws lambda update-function-configuration \
    --function-name MyPyLambdaFunction \
    --layers arn:aws:lambda:eu-west-1:account-id:layer:my-layer:3
```

### Publish a version and create an alias

```bash
# snapshot current code+config as immutable version
aws lambda publish-version --function-name MyPyLambdaFunction

# create/update an alias pointing at a version
aws lambda create-alias --function-name MyPyLambdaFunction --name prod --function-version 7
aws lambda update-alias --function-name MyPyLambdaFunction --name prod --function-version 8

# weighted alias for canary deploys (90% v7, 10% v8)
aws lambda update-alias \
    --function-name MyPyLambdaFunction \
    --name prod \
    --function-version 7 \
    --routing-config 'AdditionalVersionWeights={"8"=0.1}'
```

### Delete

```bash
aws lambda delete-function --function-name MyPyLambdaFunction
aws lambda delete-alias --function-name MyPyLambdaFunction --name prod
```

## Invoke Lambda

```bash
# simplest
aws lambda invoke \
    --function-name foobar \
    --payload $(echo "{\"foo\":\"bar\"}" | base64) \
    out.txt

# synchronous without Base64 encoding
# Change the default timeout ( 3 seconds ) to avoid hard to debug errors
aws lambda invoke \
    --function-name foobar \
    --cli-binary-format raw-in-base64-out \
    --payload '{"foo":"bar"}' \
    out.json

# Debug
aws --debug lambda invoke \
    --function-name foobar \
    --cli-binary-format raw-in-base64-out \
    --payload '{"foo":"bar"}' \
    out.json

# To invoke a function asynchronously, set InvocationType to Event

aws lambda invoke out.txt \
    --function-name foobar \
    --invocation-type Event \
    --payload $(echo "{\"foo\":\"bar\"}" | base64)


# more complicated
aws lambda invoke out.txt \
    --function-name MyPyLambdaFunction \
    --log-type Tail \
    --query 'LogResult' \
    --output text |  base64 -d
```

### Invoke and debug

```bash
 aws lambda invoke out.txt --debug\
    --function-name MyPyLambdaFunction \
    --log-type Tail \
    --query 'LogResult' \
    --output text |  base64 -d
```

## Keys

### States

<https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html>

### Tech notes

<https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-create-cmk.html>

- Imported keys have an `Origin value` of `External`
- The `import token` contains metadata to ensure that your key material is imported correctly
- Until you generate the Key Material and encrypt with the `wrapping key`, you have nothing

### Generate Symmetric Key

`aws kms create-key --origin EXTERNAL --region eu-west-2`

At this point, there is NO key.  You have just generated `meta-data` and uploaded to `aws`.  You have not generated or uploaded actual `key material` to `AWS`.

### List

`aws kms list-keys`

### Get Wrapping Key from KMS Portal

< login >

### Get the Wrapping Key and Spec

```bash
export REGION=eu-west-2
export KEY_ALIAS=cmk_with_externalmaterial
export KEY_ID=<key ID>
export KEY=`aws kms --region eu-west-2 get-parameters-for-import --key-id $KEY_ID --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_2048 --query '{Key:PublicKey,Token:ImportToken}' --output text`
```

### Copy the Base64 encoded Wrapping Key and Import Token

```bash
echo $KEY | awk '{print $1}' > PublicKey.b64
echo $KEY | awk '{print $2}' > ImportToken.b64
openssl enc -d -base64 -A -in PublicKey.b64 -out PublicKey.bin
openssl enc -d -base64 -A -in ImportToken.b64 -out ImportToken.bin

# Generate Key Material
openssl rand -out PlaintextKeyMaterial.bin 32
xxd PlaintextKeyMaterial.bin                    # print key to stdio

# Encrypt Key Material
openssl rsautl -encrypt \
                 -in PlaintextKeyMaterial.bin \
                 -oaep \
                 -inkey PublicKey.pem \
                 -keyform PEM \
                 -pubin \
                 -out EncryptedKeyMaterial.bin

# Encrypt Key Material with the public key
openssl pkeyutl \
    -in PlaintextKeyMaterial.bin \
    -out EncryptedKeyMaterial.bin \
    -inkey PublicKey.bin \
    -keyform DER \
    -pubin \
    -encrypt \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
```

### Import Key Material

You do NOT need to manually ENABLE a key.  It is auto-enabled after import:

```bash
aws kms import-key-material \
    --region ${REGION} \
    --key-id ${KEY_ID} \
    --encrypted-key-material fileb://EncryptedKeyMaterial.bin \
    --import-token fileb://ImportToken.bin \
    --expiration-model KEY_MATERIAL_EXPIRES \
    --valid-to 2021-05-05T12:00:00-08:00
```

### Test key is registered

```bash
aws kms describe-key --key-id ${KEY_ID}
```

### Encrypt / decrypt small payloads directly

For data ≤ 4 KB you can call KMS directly. For anything bigger, use **envelope encryption** (next section).

```bash
# Encrypt — output is binary; --query lets us strip to base64 ciphertext
aws kms encrypt \
    --key-id alias/my-key \
    --plaintext fileb://secret.txt \
    --query CiphertextBlob \
    --output text > ciphertext.b64

# Decrypt — feed the base64 ciphertext back in
aws kms decrypt \
    --ciphertext-blob fileb://<(base64 -d ciphertext.b64) \
    --query Plaintext \
    --output text | base64 -d > secret-recovered.txt
```

### Envelope encryption (for larger data)

KMS encrypts a *data key*; the data key encrypts your actual data locally.

```bash
# 1. Ask KMS for a data key (returns both plaintext + encrypted versions)
aws kms generate-data-key \
    --key-id alias/my-key \
    --key-spec AES_256

# 2. App uses the plaintext data key to AES-encrypt the data
# 3. App stores [encrypted data | encrypted data key] together
# 4. To decrypt: send the encrypted data key back to KMS
aws kms decrypt --ciphertext-blob fileb://encrypted-data-key.bin

# Get only the data key (without plaintext) if you only need to store it
aws kms generate-data-key-without-plaintext --key-id alias/my-key --key-spec AES_256
```

### Aliases (use these, not raw key IDs)

```bash
# list aliases
aws kms list-aliases

# create an alias pointing at a key
aws kms create-alias --alias-name alias/my-key --target-key-id ${KEY_ID}

# update what an alias points at (key rotation by reference)
aws kms update-alias --alias-name alias/my-key --target-key-id ${NEW_KEY_ID}

# delete an alias
aws kms delete-alias --alias-name alias/my-key
```

### Rotation, deletion, key policy

```bash
# enable automatic annual rotation (customer-managed keys only)
aws kms enable-key-rotation --key-id ${KEY_ID}
aws kms get-key-rotation-status --key-id ${KEY_ID}

# schedule key deletion (7-30 days waiting period; cancel within window)
aws kms schedule-key-deletion --key-id ${KEY_ID} --pending-window-in-days 30
aws kms cancel-key-deletion --key-id ${KEY_ID}

# get / put key policy (the resource-based policy on the key itself)
aws kms get-key-policy --key-id ${KEY_ID} --policy-name default
aws kms put-key-policy --key-id ${KEY_ID} --policy-name default --policy file://key-policy.json
```

### Reference

<https://aws.amazon.com/premiumsupport/knowledge-center/import-keys-kms/>

## ECR

```bash
# Describe Registry
aws ecr describe-registry

# Describe repositories
aws ecr describe-repositories

# list images in a repo
aws ecr list-images --repository-name $REPO

# details of each image
aws ecr describe-images --repository-name $REPO

# count images in a repo
aws ecr list-images --repository-name $REPO | jq '.imageIds | unique_by(.imageDigest) | length'

# list impact of Dry-Run on a Repository
aws ecr get-lifecycle-policy-preview --repository-name ${REPO}

# list policy
aws ecr get-repository-policy --repository-name ${REPO}

# Create repo
aws ecr create-repository --repository-name ${REPO_NAME}

export REG_ID=< repo ID >
export REPO_NAME=< repo name >
export REGION=eu-west-2

aws ecr put-lifecycle-policy \
    --registry-id ${REG_ID} \
    --repository-name ${REPO_NAME} \
    --lifecycle-policy-text '{"rules":[{"rulePriority":10,"description":"Expire old images","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":800},"action":{"type":"expire"}}]}'

# Create repo with auto vulnerability scan
aws ecr create-repository \
 --repository-name ${REPO_NAME} \
 --image-tag-mutability IMMUTABLE \
 --image-scanning-configuration scanOnPush=true

# Login in to managed Docker service that ECR provides
aws ecr get-login-password \
 --region ${REGION} | docker login --username AWS \
 --password-stdin <account id>.dkr.ecr.<region>.amazonaws.com

# Authenticate local Docker daemon against the ECR registry
$(aws ecr get-login --registry-ids ${REG_ID} --no-include-email)
```

## Proxy AWS CLI traffic

### Set CLI not to verify the server's Certificate Chain

`aws sts get-caller-identity --no-verify-ssl`

## Secrets Manager

```bash
# list of Secret Names ( not the actual secret string )
aws secretsmanager list-secrets
aws secretsmanager list-secrets --filters Key=name,Values=secret/in/aws

# list Version IDs of Secret
aws secretsmanager list-secret-version-ids --secret-id ${SECRET_ID}

# describe secret
aws secretsmanager describe-secret --secret-id ${SECRET_ID}

# Delete secret permanently ( not possible via UI )
aws secretsmanager delete-secret --secret-id ${SECRET_ID} --force-delete-without-recovery

# Get secret value (the actual secret string)
aws secretsmanager get-secret-value --secret-id ${NAME_OF_SECRET}
aws secretsmanager get-secret-value --secret-id ${NAME_OF_SECRET} --query SecretString --output text
aws secretsmanager get-secret-value --secret-id ${NAME_OF_SECRET} --query SecretString --output text | jq .

# Create a new secret
aws secretsmanager create-secret \
    --name my-app/db-password \
    --description "DB password for my-app" \
    --secret-string '{"username":"admin","password":"hunter2"}' \
    --kms-key-id alias/my-key

# Update an existing secret's value (creates a new version)
aws secretsmanager put-secret-value \
    --secret-id my-app/db-password \
    --secret-string '{"username":"admin","password":"new-pass"}'

# Generate a strong random password (without creating a secret)
aws secretsmanager get-random-password --password-length 32 --exclude-characters '"@/\'

# Rotate a secret immediately (requires a Lambda rotation function attached)
aws secretsmanager rotate-secret --secret-id my-app/db-password

# Restore a deleted-pending secret (within the recovery window)
aws secretsmanager restore-secret --secret-id ${SECRET_ID}
```

## Elastic Container Service ( ECS )

```bash

# list clusters
aws ecs list-clusters

# list services
aws ecs list-services --cluster ${CLUSTER_NAME}

# list Task Definitions
aws ecs list-task-definitions

# list container arn
aws ecs list-container-instances --cluster ${CLUSTER_NAME}

# Run a task
aws ecs run-task --cluster ${CLUSTER_NAME} --task-definition myapp-shell:25

# Run a task arn
aws ecs run-task --cluster ${CLUSTER_NAME} --task-definition ${TASK_DEFINITION}

# list open ports, arn
aws ecs describe-container-instances \
    --cluster ${CLUSTER_NAME} \
    --container-instances ${CONTAINER_INSTANCE_ID}

# Describe a service (desired vs running count, events, etc.)
aws ecs describe-services --cluster ${CLUSTER_NAME} --services ${SERVICE_NAME}

# Force a service to redeploy with the latest task definition
aws ecs update-service --cluster ${CLUSTER_NAME} --service ${SERVICE_NAME} --force-new-deployment

# Exec into a running task (requires execute-command enabled on the service + SSM agent)
aws ecs execute-command \
    --cluster ${CLUSTER_NAME} \
    --task ${TASK_ARN} \
    --container ${CONTAINER_NAME} \
    --command "/bin/sh" \
    --interactive

# Stop a running task
aws ecs stop-task --cluster ${CLUSTER_NAME} --task ${TASK_ARN}

# Register a new task definition from a JSON file
aws ecs register-task-definition --cli-input-json file://taskdef.json

# Describe a task definition
aws ecs describe-task-definition --task-definition my-task:42

```

## SSM Sessions

Browser-less / SSH-less shell into EC2 / ECS containers via SSM agent.

```bash
# Simplest — start an interactive shell on an instance
aws ssm start-session --target i-xxxxx

# With a specific profile / region
aws ssm start-session --target i-xxxxx --profile prod --region eu-west-1

# Run a one-shot command (no interactive shell)
aws ssm send-command \
    --instance-ids i-xxxxx \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["uname -a","df -h"]'

# Get the output of a send-command invocation
aws ssm get-command-invocation --command-id ${COMMAND_ID} --instance-id i-xxxxx

# Port forwarding (e.g. tunnel local 5432 → RDS in private subnet)
aws ssm start-session \
    --target i-xxxxx \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters '{"host":["my-db.xxx.eu-west-1.rds.amazonaws.com"],"portNumber":["5432"],"localPortNumber":["5432"]}'

# List managed instances (those the SSM agent has registered)
aws ssm describe-instance-information

# Exec into an ECS container (the older complex form)
export encodedCommands=$(echo "bash" | base64)
export ecsInstanceId="i-xxxx"
# the 64-char Container Runtime ID
export containerId="xxxx"

aws ssm start-session \
    --target $ecsInstanceId \
    --document-name someDoc \
    --parameters command="$encodedCommands",container="$containerId"
```

For ECS Fargate / ECS-on-EC2 with awsvpc mode, prefer `aws ecs execute-command` (see ECS section).

## SSM Parameter Store

### Set

```bash
aws ssm put-parameter \
    --name "username" \
    --value "foobar" \
    --type String \
    --tags "Key=month,Value=april2021"
```

### Set encrypted

```bash
aws ssm put-parameter \
    --name "username" \
    --value "foobar" \
    --type SecureString \
    --key-id "alias name"
```

### Get

```bash
export AWS_PROFILE=foo

# list all parameters in account/region (just names)
aws ssm describe-parameters

# get a single parameter
aws ssm get-parameter --name "username"
aws ssm get-parameter --name "username" --with-decryption          # decrypts SecureString
aws ssm get-parameter --name "username" --query 'Parameter.Value' --output text

# get multiple parameters by exact name
aws ssm get-parameters --names "username" "password" --with-decryption

# get a whole tree of parameters (hierarchical lookup)
aws ssm get-parameters-by-path --path "/myapp/prod/" --recursive --with-decryption

# get a specific version of a parameter
aws ssm get-parameter --name "username:3"     # version 3

# get parameter history
aws ssm get-parameter-history --name "username"
```

### Reference a Secrets Manager secret from Parameter Store

```bash
# Parameter Store can transparently resolve to a Secrets Manager secret —
# apps read everything via one API, rotating secrets are managed in Secrets Manager.
aws ssm get-parameter \
    --name "/aws/reference/secretsmanager/my-app/db-password" \
    --with-decryption
```

### Delete

```bash
aws ssm delete-parameter --name "username"
aws ssm delete-parameters --names "param1" "param2" "param3"
```

### Secrets Manager vs SSM Parameter Store

- **Parameter Store** — Standard tier is free up to 10,000 params; 4 KB max value; no native rotation; hierarchical paths; great for config + non-rotating secrets
- **Secrets Manager** — $0.40/secret/month; 64 KB max; native rotation for RDS/Aurora/DocumentDB/Redshift; resource policies; multi-region replication

Common pattern: config in Parameter Store, rotating secrets in Secrets Manager, referenced from Parameter Store via `/aws/reference/secretsmanager/<name>`. See the main study notes for the full comparison.

References:
- [Serverless Secrets](https://www.stackery.io/blog/serverless-secrets/)
- [Secrets Manager vs Parameter Store (A Cloud Guru)](https://acloudguru.com/blog/engineering/an-inside-look-at-aws-secrets-manager-vs-parameter-store)
- [1Strategy comparison](https://www.1strategy.com/blog/2019/02/28/aws-parameter-store-vs-aws-secrets-manager/)
