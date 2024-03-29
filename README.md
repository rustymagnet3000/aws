# AWS

<!-- TOC depthfrom:2 depthto:2 withlinks:true updateonsave:true orderedlist:false -->

- [whoami](#whoami)
- [SNS](#sns)
- [s3](#s3)
- [dynamodb](#dynamodb)
- [Cloudtrail](#cloudtrail)
- [Simple Notification Service  SNS](#simple-notification-service--sns)
- [Elasticache  Redis](#elasticache--redis)
- [Cloudwatch](#cloudwatch)
- [Databases](#databases)
- [Inspector](#inspector)
- [ec2](#ec2)
- [Athena](#athena)
- [Tips](#tips)
- [CLI](#cli)
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

```shell
# list Topics
aws sns list-topics

# list details of a Topic
aws sns get-topic-attributes \
    --topic-arn ${TOPIC_ARN}
    
# publish
aws sns publish \                   
    --topic-arn ${TOPIC_ARN} \
    --message file://message.txt
```

## s3

```bash
export BUCKET_NAME=mybucket  
export BUCKET_URI=export BUCKET=s3://mybucket
export BUCKET_HTTP=https://mybucket.eu-west-2.amazonaws.com

# list
aws s3 ls ${BUCKET_NAME}

# list without credentials / owning that bucket
aws s3 --endpoint-url ${BUCKET_HTTP} ls

# list with subfolders
aws s3 ls ${BUCKET_URI}--recursive
aws s3 ls ${BUCKET_URI} --recursive --human-readable --summarize

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

```

### Read compressed json file from s3

`cat compressed.ndjson| zcat`

## dynamodb

#### Set up locally

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

#### Add local data

```bashq
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

#### Delete local table

```bash
aws dynamodb delete-table \
    --table-name DELETEme \
    --endpoint-url http://localhost:8000
```

#### Query and list locally

```bash
# create empty Profile
aws configure --profile rm_local_db

# list Tables
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

#### List table and fields

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

#### Replicate a DynamoDB table locally

Original [article](https://medium.com/@balint_sera/replicate-a-dynamodb-table-409641215e8).

```bash
# describe table
aws dynamodb describe-table --table-name foo_table > foo_table.txt

#copy json into files. Example: key-schema.json

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

#### Put item

```bash
aws dynamodb put-item \
    --table-name DELETEme \
    --item '{
        "Name": {"S": "Alice"},
        "Age": {"N": "99"} 
      }' \
    --return-consumed-capacity TOTAL
```

#### Query item

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

#### Query individual items with Projection Expression

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

#### Query item with file

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

#### Query with Python Boto3

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

#### DynamoDB reserved words

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

## Simple Notification Service ( SNS )

```bash
# list topics
aws sns list-topics

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

## Databases

#### Describe

```bash
aws rds describe-db-clusters | jq '.DBClusters[] | select(.EngineVersion | contains("9.6")) | { name: .DBClusterIdentifier, version: .EngineVersion }'

aws rds describe-db-engine-versions --engine postgres | grep -A 1 AutoUpgrade| grep -A 2 true |grep PostgreSQL | sort --unique | sed -e 's/"Description": "//g'

aws rds download-db-log-file-portion \
	--db-instance-identifier foobar-db \
	--log-file-name error/postgresql.log.2021-01-01 \
	--output text > tail.txt
```

## Inspector

#### Tips

`https://awsclibuilder.com/home/services/inspector`

#### List ( with a max )

```bash
aws inspector list-findings --max-items 10
aws inspector list-findings --max-items 10 --region eu-west-1 --output table
aws inspector list-findings --max-items 10 --region eu-west-1 --output json | jq .
```

#### List Assessment Runs

``` bash
aws inspector list-assessment-runs --max-items=10
```

#### Describe finding

`aws inspector describe-findings --finding-arns arn:aws:inspector:eu-west-2:......./finding/0-6xxxxxxx`

## ec2

```bash
# Allocate Public IP address
aws ec2 allocate-address

# List Static, Public IP addresses
aws ec2 describe-addresses 

# Release Public IP address
aws ec2 release-address --allocation-id eipallocXXXXXXXXX

# Describe VPC
aws ec2 describe-vpc-endpoint-services

# Describe instances
aws --profile saml ec2 describe-instances --region ${AWS_REGION}

# regex or wildcard
aws ec2 describe-images --filters 'Name=name,Values="*"'
```

## Athena

#### List table and fields

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
// if errors due to Python version: `xcode-select --install`
// if you installed via other methods and want to clean-up:
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

## saml2aws

> CLI tool which enables you to login and retrieve AWS temporary credentials.

#### Set up

```bash
brew install awscli
brew install saml2aws
saml2aws --version

saml2aws configure
Select provider ( like Google )
URL: enter URL of Identity Provider
Username: email known to Identity Provider
Password: Password associated to email
```

#### Day-2-Day use

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

#### IAM account summary

```bash
aws organizations list-accounts 
aws iam get-account-summary
aws iam list-roles
```

#### Roles and Policies

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

#### Best practices

- [AWS best practice guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Best practices for managing AWS access keys](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
- [Good tips on Access Keys](https://ashishrajan.medium.com/aws-security-best-practices-access-keys-cloudsecurity-facb20aa0db6)

#### Temporary credentials trump Access Keys

>Use IAM roles instead of long-term access keys  In many scenarios, you don't need long-term access keys that never expire (as you have with an IAM user). Instead, you can create IAM roles and generate temporary security credentials. Temporary security credentials consist of an access key ID and a secret access key, but they also include a security token that indicates when the credentials expire.

#### Retire long-term AWS keys for 2FA and temp credentials

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

#### Add new 2FA device in AWS IAM Console

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

#### Up to 12 hours CLI access via Temp Credentials

[Set up 12 hours CLI access](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/)

#### Set new, temp profile

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

#### Get csv file of all accounts

```bash
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content  | base64 -D > aws_cred_report.csv
```

#### Dormant accounts manually

```bash
aws iam list-access-keys          // ListAccessKeys
aws iam get-access-key-last-used --access-key-id FFFFFFFFFFFFFFFF
```

#### List users

```bash
aws iam list-users --output json
aws iam list-users --output text | awk '{print $NF}'        // just username
aws iam list-users --output text > users.txt | wc -l        // count users
```

#### List Access Keys by User

```bash
aws iam list-access-keys --user-name 'foobar'
aws iam list-access-keys --user-name 'foobar_with_multiple_keys' --max-items 5
```

#### List all Access Key IDs

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
    --function-name  MyPyLambdaFunction \
    --zip-file fileb://my-deployment-package.zip \
```

### Update environmental variable

```bash
aws lambda update-function-code \
    --function-name  MyPyLambdaFunction \
    --environment Variables={LD_LIBRARY_PATH=/usr/bin/test/lib64}
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
aws kms describe-key \
    --key-id ${KEY_ID}
```

### Reference

<https://aws.amazon.com/premiumsupport/knowledge-center/import-keys-kms/>

## ECR

```shell
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

#### Set CLI not to verify the server's Certificate Chain

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

#get Secret value
aws secretsmanager get-secret-value --secret-id ${NAME_OF_SECRET}
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

```

## SSM Sessions

```bash
export encodedCommands=$(echo "bash" | base64)
export ecsInstanceId="i-xxxx"
# the 64-char Container Runtime ID
export containerId="xxxx"

aws ssm start-session \
    --target $ecsInstanceId \
    --document-name someDoc \
    --parameters command="$encodedCommands",container="$containerId"
```

## SSM Parameter Store

#### Set

```bash
aws ssm put-parameter \
    --name "username" \
    --value "foobar" \
    --type String \
    --tags "Key=month,Value=april2021"
```

#### Set encrypted

```bash
aws ssm put-parameter \
    --name "username" \
    --value "foobar" \
    --type SecureString \
    --key-id "alias name"
```

#### Get

```bash
export AWS_PROFILE=foo
aws ssm describe-parameters
aws ssm get-parameters --name "username"
aws ssm get-parameters --name "username" --with-decryption
aws ssm get-parameters-by-path --path "/foo/bar/"    <-- full path minus the parameter name
```

#### Secrets Manager vs SSM

```bash
https://www.stackery.io/blog/serverless-secrets/

https://acloudguru.com/blog/engineering/an-inside-look-at-aws-secrets-manager-vs-parameter-store?utm_source=legacyla&utm_medium=redirect&utm_campaign=one_platform

https://www.1strategy.com/blog/2019/02/28/aws-parameter-store-vs-aws-secrets-manager/

https://liuhongbo.medium.com/build-an-aws-serverless-application-using-sam-aae383e68b6f
```
