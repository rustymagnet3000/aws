# AWS

<!-- TOC depthfrom:2 depthto:2 withlinks:true updateonsave:true orderedlist:false -->

- [dynamodb](#dynamodb)
- [Athena](#athena)
- [Tips](#tips)
- [CLI](#cli)
- [saml2aws](#saml2aws)
- [IAM](#iam)
- [Create lambda](#create-lambda)
- [Keys](#keys)
- [Container Registry](#container-registry)
- [Deploy AWS Infrastructure as Code IaC](#deploy-aws-infrastructure-as-code-iac)

<!-- /TOC -->

## dynamodb

#### List table and fields

```bash
export AWS_DEFAULT_REGION=us-east-x
aws dynamodb list-tables
```

#### Describe table

`aws dynamodb describe-table   --table-name footable`

#### Read table

`aws dynamodb scan --table-name footable`

#### Query table

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

## Athena

#### List table and fields

```bash
aws athena list-table-metadata \
    --catalog-name AwsDataCatalog \
    --database-name sampledb \
    --max-items 2 \
    --region=us-east-2
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
```

#### Day-2-Day use

```bash
eval $(saml2aws script)     // check if logged in
saml2aws login
saml2aws login --verbose
aws --profile saml ec2 describe-instances --region ${REGION}
```

## IAM

#### List users

`aws iam list-users --output json`

#### List all Access Key IDs

List all [Key IDs](https://stackoverflow.com/questions/24028610/find-the-owner-of-an-aws-access-key).

```bash
for user in $(aws iam list-users --output text | awk '{print $NF}'); do
    aws iam list-access-keys --user $user --output text
done
```

### Best practice

[IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

## Create lambda

### Info

```bash
aws lambda list-functions --max-items 10
aws lambda get-function --function-name MyPyLambdaFunction
aws lambda get-function-configuration --function-name MyPyLambdaFunction
```

### Create role

The `file://` is required:

`aws iam create-role --role-name rm-lambda-demo-role --assume-role-policy-document file://trust-policy.json`

### display info about IAM identity used to authenticate the request

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

### Invoke

```bash
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

### Invoke with inline json ( BROKEN )

```bash
aws lambda invoke out.txt \
    --function-name MyPyLambdaFunction \
    --invocation-type Event \
    --cli-binary-format raw-in-base64-out \
    --payload $(echo "{\"foo\":\"bar\"}" | base64)
```

#### Payload from file ( BROKEN )

aws lambda invoke out.txt \
    --function-name MyPyLambdaFunction \
    --invocation-type Event \
    --cli-binary-format raw-in-base64-out \
    --payload file://input.json

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
```

### Generate Key Material

```bash
openssl rand -out PlaintextKeyMaterial.bin 32
xxd PlaintextKeyMaterial.bin                    # print key to stdio
```

### Encrypt Key Material

```bash
openssl rsautl -encrypt \                                                             
                 -in PlaintextKeyMaterial.bin \
                 -oaep \
                 -inkey PublicKey.pem \   
                 -keyform PEM \   
                 -pubin \
                 -out EncryptedKeyMaterial.bin
```

### Encrypt Key Material with the public key

openssl pkeyutl \
    -in PlaintextKeyMaterial.bin \
    -out EncryptedKeyMaterial.bin \
    -inkey PublicKey.bin \
    -keyform DER \
    -pubin \
    -encrypt \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \

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

## Container Registry

#### Create repo

```bash
aws ecr create-repository --repository-name ${REPO_NAME}

export REG_ID=< repo ID >
export REPO_NAME=< repo name >
export REGION=eu-west-2

aws ecr put-lifecycle-policy \   
    --registry-id ${REG_ID} \
    --repository-name ${REPO_NAME} \        
    --lifecycle-policy-text '{"rules":[{"rulePriority":10,"description":"Expire old images","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":800},"action":{"type":"expire"}}]}'
{
```

#### Create repo with auto vulnerability scan

```bash
aws ecr create-repository \
 --repository-name ${REPO_NAME} \
 --image-tag-mutability IMMUTABLE \
 --image-scanning-configuration scanOnPush=true
```

#### Login in to managed Docker service that ECR provides

```bash
aws ecr get-login-password \
 --region ${REGION} | docker login --username AWS \
 --password-stdin <account id>.dkr.ecr.<region>.amazonaws.com
```

#### Authenticate local Docker daemon against the ECR registry

`$(aws ecr get-login --registry-ids ${REG_ID} --no-include-email)`

## Deploy AWS Infrastructure as Code (IaC)

Great intro to writing [AWS Terraform files](https://blog.gruntwork.io/an-introduction-to-terraform-f17df9c6d180):

```terraform
brew upgrade hashicorp/tap/terraform
terraform --version
terraform -install-autocomplete
terraform init
terraform plan
terraform apply
terraform output
terraform output public_ip
```
