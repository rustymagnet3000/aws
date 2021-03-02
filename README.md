# aws

## CLI

### Starting

#### Version

`aws --version`

#### Persisted config

`cat ~/.aws/config`

#### Persisted credentials

`cat ~/.aws/credentials`

#### Remove credentials / profiles

`vi ~/.aws/config`

#### Update

`pip3 install awscli --upgrade`

#### List

```bash
aws configure list
aws configure list-profiles
```

#### Region

```bash
aws configure set region eu-west-2 --profile integ
aws configure get region --profile integ
```

#### Configure profile

```bash
aws configure --profile rm_lambda_demo
AWS Access Key ID [None]: ....XW
AWS Secret Access Key [None]: ...zO0
Default region name [None]: eu-west-2
Default output format [None]: json
```

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
