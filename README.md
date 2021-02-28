# aws

## CLI

### Starting

#### Version

`aws --version`

#### Persisted config

`cat ~/.aws/config`

#### Persisted credentials

`cat ~/.aws/credentials`

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

#### Create role

The `file://` is required:

`aws iam create-role --role-name rm-lambda-demo-role --assume-role-policy-document file://trust-policy.json`

#### Get role ARN

`aws iam get-role --role-name rm-lambda-demo-role`

### Python upload code

Ensure the python function can inject parameters:

```python
def rm_handler(event, context):
    send_cake_recipe()
```

#### Zip up code and dependencies

```bash
 pip3 install -r requirements.txt --target ./package
cd package
zip -r ../my-deployment-package.zip .
cd ..
zip -g my-deployment-package.zip demo_lambda.py
```

#### Create function

```bash
aws lambda create-function \
    --function-name MyPyLambdaFunction \
    --runtime python3.7 \
    --zip-file fileb://my-deployment-package.zip \
    --handler demo_lambda.rm_handler \
    --role arn:aws:iam::400907146110:role/rm-lambda-demo-role
```

#### Invoke function

```bash
aws lambda invoke --function-name MyPyLambdaFunction \
    --invocation-type Event \
    --cli-binary-format raw-in-base64-out \
    --payload '{"new_ingrediant": "eggs"}' response.json 
```
