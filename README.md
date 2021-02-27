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

#### Create role

`aws iam create-role --role-name lambda-ex --assume-role-policy-document trust-policy.json`
