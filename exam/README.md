# AWS Exam

<!-- TOC depthfrom:2 depthto:2 withlinks:true updateonsave:true orderedlist:false -->

- [AWS Exam](#aws-exam)
  - [Useful links](#useful-links)
  - [EC2](#ec2)
    - [Elastic IP versus Standard Public IP](#elastic-ip-versus-standard-public-ip)

<!-- /TOC -->

## Useful links

- [Somebody who passed](https://medium.com/datamindedbe/hooray-im-an-aws-certified-pro-architect-now-what-89f4d8b22596)
- `acloud.guru` videos
- `whizlabs` practice exams

## EC2

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