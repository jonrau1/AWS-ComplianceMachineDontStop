# AWS-ComplianceMachineDontStop
Terraform Scripts (and other goodies) to making your AWS Account SuperDuperCompliant(TM)

Some Caveats:
- Version 1 is Very Raw -- will be refactoring to use Variables and TFVARs, one day (as well as making this readme less offensive to all of humanity)
- NACL & SG Rules are Pretty Permissive, Change Those
- This is assuming you are in a MASTER Account -- I have not included any GuardDuty Member sign-ups or Security Hub Member
- This does not use Macie
- This assumes you do not have Config, Global CloudTrail, and your own encryption schemes setup
- Buckets do not have Bucket Policies, nor do they have Lifecycles (yet)

Following Services will be Utilizied
- AWS Config
- AWS CloudWatch
- AWS CloudTrail
- AWS VPC
- AWS IAM (Roles/Policies/STS)
- AWS Inspector
- AWS SNS
- AWS S3
- AWS KMS
- AWS Security Hub
- AWS CloudFormation (within TF, because I'm lazy)
- AWS GuardDuty
