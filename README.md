# AWS Compliance Machine Don't Stop!
#### Proof of Value Terraform Scripts to utilize Amazon Web Services (AWS) Security, Identity & Compliance Services to Support your AWS Account Security Posture. 
These Terraform Scripts are made with using the Preview of AWS Security Hub in Mind. Security Hub collects Information from GuardDuty, Macie, Inspector as well as AWS Config. Security Hub (the Preview at least) comes with Center for Internet Security (CIS) Config Rules that follow best security practices for account-wide security posture. The Services that are turned on, as well as the inline CloudFormation Stack are all made to support these CIS Rules from Security Hub, and also go a good way towards general security hardening for your account. Visualization & Alerting support have also been added (please refer to ReadMe & Changelog) via Kinesis and Glue to perform crawling & ETL of logs from AWS WAF. Services that are used are listed later in the Readme, this is also a work in progress and other features may be added such as Amazon Macie, and Custom Lambda Functions / CloudWatch Events to further Support Security Posture on AWS.

## Getting Started

### Baseline Knowledge Required
- **UPDATE** I have removed the `terraform.tfvars` files as the better way to use Terraform is to provide a properly permissioned EC2 Instance Profile without any keys on the instance. The `provider.tf` files now have the only thing needed (a Region) to run `terraform init` with the proper role attached
    - Refer to my other Repo here for Remote State Management w/ Terraform: https://github.com/jonrau1/AWS-CodePipeline-TerraformCICD-Workshop
- Basic Level Understanding of navigating AWS Console, usage of SSH (or however you use Terraform) and Linux text editors (Vi, Vim, Nano, etc)
- Basic Knowledge on Installing / Maintaing AWS Simple Systems Manager (SSM) and Amazon Inspector Agents on your Linux/Windows EC2 Instances
- Basic Level Understanding of how AWS Security, Identity & Compliance Services Work with One Another
- Basic Knowledge of Terraform Concepts & Commands Expertise (and Somewhere to Use it from)
- The Region You Deploy this PoV to **Must Not Have** GuardDuty, Security Hub, or Config Enabled!

### AWS Services Used
- **GuardDuty** (https://aws.amazon.com/guardduty/)
    - A threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts and workloads
- **KMS** (https://aws.amazon.com/kms/)
    - KMS makes it easy for you to create and manage keys and control the use of encryption across a wide range of AWS services and in your applications. AWS KMS is a secure and resilient service that uses FIPS 140-2 validated hardware security modules to protect your keys
- **Security Hub** (https://aws.amazon.com/security-hub/)
    - Security Hub gives you a comprehensive view of your high-priority security alerts and compliance status across AWS accounts
- **ElasticSearch Service** (https://aws.amazon.com/elasticsearch-service/)
    -  Elasticsearch Service is a fully managed service that makes it easy for you to deploy, secure, and operate Elasticsearch at scale with zero down time. The service offers open-source Elasticsearch APIs, managed Kibana, and integrations with Logstash and other AWS Services, enabling you to securely ingest data from any source and search, analyze, and visualize it in real time.
- **Cognito** (https://aws.amazon.com/cognito/)
    - Cognito lets you add user sign-up, sign-in, and access control to your web and mobile apps quickly and easily. Amazon Cognito scales to millions of users and supports sign-in with social identity providers, such as Facebook, Google, and Amazon, and enterprise identity providers via SAML 2.0.
- **Glue** (https://aws.amazon.com/glue/)
    - AWS Glue is a fully managed extract, transform, and load (ETL) service that makes it easy for customers to prepare and load their data for analytics.
- **Kinesis Data Firehose** (https://aws.amazon.com/kinesis/data-firehose/)
    - Amazon Kinesis Data Firehose is the easiest way to reliably load streaming data into data stores and analytics tools. It can capture, transform, and load streaming data into Amazon S3, Amazon Redshift, Amazon Elasticsearch Service, and Splunk, enabling near real-time analytics with existing business intelligence tools and dashboards you’re already using today.
- **WAF** (https://aws.amazon.com/waf/)
    - AWS WAF is a web application firewall that helps protect your web applications from common web exploits that could affect application availability, compromise security, or consume excessive resources. AWS WAF gives you control over which traffic to allow or block to your web applications by defining customizable web security rules.
- **Systems Manager** (https://aws.amazon.com/systems-manager/)
    - Systems Manager simplifies resource and application management, shortens the time to detect and resolve operational problems, and makes it easy to operate and manage your infrastructure securely at scale.
- **Lambda** (https://aws.amazon.com/lambda/)
    - AWS Lambda automatically runs your code without requiring you to provision or manage servers. Just write the code and upload it to Lambda...it can be directly triggered by AWS services such as S3, DynamoDB, Kinesis, SNS, and CloudWatch...
- **Config** (https://aws.amazon.com/config/)
    - A service that enables you to assess, audit, and evaluate the configurations of your AWS resources
- **XRay** (https://aws.amazon.com/xray/)
    - X-Ray helps developers analyze and debug production, distributed applications, such as those built using a microservices architecture. With X-Ray, you can understand how your application and its underlying services are performing to identify and troubleshoot the root cause of performance issues and errors
- **CloudWatch Logs** (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)
    - Used to monitor, store, and access your log files from Amazon Elastic Compute Cloud (Amazon EC2) instances, AWS CloudTrail, Route 53, and other sources
- **CloudWatch Events** (https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html)
    - Amazon CloudWatch Events delivers a near real-time stream of system events that describe changes in Amazon Web Services (AWS) resources. Using simple rules that you can quickly set up, you can match events and route them to one or more target functions or streams.
- **CloudWatch Alarms** (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
    - You can create a CloudWatch alarm that watches a single CloudWatch metric or the result of a math expression based on CloudWatch metrics. The alarm performs one or more actions based on the value of the metric or expression relative to a threshold over a number of time periods. The action can be an Amazon EC2 action, an Amazon EC2 Auto Scaling action, or a notification sent to an Amazon SNS topic.
- **CloudTrail** (https://aws.amazon.com/cloudtrail/)
    - A service that enables governance, compliance, operational auditing, and risk auditing of your AWS account
- **VPC** (https://aws.amazon.com/vpc/)
    - Amazon Virtual Private Cloud (Amazon VPC) lets you provision a logically isolated section of the AWS Cloud where you can launch AWS resources in a virtual network that you define. You have complete control over your virtual networking environment, including selection of your own IP address range, creation of subnets, and configuration of route tables and network gateways. You can use both IPv4 and IPv6 in your VPC for secure and easy access to resources and applications.
- **PrivateLink** (https://aws.amazon.com/privatelink/)
    - AWS PrivateLink simplifies the security of data shared with cloud-based applications by eliminating the exposure of data to the public Internet. AWS PrivateLink provides private connectivity between VPCs, AWS services, and on-premises applications, securely on the Amazon network. AWS PrivateLink makes it easy to connect services across different accounts and VPCs to significantly simplify the network architecture.
- **IAM** (https://aws.amazon.com/iam/)
    - Enables you to manage access to AWS services and resources securely
- **Inspector** (https://aws.amazon.com/inspector/)
    - Automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Amazon Inspector automatically assesses applications for exposure, vulnerabilities, and deviations from best practices
- **SNS** (https://aws.amazon.com/sns/)
    - A highly available, durable, secure, fully managed pub/sub messaging service that enables you to decouple microservices, distributed systems, and serverless applications
- **S3** (https://aws.amazon.com/s3/)
    - An object storage service that offers industry-leading scalability, data availability, security, and performance. This means customers of all sizes and industries can use it to store and protect any amount of data for a range of use cases, such as websites, mobile applications, backup and restore, archive, enterprise applications, IoT devices, and big data analytics

### Prerequisites:
**Below Steps are Done on a Fresh Install of Ubuntu 18.04LTS**
**Refer to (https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent.html) for Information on how to Install the SSM Agent on Non-Amazon Linux / Ubuntu Distros**
1. Update Your System
`sudo apt update && sudo apt upgrade -y`
2. Download Latest Version of Inspector Agent (https://docs.aws.amazon.com/inspector/latest/userguide/inspector_installing-uninstalling-agents.html)
`wget https://inspector-agent.amazonaws.com/linux/latest/install`
3. Install Inspector Agent
`sudo bash install`
4. Install Unzip
`sudo apt-get install unzip`
5. Grab the Latest Version of Terraform (https://www.terraform.io/downloads.html)
`wget https://releases.hashicorp.com/terraform/0.11.13/terraform_0.11.13_linux_amd64.zip`
6. Unzip Terraform Installation
`unzip terraform_0.11.13_linux_amd64.zip`
7. Move to /local/bin - or you can add Terraform to your PATH
`sudo mv terraform /usr/local/bin/`
8. Ensure that Terraform is Installed Correctly
`terraform --version`
9. To use Systems Manager with your EC2 Instances, ensure your EC2 Instances have an Instance Profile that allows full access to SSM Attached to them (https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-configuring-access-role.html)

### Installing & Configuration
1. Create & Navigate to a New Directory
`mkdir aws-cmds && cd aws-cmds`
2. Clone this Repo
`git clone https://github.com/jonrau1/AWS-ComplianceMachineDontStop.git`
3. Add your Region to the *provider.tf* - **Ensure your EC2 Instance has an Instance Profile that allows permissions to deploy all CMDS Resources**
`nano provider.tf`
4. Fill out the *variables.tf* file
`nano variables.tf`
5. Ensure proper elements for your Region from *variables.tf* are Referenced in *data.tf*
`nano data.tf`
6. (Only if Using WAF) navigate to WAF Sub-Directory
`cd AWS WAF`
7. (Only if Using WAF) repeat steps 3-5 & modify Rules & IPs based on reccomendations from https://d0.awsstatic.com/whitepapers/Security/aws-waf-owasp.pdf
`nano waf.tf`
8. (Only if using VPC Module) fill out Variables -- make sure to specify Region as it is used by VPC Endpoints (PrivateLink)
`cd VPC Module` && `nano variables.tf`
9. (Only if using ElasticSearch Service Module) fill out Variables 
    - **WARNING: ES may take over an hour to deploy depending on how you modify the deployment**
`cd ElasticSearch Service` && `nano variables.tf`
#### !! Notes on `Variables.tf` !!
- There is a List Variable for Amazon Inspector ARNs for the Rules Packages within for US-EAST-1 and US-WEST-1 Regions, you will need to modify that whole list for regions outside of US-EAST-1/US-WEST-1 and modify the correct variable reference within `main.tf`
- You will also need to modify `data.tf` to use the populated `InspectorRemediationSNSTopicPolicyData_*` Variable for your Region within the Resource Element: `data "aws_iam_policy_document" "Inspector_Remediation_SNS_Topic_Policy_Data"`
- Ensure that the `PathToInspectorRemediationLambdaUpload` within `variables.tf` uses just the folder path, and does not refer to the ZIP File -- i.e. `default = "~/aws-cmds/functions/"`

### Deploying
1. Initialize your AWS Provider
`terraform init`
2. Create a Plan
`terraform plan`
3. Apply the Plan
`terraform apply`
4. Deploy
`yes`
5. Navigate to AWS Config Console & Finish Setup
    - Ensure you use your Created Role & Not the Service Linked Role
    - Navigate to Settings and then click Save for additional resources to be added into IAM Role Policy
6. Attach Remediation SNS Topic to your Inspector Assessment Target Group (Terraform does not yet support this)
    - Navigate to Inspector > Assessment Templates > <Your Assessment Template> > Manage SNS Topics > Select Your Remediation SNS Topic
    - Remove All Events *except* for `Findings Reported` & Save
7. Navigate to AWS Glue Console and Edit your Crawlers, go into the `Output` section > `Configuration Options` and check the box that says "Update all new and existing partitions with metadata from the table"
8. Ensure you CIS Compliance SNS Topic has a Subscriber that is confirmed (Email, SMS, etc) to ensure CIS Compliance checks for Metrics & Alarms Pass

### Out of Scope
- Macie -- Terraform currently does not support Activating Macie, only subscribing Buckets to Scan to Macie

## Next Steps
This Proof of Value is only a small step towards an excellent Security Posture for your AWS Accounts. A Multitude of other Security, Identity & Compliance solutions are available to complement the above deployed Services, such as Macie, SSO, Directory Services, ACM, Secrets Manager, Cognito and Firewall Manager. The proper privacy-by-design and security-by-design for Software Development, Application Lifecycle and Architecture must be also be followed to ensure a hardened state, which this PoV does not supply.

### Modifications to Deployment / Further Configuration
- Add AWS-Managed / Custom Config Rules to your AWS Config Setup
- Add Customer Providers into Security Hub / GuardDuty from Marketplace
- Ingest Data into ElasticSearch Service
    - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-aws-integrations.html
- Modify WAF IPSet Blacklist / Create WAF IPSet Whitelist
- Add Additional WAF Match Sets (Conditions)
- Apply WAF WACL to a CloudFront Distribution
- Write Athena SQL Queries against AWS Glue Database created for AWS WAF Logs & GuardDuty Findings
    - https://aws.amazon.com/blogs/security/how-to-visualize-amazon-guardduty-findings-serverless-edition/
- Perform data visualizations of AWS WAF logs using QuickSight
    - https://aws.amazon.com/blogs/security/enabling-serverless-security-analytics-using-aws-waf-full-logs/

### High-Level Reading
- https://aws.amazon.com/architecture/well-architected/
- https://aws.amazon.com/security/
- https://aws.amazon.com/blogs/security/ 
- https://docs.aws.amazon.com/aws-technical-content/latest/aws-governance-at-scale/introduction.html
- https://aws.amazon.com/compliance/hipaa-compliance/
- https://aws.amazon.com/compliance/pci-dss-level-1-faqs/
- https://aws.amazon.com/compliance/soc-faqs/
- https://aws.amazon.com/blogs/security/the-top-10-most-downloaded-aws-security-and-compliance-documents-in-2017/

### Security Whitepapers & Workbooks
- https://d1.awsstatic.com/whitepapers/compliance/AWS_Anitian_Workbook_PCI_Cloud_Compliance.pdf
- https://d1.awsstatic.com/whitepapers/compliance/AWS_HIPAA_Compliance_Whitepaper.pdf
- https://d0.awsstatic.com/whitepapers/Security/AWS_Security_Best_Practices.pdf
- https://d0.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf
- https://d0.awsstatic.com/whitepapers/Security/aws-waf-owasp.pdf
- https://d0.awsstatic.com/whitepapers/compliance/AWS_Risk_and_Compliance_Whitepaper.pdf
- https://d0.awsstatic.com/whitepapers/compliance/AWS_Auditing_Security_Checklist.pdf
- https://aws.amazon.com/blogs/security/new-whitepaper-achieving-operational-resilience-in-the-financial-sector-and-beyond/

### AWS Security Solutions & Reference Architecture
- https://aws.amazon.com/blogs/security/enabling-serverless-security-analytics-using-aws-waf-full-logs/
- https://aws.amazon.com/blogs/security/trimming-aws-waf-logs-with-amazon-kinesis-firehose-transformations/
- https://aws.amazon.com/blogs/security/how-to-visualize-amazon-guardduty-findings-serverless-edition/
- https://aws.amazon.com/blogs/security/how-to-visualize-and-refine-your-networks-security-by-adding-security-group-ids-to-your-vpc-flow-logs/
- https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-aws-web-application-firewall-to-automatically-block-suspicious-hosts/
- https://aws.amazon.com/blogs/security/how-to-remediate-amazon-inspector-security-findings-automatically/
- https://aws.amazon.com/blogs/security/how-to-set-up-continuous-golden-ami-vulnerability-assessments-with-amazon-inspector/?nc1=b_rp