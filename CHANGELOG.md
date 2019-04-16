# Change Log
- 22 FEB 2019: Basic Reference .tf Files Uploaded for Security Hub, GuardDuty and Inspector
- 6 MAR 2019: Released version 0.9 - Combined Files, Many Bugs
- 7 APR 2019: Released version 1.0 - Major Refactor & Break-Fixes for IAM Roles, Incorrect Interpolation Syntax; Added Support for data.tf and variables.tf
- 8 APR 2019: Update for version 1.0.1 - Added Support for Inspector Finding Remediation via Lambda/IAM Role/SNS; Refer to Readme for Manual Steps that must be Accomplished to use this Remediation Automation. 
- 9 APR 2019: Fixed Issue where Config could not access Encrypted SNS Topic & Refactored Policy to include AWS Managed Config Read-Only Role Policy. Added KMS Permissions to Lambdda Execution Role. Added Lambda, SNS, Config-specific IAM Entities to SNS Customer Manager CMK. Troubleshooting Security Hub CIS Compliance & Insights failing. Added template for Provider.TF w/ VAR for Access Key & Secret Key interpolated through a Sample Terraform.tfvars file
- 15 APR 2019: Added Support for AWS WAF, placed files into their own sub-directory to be used as a Module, or deployed from within. Currently has an IP Set Blacklist based on the Author's own Threat Intelligence findings, as well as reccomendations for Match Sets from the Whitepaper "Use AWS WAF to Mitigate OWASP’s Top 10 Web Application Vulnerabilities" Whitepaper (link way below) for XSS, SQLi, and Size Constraint.
- 15 APR 2019 (Late): Removed Lambda & Inspector from SNS KMS Customer CMK, Removed Extra Lambda KMS Policy, Added defualt AWS KMS key for SNS
- 16 APR 2019: Removed SNS Encryption for Remediation SNS Topic for Inspector
