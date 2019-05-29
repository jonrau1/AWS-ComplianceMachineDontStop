## Enables a GuardDuty Detector in your Region Specified by Provider.tf
resource "aws_guardduty_detector" "GuardDuty_Detector" {
  enable = true
  finding_publishing_frequency = "${var.GuardDuty_Finding_Publishing_Frequency}"
}
## Creates a CMK to use for Encrypting CloudTrail Logs
resource "aws_kms_key" "CloudTrail_Customer_CMK" {
  description             = "CloudTrail Encryption - Managed by Terraform"
  deletion_window_in_days = "${var.CloudTrail_CMK_Deletion_Window}"
  enable_key_rotation     = true
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "Key policy created by CloudTrail",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": [
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${aws_iam_user.KMS_Key_Admin_IAM_User.name}" 
            ]},
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
            "Action": "kms:GenerateDataKey*",
            "Resource": "*",
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}}
        },
        {
            "Sid": "Allow CloudTrail to describe key",
            "Effect": "Allow",
            "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
            "Action": "kms:DescribeKey",
            "Resource": "*"
        },
        {
            "Sid": "Allow principals in the account to decrypt log files",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}
            }
        },
        {
            "Sid": "Allow alias creation during setup",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "kms:CreateAlias",
            "Resource": "*",
            "Condition": {"StringEquals": {
                "kms:ViaService": "ec2.region.amazonaws.com",
                "kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"
            }}
        },
        {
            "Sid": "Enable cross account log decryption",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}
            }
        }
    ]
}
POLICY
}
## Creates a KMS Key for using to Encrypt AWS Config Recordings sent to SNS
resource "aws_kms_key" "Config_Recorder_SNS_Customer_CMK" {
  description             = "Encrypt AWS Config Recordings sent to SNS - Manged by Terraform"
  deletion_window_in_days = "${var.Config_Recorder_SNS_Customer_CMK_Deletion_Window}"
  enable_key_rotation     = true
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "key-consolepolicy-3",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow access for Key Administrators",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${aws_iam_user.KMS_Key_Admin_IAM_User.name}"
                ]
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow config access",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${aws_iam_role.Config_IAM_Role.arn}"
            },
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:Encrypt",
                "kms:Describe",
                "kms:Get*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow sns access",
            "Effect": "Allow",
            "Principal": {
                "Service": "sns.amazonaws.com"
            },
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey*",
                "kms:Describe",
                "kms:Get*",
                "kms:Encrypt"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}
resource "aws_kms_alias" "CloudTrail_Key_Alias" {
  name          = "alias/${var.CloudTrail_Key_Alias_Name}"
  target_key_id = "${aws_kms_key.CloudTrail_Customer_CMK.arn}"
}
resource "aws_kms_alias" "Config_SNS_Key_Alias" {
  name          = "alias/${var.Config_SNS_Key_Alias_Name}"
  target_key_id = "${aws_kms_key.Config_Recorder_SNS_Customer_CMK.arn}"
}
## not specifiying 'resource_group_arn' in Assessment Target will apply to all EC2 Instances w/ Inspector Agent for
resource "aws_inspector_assessment_target" "Inspector_Assessment_Target_All" {
  name = "${var.Inspector_Assessment_Target_All_Group_Name}"
}
## Uses LIST Variables for Rule Packages
resource "aws_inspector_assessment_template" "Inspector_Assessment_Template" {
  name               = "${var.Inspector_Assessment_Template_Name}"
  target_arn         = "${aws_inspector_assessment_target.Inspector_Assessment_Target_All.arn}"
  duration           = 3600
  rules_package_arns = "${var.Inspector_Assessment_Rules_Packages_USEast1}"
}
## Creates S3 Bucket to upload Lambda Function ZIPs into for later usage
## Bucket is Versioned, Logged via CT, Logged for HTTP Access Logs and Uses SSE-S3 Encryption
resource "aws_s3_bucket" "Lambda_Artifacts_S3_Bucket" {
  bucket = "${var.Lambda_Artifacts_S3_Bucket_Name}"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
    target_prefix = "LambdaAccess/"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
## Uploads the GuardDuty Log Parsing Lambda Function to the Created S3 Bucket
resource "aws_s3_bucket_object" "GuardDuty_Log_Parsing_Lambda_Object_Upload" {
  bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  key    = "CMDS-Lambdas/gd-sorter.zip"
  source = "${var.Path_To_Lambda_Upload}/gd-sorter.zip"
}
## Creates Lambda Function to Parse out GuardDuty Findings for crawling with Glue & Querying with Athena
## X-Ray Tracing is Enabled to get Traces for Debug & APM
resource "aws_lambda_function" "Lambda_Function_GuardDuty_Log_Parsing" {
  s3_bucket        = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  s3_key           = "${aws_s3_bucket_object.GuardDuty_Log_Parsing_Lambda_Object_Upload.id}"
  function_name    = "${var.GuardDuty_LogParsing_Function_Name}"
  description      = "Lambda Function to Parse out Findings from GuardDuty for eventual consumption by Glue"
  role             = "${aws_iam_role.Lambda_Function_GuardDuty_Log_Parsing_IAM_Role.arn}"
  handler          = "gd-sorter.lambda_handler"
  runtime          = "python3.6"
  memory_size      = "${var.GuardDuty_LogParsing_FunctionMemory}"
  timeout          = "${var.GuardDuty_LogParsing_FunctionTimeout}"
  tracing_config {
    mode = "Active"
  }
}
## Lambda Execution Role for GuardDuty Parsing Function
resource "aws_iam_role" "Lambda_Function_GuardDuty_Log_Parsing_IAM_Role" {
  name = "${var.GuardDuty_LogParsing_Function_Name}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "GDLogParsing_Lambda_Attach_LambdaExecute" {
  role       = "${aws_iam_role.Lambda_Function_GuardDuty_Log_Parsing_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSLambdaExecute.arn}"
}
resource "aws_iam_role_policy_attachment" "GDLogParsing_Lambda_Attach_AWSXrayWriteOnlyAccess" {
  role       = "${aws_iam_role.Lambda_Function_GuardDuty_Log_Parsing_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSXrayWriteOnlyAccess.arn}"
}
## Allows Source Invocation from S3 to fire off GuardDuty Parsing Function
resource "aws_lambda_permission" "GuardDuty_Lambda_Bucket_Invocation_Permission" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Lambda_Function_GuardDuty_Log_Parsing.arn}"
  principal     = "s3.amazonaws.com"
  source_arn    = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}"
}
## Uploads the Inspector auto remediation Lambda file into S3
resource "aws_s3_bucket_object" "Inspector_Remediation_Lambda_Object_Upload" {
  bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  key    = "CMDS-Lambdas/lambda-auto-remediate.zip"
  source = "${var.Path_To_Lambda_Upload}/lambda-auto-remediate.zip"
}
## Creates a Lambda function that is invoked from SNS to call Systems Manager Run Command to run updates on Debian and Amazon Linux based instances
## SNS Topic will be configured from the Inspector end (not yet supported via Terraform) to emit on Findings to invoke the function
## The Function will invoke multiple times per function hence the high memory & timeout
## Systems Manager Run Command log outputs will show multiple failures (false negative) due to the concurrency limitations
resource "aws_lambda_function" "Lambda_Function_Inspector_Remediation" {
  s3_bucket        = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  s3_key           = "${aws_s3_bucket_object.Inspector_Remediation_Lambda_Object_Upload.id}"
  function_name    = "${var.Inspector_Remediation_Function_Name}"
  description      = "Invokes SSM Run Command based on Inspector Findings from SNS"
  role             = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.arn}"
  handler          = "lambda-auto-remediate.lambda_handler"
  runtime          = "python2.7"
  memory_size      = "${var.Inspector_Remediation_Function_Memory}"
  timeout          = "${var.Inspector_Remediation_Function_Timeout}"
  tracing_config {
    mode = "Active"
  }
}
resource "aws_iam_role" "Lambda_Function_Inspector_Remediation_IAMRole" {
  name = "${var.Inspector_Remediation_Function_Name}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "Remediation_Lambda_Attach_InspectorRO" {
  role       = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AmazonInspectorReadOnlyAccess.arn}"
}
resource "aws_iam_role_policy_attachment" "Remediation_Lambda_Attach_SSMFullAccess" {
  role       = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AmazonSSMFullAccess.arn}"
}
resource "aws_iam_role_policy_attachment" "Remediation_Lambda_Attach_AWSXrayWriteOnlyAccess" {
  role       = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSXrayWriteOnlyAccess.arn}"
}
resource "aws_iam_role_policy_attachment" "Remediation_Lambda_Attach_BasicLambdaExec" {
  role       = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSLambdaBasicExecutionRole.arn}"
}
## SNS Topic that you will subscribed SNS to -- the Policy is created in an external Data document
## You can optionally add encryption to this SNS topic
resource "aws_sns_topic" "Inspector_Remediation_SNS_Topic" {
  name = "${var.Inspector_Remediation_SNS_Topic_Name}"
}
## Within the Data Policy a Variable is passed for the ROOT Principal for the Inspector Service
## Inspector's Service Account will emit the findings based on telemetry and needs Access to publish
resource "aws_sns_topic_policy" "Inspector_Remediation_SNS_Topic_Policy" {
  arn    = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
  policy = "${data.aws_iam_policy_document.Inspector_Remediation_SNS_Topic_Policy_Data.json}"
}
## Gives SNS permission to invoke the Vulnerability Patching Function
resource "aws_lambda_permission" "Inspector_Remediation_SNS_Lambda_Permission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Lambda_Function_Inspector_Remediation.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
}
## Subs Lambda to the SNS policy to get invoked
resource "aws_sns_topic_subscription" "Inspector_Remediation_SNS_Subscription" {
  topic_arn = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.Lambda_Function_Inspector_Remediation.arn}"
}
## Creates an AWS Config Configuration Recorder -- this is a Regional resource and config must not have been enabled
## Recording Group configuration will support all resoruces types to include IAM policies, roles, etc
## The Name is actually abstracted from the user, it is only used by the API, will be "default" if not
resource "aws_config_configuration_recorder" "Config_Configuration_Recorder" {
  name     = "${var.Config_Configuration_Recorder_Name}"
  role_arn = "${aws_iam_role.Config_IAM_Role.arn}"

  recording_group = {
    all_supported                 = true
    include_global_resource_types = true
  }
}
## Delivery Channel allows Config to emit Configuration History & State to S3
## SNS is optional but you can subscribe downstream services such as Lambda to it
resource "aws_config_delivery_channel" "Config_Configuration_Delivery_Channel" {
  name           = "${var.Config_Configuration_Delivery_Channel_Name}"
  s3_bucket_name = "${aws_s3_bucket.Config_Artifacts_S3_Bucket.bucket}"
  sns_topic_arn  = "${aws_sns_topic.Config_SNS_Topic.id}"
}
## This Terraform Resource will turn the Configuration Recorder "on"
## Depends_On is passed to avoid a race condition
resource "aws_config_configuration_recorder_status" "Config_Configuration_Recorder_Status" {
  name       = "${aws_config_configuration_recorder.Config_Configuration_Recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.Config_Configuration_Delivery_Channel"]
}
## Config will publish near real time Configuration changes into SNS
## This SNS topic is encrypted via the KMS key set earlier -- any downstream services will also need access to it
resource "aws_sns_topic" "Config_SNS_Topic" {
  name              = "${var.Config_SNS_Topic_Name}"
  kms_master_key_id = "${aws_kms_key.Config_Recorder_SNS_Customer_CMK.id}"
  policy = <<POLICY
{
  "Id": "Policy_ID",
  "Statement": [
    {
      "Sid": "AWSConfigSNSPolicy",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.Config_IAM_Role.arn}"
      },
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns::${data.aws_caller_identity.current.account_id}:${var.Config_SNS_Topic_Name}"
    }
  ]
}
POLICY
}
## This is the S3 Bucket that Config will send the Config State files into
resource "aws_s3_bucket" "Config_Artifacts_S3_Bucket" { 
  bucket = "${var.Config_Artifacts_S3_Bucket_Name}"
  acl    = "private"

  versioning {
      enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
    target_prefix = "configaccess/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
## sts Assume Role for config -- attaching the default config service policy via Data resoruce
resource "aws_iam_role" "Config_IAM_Role" {
  name = "${var.Config_Configuration_Recorder_Name}-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "thisissid028129128"
    }
  ]
}
POLICY
}
resource "aws_iam_role_policy_attachment" "Config_Role_Managed_Policy_Attachment" {
  role       = "${aws_iam_role.Config_IAM_Role.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSConfigRole.arn}"
}
## Policy is needed for the Delivery Channel -- gives access to the Config S3 Bucket & SNS Topic
resource "aws_iam_role_policy" "Config_Role_Policy" {
  name   = "${var.Config_Configuration_Recorder_Name}-policy"
  role   = "${aws_iam_role.Config_IAM_Role.id}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1554678006121",
      "Action": "s3:*",
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.Config_Artifacts_S3_Bucket.arn}",
        "${aws_s3_bucket.Config_Artifacts_S3_Bucket.arn}/*"
      ]
    },
    {
      "Sid": "Stmt1554678078717",
      "Action": [
        "sns:Publish"
      ],
      "Effect": "Allow",
      "Resource": "${aws_sns_topic.Config_SNS_Topic.id}"
    }   
  ]
}
POLICY
}
## This S3 Bucket will collect HTTP Access Logs from all other defined S3 Buckets
## Do not set access logging on itself otherwise you will have a large (and expensive) volume of logs in your bucket
resource "aws_s3_bucket" "Server_Access_Log_S3_Bucket" {
  bucket = "${var.Server_Access_Log_S3_Bucket_Name}"
  acl    = "log-delivery-write"

  versioning {
      enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
## No arguments are support for the Security Hub account -- Terraform simply calls the API to enable it
## Config Recorder & Delivery Channel needs to be present in the account before Security Hub can be enabled programmatically
resource "aws_securityhub_account" "Security_Hub_Enabled" {}
## This SNS Topic is where the CloudWatch Alarms will publish their findings to regarding the CIS AWS Benchmarks rules defined by Config
## Both the Metric Filter & Alarms plus a subscribed-to SNS Topic are needed to achieve compliance
## CIS_Compliance_ prefixes for Terraform Resource names will be referenced multiple times -- this was the basis behind the ComplianceMachineDon'tStop project
## It is also encrypted by the Config SNS Key -- despite the name (Would be confusing either way since not all SNS topics in this file are encrypted)
resource "aws_sns_topic" "CIS_Compliance_Alerts_SNS_Topic" {
  name              = "${var.CIS_Compliance_Alerts_SNS_Topic_Name}"
  kms_master_key_id = "${aws_kms_key.Config_Recorder_SNS_Customer_CMK.id}" 
}
## This CloudWatch Logs Group is for CloudTrail to publish API Logs too, it is also called CIS Compliance since that is another CIS Benchmark
## It actually makes up 4 checks -- Encrypted, Logged, Validated, Global
resource "aws_cloudwatch_log_group" "CIS_Compliance_CloudWatch_LogsGroup" {
  name = "${var.CIS_Compliance_CloudWatch_LogsGroup_Name}"
}
resource "aws_iam_role" "CloudWatch_LogsGroup_IAM_Role" {
  name = "${var.CIS_Compliance_CloudWatch_LogsGroup_Name}-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "CIS_Compliance_CloudWatch_LogsGroup_Policy" {
  name   = "${var.CIS_Compliance_CloudWatch_LogsGroup_Name}-policy"
  role   = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.arn}*"
    }
  ]
}
EOF
}
## This CloudTrail Trail is called CIS Compliance as it was made with the Security Hub CIS benchmarks in mind
## This Trail is Global (multi-regional) and has encrypion, validation and CloudWatch delivery configured to be in Compliance
## This Trail also logs all Object-level Data Events for Lambda & S3 for enhanced auditing capabilities
resource "aws_cloudtrail" "CIS_Compliance_CloudTrail_Trail" { 
  name                          = "${var.CIS_Compliance_CloudTrail_Trail_Name}" 
  s3_bucket_name                = "${aws_s3_bucket.CIS_Compliance_CloudTrail_Logs_S3_Bucket.id}"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "${aws_kms_key.CloudTrail_Customer_CMK.arn}"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.arn}"
  cloud_watch_logs_role_arn     = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}
## CloudTrail at a minimum needs a S3 bucket to set the API Logs too
## The default created CloudTrail Bucket Policy is attached in-line of this Resource
resource "aws_s3_bucket" "CIS_Compliance_CloudTrail_Logs_S3_Bucket" {  
  bucket = "${var.CIS_Compliance_CloudTrail_Logs_S3_Bucket_Name}" 
  acl = "private"

  versioning {
      enabled = true
  }
  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
    target_prefix = "cloudtrailaccess/"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.CIS_Compliance_CloudTrail_Logs_S3_Bucket_Name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.CIS_Compliance_CloudTrail_Logs_S3_Bucket_Name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}
## These next resources are the CloudWatch Log Metric Filter & associated Alarms to be in compliance with CIS Benchmarks
resource "aws_cloudwatch_log_metric_filter" "CIS_Unauthorized_API_Calls_Metric_Filter" {
  name           = "CIS-UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-UnauthorizedAPICalls"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_Unauthorized_API_Calls_CW_Alarm" {
  alarm_name                = "CIS-3.1-UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Unauthorized_API_Calls_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_No_MFA_Console_Signin_Metric_Filter" {
  name           = "CIS-ConsoleSigninWithoutMFA"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-ConsoleSigninWithoutMFA"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_No_MFA_Console_Signin_CW_Alarm" {
  alarm_name                = "CIS-3.2-ConsoleSigninWithoutMFA"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_No_MFA_Console_Signin_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "CIS_Root_Account_Use_Metric_Filter" {
  name           = "CIS-RootAccountUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-RootAccountUsage"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_Root_Account_Use_CW_Alarm" {
  alarm_name                = "CIS-3.3-RootAccountUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Root_Account_Use_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_IAM_Policy_Change_Metric_Filter" {
  name           = "CIS-IAMPolicyChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-IAMPolicyChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_IAM_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.4-IAMPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_IAM_Policy_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_CloudTrail_Config_Change_Metric_Filter" {
  name           = "CIS-CloudTrailChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-CloudTrailChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_CloudTrail_Config_Change_CW_Alarm" {
  alarm_name                = "CIS-3.5-CloudTrailChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_CloudTrail_Config_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Console_AuthN_Failure_Metric_Filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Console_AuthN_Failure_CW_Alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Console_AuthN_Failure_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Disable_Or_Delete_CMK_Metric_Filter" {
  name           = "CIS-DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-DisableOrDeleteCMK"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Disable_Or_Delete_CMK_CW_Alarm" {
  alarm_name                = "CIS-3.7-DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Disable_Or_Delete_CMK_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_S3_Bucket_Policy_Change_Metric_Filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_S3_Bucket_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_S3_Bucket_Policy_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_AWS_Config_Change_Metric_Filter" {
  name           = "CIS-AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-AWSConfigChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_AWS_Config_Change_CW_Alarm" {
  alarm_name                = "CIS-3.9-AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_AWS_Config_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Security_Group_Changes_Metric_Filter" {
  name           = "CIS-SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-SecurityGroupChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Security_Group_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.10-SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Security_Group_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Network_ACL_Changes_Metric_Filter" {
  name           = "CIS-NetworkACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-NetworkACLChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Network_ACL_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.11-NetworkACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Network_ACL_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Network_Gateway_Changes_Metric_Filter" {
  name           = "CIS-NetworkGatewayChanges"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-NetworkGatewayChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Network_Gateway_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.12-NetworkGatewayChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Network_Gateway_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Route_Table_Changes_Metric_Filter" {
  name           = "CIS-RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-RouteTableChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Route_Table_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.13-RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Route_Table_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_VPC_Changes_Metric_Filter" {
  name           = "CIS-VPCChanges"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = "${aws_cloudwatch_log_group.CISComplianceCloudWatchLogsGroupName.name}"

  metric_transformation {
    name      = "CIS-VPCChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_VPC_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.14-VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_VPC_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.CIS_Compliance_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
## This is the end of the CIS Compliance Cloudwatch Alarms & Metric Filters section

## A crypto-office Group and associated IAM entities (policy, users, etc) were created to add something other than Root into the Key Adminstrators for the CMKs
## It is not in good practice to rely on Root for high level administrative tasks -- and key adminstration should be led by a crypto officer of some sort anyway
## If you know the term COMSEC Custodian -- this is essentially what it is
resource "aws_iam_group" "KMS_Key_Admin_IAM_Group" {
  name = "${var.KMS_Key_Admin_IAM_Group_Name}"
}
resource "aws_iam_policy" "KMS_Key_Admin_IAM_Policy" {
  name        = "${var.KMS_Key_Admin_IAM_Group_Name}-policy"
  path        = "/"
  description = "Allows Admin Privs for KMS to the KMS Key Admin Group - Managed by Terraform"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}
EOF
}
resource "aws_iam_user" "KMS_Key_Admin_IAM_User" {
  name = "${var.KMS_Key_Admin_IAM_User_Name}"
}
resource "aws_iam_group_policy_attachment" "KMS_Key_Admin_Group_IAM_Policy_Attachment" {
  group      = "${aws_iam_group.KMS_Key_Admin_IAM_Group.name}"
  policy_arn = "${aws_iam_policy.KMS_Key_Admin_IAM_Policy.arn}"
}
resource "aws_iam_group_membership" "KMS_Key_Admin_IAM_Group_Membership" {
  name = "${var.KMS_Key_Admin_IAM_User_Name}-membership"

  users = ["${aws_iam_user.KMS_Key_Admin_IAM_User.name}"]

  group = "${aws_iam_group.KMS_Key_Admin_IAM_Group.name}"
}
## This KDF Stream is where you will send your CloudWatch Event-parsed GuardDuty findings into
## The Stream will drop the findings into S3 which you will crawl with Glue, Query with Athena and Visualize with QuickSight
## This was inspired by serverless findings AWS Security Blog Posts
## You will need to write the Athena queries and setup QuickSight on your own as they are not supported by Terraform
resource "aws_kinesis_firehose_delivery_stream" "GuardDuty_Finding_KDF_Delivery_Stream" {
  name        = "${var.GuardDuty_Finding_KDF_Delivery_Stream_Name}"
  destination = "extended_s3"
  extended_s3_configuration {
    prefix          = "raw/firehose/"
    role_arn        = "${aws_iam_role.GuardDuty_Finding_KDF_Delivery_Stream_Role.arn}"
    bucket_arn      = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}"
    buffer_size     = "${var.GuardDutyFindingKDFDeliveryStream_BufferSize}"
    buffer_interval = "${var.GuardDutyFindingKDFDeliveryStream_BufferInterval}"
  }
}
## Bucket where KDF will shoot GuardDuty findings into
resource "aws_s3_bucket" "GuardDuty_Finding_KDF_Logs_Bucket" {
  bucket = "${var.GuardDuty_Finding_KDF_Delivery_Stream}-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
    target_prefix = "guarddutyfindingaccess/"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
resource "aws_iam_role" "GuardDuty_Finding_KDF_Delivery_Stream_Role" {
  name = "${var.GuardDuty_Finding_KDF_Delivery_Stream}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_policy" "GuardDuty_Finding_KDF_Delivery_Stream_Role_Policy" {
  name        = "${var.GuardDuty_Finding_KDF_Delivery_Stream}-policy"
  path        = "/"
  description = "Gives Firehose access to S3 Bucket - Managed by Terraform"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1555544710122",
      "Action": [
        "s3:AbortMultipartUpload",        
        "s3:GetBucketLocation",        
        "s3:GetObject",        
        "s3:ListBucket",        
        "s3:ListBucketMultipartUploads",        
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}",
        "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}/*"
      ]
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "GuardDuty_Finding_Stream_Role_Attachment" {
  role       = "${aws_iam_role.GuardDuty_Finding_KDF_Delivery_Stream_Role.name}"
  policy_arn = "${aws_iam_policy.GuardDuty_Finding_KDF_Delivery_Stream_Role_Policy.arn}"
}
## This CloudWatch Rue will take any GuardDuty Finding and send it to KDF
## You can further scope down the syntax to specify certain findings and also send them to other places
resource "aws_cloudwatch_event_rule" "GuardDuty_Finding_CloudWatch_Event_Rule" {
  name          = "${var.GuardDuty_Finding_CloudWatch_Event_Rule_Name}"
  description   = "Places GuardDuty findings into a KDF Delivery Stream - Managed by Terraform"
  event_pattern = <<PATTERN
{
  "source": [
    "aws.guardduty"
  ],
  "detail-type": [
    "GuardDuty Finding"
  ]
}
PATTERN
}
resource "aws_iam_role" "GuardDuty_Finding_CWEtoKDF_Role" {
  name = "${var.GuardDuty_Finding_CWEtoKDF_Role_Name}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
## Findings can either be placed as a single record or as a batch -- KDF automatically handles Sharding -- hence all that you need to specify is buffering
resource "aws_iam_policy" "GuardDuty_Finding_CWEtoKDF_Role_Policy" {
  name        = "${var.GuardDuty_Finding_CWEtoKDF_Role_Name}-policy"
  path        = "/"
  description = "Allows CWE to place records into a KDF Stream - Managed by Terraform"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "firehose:PutRecord",
                "firehose:PutRecordBatch"
            ],
            "Resource": [
                "${aws_kinesis_firehose_delivery_stream.GuardDuty_Finding_KDF_Delivery_Stream.arn}"
            ]
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "GuardDuty_Finding_CWEtoKDF_Policy_Attachment" {
  role       = "${aws_iam_role.GuardDuty_Finding_CWEtoKDF_Role.name}"
  policy_arn = "${aws_iam_policy.GuardDuty_Finding_CWEtoKDF_Role_Policy.arn}"
}
## In the Console, you would Choose the target as you create the Event Rule -- Terraform needs to make a separate API call for this action
resource "aws_cloudwatch_event_target" "GuardDuty_Finding_CloudWatch_Event_KDF_Target" {
  rule      = "${aws_cloudwatch_event_rule.GuardDuty_Finding_CloudWatch_Event_Rule.name}"
  arn       = "${aws_kinesis_firehose_delivery_stream.GuardDuty_Finding_KDF_Delivery_Stream.arn}"
  role_arn  = "${aws_iam_role.GuardDuty_Finding_CWEtoKDF_Role.arn}"
}
## This is an S3 Bucket Event -- anytime an object is placed within the prefix path (raw/firehose/) it will invoke the Lambda function
## I grouped the Lambdas together -- hence why the S3 Permission and the rest of the function is further up in this file
resource "aws_s3_bucket_notification" "GuardDuty_Finding_KDF_LogBucket_Object_Event" {
  bucket = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.id}"
  lambda_function {
    lambda_function_arn = "${aws_lambda_function.Lambda_Function_GuardDuty_Log_Parsing.arn}"
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "raw/firehose/"
  }
}
## Providers a Glue Catalog Database -- this is where the Crawler will partition out what it pulled from the Logs
## This Data Catalog is also what will be reference when you write you SQL Queries in Athena
resource "aws_glue_catalog_database" "GuardDuty_Findings_Parsed_DataCatalogDB" {
  name = "${var.GuardDuty_Findings_Parsed_DataCatalogDB_Name}"
}
## this Crawler runs on a Cron Expression every 15 Minutes to crawl and partition out the emitted Sorted Logs from the GD Findings Lambda
## The Lambda function automatically changes the Path of its relationalized data it is fed from KDF
## You can set the Cron to a much lower setting depending on the amount (lack of) GD Findings you may have
## Also ensure that you go into this Crawler in the Console and select "Update Metadata" options in the schema change behavior
## Underneath Glue & Athena is Apache HIVE (And some other MapReduce services) that will take a large crap on you if the metadata tables arent updated
resource "aws_glue_crawler" "GuardDuty_Findings_Parsed_Glue_Crawler" {
  name          = "${var.GuardDuty_Findings_Parsed_Glue_Crawler_Name}"
  database_name = "${aws_glue_catalog_database.GuardDuty_Findings_Parsed_DataCatalogDB.name}"
  role          = "${aws_iam_role.GuardDuty_Findings_Parsed_Glue_Crawler_Role.arn}"
  schedule      = "cron(0/15 * * * ? *)"
  schema_change_policy {
      update_behavior = "UPDATE_IN_DATABASE"
  }
  s3_target {
    path = "s3://${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.bucket}/raw/by_finding_type/"
  }
}
resource "aws_iam_role" "GuardDuty_Findings_Parsed_Glue_Crawler_Role" {
  name = "${var.GuardDuty_Findings_Parsed_Glue_Crawler_Name}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "glue.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_policy" "GuardDuty_Findings_Parsed_Glue_Crawler_Role_S3Policy" {
  name        = "${var.GuardDuty_Findings_Parsed_Glue_Crawler_Name}-policy"
  path        = "/"
  description = "Allows Glue to Retrieve and Send Objects from S3 - Managed by Terraform"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": [
                "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}/*"
            ]
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "GuardDuty_Findings_Parsed_Glue_Crawler_Role_ServicePolicy_Attachment" {
  role       = "${aws_iam_role.GuardDuty_Findings_Parsed_Glue_Crawler_Role.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSGlueServiceRole.arn}"
}
resource "aws_iam_role_policy_attachment" "GuardDuty_Findings_Parsed_Glue_Crawler_Role_S3Policy_Attachment" {
  role       = "${aws_iam_role.GuardDuty_Findings_Parsed_Glue_Crawler_Role.name}"
  policy_arn = "${aws_iam_policy.GuardDuty_Findings_Parsed_Glue_Crawler_Role_S3Policy.arn}"
}