resource "aws_guardduty_detector" "GuardDuty_Detector" {
  enable = true
  finding_publishing_frequency = "${var.GuardDutyPublishingFrequency}"
}
resource "aws_kms_key" "CloudTrail_Customer_CMK" {
  description             = "${var.CloudTrailCMKDescription}"
  deletion_window_in_days = "${var.CloudTrailCMKDeletionWindow}"
  enable_key_rotation = true
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
resource "aws_kms_key" "SNS_Customer_CMK" {
  description             = "${var.SNSCMKDescription}"
  deletion_window_in_days = "${var.SNSCMKDeletionWindow}"
  enable_key_rotation = true
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

resource "aws_kms_alias" "Trail_Key_Alias" {
  name          = "${var.CloudTrailKeyAlias}"
  target_key_id = "${aws_kms_key.CloudTrail_Customer_CMK.arn}"
}
resource "aws_kms_alias" "SNS_Key_Alias" {
  name          = "${var.SNSKeyAlias}"
  target_key_id = "${aws_kms_key.SNS_Customer_CMK.arn}"
}
resource "aws_inspector_resource_group" "Inspector_Resource_Group" {
  tags = {
    Name = "${var.InspectorResourceGroupNameTag}"
  }
}
resource "aws_inspector_assessment_target" "Inspector_Assessment_Target_All" {
  name               = "${var.InspectorTargetGroupName}"
}
// not specifiying 'resource_group_arn' will apply to all EC2 w/ Inspector Agent
resource "aws_inspector_assessment_template" "Inspector_Assessment_Template" {
  name       = "${var.InspectorAssessmentTemplateName}"
  target_arn = "${aws_inspector_assessment_target.Inspector_Assessment_Target_All.arn}"
  duration   = 3600

  rules_package_arns = "${var.InspectorAssessmentRulesPackages_USEast1}"
}
resource "aws_s3_bucket" "Lambda_Artifacts_S3_Bucket" {
  bucket = "${var.LambdaArtifactBucketName}"
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
resource "aws_s3_bucket_object" "GuardDuty_Log_Parsing_Lambda_Object_Upload" {
  bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  key    = "${var.LambdaUploadPrefix}/gd-sorter.zip"
  source = "${var.PathToLambdaUpload}/gd-sorter.zip"
}
resource "aws_lambda_function" "Lambda_Function_GuardDuty_Log_Parsing" {
  s3_bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  s3_key = "${aws_s3_bucket_object.GuardDuty_Log_Parsing_Lambda_Object_Upload.id}"
  function_name    = "${var.GuardDutyLogParsingFunctionName}"
  description      = "${var.GuardDutyLogParsingFunctionDescription}"
  role             = "${aws_iam_role.Lambda_Function_GuardDuty_Log_Parsing_IAMRole.arn}"
  handler          = "gd-sorter.lambda_handler"
  runtime          = "python3.6"
  memory_size      = "${var.GuardDutyLogParsingFunctionMemory}"
  timeout          = "${var.GuardDutyLogParsingFunctionTimeout}"
}
resource "aws_iam_role" "Lambda_Function_GuardDuty_Log_Parsing_IAMRole" {
  name = "${var.GuardDutyLogParsingFunctionRoleName}"
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
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Lambda_Function_GuardDuty_Log_Parsing.arn}"
  principal     = "s3.amazonaws.com"
  source_arn    = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}"
}
resource "aws_s3_bucket_object" "Inspector_Remediation_Lambda_Object_Upload" {
  bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  key    = "${var.LambdaUploadPrefix}/lambda-auto-remediate.zip"
  source = "${var.PathToLambdaUpload}/lambda-auto-remediate.zip"
}
resource "aws_lambda_function" "Lambda_Function_Inspector_Remediation" {
  s3_bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  s3_key = "${aws_s3_bucket_object.Inspector_Remediation_Lambda_Object_Upload.id}"
  function_name    = "${var.InspectorRemediationFunctionName}"
  description      = "${var.InspectorRemediationFunctionDescription}"
  role             = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.arn}"
  handler          = "lambda-auto-remediate.lambda_handler"
  runtime          = "python2.7"
  memory_size      = "${var.InspectorRemediationFunctionMemory}"
  timeout          = "${var.InspectorRemediationFunctionTimeout}"
}
resource "aws_iam_role" "Lambda_Function_Inspector_Remediation_IAMRole" {
  name = "${var.LambdaFunctionInspectorRemediationRoleName}"
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
resource "aws_iam_role_policy_attachment" "Remediation_Lambda_Attach_BasicLambdaExec" {
  role       = "${aws_iam_role.Lambda_Function_Inspector_Remediation_IAMRole.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSLambdaBasicExecutionRole.arn}"
}
resource "aws_sns_topic" "Inspector_Remediation_SNS_Topic" {
  name = "${var.InspectorRemediationSNSTopicName}"
}
resource "aws_sns_topic_policy" "Inspector_Remediation_SNS_Topic_Policy" {
  arn = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
  policy = "${data.aws_iam_policy_document.Inspector_Remediation_SNS_Topic_Policy_Data.json}"
}
resource "aws_lambda_permission" "Inspector_Remediation_SNS_Lambda_Permission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Lambda_Function_Inspector_Remediation.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
}
resource "aws_sns_topic_subscription" "Inspector_Remediation_SNS_Subscription" {
  topic_arn = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.Lambda_Function_Inspector_Remediation.arn}"
}
resource "aws_config_configuration_recorder" "Config_Configuration_Recorder" {
  name     = "${var.ConfigurationRecorderName}"
  role_arn = "${aws_iam_role.Config_IAM_Role.arn}"

  recording_group = {
    all_supported                 = true
    include_global_resource_types = true
  }
}
resource "aws_config_delivery_channel" "Config_Configuration_Delivery_Channel" {
  name           = "${var.ConfigurationDeliveryChannelName}"
  s3_bucket_name = "${aws_s3_bucket.Config_Artifacts_S3_Bucket.bucket}"
  sns_topic_arn = "${aws_sns_topic.Config_SNS_Topic.id}"
}
resource "aws_config_configuration_recorder_status" "Config_Configuration_Recorder_Status" {
  name       = "${aws_config_configuration_recorder.Config_Configuration_Recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.Config_Configuration_Delivery_Channel"]
}
resource "aws_sns_topic" "Config_SNS_Topic" {
  name = "${var.ConfigSNSTopicName}"
  kms_master_key_id = "${aws_kms_key.SNS_Customer_CMK.id}"
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
      "Resource": "arn:aws:sns::${data.aws_caller_identity.current.account_id}:${var.ConfigSNSTopicName}"
    }
  ]
}
POLICY
}
resource "aws_iam_role" "Config_IAM_Role" {
  name = "${var.ConfigIAMRoleName}"
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
  role = "${aws_iam_role.Config_IAM_Role.name}"
  policy_arn = "${data.aws_iam_policy.Data_Policy_AWSConfigRole.arn}"
}
resource "aws_iam_role_policy" "Config_Role_Policy" {
  name = "${var.ConfigIAMRolePolicyName}"
  role = "${aws_iam_role.Config_IAM_Role.id}"
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

resource "aws_s3_bucket" "Server_Access_Log_S3_Bucket" {
  bucket = "${var.ServerAccessLogS3BucketName}"
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
resource "aws_s3_bucket" "Config_Artifacts_S3_Bucket" { 
  bucket = "${var.ConfigArtifactsBucketName}"
  acl = "private"

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
resource "aws_securityhub_account" "Security_Hub_Enabled" {}
// Hits SecHub API - turns it on for account Auto-Enables CIS Benchmark Rules -- need to turn on config first
resource "aws_sns_topic" "CIS_Compliance_Alerts_SNS_Topic" {
  name = "${var.CISComplianceAlertsSNSTopicName}"
  kms_master_key_id = "${aws_kms_key.SNS_Customer_CMK.id}" 
}
resource "aws_cloudwatch_log_group" "CIS_Compliance_CloudWatch_LogsGroup" {
  name = "${var.CISComplianceCloudWatchLogsGroupName}"
}
resource "aws_iam_role" "CloudWatch_LogsGroup_IAM_Role" {
  name = "${var.CloudWatchLogsGroupRoleName}"

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
  name = "${var.CloudWatchLogsGroupPolicyName}"
  role = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.id}"
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
      "Resource": "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.arn}"
    }
  ]
}
EOF
}
resource "aws_cloudtrail" "CIS_Compliance_CloudTrail_Trail" { 
  name                          = "${var.CISComplianceCloudTrailName}" 
  s3_bucket_name                = "${aws_s3_bucket.CloudTrail_Logs_S3_Bucket.id}"
  include_global_service_events = true
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = "${aws_kms_key.CloudTrail_Customer_CMK.arn}"
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.arn}"
  cloud_watch_logs_role_arn = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}
resource "aws_s3_bucket" "CloudTrail_Logs_S3_Bucket" {  
  bucket = "${var.CloudTrailLogS3BucketName}" 
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
            "Resource": "arn:aws:s3:::${var.CloudTrailLogS3BucketName}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.CloudTrailLogS3BucketName}/*",
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
resource "aws_iam_group" "KMS_Key_Admin_IAM_Group" {
  name = "${var.CMKAdminsIAMGroupName}"
}
resource "aws_iam_policy" "KMS_Key_Admin_IAM_Policy" {
  name        = "${var.CMKAdminsIAMPolicyName}"
  path        = "/"
  description = "${var.CMKAdminsIAMPolicyDescription}"
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
  name = "${var.CMKAdminsIAMUserName}"
}
resource "aws_iam_group_policy_attachment" "KMS_Key_Admin_Group_IAM_Policy_Attachment" {
  group      = "${aws_iam_group.KMS_Key_Admin_IAM_Group.name}"
  policy_arn = "${aws_iam_policy.KMS_Key_Admin_IAM_Policy.arn}"
}
resource "aws_iam_group_membership" "KMS_Key_Admin_IAM_Group_Membership" {
  name = "${var.CMKAdminIAMGroupMembershipName}"

  users = ["${aws_iam_user.KMS_Key_Admin_IAM_User.name}"]

  group = "${aws_iam_group.KMS_Key_Admin_IAM_Group.name}"
}
resource "aws_kinesis_firehose_delivery_stream" "GuardDuty_Finding_KDF_Delivery_Stream" {
  name        = "${var.GuardDutyFindingKinesisFirehoseStreamName}"
  destination = "extended_s3"
  extended_s3_configuration {
    prefix = "raw/firehose/"
    role_arn   = "${aws_iam_role.GuardDuty_Finding_KDF_Delivery_Stream_Role.arn}"
    bucket_arn = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.arn}"
    buffer_size = "${var.GuardDutyFindingKDFDeliveryStream_BufferSize}"
    buffer_interval = "${var.GuardDutyFindingKDFDeliveryStream_BufferInterval}"
  }
}
resource "aws_s3_bucket" "GuardDuty_Finding_KDF_Logs_Bucket" {
  bucket = "${var.GuardDutyFindingsRawLogBucket}"
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
  name = "${var.GuardDutyFindingKinesisFirehoseStreamRoleName}"
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
  name        = "${var.GuardDutyFindingKinesisFirehoseStreamPolicyName}"
  path        = "/"
  description = "${var.GuardDutyFindingKinesisFirehoseStreamPolicyDescription}"
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
resource "aws_cloudwatch_event_rule" "GuardDuty_Finding_CloudWatch_Event_Rule" {
  name        = "${var.GuardDutyFindingCloudWatchEventRuleName}"
  description = "${var.GuardDutyFindingCloudWatchEventRuleDescription}"
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
  name = "${var.GuardDutyFindingCWEtoKDFRoleName}"
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
resource "aws_iam_policy" "GuardDuty_Finding_CWEtoKDF_Role_Policy" {
  name        = "${var.GuardDutyFindingCWEtoKDFRolePolicyName}"
  path        = "/"
  description = "${var.GuardDutyFindingCWEtoKDFRolePolicyDescription}"
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
resource "aws_cloudwatch_event_target" "GuardDuty_Finding_CloudWatch_Event_KDF_Target" {
  rule      = "${aws_cloudwatch_event_rule.GuardDuty_Finding_CloudWatch_Event_Rule.name}"
  arn       = "${aws_kinesis_firehose_delivery_stream.GuardDuty_Finding_KDF_Delivery_Stream.arn}"
  role_arn  = "${aws_iam_role.GuardDuty_Finding_CWEtoKDF_Role.arn}"
}
resource "aws_s3_bucket_notification" "GuardDuty_Finding_KDF_LogBucket_Object_Event" {
  bucket = "${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.id}"
  lambda_function {
    lambda_function_arn = "${aws_lambda_function.Lambda_Function_GuardDuty_Log_Parsing.arn}"
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "raw/firehose/"
  }
}
resource "aws_glue_catalog_database" "GuardDuty_Findings_Parsed_DataCatalogDB" {
  name = "${var.GuardDutyFindingsGlueDBName}"
}
resource "aws_glue_crawler" "GuardDuty_Findings_Parsed_Glue_Crawler" {
  name = "${var.GuardDutyFindingsCrawlerName}"
  database_name = "${aws_glue_catalog_database.GuardDuty_Findings_Parsed_DataCatalogDB.name}"
  role = "${aws_iam_role.GuardDuty_Findings_Parsed_Glue_Crawler_Role.arn}"
  schedule = "cron(0/15 * * * ? *)"
  schema_change_policy {
      update_behavior = "UPDATE_IN_DATABASE"
  }
  s3_target {
    path = "s3://${aws_s3_bucket.GuardDuty_Finding_KDF_Logs_Bucket.bucket}/raw/by_finding_type/"
  }
}
resource "aws_iam_role" "GuardDuty_Findings_Parsed_Glue_Crawler_Role" {
  name = "${var.GuardDutyFindingsGlueCrawlerRoleName}"
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
  name        = "${var.GuardDutyFindingsGlueCrawlerRoleS3PolicyName}"
  path        = "/"
  description = "${var.GuardDutyFindingsGlueCrawlerRoleS3PolicyDescription}"
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