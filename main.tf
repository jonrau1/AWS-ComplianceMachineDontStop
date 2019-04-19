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
resource "aws_sns_topic" "CIS_Compliance_CFN_Stack_SNS_Topic" {
  name = "${var.CISComplianceCFNStackSNSTopicName}"
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
resource "aws_cloudformation_stack" "Security_Hub_CIS_Compliance_Alarms_CFN_Stack" {
  name = "${var.SecurityHubCISComplianceAlarmsCFNStackName}"
  parameters = {
    AlarmNotificationTopicARN = "${aws_sns_topic.CIS_Compliance_CFN_Stack_SNS_Topic.arn}"
    CloudtrailLogGroupName = "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.name}"
  }
  template_body = <<STACK
Parameters:
  AlarmNotificationTopicARN:
    Description: SNS topic to send alerts to
    Type: String
  CloudtrailLogGroupName:
    Description: Name of the Cloudtrail log group
    Type: String
Resources:
#===============================================================================================================================
# MetricFilter and CloudWatch Alarm Section
#===============================================================================================================================

# ------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.1   Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)
# ------------------------------------------------------------------------------------------------------------------------------------
  UnauthorizedApiCallsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Unauthorized Activity Attempt
      AlarmDescription: Alarm if Multiple unauthorized actions or logins attempted
      MetricName: UnauthorizedAttemptCount
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: '1'
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  UnauthorizedApiCallsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.errorCode = "*UnauthorizedOperation") ||
          ($.errorCode = "AccessDenied*")
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: UnauthorizedAttemptCount

# ------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.2   Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
# ------------------------------------------------------------------------------------------------------------------------------------
  NoMfaConsoleLoginsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Console Signin Without MFA
      AlarmDescription: Alarm if there is a Management Console sign-in without MFA
      MetricName: ConsoleSigninWithoutMFA
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  NoMfaConsoleLoginsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = "ConsoleLogin") &&
          ($.additionalEventData.MFAUsed != "Yes")
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: ConsoleSigninWithoutMFA

# ------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 1.1   Avoid the use of the "root" account (Scored)
# CIS AWS Foundations Benchmark - 3.3   Ensure a log metric filter and alarm exist for usage of "root" account  (Scored)
# ------------------------------------------------------------------------------------------------------------------------------------
  RootAccountLoginsAlarm:
    Type: AWS::CloudWatch::Alarm
    DependsOn:
    - NoMfaConsoleLoginsAlarm
    Properties:
      AlarmName: CIS-Root Activity
      AlarmDescription: Alarm if a 'root' user uses the account
      MetricName: RootUserEventCount
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  RootAccountLoginsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          $.userIdentity.type = "Root" &&
          $.userIdentity.invokedBy NOT EXISTS &&
          $.eventType != "AwsServiceEvent"
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: RootUserEventCount

# --------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Scored)
# --------------------------------------------------------------------------------------------------------------------------------------------
  IAMPolicyChangesAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-IAM Policy Changes
      AlarmDescription: Alarm if an IAM policy changes
      MetricName: IAMPolicyChangeEventCount
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  IAMPolicyChangesFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName=DeleteGroupPolicy) ||
          ($.eventName=DeleteRolePolicy) ||
          ($.eventName=DeleteUserPolicy) ||
          ($.eventName=PutGroupPolicy) ||
          ($.eventName=PutRolePolicy) ||
          ($.eventName=PutUserPolicy) ||
          ($.eventName=CreatePolicy) ||
          ($.eventName=DeletePolicy) ||
          ($.eventName=CreatePolicyVersion) ||
          ($.eventName=DeletePolicyVersion) ||
          ($.eventName=AttachRolePolicy) ||
          ($.eventName=DetachRolePolicy) ||
          ($.eventName=AttachUserPolicy) ||
          ($.eventName=DetachUserPolicy) ||
          ($.eventName=AttachGroupPolicy) ||
          ($.eventName=DetachGroupPolicy)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: IAMPolicyChangeEventCount

# --------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)
# --------------------------------------------------------------------------------------------------------------------------------------------
  CloudtrailConfigChangesAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Cloudtrail Config Changes
      AlarmDescription: Alarm if the configuration for Cloudtrail changes
      MetricName: CloudtrailConfigChangeEventCount
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  CloudtrailConfigChangesFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = CreateTrail) ||
          ($.eventName = UpdateTrail) ||
          ($.eventName = DeleteTrail) || 
          ($.eventName = StartLogging) ||
          ($.eventName = StopLogging)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: CloudtrailConfigChangeEventCount

# --------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)
# --------------------------------------------------------------------------------------------------------------------------------------------
  FailedConsoleLoginsAlarm:
    Type: AWS::CloudWatch::Alarm
    DependsOn:
    - RootAccountLoginsAlarm
    Properties:
      AlarmName: CIS-Console Login Failures
      AlarmDescription: Alarm if there are AWS Management Console authentication failures
      MetricName: ConsoleLoginFailures
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: '300'
      EvaluationPeriods: '1'
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  FailedConsoleLoginsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = ConsoleLogin) &&
          ($.errorMessage = "Failed authentication")
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: ConsoleLoginFailures

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.7   Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  DisabledOrDeletedCmksAlarm:
    Type: AWS::CloudWatch::Alarm
    DependsOn:
    - FailedConsoleLoginsAlarm
    Properties:
      AlarmName: CIS-KMS Key Disabled or Scheduled for Deletion
      AlarmDescription: Alarm if customer created CMKs get disabled or scheduled for
        deletion
      MetricName: KMSCustomerKeyDeletion
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  DisabledOrDeletedCmksFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventSource = kms.amazonaws.com) &&
          (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: KMSCustomerKeyDeletion

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  S3BucketPolicyChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-S3 Bucket Policy Changed
      AlarmDescription: Alarm if any S3 bucket policies are changed
      MetricName: S3BucketPolicyChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  S3BucketPolicyChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventSource = s3.amazonaws.com) &&
          (($.eventName = PutBucketAcl) || 
            ($.eventName = PutBucketPolicy) || 
            ($.eventName = PutBucketCors) || 
            ($.eventName = PutBucketLifecycle) || 
            ($.eventName = PutBucketReplication) || 
            ($.eventName = DeleteBucketPolicy) || 
            ($.eventName = DeleteBucketCors) || 
            ($.eventName = DeleteBucketLifecycle) || 
            ($.eventName = DeleteBucketReplication))
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: S3BucketPolicyChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  AWSConfigConfigurationChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-AWS Config Configuration has changed
      AlarmDescription: Alarm if the configuration for AWS Config changes
      MetricName: AWSConfigConfigurationChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  AWSConfigConfigurationChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventSource = config.amazonaws.com) && 
          (($.eventName=StopConfigurationRecorder)||
           ($.eventName=DeleteDeliveryChannel)||
           ($.eventName=PutDeliveryChannel)||
           ($.eventName=PutConfigurationRecorder))
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: AWSConfigConfigurationChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  SecurityGroupChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Security Groups Have Changed
      AlarmDescription: Alarm if there are any changes to security groups
      MetricName: SecurityGroupChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  SecurityGroupChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = AuthorizeSecurityGroupIngress) || 
          ($.eventName = AuthorizeSecurityGroupEgress) || 
          ($.eventName = RevokeSecurityGroupIngress) || 
          ($.eventName = RevokeSecurityGroupEgress) || 
          ($.eventName = CreateSecurityGroup) || 
          ($.eventName = DeleteSecurityGroup)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: SecurityGroupChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  NACLChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-NACLs Have Changed
      AlarmDescription: Alarm if there are any changes to Network ACLs (NACLs)
      MetricName: NACLChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  NACLChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = CreateNetworkAcl) || 
          ($.eventName = CreateNetworkAclEntry) || 
          ($.eventName = DeleteNetworkAcl) || 
          ($.eventName = DeleteNetworkAclEntry) || 
          ($.eventName = ReplaceNetworkAclEntry) || 
          ($.eventName = ReplaceNetworkAclAssociation)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: NACLChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  NetworkGatewayChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Network Gateways Have Changed
      AlarmDescription: Alarm if there are any changes to network gateways
      MetricName: NetworkGatewayChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  NetworkGatewayChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = CreateCustomerGateway) || 
          ($.eventName = DeleteCustomerGateway) || 
          ($.eventName = AttachInternetGateway) || 
          ($.eventName = CreateInternetGateway) || 
          ($.eventName = DeleteInternetGateway) || 
          ($.eventName = DetachInternetGateway)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: NetworkGatewayChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  RouteTableChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-Route Tables Have Changed
      AlarmDescription: Alarm if there are any changes to route tables
      MetricName: RouteTableChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  RouteTableChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = CreateRoute) || 
          ($.eventName = CreateRouteTable) || 
          ($.eventName = ReplaceRoute) || 
          ($.eventName = ReplaceRouteTableAssociation) || 
          ($.eventName = DeleteRouteTable) || 
          ($.eventName = DeleteRoute) || 
          ($.eventName = DisassociateRouteTable)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: RouteTableChanges

# -------------------------------------------------------------------------------------------------------------------------------------------------------
# CIS AWS Foundations Benchmark - 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)
# -------------------------------------------------------------------------------------------------------------------------------------------------------
  VPCChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CIS-VPC Has Changed
      AlarmDescription: Alarm if there are any changes to any VPCs
      MetricName: VPCChanges
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlarmNotificationTopicARN
      ComparisonOperator: GreaterThanOrEqualToThreshold
  VPCChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudtrailLogGroupName
      FilterPattern: |-
        {
          ($.eventName = CreateVpc) || 
          ($.eventName = DeleteVpc) || 
          ($.eventName = ModifyVpcAttribute) || 
          ($.eventName = AcceptVpcPeeringConnection) || 
          ($.eventName = CreateVpcPeeringConnection) || 
          ($.eventName = DeleteVpcPeeringConnection) || 
          ($.eventName = RejectVpcPeeringConnection) || 
          ($.eventName = AttachClassicLinkVpc) || 
          ($.eventName = DetachClassicLinkVpc) || 
          ($.eventName = DisableVpcClassicLink) || 
          ($.eventName = EnableVpcClassicLink)
        }
      MetricTransformations:
      - MetricValue: '1'
        MetricNamespace: CloudTrailMetrics
        MetricName: VPCChanges
STACK
}
resource "aws_cloudformation_stack" "Security_Hub_CloudTrail_Alarms_CFN_Stack" {
  name = "${var.SecurityHubCloudTrailAlarmsCFNStackName}"
  parameters = {
    Email = "${var.SecurityHubAlerts_EmailAddress}"
    LogGroupName = "${aws_cloudwatch_log_group.CIS_Compliance_CloudWatch_LogsGroup.name}"
  }
  template_body = <<STACK
Parameters:
  LogGroupName:
    Type: String
    Default: CloudTrail/DefaultLogGroup
    Description: >-
      Enter CloudWatch Logs log group name. Default is
      CloudTrail/DefaultLogGroup
  Email:
    Type: String
    Description: Email address to notify when an API activity has triggered an alarm
Resources:
  SecurityGroupChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName =
        AuthorizeSecurityGroupEgress) || ($.eventName =
        RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress)
        || ($.eventName = CreateSecurityGroup) || ($.eventName =
        DeleteSecurityGroup) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: SecurityGroupEventCount
          MetricValue: '1'
  SecurityGroupChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailSecurityGroupChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, update or delete a Security
        Group.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: SecurityGroupEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  NetworkAclChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = CreateNetworkAcl) || ($.eventName =
        CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) ||
        ($.eventName = DeleteNetworkAclEntry) || ($.eventName =
        ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)
        }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: NetworkAclEventCount
          MetricValue: '1'
  NetworkAclChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailNetworkAclChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, update or delete a Network
        ACL.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: NetworkAclEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  GatewayChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = CreateCustomerGateway) || ($.eventName =
        DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) ||
        ($.eventName = CreateInternetGateway) || ($.eventName =
        DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: GatewayEventCount
          MetricValue: '1'
  GatewayChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailGatewayChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, update or delete a Customer
        or Internet Gateway.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: GatewayEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  VpcChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName
        = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) ||
        ($.eventName = CreateVpcPeeringConnection) || ($.eventName =
        DeleteVpcPeeringConnection) || ($.eventName =
        RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) ||
        ($.eventName = DetachClassicLinkVpc) || ($.eventName =
        DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: VpcEventCount
          MetricValue: '1'
  VpcChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailVpcChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, update or delete a VPC, VPC
        peering connection or VPC connection to classic.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: VpcEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  EC2InstanceChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = RunInstances) || ($.eventName = RebootInstances) ||
        ($.eventName = StartInstances) || ($.eventName = StopInstances) ||
        ($.eventName = TerminateInstances) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: EC2InstanceEventCount
          MetricValue: '1'
  EC2InstanceChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailEC2InstanceChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, terminate, start, stop or
        reboot an EC2 instance.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: EC2InstanceEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  EC2LargeInstanceChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = RunInstances) && (($.requestParameters.instanceType =
        *.8xlarge) || ($.requestParameters.instanceType = *.4xlarge)) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: EC2LargeInstanceEventCount
          MetricValue: '1'
  EC2LargeInstanceChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailEC2LargeInstanceChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, terminate, start, stop or
        reboot a 4x or 8x-large EC2 instance.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: EC2LargeInstanceEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  CloudTrailChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) ||
        ($.eventName = DeleteTrail) || ($.eventName = StartLogging) ||
        ($.eventName = StopLogging) }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: CloudTrailEventCount
          MetricValue: '1'
  CloudTrailChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailChanges
      AlarmDescription: >-
        Alarms when an API call is made to create, update or delete a CloudTrail
        trail, or to start or stop logging to a trail.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: CloudTrailEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  ConsoleSignInFailuresMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed
        authentication") }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: ConsoleSignInFailureCount
          MetricValue: '1'
  ConsoleSignInFailuresAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailConsoleSignInFailures
      AlarmDescription: >-
        Alarms when an unauthenticated API call is made to sign into the
        console.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: ConsoleSignInFailureCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '3'
  AuthorizationFailuresMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        { ($.errorCode = "*UnauthorizedOperation") || ($.errorCode =
        "AccessDenied*") }
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: AuthorizationFailureCount
          MetricValue: '1'
  AuthorizationFailuresAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailAuthorizationFailures
      AlarmDescription: Alarms when an unauthorized API call is made.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: AuthorizationFailureCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  IAMPolicyChangesMetricFilter:
    Type: 'AWS::Logs::MetricFilter'
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: >-
        {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: IAMPolicyEventCount
          MetricValue: '1'
  IAMPolicyChangesAlarm:
    Type: 'AWS::CloudWatch::Alarm'
    Properties:
      AlarmName: CloudTrailIAMPolicyChanges
      AlarmDescription: Alarms when an API call is made to change an IAM policy.
      AlarmActions:
        - !Ref AlarmNotificationTopic
      MetricName: IAMPolicyEventCount
      Namespace: CloudTrailMetrics
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: '1'
      Period: '300'
      Statistic: Sum
      Threshold: '1'
  AlarmNotificationTopic:
    Type: 'AWS::SNS::Topic'
    Properties:
      Subscription:
        - Endpoint: !Ref Email
          Protocol: email
STACK
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