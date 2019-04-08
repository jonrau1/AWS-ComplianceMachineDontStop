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
                "kms:GenerateDataKey",
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
  rules_package_arns = "${var.InspectorAssessmentRulesPackages_USWest1}"
}
resource "aws_s3_bucket" "Lambda_Artifacts_S3_Bucket" {
  bucket = "${var.LambdaArtifactBucketName}"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
resource "aws_s3_bucket_object" "Inspector_Remediation_Lambda_Object_Upload" {
  bucket = "${aws_s3_bucket.Lambda_Artifacts_S3_Bucket.id}"
  key    = "${var.InspectorRemediationLambdaUploadPrefix}/lambda-auto-remediate.zip"
  source = "${var.PathToInspectorRemediationLambdaUpload}/lambda-auto-remediate.zip"
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
  kms_master_key_id = "${aws_kms_key.SNS_Customer_CMK.id}"
}
resource "aws_sns_topic_policy" "Inspector_Remediation_SNS_Topic_Policy" {
  arn = "${aws_sns_topic.Inspector_Remediation_SNS_Topic.arn}"
  policy = "${data.aws_iam_policy_document.Inspector_Remediation_SNS_Topic_Policy_Data.json}"
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
    },
    {
      "Sid": "Stmt1554678147797",
      "Action": [
        "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "ec2:Describe*",
                "config:Put*",
                "config:Get*",
                "config:List*",
                "config:Describe*",
                "config:BatchGet*",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTags",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetAccountAuthorizationDetails",
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:GetGroup",
                "iam:GetGroupPolicy",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:GetUser",
                "iam:GetUserPolicy",
                "iam:ListAttachedGroupPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListEntitiesForPolicy",
                "iam:ListGroupPolicies",
                "iam:ListGroupsForUser",
                "iam:ListInstanceProfilesForRole",
                "iam:ListPolicyVersions",
                "iam:ListRolePolicies",
                "iam:ListUserPolicies",
                "iam:ListVirtualMFADevices",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "elasticloadbalancing:DescribeTags",
                "acm:DescribeCertificate",
                "acm:ListCertificates",
                "acm:ListTagsForCertificate",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSecurityGroups",
                "rds:DescribeDBSnapshotAttributes",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBSubnetGroups",
                "rds:DescribeEventSubscriptions",
                "rds:ListTagsForResource",
                "rds:DescribeDBClusters",
                "s3:GetAccelerateConfiguration",
                "s3:GetBucketAcl",
                "s3:GetBucketCORS",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketPolicy",
                "s3:GetBucketRequestPayment",
                "s3:GetBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketWebsite",
                "s3:GetLifecycleConfiguration",
                "s3:GetReplicationConfiguration",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetAccountPublicAccessBlock",
                "redshift:DescribeClusterParameterGroups",
                "redshift:DescribeClusterParameters",
                "redshift:DescribeClusterSecurityGroups",
                "redshift:DescribeClusterSnapshots",
                "redshift:DescribeClusterSubnetGroups",
                "redshift:DescribeClusters",
                "redshift:DescribeEventSubscriptions",
                "redshift:DescribeLoggingStatus",
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "dynamodb:ListTagsOfResource",
                "cloudwatch:DescribeAlarms",
                "application-autoscaling:DescribeScalableTargets",
                "application-autoscaling:DescribeScalingPolicies",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeLifecycleHooks",
                "autoscaling:DescribePolicies",
                "autoscaling:DescribeScheduledActions",
                "autoscaling:DescribeTags",
                "lambda:GetFunction",
                "lambda:GetPolicy",
                "lambda:ListFunctions",
                "lambda:GetAlias",
                "lambda:ListAliases",
                "waf-regional:GetWebACLForResource",
                "waf-regional:GetWebACL",
                "cloudfront:ListTagsForResource",
                "guardduty:ListDetectors",
                "guardduty:GetMasterAccount",
                "guardduty:GetDetector",
                "codepipeline:ListPipelines",
                "codepipeline:GetPipeline",
                "codepipeline:GetPipelineState",
                "kms:ListKeys",
                "kms:GetKeyRotationStatus",
                "kms:DescribeKey",
                "ssm:DescribeDocument",
                "ssm:GetDocument",
                "ssm:DescribeAutomationExecutions",
                "ssm:GetAutomationExecution",
                "shield:DescribeProtection"
      ],
      "Effect": "Allow",
      "Resource": "*"
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