// Cloud Compliance Machine Don't Stop, Son!
// Made with Love (and lots of verbosity) by Jon Rau

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
} 

resource "aws_guardduty_detector" "MyDetector" {
  enable = true
  finding_publishing_frequency = "SIX_HOURS"
}

resource "aws_kms_key" "trailkey" { // REVIEW POLICY FOR PRINCIPALS, ALSO ADD IN KEY ADMIN PROVISIONS
  description             = "KMS Key For CloudTrail - Buckets & Trail"
  deletion_window_in_days = 30
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
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/Admin" // CHANGE YOUR ADMIN USER
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

resource "aws_kms_key" "configkey" {
  description             = "KMS Key For Config Bucket & SNS"
  deletion_window_in_days = 30
  enable_key_rotation = true
}

resource "aws_kms_key" "logbucketkey" {
  description             = "KMS Key for S3 server access log bucket"
  deletion_window_in_days = 30
  enable_key_rotation = true
}

resource "aws_inspector_resource_group" "inspect-group" {
  tags = {
    Name = "Main Inpsector Target Group"
    Env  = "Non-Prod"
  }
}

resource "aws_inspector_assessment_target" "inspect-target" {
  name               = "target-all"
  // not specifiying 'resource_group_arn' will apply to all EC2 w/ Inspector Agent
}

resource "aws_inspector_assessment_template" "inspect-temp" {
  name       = "assess-all"
  target_arn = "${aws_inspector_assessment_target.inspect-target.arn}"
  duration   = 3600

  rules_package_arns = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // CVE
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OS SecConf B-Mark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // Sec Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability / TRANSEC
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h", // RBA (Runtime Behavior Analytics)
   // us-west2rules
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p",  // CVE
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc",  // CIS
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl",  // SEC BP
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ",  // TRANSEC
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-vg5GGHSD",  // RBA
   // us-west1rules
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa",  // CVE
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX",  // CIS
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF",  // SEC BP
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm",  // TRANSEC
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0",   // RBA
  ]
}

resource "aws_config_configuration_recorder_status" "config-status" {
  name       = "${aws_config_configuration_recorder.config-recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.config-delivchan"]
}

resource "aws_iam_role_policy_attachment" "a" {
  role       = "${aws_iam_role.configrole.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket_prefix = "compliancemachine-serveraccesslogs"
  acl    = "log-delivery-write"

  versioning {
      enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.logbucketkey.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket" "b" { 
  bucket_prefix = "compliancemachine-config"
  acl = "private"

  versioning {
      enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.log_bucket.id}"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.trailkey.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_config_delivery_channel" "config-delivchan" {
  name           = "compliancemachineconfigdeliv"
  s3_bucket_name = "${aws_s3_bucket.b.bucket}"
  sns_topic_arn = "${aws_sns_topic.config-sns.id}"
}

resource "aws_sns_topic" "config-sns" {
  name = "ThisIsAConfigSNSTopic"
  kms_master_key_id = "${aws_kms_key.configkey.id}" // put a KMS Key Here & share it with your config bucket
}

resource "aws_config_configuration_recorder" "config-recorder" {
  name     = "ThisIsAConfigRecorder"
  role_arn = "${aws_iam_role.configrole.arn}"
}

resource "aws_iam_role" "configrole" {
  name = "ThisIsAWSConfigRole"

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
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "configpolicy" {
  name = "ThisIsAWSConfigRolePolicy"
  role = "${aws_iam_role.configrole.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.b.arn}",
        "${aws_s3_bucket.b.arn}/*"
      ]
    }
  ]
}
POLICY
}

resource "aws_securityhub_account" "sechub" {}
// Hits SecHub API - turns it on for account Auto-Enables CIS Benchmark Rules -- need to turn on config first

// need to create a new SNS Topic apart from the Config one (you will probably be over communicating)
// Use CloudWatch Logs Group you create for CT -- don't use the Flow Logs one
// Trail needs a Key & Key Policy (share it with the CT Bucket)
// Use the Trail Key for the new SNS Topic as well

resource "aws_sns_topic" "stacksns" {
  name = "ThisIsAConfigSNSTopic"
  kms_master_key_id = "alias/aws/sns" // put a KMS Key Here & share it with your config bucket
}

resource "aws_cloudwatch_log_group" "yada" {
  name = "ciscomploggrp"
}

resource "aws_iam_role" "cwlrole" {
  name = "CloudWatchLogsGroupRole"

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

resource "aws_iam_role_policy" "cwlpolicy" {
  name = "CloudWatchLogsGroupPolicy"
  role = "${aws_iam_role.cwlrole.id}"

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
      "Resource": "*"
    }
  ]
}
EOF
}
resource "aws_cloudtrail" "foobar" {  // this also needs a KMS Key -- will need to pass a Policy Inline with aws_kms_key -- refer to AWS Docs
  name                          = "Ciscomptrail" 
  s3_bucket_name                = "${aws_s3_bucket.foo.id}"
  include_global_service_events = true
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = "${aws_kms_key.trailkey.arn}"
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.yada.arn}"
  cloud_watch_logs_role_arn = "${aws_iam_role.cwlrole.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_s3_bucket" "foo" {  //this is a very bad bucket -- needs some more security sauce
  bucket = "thisisciscomptrailbucket"
  force_destroy = false // not to be confused w/ object lock or mfa delete  
  acl = "private"

  versioning {
      enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.log_bucket.id}"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.trailkey.arn}"
        sse_algorithm     = "aws:kms"
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
            "Resource": "arn:aws:s3:::thisisciscomptrailbucket"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::thisisciscomptrailbucket/*",
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

resource "aws_cloudformation_stack" "ciscomp" {
  name = "CISAWSFoundationsBenchmarkMetricAlarms"

  parameters = {
    AlarmNotificationTopicARN = "${aws_sns_topic.stacksns.arn}"
    CloudtrailLogGroupName = "${aws_cloudwatch_log_group.yada.name}" // ENSURE YOU USE NAME AND NOT ID/ARN!!!!!!
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


resource "aws_vpc" "vpc_main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"
  enable_dns_support = true
  enable_dns_hostnames = true

  tags = {
    Name = "MainVPC"
  }
}

resource "aws_subnet" "snet1" {
  vpc_id     = "${aws_vpc.vpc_main.id}"
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone = "${data.aws_availability_zones.available.names[0]}"

  tags = {
    Name = "Subnet1"
  }
}

resource "aws_subnet" "snet2" {
  vpc_id     = "${aws_vpc.vpc_main.id}"
  cidr_block = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone = "${data.aws_availability_zones.available.names[1]}"

  tags = {
    Name = "Subnet2"
  }
}

resource "aws_subnet" "snet3" {
  vpc_id     = "${aws_vpc.vpc_main.id}"
  cidr_block = "10.0.3.0/24"
  map_public_ip_on_launch = true
  availability_zone = "${data.aws_availability_zones.available.names[2]}"

  tags = {
    Name = "Subnet3"
  }
}

resource "aws_subnet" "snet4" {
  vpc_id     = "${aws_vpc.vpc_main.id}"
  cidr_block = "10.0.4.0/24"
  map_public_ip_on_launch = true
  availability_zone = "${data.aws_availability_zones.available.names[3]}"

  tags = {
    Name = "Subnet4"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.vpc_main.id}"

  tags = {
    Name = "VPCMainIGW"
  }
}

resource "aws_route_table" "mainrtb" {
  vpc_id = "${aws_vpc.vpc_main.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.igw.id}"
  }

  tags = {
    Name = "VPCMainRTB"
  }
}

resource "aws_route_table_association" "rtb-a1" {
  subnet_id      = "${aws_subnet.snet1.id}"
  route_table_id = "${aws_route_table.mainrtb.id}"
}

resource "aws_route_table_association" "rtb-a2" {
  subnet_id      = "${aws_subnet.snet2.id}"
  route_table_id = "${aws_route_table.mainrtb.id}"
}

resource "aws_route_table_association" "rtb-a3" {
  subnet_id      = "${aws_subnet.snet3.id}"
  route_table_id = "${aws_route_table.mainrtb.id}"
}

resource "aws_route_table_association" "rtb-a4" {
  subnet_id      = "${aws_subnet.snet4.id}"
  route_table_id = "${aws_route_table.mainrtb.id}"
}

resource "aws_network_acl" "vpcmain-nacl" {
  vpc_id = "${aws_vpc.vpc_main.id}"
  subnet_ids = [ "${aws_subnet.snet1.id}","${aws_subnet.snet2.id}","${aws_subnet.snet3.id}","${aws_subnet.snet4.id}" ]

  egress {
    protocol   = "tcp"
    rule_no    = 101
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }
  
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 101
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  
  egress {
    protocol   = "tcp"
    rule_no    = 400
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 4995
    to_port    = 65535
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 400
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 4995
    to_port    = 65535
  }
  
  ingress {
    protocol   = -1
    rule_no    = 1000
    action     = "allow"
    cidr_block = "${aws_vpc.vpc_main.cidr_block}"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 1001
    action     = "allow"
    cidr_block = "${aws_vpc.vpc_main.cidr_block}"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "VPCMainNACL"
  }
}

resource "aws_security_group" "newsg" { //Change rules to map your compliance
  name        = "VPCMainSG"
  description = "VPCMain Security Group, Came with 22/80/443"
  vpc_id = "${aws_vpc.vpc_main.id}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.168.1.0/24"] // CHANGE THIS IMMEDIATELY
  }

   egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags {
    Name = "ThisIsMySG"
  }
}

resource "aws_flow_log" "flowlogs" {
  iam_role_arn    = "${aws_iam_role.flowrole.arn}"
  log_destination = "${aws_cloudwatch_log_group.flow-cwl.arn}"
  traffic_type    = "ALL"
  vpc_id          = "${aws_vpc.vpc_main.id}"
}

resource "aws_cloudwatch_log_group" "flow-cwl" {
  name = "MainVPC-VPCFlowLogsCWLGroup"
}

resource "aws_iam_role" "flowrole" {
  name = "IAmTheFlowLogRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "flowrolepolicy" {
  name = "IAmTheFlowLogRolePolicy"
  role = "${aws_iam_role.flowrole.id}"

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
      "Resource": "*"
    }
  ]
}
EOF
}