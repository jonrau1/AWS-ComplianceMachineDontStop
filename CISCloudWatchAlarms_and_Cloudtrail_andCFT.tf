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
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.yada.arn}"
  cloud_watch_logs_role_arn = "${aws_iam_role.cwlrole.arn}"
}

resource "aws_s3_bucket" "foo" {  //this is a very bad bucket -- needs some more security sauce
  bucket = "thisisciscomptrailbucket"
  force_destroy = false // not to be confused w/ object lock or mfa delete

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

