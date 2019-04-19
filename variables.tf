variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "GuardDutyPublishingFrequency" {
  default = "FIFTEEN_MINUTES"
}
variable "CloudTrailCMKDescription" {
  default = "this key for cloudtrail"
}
variable "CloudTrailCMKDeletionWindow" {
  default = "30"
}
variable "SNSCMKDescription" {
  default = ""
}
variable "SNSCMKDeletionWindow" {
  default = "30"
}
variable "CloudTrailKeyAlias" {
  default ="alias/"
}
variable "SNSKeyAlias" {
  default = "alias/"
}
variable "InspectorResourceGroupNameTag" {
  default = ""
}
variable "InspectorTargetGroupName" {
  default = ""
}
variable "InspectorAssessmentTemplateName" {
  default = ""
}
variable "InspectorAssessmentRulesPackages_USEast1" {
  type = "list"
  default = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OpSys Security Configuration Benchmark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // AWS Security Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h", // RBA (Runtime Behavior Analytics)
   ]
}
variable "InspectorAssessmentRulesPackages_USWest1" {
  type = "list"
  default = [
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX", // CIS OpSys Security Configuration Benchmark
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF", // AWS Security Best Practices
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm", // Network Reachability
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0x", // RBA (Runtime Behavior Analytics)
   ]
}
variable "LambdaArtifactBucketName" {
  default = ""
}
variable "LambdaUploadPrefix" {
  default = "lambda"
}
variable "PathToLambdaUpload" {
  default = "~/aws-cmds/functions/"
}
variable "GuardDutyLogParsingFunctionName" {
  default = ""
}
variable "GuardDutyLogParsingFunctionDescription" {
  default = ""
}
variable "GuardDutyLogParsingFunctionMemory" {
  default = "128"
}
variable "GuardDutyLogParsingFunctionTimeout" {
  default = "240"
}
variable "GuardDutyLogParsingFunctionRoleName" {
  default = ""
}
variable "InspectorRemediationFunctionName" {
  default = ""
}
variable "InspectorRemediationFunctionDescription" {
  default = ""
}
variable "InspectorRemediationFunctionMemory" {
  default = "640"
}
variable "InspectorRemediationFunctionTimeout" {
  default = "240"
}
variable "LambdaFunctionInspectorRemediationRoleName" {
  default = ""
}
variable "InspectorRemediationSNSTopicName" {
  default = ""
}
variable "InspectorRemediationSNSTopicPolicyData_USEAST1_Principal" {
  default = "arn:aws:iam::316112463485:root"
}
variable "InspectorRemediationSNSTopicPolicyData_USEAST2_Principal" {
  default = "arn:aws:iam::646659390643:root"
}
variable "InspectorRemediationSNSTopicPolicyData_USWEST1_Principal" {
  default = "arn:aws:iam::166987590008:root"
}
variable "InspectorRemediationSNSTopicPolicyData_USWEST2_Principal" {
  default = "arn:aws:iam::758058086616:root"
}
variable "ConfigurationRecorderName" {
  default = ""
}
variable "ConfigurationDeliveryChannelName" {
  default = ""
}
variable "ConfigSNSTopicName" {
  default = ""
}
variable "ConfigIAMRoleName" {
  default = ""
}
variable "ConfigIAMRolePolicyName" {
  default = ""
}
variable "ServerAccessLogS3BucketName" {
  default = ""
}
variable "ConfigArtifactsBucketName" {
  default = ""
}
variable "CISComplianceCFNStackSNSTopicName" {
  default = ""
}
variable "CISComplianceCloudWatchLogsGroupName" {
  default = ""
}
variable "CloudWatchLogsGroupRoleName" {
  default = ""
}
variable "CloudWatchLogsGroupPolicyName" {
  default = ""
}
variable "CISComplianceCloudTrailName" {
  default = ""
}
variable "CloudTrailLogS3BucketName" {
  default = ""
}
variable "SecurityHubCISComplianceAlarmsCFNStackName" {
  default = ""
  description = "name of the CloudFormation Stack for the CIS-Aligned Alarms"
}
variable "SecurityHubCloudTrailAlarmsCFNStackName" {
  default = ""
  description = "name of the CloudFormation Stack for the email subscribed CloudTrail alarms"
}
variable "SecurityHubAlerts_EmailAddress" {
  default = ""
  description = "can be an indivdual or distro list"
}
variable "CMKAdminsIAMGroupName" {
  default = ""
}
variable "CMKAdminsIAMPolicyName" {
  default = ""
}
variable "CMKAdminsIAMPolicyDescription" {
  default = ""
}
variable "CMKAdminsIAMUserName" {
  default = ""
}
variable "CMKAdminIAMGroupMembershipName" {
  default = ""
}
variable "GuardDutyFindingKDFDeliveryStream_BufferSize" {
  default = "5"
  description = "Buffer incoming data to the specified size in MB before delivering it to the destination The default value is 5"
}
variable "GuardDutyFindingKDFDeliveryStream_BufferInterval" {
  default = "300"
  description = "Buffer incoming data for the specified period of time in seconds before delivering it to the destination The default value is 300."
}
variable "GuardDutyFindingKinesisFirehoseStreamName" {
  default = ""
}
variable "GuardDutyFindingsRawLogBucket" {
  default = ""
}
variable "GuardDutyFindingKinesisFirehoseStreamRoleName" {
  default = ""
}
variable "GuardDutyFindingKinesisFirehoseStreamPolicyName" {
  default = ""
}
variable "GuardDutyFindingKinesisFirehoseStreamPolicyDescription" {
  default = ""
}
variable "GuardDutyFindingCloudWatchEventRuleName" {
  default = ""
}
variable "GuardDutyFindingCloudWatchEventRuleDescription" {
  default = ""
}
variable "GuardDutyFindingCWEtoKDFRoleName" {
  default = ""
}
variable "GuardDutyFindingCWEtoKDFRolePolicyName" {
  default = ""
}
variable "GuardDutyFindingCWEtoKDFRolePolicyDescription" {
  default = ""
}
variable "GuardDutyFindingsGlueDBName" {
  default = ""
}
variable "GuardDutyFindingsCrawlerName" {
  default = ""
}
variable "GuardDutyFindingsGlueCrawlerRoleName" {
  default = ""
}
variable "GuardDutyFindingsGlueCrawlerRoleS3PolicyName" {
  default = ""
}
variable "GuardDutyFindingsGlueCrawlerRoleS3PolicyDescription" {
  default = ""
}