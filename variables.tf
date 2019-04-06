variable "GuardDutyPublishingFrequency" {
  default = "SIX_HOURS"
}

variable "CloudTrailCMKDescription" {
  default = ""
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
