variable "GuardDuty_Finding_Publishing_Frequency" {
  default     = "FIFTEEN_MINUTES"
  description = " Specifies the frequency of notifications sent for subsequent finding occurrences"
}
variable "CloudTrail_CMK_Deletion_Window" {
  default = 7
}
variable "Config_Recorder_SNS_Customer_CMK_Deletion_Window" {
  default = 7
}
variable "CloudTrail_Key_Alias_Name" {
  default =""
}
variable "Config_SNS_Key_Alias_Name" {
  default = ""
}
variable "Inspector_Assessment_Target_All_Group_Name" {
  default = ""
}
variable "InspectorAssessmentTemplateName" {
  default = ""
}
variable "Inspector_Assessment_Rules_Packages_USEast1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OpSys Security Configuration Benchmark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // AWS Security Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h", // RBA (Runtime Behavior Analytics)
   ]
}
variable "Inspector_Assessment_Rules_Packages_USWest1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX", // CIS OpSys Security Configuration Benchmark
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF", // AWS Security Best Practices
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm", // Network Reachability
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0x", // RBA (Runtime Behavior Analytics)
  ]
}
variable "Lambda_Artifacts_S3_Bucket_Name" {
  default = ""
}
variable "Path_To_Lambda_Upload" {
  default = "~/aws-cmds/functions/"
}
variable "GuardDuty_LogParsing_Function_Name" {
  default = ""
}
variable "GuardDuty_LogParsing_FunctionMemory" {
  default = 128
}
variable "GuardDuty_LogParsing_FunctionTimeout" {
  default = 240
}
variable "Inspector_Remediation_Function_Name" {
  default = ""
}
variable "Inspector_Remediation_Function_Memory" {
  default = 640
}
variable "Inspector_Remediation_Function_Timeout" {
  default = 240
}
variable "Inspector_Remediation_SNS_Topic_Name" {
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
variable "Config_Configuration_Recorder_Name" {
  default = ""
}
variable "Config_Configuration_Delivery_Channel_Name" {
  default = ""
}
variable "Config_SNS_Topic_Name" {
  default = ""
}
variable "Server_Access_Log_S3_Bucket_Name" {
  default = ""
}
variable "Server_Access_Log_S3_Bucket_Name" {
  default = ""
}
variable "CIS_Compliance_Alerts_SNS_Topic_Name" {
  default = ""
}
variable "CIS_Compliance_CloudWatch_LogsGroup_Name" {
  default = ""
}
variable "CIS_Compliance_CloudTrail_Trail_Name" {
  default = ""
}
variable "CIS_Compliance_CloudTrail_Logs_S3_Bucket_Name" {
  default = ""
}
variable "CIS_Metric_Alarm_Namespace" {
  default = "LogMetrics"
}
variable "KMS_Key_Admin_IAM_Group_Name" {
  default = ""
}
variable "KMS_Key_Admin_IAM_User_Name" {
  default = ""
}
## Please ensure this is lower case
variable "GuardDuty_Finding_KDF_Delivery_Stream" {
  default     = "lower-case-please"
  description = "Ensure this is lowercase as the value is prepended to the S3 bucket name"
}
variable "GuardDutyFindingKDFDeliveryStream_BufferSize" {
  default = "5"
  description = "Buffer incoming data to the specified size in MB before delivering it to the destination The default value is 5"
}
variable "GuardDutyFindingKDFDeliveryStream_BufferInterval" {
  default = "300"
  description = "Buffer incoming data for the specified period of time in seconds before delivering it to the destination The default value is 300."
}
variable "GuardDuty_Finding_CloudWatch_Event_Rule_Name" {
  default = ""
}
variable "GuardDuty_Finding_CWEtoKDF_Role_Name" {
  default = ""
}
variable "GuardDuty_Findings_Parsed_DataCatalogDB_Name" {
  default = ""
}
variable "GuardDuty_Findings_Parsed_Glue_Crawler_Name" {
  default = ""
}