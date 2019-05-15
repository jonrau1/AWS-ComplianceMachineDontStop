variable "GlobalWAFIPSetName" {
  default = ""
  description = "name of the WAF IP Set for Global WAF WACL"
}
variable "GlobalWAFSQLIMatchSetName" {
  default = ""
  description = "name of the WAF SQL Injection Match Set for Global WAF WACL"
}
variable "GlobalWAFXSSMatchSetName" {
  default = ""
  description = "name of the WAF Cross-Site Scripting Match Set for Global WAF WACL"
}
variable "GlobalWAFSizeConstraintMatchSetName" {
 default = ""
 description = "name of the WAF Size Constraint Match Set for Global WAF WACL" 
}
variable "WAFConstraintSet_URI_Size" {
  default = "512"
  description = "Maximum Expected URI Path Size in Bytes"
}
variable "WAFConstraintSet_QueryString_Size" {
  default = "1024"
  description = "Maximum Expected Size of the Query String in Bytes"
}
variable "WAFConstraintSet_Body_Size" {
  default = "4096"
  description = "Maximum Expected Size of the Request Body Size in Bytes"
}
variable "WAFConstraintSet_Cookie_Header_Size" {
  default = "4096"
  description = "Maximum Expected Size of the Cookie in Bytes"
}
variable "GlobalWAFRuleIPSetBlacklistName" {
  default = ""
  description = "name of the Blacklist WAF Rule"
}
variable "GlobalWAFRuleIPSetBlacklistMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Blacklist WAF Rule can be the same as Rule Name"
}
variable "GlobalWAF_BlacklistWebACLName" {
  default = ""
  description = "Name of the Web ACL for Blacklist IPs"
}
variable "GlobalWAF_BlacklistWebACLMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Blacklist Web ACL can be the same as Rule Name"
}
variable "GlobalWAFRuleSQLiMatchSetName" {
  default = ""
  description = "name of the SQL Injection Match Set WAF Rule"
}
variable "GlobalWAFRuleSQLiMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the SQL Injection Match Set can be the same as Rule Name"
}
variable "GlobalWAF_SQLIWebACLName" {
  default = ""
  description = "Name of the Web ACL for SQL Injection Rules"
}
variable "GlobalWAF_SQLIWebACLMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the SQL Injection Rules Web ACL can be the same as Rule Name"
}
variable "GlobalWAFRuleXSSMatchSetName" {
  default = ""
  description = "name of the Cross-Site Scripting Match Set WAF Rule"
}
variable "GlobalWAFRuleSXSSMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Cross-Site Scripting Match Set can be the same as Rule Name"
}
variable "GlobalWAF_XSSWebACLName" {
  default = ""
  description = "Name of the Web ACL for XSS Rules"
}
variable "GlobalWAF_XSSWebACLMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the XSS Web ACL can be the same as Rule Name"
}
variable "GlobalWAFRuleSizeConstraintMatchSetName" {
  default = ""
  description = "name of the Constraint Size Match Set WAF Rule"
}
variable "GlobalWAFRuleSConstraintSizeMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Constraint Size Match Set can be the same as Rule Name"
}
variable "GlobalWAF_SizeConstraintWebACLName" {
  default = ""
  description = "Name of the Web ACL for Size Constraint Rules"
}
variable "GlobalWAF_SizeConstraintWebACLMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Size Constraint Web ACL can be the same as Rule Name"
}
variable "WAFLogsKinesisFirehoseStreamNamePrefix" {
  default = ""
  description = "Value that will append the KDF Stream name must begin with aws-waf-logs-"
}
variable "WAFLogsS3BucketName" {
  default = ""
}
variable "WAFLogsKinesisFirehoseStreamRoleName" {
  default = ""
}
variable "WAFLogsKinesisFirehoseStreamRolePolicyName" {
  default = ""
}
variable "WAFLogsKinesisFirehoseStreamRolePolicyDescription" {
  default = "This allows Kinesis for WAF Logs to put logs into S3"
}
variable "WAFVisualizationGlueDBName" {
  default = ""
  description = "Name of the Glue Data Catalog DB to dump crawler findings into"
}
variable "WAFVisualizationGlueCrawlerName" {
  default = ""
}
variable "WAFVisualizationGlueTablePrefixName" {
  default = "" 
  description = "The table prefix used for catalog tables that are created"
}
variable "WAFVisualizationGlueCrawlerRoleName" {
  default = ""
}
variable "WAFVisualizationGlueCrawlerRoleS3PolicyName" {
  default = ""
}
variable "WAFVisualizationGlueCrawlerRoleS3PolicyDescription" {
  default = ""
}