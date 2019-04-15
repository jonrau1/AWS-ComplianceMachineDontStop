variable "aws_access_key" {}
variable "aws_secret_key" {}
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
variable "GlobalWAFRuleSQLiMatchSetName" {
  default = ""
  description = "name of the SQL Injection Match Set WAF Rule"
}
variable "GlobalWAFRuleSQLiMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the SQL Injection Match Set can be the same as Rule Name"
}
variable "GlobalWAFRuleXSSMatchSetName" {
  default = ""
  description = "name of the Cross-Site Scripting Match Set WAF Rule"
}
variable "GlobalWAFRuleSXSSMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Cross-Site Scripting Match Set can be the same as Rule Name"
}
variable "GlobalWAFRuleSizeConstraintMatchSetName" {
  default = ""
  description = "name of the Constraint Size Match Set WAF Rule"
}
variable "GlobalWAFRuleSConstraintSizeMatchSeMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Constraint Size Match Set can be the same as Rule Name"
}
variable "GlobalWAFWebACLName" {
  default = ""
  description = "Name of the Web ACL aka WACL"
}
variable "GlobalWAFWebACLMetricName" {
  default = ""
  description = "name of the CloudWatch Metric for the Web ACL can be the same as Rule Name"
}