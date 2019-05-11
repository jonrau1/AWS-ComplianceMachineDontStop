variable "AWS_Region" {
  default     = "us-east-1"
  description = "Region will pass to VPC Endpoints"
}
variable "Network_Resource_Count" {
  default     = 3
  description = "Amount of Network Resources Provisioned e.g. Subnets and Route Tables - Adjust for Regional AZ Count and HA Requirements"
}
variable "CMDS_VPC_CIDR" {
  default     = "172.17.0.0/16"
  description = "RFC1918 CIDR for VPC - Subnet CIDR Block Calculations will be handled by Terraform"
}
variable "CMDS_VPC_DNS_Support" {
  default     = "true"
  description = "Indicates whether the DNS resolution is supported"
}
variable "CMDS_VPC_DNS_Hostnames" {
  default     = "true"
  description = "Indicates whether instances with public IP addresses get corresponding public DNS hostnames"
}
variable "CMDS_VPC_Name_Tag" {
  default = "fob-omishan-3tvpc"
}
variable "CMDS_IGW_Name_Tag" {
  default = "fob-omishan-3tigw"
}
variable "CMDS_Public_RTB_Name_Tag" {
  default = "fob-omishan-3t-pub-rtb"
}
variable "CMDS_FlowLogs_CWL_Group_Name" {
  default = "fob-omishan-3tvpc-flows"
}
variable "CMDS_FlowLogs_to_CWL_Role_Name" {
  default = "fob-omishan-3tvpc-flowrole"
}
variable "CMDS_FlowLogs_to_CWL_Role_Policy_Name" {
  default = "fobomishan-3tvpc-flowpol"
}
variable "VPCE_Interface_SG_Name" {
  default = "fob-omishan-vpce-firewall"
}
variable "VPCE_Interface_SG_Description" {
  default = "fob-omishan-vpce-firewall"
}
variable "CMDS_Default_NACL_Name_Tag" {
  default = "fob-omishan-default-nacl"
}