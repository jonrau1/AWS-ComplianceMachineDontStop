variable "aws_region" {
  default = ""
  description = "this value will populate the AWS Provider as well as VPC Endpoint Interfaces and Gateways"
}
variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "PrimaryVPCTenancy" {
  default = ""
  description = "default or dedicated"
}
variable "PrimaryVPCCIDRBlock" {
  default = ""
}
variable "PrimaryVPCDNSSupport" {
  default = "true"
  description = "true or false"
}
variable "PrimaryVPCDNSHostnames" {
  default = ""
  description = "true or false"
}
variable "PrimaryVPCTagName" {
  default = ""
  description = "Name tag value of the VPC"
}
variable "PubSnet1CIDRBlock" {
  default = ""
  description = "CIDR Block for Public Subnet Number 1"
}
variable "PubSnet1PublicIPOnLaunch" {
  default = ""
  description = "true or false"
}
variable "PubSnet1NameTag" {
  default = ""
}
variable "PrivSnet1CIDRBlock" {
  default = ""
  description = "CIDR Block for Private Subnet Number 1 mapping public IP is not needed due to NATGW"
}
variable "PrivSnet1NameTag" {
  default = ""
}
variable "PrivSnet2CIDRBlock" {
  default = ""
  description = "CIDR Block for Private Subnet Number 2 mapping public IP is not needed due to NATGW"
}
variable "PrivSnet2NameTag" {
  default = ""
}
variable "PrimaryVPCIGWNameTag" {
  default = ""
  description = "Tag Value for Name of Internet Gateway"
}
variable "PublicRTBNameTag" {
  default = ""
  description = "Tag Value for Name of the Public Internet-facing Route Table"
}
variable "PrimaryVPCNatGWEIPNameTag" {
  default = ""
  description = "Name tag for the EIP associated with the NAT-GW"
}
variable "PrimaryVPCNatGWNameTag" {
  default = ""
  description = "Name tag for the NAT Gateway"
}
variable "PrivateRTBNameTag" {
  default = ""
  description = "Tag Value for Name of the Private Subnet Route Table"
}
variable "PrincipalSecGroupName" {
  default = ""
  description = "Group Name is different than Name Tag Value - Same Purpose"
}
variable "PrincipalSecGroupDescription" {
  default = ""
}
variable "PrincipalSecGrpSSH-MyIPRange" {
  default = ""
  description = "Your Home or Office IP Range for SSH"
}
variable "PrimaryVPCDefaultNACLNameTag" {
  default = ""
}
variable "PrimaryVPCFlowLogCWLGroupName" {
  default = ""
}
variable "FlowLogsIAMRoleName" {
  default = ""
}
variable "FlowLogsIAMRolePolicyName" {
  default = ""
}