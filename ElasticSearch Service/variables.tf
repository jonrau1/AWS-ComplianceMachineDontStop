variable "CMDS_ES_Cognito_User_Pool_Name" {
  default = "kibana-users"
}
variable "CMDS_ES_Cognito_User_Pool_Password_Min_Length" {
  default = 8
}
variable "CMDS_ES_Cognito_User_Pool_Domain_Name" {
  default = ""
}
variable "CMDS_ES_Cognito_Identity_Pool_Name" {
  default = "kibanaidp"
}
variable "CMDS_ElasticSearch_Domain_Name" {
  default = ""
}
variable "CMDS_ElasticSearch_Domain_ES_Version" {
  default = "6.5"
}
variable "CMDS_ElasticSearch_Domain_Instance_Type" {
  default = "c4.large.elasticsearch"
}
variable "CMDS_ElasticSearch_Domain_Instance_Count" {
  default = "2"
}