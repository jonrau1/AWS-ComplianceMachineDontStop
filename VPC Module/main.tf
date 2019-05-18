resource "aws_vpc" "CMDS_VPC" {
  cidr_block           = "${var.CMDS_VPC_CIDR}"
  enable_dns_support   = "${var.CMDS_VPC_DNS_Support}"
  enable_dns_hostnames = "${var.CMDS_VPC_DNS_Hostnames}"
  tags {
      Name = "${var.CMDS_VPC_Name_Tag}"
  }
}
resource "aws_subnet" "CMDS_Public_Subnets" {
  count                   = "${var.Network_Resource_Count}"
  vpc_id                  = "${aws_vpc.CMDS_VPC.id}"
  cidr_block              = "${cidrsubnet(aws_vpc.CMDS_VPC.cidr_block, 8, var.Network_Resource_Count + count.index)}"
  availability_zone       = "${data.aws_availability_zones.Available_AZ.names[count.index]}"
  map_public_ip_on_launch = true
  tags {
    Name = "${var.CMDS_VPC_Name_Tag}-PUB-Subnet-${element(data.aws_availability_zones.Available_AZ.names, count.index)}"
  }
}
resource "aws_subnet" "CMDS_Private_Subnets" {
  count             = "${var.Network_Resource_Count}"
  vpc_id            = "${aws_vpc.CMDS_VPC.id}"
  cidr_block        = "${cidrsubnet(aws_vpc.CMDS_VPC.cidr_block, 8, count.index)}"
  availability_zone = "${data.aws_availability_zones.Available_AZ.names[count.index]}"
  tags {
    Name = "${var.CMDS_VPC_Name_Tag}-PRIV-Subnet-${element(data.aws_availability_zones.Available_AZ.names, count.index)}"
  }
}
resource "aws_internet_gateway" "CMDS_IGW" {
  vpc_id = "${aws_vpc.CMDS_VPC.id}"
  tags {
      Name = "${var.CMDS_IGW_Name_Tag}"
  }
}
resource "aws_route_table" "CMDS_Public_RTB" {
  count  = "${var.Network_Resource_Count}"
  vpc_id = "${aws_vpc.CMDS_VPC.id}"
  route {
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.CMDS_IGW.id}"
  }
  tags {
    Name = "PUB-RTB-${element(aws_subnet.CMDS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_eip" "NATGW_Elastic_IPs" {
  count      = "${var.Network_Resource_Count}"
  vpc        = true
  depends_on = ["aws_internet_gateway.CMDS_IGW"]
  tags {
    Name = "NAT-Gateway-EIP-${element(aws_subnet.CMDS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_nat_gateway" "CMDS_NAT_Gateway" {
  count         = "${var.Network_Resource_Count}"
  subnet_id     = "${element(aws_subnet.CMDS_Public_Subnets.*.id, count.index)}"
  allocation_id = "${element(aws_eip.NATGW_Elastic_IPs.*.id, count.index)}"
  tags {
    Name = "NAT-Gateway-${element(aws_subnet.CMDS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_route_table" "CMDS_Private_RTB" {
  count  = "${var.Network_Resource_Count}"
  vpc_id = "${aws_vpc.CMDS_VPC.id}"
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = "${element(aws_nat_gateway.CMDS_NAT_Gateway.*.id, count.index)}"
  }
  tags {
    Name = "PRIV-RTB-${element(aws_subnet.CMDS_Private_Subnets.*.id, count.index)}"
  }
}
resource "aws_route_table_association" "Public_Subnet_Association" {
  count          = "${var.Network_Resource_Count}"
  subnet_id      = "${element(aws_subnet.CMDS_Public_Subnets.*.id, count.index)}"
  route_table_id = "${element(aws_route_table.CMDS_Public_RTB.*.id, count.index)}"
}
resource "aws_route_table_association" "Private_Subnet_Association" {
  count          = "${var.Network_Resource_Count}"
  subnet_id      = "${element(aws_subnet.CMDS_Private_Subnets.*.id, count.index)}"
  route_table_id = "${element(aws_route_table.CMDS_Private_RTB.*.id, count.index)}"
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Gateway_S3" {
  vpc_id            = "${aws_vpc.CMDS_VPC.id}"
  service_name      = "com.amazonaws.${var.AWS_Region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [
    "${aws_route_table.CMDS_Public_RTB.id}",
    "${aws_route_table.CMDS_Private_RTB.*.id}"
  ]
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Interface_Cloudwatch_Logs" {
  vpc_id             = "${aws_vpc.CMDS_VPC.id}"
  service_name       = "com.amazonaws.${var.AWS_Region}.logs"
  vpc_endpoint_type  = "Interface"
  security_group_ids = ["${aws_security_group.VPCE_Interface_SG.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Interface_SSM" {
  vpc_id             = "${aws_vpc.CMDS_VPC.id}"
  service_name       = "com.amazonaws.${var.AWS_Region}.ssm"
  vpc_endpoint_type  = "Interface"
  security_group_ids = ["${aws_security_group.VPCE_Interface_SG.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Interface_SSMMessages" {
  vpc_id             = "${aws_vpc.CMDS_VPC.id}"
  service_name       = "com.amazonaws.${var.AWS_Region}.ssmmessages"
  vpc_endpoint_type  = "Interface"
  security_group_ids = ["${aws_security_group.VPCE_Interface_SG.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Interface_EC2" {
  vpc_id             = "${aws_vpc.CMDS_VPC.id}"
  service_name       = "com.amazonaws.${var.AWS_Region}.ec2"
  vpc_endpoint_type  = "Interface"
  security_group_ids = ["${aws_security_group.VPCE_Interface_SG.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "CMDS_VPCE_Interface_EC2Messages" {
  vpc_id             = "${aws_vpc.CMDS_VPC.id}"
  service_name       = "com.amazonaws.${var.AWS_Region}.ec2messages"
  vpc_endpoint_type  = "Interface"
  security_group_ids = ["${aws_security_group.VPCE_Interface_SG.id}"]
  private_dns_enabled = true
}
resource "aws_flow_log" "CMDS_VPC_Flow_Log" {
  iam_role_arn    = "${aws_iam_role.CMDS_FlowLogs_to_CWL_Role.arn}"
  log_destination = "${aws_cloudwatch_log_group.CMDS_FlowLogs_CWL_Group.arn}"
  traffic_type    = "ALL"
  vpc_id          = "${aws_vpc.CMDS_VPC.id}"
}
resource "aws_cloudwatch_log_group" "CMDS_FlowLogs_CWL_Group" {
  name = "${var.CMDS_FlowLogs_CWL_Group_Name}"
}
resource "aws_iam_role" "CMDS_FlowLogs_to_CWL_Role" {
  name = "${var.CMDS_FlowLogs_to_CWL_Role_Name}"
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
resource "aws_iam_role_policy" "CMDS_FlowLogs_to_CWL_Role_Policy" {
  name = "${var.CMDS_FlowLogs_to_CWL_Role_Policy_Name}"
  role = "${aws_iam_role.CMDS_FlowLogs_to_CWL_Role.id}"
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
      "Resource": "${aws_cloudwatch_log_group.CMDS_FlowLogs_CWL_Group.arn}*"
    }
  ]
}
EOF
}
resource "aws_default_security_group" "Default_Security_Group" {
  vpc_id = "${aws_vpc.CMDS_VPC.id}"
  tags {
    Name = "DEFAULT_DO_NOT_USE"
  }
}
resource "aws_security_group" "VPCE_Interface_SG" {
  name        = "${var.VPCE_Interface_SG_Name}"
  description = "${var.VPCE_Interface_SG_Description} - Managed by Terraform"
  vpc_id      = "${aws_vpc.CMDS_VPC.id}"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
  tags {
      Name = "${var.VPCE_Interface_SG_Name}"
  }
}

resource "aws_default_network_acl" "CMDS_Default_NACL" {
  default_network_acl_id = "${aws_vpc.CMDS_VPC.default_network_acl_id}"
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags {
    Name = "${var.CMDS_Default_NACL_Name_Tag}"
  }
}