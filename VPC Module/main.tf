resource "aws_vpc" "Primary_VPC" {
  instance_tenancy = "${var.PrimaryVPCTenancy}"
  cidr_block = "${var.PrimaryVPCCIDRBlock}"
  enable_dns_support = "${var.PrimaryVPCDNSSupport}"
  enable_dns_hostnames = "${var.PrimaryVPCDNSHostnames}"
  tags {
      Name = "${var.PrimaryVPCTagName}"
  }
}
resource "aws_subnet" "Primary_VPC_PublicSubnet1" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  cidr_block = "${var.PubSnet1CIDRBlock}"
  availability_zone = "${data.aws_availability_zones.Available_Region_AZ.names[0]}"
  map_public_ip_on_launch = "${var.PubSnet1PublicIPOnLaunch}"
  tags {
      Name = "${var.PubSnet1NameTag}"
  }
}
resource "aws_subnet" "Primary_VPC_PrivateSubnet1" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  cidr_block = "${var.PrivSnet1CIDRBlock}"
  availability_zone = "${data.aws_availability_zones.Available_Region_AZ.names[1]}"
  tags {
      Name = "${var.PrivSnet1NameTag}"
  }
}
resource "aws_subnet" "Primary_VPC_PrivateSubnet2" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  cidr_block = "${var.PrivSnet2CIDRBlock}"
  availability_zone = "${data.aws_availability_zones.Available_Region_AZ.names[2]}"
  tags {
      Name = "${var.PrivSnet2NameTag}"
  }
}
resource "aws_internet_gateway" "Primary_VPC_IGW" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  tags {
      Name = "${var.PrimaryVPCIGWNameTag}"
  }
}
resource "aws_route_table" "Primacy_VPC_Public_RouteTable" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  route {
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.Primary_VPC_IGW.id}"
  }
  tags {
    Name = "${var.PublicRTBNameTag}"
  }
}
resource "aws_route_table_association" "Primary_VPC_Public_Subnet1_Attachment" {
  subnet_id      = "${aws_subnet.Primary_VPC_PublicSubnet1.id}"
  route_table_id = "${aws_route_table.Primacy_VPC_Public_RouteTable.id}"
}
resource "aws_eip" "Primary_VPC_NATGW_EIP" {
  vpc = true
  tags {
    Name = "${var.PrimaryVPCNatGWEIPNameTag}"
  }
}
resource "aws_nat_gateway" "Primary_VPC_NATGW" {
  allocation_id = "${aws_eip.Primary_VPC_NATGW_EIP.id}"
  subnet_id     = "${aws_subnet.Primary_VPC_PublicSubnet1.id}"
  depends_on = ["aws_internet_gateway.Primary_VPC_IGW"]
  tags {
    Name = "${var.PrimaryVPCNatGWNameTag}"
  }
}
resource "aws_route_table" "Primacy_VPC_Private_RouteTable" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = "${aws_nat_gateway.Primary_VPC_NATGW.id}"
  }
  tags {
    label = "${var.PrivateRTBNameTag}"
  }
}
resource "aws_route_table_association" "Primary_VPC_Private_Subnet1_Attachment" {
  subnet_id      = "${aws_subnet.Primary_VPC_PrivateSubnet1.id}"
  route_table_id = "${aws_route_table.Primacy_VPC_Private_RouteTable.id}"
}
resource "aws_route_table_association" "Primary_VPC_Private_Subnet2_Attachment" {
  subnet_id      = "${aws_subnet.Primary_VPC_PrivateSubnet2.id}"
  route_table_id = "${aws_route_table.Primacy_VPC_Private_RouteTable.id}"
}
resource "aws_default_security_group" "Primary_VPC_Default_SecGroup" {
  vpc_id = "${aws_vpc.Primary_VPC.id}"
  tags {
    Name = "DEFAULT_DO_NOT_USE"
    Purpose = "To Strip All Rules From Default"
  }
}
resource "aws_security_group" "Primary_VPC_Principal_SecGroup" {
  name        = "${var.PrincipalSecGroupName}"
  description = "${var.PrincipalSecGroupDescription}"
  vpc_id      = "${aws_vpc.Primary_VPC.id}"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.PrincipalSecGrpSSH-MyIPRange}"]
  }
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
}
resource "aws_default_network_acl" "Primary_VPC_Default_NACL" {
  default_network_acl_id = "${aws_vpc.Primary_VPC.default_network_acl_id}"
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
    Name = "${var.PrimaryVPCDefaultNACLNameTag}"
  }
}
resource "aws_vpc_endpoint" "Primary_VPC_VPCE_Gateway_S3" {
  vpc_id       = "${aws_vpc.Primary_VPC.id}"
  service_name = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = ["${aws_route_table.Primacy_VPC_Private_RouteTable.id}","${aws_route_table.Primacy_VPC_Public_RouteTable.id}"]
}
resource "aws_vpc_endpoint" "Primary_VPC_VPCE_Interface_SSM" {
  vpc_id            = "${aws_vpc.Primary_VPC.id}"
  service_name      = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type = "Interface"
  security_group_ids = ["${aws_security_group.Primary_VPC_Principal_SecGroup.id}"]
  subnet_ids = ["${aws_subnet.Primary_VPC_PublicSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet2.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "Primary_VPC_VPCE_Interface_SSMMessages" {
  vpc_id            = "${aws_vpc.Primary_VPC.id}"
  service_name      = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type = "Interface"
  security_group_ids = ["${aws_security_group.Primary_VPC_Principal_SecGroup.id}"]
  subnet_ids = ["${aws_subnet.Primary_VPC_PublicSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet2.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "Primary_VPC_VPCE_Interface_EC2" {
  vpc_id            = "${aws_vpc.Primary_VPC.id}"
  service_name      = "com.amazonaws.${var.aws_region}.ec2"
  vpc_endpoint_type = "Interface"
  security_group_ids = ["${aws_security_group.Primary_VPC_Principal_SecGroup.id}"]
  subnet_ids = ["${aws_subnet.Primary_VPC_PublicSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet2.id}"]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "Primary_VPC_VPCE_Interface_EC2Messages" {
  vpc_id            = "${aws_vpc.Primary_VPC.id}"
  service_name      = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type = "Interface"
  security_group_ids = ["${aws_security_group.Primary_VPC_Principal_SecGroup.id}"]
  subnet_ids = ["${aws_subnet.Primary_VPC_PublicSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet1.id}","${aws_subnet.Primary_VPC_PrivateSubnet2.id}"]
  private_dns_enabled = true
}
resource "aws_flow_log" "Primary_VPC_FlowLog" {
  iam_role_arn    = "${aws_iam_role.FlowLogsRole.arn}"
  log_destination = "${aws_cloudwatch_log_group.Primary_VPC_FlowLog_CloudWatch_LogGroup.arn}"
  traffic_type    = "ALL"
  vpc_id          = "${aws_vpc.Primary_VPC.id}"
}
resource "aws_cloudwatch_log_group" "Primary_VPC_FlowLog_CloudWatch_LogGroup" {
  name = "${var.PrimaryVPCFlowLogCWLGroupName}"
}
resource "aws_iam_role" "FlowLogsRole" {
  name = "${var.FlowLogsIAMRoleName}"
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
resource "aws_iam_role_policy" "FlowLogsRolePolicy" {
  name = "${var.FlowLogsIAMRolePolicyName}"
  role = "${aws_iam_role.FlowLogsRole.id}"
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