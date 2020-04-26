resource "aws_cognito_user_pool" "CMDS_ES_Cognito_User_Pool" {
  name                       = "${var.CMDS_ES_Cognito_User_Pool_Name}"
  email_verification_subject = "${var.CMDS_ElasticSearch_Domain_Name} Kibana Device Verification Code"
  email_verification_message = "Please use the following code {####}"
  alias_attributes           = ["email", "preferred_username"]
  auto_verified_attributes   = ["email"]
  admin_create_user_config {
    allow_admin_create_user_only = false
  }
  password_policy {
      minimum_length    = "${var.CMDS_ES_Cognito_User_Pool_Password_Min_Length}"
      require_lowercase = true
      require_numbers   = true
      require_symbols   = true
      require_uppercase = true
  }
  schema {
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = false
    name                     = "email"
    required                 = true

    string_attribute_constraints {
      min_length = 7
      max_length = 32
    }
  }
}
resource "aws_cognito_user_pool_domain" "CMDS_ES_Cognito_User_Pool_Domain" {
  domain       = "${var.CMDS_ES_Cognito_User_Pool_Domain_Name}"
  user_pool_id = "${aws_cognito_user_pool.CMDS_ES_Cognito_User_Pool.id}"
}
resource "aws_cognito_identity_pool" "CMDS_ES_Cognito_Identity_Pool" {
  identity_pool_name               = "${var.CMDS_ES_Cognito_Identity_Pool_Name}"
  allow_unauthenticated_identities = true # MUST BE TRUE FOR KIBANA TO USE THIS
}
resource "aws_iam_role" "ES_Identity_Pool_Authenticated_Role" {
  name = "${var.CMDS_ES_Cognito_Identity_Pool_Name}-authenticated-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.CMDS_ES_Cognito_Identity_Pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Identity_Pool_Authenticated_Policy" {
  name = "${var.CMDS_ES_Cognito_Identity_Pool_Name}-authenticated-policy"
  role = "${aws_iam_role.ES_Identity_Pool_Authenticated_Role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:ESHttp*",
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}
resource "aws_iam_role" "ES_Identity_Pool_Unauthenticated_Role" {
  name               = "${var.CMDS_ES_Cognito_Identity_Pool_Name}-unauthenticated-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.CMDS_ES_Cognito_Identity_Pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Identity_Pool_Unauthenticated_Policy" {
  name   = "${var.CMDS_ES_Cognito_Identity_Pool_Name}-unauthenticated-policy"
  role   = "${aws_iam_role.ES_Identity_Pool_Unauthenticated_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}
resource "aws_cognito_identity_pool_roles_attachment" "ES_ID_Pool_Role_Attachment" {
  identity_pool_id    = "${aws_cognito_identity_pool.CMDS_ES_Cognito_Identity_Pool.id}"
  roles = {
    "authenticated"   = "${aws_iam_role.ES_Identity_Pool_Authenticated_Role.arn}"
    "unauthenticated" = "${aws_iam_role.ES_Identity_Pool_Unauthenticated_Role.arn}"
  }
}
resource "aws_iam_role" "ES_Cognito_Role" {
  name               = "${var.CMDS_ElasticSearch_Domain_Name}-cognito-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Cognito_Policy" {
  name   = "${var.CMDS_ElasticSearch_Domain_Name}-cognito-policy"
  role   = "${aws_iam_role.ES_Cognito_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPool",
                "cognito-idp:CreateUserPoolClient",
                "cognito-idp:DeleteUserPoolClient",
                "cognito-idp:DescribeUserPoolClient",
                "cognito-idp:AdminInitiateAuth",
                "cognito-idp:AdminUserGlobalSignOut",
                "cognito-idp:ListUserPoolClients",
                "cognito-identity:DescribeIdentityPool",
                "cognito-identity:UpdateIdentityPool",
                "cognito-identity:SetIdentityPoolRoles",
                "cognito-identity:GetIdentityPoolRoles"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "cognito-identity.amazonaws.com"
                }
            }
        }
    ]
}
EOF
}
resource "aws_elasticsearch_domain" "CMDS_ES_ElasticSearch_Domain" {
  domain_name           = "${var.CMDS_ElasticSearch_Domain_Name}"
  elasticsearch_version = "${var.CMDS_ElasticSearch_Domain_ES_Version}"

  cluster_config {
    dedicated_master_enabled = true
    zone_awareness_enabled   = true
    instance_type            = "${var.CMDS_ElasticSearch_Domain_Instance_Type}"
    instance_count           = "${var.CMDS_ElasticSearch_Domain_Instance_Count}"    
    dedicated_master_type    = "${var.CMDS_ElasticSearch_Domain_Instance_Type}"
    dedicated_master_count   = "${var.CMDS_ElasticSearch_Domain_Instance_Count}"
  }
  ebs_options {
      ebs_enabled  = true
      volume_type  = "gp2"
      volume_size  = "25"
  }
  encrypt_at_rest {
      enabled = true
  }
  node_to_node_encryption {
      enabled = true
  }
  snapshot_options {
    automated_snapshot_start_hour = 23
  }
  cognito_options {
      enabled          = true
      user_pool_id     = "${aws_cognito_user_pool.CMDS_ES_Cognito_User_Pool.id}"
      identity_pool_id = "${aws_cognito_identity_pool.CMDS_ES_Cognito_Identity_Pool.id}"
      role_arn         = "${aws_iam_role.ES_Cognito_Role.arn}"
  }
}