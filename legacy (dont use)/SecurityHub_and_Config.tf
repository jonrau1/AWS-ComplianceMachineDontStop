// Previous usage of Config will leave a Recorder and Delivery Channel in place, Terraform will fail since you can only have ONE
// use AWS CLI to delete recorder & delivery channel and manage state from TF
// aws configservice describe-configuration-recorder-status
// aws configservice delete-configuration-recorder --configuration-recorder-name <name>
// aws configservice describe-configuration-recorder-status
// aws configservice delete-delivery-channel --delivery-channel-name default

resource "aws_config_configuration_recorder_status" "config-status" {
  name       = "${aws_config_configuration_recorder.config-recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.config-delivchan"]
}

resource "aws_iam_role_policy_attachment" "a" {
  role       = "${aws_iam_role.configrole.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_s3_bucket" "b" { // very bad bucket -- add KMS/CT/Access Logging,etc
  bucket_prefix = "awsconfig-example"
}

resource "aws_config_delivery_channel" "config-delivchan" {
  name           = "example"
  s3_bucket_name = "${aws_s3_bucket.b.bucket}"
  sns_topic_arn = "${aws_sns_topic.config-sns.id}"
}

resource "aws_sns_topic" "config-sns" {
  name = "ThisIsAConfigSNSTopic"
  kms_master_key_id = "alias/aws/sns" // put a KMS Key Here & share it with your config bucket
}

resource "aws_config_configuration_recorder" "config-recorder" {
  name     = "ThisIsAConfigRecorder"
  role_arn = "${aws_iam_role.configrole.arn}"
}

resource "aws_iam_role" "configrole" {
  name = "ThisIsAWSConfigRole"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "configpolicy" {
  name = "ThisIsAWSConfigRolePolicy"
  role = "${aws_iam_role.configrole.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.b.arn}",
        "${aws_s3_bucket.b.arn}/*"
      ]
    }
  ]
}
POLICY
}

resource "aws_securityhub_account" "sechub" {}
// Hits SecHub API - turns it on for account Auto-Enables CIS Benchmark Rules -- need to turn on config first