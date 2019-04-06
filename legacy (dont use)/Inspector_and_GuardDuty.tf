resource "aws_inspector_resource_group" "inspect-group" {
  tags = {
    Name = "Main Inpsector Target Group"
    Env  = "Non-Prod"
  }
}

resource "aws_inspector_assessment_target" "inspect-target" {
  name               = "target-all"
  // not specifiying 'resource_group_arn' will apply to all EC2 w/ Inspector Agent
}

resource "aws_inspector_assessment_template" "inspect-temp" {
  name       = "assess-all"
  target_arn = "${aws_inspector_assessment_target.inspect-target.arn}"
  duration   = 3600

  rules_package_arns = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // CVE
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OS SecConf B-Mark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // Sec Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability / TRANSEC
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h", // RBA (Runtime Behavior Analytics)
   // us-west2rules
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p",  // CVE
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc",  // CIS
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl",  // SEC BP
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ",  // TRANSEC
   // "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-vg5GGHSD",  // RBA
   // us-west1rules
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa",  // CVE
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX",  // CIS
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF",  // SEC BP
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm",  // TRANSEC
   // "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0",   // RBA
  ]
}

// The Detector is what GuardDuty uses to Aggregate Findings -- Terraform Destroy will totally remove GuardDuty, using 'enable = false' will SUSPEND GuardDuty instead
resource "aws_guardduty_detector" "MyDetector" {
  enable = true
  finding_publishing_frequency = "SIX_HOURS"
}