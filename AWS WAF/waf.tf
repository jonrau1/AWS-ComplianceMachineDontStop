resource "aws_waf_rule" "Global_WAF_Rule_IPSet_Blacklist" {
  name        = "${var.GlobalWAFRuleIPSetBlacklistName}"
  metric_name = "${var.GlobalWAFRuleIPSetBlacklistMetricName}"
  predicates {
    data_id = "${aws_waf_ipset.Global_WAF_IPSet.id}"
    negated = false
    type    = "IPMatch"
  }
}
resource "aws_waf_rule" "Global_WAF_SQLi_MatchSet" {
  name        = "${var.GlobalWAFRuleSQLiMatchSetName}"
  metric_name = "${var.GlobalWAFRuleSQLiMatchSeMetricName}"
  predicates{
    data_id = "${aws_waf_sql_injection_match_set.Global_WAF_SQLi_MatchSet.id}"
    negated = false
    type = "SqlInjectionMatch"
  }
}
resource "aws_waf_rule" "Global_WAF_Rule_XSS_MatchSet" {
  name        = "${var.GlobalWAFRuleXSSMatchSetName}"
  metric_name = "${var.GlobalWAFRuleSXSSMatchSeMetricName}"
  predicates {
    data_id = "${aws_waf_xss_match_set.Global_WAF_XSS_MatchSet.id}"
    negated = false
    type = "XssMatch"
  }
}
resource "aws_waf_rule" "Global_WAF_Rule_SizeConstraint_MatchSet" {
  name        = "${var.GlobalWAFSizeConstraintMatchSetName}"
  metric_name = "${var.GlobalWAFRuleSConstraintSizeMatchSeMetricName}"
  predicates {
    data_id = "${aws_waf_size_constraint_set.Global_WAF_SizeConstraint_MatchSet.id}"
    negated = false
    type = "SizeConstraint"
  }
}
resource "aws_waf_web_acl" "Global_WAF_Blacklist_WACL" {
  name        = "${var.GlobalWAFWebACLName}"
  metric_name = "${var.GlobalWAFWebACLMetricName}"
  default_action {
    type = "ALLOW"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = "${aws_waf_rule.Global_WAF_Rule_IPSet_Blacklist.id}"
    type     = "REGULAR"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 2
    rule_id  = "${aws_waf_rule.Global_WAF_SQLi_MatchSet.id}"
    type     = "REGULAR"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 3
    rule_id  = "${aws_waf_rule.Global_WAF_Rule_XSS_MatchSet.id}"
    type     = "REGULAR"
  }
   rules {
    action {
      type = "BLOCK"
    }
    priority = 4
    rule_id  = "${aws_waf_rule.Global_WAF_Rule_SizeConstraint_MatchSet.id}"
    type     = "REGULAR"
  }
}