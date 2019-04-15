resource "aws_waf_sql_injection_match_set" "Global_WAF_SQLi_MatchSet" {
  name = "${var.GlobalWAFSQLIMatchSetName}"
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "URI"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "URI"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "BODY"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "BODY"
    }
  }  
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Cookie"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Cookie"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
}
resource "aws_waf_xss_match_set" "Global_WAF_XSS_MatchSet" {
  name = "${var.GlobalWAFXSSMatchSetName}"
  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "BODY"
    }
  }
  xss_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "BODY"
    }
  }
  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  xss_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }
  xss_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }
  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "URI"
    }
  }
  xss_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "URI"
    }
  }
}
resource "aws_waf_size_constraint_set" "Global_WAF_SizeConstraint_MatchSet" {
  name = "${var.GlobalWAFSizeConstraintMatchSetName}"
  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "${var.WAFConstraintSet_URI_Size}"
    field_to_match {
      type = "URI"
    }
  }
  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "${var.WAFConstraintSet_QueryString_Size}"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "${var.WAFConstraintSet_Body_Size}"
    field_to_match {
      type = "BODY"
    }
  }
  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "${var.WAFConstraintSet_Cookie_Header_Size}"
    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }
}