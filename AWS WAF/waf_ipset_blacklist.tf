resource "aws_waf_ipset" "Global_WAF_IPSet" {
  name = "${var.GlobalWAFIPSetName}"
  ip_set_descriptors {
    type  = "IPV4"
    value = "103.207.38.203/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "107.6.169.250/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "120.52.152.17/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "120.52.152.19/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "139.162.77.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "172.245.13.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "178.73.215.171/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "184.105.139.119/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "184.105.247.242/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "184.154.189.92/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "185.142.236.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "185.176.27.42/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "185.195.201.148/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "185.245.86.226/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "185.254.122.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "196.52.43.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "198.108.67.19/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "198.108.66.23/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "198.20.103.245/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "198.143.155.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "198.51.100.0/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "216.75.62.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "222.186.43.80/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "222.187.225.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "3.81.56.191/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "47.190.18.35/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "61.160.236.77/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "66.212.168.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "66.240.219.146/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "71.6.135.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "71.6.142.80/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "71.6.142.87/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "71.6.158.166/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "71.6.199.23/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "80.82.77.0/24"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "81.22.45.193/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "81.22.45.54/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "82.102.173.79/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "83.143.246.30/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "89.248.168.51/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "89.248.172.16/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "89.248.174.3/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "92.63.197.158/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "94.102.52.41/32"
  }
}