package exchange.peering

import rego.v1

default allow := false
default reason := "denied: vlan or asn outside approved exchange boundary"

allow if {
	input.vlan_id >= 100
	input.vlan_id <= 3999
	input.asn >= 64512
	input.asn <= 65534
	input.region in {"us-east-1", "us-west-2", "eu-central-1"}
}

reason := "allowed: exchange peering parameters within approved range" if {
	allow
}
