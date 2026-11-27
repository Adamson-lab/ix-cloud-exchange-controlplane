package exchange.window

import rego.v1

default allow := false
default reason := "denied: port provision outside UTC window without active grace lock"

# Permit off-window changes up to 15 minutes when an active incident hold extends the maintenance lock.
grace_hold if {
	input.grace_extension.active == true
	count(input.grace_extension.incident_id) >= 4
	input.grace_extension.extra_minutes <= 15
	input.operator_role in {"ix-netops", "incident-lead"}
}

allow if {
	grace_hold
}

allow if {
	not grace_hold
	input.operator_role in {"ix-netops", "incident-lead", "exchange-bot"}
	input.utc_hour >= 2
	input.utc_hour <= 22
}

reason := "allowed via active 15m grace extension" if {
	allow
	grace_hold
}

reason := "allowed within UTC exchange window" if {
	allow
	not grace_hold
}
