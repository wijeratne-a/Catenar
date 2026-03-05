package aegis

default allow = false
default reason = "policy denied request"

allow {
  input.agent_metadata.domain == "defi"
  not blocked
}

reason = "restricted endpoint access"

blocked {
  endpoint := input.public_values.restricted_endpoints[_]
  contains(input.execution_trace[_].target, endpoint)
}
