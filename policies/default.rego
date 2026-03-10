package catenar

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

reason = "regulated domain requires model_id on all trace entries"

blocked {
  input.agent_metadata.domain == "regulated"
  entry := input.execution_trace[_]
  object.get(entry, "model_id", "") == ""
}
