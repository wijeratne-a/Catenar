# Request-level payload policy for Catenar proxy (A2T/A2A/A2D).
# Evaluates decrypted HTTP request: method, path, host, body, headers, identity.
# input.topology is available ("a2a" when both x-catenar-caller and x-catenar-trace present, else "tool").
package catenar.payload

default allow = true
default reason = ""
default violation_type = ""
default suggestion = ""

# Identity fields in payload policy are currently advisory only.
# Authoritative identity/task binding is enforced by verifier task tokens.

# Deny if body.text matches SSN-like pattern (A2T).
allow = false {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}
reason = "body contains SSN-like pattern" {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}
violation_type = "sensitive_data_exposure" {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}
suggestion = "Remove or redact SSN-like patterns from the request body before sending" {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}

# A2A: when x-catenar-caller is present (agent-to-agent), require x-catenar-trace for audit chain.
allow = false {
  caller := input.headers["x-catenar-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-catenar-trace"]
  trace == null
}
reason = "A2A call requires x-catenar-trace header" {
  caller := input.headers["x-catenar-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-catenar-trace"]
  trace == null
}
violation_type = "missing_audit_trace" {
  caller := input.headers["x-catenar-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-catenar-trace"]
  trace == null
}
suggestion = "Add x-catenar-trace header with the parent trace when making agent-to-agent calls" {
  caller := input.headers["x-catenar-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-catenar-trace"]
  trace == null
}
