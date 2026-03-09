# Response-level policy for upstream prompt-injection and secret exfiltration patterns.
package aegis.response

default allow = true

# Reject common instruction-hijack patterns in model/tool responses.
allow = false {
  input.body != null
  body_text := lower(input.body)
  regex.match("ignore (all|any|previous) (instructions|rules)", body_text)
}
reason = "response contains instruction-hijack pattern" {
  input.body != null
  body_text := lower(input.body)
  regex.match("ignore (all|any|previous) (instructions|rules)", body_text)
}
response_injection = "ResponseInjection" {
  input.body != null
  body_text := lower(input.body)
  regex.match("ignore (all|any|previous) (instructions|rules)", body_text)
}

# Block likely system prompt disclosure attempts.
allow = false {
  input.body != null
  body_text := lower(input.body)
  contains(body_text, "system prompt")
  contains(body_text, "do not reveal")
}
reason = "response indicates possible system-prompt leakage" {
  input.body != null
  body_text := lower(input.body)
  contains(body_text, "system prompt")
  contains(body_text, "do not reveal")
}
response_injection = "ResponseInjection" {
  input.body != null
  body_text := lower(input.body)
  contains(body_text, "system prompt")
  contains(body_text, "do not reveal")
}

# Block explicit credential markers in plaintext responses.
allow = false {
  input.body != null
  body_text := lower(input.body)
  regex.match("(api_key|apikey|secret_key|secretkey|private_key|privatekey)[ \\t]*[=:]", body_text)
}
reason = "response appears to contain credential-like secrets" {
  input.body != null
  body_text := lower(input.body)
  regex.match("(api_key|apikey|secret_key|secretkey|private_key|privatekey)[ \\t]*[=:]", body_text)
}
response_injection = "ResponseInjection" {
  input.body != null
  body_text := lower(input.body)
  regex.match("(api_key|apikey|secret_key|secretkey|private_key|privatekey)[ \\t]*[=:]", body_text)
}
