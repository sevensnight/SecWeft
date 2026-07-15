# API Gateway

This edge service is the only platform component published outside the internal
Compose network. It serves the web console and routes versioned API, health, and
OpenAPI requests to the existing FastAPI control plane.

TLS is expected to terminate at the deployment ingress or load balancer. The
local Compose profile binds the gateway to `127.0.0.1` by default. No credential
is accepted in a URL, added by the gateway, or written to access logs.
