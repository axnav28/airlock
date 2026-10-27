# Threat model and limitations

Airlock treats email, web results, and note/skill-like files as untrusted data. The planner and Reader can suggest actions, but the interpreter assigns runtime provenance and the deterministic policy engine evaluates final arguments immediately before adapter execution.

The demonstrated claim is narrower than “prompt injection is solved”: in the implemented adapters, an untrusted recipient cannot send email, a secret-derived query cannot reach search, and a path must be constrained to the synthetic fixture root. Tests assert the underlying operation did not execute after denial.

Out of scope are compromised host kernels, malicious dependencies, real provider-side account compromise, covert channels not represented by the adapters, and universal factual correctness of Reader summaries. NemoClaw/OpenShell can add lower-level network/filesystem/process controls, but it does not replace semantic authorization and is not claimed as installed in this checkout.
