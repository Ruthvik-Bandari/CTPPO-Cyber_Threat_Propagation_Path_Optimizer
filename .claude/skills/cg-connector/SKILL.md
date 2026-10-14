---
name: cg-connector
description: Build a bounded adapter for one named tool (Elasticsearch schema read, Git rule import, Atomic Red Team capture import, Zeek/Suricata JSON, Wazuh alerts, osquery output) using describe_schema, fetch_fixture and execute_read_query with allowlisted endpoints and credential references. Use when integrating a specific named tool. Do not use for generic shell execution, scanning, or active lab execution without a separate reviewed capability.
---

# Bounded connector adapter

Plan refs: section 15 (all), 6 (trust boundaries), 7 (ConnectorConfig), 16.

## Expected inputs

- The named tool and the phase from the section 15 table (core, extension, deferred).
- The evidence the repair workflow needs from it.
- Allowlisted host, scheme and port, and a credential reference name (never the secret).

## Steps

1. Confirm the tool is justified by a repair workflow need. Deferred tools (scanners, Splunk) need a documented demonstrated workflow first.
2. Define the adapter: name, version, supported schemas, capabilities, health check, timeout, pagination, limits, credential ref, output manifest.
3. Implement only describe_schema, fetch_fixture and execute_read_query. Deployment or active lab execution is a separate capability requiring a target allowlist and explicit operator action.
4. Enforce host and scheme allowlists; block redirects to non-allowlisted hosts, link-local and cloud metadata addresses (169.254.169.254, fd00:ec2::254) and unrelated internal services.
5. Use minimum-privilege, read-only credentials resolved from local secret references; redact auth material from logs, evidence and prompts.
6. Hash imported artifacts and feed them through cg-telemetry-ingest validation. Imported output is untrusted data.
7. Update the capability matrix (UI and CLI response): importing a tool's output does not mean CyberGuard can run the tool or support its rule semantics.
8. Tests: SSRF attempts, redirect bypass, oversized response, timeout, secret redaction.

## Output evidence

- Adapter contract, allowlist config, test output, capability matrix diff.

## Failure conditions (stop and report)

- The request turns an import into an unrestricted scan, arbitrary URL fetch or shell command.
- Credentials would be stored in config, evidence or prompts.
- The target is not explicitly authorized lab or local infrastructure.
