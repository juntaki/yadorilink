# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities by email to **me@juntaki.com**
rather than opening a public issue. Include as much detail as you can
(affected component, reproduction steps, potential impact) so it can be
triaged quickly. You should get an acknowledgment within a few days.

## Project status

YadoriLink is pre-1.0 and under active development. Until a 1.0 release:

- The CLI, IPC, and sync-protocol interfaces are not stable and may
  change between versions without a deprecation period.
- The cryptographic design (device identity, transport encryption, at-rest
  key handling) has not been through an independent third-party audit.
  Review the source yourself before relying on it for sensitive data.

## Scope

This applies to the client-side code in this repository: the CLI,
daemon, sync engine, transport/relay, local storage, and shell
integrations. The coordination-plane service itself is operated
separately and is out of scope for reports made here.
