# TSK Protocol Specification: Wire Version 1

Normative behavior is defined in [../SPEC.md](../SPEC.md) and the executable
source. This path is retained for existing links.

## Security Model

TSK authenticates possession of a provisioned shared secret plus synchronized
server/client lifecycle state. It diversifies derived values across static,
time-window, and counter schedules. Generated credentials contain at least one
counter-based segment, and the server commits all counter and usage changes
atomically.

The following are explicitly not protocol properties:

- secret segment layout;
- hardware-backed identity;
- a digital signature or non-repudiation;
- FIPS 140 validation of an unspecified runtime;
- DoD Impact Level authorization or compliance;
- protection after shared-secret compromise.

## Provisioning

Provisioning returns the client ID and ordered segment metadata. The shared
secret is transferred separately through a deployment-controlled protected
channel and must be stored according to deployment policy. The server retains
the authoritative map, counters, lifecycle state, and secret.

## Lifecycle

States are `active`, `expiring`, `revoked`, and `expired`. `expiring` remains
valid only for the remaining authorized requests. At the hard cap, validation
denies. There is no permissive grace mode.

Authorized replacement writes the new credential and revokes the old one in a
single store operation. Implementations that cannot provide this atomicity do
not satisfy the store contract.

## Evidence Boundary

Repository tests cover named finite cases. Test success does not establish the
absence of unknown attacks, production readiness, or an external authorization.
