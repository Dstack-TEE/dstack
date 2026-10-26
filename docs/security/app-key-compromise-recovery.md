# App Key Compromise Recovery

This guide applies when an app key may have been disclosed. It covers recovery
from vulnerabilities in application code, the dstack OS, and KMS. For reporting
a newly discovered vulnerability, follow [SECURITY.md](../../SECURITY.md) before
sharing exploit details.

## Recovery model

KMS derives an app's key from the KMS root key and the app ID. Removing an
allowed compose hash, OS image, or device prevents future key release, but does
not revoke key material that has already left KMS. Reusing the same app ID under
the same KMS root also reproduces the same app identity.

Consequently:

- if an app key may be disclosed, retire that app ID;
- if the KMS root key may be disclosed, retire the entire KMS trust domain.

dstack does not currently provide in-place app-key versioning or rotation. A
replacement identity is therefore the recovery boundary.

## Immediate containment

Before recovery:

1. Stop or isolate affected app and KMS instances.
2. Remove affected compose hashes, OS image hashes, and device IDs from the
   authorization policy.
3. Preserve attestation evidence, authorization history, logs, and relevant
   on-chain records for investigation.
4. Identify every app ID for which a key could have been obtained. If the scope
   cannot be established reliably, use the broader recovery case.

Containment stops further key release. It does not restore trust in an existing
app ID or KMS root.

## Choose the recovery boundary

| Compromise | Required recovery |
| --- | --- |
| Application code discloses its app key | Create a new app ID for that application. The existing KMS domain can remain in use. |
| A dstack OS vulnerability discloses app keys | Remove the vulnerable OS image and create new app IDs for every affected application. If KMS ran on the affected OS, treat the KMS root as potentially disclosed. |
| A KMS authorization vulnerability releases app keys but cannot expose the KMS root | Fix KMS and create new app IDs for every application whose key could have been released. If the affected set is unknown, replace all app IDs in the domain. |
| KMS software, its OS, or its TEE may expose the KMS root | Create a new KMS trust domain and new app IDs for every application. |

Arbitrary code execution inside KMS should normally be treated as potential
KMS-root disclosure: proving that an attacker did not copy a small root secret
is generally not possible.

## Replace an app identity

When the KMS root remains trusted:

1. Fix and review the vulnerable application or OS.
2. Deploy a new app contract to obtain a new app ID.
3. Allow only the fixed compose hash and trusted OS image and devices.
4. Deploy the application with the new app ID.
5. Rotate application credentials and any business keys that the old instance
   could access, including API tokens, database credentials, signing keys, and
   data-encryption keys.
6. Update relying parties to trust the new app ID and reject the old identity.

Treat data exported by a compromised instance as untrusted input. Validate it
before importing it, and re-encrypt retained confidential data under keys that
the old instance never possessed.

## Replace a KMS trust domain

When the KMS root may be disclosed, changing app IDs under that root is not a
recovery: an attacker with the root can derive their keys too. Instead:

1. Fix the KMS, OS, TEE, or authorization vulnerability and revoke the affected
   measurements.
2. Bootstrap a new KMS root in a trusted environment. Do not onboard or copy
   root-key material from the affected KMS domain.
3. Publish the new KMS public-key trust anchor and update the KMS contract or
   deployment configuration as applicable.
4. Create new app IDs for every application and rotate their credentials and
   business keys.
5. Update gateways, verifiers, clients, and other relying parties to reject the
   old KMS root and identities certified by it.

## Completion checklist

Recovery is complete only when:

- vulnerable measurements and old app IDs can no longer obtain keys;
- replacement instances attest to the expected fixed software and policy;
- replacement app keys differ from the compromised identities;
- affected credentials and data-encryption keys have been rotated;
- all relying parties reject old app IDs and, when applicable, the old KMS
  trust anchor.

See [On-chain Governance](../onchain-governance.md) for authorization controls
and the [Security Model](./security-model.md) for the underlying trust
boundaries.
