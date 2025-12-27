# Documentation Writing Guide

Guidelines for writing dstack documentation, README, and marketing content.

## Messaging

- **Primary keyword**: "Confidential AI" — use in tagline and first paragraph
- **Secondary keyword**: "Private AI" — use in explanatory context
- **Key differentiator**: NVIDIA Confidential Computing support (H100, Blackwell GPUs)
- **Base images**: `dstack-nvidia-0.5.x` for GPU TEE support

## Writing Style

- **Don't over-explain** why a framework is needed — assert dstack as the solution, hint at alternatives being insufficient
- **Avoid analogies as taglines** (e.g., "X for Y") — dstack is a new category, not a better version of something else
- **Problem → Solution flow** without explicit labels like "The problem:" or "The solution:"
- **Demonstrate features through actions**, not parenthetical annotations
  - Bad: "Generates quotes (enabling *workload identity*)"
  - Good: "Generates TDX attestation quotes so users can verify exactly what's running"

## Architecture Descriptions

When describing components for security researchers:
- Explain **what each component does** (actions)
- Show **how features emerge** from the architecture naturally
- Map components to security properties:
  - Guest Agent → workload identity, key isolation, disk encryption
  - KMS → code governance, key derivation bound to attested identity
  - Gateway → encrypted networking, RA-TLS
  - VMM → Docker Compose native, reproducible OS, GPU allocation

## Target Audiences

**Developers** care about:
- Easy onboarding (Docker Compose native)
- No code changes required
- Existing workflow compatibility

**Security researchers** care about:
- Trust model (what's trusted, what's not)
- How attestation proves code integrity
- How key management prevents operator access
- How code governance is enforced on-chain

## Feature-to-Component Mapping

| Feature | Component | How it works |
|---------|-----------|--------------|
| Workload identity | Guest Agent | TDX attestation quotes |
| Isolated keys | Guest Agent + KMS | Per-app key derivation bound to attested identity |
| Encrypted by default | Guest Agent (disk) + Gateway (TLS) | Ephemeral disk keys, RA-TLS |
| Code governance | KMS | On-chain smart contract policies |
| Docker Compose native | VMM | Direct parsing, no translation |
| Reproducible OS | VMM | Deterministic image builds |
| Confidential GPUs | VMM + hardware | NVIDIA H100/Blackwell allocation |

## Procedural Documentation (Guides & Tutorials)

### Test Before You Document
- **Run every command** before documenting it — reading code is not enough
- Commands may prompt for confirmation, require undocumented env vars, or fail silently
- Create a test environment and execute the full flow end-to-end

### Show What Success Looks Like
- **Add sample outputs** after commands so users can verify they're on track
- For deployment commands, show the key values users need to note (addresses, IDs)
- For validation commands, show both success and failure outputs

### Environment Variables
- **List all required env vars explicitly** — don't assume users will discover them
- If multiple tools use similar-but-different var names, clarify which is which
- Show the export pattern once, then reference it in subsequent commands

### Avoid Expert Blind Spots
- If you say "add the hash", explain how to compute the hash
- If you reference a file, explain where to find it
- If a value comes from a previous step, remind users which step

### Cross-Reference Related Docs
- Link to prerequisite guides (don't repeat content)
- Link to detailed guides for optional deep-dives
- Use anchor links for specific sections when possible
