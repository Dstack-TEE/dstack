# Documentation Writing Guide

Guidelines for writing dstack documentation, README, and marketing content.

## Writing Style

- **Don't over-explain** why a framework is needed — assert the solution, hint at alternatives being insufficient
- **Avoid analogies as taglines** (e.g., "X for Y") — if it's a new category, don't frame it as a better version of something else
- **Problem → Solution flow** without explicit labels like "The problem:" or "The solution:"
- **Demonstrate features through actions**, not parenthetical annotations
  - Bad: "Generates quotes (enabling *workload identity*)"
  - Good: "Generates TDX attestation quotes so users can verify exactly what's running"

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

## Security Documentation

### Trust Model Framing

**Distinguish trust from verification:**
- "Trust" = cannot be verified, must assume correct (e.g., hardware)
- "Verify" = can be cryptographically proven (e.g., measured software)

**Correct framing:**
- Bad: "You must trust the OS" (when it's verifiable)
- Good: "The OS is measured during boot and recorded in the attestation quote. You verify it by..."

### Limitations: Be Honest, Not Alarmist

State limitations plainly without false mitigations:
- Bad: "X is a single point of failure. Mitigate by running your own X."
- Good: "X is protected by [mechanism]. Like all [category] systems, [inherent limitation]. We are developing [actual solution] to address this."

Don't suggest mitigations that don't actually help. If something is an inherent limitation of the technology, say so.

## Documentation Quality Checklist

From doc-requirements.md:

1. **No bullet point walls** — Max 3-5 bullets before breaking with prose
2. **No redundancy** — Don't present same info from opposite perspectives
3. **Conversational language** — Write like explaining to a peer
4. **Short paragraphs** — Max 4 sentences per paragraph
5. **Lead with key takeaway** — First sentence tells reader why this matters
6. **Active voice** — "TEE encrypts memory" not "Memory is encrypted by TEE"
7. **Minimal em-dashes** — Max 1-2 per page, replace with "because", "so", or separate sentences

### Redundancy Patterns to Avoid

These often say the same thing:
- "What we protect against" + "What you don't need to trust"
- "Security guarantees" + "What attestation proves"

Combine into single sections. One detailed explanation, brief references elsewhere.

## README Structure

### Order Matters
- **Quick Start before Prerequisites** — Lead with what it does, not setup
- **How It Works after Quick Start** — Users want to run it first, understand later
- Cleanup at the end, Further Reading last

### Don't Duplicate
- Link to conceptual docs instead of repeating content
- If an overview README duplicates an example README, cut the overview
- One detailed explanation, brief references elsewhere

### Remove Unrealistic Sections
- If most users can't actually do something (e.g., run locally without special hardware), don't include it
- Don't document workflows that require resources users don't have

### Match the Workflow to the User
- Use tools your audience already knows (e.g., Jupyter for ML practitioners)
- Prefer official/existing images when they exist — don't reinvent
- Make the correct path the default, mention alternatives briefly

## Code Examples

### Question Every Snippet
- Does this code actually demonstrate something meaningful?
- Would a reader understand what it does without the prose?
- `do_thing(b"magic-string")` means nothing — show real use or remove it

### Diagrams
- Mermaid over ASCII art — GitHub renders it nicely
- Keep diagrams simple — 3-5 nodes max
- Label edges with actions, not just arrows

## Conciseness

### Less is More
- 30 lines beats 150 if it says the same thing
- Cut sections that don't help users accomplish their goal
- Tables for reference, prose for explanation — don't over-table

### Performance and Benchmarks
- One memorable number + link to full report
- Don't overwhelm with data the reader didn't ask for

### Reader-First Writing
- Ask "what does the reader want to know?" not "what do I want to say?"
- If a section answers a question nobody asked, cut it

## Maintenance

### Consistency Checks
- After terminology changes, grep for related terms across all files
- Use correct industry/vendor terminology (e.g., "Confidential Computing" not "Encrypted Computing")

### Clean Up Old Files
- When approach changes, delete orphaned files (old scripts, Dockerfiles)
- Don't leave artifacts from previous implementations
