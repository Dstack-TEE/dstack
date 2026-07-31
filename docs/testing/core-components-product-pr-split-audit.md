# Core component product PR split audit

This document records the completion gates for replacing monolithic product PR #840.

## Inventory

The authoritative split-PR inventory is
[`core-components-product-pr-inventory.tsv`](core-components-product-pr-inventory.tsv).
It lists 130 product PRs (#842 through #970 plus #976), including each head branch, GitHub base,
and explicit dependency for every stacked PR.

The per-commit inventory is
[`core-components-product-pr-accounting.tsv`](core-components-product-pr-accounting.tsv).
It classifies all 332 historical commits from #840.

## Mechanical gates

The final audit applies these gates:

1. Every PR from #842 through #970 plus #976 exists and is open.
2. Every accounting target branch exists remotely and has an open PR.
3. Every direct PR is based on `master`.
4. Every non-`master` PR title starts with `[STACKED on #NNN]`, where `#NNN`
   is the PR owning its actual GitHub base branch.
5. Every stacked PR body names the same parent and warns about merge order.
6. The declared base is an ancestor of every split head.
7. Every split product diff is non-empty, passes `git diff --check`, and excludes
   `REUSE.toml`, `docs/test-plans/**`, `docs/testing/**`, and `tools/dstack-test/**`.
8. Every `RETAINED` accounting row has an exact stable patch-ID match in the
   delta of one of its declared target PRs.
9. Every `MANUAL` target is compiled against its declared PR base and reviewed
   as an upstream-adapted preservation of the named behavior.
10. Rewritten dependency chains are compiled again after their final ancestry
    changes.

## Coverage model

Historical commits with no intended standalone product delta are explicitly
classified as `TEST_ONLY`, `REVERTED`, `EXISTING_PR`, or `SUPERSEDED`; they are
not silently omitted. `RETAINED` and `MANUAL` rows map to the split product PRs.
The existing independent WireGuard fix is #839, and compatibility RPC behavior
is superseded by merged upstream PR #830.

PR #841 is based directly on `master` and contains only test infrastructure,
evidence, documentation, and these accounting artifacts.
