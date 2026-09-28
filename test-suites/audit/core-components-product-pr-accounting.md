# Core component product commit accounting

This inventory accounts for every commit formerly carried by product PR #840.

- `RETAINED`: the stable patch is present on one or more split product branches.
- `MANUAL`: the behavior is retained, but conflict resolution or upstream adaptation changed its stable patch ID.
- `EXISTING_PR`: an already-open independent PR carries the change.
- `SUPERSEDED`: a newer implementation is already present upstream.
- `REVERTED`: the historical commit and its revert have no net product effect.
- `REJECTED`: review determined that the historical change weakens the intended behavior, so it is deliberately not carried forward.
- `TEST_ONLY`: test-only, formatting, fixture, or test dependency work; it is not a standalone product bug.

The TSV is the authoritative per-commit inventory. It contains all 332 commits with no unclassified rows.
