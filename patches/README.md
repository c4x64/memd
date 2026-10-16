# patches — local adjustments against pinned upstream mirrors (if ever needed)

Today: empty. This repo re-implements behavior instead of patching
upstream code, so no patches ship.

If a pin-update review ever requires carrying a local delta:
- Put it here as `patches/<name>/NNN-short-reason.patch` (unified diff
  against the pinned SHA in `third_party/pins.json`).
- `tools/sync-upstream.py` applies it `--3way` to the fresh mirror.
- If it does not apply cleanly the sync ABORTS and a MANUAL merge fix
  is required: resolve inside `third_party/upstream/<name>/`, refresh
  the patch, re-run sync, then run the full app test suite + CI.
- Record every patch and its reason in `UPSTREAM.md`.
