# KernelCI kernel build batches

The `prepare-kcidb-batch` job reads valid `kernelci` builds from the
`kernelci-production.kernelci_production` BigQuery dataset. It includes
every eligible distinct kernel/configuration/architecture target across
Ranchu and consumer builds and requires at least 10,001 targets. The
manifest validator checks the complete query result against BigQuery's
source count so truncated results fail instead of being reported as
complete. The source count and each target's source URL, commit, `.config`
URL, architecture, and configuration name are retained in a GitHub
Actions artifact named `kernelci-manifest`.

Before running the workflow, add a repository Actions secret named
`KCIDB_GCP_CREDENTIALS` containing a Google service-account JSON key.
The service account needs permission to create BigQuery query jobs in
`kernelci-production` and read the `kernelci_production` dataset. The key
is used only in the manifest-query job; kernel builds run without it.

Each run compiles at most 256 manifest records, with at most 32 jobs
running at once. A batch result stores its module, result JSON, and build
log as GitHub Actions artifacts. Kernel source checkouts are cached by
target key in GitHub Actions Cache; entries are best-effort and may be
evicted. No kernel sources or build outputs are saved to a device.
Build failures are reported per target rather than skipped. The module
still has architecture- and kernel-version-specific code, so the
cross-architecture and older-kernel jobs are expected to identify
portability gaps until those code paths are updated.

To continue a manifest, dispatch the workflow again with:

- `manifest_run_id`: the run ID shown in the previous run's summary.
- `batch_offset`: the exact `next_offset` shown in that summary.

The manifest is retained for 90 days and is re-uploaded on every resumed
run, extending its availability. Start a fresh query by leaving
`manifest_run_id` empty and `batch_offset` at `0`.
