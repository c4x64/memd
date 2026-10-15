# KernelCI Kernel Build Batches

The `prepare-kcidb-batch` job retrieves verified KernelCI builds from
the public Maestro mirror first (`https://api.kernelci.org`, no
credentials needed; `kcidb_mirror.py` pages passing `kbuild` nodes and
maps them onto the manifest schema with `device_class: "maestro"`).
BigQuery (`kernelci-production.kernelci_production`) remains as an
authenticated fallback when the mirror falls short, and a prior
manifest artifact can be resumed via `manifest_run_id`. Every source
requires at least 10,001 unique targets. The manifest validator checks
a complete result against the source counts; a truncated result is
rejected rather than reported as complete. The source count and each
target's source URL, commit, `.config` URL, architecture, and
configuration name are retained in a GitHub Actions artifact named
`kernelci-manifest`.

Before running the workflow, create a repository Actions secret named
`KCIDB_GCP_CREDENTIALS` and place within it a Google service-account JSON
key. BigQuery query jobs are billed to the GCP project identified by the
key's `project_id`; the workflow reads the source tables from
`kernelci-production.kernelci_production`. Enable the BigQuery API and grant
the service account BigQuery Job User (`roles/bigquery.jobUser`) on its
credential project. It must also have BigQuery Data Viewer
(`roles/bigquery.dataViewer`) access to the `kernelci_production` dataset.
This key is used solely by the manifest-query job; kernel builds do not
require it.

Each run compiles at most 250 manifest records, with at most 32 jobs
running concurrently. A batch result stores its module, result JSON, and build
log as GitHub Actions artifacts. Kernel source checkouts are cached by
target key in GitHub Actions Cache; entries are retained on a best-effort
basis and may be evicted. Kernel sources and build outputs are not saved
to a device.
Build failures are reported per target rather than skipped. The module
contains architecture- and kernel-version-specific code; accordingly,
cross-architecture and older-kernel jobs may reveal portability
deficiencies until the relevant code paths have been revised.

To continue processing a manifest, dispatch the workflow again with:

- `manifest_run_id`: the run ID displayed in the preceding run's summary.
- `batch_offset`: the precise `next_offset` displayed in that summary.

The manifest is retained for 90 days and uploaded anew whenever a run is
resumed, thereby extending its availability. To begin a fresh query, leave
`manifest_run_id` empty and set `batch_offset` to `0`.

Release publication is separate from ordinary CI. Pushes and scheduled
runs build and retain artifacts but do not publish a release. A manual
workflow dispatch requires a release channel: `alpha`, `beta`, `rc`, or
`stable`. The first three create pre-releases; `stable` creates a full
release. Publication occurs only after the build and packaging jobs
succeed. Pre-release tags take the form `rwbridge-<channel>-<run-number>`;
stable tags take the form `rwbridge-<run-number>`.
<!-- .github/scripts/KCIDB_BUILDING.md[∂ µ∂] -->
