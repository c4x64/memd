WITH versioned_checkouts AS (
  SELECT
    id AS checkout_id,
    tree_name,
    git_repository_url,
    git_repository_branch,
    git_commit_hash,
    git_commit_name
  FROM `kernelci-production.kernelci_production.checkouts`
  WHERE
    REGEXP_CONTAINS(git_commit_name, r'^v([4-9]|[1-9][0-9]+)\.[0-9]+')
    OR REGEXP_CONTAINS(
      LOWER(git_repository_branch),
      r'(android|goldfish)[^0-9]*(4\.[0-9]|[5-9]\.[0-9]|[1-9][0-9]+\.[0-9]+)'
    )
    OR REGEXP_CONTAINS(
      LOWER(git_repository_branch),
      r'android[0-9]+-[0-9]+\.[0-9]+'
    )
),
classified_builds AS (
  SELECT
    b.id AS build_id,
    b.checkout_id,
    b.architecture,
    b.config_name,
    b.config_url,
    b.compiler,
    b.valid,
    b.start_time AS build_time,
    vc.git_commit_name AS kernel_version,
    vc.git_commit_hash AS kernel_hash,
    vc.git_repository_url,
    vc.git_repository_branch AS kernel_branch,
    vc.tree_name,
    CASE
      WHEN LOWER(b.config_name) LIKE '%goldfish%' THEN 'ranchu'
      WHEN LOWER(b.config_name) LIKE '%ranchu%' THEN 'ranchu'
      WHEN LOWER(vc.tree_name) LIKE '%goldfish%' THEN 'ranchu'
      WHEN LOWER(vc.git_repository_branch) LIKE '%goldfish%' THEN 'ranchu'
      ELSE 'oem_consumer'
    END AS device_class
  FROM `kernelci-production.kernelci_production.builds` AS b
  INNER JOIN versioned_checkouts AS vc
    ON b.checkout_id = vc.checkout_id
  WHERE b.valid IS TRUE
    AND LOWER(b.origin) = 'kernelci'
    AND STARTS_WITH(LOWER(b.config_url), 'https://')
    AND STARTS_WITH(LOWER(vc.git_repository_url), 'https://')
    AND REGEXP_CONTAINS(
      vc.git_commit_hash,
      r'^[0-9A-Fa-f]{40}([0-9A-Fa-f]{24})?$'
    )
    AND NULLIF(TRIM(b.architecture), '') IS NOT NULL
    AND NULLIF(TRIM(b.config_name), '') IS NOT NULL
    AND NULLIF(TRIM(vc.git_repository_branch), '') IS NOT NULL
    AND NULLIF(TRIM(vc.tree_name), '') IS NOT NULL
    AND NULLIF(TRIM(vc.git_commit_name), '') IS NOT NULL
),
unique_builds AS (
  SELECT * EXCEPT (dedupe_rank)
  FROM (
    SELECT
      classified_builds.*,
      ROW_NUMBER() OVER (
        PARTITION BY
          kernel_hash,
          git_repository_url,
          kernel_branch,
          tree_name,
          architecture,
          config_name,
          device_class
        ORDER BY build_time DESC, build_id
      ) AS dedupe_rank
    FROM classified_builds
  )
  WHERE dedupe_rank = 1
),
source_counts AS (
  SELECT
    COUNT(*) AS source_unique_count,
    COUNTIF(device_class = 'ranchu') AS source_ranchu_count,
    COUNTIF(device_class = 'oem_consumer') AS source_consumer_count
  FROM unique_builds
),
ranked_builds AS (
  SELECT
    unique_builds.*,
    source_counts.source_unique_count,
    source_counts.source_ranchu_count,
    source_counts.source_consumer_count,
    ROW_NUMBER() OVER (
      PARTITION BY device_class
      ORDER BY build_time DESC, build_id
    ) AS class_seq
  FROM unique_builds
  CROSS JOIN source_counts
)
SELECT
  kernel_version,
  kernel_hash,
  kernel_branch,
  git_repository_url,
  tree_name,
  device_class,
  build_id,
  checkout_id,
  architecture,
  config_name,
  config_url,
  compiler,
  valid,
  build_time,
  source_unique_count,
  source_ranchu_count,
  source_consumer_count
FROM ranked_builds
ORDER BY class_seq, device_class, build_id;
-- .github/scripts/kcidb_builds.sql[∂]
