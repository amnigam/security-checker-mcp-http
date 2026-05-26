"""Central size limits for the stateless scan tool.

Both limits are defined here so they can be tuned in one place and are
referenced consistently by the scan tool, its description, and the
self-correcting overflow error.

- PER_FILE_MAX_BYTES: any single file larger than this is skipped (not
  reviewed) and reported in the scan result's "skipped" list.
- BATCH_MAX_BYTES: if the combined content of one scan() call exceeds
  this, the call is rejected with a payload_too_large error instructing
  the caller to split into smaller batches.
"""

PER_FILE_MAX_BYTES = 1 * 1024 * 1024   # 1 MB per file
BATCH_MAX_BYTES = 6 * 1024 * 1024      # 6 MB combined per scan() call


def mb(n_bytes: int) -> str:
    """Human-readable MB string for messages."""
    return f"{n_bytes / (1024 * 1024):.1f} MB"
