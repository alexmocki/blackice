# Decisions Normalization Contract 📜

This document describes the **Normalization Contract** for `decisions.jsonl` used by the BlackIce pipeline and API. The goal is to make normalization deterministic, idempotent, auditable, and minimal (no semantic changes).

## Principles ✨

- **Deterministic serialization** — output must use stable JSON serialization so byte-for-byte comparisons are meaningful (use `json.dumps(..., ensure_ascii=False, sort_keys=True)`).
- **Idempotent** — running normalization more than once must not change the output further.
- **No semantic mutation** — normalization must not change domain semantics (decisions, risk, rule_id, etc.). It may only canonicalize representation.
- **Auditable** — normalization should be observable (report counts, and when changed) to enable `warn` and `strict` audit modes.

## Invariants 🔒

1. Evidence rows must include `subject_type` and `subject_id` when available on the decision. Normalization must inject missing subject identity into evidence rows (not overwrite existing identity fields).
2. Remove blank lines and non-deterministic formatting (stable ordering of keys, consistent quoting and encoding).
3. Normalize primitive types where appropriate (e.g., `subject_id` as a string) to avoid accidental diffs.
4. Produce an `(total_read, total_written)` pair and make it easy to detect `changed` (for example, by comparing bytes/sha256 of the output).

## Audit Modes (Behavior) ⚖️

- **off**: do not run normalization or gate the pipeline.
- **warn**: run normalization and record `normalized_count` in the summary; continue execution.
- **strict**: if normalization changes the output, the pipeline should fail with a structured error (HTTP 409 `AUDIT_NORMALIZATION` when used via the API) and include details (e.g., `normalized_count`, `audit_mode`).

## Recommended Tests ✅

- **Propagation test**: evidence rows get `subject_type`/`subject_id` when decision has them.
- **Idempotency test**: applying normalization twice yields identical output.
- **Strict-mode rejection test**: API returns 409 when `audit_mode=strict` and normalized output differs.
- **No-op test**: normalization does nothing on already-normalized files.

## Implementation Notes 🔧

- Centralize normalization in a single function (e.g., `blackice.cli.validate.normalize_decisions_jsonl`) used by CLI and API.
- Write to a temporary file and atomically replace the original when appropriate.
- Consider adding `normalization_version` and/or a SHA256 fingerprint in the summary for traceability.

---

If you want, I can add a short `example-normalization.jsonl` fixture and a CI check to ensure normalization stays stable across changes.