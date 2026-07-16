# Benchmark Data

Each CVE is organized as `benchmark/<CWE>/<CVE-ID>/` containing:
- `metadata.json` — run history and CVE attributes
- `all_fixes.md` — side-by-side human vs AI fix comparison
- `verdicts/pr_<N>_verdict.json` — per-PR council and human verdicts

## Editing Verdict Files

To add a human verdict, append an entry to the `human_verdicts` array in the relevant `pr_<N>_verdict.json`:

```json
"human_verdicts": [
  {
    "name": "Shivani",
    "date": "2026-07-16",
    "classification": "Accepted",
    "reasoning": "The AI fix correctly addresses the vulnerability..."
  }
]
```

### Fields

| Field | Type | Values |
|---|---|---|
| `name` | string | Reviewer's name. Leave as `""` to remain anonymous. |
| `date` | string | ISO date: `YYYY-MM-DD` |
| `classification` | string | `"Accepted"` or `"Rejected"` |
| `reasoning` | string | Free-text explanation of the verdict. |
