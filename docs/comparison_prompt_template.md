# Fix Comparison Prompt Template

Reusable prompt for evaluating AppSecAI-generated fixes against human-written fixes. Submit to multiple LLMs (Claude, GPT-4o, Gemini) per CVE. Disagreements between models should be flagged for human review.

---

## Prompt

You are a security code reviewer. You will be shown a real vulnerability, the original vulnerable code, a human-written fix that was actually merged to resolve it, and an AI-generated fix produced independently (without seeing the human fix). Your job is to judge the quality of the AI-generated fix.

### Vulnerability

- **CVE ID:** [CVE-ID]
- **CWE:** [CWE-ID and name]
- **Severity:** [severity]
- **Description:** [1-2 sentence description of the vulnerability]

### Original Vulnerable Code

```java
[paste vulnerable code block]
```

### Human Fix (actually merged upstream)

```java
[paste human after/patched code block]
```

### AI-Generated Fix (AppSecAI, generated independently)

```diff
[paste AppSecAI's diff/proposed code]
```

### Your task

Evaluate the AI-generated fix against the human fix and answer:

1. **Classification** — choose exactly one:
   - **Equivalent** — fixes the same root cause in a functionally equivalent way, even if implementation differs stylistically
   - **Better** — fixes the root cause and is more robust, complete, or maintainable than the human fix
   - **Partial** — fixes the immediate reported issue but misses related cases, edge conditions, or doesn't fully close the vulnerability class
   - **Incorrect** — does not fix the vulnerability, fixes the wrong thing, or introduces a new issue
   - **Miss** — fails to identify any fix at all

2. **Reasoning** — 2-4 sentences explaining your classification. Be specific about what matches, differs, or is missing compared to the human fix.

3. **Risk flag** — does the AI fix introduce any new bug, regression, or behavior change not present in the human fix? Yes/No + explanation if yes.

4. **Confidence** — High/Medium/Low confidence in your own classification above.

Respond in this exact format:

```
Classification: [one of the 5 options]
Reasoning: [2-4 sentences]
Risk flag: [Yes/No] — [explanation if yes]
Confidence: [High/Medium/Low]
```

---

## Usage notes

- Run this same prompt through at least 2-3 different models (e.g. Claude, GPT-4o, Gemini) per CVE — disagreements between models are worth flagging for human review.
- Log every result in `pipeline_data/fix_comparisons.json` (CVE ID, model, classification, reasoning, risk flag, confidence, date).
- A "Partial" or "Incorrect" classification with high confidence across multiple models is exactly the kind of gap analysis Kevin wants — write these up as case studies.
- Keep the vulnerable/human-fix/AI-fix code blocks verbatim from `fixes/*.md` and the actual PR diff.
