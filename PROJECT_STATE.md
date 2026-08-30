# PROJECT STATE — Article 9 Evidence Adapter
# Updated: 2026-08-30
# Source: full folder + git inspection by incoming LLM session

---

## PART A — CHAT / RESEARCH STATE

### Paper

**Title (fixed, do not alter):**
"Authorization Logs Are Not Compliance Evidence: The Article 9 Gap in Agent Harness Security"

**One-sentence contribution:**
Authorization logs prove a control fired; they do not prove Article 9's risk-management process exists, was followed, or produced an evidence record — the Evidence Adapter closes that gap by translating security telemetry into lifecycle compliance evidence.

**DOI / Zenodo:** 10.5281/zenodo.21834704 (v2 NOT YET PUSHED — pending eval results)

**Repo:** https://github.com/pavjstn-ui/article9-evidence-adapter

---

### Publication Order

Article 9 paper:
1. Zenodo — PUBLISHED (v1)
2. HAL — NEXT
3. SSRN — follows HAL
4. OpenAIRE indexing check
5. Slovak/EU repository
6. Open Research Europe eligibility check
7. No arXiv (no endorsement, user preference)

Rule: ONE PLATFORM AT A TIME.

---

### Section Status

| Section | Status |
|---------|--------|
| S1 Introduction | NOT WRITTEN — write last, after all other sections locked |
| S2 Article 9 analysis | DRAFTED — not on disk locally; was in previous chat session |
| S3 Four gaps | LOCKED |
| S4 Adapter architecture | LOCKED |
| S5 Implementation | LOCKED — 7/7 tests passing, pushed to remote |
| S6 Evaluation | DRAFTED (methodology only) — results NOT yet generated |
| S7 Limitations | NOT WRITTEN |
| CON Conclusion | NOT WRITTEN |

---

### Section 3 — Four Evidence Gaps (LOCKED)

**Gap 1 — Decision ≠ Risk**
Missing: authorization event → risk-register entry

**Gap 2 — Control ≠ Mitigation Evidence**
Missing: control → mitigation rationale + effectiveness assessment

**Gap 3 — Event ≠ Residual-Risk Assessment**
Missing: authorization decision → residual-risk determination → acceptability judgment

**Gap 4 — Log ≠ Lifecycle Evidence**
Missing: authorization event stream → pattern evaluation → risk re-assessment → documented update

Language discipline: use "cannot demonstrate", "does not by itself establish", "difficult to reconcile with" — NOT absolute legal claims.

---

### Section 4 — Evidence Adapter Architecture (LOCKED)

| Component | Maps gap | Function |
|-----------|----------|----------|
| C1 Risk-Register Linker | Gap 1 | decision → identified risk |
| C2 Mitigation-Rationale Recorder | Gap 2 | control → mitigation rationale/effectiveness |
| C3 Residual-Risk Assessor | Gap 3 | decision → residual risk |
| C4 Lifecycle Feedback Connector | Gap 4 | event stream → pattern/review → risk re-assessment |

Key constraint: the adapter MUST NOT autonomously determine acceptability. That is a human-review determination enforced in the data model (AcceptabilityStatus cannot reach HUMAN_REVIEWED_ACCEPTABLE without explicit `human_review(reviewer, acceptable)` call).

---

### Section 5 — Implementation (LOCKED)

Files: `evidence_adapter.py`, `test_adapter.py`
Test result: **7/7 passing** (custom harness — `python3 test_adapter.py`, not pytest)

Five issues identified and fixed before lock:
1. Count: six input stores (not five)
2. Timestamp schema/code discrepancy — resolved
3. T1: external write receiving ALLOW (not internal file read)
4. T4: unlinked rule with no risk-register mapping (not a "policy change" event); key result: produces evidence failure, not plausible-but-ungrounded record
5. C1 incremental claim: incremental closure is an architectural property, not demonstrated by the prototype

Known limitations (Section 5.6 — do NOT hide these):
- No persistence
- No pattern detection beyond sliding window
- Single-agent model

Strongest result: T4 — unlinked rule produces self-documenting evidence failure.

Implementation details:
- C4 uses `deque(maxlen=W)` sliding window, W=50 default, W=20 for eval
- `agent_id` and `task_id` are both first-class fields on `AuthorizationEvent` (agent_id ≠ task_id)
- `sequence_id` also present on AuthorizationEvent

---

### Section 6 — Evaluation (METHODOLOGY DRAFTED, NO RESULTS)

**DO NOT fabricate results.**

Objectives:
- O1: Real workload — AgentDojo v0.1.35 events, not hand-constructed fixtures
- O2: Pattern signal vs noise — C4 precision/recall/FP/FN rate
- O3: Schema coherence under chaining — traceability across tool-call sequences

Planned structure: 6.1 Objectives / 6.2 AgentDojo Integration / 6.3 Pattern Detection / 6.4 Multi-Rule Chained / 6.5 Results / 6.6 Interpretation

Pattern definitions (FIXED before seeing results — do not move goalposts):
- Signal: deny/allow pattern matching known-bad AgentDojo adversarial injection attempts
- Noise: deny/allow variation in benign tasks not corresponding to adversarial behavior

Metrics: Precision, Recall, False-positive rate, False-negative rate

AgentDojo is NOT an Article 9 validator — it provides realistic agent/tool interactions. The evaluation tests whether the adapter can process that workload and produce structured evidence records.

**Two unresolved issues before running:**

1. **C4 windowing** — draft says fixed window W but prototype uses deque(maxlen=W) sliding window per risk class. This IS a sliding window. Verify whether the eval notebook methodology text correctly describes this behavior. If it claimed "cumulative", correct the methodology. If it already says "sliding window W=20", it's consistent.

2. **task_id vs agent_id** — an agent can execute multiple tasks. The schema has both `agent_id` and `task_id` on `AuthorizationEvent`. The evaluation should determine whether task_id is correctly populated per AgentDojo task and whether sequence_id preserves ordering within a task.

**Eval notebook status:** `evidence_adapter_eval.ipynb` — NOT on disk. Was downloaded from a previous chat session but never committed to repo. Must be recovered from that chat history or recreated.

Notebook spec:
- Agent: Llama-3.1-8B-Instruct via Colab Pro (L4 GPU)
- Tasks: 5 benign + 9 adversarial AgentDojo banking suite pairs
- Window: W=20
- Output: /content/evidence_adapter_results.jsonl + Cell 7 printed table

---

### Claim Discipline

Distinguish between:
1. Regulatory requirement
2. Analytical framework (this paper's four-gap taxonomy)
3. Architecture proposed by this paper
4. Behavior demonstrated by prototype
5. Behavior demonstrated experimentally
6. Future work

Do NOT claim: compliance proven, adapter guarantees compliance, AgentDojo validates Article 9, limitations solved if they are not.

---

## PART B — ACTUAL PROJECT / FOLDER STATE

**Path:** `/Users/macski/Projects/article9-evidence-adapter/`
**Remote:** https://github.com/pavjstn-ui/article9-evidence-adapter.git
**Branch:** master (up to date with origin/master)
**Git status:** clean (only `__pycache__/*.pyc` modified — irrelevant)

### Recent commits

```
44486eb fix: add missing _deny_rate() method; handover: session state 2026-08-30
ba1171b feat: C4 sliding window (W=50); add task_id+sequence_id to AuthorizationEvent
6ebfeb6 fix: residual-risk bound check inverted (>= -> <=)
6c5c7ad chore: add gitignore
d76e95b v1: Evidence Adapter — four gap taxonomy, seven test scenarios
```

### Files present

```
evidence_adapter.py      (7892 bytes)
test_adapter.py          (5219 bytes)
FRESH_CHAT_HANDOVER.md   (handover from 2026-08-30 session — committed)
.gitignore
```

### Actual test status (verified this session)

```
python3 test_adapter.py
=== 7 passed  0 failed ===
```

Note: `python3 -m pytest test_adapter.py` collects 0 items — the test harness is custom, not pytest-compatible. Use `python3 test_adapter.py` directly.

### Files NOT present (missing from repo)

- `evidence_adapter_eval.ipynb` — was in Colab / previous chat, never committed
- Section 2 draft — in previous chat session, not in pat-vault or on disk
- Sections 1, 7, Conclusion — not written
- Any compiled LaTeX / PDF

---

## DISCREPANCIES

**CHAT STATE:** "eval notebook downloaded from chat — NOT yet committed"
**FOLDER STATE:** Confirmed — notebook not present anywhere on disk or in repo. Must be recovered from previous chat or recreated.

**CHAT STATE:** "7/7 tests passing"
**FOLDER STATE:** Confirmed — verified by running `python3 test_adapter.py` this session.

**CHAT STATE:** "C4 uses deque(maxlen=W) sliding window"
**FOLDER STATE:** Confirmed in `evidence_adapter.py` lines 111, 137-141. `_windows` is a `dict[str, deque]`; each risk_id gets `deque(maxlen=self.window_size)`. This IS a proper sliding window.

**CHAT STATE:** "S2 Article 9 analysis DRAFTED"
**FOLDER STATE:** Not on disk. Not in pat-vault/inbox/raw/. Only the Section 5 draft is in pat-vault (`20260828_article9-paper_section5.md`).

**CHAT STATE:** "Zenodo DOI 10.5281/zenodo.21834704"
**FOLDER STATE:** Cannot verify from repo — take at face value from handover.

---

## CURRENT NEXT ACTION

**Primary blocker:** `evidence_adapter_eval.ipynb` does not exist on disk.

**Step 1 (immediate):** Recover or recreate `evidence_adapter_eval.ipynb`.
- Option A: Retrieve from the previous chat session that generated it.
- Option B: Recreate from the spec in the handover (Llama-3.1-8B-Instruct, 5 benign + 9 adversarial banking tasks, W=20, cells 1-7 producing JSONL + summary table).

**Step 2:** Commit the notebook to the repo before uploading to Colab.

**Step 3:** Upload to Colab Pro (L4 GPU), run cells 1-7, capture Cell 7 output.

**Step 4:** Paste Cell 7 numbers into chat → fill Section 6.3 and 6.5 results tables → lock Section 6.

**Step 5:** Write Section 7 (Limitations) and Conclusion.

**Step 6:** Write Section 1 (Introduction — written last).

**Step 7:** LaTeX assembly in Overleaf (base: Articel9.tex in pat-vault) → push compiled PDF to Zenodo as v2 under DOI 10.5281/zenodo.21834704.

Do not start Section 6.5 prose until actual experiment results are in hand.
