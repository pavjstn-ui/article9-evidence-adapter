---
ARTICLE 9 EVIDENCE ADAPTER — HANDOVER 2026-08-30

CURRENT BLOCKER
  eval notebook not yet run. Upload evidence_adapter_eval.ipynb to Colab Pro,
  run cells 1-7, paste Cell 7 output into chat.

PAPER
  Title:  Authorization Logs Are Not Compliance Evidence:
          The Article 9 Gap in Agent Harness Security
  Repo:   https://github.com/pavjstn-ui/article9-evidence-adapter
  Zenodo: 10.5281/zenodo.21834704 (v2 not yet pushed)

SECTION STATUS
  S1  Introduction          NOT WRITTEN
  S2  Article 9 analysis    DRAFTED (download from previous chat if not on Mac)
  S3  Four gaps             LOCKED
  S4  Adapter architecture  LOCKED
  S5  Implementation        LOCKED — confirmed in pat-vault, pushed
  S6  Evaluation            DRAFTED — results pending eval run
  S7  Limitations           NOT WRITTEN
  CON Conclusion            NOT WRITTEN

PROTOTYPE — FOLDER STATE
  total 40
  drwxr-xr-x    7 macski  staff   224 28 Aug 23:01 .
  drwxr-xr-x  110 macski  staff  3520 30 Aug 12:30 ..
  drwxr-xr-x   13 macski  staff   416 28 Aug 23:17 .git
  -rw-r--r--    1 macski  staff    13 28 Aug 23:01 .gitignore
  drwxr-xr-x    4 macski  staff   128 28 Aug 23:17 __pycache__
  -rw-r--r--    1 macski  staff  7892 28 Aug 23:17 evidence_adapter.py
  -rw-r--r--    1 macski  staff  5219 28 Aug 23:17 test_adapter.py

GIT LOG
  ba1171b feat: C4 sliding window (W=50); add task_id+sequence_id to AuthorizationEvent
  6ebfeb6 fix: residual-risk bound check inverted (>= -> <=)
  6c5c7ad chore: add gitignore
  d76e95b v1: Evidence Adapter — four gap taxonomy, seven test scenarios

TEST STATUS
  === 7 passed  0 failed ===

  NOTE: ba1171b introduced a regression — _deny_rate() was called in
  assess_residual_risk() but never defined as a method. Fixed in this session
  by adding EvidenceAdapter._deny_rate(risk_id) -> float. Tests now 7/7 passing.

BOUND CHECK CONFIRMED
        within = None
            within = self._deny_rate(link.risk_id) <= b.max_deny_rate

EVAL NOTEBOOK
  Filename: evidence_adapter_eval.ipynb
  Location: downloaded from chat — NOT yet committed to repo
  Status:   NOT RUN
  Agent:    Llama-3.1-8B-Instruct via Colab Pro
  Tasks:    5 benign + 9 adversarial AgentDojo banking suite pairs
  Window:   W=20 (fixed for this run)
  Output:   /content/evidence_adapter_results.jsonl + Cell 7 printed table

NEXT COMMAND
  Upload evidence_adapter_eval.ipynb to Colab Pro → Runtime: L4 GPU →
  run cells 1-7 → paste Cell 7 output into new chat with this handover.

UNRUN AFTER EVAL
  PROMPT A — fill Section 6.5
    Paste Cell 7 numbers. Fill the results tables in Section 6.3 and 6.5.
    Lock Section 6.

  PROMPT B — Section 7 + Conclusion
    Write Section 7 (limitations extending 5.6 with eval findings).
    Write Conclusion (3 sentences: gap identified / adapter built / eval result).

  PROMPT C — Section 1
    Write Introduction. Must accurately describe what the paper does.
    Written last so it matches the finished paper.

  PROMPT D — LaTeX assembly
    Assemble all sections in Overleaf. Base file: Articel9.tex in pat-vault.
    Push compiled PDF to Zenodo as v2 under DOI 10.5281/zenodo.21834704.

KEY CONSTRAINTS (do not lose these)
  - acceptability_status cannot reach human_reviewed_acceptable without
    explicit human_review(reviewer, acceptable) call — enforced in data model
  - agent_id != task_id — both are first-class fields on AuthorizationEvent
  - C4 uses deque(maxlen=W) sliding window, W=50 default, W=20 for eval
  - All section drafts saved to pat-vault/inbox/raw/ — never Downloads
  - Git push to article9-evidence-adapter uses HTTPS (SSH hangs on Catalina)
---
