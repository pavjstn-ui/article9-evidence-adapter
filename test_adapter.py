import json, os, sys, uuid
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_adapter import *

def _now(): return datetime.now(timezone.utc)

RISK = RiskRegisterEntry(risk_id="risk-001", risk_class="data_exfiltration",
    description="Agent transmits internal data to external endpoint.", identified_by="security-team")
RAT  = MitigationRationale(rationale_id="rat-001", rule_id="rule-deny-ext-write",
    risk_id="risk-001", rationale="DENY all external writes. No legitimate use case.",
    adequacy_assessment="Full DENY adequate; reviewed by security-lead.", assessed_by="security-lead")
BOUND = AcceptabilityBound(bound_id="bnd-001", risk_id="risk-001",
    max_deny_rate=0.05, defined_by="risk-owner")
PLAN = MonitoringPlanRef(plan_id="plan-001", review_interval_days=30, plan_owner="compliance-team")

def make_adapter():
    return EvidenceAdapter(
        risk_register={"risk-001": RISK},
        rule_risk_mapping={"rule-deny-ext-write": "risk-001"},
        rationale_store={"rat-001": RAT},
        rule_rationale_map={"rule-deny-ext-write": "rat-001"},
        bounds_store={"risk-001": BOUND},
        monitoring_plan=PLAN,
        window_size=50,
    )

def ev(decision, rule_id="rule-deny-ext-write", action="https://ext.io/x", task_id=None, seq=None):
    return AuthorizationEvent(agent_id="agent-a", tool_name="write_file",
        action=action, rule_id=rule_id, decision=decision, task_id=task_id, sequence_id=seq)

def flat(bundle, flags=None):
    link=bundle["c1_risk_link"]; mit=bundle["c2_mitigation"]; res=bundle["c3_residual_risk"]
    sm={AcceptabilityStatus.AWAITING_REVIEW:"pending_human_review",
        AcceptabilityStatus.HUMAN_REVIEWED_ACCEPTABLE:"human_reviewed_acceptable",
        AcceptabilityStatus.HUMAN_REVIEWED_UNACCEPTABLE:"human_reviewed_unacceptable"}
    return {"event_id":link.event_id,"risk_id":link.risk_id,"control_id":link.rule_id,
            "mitigation_id":mit.rationale_id,"evaluation_id":res.record_id,
            "decision":res.decision.value,"residual_risk":res.post_decision_risk.value,
            "acceptability_status":sm[res.acceptability_status],
            "evidence_links":["Art. 9(2)(a)","Art. 9(2)(d)","Art. 9(5)"],
            "unlinked_rule":link.unlinked,"flags":flags or [],
            "task_id":link.event_id[:8],"sequence_id":None}

PASS=FAIL=0
def check(name, fn):
    global PASS, FAIL
    try: fn(); print(f"  PASS  {name}"); PASS+=1
    except Exception as e: print(f"  FAIL  {name}: {e}"); FAIL+=1

def t1():
    a=make_adapter(); b=a.process(ev(Decision.ALLOW)); r=flat(b)
    assert r["decision"]=="ALLOW"; assert r["acceptability_status"]=="pending_human_review"
    assert r["residual_risk"]=="not_eliminated"
    print(json.dumps(r, indent=2))

def t2():
    a=make_adapter(); b=a.process(ev(Decision.DENY)); r=flat(b)
    assert r["decision"]=="DENY"; assert r["residual_risk"]=="reduced"
    assert r["acceptability_status"]=="pending_human_review"
    print(json.dumps(r, indent=2))

def t3():
    a=make_adapter()
    for _ in range(10): a.process(ev(Decision.DENY))
    t0=_now(); rep=a.generate_pattern_report("risk-001",t0,t0,["deny_rate_spike"],["repeated ext writes"])
    assert rep.deny_rate==1.0; assert rep.review_task_open
    print(json.dumps(rep.model_dump(mode="json"), indent=2))

def t4():
    a=make_adapter(); b=a.process(ev(Decision.DENY, rule_id="rule-unknown")); r=flat(b,["UNLINKED_RULE: Gap 1 failure"])
    assert r["unlinked_rule"]; assert r["risk_id"]=="UNLINKED"; assert r["mitigation_id"]=="NO_RATIONALE_ON_RECORD"
    print(json.dumps(r, indent=2))

def t5():
    a=make_adapter(); b=a.process(ev(Decision.ALLOW)); r=flat(b,["adversarial_bypass","Art.15(5): prompt injection"])
    assert r["decision"]=="ALLOW"; assert r["residual_risk"]=="not_eliminated"
    print(json.dumps(r, indent=2))

def t6():
    a=make_adapter()
    a.rationale_store["rat-001-v2"]=MitigationRationale(rationale_id="rat-001-v2",
        rule_id="rule-deny-ext-write",risk_id="risk-001",
        rationale="DENY + log args. Updated post review.",
        adequacy_assessment="Enhanced DENY adequate.",assessed_by="security-lead")
    a.rule_rationale_map["rule-deny-ext-write"]="rat-001-v2"
    b=a.process(ev(Decision.DENY)); r=flat(b,["mitigation_updated: rat-001 -> rat-001-v2"])
    assert r["mitigation_id"]=="rat-001-v2"
    print(json.dumps(r, indent=2))

def t7():
    a=make_adapter(); b=a.process(ev(Decision.DENY))
    res=b["c3_residual_risk"]
    assert res.acceptability_status==AcceptabilityStatus.AWAITING_REVIEW
    res.human_review("risk-owner", acceptable=True)
    assert res.acceptability_status==AcceptabilityStatus.HUMAN_REVIEWED_ACCEPTABLE
    r=flat(b); r["acceptability_status"]="human_reviewed_acceptable"
    print(json.dumps(r, indent=2))

print("\n=== Article 9 Evidence Adapter — Test Harness ===")
for name,fn in [("T1 normal ALLOW",t1),("T2 normal DENY",t2),
    ("T3 repeated DENYs / C4 pattern",t3),("T4 unlinked rule / Gap 1",t4),
    ("T5 adversarial bypass",t5),("T6 mitigation update",t6),("T7 human review",t7)]:
    print(f"\n--- {name} ---"); check(name, fn)
print(f"\n=== {PASS} passed  {FAIL} failed ===")
