from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

def _now(): return datetime.now(timezone.utc)

class ArticleRef(str, Enum):
    ART_9_2_A = "Art. 9(2)(a)"; ART_9_2_C = "Art. 9(2)(c)"
    ART_9_2_D = "Art. 9(2)(d)"; ART_9_5 = "Art. 9(5)"; ART_72 = "Art. 72"

class Decision(str, Enum):
    ALLOW = "ALLOW"; DENY = "DENY"

class AcceptabilityStatus(str, Enum):
    AWAITING_REVIEW = "awaiting_review"
    HUMAN_REVIEWED_ACCEPTABLE = "human_reviewed_acceptable"
    HUMAN_REVIEWED_UNACCEPTABLE = "human_reviewed_unacceptable"

class ResidualRiskState(str, Enum):
    NOT_ELIMINATED = "not_eliminated"; REDUCED = "reduced"; PENDING_REVIEW = "pending_review"

class ReviewDetermination(str, Enum):
    NO_CHANGE = "no_change"; RISK_UPDATED = "risk_updated"
    MITIGATION_UPDATED = "mitigation_updated"; ESCALATED = "escalated"

class AuthorizationEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str; tool_name: str; action: str; rule_id: str
    decision: Decision; timestamp: datetime = Field(default_factory=_now)
    raw_payload: Optional[dict] = None

class RiskRegisterEntry(BaseModel):
    risk_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_class: str; description: str
    article_ref: ArticleRef = ArticleRef.ART_9_2_A
    identified_at: datetime = Field(default_factory=_now); identified_by: str

class MitigationRationale(BaseModel):
    rationale_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str; risk_id: str; rationale: str
    alternatives_considered: list[str] = []
    adequacy_assessment: str
    article_ref: list[ArticleRef] = [ArticleRef.ART_9_2_D, ArticleRef.ART_9_5]
    assessed_by: str; assessed_at: datetime = Field(default_factory=_now)

class AcceptabilityBound(BaseModel):
    bound_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_id: str; max_deny_rate: Optional[float] = None
    max_near_misses_per_period: Optional[int] = None
    defined_by: str; defined_at: datetime = Field(default_factory=_now)

class MonitoringPlanRef(BaseModel):
    plan_id: str; review_interval_days: int; plan_owner: str

class RiskRegisterLink(BaseModel):
    link_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str; risk_id: str; risk_class: str; rule_id: str
    article_ref: ArticleRef = ArticleRef.ART_9_2_A
    linked_by: str; linked_at: datetime = Field(default_factory=_now); unlinked: bool = False

class MitigationEvidenceRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str; rationale_id: str; risk_id: str; rule_id: str
    article_ref: list[ArticleRef] = [ArticleRef.ART_9_2_D]
    recorded_at: datetime = Field(default_factory=_now)

class ResidualRiskRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str; risk_id: str; decision: Decision
    post_decision_risk: ResidualRiskState
    acceptability_bound_id: Optional[str] = None
    within_bound: Optional[bool] = None
    acceptability_status: AcceptabilityStatus = AcceptabilityStatus.AWAITING_REVIEW
    reviewed_by: Optional[str] = None; reviewed_at: Optional[datetime] = None
    article_ref: ArticleRef = ArticleRef.ART_9_5
    assessed_at: datetime = Field(default_factory=_now)
    def human_review(self, reviewer: str, acceptable: bool):
        self.reviewed_by = reviewer; self.reviewed_at = _now()
        self.acceptability_status = AcceptabilityStatus.HUMAN_REVIEWED_ACCEPTABLE if acceptable else AcceptabilityStatus.HUMAN_REVIEWED_UNACCEPTABLE

class PatternReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_id: str; period_start: datetime; period_end: datetime
    event_count: int; deny_rate: float; near_miss_count: int
    anomaly_flags: list[str] = []; emerging_patterns: list[str] = []
    monitoring_plan_id: str
    article_ref: list[ArticleRef] = [ArticleRef.ART_9_2_C, ArticleRef.ART_72]
    generated_at: datetime = Field(default_factory=_now); review_task_open: bool = True

class ReviewOutcome(BaseModel):
    outcome_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_id: str; reviewer: str; determination: ReviewDetermination
    risk_record_updated: bool; notes: Optional[str] = None
    review_completed_at: datetime = Field(default_factory=_now)

class EvidenceAdapter:
    """Translation layer: security plane -> Article 9 compliance plane.
    Does not modify decisions. Does not make acceptability determinations."""
    def __init__(self, risk_register, rule_risk_mapping, rationale_store,
                 rule_rationale_map, bounds_store, monitoring_plan):
        self.risk_register = risk_register; self.rule_risk_mapping = rule_risk_mapping
        self.rationale_store = rationale_store; self.rule_rationale_map = rule_rationale_map
        self.bounds_store = bounds_store; self.monitoring_plan = monitoring_plan
        self._deny: dict[str,int] = {}; self._allow: dict[str,int] = {}

    def link_risk(self, event):
        rid = self.rule_risk_mapping.get(event.rule_id)
        if not rid or rid not in self.risk_register:
            return RiskRegisterLink(event_id=event.event_id, risk_id="UNLINKED",
                risk_class="UNLINKED", rule_id=event.rule_id, linked_by="rule_mapping", unlinked=True)
        e = self.risk_register[rid]
        return RiskRegisterLink(event_id=event.event_id, risk_id=rid,
            risk_class=e.risk_class, rule_id=event.rule_id, linked_by="rule_mapping")

    def record_mitigation(self, event, link):
        return MitigationEvidenceRecord(event_id=event.event_id,
            rationale_id=self.rule_rationale_map.get(event.rule_id, "NO_RATIONALE_ON_RECORD"),
            risk_id=link.risk_id, rule_id=event.rule_id)

    def assess_residual_risk(self, event, link):
        b = self.bounds_store.get(link.risk_id)
        post = ResidualRiskState.REDUCED if event.decision == Decision.DENY else ResidualRiskState.NOT_ELIMINATED
        within = None
        if b and b.max_deny_rate is not None:
            d = self._deny.get(link.risk_id,0); a = self._allow.get(link.risk_id,0)
            within = (d/(d+a) if d+a else 0.0) >= b.max_deny_rate
        return ResidualRiskRecord(event_id=event.event_id, risk_id=link.risk_id,
            decision=event.decision, post_decision_risk=post,
            acceptability_bound_id=b.bound_id if b else None, within_bound=within)

    def ingest(self, event, link):
        r = link.risk_id
        if event.decision == Decision.DENY: self._deny[r] = self._deny.get(r,0)+1
        else: self._allow[r] = self._allow.get(r,0)+1

    def generate_pattern_report(self, risk_id, period_start, period_end,
                                 anomaly_flags=None, emerging_patterns=None):
        d=self._deny.get(risk_id,0); a=self._allow.get(risk_id,0); t=d+a
        return PatternReport(risk_id=risk_id, period_start=period_start, period_end=period_end,
            event_count=t, deny_rate=d/t if t else 0.0, near_miss_count=0,
            anomaly_flags=anomaly_flags or [], emerging_patterns=emerging_patterns or [],
            monitoring_plan_id=self.monitoring_plan.plan_id)

    def process(self, event):
        link=self.link_risk(event); mit=self.record_mitigation(event,link)
        res=self.assess_residual_risk(event,link); self.ingest(event,link)
        return {"event_id":event.event_id,"c1_risk_link":link,"c2_mitigation":mit,
                "c3_residual_risk":res,"c4_ingested":True,"unlinked_rule":link.unlinked,
                "awaiting_human_review":res.acceptability_status==AcceptabilityStatus.AWAITING_REVIEW}
