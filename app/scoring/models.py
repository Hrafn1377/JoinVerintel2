from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Verdict(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Signal:
    label: str
    verdict: Verdict
    score: float
    weight: float
    reason: str
    source: str


@dataclass
class VerificationReport:
    signals: List[Signal] = field(default_factory=list)
    overall_score: float = 0.0
    summary: str = ""

    def compute(self):
        if not self.signals:
            self.overall_score = 0.0
            return
        
        total_weight = sum(s.weight for s in self.signals)
        if total_weight == 0:
            self.overall_score = 0.0
            return
        
        weighted_score = sum(s.score * s.weight for s in self.signals)
        self.overall_score = weighted_score / total_weight