"""tooltrap.scoring — detector suite and scoring engine."""
from tooltrap.scoring.base import BaseDetector
from tooltrap.scoring.models import ScoringResult, VerdictLevel
from tooltrap.scoring.scorer import Scorer
__all__ = ["BaseDetector", "Scorer", "ScoringResult", "VerdictLevel"]
