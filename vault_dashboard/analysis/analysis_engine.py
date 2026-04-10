from collections import Counter
from datetime import timedelta

from django.utils import timezone

from .detection import AlertGroupingService, BaselineDeviationDetector, RiskScoringEngine
from .ingestion import AuditLogIngestionService


class IncidentSummarizer:
    def summarize(self, scored_alerts, deviations):
        if not scored_alerts:
            return "No notable incidents detected in current analysis window."

        top = scored_alerts[0]
        summary = (
            f"Top incident candidate: user '{top['username']}' performed "
            f"{top['event_count']} {top['action']} events on {top['entity']} "
            f"(severity={top['severity']}, score={top['risk_score']})."
        )
        if deviations:
            summary += f" Baseline detector flagged {len(deviations)} behavior deviation(s)."
        return summary


class PredictiveWarningEngine:
    """Lightweight trend detector for near-term anomaly warning."""

    def predict(self, events):
        now = timezone.now()
        current_cutoff = now - timedelta(hours=6)
        previous_cutoff = now - timedelta(hours=12)

        current = Counter()
        previous = Counter()
        for event in events:
            action = event["action"]
            if event["timestamp"] >= current_cutoff:
                current[action] += 1
            elif event["timestamp"] >= previous_cutoff:
                previous[action] += 1

        warnings = []
        for action, current_count in current.items():
            prev_count = previous.get(action, 0)
            if current_count >= 8 and (prev_count == 0 or current_count >= prev_count * 2):
                warnings.append(
                    {
                        "action": action,
                        "current_6h": current_count,
                        "previous_6h": prev_count,
                        "warning": "Trend suggests near-term anomaly if activity continues.",
                    }
                )
        return warnings


class VaultAnalysisOrchestrator:
    """Modular pipeline: ingestion -> detection -> analysis -> output."""

    def __init__(self):
        self.ingestion = AuditLogIngestionService()
        self.grouping = AlertGroupingService()
        self.risk = RiskScoringEngine()
        self.deviation = BaselineDeviationDetector()
        self.summarizer = IncidentSummarizer()
        self.predictive = PredictiveWarningEngine()

    def run(self, hours=24):
        events = self.ingestion.load(hours=hours)
        grouped = self.grouping.group(events)
        scored = self.risk.score_groups(grouped)
        deviations = self.deviation.detect(events)
        predicted = self.predictive.predict(events)
        summary = self.summarizer.summarize(scored, deviations)

        return {
            "event_count": len(events),
            "alert_groups": scored[:25],
            "deviations": deviations[:25],
            "predictive_warnings": predicted[:10],
            "incident_summary": summary,
        }
