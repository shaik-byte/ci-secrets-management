from collections import Counter, defaultdict
from datetime import timedelta

from django.utils import timezone


class AlertGroupingService:
    """Deduplicate and group similar events for analyst-friendly output."""

    def group(self, events):
        grouped = defaultdict(list)
        for event in events:
            key = (event["username"], event["action"], event["entity"])
            grouped[key].append(event)
        return grouped


class BaselineDeviationDetector:
    """Compare recent user behavior against a historical baseline."""

    def detect(self, events):
        now = timezone.now()
        recent_cutoff = now - timedelta(hours=24)
        baseline_cutoff = now - timedelta(days=7)

        recent = Counter()
        baseline = Counter()
        for event in events:
            stamp = event["timestamp"]
            key = (event["username"], event["action"])
            if stamp >= recent_cutoff:
                recent[key] += 1
            elif stamp >= baseline_cutoff:
                baseline[key] += 1

        deviations = []
        for key, recent_count in recent.items():
            baseline_avg = baseline.get(key, 0) / 6 if baseline.get(key, 0) else 0
            ratio = (recent_count / baseline_avg) if baseline_avg else (recent_count if recent_count else 0)
            if recent_count >= 5 and ratio >= 2:
                deviations.append(
                    {
                        "username": key[0],
                        "action": key[1],
                        "recent_count": recent_count,
                        "baseline_avg": round(baseline_avg, 2),
                        "ratio": round(ratio, 2),
                        "reason": "Activity significantly above historical baseline.",
                    }
                )
        return deviations


class RiskScoringEngine:
    """Explainable weighted scoring for grouped alerts."""

    HIGH_RISK_ACTIONS = {"DELETE", "UPDATE", "COPY"}

    def score_groups(self, grouped):
        scored = []
        for (username, action, entity), rows in grouped.items():
            event_count = len(rows)
            ips = {row["ip_address"] for row in rows if row["ip_address"]}
            ip_count = len(ips)
            score = 10
            reasons = []

            if action in self.HIGH_RISK_ACTIONS:
                score += 25
                reasons.append(f"{action} is high-impact action.")
            if event_count >= 10:
                score += 20
                reasons.append("High event volume in analysis window.")
            if ip_count >= 3:
                score += 20
                reasons.append("Multiple source IPs observed.")
            if entity.lower() in {"secret", "accesspolicy", "policygroup"}:
                score += 15
                reasons.append("Sensitive entity touched.")

            severity = "low"
            if score >= 70:
                severity = "critical"
            elif score >= 50:
                severity = "high"
            elif score >= 30:
                severity = "medium"

            scored.append(
                {
                    "username": username,
                    "action": action,
                    "entity": entity,
                    "event_count": event_count,
                    "source_ip_count": ip_count,
                    "risk_score": min(score, 100),
                    "severity": severity,
                    "reasons": reasons or ["Baseline operational activity."],
                }
            )
        return sorted(scored, key=lambda x: x["risk_score"], reverse=True)
