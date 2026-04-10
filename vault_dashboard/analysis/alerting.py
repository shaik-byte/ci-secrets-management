class AlertingRouter:
    """
    Controlled automation adapter.
    V1 returns channel plan only (no auto-remediation side effects).
    """

    def build_delivery_plan(self, alerts):
        has_critical = any(a.get("severity") == "critical" for a in alerts)
        if has_critical:
            return ["email", "slack", "webhook"]
        if alerts:
            return ["email", "webhook"]
        return []
