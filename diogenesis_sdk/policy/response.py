"""Graduated response — track repeat offenders and escalate."""


class GraduatedResponse:
    """Track violations per source and escalate response level.

    Level 1 (1st violation): LOG — record but take no action
    Level 2 (2nd violation): WARN — add to warnings list
    Level 3 (3rd+ violation): ALERT — add to critical alerts
    """

    ACTIONS = {1: "LOG", 2: "WARN", 3: "ALERT"}

    def __init__(self):
        self._violation_counts = {}   # source -> count
        self._escalation_levels = {}  # source -> level (1, 2, 3)

    def record_violation(self, source, alert=None) -> dict:
        """Record a violation from a source. Returns escalation info."""
        count = self._violation_counts.get(source, 0) + 1
        self._violation_counts[source] = count

        level = min(count, 3)
        self._escalation_levels[source] = level
        action = self.ACTIONS.get(level, "ALERT")

        return {
            "source": source,
            "count": count,
            "level": level,
            "action": action,
            "alert": alert,
        }

    def get_escalations(self) -> list:
        """Return all sources with escalation level >= 2."""
        return [
            {"source": src, "level": lvl, "count": self._violation_counts.get(src, 0),
             "action": self.ACTIONS.get(lvl, "ALERT")}
            for src, lvl in self._escalation_levels.items()
            if lvl >= 2
        ]

    def reset(self, source=None) -> None:
        """Reset violation count for a source, or all if None."""
        if source is None:
            self._violation_counts.clear()
            self._escalation_levels.clear()
        else:
            self._violation_counts.pop(source, None)
            self._escalation_levels.pop(source, None)

    @property
    def total_violations(self) -> int:
        return sum(self._violation_counts.values())
