"""Behavioral baseline generator — fingerprints normal application patterns."""

from collections import Counter


def generate_baseline(events: list) -> dict:
    """Generate behavioral baseline from 1000+ events.

    Returns a fingerprint of normal application behavior:
    top imports, file access patterns, network destinations,
    subprocess commands, and caller distribution.
    """
    total = len(events)
    if total < 1000:
        return {
            "status": "ACCUMULATING",
            "events": total,
            "needed": 1000 - total,
        }

    cat_counts = Counter(e.get("type", "unknown") for e in events)

    # Classification summary
    classifications = Counter(e.get("classification", "UNKNOWN") for e in events)

    # Import patterns
    import_events = [e for e in events if e["type"] == "import"]
    top_imports = Counter(
        e.get("detail", {}).get("module", "?") for e in import_events
    ).most_common(20)

    # File patterns
    file_events = [e for e in events if e["type"] == "file"]
    file_modes = Counter(e.get("detail", {}).get("mode", "?") for e in file_events)
    file_classes = Counter(e.get("classification", "?") for e in file_events)

    # Network patterns
    net_events = [e for e in events if e["type"] == "network"]
    net_methods = Counter(e.get("detail", {}).get("method", "?") for e in net_events)
    net_classes = Counter(e.get("classification", "?") for e in net_events)

    # Subprocess patterns
    sub_events = [e for e in events if e["type"] == "subprocess"]
    sub_commands = Counter(
        e.get("detail", {}).get("command", "?")[:50] for e in sub_events
    ).most_common(10)

    # Top callers
    top_callers = Counter(
        e.get("caller_file", "?") for e in events
    ).most_common(15)

    # Suspicious and unexpected details
    suspicious = [e for e in events if e.get("classification") == "SUSPICIOUS"]
    unexpected = [e for e in events if e.get("classification") == "UNEXPECTED"]

    return {
        "status": "BASELINE_READY",
        "total_events": total,
        "category_counts": dict(cat_counts),
        "classifications": dict(classifications),
        "top_imports": top_imports,
        "file_modes": dict(file_modes),
        "file_classifications": dict(file_classes),
        "network_methods": dict(net_methods),
        "network_classifications": dict(net_classes),
        "subprocess_commands": sub_commands,
        "top_callers": top_callers,
        "suspicious_count": len(suspicious),
        "unexpected_count": len(unexpected),
        "suspicious_details": [
            {"type": e["type"], "detail": e.get("detail", {}),
             "caller": e.get("caller_file", "?")}
            for e in suspicious[-10:]
        ],
    }
