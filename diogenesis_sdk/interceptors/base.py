"""Base interceptor with re-entrancy guard and common logging."""

import sys
import time
import threading


class BaseInterceptor:
    """Abstract base for all Diogenesis interceptors.

    Provides:
    - Re-entrancy guard (per-thread) to prevent infinite recursion
    - Common event logging to the shared buffer
    - Clean activate/deactivate lifecycle
    """

    def __init__(self, name: str, event_buffer, classifier):
        self.name = name
        self._buffer = event_buffer
        self._classifier = classifier
        self._active = False
        self._original = None
        self._local = threading.local()

    @property
    def is_active(self) -> bool:
        return self._active

    def activate(self) -> None:
        raise NotImplementedError

    def deactivate(self) -> None:
        raise NotImplementedError

    def _enter_hook(self) -> bool:
        """Returns True if we should log (not re-entrant). False = skip logging."""
        depth = getattr(self._local, "depth", 0)
        if depth > 0:
            return False
        self._local.depth = depth + 1
        return True

    def _exit_hook(self) -> None:
        self._local.depth = max(0, getattr(self._local, "depth", 1) - 1)

    def _get_caller(self) -> tuple:
        """Get caller filename, line number, function name.

        Uses sys._getframe to avoid importing inspect (which would
        trigger the import interceptor recursively).
        """
        try:
            # Frame 0 = _get_caller, 1 = _log_event or wrapper, 2 = hooked fn, 3 = actual caller
            frame = sys._getframe(3)
            return (frame.f_code.co_filename, frame.f_lineno, frame.f_code.co_name)
        except (ValueError, AttributeError):
            return ("unknown", 0, "unknown")

    def _log_event(self, detail: dict, classification: str) -> None:
        event = {
            "type": self.name,
            "timestamp": time.time(),
            "caller_file": detail.get("caller_file", "unknown"),
            "caller_line": detail.get("caller_line", 0),
            "caller_func": detail.get("caller_func", "unknown"),
            "detail": {k: v for k, v in detail.items()
                       if k not in ("caller_file", "caller_line", "caller_func")},
            "classification": classification,
        }
        self._buffer.append(event)
