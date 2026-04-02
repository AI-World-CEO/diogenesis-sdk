"""File access interceptor — wraps builtins.open."""

import builtins

from .base import BaseInterceptor


class FileHook(BaseInterceptor):

    def __init__(self, event_buffer, classifier):
        super().__init__("file", event_buffer, classifier)

    def activate(self) -> None:
        if self._active:
            return
        self._original = builtins.open
        builtins.open = self._hooked_open
        self._active = True

    def deactivate(self) -> None:
        if not self._active or self._original is None:
            return
        builtins.open = self._original
        self._active = False

    def _hooked_open(self, file, mode="r", *args, **kwargs):
        if self._enter_hook():
            try:
                caller_file, caller_line, caller_func = self._get_caller()
                filepath = str(file)
                classification = self._classifier.classify_file(filepath, mode)
                self._log_event({
                    "path": filepath,
                    "mode": mode,
                    "caller_file": caller_file,
                    "caller_line": caller_line,
                    "caller_func": caller_func,
                }, classification)
            except Exception:
                pass
            finally:
                self._exit_hook()
        return self._original(file, mode, *args, **kwargs)
