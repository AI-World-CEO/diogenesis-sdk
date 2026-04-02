"""Import interceptor — wraps builtins.__import__."""

import builtins

from .base import BaseInterceptor


class ImportHook(BaseInterceptor):

    def __init__(self, event_buffer, classifier):
        super().__init__("import", event_buffer, classifier)

    def activate(self) -> None:
        if self._active:
            return
        self._original = builtins.__import__
        builtins.__import__ = self._hooked_import
        self._active = True

    def deactivate(self) -> None:
        if not self._active or self._original is None:
            return
        builtins.__import__ = self._original
        self._active = False

    def _hooked_import(self, name, *args, **kwargs):
        if self._enter_hook():
            try:
                caller_file, caller_line, caller_func = self._get_caller()
                classification = self._classifier.classify_import(name)
                self._log_event({
                    "module": name,
                    "caller_file": caller_file,
                    "caller_line": caller_line,
                    "caller_func": caller_func,
                }, classification)
            except Exception:
                pass
            finally:
                self._exit_hook()
        return self._original(name, *args, **kwargs)
