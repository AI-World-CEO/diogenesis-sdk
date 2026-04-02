"""Network interceptor — wraps requests.get/post/put/delete if available."""

from .base import BaseInterceptor


class NetworkHook(BaseInterceptor):

    def __init__(self, event_buffer, classifier):
        super().__init__("network", event_buffer, classifier)
        self._originals = {}  # method_name -> original_fn
        self._requests_module = None

    def activate(self) -> None:
        if self._active:
            return
        try:
            import requests
            self._requests_module = requests
        except ImportError:
            return  # requests not installed — nothing to hook

        for method in ("get", "post", "put", "delete"):
            original = getattr(self._requests_module, method)
            self._originals[method] = original
            setattr(self._requests_module, method, self._make_hook(method, original))

        self._active = True

    def deactivate(self) -> None:
        if not self._active or self._requests_module is None:
            return
        for method, original in self._originals.items():
            setattr(self._requests_module, method, original)
        self._originals.clear()
        self._active = False

    def _make_hook(self, method_name: str, original_fn):
        def _hooked(url, *args, **kwargs):
            if self._enter_hook():
                try:
                    caller_file, caller_line, caller_func = self._get_caller()
                    classification = self._classifier.classify_network(str(url), method_name)
                    self._log_event({
                        "url": str(url)[:200],
                        "method": method_name.upper(),
                        "caller_file": caller_file,
                        "caller_line": caller_line,
                        "caller_func": caller_func,
                    }, classification)
                except Exception:
                    pass
                finally:
                    self._exit_hook()
            return original_fn(url, *args, **kwargs)
        return _hooked
