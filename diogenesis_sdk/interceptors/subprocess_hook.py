"""Subprocess interceptor — wraps subprocess.run, subprocess.Popen, os.system."""

import os
import subprocess

from .base import BaseInterceptor


class SubprocessHook(BaseInterceptor):

    def __init__(self, event_buffer, classifier):
        super().__init__("subprocess", event_buffer, classifier)
        self._original_run = None
        self._original_popen = None
        self._original_os_system = None

    def activate(self) -> None:
        if self._active:
            return
        self._original_run = subprocess.run
        self._original_popen = subprocess.Popen
        self._original_os_system = os.system
        subprocess.run = self._hooked_run
        subprocess.Popen = self._hooked_popen
        os.system = self._hooked_os_system
        self._active = True

    def deactivate(self) -> None:
        if not self._active:
            return
        if self._original_run is not None:
            subprocess.run = self._original_run
        if self._original_popen is not None:
            subprocess.Popen = self._original_popen
        if self._original_os_system is not None:
            os.system = self._original_os_system
        self._active = False

    def _log_command(self, cmd, variant="run"):
        if self._enter_hook():
            try:
                caller_file, caller_line, caller_func = self._get_caller()
                cmd_str = str(cmd)[:200]
                classification = self._classifier.classify_subprocess(cmd_str)
                self._log_event({
                    "command": cmd_str,
                    "variant": variant,
                    "caller_file": caller_file,
                    "caller_line": caller_line,
                    "caller_func": caller_func,
                }, classification)
            except Exception:
                pass
            finally:
                self._exit_hook()

    def _hooked_run(self, *args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", "unknown")
        self._log_command(cmd, "run")
        return self._original_run(*args, **kwargs)

    def _hooked_popen(self, *args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", "unknown")
        self._log_command(cmd, "Popen")
        return self._original_popen(*args, **kwargs)

    def _hooked_os_system(self, command):
        self._log_command(command, "os.system")
        return self._original_os_system(command)
