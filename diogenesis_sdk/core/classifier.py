"""Classify intercepted calls as KNOWN, UNEXPECTED, or SUSPICIOUS."""

import sys

# Python stdlib modules (3.10+ has sys.stdlib_module_names)
try:
    _STDLIB = set(sys.stdlib_module_names)
except AttributeError:
    _STDLIB = {
        "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
        "asyncore", "atexit", "base64", "bdb", "binascii", "binhex",
        "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
        "cmath", "cmd", "code", "codecs", "codeop", "collections",
        "colorsys", "compileall", "concurrent", "configparser", "contextlib",
        "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
        "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
        "difflib", "dis", "distutils", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "grp", "gzip", "hashlib", "heapq",
        "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp",
        "importlib", "inspect", "io", "ipaddress", "itertools", "json",
        "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
        "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
        "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
        "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
        "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
        "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
        "queue", "quopri", "random", "re", "readline", "reprlib",
        "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
        "selectors", "shelve", "shlex", "shutil", "signal", "site",
        "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
        "ssl", "stat", "statistics", "string", "stringprep", "struct",
        "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog",
        "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
        "textwrap", "threading", "time", "timeit", "tkinter", "token",
        "tokenize", "trace", "traceback", "tracemalloc", "tty", "turtle",
        "turtledemo", "types", "typing", "unicodedata", "unittest", "urllib",
        "uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
        "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc",
        "zipapp", "zipfile", "zipimport", "zlib",
        "_thread", "_io", "_codecs", "_signal", "_weakref", "_abc",
        "_functools", "_operator", "_collections", "_heapq", "_bisect",
        "_random", "_sha512", "_socket", "_ssl", "_struct",
    }


class Classifier:
    """Classifies intercepted calls into KNOWN, UNEXPECTED, SUSPICIOUS."""

    def __init__(self, config: dict):
        wl = config.get("whitelist", {})
        sp = config.get("suspicious_patterns", {})

        self._import_whitelist = set(wl.get("import_modules", []))
        self._file_whitelist = list(wl.get("file_paths", []))
        self._network_whitelist = set(wl.get("network_hosts", ["localhost", "127.0.0.1"]))
        self._subprocess_whitelist = list(wl.get("subprocess_commands", []))

        self._suspicious_imports = set(sp.get("imports", []))
        self._suspicious_files = list(sp.get("file_paths", []))
        self._suspicious_hosts = set(sp.get("network_hosts", []))
        self._suspicious_commands = list(sp.get("subprocess_commands", []))

    def classify_import(self, module_name: str) -> str:
        top = module_name.split(".")[0]
        if top in self._suspicious_imports:
            return "SUSPICIOUS"
        if top in _STDLIB:
            return "KNOWN"
        if top in self._import_whitelist:
            return "KNOWN"
        return "UNEXPECTED"

    def classify_file(self, path: str, mode: str) -> str:
        s = str(path).replace("\\", "/")
        for pattern in self._suspicious_files:
            if pattern.replace("\\", "/") in s:
                return "SUSPICIOUS"
        for pattern in self._file_whitelist:
            if s.startswith(pattern.replace("\\", "/")):
                return "KNOWN"
        return "UNEXPECTED"

    def classify_subprocess(self, command: str) -> str:
        cmd_lower = str(command).lower()
        for pattern in self._suspicious_commands:
            if pattern.lower() in cmd_lower:
                return "SUSPICIOUS"
        for pattern in self._subprocess_whitelist:
            if pattern.lower() in cmd_lower:
                return "KNOWN"
        return "UNEXPECTED"

    def classify_network(self, url: str, method: str) -> str:
        url_lower = str(url).lower()
        for host in self._suspicious_hosts:
            if host.lower() in url_lower:
                return "SUSPICIOUS"
        for host in self._network_whitelist:
            if host.lower() in url_lower:
                return "KNOWN"
        return "UNEXPECTED"
