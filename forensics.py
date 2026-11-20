"""
forensics.py - shared forensic-logging helpers (COMP 5710 SQA project).

Every event is one line in forensics.log:

    <UTC timestamp> | <LEVEL> | <module.function> | <KIND> | <details>

KIND is CALL, RETURN, EXCEPTION or EVENT.

Design rules
  * Logging never changes behaviour: return values and exceptions pass through untouched.
  * Logging never crashes the program: every helper swallows its own errors
    (including RecursionError from deeply nested input).
  * SLI-KUBE hunts hard-coded secrets, so raw values are never written to the log.
    Strings are logged as length + salted HMAC prefix (lets you see "same value
    again" without revealing it; the salt is random per process and never written).
    Dicts/lists are logged as type + length only, so huge or deeply nested inputs
    cannot blow up the logger.
  * Set FORENSICS_DISABLED=1 to turn logging off (used for the fuzzing step in CI).
  * Set FORENSICS_LOG=<path> to change the log file (default: forensics.log).
"""
import functools
import hashlib
import hmac
import logging
import os
import sys
import time

DEFAULT_LOG = "forensics.log"
_MAX_TEXT = 200
_SALT = os.urandom(16)
_logger = None


def _enabled():
    return os.environ.get("FORENSICS_DISABLED", "").lower() not in ("1", "true", "yes")


def _log_path():
    return os.environ.get("FORENSICS_LOG", DEFAULT_LOG)


def _get_logger():
    """Create the file handler lazily so importing a module never creates a file."""
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger("forensics")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    if not logger.handlers:
        try:
            handler = logging.FileHandler(_log_path(), mode="a", encoding="utf-8")
        except OSError:
            handler = logging.NullHandler()
        fmt = logging.Formatter("%(asctime)s.%(msecs)03dZ | %(levelname)-7s | %(message)s",
                                datefmt="%Y-%m-%dT%H:%M:%S")
        fmt.converter = time.gmtime
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    _logger = logger
    return logger


def reset_log():
    """Start a fresh log file (run_forensics.py calls this once per run)."""
    global _logger
    try:
        logger = logging.getLogger("forensics")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        _logger = None
        open(_log_path(), "w", encoding="utf-8").close()
    except Exception:
        pass


def _clip(text):
    text = str(text).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT] + "...[truncated]"


def path(value):
    """Log a value verbatim (clipped). Only use for things that are known to be file paths."""
    try:
        return _clip(os.fspath(value) if isinstance(value, os.PathLike) else value)
    except Exception:
        return "<unprintable>"


def safe(value):
    """Safe, bounded description of any value. Never raises."""
    try:
        if isinstance(value, os.PathLike):
            value = os.fspath(value)
        if value is None or isinstance(value, (bool, int, float)):
            return repr(value)
        if isinstance(value, str):
            if value.lower().endswith((".yml", ".yaml")):
                return "path:" + _clip(value)
            tag = hmac.new(_SALT, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]
            return "str(len=%d,id=%s)" % (len(value), tag)
        if isinstance(value, (dict, list, tuple, set, frozenset)):
            return "%s(len=%d)" % (type(value).__name__, len(value))
        return "<%s>" % type(value).__name__
    except Exception:
        return "<unsummarizable>"


def _emit(level, where, kind, details=""):
    if not _enabled():
        return
    try:
        _get_logger().log(level, "%s | %s | %s", where, kind, details)
    except Exception:
        pass


def _raised_at(exc):
    tb = exc.__traceback__
    last = None
    while tb is not None:
        last, tb = tb, tb.tb_next
    if last is None:
        return "unknown"
    return "%s:%d" % (os.path.basename(last.tb_frame.f_code.co_filename), last.tb_lineno)


def forensic(func):
    """Decorator: log the call (summarised args), the return value (summarised),
    how long it took, and any exception (then re-raise it unchanged)."""
    where = "%s.%s" % (func.__module__, func.__qualname__)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not _enabled():
            return func(*args, **kwargs)
        try:
            parts = [safe(a) for a in args[:6]]
            parts += ["%s=%s" % (k, safe(v)) for k, v in list(kwargs.items())[:6]]
            _emit(logging.INFO, where, "CALL", "args=[%s]" % ", ".join(parts))
        except Exception:
            pass
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            _emit(logging.ERROR, where, "EXCEPTION",
                  "%s at %s msg=%s elapsed_ms=%.2f"
                  % (type(exc).__name__, _raised_at(exc), _clip(exc),
                     (time.perf_counter() - start) * 1000))
            raise
        _emit(logging.INFO, where, "RETURN",
              "result=%s elapsed_ms=%.2f" % (safe(result), (time.perf_counter() - start) * 1000))
        return result

    return wrapper


def event(message, level="INFO"):
    """Manual log line for a decision point; module and function name are filled in automatically."""
    try:
        frame = sys._getframe(1)
        where = "%s.%s" % (frame.f_globals.get("__name__", "?"), frame.f_code.co_name)
        _emit(getattr(logging, level.upper(), logging.INFO), where, "EVENT", _clip(message))
    except Exception:
        pass
