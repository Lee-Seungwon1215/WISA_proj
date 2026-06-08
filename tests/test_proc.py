"""Bundle N (T12 + T18): policy tests for the subprocess wrapper.

Locks in:
  - `timeout` is required (no default fallback).
  - garbage-byte stdout from a child does NOT raise `UnicodeDecodeError`
    in the parent — it survives as a replacement-character string so
    callers can record it in their ERROR diagnostics.
"""

import subprocess

import pytest

from ctkat._proc import ToolNotFoundError, run_text


def test_run_text_requires_timeout_keyword():
    # `timeout` is keyword-only with no default — forgetting it should
    # be a TypeError, not a silent "wait forever".
    with pytest.raises(TypeError):
        run_text(["true"])  # type: ignore[call-arg]


def test_run_text_garbage_bytes_do_not_raise_unicodedecodeerror():
    # T18: a child that prints invalid UTF-8 must NOT crash the parent
    # — instead the bytes survive as replacement characters and the
    # caller can include them in its diagnostic.
    proc = run_text(
        ["python3", "-c",
         "import sys; sys.stdout.buffer.write(b'\\xff\\xfe garbage\\n')"],
        timeout=5,
    )
    assert proc.returncode == 0
    # The 0xff/0xfe bytes are not valid UTF-8 — they survive as U+FFFD
    # (the Unicode replacement character) instead of raising.
    assert "�" in proc.stdout
    assert "garbage" in proc.stdout


def test_run_text_timeout_raises_timeoutexpired():
    # T12: timeout actually fires. Picks a very short sleep + very short
    # timeout to keep the test fast.
    with pytest.raises(subprocess.TimeoutExpired):
        run_text(["sleep", "5"], timeout=0.1)


def test_run_text_shell_mode_works():
    # builder.run_shell uses shell=True — make sure the wrapper still
    # routes that correctly.
    proc = run_text("echo hello", shell=True, timeout=5)
    assert proc.returncode == 0
    assert "hello" in proc.stdout


def test_run_text_missing_executable_raises_toolnotfound():
    # FN-1: the policy this helper centralizes must cover the most common
    # failure — argv[0] isn't installed / not on PATH. It surfaces as a typed
    # ToolNotFoundError (not a raw FileNotFoundError traceback from inside
    # _execute_child), carrying the offending program name.
    with pytest.raises(ToolNotFoundError) as ei:
        run_text(["ctkat-no-such-binary-xyz"], timeout=5)
    assert "ctkat-no-such-binary-xyz" in str(ei.value)
    assert ei.value.tool == "ctkat-no-such-binary-xyz"


def test_toolnotfound_is_filenotfounderror_subclass():
    # FN-1: subclassing FileNotFoundError keeps the two pre-existing
    # `except FileNotFoundError` sites (asm_scan nm, coverage_check probe)
    # catching it unchanged.
    assert issubclass(ToolNotFoundError, FileNotFoundError)
    with pytest.raises(FileNotFoundError):
        run_text(["ctkat-no-such-binary-xyz"], timeout=5)
