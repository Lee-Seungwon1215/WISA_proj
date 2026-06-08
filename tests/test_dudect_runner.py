import math
from pathlib import Path

import pytest

from ctkat.dudect_runner import parse_timing_csv, run_timing_harness


def test_parse_basic_csv():
    text = "sample_id,class,cycles\n0,0,100\n1,1,200\n2,0,110\n"
    s = parse_timing_csv(text)
    assert s.classes == [0, 1, 0]
    assert s.cycles == [100, 200, 110]


def test_parse_drops_nonfinite_cycles_as_malformed():
    # FN / S6 (fail-open fix): float('nan')/float('inf') do NOT raise on parse
    # and are not == 0.0, so they used to slip into samples and poison the
    # t-test (abs(nan) < every threshold => silent PASS). They must be dropped
    # as malformed, leaving only finite samples.
    text = (
        "sample_id,class,cycles\n"
        "0,0,100\n"
        "1,1,nan\n"
        "2,1,inf\n"
        "3,1,-inf\n"
        "4,0,110\n"
    )
    s = parse_timing_csv(text)
    assert s.classes == [0, 0]
    assert s.cycles == [100, 110]
    assert all(math.isfinite(c) for c in s.cycles)


def test_parse_nonfinite_flood_trips_malformed_warning(capsys):
    # The dropped non-finite rows feed the existing malformed-rate warning so a
    # corrupt run is surfaced, not silently shrunk.
    rows = "".join(f"{i},{i%2},nan\n" for i in range(20))
    parse_timing_csv("sample_id,class,cycles\n0,0,100\n" + rows)
    assert "malformed" in capsys.readouterr().err.lower()


def test_run_timing_harness_missing_binary_raises_runtimeerror(tmp_path):
    # FN-1: a binary that can't be executed (here: doesn't exist) must become a
    # RuntimeError so _do_dudect's existing handler maps it to status=ERROR,
    # not a raw FileNotFoundError traceback escaping the T6 promise.
    missing = tmp_path / "nope_binary"
    with pytest.raises(RuntimeError):
        run_timing_harness(missing, tmp_path, timeout=5)


def test_run_timing_harness_stdout_cap(monkeypatch, tmp_path):
    import subprocess
    from ctkat import dudect_runner as dr

    monkeypatch.setattr(dr, "MAX_TIMING_STDOUT_BYTES", 16)

    def fake_run(cmd, *, cwd, stdout, stderr, timeout, check):
        stdout.write(b"sample_id,class,cycles\n0,0,100\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(dr.subprocess, "run", fake_run)
    binary = tmp_path / "h"
    binary.write_text("#!/bin/sh\n")
    with pytest.raises(RuntimeError, match="stdout exceeded"):
        run_timing_harness(binary, tmp_path, timeout=5)


def test_parse_skips_malformed_rows():
    text = (
        "sample_id,class,cycles\n"
        "0,0,100\n"
        "garbage line\n"
        "1,abc,200\n"      # bad class
        "2,1,xyz\n"        # bad cycles
        "3,1,300\n"
    )
    s = parse_timing_csv(text)
    assert s.classes == [0, 1]
    assert s.cycles == [100, 300]


def test_empty_input_raises():
    with pytest.raises(ValueError):
        parse_timing_csv("")


def test_wrong_header_raises():
    with pytest.raises(ValueError):
        parse_timing_csv("not,a,csv\n0,0,0\n")


def test_high_malformed_rate_emits_warning(capsys):
    # 1 valid + 19 malformed = 95% drop rate → above 5% threshold
    text = "sample_id,class,cycles\n" + "0,0,100\n" + "\n".join(["junk"] * 19) + "\n"
    parse_timing_csv(text)
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert "malformed" in captured.err.lower()


def test_low_malformed_rate_is_silent(capsys):
    # 100 valid + 1 malformed = ~1% drop → below threshold, no warning
    rows = [f"{i},0,{100 + i}" for i in range(100)] + ["junk_row"]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    captured = capsys.readouterr()
    assert captured.err == ""


# --- Bundle B: zero-cycle sentinel filter ------------------------------------


def test_zero_cycle_samples_dropped():
    # cycles=0 are Bundle A underflow sentinels and must be filtered out
    # before they enter the t-test (otherwise they drag the mean down).
    text = "sample_id,class,cycles\n0,0,100\n1,1,0\n2,0,200\n3,1,300\n"
    s = parse_timing_csv(text)
    assert s.classes == [0, 0, 1]
    assert s.cycles == [100, 200, 300]


def test_high_zero_rate_emits_warning(capsys):
    # 1 valid + 5 zero = >1% threshold → should warn
    rows = ["0,0,100"] + [f"{i},0,0" for i in range(1, 6)]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    captured = capsys.readouterr()
    assert "zero-cycle" in captured.err.lower()


def test_low_zero_rate_is_silent(capsys):
    # 200 valid + 1 zero = 0.5% → below 1% threshold, no warning
    rows = [f"{i},0,{100 + i}" for i in range(200)] + ["999,0,0"]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    captured = capsys.readouterr()
    assert "zero-cycle" not in captured.err.lower()


# --- Bundle F: per-class drop tracking (F4) + raw counts (S1) ---------------


def test_timing_samples_tracks_raw_counts_and_per_class_drops():
    # 4 class-0 rows: 1 zero, 3 valid. 4 class-1 rows: 0 zero, 4 valid.
    rows = [
        "0,0,100", "1,0,0", "2,0,200", "3,0,300",
        "4,1,1000", "5,1,1100", "6,1,1200", "7,1,1300",
    ]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    s = parse_timing_csv(text)
    assert s.raw_n_total == 8
    assert s.dropped_zero_n0 == 1
    assert s.dropped_zero_n1 == 0
    # Surviving cycles confirm the filter only dropped the zero row.
    assert len(s.cycles) == 7


def test_asymmetric_zero_drop_emits_per_class_warning(capsys):
    # Class 0: 10 valid + 10 zero (50% drop). Class 1: 100 valid + 0 zero.
    # Per-class gap = 50% vs 0%, well above the 5% threshold → warn.
    rows = (
        [f"{i},0,{100+i}" for i in range(10)]
        + [f"{10+i},0,0" for i in range(10)]
        + [f"{20+i},1,{1000+i}" for i in range(100)]
    )
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    err = capsys.readouterr().err.lower()
    assert "asymmetric" in err
    assert "class-0" in err
    assert "class-1" in err


def test_symmetric_zero_drop_no_per_class_warning(capsys):
    # Both classes drop ~50% — that's a noisy host, not a bias signal.
    # Per-class warning should NOT fire (the overall zero-rate warning may).
    rows = (
        [f"{i},0,{100+i}" for i in range(10)]
        + [f"{10+i},0,0" for i in range(10)]
        + [f"{20+i},1,{1000+i}" for i in range(10)]
        + [f"{30+i},1,0" for i in range(10)]
    )
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    err = capsys.readouterr().err.lower()
    # Per-class asymmetry warning must NOT fire (symmetric drop).
    assert "asymmetric" not in err


def test_per_class_warning_silent_when_one_class_empty(capsys):
    # A single-class harness (only class 0) must not trip the per-class
    # check trivially — without a class-1 baseline there's no gap to detect.
    rows = [f"{i},0,{100+i}" for i in range(10)] + [f"{10+i},0,0" for i in range(10)]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    err = capsys.readouterr().err.lower()
    assert "asymmetric" not in err


def test_invalid_class_value_counted_as_malformed():
    """S5: the harness only ever emits class 0 or 1. A row with any other
    class is corrupt output. It must NOT be appended to samples (where the
    downstream `if cls == 0/1` filter would silently drop it from the t-test
    while it still inflated raw_n_total) — instead it counts as malformed so
    the malformed-rate warning path sees it."""
    text = "sample_id,class,cycles\n0,0,100\n1,1,200\n2,2,150\n3,0,110\n"
    s = parse_timing_csv(text)
    # class-2 row excluded from samples entirely
    assert 2 not in s.classes
    assert len(s.classes) == 3
    # and it didn't masquerade as a valid sample
    assert all(c in (0, 1) for c in s.classes)


def test_invalid_class_high_rate_warns(capsys):
    """S5: a flood of bad-class rows should trip the malformed warning rather
    than vanish silently."""
    rows = ["0,0,100"] + [f"{i},2,100" for i in range(1, 20)]
    text = "sample_id,class,cycles\n" + "\n".join(rows) + "\n"
    parse_timing_csv(text)
    err = capsys.readouterr().err
    assert "malformed" in err.lower()
