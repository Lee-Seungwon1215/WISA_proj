import pytest

from ctkat.dudect_runner import parse_timing_csv


def test_parse_basic_csv():
    text = "sample_id,class,cycles\n0,0,100\n1,1,200\n2,0,110\n"
    s = parse_timing_csv(text)
    assert s.classes == [0, 1, 0]
    assert s.cycles == [100, 200, 110]


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
