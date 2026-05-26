from pathlib import Path

from ctkat.valgrind_parser import (
    FindingType,
    Severity,
    parse_valgrind_log,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_empty_log_yields_no_findings():
    assert parse_valgrind_log("") == []


def test_bad_log_detects_secret_dependent_branch():
    text = (FIXTURES / "valgrind_bad.log").read_text()
    findings = parse_valgrind_log(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == FindingType.SECRET_DEPENDENT_BRANCH
    assert f.severity == Severity.HIGH
    assert f.frames, "expected at least one stack frame"
    assert f.frames[0].function == "bad_compare"
    assert f.frames[0].file == "bad_compare.c"
    assert f.frames[0].line == 10
    assert f.origin_frames, "expected origin frame"
    assert f.origin_frames[0].function == "main"
    assert f.origin_frames[0].file == "harness_bad.c"
    assert f.origin_frames[0].line == 18


def test_safe_log_yields_no_findings():
    text = (FIXTURES / "valgrind_safe.log").read_text()
    assert parse_valgrind_log(text) == []


def test_multi_log_yields_two_distinct_findings():
    text = (FIXTURES / "valgrind_multi.log").read_text()
    findings = parse_valgrind_log(text)
    assert len(findings) == 2

    branch = findings[0]
    assert branch.type == FindingType.SECRET_DEPENDENT_BRANCH
    assert branch.severity == Severity.HIGH
    # 3-deep call stack should all be captured
    assert [fr.function for fr in branch.frames] == ["foo", "bar", "main"]
    assert branch.frames[0].file == "foo.c"
    assert branch.frames[0].line == 23

    value_use = findings[1]
    assert value_use.type == FindingType.SECRET_DEPENDENT_VALUE_USE
    assert value_use.severity == Severity.MEDIUM
    assert value_use.frames[0].function == "poly_reduce"
    assert value_use.frames[0].line == 88


def test_banner_and_footer_lines_are_ignored():
    # Valgrind real output starts with a banner block and ends with HEAP/ERROR
    # SUMMARY lines. These must not be classified as findings.
    text = (FIXTURES / "valgrind_multi.log").read_text()
    findings = parse_valgrind_log(text)
    messages = [f.message for f in findings]
    assert all("Memcheck," not in m for m in messages)
    assert all("ERROR SUMMARY" not in m for m in messages)
    assert all("Copyright" not in m for m in messages)


def test_value_use_in_memory_function_promoted_to_memory_access():
    # "Use of uninitialised value" whose top stack frame is `memcpy` should
    # be promoted from VALUE_USE (MEDIUM) to MEMORY_ACCESS (HIGH).
    text = (
        "==1== Use of uninitialised value of size 8\n"
        "==1==    at 0x4001234: memcpy (memcpy.c:42)\n"
        "==1==    by 0x4001100: my_caller (mycode.c:7)\n"
        "==1==  Uninitialised value was created by a client request\n"
        "==1==    at 0x4001000: main (main.c:5)\n"
        "==1== \n"
    )
    findings = parse_valgrind_log(text)
    assert len(findings) == 1
    assert findings[0].type == FindingType.SECRET_DEPENDENT_MEMORY_ACCESS
    assert findings[0].severity == Severity.HIGH


def test_value_use_with_lookup_pattern_promoted():
    # Any frame whose function name contains a lookup-table pattern triggers
    # the promotion.
    text = (
        "==1== Use of uninitialised value of size 1\n"
        "==1==    at 0x401234: aes_ttable_round (aes.c:88)\n"
        "==1==    by 0x401100: aes_encrypt (aes.c:10)\n"
        "==1== \n"
    )
    findings = parse_valgrind_log(text)
    assert findings[0].type == FindingType.SECRET_DEPENDENT_MEMORY_ACCESS


def test_back_to_back_findings_both_get_finalized():
    # Regression: when one finding closes because a NEW finding header arrives
    # (no blank `==PID== ` line in between), the first finding must still go
    # through _finalize so VALUE_USE→MEMORY_ACCESS promotion is applied.
    text = (
        "==1== Use of uninitialised value of size 1\n"
        "==1==    at 0x401234: sbox_lookup (aes.c:88)\n"
        "==1==    by 0x401100: main (main.c:5)\n"
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x401500: another_fn (other.c:12)\n"
        "==1==    by 0x401100: main (main.c:5)\n"
        "==1== \n"
    )
    findings = parse_valgrind_log(text)
    assert len(findings) == 2
    # The first finding's promotion must have run despite the lack of a
    # blank-line boundary before the second finding started.
    assert findings[0].type == FindingType.SECRET_DEPENDENT_MEMORY_ACCESS
    assert findings[0].severity == Severity.HIGH
    assert findings[1].type == FindingType.SECRET_DEPENDENT_BRANCH


def test_value_use_in_ordinary_function_stays_value_use():
    text = (
        "==1== Use of uninitialised value of size 8\n"
        "==1==    at 0x401234: poly_reduce (poly.c:51)\n"
        "==1==    by 0x401100: main (main.c:5)\n"
        "==1== \n"
    )
    findings = parse_valgrind_log(text)
    assert findings[0].type == FindingType.SECRET_DEPENDENT_VALUE_USE
    assert findings[0].severity == Severity.MEDIUM


def test_truncated_log_does_not_crash():
    # Log cut off mid-finding (no closing blank line, no error summary).
    # Should still surface the partial finding rather than dropping it.
    text = (
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x401234: foo (foo.c:10)\n"
        # No "==1== " closing line — simulates killed process.
    )
    findings = parse_valgrind_log(text)
    assert len(findings) == 1
    assert findings[0].type == FindingType.SECRET_DEPENDENT_BRANCH
    assert findings[0].frames[0].function == "foo"


def test_lines_without_pid_prefix_are_ignored():
    # Real Valgrind output sometimes interleaves non-prefixed lines (e.g.
    # the harness's own stderr). They must not be classified as findings.
    text = (
        "Some harness stderr leaking through\n"
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x401234: foo (foo.c:10)\n"
        "==1== \n"
        "more stray junk\n"
    )
    findings = parse_valgrind_log(text)
    assert len(findings) == 1


def test_strcmp_no_longer_promoted_to_memory_access():
    # Regression: strcmp/strncmp/memcmp are *comparison* routines, not
    # memory primitives — their access pattern is loop-counter-indexed, not
    # secret-indexed. Earlier we wrongly inflated their findings to HIGH
    # MEMORY_ACCESS; they should now stay as MEDIUM VALUE_USE.
    text = (
        "==1== Use of uninitialised value of size 1\n"
        "==1==    at 0x401234: strcmp (strcmp.c:42)\n"
        "==1==    by 0x401100: main (main.c:5)\n"
        "==1== \n"
    )
    findings = parse_valgrind_log(text)
    assert findings[0].type == FindingType.SECRET_DEPENDENT_VALUE_USE
    assert findings[0].severity == Severity.MEDIUM


def test_unknown_message_is_skipped():
    # Whitelist policy: unrecognized diagnostics are skipped rather than
    # surfaced as UNKNOWN findings (avoids banner noise polluting the report).
    text = (
        "==1== Some unfamiliar valgrind diagnostic\n"
        "==1==    at 0x1: weird (weird.c:1)\n"
        "==1== \n"
    )
    assert parse_valgrind_log(text) == []


# --- Bundle I: T2 lookup_patterns override + T3 dropped count -----------


def test_lookup_patterns_override_disables_promotion():
    # T2: a stack frame whose function name contains a built-in pattern
    # ("lookup") would normally promote VALUE_USE → MEMORY_ACCESS. Passing
    # an empty list MUST disable the heuristic.
    text = (
        "==1== Use of uninitialised value of size 8\n"
        "==1==    at 0x1: my_lookup_helper (foo.c:1)\n"
        "==1== \n"
    )
    promoted = parse_valgrind_log(text)
    assert promoted[0].type == FindingType.SECRET_DEPENDENT_MEMORY_ACCESS
    not_promoted = parse_valgrind_log(text, lookup_patterns=[])
    assert not_promoted[0].type == FindingType.SECRET_DEPENDENT_VALUE_USE


def test_lookup_patterns_override_uses_user_list():
    # User-supplied pattern should fire for matching names even when the
    # built-in list wouldn't have matched.
    text = (
        "==1== Use of uninitialised value of size 8\n"
        "==1==    at 0x1: my_special_routine (foo.c:1)\n"
        "==1== \n"
    )
    default = parse_valgrind_log(text)
    assert default[0].type == FindingType.SECRET_DEPENDENT_VALUE_USE
    overridden = parse_valgrind_log(text, lookup_patterns=["special"])
    assert overridden[0].type == FindingType.SECRET_DEPENDENT_MEMORY_ACCESS


def test_dropped_count_increments_on_unrecognized_lines():
    # T3: unrecognized header lines must be counted, not silently dropped.
    from ctkat.valgrind_parser import parse_valgrind_log_with_stats
    text = (
        "==1== Memcheck, a memory error detector\n"
        "==1== Command: ./bin/foo\n"
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x1: foo (foo.c:1)\n"
        "==1== \n"
        "==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
    )
    findings, dropped = parse_valgrind_log_with_stats(text)
    assert len(findings) == 1
    # Banner/footer lines counted as dropped (3 banner + 1 error summary).
    assert dropped >= 3


def test_dropped_count_zero_on_pure_findings_log():
    from ctkat.valgrind_parser import parse_valgrind_log_with_stats
    text = (
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x1: foo (foo.c:1)\n"
        "==1== \n"
    )
    _, dropped = parse_valgrind_log_with_stats(text)
    assert dropped == 0
