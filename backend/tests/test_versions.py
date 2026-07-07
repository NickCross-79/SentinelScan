"""Version parsing and range comparison edge cases."""

from vuln_engine.versions import in_range, parse_version


def test_parse_standard_and_nonstandard():
    assert str(parse_version("2.4.49")) == "2.4.49"
    # OpenSSH-style suffix is tolerated by stripping to the numeric prefix.
    assert str(parse_version("7.2p2")) == "7.2"
    assert parse_version(None) is None
    assert parse_version("not-a-version") is None


def test_inclusive_bounds():
    assert in_range("2.4.49", "2.4.49", True, "2.4.49", True)
    assert not in_range("2.4.50", "2.4.49", True, "2.4.49", True)


def test_exclusive_end_bound():
    assert in_range("7.2", None, False, "7.7", False)
    assert not in_range("7.7", None, False, "7.7", False)  # exclusive end
    assert not in_range("7.8", None, False, "7.7", False)


def test_open_start_bound():
    assert in_range("1.0.0", None, False, "1.20.0", True)


def test_unparseable_version_is_not_in_range():
    assert not in_range("garbage", "1.0", True, "2.0", True)
