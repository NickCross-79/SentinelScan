"""CVE matching against detected service CPEs."""

from vuln_engine import match_service, parse_cpe


def test_parse_cpe():
    assert parse_cpe("cpe:2.3:a:apache:http_server:2.4.49") == ("apache", "http_server", "2.4.49")
    assert parse_cpe("cpe:2.3:a:nginx:nginx:*") == ("nginx", "nginx", None)
    assert parse_cpe("not-a-cpe") is None


def test_apache_2449_matches_both_cves():
    """The plan's worked example: Apache 2.4.49 → CVE-2021-41773 (+42013)."""
    ids = {m.cve.id for m in match_service("cpe:2.3:a:apache:http_server:2.4.49")}
    assert "CVE-2021-41773" in ids
    assert "CVE-2021-42013" in ids


def test_critical_ranks_first():
    matches = match_service("cpe:2.3:a:apache:http_server:2.4.49")
    assert matches[0].cve.severity == "critical"


def test_patched_apache_has_no_matches():
    assert match_service("cpe:2.3:a:apache:http_server:2.4.58") == []


def test_openssh_username_enum_matches_old_versions():
    ids = {m.cve.id for m in match_service("cpe:2.3:a:openbsd:openssh:7.2p2")}
    assert "CVE-2018-15473" in ids
    # Fixed version must not match (exclusive end at 7.7).
    assert match_service("cpe:2.3:a:openbsd:openssh:7.7") == []


def test_unknown_version_is_low_confidence():
    matches = match_service("cpe:2.3:a:apache:http_server:*")
    assert matches, "product-only match should still surface potential CVEs"
    assert all(m.needs_review for m in matches)
