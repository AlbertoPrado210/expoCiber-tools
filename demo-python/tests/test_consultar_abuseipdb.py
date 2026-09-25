import pytest

from consultar_abuseipdb import DemoError, sanitize_report, validate_public_ip


def test_validate_public_ip_accepts_global_address() -> None:
    assert validate_public_ip("1.1.1.1") == "1.1.1.1"


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.4", "not-an-ip"])
def test_validate_public_ip_rejects_non_global_or_invalid(value: str) -> None:
    with pytest.raises(DemoError):
        validate_public_ip(value)


def test_sanitize_report_keeps_only_presentation_fields() -> None:
    source = {
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 65,
        "countryCode": "NL",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.invalid",
        "totalReports": 439,
        "numDistinctUsers": 182,
        "lastReportedAt": "2026-09-06T00:00:00+00:00",
        "unexpected_secret": "must-not-survive",
    }

    result = sanitize_report("45.154.98.44", "Caso de prueba", source, 90)

    assert result["abuse_confidence_score"] == 65
    assert result["total_reports"] == 439
    assert "unexpected_secret" not in result
