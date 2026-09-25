import pytest

from consultar_hibp import (
    DemoError,
    is_test_account,
    mask_email,
    sanitize_breach,
    translate_data_class,
    validate_email,
)


def test_validate_email_normalizes_account() -> None:
    assert validate_email(" TEST@Example.com ") == "test@example.com"


@pytest.mark.parametrize("value", ["missing-at", "@example.com", "test@localhost"])
def test_validate_email_rejects_invalid_values(value: str) -> None:
    with pytest.raises(DemoError):
        validate_email(value)


def test_official_test_domain_is_detected() -> None:
    assert is_test_account("multiple-breaches@hibp-integration-tests.com")
    assert not is_test_account("person@example.com")


def test_personal_email_is_masked() -> None:
    assert mask_email("alberto@example.com") == "al*****@example.com"


def test_known_data_class_is_translated_for_the_audience() -> None:
    assert translate_data_class("Passwords") == "Contraseñas"


def test_sanitize_breach_drops_description_and_logo() -> None:
    source = {
        "Name": "Example",
        "Title": "Example breach",
        "Domain": "example.com",
        "BreachDate": "2020-01-01",
        "PwnCount": 123,
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "Description": "HTML that is not needed in the terminal",
        "LogoPath": "https://example.com/logo.png",
    }

    result = sanitize_breach(source)

    assert result["title"] == "Example breach"
    assert "Description" not in result
    assert "LogoPath" not in result
