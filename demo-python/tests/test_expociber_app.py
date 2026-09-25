from expociber_app import obtain_hibp, parse_args


def test_hibp_offline_integration_uses_official_backup() -> None:
    result = obtain_hibp(sample_name="multiple", mode="offline")

    assert result.origin == "respaldo local"
    assert result.data["breach_count"] == 3
    assert result.data["is_official_test_account"] is True


def test_noninteractive_arguments_are_parsed() -> None:
    args = parse_args(["--module", "hibp", "--mode", "offline", "--no-prompt"])

    assert args.module == "hibp"
    assert args.mode == "offline"
    assert args.no_prompt is True
