import argparse
import json

import pytest

from cybersec.api_client import APIClientSettings, client_from_env
from cybersec.api_client_cli import run_remote_command
from cybersec.cli import build_parser


TOKEN = "stage26-test-token-with-at-least-24-characters"


def test_client_settings_read_environment_and_validate_loopback():
    env = {
        "CYBERSEC_API_URL": "http://localhost:8765",
        "CYBERSEC_API_TOKEN": TOKEN,
        "CYBERSEC_API_TIMEOUT": "4.5",
        "CYBERSEC_API_RETRIES": "3",
        "CYBERSEC_API_RETRY_BACKOFF": "0.2",
    }
    settings = APIClientSettings.from_env(env)
    assert settings.base_url == "http://localhost:8765"
    assert settings.timeout == 4.5
    assert settings.retries == 3
    assert settings.retry_backoff == 0.2
    assert client_from_env(env).retries == 3


def test_client_settings_reject_non_loopback_and_invalid_values():
    with pytest.raises(ValueError, match="loopback"):
        APIClientSettings.from_env({"CYBERSEC_API_URL": "http://example.org", "CYBERSEC_API_TOKEN": TOKEN})
    with pytest.raises(ValueError, match="CYBERSEC_API_RETRIES"):
        APIClientSettings.from_env({"CYBERSEC_API_RETRIES": "many"})
    with pytest.raises(ValueError, match="CYBERSEC_API_TOKEN"):
        client_from_env({})


def test_remote_cli_parser_builds_expected_arguments():
    parser = build_parser()
    args = parser.parse_args(["remote", "jobs", "--status", "queued", "--tool", "demo", "--limit", "20"])
    assert args.command == "remote"
    assert args.remote_command == "jobs"
    assert args.status == "queued"
    assert args.tool == "demo"
    assert args.limit == 20


def test_remote_mutations_require_confirmation():
    args = argparse.Namespace(remote_command="target-add", url="https://example.com", confirm_authorized=False)
    with pytest.raises(PermissionError, match="--confirm-authorized"):
        run_remote_command(args, client=object())


def test_remote_cli_prints_page_as_json(capsys):
    class FakePage:
        items = [{"id": 1, "url": "https://example.com/"}]
        total = 1
        limit = 25
        offset = 0

    class FakeClient:
        def list_targets(self, **kwargs):
            assert kwargs == {"limit": 25, "offset": 0}
            return FakePage()

    args = argparse.Namespace(remote_command="targets", limit=25, offset=0)
    assert run_remote_command(args, client=FakeClient()) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["total"] == 1
    assert output["items"][0]["id"] == 1


def test_client_settings_reject_non_finite_timing_values():
    with pytest.raises(ValueError, match="finite"):
        APIClientSettings.from_env({"CYBERSEC_API_TIMEOUT": "nan"})
    with pytest.raises(ValueError, match="finite"):
        APIClientSettings.from_env({"CYBERSEC_API_RETRY_BACKOFF": "inf"})
