"""Unit tests for ThreatLens Typer CLI commands, error handling, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import respx
from typer.testing import CliRunner

from threatlens.cli import app

runner = CliRunner()


@pytest.fixture
def mock_all_providers(fixtures_dir: Path) -> respx.MockRouter:
    """Setup respx mocks for 8.8.8.8 across all 3 providers."""
    router = respx.mock(assert_all_called=False)
    vt_data = json.loads(
        (fixtures_dir / "virustotal" / "ip_success.json").read_text(encoding="utf-8")
    )
    otx_data = json.loads((fixtures_dir / "otx" / "ip_success.json").read_text(encoding="utf-8"))
    abuse_data = json.loads(
        (fixtures_dir / "abuseipdb" / "ip_success.json").read_text(encoding="utf-8")
    )

    router.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(
        status_code=200, json=vt_data, headers={"content-type": "application/json"}
    )
    router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(
        status_code=200, json=otx_data, headers={"content-type": "application/json"}
    )
    router.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=200, json=abuse_data, headers={"content-type": "application/json"}
    )
    return router


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ThreatLens: Multi-provider Threat Intelligence Aggregator & CLI" in result.stdout
    assert "lookup" in result.stdout
    assert "batch" in result.stdout
    assert "providers" in result.stdout
    assert "serve" in result.stdout


def test_cli_lookup_invalid_ioc() -> None:
    result = runner.invoke(app, ["lookup", "invalid_ioc_string"])
    assert result.exit_code == 1
    assert "Error:" in result.stderr


def test_cli_lookup_success(mock_all_providers: respx.MockRouter, tmp_path: Path) -> None:
    with mock_all_providers, patch.dict("os.environ", {"THREATLENS_CACHE_DIR": str(tmp_path)}):
        result = runner.invoke(app, ["lookup", "8.8.8.8"])
        # Exit code will be 0 (clean/low risk) or 2 (malicious/suspicious)
        assert result.exit_code in (0, 2)
        assert "ThreatLens Intelligence" in result.stdout
        assert "8.8.8.8" in result.stdout


def test_cli_lookup_json_flag(mock_all_providers: respx.MockRouter, tmp_path: Path) -> None:
    with mock_all_providers, patch.dict("os.environ", {"THREATLENS_CACHE_DIR": str(tmp_path)}):
        result = runner.invoke(app, ["lookup", "8.8.8.8", "--json"])
        assert result.exit_code in (0, 2)
        data = json.loads(result.stdout)
        assert data["ioc"] == "8.8.8.8"
        assert data["normalized_value"] == "8.8.8.8"
        assert "verdict" in data
        assert "risk_score" in data


def test_cli_batch_file_not_found() -> None:
    result = runner.invoke(app, ["batch", "non_existent_file.txt"])
    assert result.exit_code == 1
    assert "Input file not found" in result.stderr


def test_cli_batch_empty_file(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("# Only comments\n\n   \n", encoding="utf-8")
    result = runner.invoke(app, ["batch", str(empty_file)])
    assert result.exit_code == 0
    assert "No valid indicators found" in result.stderr


def test_cli_batch_success_and_export(mock_all_providers: respx.MockRouter, tmp_path: Path) -> None:
    input_file = tmp_path / "iocs.txt"
    input_file.write_text("8.8.8.8\n# comment\n8.8.8.8\n", encoding="utf-8")
    out_file = tmp_path / "report.html"

    with mock_all_providers, patch.dict("os.environ", {"THREATLENS_CACHE_DIR": str(tmp_path)}):
        result = runner.invoke(
            app,
            [
                "batch",
                str(input_file),
                "--output",
                str(out_file),
                "--format",
                "html",
                "--concurrency",
                "2",
            ],
        )
        assert result.exit_code in (0, 2)
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "8.8.8.8" in content


def test_cli_batch_stdin(mock_all_providers: respx.MockRouter, tmp_path: Path) -> None:
    with mock_all_providers, patch.dict("os.environ", {"THREATLENS_CACHE_DIR": str(tmp_path)}):
        result = runner.invoke(
            app,
            ["batch", "-", "--format", "csv"],
            input="8.8.8.8\n",
        )
        assert result.exit_code in (0, 2)
        assert "ioc,ioc_type" in result.stdout
        assert "8.8.8.8" in result.stdout


def test_cli_providers_command(tmp_path: Path) -> None:
    with patch.dict("os.environ", {"THREATLENS_CACHE_DIR": str(tmp_path)}):
        result = runner.invoke(app, ["providers"])
        assert result.exit_code == 0
        assert "ThreatLens Provider Telemetry" in result.stdout
        assert "VIRUSTOTAL" in result.stdout
        assert "OTX" in result.stdout
        assert "ABUSEIPDB" in result.stdout


def test_cli_serve_command() -> None:
    with patch("uvicorn.run") as mock_uvicorn:
        result = runner.invoke(app, ["serve", "--host", "127.0.0.1", "--port", "9000"])
        assert result.exit_code == 0
        assert "Starting ThreatLens REST service" in result.stdout
        mock_uvicorn.assert_called_once_with(
            "threatlens.api.app:create_app",
            factory=True,
            host="127.0.0.1",
            port=9000,
            reload=False,
        )
