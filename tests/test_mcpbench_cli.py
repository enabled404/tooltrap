"""tests/test_mcpbench_cli.py — `tooltrap mcpbench` CLI smoke tests."""

from __future__ import annotations

import json

from click.testing import CliRunner

from tooltrap.cli import main


def test_mcpbench_list():
    runner = CliRunner()
    result = runner.invoke(main, ["mcpbench", "list"])
    assert result.exit_code == 0, result.output
    assert "MCP01-01" in result.output
    assert "MCP05-06" in result.output


def test_mcpbench_list_json_category_filter():
    runner = CliRunner()
    result = runner.invoke(main, ["mcpbench", "list", "-c", "MCP02", "-o", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload) == 6
    assert all(p["category"] == "MCP02" for p in payload)


def test_mcpbench_run_hardened_json():
    runner = CliRunner()
    result = runner.invoke(
        main, ["mcpbench", "run", "--agent", "hardened", "-c", "MCP01", "-o", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["total"] == 6
    assert payload["summary"]["counts"] == {"pass": 6}
    assert payload["results"][0]["id"] == "MCP01-01"


def test_mcpbench_run_naive_text_shows_vulnerable():
    runner = CliRunner()
    result = runner.invoke(
        main, ["mcp-bench", "run", "--agent", "naive", "-c", "MCP04"]
    )
    assert result.exit_code == 0, result.output
    assert "VULNERABLE" in result.output
    assert "SUMMARY" in result.output


def test_mcpbench_run_save_and_report(tmp_path):
    runner = CliRunner()
    save_path = tmp_path / "run.json"
    result = runner.invoke(
        main,
        ["mcpbench", "run", "--agent", "naive", "-c", "MCP05",
         "-o", "json", "--save", str(save_path)],
    )
    assert result.exit_code == 0, result.output
    assert save_path.exists()
    saved = json.loads(save_path.read_text())
    assert saved["summary"]["counts"] == {"vulnerable": 6}

    report = runner.invoke(main, ["mcpbench", "report", "-i", str(save_path)])
    assert report.exit_code == 0, report.output
    assert "SUMMARY" in report.output
    assert "VULNERABLE" in report.output
    assert "MCP05" in report.output
