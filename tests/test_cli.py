"""Unit tests for ProofLens CLI commands."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from prooflens.cli.main import app
from prooflens.core.r1cs_parser import R1CSBinaryWriter
from prooflens.core.witness import WTNSBinaryWriter
from prooflens.studio.samples import generate_multiplier_sample, generate_vulnerable_underconstrained_sample

runner = CliRunner()


@pytest.fixture
def circuit_files(tmp_path: Path):
    circ, wit, _ = generate_multiplier_sample(valid=True)
    r1cs_file = tmp_path / "test.r1cs"
    wtns_file = tmp_path / "test.wtns"
    sym_file = tmp_path / "test.sym"

    R1CSBinaryWriter.to_file(circ, r1cs_file)
    WTNSBinaryWriter.to_file(wit, wtns_file)
    sym_file.write_text("0,1,main\n1,main.out,main\n2,main.a,main\n3,main.b,main\n", encoding="utf-8")

    return r1cs_file, wtns_file, sym_file


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ProofLens version" in result.output


def test_cli_inspect(circuit_files):
    r1cs_file, _, sym_file = circuit_files
    result = runner.invoke(app, ["inspect", str(r1cs_file), "--sym", str(sym_file)])
    assert result.exit_code == 0
    assert "Total Wires" in result.output
    assert "Total Constraints" in result.output
    assert "main.a * main.b == main.out" in result.output


def test_cli_check_satisfied(circuit_files):
    r1cs_file, wtns_file, sym_file = circuit_files
    result = runner.invoke(app, ["check", str(r1cs_file), "--witness", str(wtns_file), "--sym", str(sym_file)])
    assert result.exit_code == 0
    assert "CIRCUIT SATISFIED" in result.output


def test_cli_check_violation(tmp_path: Path):
    circ, wit_bad, _ = generate_multiplier_sample(valid=False)
    r1cs_file = tmp_path / "bad.r1cs"
    wtns_file = tmp_path / "bad.wtns"

    R1CSBinaryWriter.to_file(circ, r1cs_file)
    WTNSBinaryWriter.to_file(wit_bad, wtns_file)

    result = runner.invoke(app, ["check", str(r1cs_file), "--witness", str(wtns_file)])
    assert result.exit_code == 0
    assert "CIRCUIT UNSATISFIED" in result.output
    assert "Violation at Constraint C0" in result.output


def test_cli_audit(tmp_path: Path):
    circ, _, _ = generate_vulnerable_underconstrained_sample()
    r1cs_file = tmp_path / "vuln.r1cs"
    R1CSBinaryWriter.to_file(circ, r1cs_file)

    result = runner.invoke(app, ["audit", str(r1cs_file)])
    assert result.exit_code == 0
    assert "Security Audit" in result.output
    assert "UNDER_CONSTRAINED" in result.output or "DEAD_SIGNAL" in result.output


def test_cli_trace(circuit_files):
    r1cs_file, wtns_file, sym_file = circuit_files
    result = runner.invoke(app, ["trace", str(r1cs_file), "--signal", "1", "--sym", str(sym_file), "--witness", str(wtns_file)])
    assert result.exit_code == 0
    assert "Dependency Provenance Trace" in result.output


def test_cli_export_dag(circuit_files, tmp_path: Path):
    r1cs_file, wtns_file, sym_file = circuit_files
    out_file = tmp_path / "exported_dag.json"
    result = runner.invoke(app, ["export-dag", str(r1cs_file), "--output", str(out_file), "--sym", str(sym_file), "--witness", str(wtns_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    assert out_file.stat().st_size > 0
