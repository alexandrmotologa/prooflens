"""Unit tests for new advanced features: Evaluator, AutoFixer, Diff, BitWidth, Exporter."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from prooflens.cli.main import app
from prooflens.core.diff import CircuitDiffer
from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader
from prooflens.core.r1cs_parser import R1CSBinaryWriter
from prooflens.core.witness import WTNSBinaryWriter, Witness
from prooflens.debugger.bitwidth import BitWidthScanner
from prooflens.debugger.evaluator import ForwardWitnessEvaluator
from prooflens.debugger.exporter import TestVectorExporter
from prooflens.debugger.solver import WitnessAutoFixer
from prooflens.studio.app import app as fastapi_app
from prooflens.studio.samples import generate_multiplier_sample, generate_pythagorean_sample

runner = CliRunner()
client = TestClient(fastapi_app)


def test_forward_evaluator_multiplier():
    circ, _, _ = generate_multiplier_sample()
    evaluator = ForwardWitnessEvaluator(circ)

    # Supply inputs only: a=6, b=7
    res = evaluator.evaluate_from_inputs({"main.a": 6, "main.b": 7})

    assert res.is_complete is True
    assert res.witness[1].value == 42  # out
    assert len(res.steps) > 0


def test_auto_fixer_multiplier():
    circ, wit_bad, _ = generate_multiplier_sample(valid=False)
    # wit_bad has out=99 instead of 42
    fixer = WitnessAutoFixer(circ, wit_bad)
    fixes = fixer.find_all_fixes()

    assert len(fixes) > 0
    top_fix = fixes[0]
    # Should suggest out = 42
    assert top_fix.suggested_value.value == 42
    assert top_fix.net_satisfied_change == 1


def test_circuit_diff():
    cA, _, _ = generate_multiplier_sample()
    cB, _, _ = generate_pythagorean_sample()

    differ = CircuitDiffer(cA, cB)
    report = differ.compute_diff()

    assert report.has_changes is True
    assert report.constraints_delta == len(cB.constraints) - len(cA.constraints)
    assert report.wires_delta == cB.header.n_wires - cA.header.n_wires


def test_bitwidth_scanner_boolean_check():
    # Circuit with 1 bit decomposition x = 1*b0 + 2*b1
    # b0 has boolean check b0 * (1 - b0) == 0
    # b1 is MISSING its boolean check!
    header = R1CSHeader(field_size=32, prime=BN254_PRIME, n_wires=4, n_constraints=2)

    # C0: x == 1*b0 + 2*b1  => (1*b0 + 2*b1) * 1 == x
    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1), 3: FieldElement(2)}),
        b=LinearCombination({0: FieldElement(1)}),
        c=LinearCombination({1: FieldElement(1)}),
    )
    # C1: b0 * (1 - b0) == 0
    c1 = Constraint(
        id=1,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({0: FieldElement(1), 2: FieldElement(-1)}),
        c=LinearCombination(),
    )

    circ = R1CSCircuit(header=header, constraints=[c0, c1])
    circ.set_symbols({0: "1", 1: "main.x", 2: "main.b0", 3: "main.b1"})

    scanner = BitWidthScanner(circ)
    findings = scanner.scan()

    missing_bool = [f for f in findings if f.category == "MISSING_BOOLEAN_CHECK"]
    assert len(missing_bool) == 1
    assert missing_bool[0].signal_name == "main.b1"


def test_test_vector_exporter(tmp_path: Path):
    circ, wit, _ = generate_multiplier_sample(valid=True)
    exporter = TestVectorExporter(circ, wit)

    json_data = exporter.export_json()
    assert "publicSignals" in json_data
    assert "42" in json_data["publicSignals"]

    solidity_code = exporter.export_foundry_solidity()
    assert "contract CircuitProofTest" in solidity_code
    assert "pubSignals.push(42);" in solidity_code

    out_sol = tmp_path / "Test.t.sol"
    exporter.write_to_file(out_sol, format_type="foundry")
    assert out_sol.exists()


def test_cli_new_commands(tmp_path: Path):
    circ, wit, _ = generate_multiplier_sample(valid=True)
    r1cs_file = tmp_path / "c.r1cs"
    wtns_file = tmp_path / "w.wtns"
    inputs_file = tmp_path / "in.json"
    inputs_file.write_text('{"main.a": 6, "main.b": 7}', encoding="utf-8")

    R1CSBinaryWriter.to_file(circ, r1cs_file)
    WTNSBinaryWriter.to_file(wit, wtns_file)

    sym_file = tmp_path / "c.sym"
    sym_file.write_text("0,1,main\n1,main.out,main\n2,main.a,main\n3,main.b,main\n", encoding="utf-8")

    # compute-witness
    res_comp = runner.invoke(app, ["compute-witness", str(r1cs_file), "--inputs", str(inputs_file), "--sym", str(sym_file)])
    assert res_comp.exit_code == 0
    assert "Witness computed successfully" in res_comp.output

    # diff
    p_circ, _, _ = generate_pythagorean_sample()
    r1cs_p = tmp_path / "p.r1cs"
    R1CSBinaryWriter.to_file(p_circ, r1cs_p)
    res_diff = runner.invoke(app, ["diff", str(r1cs_file), str(r1cs_p)])
    assert res_diff.exit_code == 0
    assert "Circuit Diff" in res_diff.output

    # scan-bits
    res_scan = runner.invoke(app, ["scan-bits", str(r1cs_file)])
    assert res_scan.exit_code == 0

    # export-test
    out_test = tmp_path / "Exported.t.sol"
    res_exp = runner.invoke(app, ["export-test", str(r1cs_file), "--witness", str(wtns_file), "--output", str(out_test)])
    assert res_exp.exit_code == 0
    assert out_test.exists()


def test_studio_new_endpoints():
    # 1. auto-fixes
    res = client.get("/api/circuit/auto-fixes")
    assert res.status_code == 200

    # 2. compute witness
    res_comp = client.post("/api/witness/compute", json={"inputs": {"2": 6, "3": 7}})
    assert res_comp.status_code == 200

    # 3. trace-steps
    res_steps = client.get("/api/circuit/trace-steps")
    assert res_steps.status_code == 200
    assert isinstance(res_steps.json(), list)

    # 4. export-test
    res_exp = client.get("/api/circuit/export-test?format=foundry")
    assert res_exp.status_code == 200
    assert "code" in res_exp.json()
