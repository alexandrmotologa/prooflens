"""Additional tests to reach maximal test coverage across all modules."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from prooflens.cli.main import app
from prooflens.core.field import BLS12_381_PRIME, BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader, Wire, WireType
from prooflens.core.r1cs_parser import R1CSBinaryParser, R1CSBinaryWriter
from prooflens.core.witness import JSONWitnessParser, SymbolTableParser, Witness, WTNSBinaryParser, WTNSBinaryWriter
from prooflens.debugger.sourcemap import CircomSourceMapper
from prooflens.studio.samples import generate_multiplier_sample

runner = CliRunner()


def test_field_coverage_edges():
    f = FieldElement("0x2a")
    assert f.value == 42
    assert repr(f) == "Fq(42)"
    assert str(f) == "42"

    large = FieldElement(BN254_PRIME - 5)
    assert repr(large) == "Fq(-5)"
    assert str(large) == "-5"
    assert "-5" in large.format_full()

    huge = FieldElement(123456789012345)
    assert "0x" in huge.format_full()

    # Field element initializations
    f_from_f = FieldElement(f)
    assert f_from_f == f

    with pytest.raises(TypeError):
        FieldElement([1, 2, 3])

    with pytest.raises(TypeError):
        f ** "invalid"

    # Arithmetic r-ops
    assert (5 + f).value == 47
    assert (100 - f).value == 58
    assert (2 * f).value == 84
    div_res = 84 / f
    assert div_res.value == 2

    # Equality with non-FieldElement
    assert f == 42
    assert f != "42"

    # Hash
    assert isinstance(hash(f), int)


def test_r1cs_coverage_edges():
    w = Wire(id=1, name="main.out", wire_type=WireType.PUBLIC_OUTPUT)
    assert repr(w) == "Wire(id=1, name='main.out', type=public_output)"

    lc = LinearCombination()
    assert lc.is_empty()
    assert lc.format_formula() == "0"
    assert repr(lc) == "LC(0)"

    lc.add_term(1, 1)
    lc.add_term(2, -1)
    formula = lc.format_formula({1: "a", 2: "b"})
    assert "a" in formula
    assert "- b" in formula

    c = Constraint(id=99, a=lc, b=LinearCombination({0: FieldElement(1)}), c=lc)
    assert "Constraint(id=99" in repr(c)

    # Circuit methods
    h = R1CSHeader(field_size=32, prime=BN254_PRIME, n_wires=2, n_constraints=1)
    circuit = R1CSCircuit(header=h, constraints=[c])
    assert circuit.get_wire_name(999) == "w999"
    assert circuit.get_wire_type(999) == "intermediate"


def test_witness_file_io(tmp_path: Path):
    w = Witness()
    w[0] = 1
    w[1] = 50
    json_path = tmp_path / "wit.json"
    json_path.write_text('{"0": 1, "1": 50}', encoding="utf-8")

    w_loaded = JSONWitnessParser.from_file(json_path)
    assert w_loaded[1].value == 50

    json_dict = w.to_json_dict({1: "main.out"})
    assert json_dict["main.out"] == "50"

    wtns_file = tmp_path / "test.wtns"
    WTNSBinaryWriter.to_file(w, wtns_file)
    parsed = WTNSBinaryParser.from_file(wtns_file)
    assert parsed[1].value == 50


def test_source_mapper_file_io(tmp_path: Path):
    circom_file = tmp_path / "sample.circom"
    circom_file.write_text("template Foo() {\n signal input x;\n}\n", encoding="utf-8")

    mapper = CircomSourceMapper()
    mapper.load_source_file(circom_file)
    loc = mapper.get_signal_location("x")
    assert loc is not None
    assert loc.line_number == 2


def test_cli_trace_invalid(tmp_path: Path):
    circ, _, _ = generate_multiplier_sample()
    r1cs_file = tmp_path / "test.r1cs"
    R1CSBinaryWriter.to_file(circ, r1cs_file)

    res = runner.invoke(app, ["trace", str(r1cs_file), "--signal", "nonexistent_signal"])
    assert res.exit_code == 1
    assert "Unknown signal" in res.output
