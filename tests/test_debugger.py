"""Unit tests for CircuitDebugger, DAGEngine, and CircomSourceMapper."""

import pytest
from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader
from prooflens.core.witness import Witness
from prooflens.debugger.dag import DAGEngine
from prooflens.debugger.engine import CircuitDebugger
from prooflens.debugger.sourcemap import CircomSourceMapper


@pytest.fixture
def sample_circuit():
    # 2 inputs: a (wire 2), b (wire 3)
    # 1 intermediate: prod (wire 4)
    # 1 output: out (wire 1)
    # Constraints:
    # C0: a * b == prod  (wire 2 * wire 3 == wire 4)
    # C1: prod * 1 == out (wire 4 * wire 0 == wire 1)
    # Wire 5 is an unconstrained dead signal (for audit testing)
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=6,
        n_pub_out=1,
        n_pub_in=0,
        n_prv_in=2,
        n_labels=6,
        n_constraints=2,
    )
    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({3: FieldElement(1)}),
        c=LinearCombination({4: FieldElement(1)}),
    )
    c1 = Constraint(
        id=1,
        a=LinearCombination({4: FieldElement(1)}),
        b=LinearCombination({0: FieldElement(1)}),
        c=LinearCombination({1: FieldElement(1)}),
    )
    circuit = R1CSCircuit(header=header, constraints=[c0, c1])
    circuit.set_symbols({
        0: "1",
        1: "main.out",
        2: "main.a",
        3: "main.b",
        4: "main.prod",
        5: "main.unused",
    })
    return circuit


def test_circuit_debugger_valid(sample_circuit):
    # a=3, b=4 => prod=12 => out=12
    witness = Witness()
    witness[0] = 1
    witness[1] = 12
    witness[2] = 3
    witness[3] = 4
    witness[4] = 12
    witness[5] = 0

    debugger = CircuitDebugger(sample_circuit, witness)
    report = debugger.run_debug()

    assert report.total_constraints == 2
    assert report.satisfied_count == 2
    assert report.unsatisfied_count == 0
    assert report.is_valid is True
    assert report.constant_one_valid is True


def test_circuit_debugger_failure_isolation(sample_circuit):
    # Invalid witness: prod=99 instead of 12
    witness = Witness()
    witness[0] = 1
    witness[1] = 12
    witness[2] = 3
    witness[3] = 4
    witness[4] = 99
    witness[5] = 0

    debugger = CircuitDebugger(sample_circuit, witness)
    report = debugger.run_debug()

    assert report.is_valid is False
    assert report.unsatisfied_count > 0

    # C0 should fail: 3 * 4 != 99
    f0 = next(f for f in report.failures if f.constraint_id == 0)
    assert f0.residual.to_signed_int() == 12 - 99  # -87
    culprit_names = [c.name for c in f0.culprit_candidates]
    assert "main.prod" in culprit_names


def test_circuit_debugger_audit(sample_circuit):
    debugger = CircuitDebugger(sample_circuit)
    findings = debugger.audit_circuit()

    # Wire 5 is unused -> DEAD_SIGNAL
    dead_findings = [f for f in findings if f.category == "DEAD_SIGNAL"]
    assert len(dead_findings) == 1
    assert dead_findings[0].wire_id == 5
    assert dead_findings[0].signal_name == "main.unused"


def test_dag_engine(sample_circuit):
    witness = Witness()
    witness[0] = 1
    witness[1] = 12
    witness[2] = 3
    witness[3] = 4
    witness[4] = 12

    dag_engine = DAGEngine(sample_circuit, witness)
    dag = dag_engine.build_dag()

    assert len(dag.nodes) > 0
    assert len(dag.edges) > 0

    # Cytoscape export
    elements = dag.to_cytoscape_elements()
    assert len(elements) == len(dag.nodes) + len(dag.edges)

    # Provenance trace for output signal (sig_1)
    prov_dag = dag_engine.trace_provenance("sig_1")
    prov_node_ids = {n.id for n in prov_dag.nodes}
    assert "sig_1" in prov_node_ids
    assert "cons_1" in prov_node_ids
    assert "sig_4" in prov_node_ids  # prod feeds cons_1

    # Downstream blast radius trace from input (sig_2: main.a)
    down_dag = dag_engine.trace_downstream("sig_2")
    down_node_ids = {n.id for n in down_dag.nodes}
    assert "sig_2" in down_node_ids
    assert "cons_0" in down_node_ids
    assert "sig_4" in down_node_ids


def test_circom_source_mapper():
    circom_code = """
template Multiplier() {
    signal input a;
    signal input b;
    signal output out;
    out <== a * b;
}
component main = Multiplier();
"""
    mapper = CircomSourceMapper()
    mapper.load_source_text("multiplier.circom", circom_code)

    loc = mapper.get_signal_location("main.a")
    assert loc is not None
    assert loc.file_path == "multiplier.circom"
    assert "signal input a;" in loc.line_text
    assert loc.line_number == 3
