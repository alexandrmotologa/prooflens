"""Unit tests for R1CS data models, evaluation, and binary parser/writer."""

import pytest
from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader, WireType
from prooflens.core.r1cs_parser import R1CSBinaryParser, R1CSBinaryWriter


def test_linear_combination():
    lc = LinearCombination()
    lc.add_term(1, 3)
    lc.add_term(2, -2)
    lc.add_term(0, 5)

    assert lc.wire_ids == {0, 1, 2}

    witness = {
        0: FieldElement(1),
        1: FieldElement(10),
        2: FieldElement(4),
    }

    # 5*1 + 3*10 - 2*4 = 5 + 30 - 8 = 27
    res = lc.eval(witness)
    assert res.value == 27
    assert res.to_signed_int() == 27

    # Cancel a term
    lc.add_term(1, -3)
    assert 1 not in lc.terms
    assert lc.wire_ids == {0, 2}


def test_constraint_evaluation_satisfied_and_unsatisfied():
    # Constraint: (w1 + 2) * (w2) == w3
    # A = w1 + 2*w0
    # B = w2
    # C = w3
    lc_a = LinearCombination({1: FieldElement(1), 0: FieldElement(2)})
    lc_b = LinearCombination({2: FieldElement(1)})
    lc_c = LinearCombination({3: FieldElement(1)})

    constraint = Constraint(id=0, a=lc_a, b=lc_b, c=lc_c)

    # Valid witness: w1=3, w2=4 => (3+2)*4 = 20 => w3=20
    valid_witness = {
        0: FieldElement(1),
        1: FieldElement(3),
        2: FieldElement(4),
        3: FieldElement(20),
    }
    eval_ok = constraint.evaluate(valid_witness)
    assert eval_ok.is_satisfied
    assert eval_ok.residual.is_zero()
    assert eval_ok.unsatisfied_reason is None

    # Invalid witness: w3 = 99
    invalid_witness = {
        0: FieldElement(1),
        1: FieldElement(3),
        2: FieldElement(4),
        3: FieldElement(99),
    }
    eval_fail = constraint.evaluate(invalid_witness)
    assert not eval_fail.is_satisfied
    assert not eval_fail.residual.is_zero()
    assert eval_fail.residual.to_signed_int() == 20 - 99  # -79
    assert eval_fail.unsatisfied_reason is not None


def test_r1cs_binary_roundtrip():
    # Construct a realistic 2-constraint circuit:
    # 1. w1 * w2 == w3 (multiplier: x * y = z)
    # 2. (w3 + 1) * 1 == w4 (increment)
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=5,  # 0: 1, 1: out (w3), 2: pub_in (w1), 3: prv_in (w2), 4: aux (w4)
        n_pub_out=1,
        n_pub_in=1,
        n_prv_in=1,
        n_labels=5,
        n_constraints=2,
    )

    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({3: FieldElement(1)}),
        c=LinearCombination({1: FieldElement(1)}),
    )
    c1 = Constraint(
        id=1,
        a=LinearCombination({1: FieldElement(1), 0: FieldElement(1)}),
        b=LinearCombination({0: FieldElement(1)}),
        c=LinearCombination({4: FieldElement(1)}),
    )

    circuit = R1CSCircuit(header=header, constraints=[c0, c1])
    assert circuit.get_wire_type(0) == WireType.ONE
    assert circuit.get_wire_type(1) == WireType.PUBLIC_OUTPUT
    assert circuit.get_wire_type(2) == WireType.PUBLIC_INPUT
    assert circuit.get_wire_type(3) == WireType.PRIVATE_INPUT
    assert circuit.get_wire_type(4) == WireType.INTERMEDIATE

    # Serialize to bytes
    r1cs_bytes = R1CSBinaryWriter.to_bytes(circuit)
    assert r1cs_bytes.startswith(b"r1cs")

    # Parse back
    parsed = R1CSBinaryParser.from_bytes(r1cs_bytes)
    assert parsed.header.n_wires == 5
    assert parsed.header.n_constraints == 2
    assert parsed.header.prime == BN254_PRIME
    assert len(parsed.constraints) == 2

    # Check constraint 0
    parsed_c0 = parsed.constraints[0]
    assert parsed_c0.a.terms == {2: FieldElement(1)}
    assert parsed_c0.b.terms == {3: FieldElement(1)}
    assert parsed_c0.c.terms == {1: FieldElement(1)}

    # Check constraint 1
    parsed_c1 = parsed.constraints[1]
    assert parsed_c1.a.terms == {1: FieldElement(1), 0: FieldElement(1)}
    assert parsed_c1.b.terms == {0: FieldElement(1)}
    assert parsed_c1.c.terms == {4: FieldElement(1)}


def test_r1cs_parser_invalid_magic():
    bad_data = b"badm\x01\x00\x00\x00"
    with pytest.raises(ValueError, match="Invalid R1CS file magic"):
        R1CSBinaryParser.from_bytes(bad_data)


def test_circuit_evaluation_summary():
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=4,
        n_pub_out=1,
        n_pub_in=1,
        n_prv_in=1,
        n_labels=4,
        n_constraints=1,
    )
    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({3: FieldElement(1)}),
        c=LinearCombination({1: FieldElement(1)}),
    )
    circuit = R1CSCircuit(header=header, constraints=[c0])
    circuit.set_symbols({0: "1", 1: "main.z", 2: "main.x", 3: "main.y"})

    witness = {
        0: FieldElement(1),
        1: FieldElement(50),
        2: FieldElement(5),
        3: FieldElement(10),
    }

    sat, unsat = circuit.evaluate_witness(witness)
    assert len(sat) == 1
    assert len(unsat) == 0

    summary = circuit.summary()
    assert summary["n_wires"] == 4
    assert summary["n_constraints"] == 1
