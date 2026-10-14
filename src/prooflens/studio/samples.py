"""Sample circuit generator providing authentic compiled R1CS circuits for testing and studio demo."""

from __future__ import annotations

from typing import Dict, Tuple

from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader
from prooflens.core.witness import Witness


def generate_multiplier_sample(valid: bool = True) -> Tuple[R1CSCircuit, Witness, str]:
    """Circom Multiplier circuit:
    template Multiplier() {
        signal input a;
        signal input b;
        signal output out;
        out <== a * b;
    }
    """
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=4,  # 0: 1, 1: out, 2: a, 3: b
        n_pub_out=1,
        n_pub_in=0,
        n_prv_in=2,
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
    circuit.set_symbols({0: "1", 1: "main.out", 2: "main.a", 3: "main.b"})

    witness = Witness()
    witness[0] = 1
    witness[2] = 7  # a
    witness[3] = 6  # b
    witness[1] = 42 if valid else 99  # out

    circom_source = """pragma circom 2.1.6;

template Multiplier() {
    signal input a;
    signal input b;
    signal output out;

    out <== a * b;
}

component main = Multiplier();
"""
    return circuit, witness, circom_source


def generate_pythagorean_sample(valid: bool = True) -> Tuple[R1CSCircuit, Witness, str]:
    """Pythagorean triplet verifier:
    a^2 + b^2 == c^2
    Constraints:
    C0: a * a == a2  (wire 2 * wire 2 == wire 4)
    C1: b * b == b2  (wire 3 * wire 3 == wire 5)
    C2: c * c == c2  (wire 1 * wire 1 == wire 6)
    C3: (a2 + b2) * 1 == c2  ((wire 4 + wire 5) * wire 0 == wire 6)
    """
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=7,
        n_pub_out=1,  # wire 1: c (public)
        n_pub_in=0,
        n_prv_in=2,  # wire 2: a, wire 3: b (private)
        n_labels=7,
        n_constraints=4,
    )
    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({2: FieldElement(1)}),
        c=LinearCombination({4: FieldElement(1)}),
    )
    c1 = Constraint(
        id=1,
        a=LinearCombination({3: FieldElement(1)}),
        b=LinearCombination({3: FieldElement(1)}),
        c=LinearCombination({5: FieldElement(1)}),
    )
    c2 = Constraint(
        id=2,
        a=LinearCombination({1: FieldElement(1)}),
        b=LinearCombination({1: FieldElement(1)}),
        c=LinearCombination({6: FieldElement(1)}),
    )
    c3 = Constraint(
        id=3,
        a=LinearCombination({4: FieldElement(1), 5: FieldElement(1)}),
        b=LinearCombination({0: FieldElement(1)}),
        c=LinearCombination({6: FieldElement(1)}),
    )

    circuit = R1CSCircuit(header=header, constraints=[c0, c1, c2, c3])
    circuit.set_symbols({
        0: "1",
        1: "main.c",
        2: "main.a",
        3: "main.b",
        4: "main.a2",
        5: "main.b2",
        6: "main.c2",
    })

    # a=3, b=4, c=5 => a2=9, b2=16, c2=25 => 9+16=25
    witness = Witness()
    witness[0] = 1
    witness[2] = 3
    witness[3] = 4
    witness[1] = 5 if valid else 7
    witness[4] = 9
    witness[5] = 16
    witness[6] = 25 if valid else 49

    circom_source = """pragma circom 2.1.6;

template Pythagorean() {
    signal input a;
    signal input b;
    signal input c;

    signal a2;
    signal b2;
    signal c2;

    a2 <== a * a;
    b2 <== b * b;
    c2 <== c * c;

    c2 === a2 + b2;
}

component main = Pythagorean();
"""
    return circuit, witness, circom_source


def generate_vulnerable_underconstrained_sample() -> Tuple[R1CSCircuit, Witness, str]:
    """Circuit with an intentional under-constrained vulnerability!
    Intermediate signal `ratio` is declared and used in an equation, but missing its binding constraint.
    Also has an unused dead signal `dead_weight`.
    """
    header = R1CSHeader(
        field_size=32,
        prime=BN254_PRIME,
        n_wires=6,
        n_pub_out=1,  # wire 1: out
        n_pub_in=1,  # wire 2: denom
        n_prv_in=1,  # wire 3: num
        n_labels=6,
        n_constraints=1,
    )
    # C0: denom * ratio == num (wire 2 * wire 4 == wire 3)
    # Notice `out` (wire 1) is never constrained!
    # And wire 5 (dead_weight) is never used!
    c0 = Constraint(
        id=0,
        a=LinearCombination({2: FieldElement(1)}),
        b=LinearCombination({4: FieldElement(1)}),
        c=LinearCombination({3: FieldElement(1)}),
    )
    circuit = R1CSCircuit(header=header, constraints=[c0])
    circuit.set_symbols({
        0: "1",
        1: "main.out",
        2: "main.denom",
        3: "main.num",
        4: "main.ratio",
        5: "main.dead_weight",
    })

    witness = Witness()
    witness[0] = 1
    witness[2] = 5
    witness[3] = 20
    witness[4] = 4  # 5 * 4 == 20
    witness[1] = 999  # completely unconstrained!
    witness[5] = 0

    circom_source = """pragma circom 2.1.6;

// VULNERABLE CIRCUIT EXAMPLE: Under-constrained signal & dead variable
template DivChecker() {
    signal input denom;
    signal input num;
    signal output out;

    signal ratio;
    signal dead_weight;

    // ratio <-- num / denom
    // Missing check: out === ratio
    denom * ratio === num;
}

component main = DivChecker();
"""
    return circuit, witness, circom_source


SAMPLE_REGISTRY = {
    "multiplier": generate_multiplier_sample,
    "pythagorean": generate_pythagorean_sample,
    "underconstrained": generate_vulnerable_underconstrained_sample,
}
