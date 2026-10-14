"""Bit-Width and Field Wrap-Around Vulnerability Scanner.

Scans R1CS circuits for boolean enforcement, bit-decomposition patterns, missing
range checks, and dangerous finite field wrap-around values (near prime modulus q).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, R1CSCircuit, WireType
from prooflens.core.witness import Witness


@dataclass
class BitCheckFinding:
    """A vulnerability finding related to bit-width or range checks."""

    severity: str  # "HIGH", "MEDIUM", "LOW"
    category: str  # "MISSING_BOOLEAN_CHECK", "RANGE_OVERFLOW", "FIELD_WRAP_AROUND"
    wire_id: int
    signal_name: str
    description: str
    expected_bits: Optional[int] = None
    actual_value: Optional[str] = None


class BitWidthScanner:
    """Detects missing boolean checks, bit decompositions, and range overflows."""

    def __init__(self, circuit: R1CSCircuit, witness: Optional[Witness] = None) -> None:
        self.circuit = circuit
        self.witness = witness
        self.modulus = circuit.header.prime

    def scan(self) -> List[BitCheckFinding]:
        """Perform comprehensive bit-width and range check audit."""
        findings: List[BitCheckFinding] = []

        # 1. Identify all signals with explicit boolean constraints: b * (1 - b) == 0 or b * b == b
        boolean_signals = self._find_boolean_enforced_signals()

        # 2. Identify bit decomposition equations: x == sum(2^i * b_i)
        decompositions = self._find_bit_decompositions()

        # 3. Check for missing boolean checks on decomposed bit signals
        for target_x, bit_wires in decompositions.items():
            for bit_wire in bit_wires:
                if bit_wire not in boolean_signals and bit_wire != 0:
                    bit_name = self.circuit.get_wire_name(bit_wire)
                    target_name = self.circuit.get_wire_name(target_x)
                    findings.append(
                        BitCheckFinding(
                            severity="HIGH",
                            category="MISSING_BOOLEAN_CHECK",
                            wire_id=bit_wire,
                            signal_name=bit_name,
                            description=(
                                f"Signal '{bit_name}' is used as a bit in decomposition of '{target_name}' "
                                f"but lacks a boolean constraint (b * (1 - b) == 0). An attacker can forge proofs!"
                            ),
                        )
                    )

        # 4. If witness is provided, inspect for field wrap-around or overflows
        if self.witness:
            half_q = self.modulus // 2
            for wid, elem in self.witness.values.items():
                if wid == 0:
                    continue
                name = self.circuit.get_wire_name(wid)

                # Check if signal is in a decomposition with known bit length
                for target_x, bit_wires in decompositions.items():
                    if wid == target_x:
                        k_bits = len(bit_wires)
                        max_allowed = (1 << k_bits) - 1
                        if elem.value > max_allowed:
                            findings.append(
                                BitCheckFinding(
                                    severity="HIGH",
                                    category="RANGE_OVERFLOW",
                                    wire_id=wid,
                                    signal_name=name,
                                    description=(
                                        f"Signal '{name}' has value {elem.value} which exceeds its "
                                        f"{k_bits}-bit range limit (max {max_allowed})."
                                    ),
                                    expected_bits=k_bits,
                                    actual_value=str(elem.value),
                                )
                            )

                # Check for negative wrap-around values (> q // 2)
                if elem.value > half_q:
                    signed_val = elem.to_signed_int()
                    findings.append(
                        BitCheckFinding(
                            severity="MEDIUM",
                            category="FIELD_WRAP_AROUND",
                            wire_id=wid,
                            signal_name=name,
                            description=(
                                f"Signal '{name}' holds a negative field representation ({signed_val} = 0x{elem.value:x}). "
                                f"Ensure consuming smart contracts do not misinterpret this as a massive uint256."
                            ),
                            actual_value=str(signed_val),
                        )
                    )

        return findings

    def _find_boolean_enforced_signals(self) -> Set[int]:
        """Find all wires constrained by b * (1 - b) == 0 or b * b == b."""
        boolean_wires: Set[int] = set()

        for c in self.circuit.constraints:
            # Pattern 1: b * b == b
            # A has {b: 1}, B has {b: 1}, C has {b: 1}
            if len(c.a.terms) == 1 and len(c.b.terms) == 1 and len(c.c.terms) == 1:
                (w_a, coeff_a) = next(iter(c.a.terms.items()))
                (w_b, coeff_b) = next(iter(c.b.terms.items()))
                (w_c, coeff_c) = next(iter(c.c.terms.items()))

                if w_a == w_b == w_c and coeff_a.is_one() and coeff_b.is_one() and coeff_c.is_one():
                    boolean_wires.add(w_a)

            # Pattern 2: b * (1 - b) == 0
            # A has {b: 1}, B has {0: 1, b: -1}, C is empty
            if len(c.a.terms) == 1 and len(c.c.terms) == 0:
                (w_a, coeff_a) = next(iter(c.a.terms.items()))
                if coeff_a.is_one() and len(c.b.terms) == 2:
                    if 0 in c.b.terms and w_a in c.b.terms:
                        if c.b.terms[0].is_one() and c.b.terms[w_a].to_signed_int() == -1:
                            boolean_wires.add(w_a)

        return boolean_wires

    def _find_bit_decompositions(self) -> Dict[int, List[int]]:
        """Detect constraints of the form sum(2^i * b_i) * 1 == x."""
        decompositions: Dict[int, List[int]] = {}

        for c in self.circuit.constraints:
            # Check if B is constant 1 ({0: 1}) and C is a single variable {x: 1}
            if len(c.b.terms) == 1 and 0 in c.b.terms and c.b.terms[0].is_one():
                if len(c.c.terms) == 1:
                    (target_x, c_coeff) = next(iter(c.c.terms.items()))
                    if c_coeff.is_one() and len(c.a.terms) >= 2:
                        # Check if A coefficients are powers of 2 (1, 2, 4, 8, ...)
                        coeffs = []
                        wires = []
                        for wid, coeff in sorted(c.a.terms.items(), key=lambda item: item[1].value):
                            coeffs.append(coeff.value)
                            wires.append(wid)

                        # Verify if coefficients match 2^0, 2^1, ...
                        is_power_of_two = True
                        for i, coeff_val in enumerate(coeffs):
                            if coeff_val != (1 << i):
                                is_power_of_two = False
                                break

                        if is_power_of_two:
                            decompositions[target_x] = wires

        return decompositions
