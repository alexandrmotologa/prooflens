"""Algebraic Constraint Solver and Witness Auto-Fixer.

Analyzes unsatisfied R1CS constraints, solves for candidate signal values over F_q,
and calculates the net satisfaction impact across the entire circuit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, R1CSCircuit
from prooflens.core.witness import Witness


@dataclass
class CandidateFix:
    """A proposed value modification for a signal that resolves a constraint violation."""

    constraint_id: int
    wire_id: int
    wire_name: str
    current_value: FieldElement
    suggested_value: FieldElement
    residual_before: FieldElement
    net_satisfied_change: int  # +1 if it resolves more constraints than it breaks
    description: str


class WitnessAutoFixer:
    """Calculates algebraic solutions to fix unsatisfied constraints in a witness vector."""

    def __init__(self, circuit: R1CSCircuit, witness: Witness) -> None:
        self.circuit = circuit
        self.witness = witness
        self.modulus = circuit.header.prime

    def find_fixes_for_constraint(self, constraint_id: int) -> List[CandidateFix]:
        """Find candidate fixes that satisfy constraint `constraint_id`."""
        if constraint_id < 0 or constraint_id >= len(self.circuit.constraints):
            return []

        c = self.circuit.constraints[constraint_id]
        eval_before = c.evaluate(self.witness.values, symbols=self.circuit.symbols)
        if eval_before.is_satisfied:
            return []  # Already satisfied

        candidates: List[CandidateFix] = []
        all_wires = [w for w in c.all_wires() if w != 0]

        for wid in all_wires:
            suggested_val = self._solve_for_wire(c, wid)
            if suggested_val is not None:
                # Test the candidate fix against all constraints
                net_change = self._evaluate_fix_impact(wid, suggested_val)
                name = self.circuit.get_wire_name(wid)
                curr_val = self.witness[wid]

                candidates.append(
                    CandidateFix(
                        constraint_id=c.id,
                        wire_id=wid,
                        wire_name=name,
                        current_value=curr_val,
                        suggested_value=suggested_val,
                        residual_before=eval_before.residual,
                        net_satisfied_change=net_change,
                        description=(
                            f"Change '{name}' from {curr_val.to_signed_int()} to "
                            f"{suggested_val.to_signed_int()} (Net satisfied change: {net_change:+d})"
                        ),
                    )
                )

        # Sort by best net satisfied change descending
        candidates.sort(key=lambda x: x.net_satisfied_change, reverse=True)
        return candidates

    def find_all_fixes(self) -> List[CandidateFix]:
        """Scan all unsatisfied constraints and return ranked candidate fixes."""
        all_fixes: List[CandidateFix] = []
        for c in self.circuit.constraints:
            eval_res = c.evaluate(self.witness.values, symbols=self.circuit.symbols)
            if not eval_res.is_satisfied:
                fixes = self.find_fixes_for_constraint(c.id)
                all_fixes.extend(fixes)
        return all_fixes

    def _solve_for_wire(self, c: Constraint, target_wire: int) -> Optional[FieldElement]:
        """Solve <A, w> * <B, w> = <C, w> for `target_wire`."""
        # 1. Linear in C
        if target_wire in c.c.terms and target_wire not in c.a.terms and target_wire not in c.b.terms:
            val_a = c.a.eval(self.witness.values)
            val_b = c.b.eval(self.witness.values)
            coeff = c.c.terms[target_wire]

            other_c = FieldElement.zero(modulus=self.modulus)
            for wid, term_coeff in c.c.terms.items():
                if wid != target_wire:
                    other_c = other_c + (term_coeff * self.witness[wid])

            # target_wire = (A * B - other_c) / coeff
            return ((val_a * val_b) - other_c) / coeff

        # 2. Linear in A
        if target_wire in c.a.terms and target_wire not in c.b.terms and target_wire not in c.c.terms:
            val_b = c.b.eval(self.witness.values)
            if val_b.is_zero():
                return None
            val_c = c.c.eval(self.witness.values)
            coeff = c.a.terms[target_wire]

            other_a = FieldElement.zero(modulus=self.modulus)
            for wid, term_coeff in c.a.terms.items():
                if wid != target_wire:
                    other_a = other_a + (term_coeff * self.witness[wid])

            # (coeff * target + other_a) * val_b = val_c
            return ((val_c / val_b) - other_a) / coeff

        # 3. Linear in B
        if target_wire in c.b.terms and target_wire not in c.a.terms and target_wire not in c.c.terms:
            val_a = c.a.eval(self.witness.values)
            if val_a.is_zero():
                return None
            val_c = c.c.eval(self.witness.values)
            coeff = c.b.terms[target_wire]

            other_b = FieldElement.zero(modulus=self.modulus)
            for wid, term_coeff in c.b.terms.items():
                if wid != target_wire:
                    other_b = other_b + (term_coeff * self.witness[wid])

            return ((val_c / val_a) - other_b) / coeff

        return None

    def _evaluate_fix_impact(self, wire_id: int, new_val: FieldElement) -> int:
        """Calculate change in total satisfied constraints if wire_id is mutated."""
        sat_before, _ = self.circuit.evaluate_witness(self.witness.values)
        count_before = len(sat_before)

        # Mutate temporarily
        old_val = self.witness[wire_id]
        self.witness[wire_id] = new_val
        sat_after, _ = self.circuit.evaluate_witness(self.witness.values)
        count_after = len(sat_after)

        # Restore original value
        self.witness[wire_id] = old_val

        return count_after - count_before
