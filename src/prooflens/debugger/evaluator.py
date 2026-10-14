"""Forward Witness Evaluator and Circuit Simulator.

Evaluates an R1CS circuit directly from primary inputs without external Circom or
snarkjs witness calculators. Traverses the constraint DAG in topological order,
solves for free intermediate and output signals, and computes the full witness vector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, WireType
from prooflens.core.witness import Witness


@dataclass
class EvaluationStep:
    """A step in the forward evaluation of a circuit."""

    step_index: int
    constraint_id: int
    solved_wire_id: Optional[int]
    solved_wire_name: Optional[str]
    assigned_value: Optional[FieldElement]
    formula: str
    is_satisfied: bool
    description: str


@dataclass
class ForwardEvaluationResult:
    """Result of forward circuit simulation."""

    witness: Witness
    is_complete: bool
    unsolved_wires: List[int]
    steps: List[EvaluationStep] = field(default_factory=list)


class ForwardWitnessEvaluator:
    """Computes a complete witness vector from initial circuit inputs."""

    def __init__(self, circuit: R1CSCircuit) -> None:
        self.circuit = circuit
        self.modulus = circuit.header.prime

    def evaluate_from_inputs(self, raw_inputs: Dict[Union[int, str], Any]) -> ForwardEvaluationResult:
        """Evaluate circuit given a dictionary of signal inputs (by wire ID or name)."""
        witness = Witness(modulus=self.modulus)
        # Wire 0 is always 1
        witness[0] = FieldElement.one(modulus=self.modulus)

        # Map user input names or IDs to wire IDs
        for key, val in raw_inputs.items():
            wire_id: Optional[int] = None
            if isinstance(key, int):
                wire_id = key
            elif isinstance(key, str):
                if key.isdigit():
                    wire_id = int(key)
                elif key in self.circuit.symbol_to_wire:
                    wire_id = self.circuit.symbol_to_wire[key]
                else:
                    # Try partial match (e.g. "a" matching "main.a")
                    for sym, wid in self.circuit.symbol_to_wire.items():
                        if sym.endswith(f".{key}") or sym == key:
                            wire_id = wid
                            break

            if wire_id is not None:
                witness[wire_id] = FieldElement(val, modulus=self.modulus)

        steps: List[EvaluationStep] = []
        solved_any = True
        remaining_constraints = list(self.circuit.constraints)
        step_idx = 0

        # Iteratively solve constraints where at most one wire is unknown
        while solved_any and remaining_constraints:
            solved_any = False
            next_remaining = []

            for c in remaining_constraints:
                all_wires = c.all_wires()
                unknown_wires = [w for w in all_wires if w not in witness]

                if len(unknown_wires) == 0:
                    # All wires known: verify satisfaction
                    eval_res = c.evaluate(witness.values, symbols=self.circuit.symbols)
                    steps.append(
                        EvaluationStep(
                            step_index=step_idx,
                            constraint_id=c.id,
                            solved_wire_id=None,
                            solved_wire_name=None,
                            assigned_value=None,
                            formula=c.format_formula(self.circuit.symbols),
                            is_satisfied=eval_res.is_satisfied,
                            description=f"Verified constraint C{c.id} with known signals.",
                        )
                    )
                    step_idx += 1
                elif len(unknown_wires) == 1:
                    target_wire = unknown_wires[0]
                    solved_val = self._solve_single_wire(c, target_wire, witness)

                    if solved_val is not None:
                        witness[target_wire] = solved_val
                        solved_any = True
                        wire_name = self.circuit.get_wire_name(target_wire)
                        steps.append(
                            EvaluationStep(
                                step_index=step_idx,
                                constraint_id=c.id,
                                solved_wire_id=target_wire,
                                solved_wire_name=wire_name,
                                assigned_value=solved_val,
                                formula=c.format_formula(self.circuit.symbols),
                                is_satisfied=True,
                                description=f"Derived signal '{wire_name}' = {solved_val.to_signed_int()} via C{c.id}.",
                            )
                        )
                        step_idx += 1
                    else:
                        next_remaining.append(c)
                else:
                    next_remaining.append(c)

            remaining_constraints = next_remaining

        # Check for unassigned wires (excluding wire 0)
        unsolved = [wid for wid in range(1, self.circuit.header.n_wires) if wid not in witness]
        is_complete = (len(unsolved) == 0)

        return ForwardEvaluationResult(
            witness=witness,
            is_complete=is_complete,
            unsolved_wires=unsolved,
            steps=steps,
        )

    def _solve_single_wire(
        self,
        c: Constraint,
        target_wire: int,
        witness: Witness,
    ) -> Optional[FieldElement]:
        """Solve <A, w> * <B, w> = <C, w> for `target_wire` when all other wires are known."""
        # Case 1: target_wire appears in C and not in A or B
        if target_wire in c.c.terms and target_wire not in c.a.terms and target_wire not in c.b.terms:
            val_a = c.a.eval(witness.values)
            val_b = c.b.eval(witness.values)
            target_coeff = c.c.terms[target_wire]

            # C_w = c_target * target_wire + other_C_terms
            # target_wire = (A*B - other_C_terms) / c_target
            other_c = FieldElement.zero(modulus=self.modulus)
            for wid, coeff in c.c.terms.items():
                if wid != target_wire:
                    other_c = other_c + (coeff * witness[wid])

            numerator = (val_a * val_b) - other_c
            return numerator / target_coeff

        # Case 2: target_wire appears in A and not in B or C
        if target_wire in c.a.terms and target_wire not in c.b.terms and target_wire not in c.c.terms:
            val_b = c.b.eval(witness.values)
            if val_b.is_zero():
                return None  # Cannot divide by zero
            val_c = c.c.eval(witness.values)
            target_coeff = c.a.terms[target_wire]

            other_a = FieldElement.zero(modulus=self.modulus)
            for wid, coeff in c.a.terms.items():
                if wid != target_wire:
                    other_a = other_a + (coeff * witness[wid])

            # (c_target * target + other_a) * val_b = val_c
            # target = (val_c / val_b - other_a) / c_target
            val_a_needed = val_c / val_b
            return (val_a_needed - other_a) / target_coeff

        # Case 3: target_wire appears in B and not in A or C
        if target_wire in c.b.terms and target_wire not in c.a.terms and target_wire not in c.c.terms:
            val_a = c.a.eval(witness.values)
            if val_a.is_zero():
                return None
            val_c = c.c.eval(witness.values)
            target_coeff = c.b.terms[target_wire]

            other_b = FieldElement.zero(modulus=self.modulus)
            for wid, coeff in c.b.terms.items():
                if wid != target_wire:
                    other_b = other_b + (coeff * witness[wid])

            val_b_needed = val_c / val_a
            return (val_b_needed - other_b) / target_coeff

        return None
