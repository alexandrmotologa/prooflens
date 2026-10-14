"""Rank-1 Constraint System (R1CS) core data structures and evaluation engine.

An R1CS system consists of constraints of the form:
    <A, w> * <B, w> = <C, w>
where w is the witness vector [1, out_1, ..., in_1, ..., aux_1, ...], and A, B, C
are linear combinations of the witness signals over a finite field F_q.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from prooflens.core.field import BN254_PRIME, FieldElement


class WireType(str, Enum):
    """Categorization of circuit signals based on Circom/iden3 R1CS convention."""

    ONE = "one"  # Constant signal (wire 0)
    PUBLIC_OUTPUT = "public_output"
    PUBLIC_INPUT = "public_input"
    PRIVATE_INPUT = "private_input"
    INTERMEDIATE = "intermediate"


@dataclass
class Wire:
    """A circuit signal / wire."""

    id: int
    name: str
    wire_type: WireType
    component: Optional[str] = None

    def __repr__(self) -> str:
        return f"Wire(id={self.id}, name='{self.name}', type={self.wire_type.value})"


class LinearCombination:
    """A sparse linear combination of circuit wires: sum(c_i * w_i)."""

    def __init__(
        self,
        terms: Optional[Dict[int, FieldElement]] = None,
        modulus: int = BN254_PRIME,
    ) -> None:
        self.modulus = modulus
        self.terms: Dict[int, FieldElement] = {}
        if terms:
            for wire_id, coeff in terms.items():
                self.add_term(wire_id, coeff)

    def add_term(self, wire_id: int, coeff: Any) -> None:
        """Add or accumulate a wire coefficient term."""
        if not isinstance(coeff, FieldElement):
            coeff = FieldElement(coeff, modulus=self.modulus)
        if coeff.is_zero():
            return
        if wire_id in self.terms:
            new_coeff = self.terms[wire_id] + coeff
            if new_coeff.is_zero():
                del self.terms[wire_id]
            else:
                self.terms[wire_id] = new_coeff
        else:
            self.terms[wire_id] = coeff

    def eval(self, witness: Dict[int, FieldElement]) -> FieldElement:
        """Evaluate the linear combination against a witness vector."""
        total = FieldElement.zero(modulus=self.modulus)
        for wire_id, coeff in self.terms.items():
            val = witness.get(wire_id, FieldElement.zero(modulus=self.modulus))
            total = total + (coeff * val)
        return total

    @property
    def wire_ids(self) -> Set[int]:
        """Return the set of non-zero wire IDs present in this linear combination."""
        return set(self.terms.keys())

    def is_empty(self) -> bool:
        """True if the linear combination has no terms (evaluates to 0)."""
        return len(self.terms) == 0

    def format_formula(self, symbols: Optional[Dict[int, str]] = None) -> str:
        """Format the linear combination into a readable algebraic expression."""
        if not self.terms:
            return "0"

        parts = []
        for wire_id, coeff in sorted(self.terms.items()):
            signed = coeff.to_signed_int()
            sign_str = "+ " if signed >= 0 else "- "
            abs_val = abs(signed)

            # Signal name or wire identifier
            if wire_id == 0:
                name = ""
            elif symbols and wire_id in symbols:
                name = symbols[wire_id]
            else:
                name = f"w{wire_id}"

            if wire_id == 0:
                term_str = f"{abs_val}"
            elif abs_val == 1:
                term_str = f"{name}"
            else:
                term_str = f"{abs_val}*{name}"

            parts.append((sign_str, term_str))

        # Build clean string
        res = ""
        for i, (sign_str, term_str) in enumerate(parts):
            if i == 0:
                if sign_str == "- ":
                    res += f"-{term_str}"
                else:
                    res += term_str
            else:
                res += f" {sign_str}{term_str}"
        return res

    def __repr__(self) -> str:
        return f"LC({self.format_formula()})"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, LinearCombination):
            return False
        return self.terms == other.terms and self.modulus == other.modulus


@dataclass
class ConstraintEvaluation:
    """The result of evaluating an R1CS constraint against a witness vector."""

    constraint_id: int
    val_a: FieldElement
    val_b: FieldElement
    val_c: FieldElement
    product: FieldElement
    residual: FieldElement
    is_satisfied: bool
    formula_repr: str
    unsatisfied_reason: Optional[str] = None


@dataclass
class Constraint:
    """A single Rank-1 constraint: <A, w> * <B, w> = <C, w>."""

    id: int
    a: LinearCombination
    b: LinearCombination
    c: LinearCombination
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    template_name: Optional[str] = None

    def evaluate(
        self,
        witness: Dict[int, FieldElement],
        symbols: Optional[Dict[int, str]] = None,
    ) -> ConstraintEvaluation:
        """Evaluate constraint satisfaction and calculate the residual error."""
        val_a = self.a.eval(witness)
        val_b = self.b.eval(witness)
        val_c = self.c.eval(witness)
        product = val_a * val_b
        residual = product - val_c
        is_satisfied = residual.is_zero()

        formula = self.format_formula(symbols)
        reason = None
        if not is_satisfied:
            reason = (
                f"Violation: ({val_a}) * ({val_b}) = {product} != {val_c} "
                f"[residual = {residual.to_signed_int()}]"
            )

        return ConstraintEvaluation(
            constraint_id=self.id,
            val_a=val_a,
            val_b=val_b,
            val_c=val_c,
            product=product,
            residual=residual,
            is_satisfied=is_satisfied,
            formula_repr=formula,
            unsatisfied_reason=reason,
        )

    def all_wires(self) -> Set[int]:
        """Return all distinct wire IDs referenced in this constraint."""
        return self.a.wire_ids | self.b.wire_ids | self.c.wire_ids

    def format_formula(self, symbols: Optional[Dict[int, str]] = None) -> str:
        """Format as `(A) * (B) = C`."""
        a_str = self.a.format_formula(symbols)
        b_str = self.b.format_formula(symbols)
        c_str = self.c.format_formula(symbols)

        # Simplify parentheses for single terms
        if len(self.a.terms) > 1:
            a_str = f"({a_str})"
        if len(self.b.terms) > 1:
            b_str = f"({b_str})"

        return f"{a_str} * {b_str} == {c_str}"

    def __repr__(self) -> str:
        return f"Constraint(id={self.id}, {self.format_formula()})"


@dataclass
class R1CSHeader:
    """Header metadata for an R1CS circuit."""

    field_size: int = 32  # 32 bytes for BN254
    prime: int = BN254_PRIME
    n_wires: int = 0
    n_pub_out: int = 0
    n_pub_in: int = 0
    n_prv_in: int = 0
    n_labels: int = 0
    n_constraints: int = 0

    @property
    def n_intermediate(self) -> int:
        """Number of intermediate / auxiliary variables."""
        # Wires: 0 is ONE constant, then pub_out, pub_in, prv_in, then intermediate
        known = 1 + self.n_pub_out + self.n_pub_in + self.n_prv_in
        return max(0, self.n_wires - known)


class R1CSCircuit:
    """Represents a compiled R1CS circuit with its constraints and signal metadata."""

    def __init__(
        self,
        header: Optional[R1CSHeader] = None,
        constraints: Optional[List[Constraint]] = None,
        symbols: Optional[Dict[int, str]] = None,
    ) -> None:
        self.header = header or R1CSHeader()
        self.constraints: List[Constraint] = constraints or []
        self.symbols: Dict[int, str] = symbols or {}
        self.symbol_to_wire: Dict[str, int] = {v: k for k, v in self.symbols.items()}
        self.wires: Dict[int, Wire] = {}
        self._populate_wires()

    def _populate_wires(self) -> None:
        """Classify each wire into its canonical type based on index boundaries."""
        h = self.header
        pub_out_start = 1
        pub_in_start = pub_out_start + h.n_pub_out
        prv_in_start = pub_in_start + h.n_pub_in
        intermediate_start = prv_in_start + h.n_prv_in

        for wire_id in range(h.n_wires):
            if wire_id == 0:
                wtype = WireType.ONE
                default_name = "1"
            elif wire_id < pub_in_start:
                wtype = WireType.PUBLIC_OUTPUT
                default_name = f"out_{wire_id - pub_out_start}"
            elif wire_id < prv_in_start:
                wtype = WireType.PUBLIC_INPUT
                default_name = f"pub_in_{wire_id - pub_in_start}"
            elif wire_id < intermediate_start:
                wtype = WireType.PRIVATE_INPUT
                default_name = f"prv_in_{wire_id - prv_in_start}"
            else:
                wtype = WireType.INTERMEDIATE
                default_name = f"aux_{wire_id - intermediate_start}"

            name = self.symbols.get(wire_id, default_name)
            self.wires[wire_id] = Wire(id=wire_id, name=name, wire_type=wtype)

    def get_wire_name(self, wire_id: int) -> str:
        """Get the human-readable symbol or default name for a wire."""
        if wire_id in self.wires:
            return self.wires[wire_id].name
        return self.symbols.get(wire_id, f"w{wire_id}")

    def get_wire_type(self, wire_id: int) -> WireType:
        """Get the WireType enum for a wire."""
        if wire_id in self.wires:
            return self.wires[wire_id].wire_type
        if wire_id == 0:
            return WireType.ONE
        return WireType.INTERMEDIATE

    def set_symbols(self, symbols: Dict[int, str]) -> None:
        """Update or inject symbol mapping from a .sym file."""
        self.symbols.update(symbols)
        self.symbol_to_wire = {v: k for k, v in self.symbols.items()}
        for wire_id, name in self.symbols.items():
            if wire_id in self.wires:
                self.wires[wire_id].name = name
            else:
                self.wires[wire_id] = Wire(
                    id=wire_id,
                    name=name,
                    wire_type=self.get_wire_type(wire_id),
                )

    def evaluate_witness(self, witness: Dict[int, FieldElement]) -> Tuple[List[ConstraintEvaluation], List[ConstraintEvaluation]]:
        """Evaluate all constraints against a witness vector.

        Returns (satisfied_constraints, unsatisfied_constraints).
        """
        satisfied: List[ConstraintEvaluation] = []
        unsatisfied: List[ConstraintEvaluation] = []

        for c in self.constraints:
            eval_res = c.evaluate(witness, symbols=self.symbols)
            if eval_res.is_satisfied:
                satisfied.append(eval_res)
            else:
                unsatisfied.append(eval_res)

        return satisfied, unsatisfied

    def summary(self) -> Dict[str, Any]:
        """Return high level summary metrics for the circuit."""
        h = self.header
        return {
            "n_wires": h.n_wires,
            "n_constraints": len(self.constraints),
            "n_public_outputs": h.n_pub_out,
            "n_public_inputs": h.n_pub_in,
            "n_private_inputs": h.n_prv_in,
            "n_intermediate": h.n_intermediate,
            "field_modulus": hex(h.prime),
            "field_size_bytes": h.field_size,
        }
