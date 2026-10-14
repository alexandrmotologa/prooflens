"""Circuit Diff and Regression Engine.

Compares two R1CS compiled circuits to detect added, removed, or modified constraints,
signal additions/deletions, and security regressions between circuit revisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from prooflens.core.r1cs import Constraint, R1CSCircuit


@dataclass
class ConstraintDiff:
    """Represents a change to an individual constraint."""

    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    constraint_id_a: Optional[int]
    constraint_id_b: Optional[int]
    formula_a: Optional[str]
    formula_b: Optional[str]
    description: str


@dataclass
class CircuitDiffReport:
    """Comprehensive diff report between two R1CS circuits."""

    wires_delta: int
    constraints_delta: int
    pub_out_delta: int
    pub_in_delta: int
    prv_in_delta: int
    intermediate_delta: int

    added_constraints: List[ConstraintDiff] = field(default_factory=list)
    removed_constraints: List[ConstraintDiff] = field(default_factory=list)
    modified_constraints: List[ConstraintDiff] = field(default_factory=list)
    security_regressions: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return (
            self.wires_delta != 0
            or self.constraints_delta != 0
            or bool(self.added_constraints)
            or bool(self.removed_constraints)
            or bool(self.modified_constraints)
        )


class CircuitDiffer:
    """Calculates structural and mathematical diffs between two R1CS circuits."""

    def __init__(self, circuit_a: R1CSCircuit, circuit_b: R1CSCircuit) -> None:
        self.circuit_a = circuit_a
        self.circuit_b = circuit_b

    def compute_diff(self) -> CircuitDiffReport:
        """Compute the full diff between circuit_a and circuit_b."""
        ha = self.circuit_a.header
        hb = self.circuit_b.header

        wires_delta = hb.n_wires - ha.n_wires
        constraints_delta = len(self.circuit_b.constraints) - len(self.circuit_a.constraints)
        pub_out_delta = hb.n_pub_out - ha.n_pub_out
        pub_in_delta = hb.n_pub_in - ha.n_pub_in
        prv_in_delta = hb.n_prv_in - ha.n_prv_in
        intermediate_delta = hb.n_intermediate - ha.n_intermediate

        # Normalize constraints to canonical string representations
        a_map: Dict[str, Constraint] = {
            self._canonical_repr(c, self.circuit_a.symbols): c
            for c in self.circuit_a.constraints
        }
        b_map: Dict[str, Constraint] = {
            self._canonical_repr(c, self.circuit_b.symbols): c
            for c in self.circuit_b.constraints
        }

        a_keys = set(a_map.keys())
        b_keys = set(b_map.keys())

        common_keys = a_keys & b_keys
        removed_keys = a_keys - b_keys
        added_keys = b_keys - a_keys

        removed_diffs: List[ConstraintDiff] = []
        for k in removed_keys:
            c = a_map[k]
            removed_diffs.append(
                ConstraintDiff(
                    change_type="REMOVED",
                    constraint_id_a=c.id,
                    constraint_id_b=None,
                    formula_a=c.format_formula(self.circuit_a.symbols),
                    formula_b=None,
                    description=f"Constraint C{c.id} was removed in new version.",
                )
            )

        added_diffs: List[ConstraintDiff] = []
        for k in added_keys:
            c = b_map[k]
            added_diffs.append(
                ConstraintDiff(
                    change_type="ADDED",
                    constraint_id_a=None,
                    constraint_id_b=c.id,
                    formula_a=None,
                    formula_b=c.format_formula(self.circuit_b.symbols),
                    description=f"Constraint C{c.id} was newly added in new version.",
                )
            )

        # Detect index-aligned modifications (constraints with same ID but different formula)
        modified_diffs: List[ConstraintDiff] = []
        min_len = min(len(self.circuit_a.constraints), len(self.circuit_b.constraints))
        for cid in range(min_len):
            ca = self.circuit_a.constraints[cid]
            cb = self.circuit_b.constraints[cid]
            rep_a = self._canonical_repr(ca, self.circuit_a.symbols)
            rep_b = self._canonical_repr(cb, self.circuit_b.symbols)
            if rep_a != rep_b:
                modified_diffs.append(
                    ConstraintDiff(
                        change_type="MODIFIED",
                        constraint_id_a=ca.id,
                        constraint_id_b=cb.id,
                        formula_a=ca.format_formula(self.circuit_a.symbols),
                        formula_b=cb.format_formula(self.circuit_b.symbols),
                        description=f"Constraint at index {cid} altered.",
                    )
                )

        # Detect security regressions
        regressions: List[str] = []
        if len(removed_diffs) > 0 and len(added_diffs) == 0:
            regressions.append(
                f"Warning: {len(removed_diffs)} constraint(s) removed without replacements. Verify circuit is not under-constrained."
            )
        if pub_out_delta != 0 or pub_in_delta != 0:
            regressions.append(
                f"Public interface changed: Public outputs delta = {pub_out_delta:+d}, Public inputs delta = {pub_in_delta:+d}."
            )

        return CircuitDiffReport(
            wires_delta=wires_delta,
            constraints_delta=constraints_delta,
            pub_out_delta=pub_out_delta,
            pub_in_delta=pub_in_delta,
            prv_in_delta=prv_in_delta,
            intermediate_delta=intermediate_delta,
            added_constraints=added_diffs,
            removed_constraints=removed_diffs,
            modified_constraints=modified_diffs,
            security_regressions=regressions,
        )

    def _canonical_repr(self, c: Constraint, symbols: Dict[int, str]) -> str:
        """Create a canonical string representation for constraint matching."""
        return c.format_formula(symbols)
