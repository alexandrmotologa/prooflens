"""Zero-Knowledge Proof circuit debugger and constraint fault isolation engine.

Evaluates mathematical satisfaction across R1CS systems, isolates failing constraints,
computes non-zero residuals, flags candidate corrupted signals, and audits circuits
for under-constrained variables and witness malleability vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from prooflens.core.field import FieldElement
from prooflens.core.r1cs import Constraint, ConstraintEvaluation, R1CSCircuit, WireType
from prooflens.core.witness import Witness


@dataclass
class CulpritSignal:
    """A signal identified as a candidate cause of constraint violation."""

    wire_id: int
    name: str
    wire_type: WireType
    assigned_value: FieldElement
    expected_value: Optional[FieldElement] = None
    role: str = ""  # "in_A", "in_B", "in_C", "defined_by_C"


@dataclass
class FailureReport:
    """Detailed diagnosis of an unsatisfied constraint."""

    constraint_id: int
    formula: str
    val_a: FieldElement
    val_b: FieldElement
    val_c: FieldElement
    product: FieldElement
    residual: FieldElement
    culprit_candidates: List[CulpritSignal] = field(default_factory=list)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    recommendation: str = ""


@dataclass
class AuditFinding:
    """Security audit finding indicating an under-constrained signal or vulnerability."""

    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    category: str  # "UNDER_CONSTRAINED", "DEAD_SIGNAL", "CONSTANT_ZERO", "MALLEABILITY"
    wire_id: int
    signal_name: str
    wire_type: WireType
    description: str


@dataclass
class DebugReport:
    """Comprehensive circuit debugging report."""

    circuit_summary: Dict[str, Any]
    total_constraints: int
    satisfied_count: int
    unsatisfied_count: int
    is_valid: bool
    failures: List[FailureReport]
    audit_findings: List[AuditFinding]
    constant_one_valid: bool


class CircuitDebugger:
    """Debugger engine for R1CS circuits and witness vectors."""

    def __init__(self, circuit: R1CSCircuit, witness: Optional[Witness] = None) -> None:
        self.circuit = circuit
        self.witness = witness or Witness(modulus=circuit.header.prime)

    def set_witness(self, witness: Witness) -> None:
        """Update the active witness."""
        self.witness = witness

    def run_debug(self) -> DebugReport:
        """Perform a full constraint satisfaction check and security audit."""
        h = self.circuit.header
        witness_dict = self.witness.values

        # 1. Check Wire 0 invariant (w[0] == 1)
        w0 = self.witness[0]
        constant_one_valid = w0.is_one()

        # 2. Evaluate all constraints
        failures: List[FailureReport] = []
        satisfied_count = 0

        for c in self.circuit.constraints:
            eval_res = c.evaluate(witness_dict, symbols=self.circuit.symbols)
            if eval_res.is_satisfied:
                satisfied_count += 1
            else:
                failure = self._analyze_failure(c, eval_res)
                failures.append(failure)

        # 3. Perform static security audit
        audit_findings = self.audit_circuit()

        is_valid = (len(failures) == 0) and constant_one_valid

        return DebugReport(
            circuit_summary=self.circuit.summary(),
            total_constraints=len(self.circuit.constraints),
            satisfied_count=satisfied_count,
            unsatisfied_count=len(failures),
            is_valid=is_valid,
            failures=failures,
            audit_findings=audit_findings,
            constant_one_valid=constant_one_valid,
        )

    def _analyze_failure(self, c: Constraint, eval_res: ConstraintEvaluation) -> FailureReport:
        """Analyze why a constraint failed and pinpoint candidate signals."""
        culprits: List[CulpritSignal] = []

        # Find signals in C
        for wid in c.c.wire_ids:
            if wid != 0:
                name = self.circuit.get_wire_name(wid)
                wtype = self.circuit.get_wire_type(wid)
                val = self.witness[wid]
                culprits.append(
                    CulpritSignal(
                        wire_id=wid,
                        name=name,
                        wire_type=wtype,
                        assigned_value=val,
                        role="output_C",
                    )
                )

        # Find signals in A and B
        for wid in c.a.wire_ids:
            if wid != 0 and wid not in [x.wire_id for x in culprits]:
                name = self.circuit.get_wire_name(wid)
                wtype = self.circuit.get_wire_type(wid)
                val = self.witness[wid]
                culprits.append(
                    CulpritSignal(
                        wire_id=wid,
                        name=name,
                        wire_type=wtype,
                        assigned_value=val,
                        role="input_A",
                    )
                )

        for wid in c.b.wire_ids:
            if wid != 0 and wid not in [x.wire_id for x in culprits]:
                name = self.circuit.get_wire_name(wid)
                wtype = self.circuit.get_wire_type(wid)
                val = self.witness[wid]
                culprits.append(
                    CulpritSignal(
                        wire_id=wid,
                        name=name,
                        wire_type=wtype,
                        assigned_value=val,
                        role="input_B",
                    )
                )

        recommendation = (
            f"Constraint {c.id} failed with residual {eval_res.residual.to_signed_int()}. "
            f"Check if signals {[x.name for x in culprits]} were assigned matching witness values."
        )

        return FailureReport(
            constraint_id=c.id,
            formula=eval_res.formula_repr,
            val_a=eval_res.val_a,
            val_b=eval_res.val_b,
            val_c=eval_res.val_c,
            product=eval_res.product,
            residual=eval_res.residual,
            culprit_candidates=culprits,
            source_file=c.source_file,
            source_line=c.source_line,
            recommendation=recommendation,
        )

    def audit_circuit(self) -> List[AuditFinding]:
        """Audit the circuit for under-constrained signals and common vulnerabilities."""
        findings: List[AuditFinding] = []

        # Count occurrences of each wire across constraints
        wire_occurrences: Dict[int, int] = {wid: 0 for wid in range(self.circuit.header.n_wires)}
        wire_roles: Dict[int, Set[str]] = {wid: set() for wid in range(self.circuit.header.n_wires)}

        for c in self.circuit.constraints:
            for wid in c.a.wire_ids:
                wire_occurrences[wid] = wire_occurrences.get(wid, 0) + 1
                wire_roles[wid].add("A")
            for wid in c.b.wire_ids:
                wire_occurrences[wid] = wire_occurrences.get(wid, 0) + 1
                wire_roles[wid].add("B")
            for wid in c.c.wire_ids:
                wire_occurrences[wid] = wire_occurrences.get(wid, 0) + 1
                wire_roles[wid].add("C")

        # 1. Detect dead signals (signals with 0 constraint occurrences)
        for wid in range(1, self.circuit.header.n_wires):
            count = wire_occurrences.get(wid, 0)
            wtype = self.circuit.get_wire_type(wid)
            name = self.circuit.get_wire_name(wid)

            if count == 0:
                findings.append(
                    AuditFinding(
                        severity="HIGH" if wtype != WireType.INTERMEDIATE else "MEDIUM",
                        category="DEAD_SIGNAL",
                        wire_id=wid,
                        signal_name=name,
                        wire_type=wtype,
                        description=f"Signal '{name}' (ID {wid}, type {wtype.value}) is declared but never referenced in any constraint.",
                    )
                )
            elif count == 1 and wtype == WireType.INTERMEDIATE:
                # Intermediate signal appearing only once: high risk of witness malleability
                findings.append(
                    AuditFinding(
                        severity="HIGH",
                        category="UNDER_CONSTRAINED",
                        wire_id=wid,
                        signal_name=name,
                        wire_type=wtype,
                        description=f"Intermediate signal '{name}' (ID {wid}) appears in only 1 constraint. It may be under-constrained, allowing proof forgery.",
                    )
                )

        return findings
