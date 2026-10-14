"""Signal dependency Directed Acyclic Graph (DAG) visualizer and tracer.

Constructs bipartite DAGs representing signal dependencies and constraint flows,
enabling root-cause provenance tracing, blast radius calculation, and interactive
graph visualizers in Web Studio.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from prooflens.core.r1cs import Constraint, R1CSCircuit, WireType
from prooflens.core.witness import Witness


@dataclass
class DAGNode:
    """A node in the circuit DAG."""

    id: str  # e.g. "sig_1" or "cons_0"
    label: str
    node_type: str  # "signal" or "constraint"
    sub_type: str  # wire_type or "gate"
    value: Optional[str] = None
    is_satisfied: Optional[bool] = None
    depth: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DAGEdge:
    """A directed edge in the circuit DAG."""

    source: str
    target: str
    role: str  # "input_A", "input_B", "output_C", "operand"
    label: Optional[str] = None


@dataclass
class CircuitDAG:
    """Complete graph representation of the circuit signal flow."""

    nodes: List[DAGNode] = field(default_factory=list)
    edges: List[DAGEdge] = field(default_factory=list)

    def to_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Export graph elements in Cytoscape.js JSON schema."""
        elements: List[Dict[str, Any]] = []

        for node in self.nodes:
            elements.append({
                "group": "nodes",
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "nodeType": node.node_type,
                    "subType": node.sub_type,
                    "value": node.value,
                    "isSatisfied": node.is_satisfied,
                    "depth": node.depth,
                    **node.metadata,
                },
                "classes": f"{node.node_type} {node.sub_type} {'satisfied' if node.is_satisfied else 'unsatisfied' if node.is_satisfied is False else ''}",
            })

        for edge in self.edges:
            elements.append({
                "group": "edges",
                "data": {
                    "id": f"{edge.source}->{edge.target}",
                    "source": edge.source,
                    "target": edge.target,
                    "role": edge.role,
                    "label": edge.label or edge.role,
                },
                "classes": edge.role,
            })

        return elements


class DAGEngine:
    """Constructs and analyzes signal dependency DAGs from R1CS circuits."""

    def __init__(self, circuit: R1CSCircuit, witness: Optional[Witness] = None) -> None:
        self.circuit = circuit
        self.witness = witness

    def build_dag(self) -> CircuitDAG:
        """Construct the complete signal flow DAG."""
        nodes: Dict[str, DAGNode] = {}
        edges: List[DAGEdge] = []

        # 1. Create Signal Nodes for all wires
        for wid, wire in self.circuit.wires.items():
            node_id = f"sig_{wid}"
            val_str = None
            if self.witness and wid in self.witness:
                val_str = str(self.witness[wid].to_signed_int())

            nodes[node_id] = DAGNode(
                id=node_id,
                label=wire.name,
                node_type="signal",
                sub_type=wire.wire_type.value,
                value=val_str,
                metadata={"wire_id": wid},
            )

        # 2. Create Constraint Nodes and Edges
        witness_dict = self.witness.values if self.witness else {}
        for c in self.circuit.constraints:
            c_node_id = f"cons_{c.id}"
            eval_res = c.evaluate(witness_dict, symbols=self.circuit.symbols) if self.witness else None
            is_sat = eval_res.is_satisfied if eval_res else None

            formula = c.format_formula(self.circuit.symbols)
            nodes[c_node_id] = DAGNode(
                id=c_node_id,
                label=f"C{c.id}: {formula}",
                node_type="constraint",
                sub_type="gate",
                is_satisfied=is_sat,
                metadata={
                    "constraint_id": c.id,
                    "formula": formula,
                    "residual": str(eval_res.residual.to_signed_int()) if eval_res else None,
                },
            )

            # Inbound edges: Signals in A and B flow into the Constraint
            for wid in c.a.wire_ids:
                if wid != 0:
                    edges.append(DAGEdge(source=f"sig_{wid}", target=c_node_id, role="input_A"))
            for wid in c.b.wire_ids:
                if wid != 0:
                    edges.append(DAGEdge(source=f"sig_{wid}", target=c_node_id, role="input_B"))

            # Outbound edges:
            # If C is a single variable, it is defined by this constraint (Constraint -> Signal)
            if len(c.c.terms) == 1:
                (c_wid, _) = next(iter(c.c.terms.items()))
                if c_wid != 0:
                    edges.append(DAGEdge(source=c_node_id, target=f"sig_{c_wid}", role="output_C"))
            else:
                # If C is a linear combination of multiple terms, signals participate in constraint check
                for wid in c.c.wire_ids:
                    if wid != 0:
                        edges.append(DAGEdge(source=f"sig_{wid}", target=c_node_id, role="check_C"))

        # 3. Compute topological depth for layout layering
        self._compute_depths(nodes, edges)

        return CircuitDAG(nodes=list(nodes.values()), edges=edges)

    def _compute_depths(self, nodes: Dict[str, DAGNode], edges: List[DAGEdge]) -> None:
        """Calculate graph depth from inputs to outputs using BFS."""
        in_degree: Dict[str, int] = {nid: 0 for nid in nodes}
        adj: Dict[str, List[str]] = {nid: [] for nid in nodes}

        for edge in edges:
            if edge.source in adj and edge.target in in_degree:
                adj[edge.source].append(edge.target)
                in_degree[edge.target] += 1

        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        for nid in queue:
            nodes[nid].depth = 0

        while queue:
            curr = queue.popleft()
            curr_depth = nodes[curr].depth
            for nxt in adj[curr]:
                if nodes[nxt].depth < curr_depth + 1:
                    nodes[nxt].depth = curr_depth + 1
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)

    def trace_provenance(self, target_id: str) -> CircuitDAG:
        """Trace all upstream ancestor signals and constraints leading to target_id."""
        full_dag = self.build_dag()
        node_map = {n.id: n for n in full_dag.nodes}

        # Reverse adjacency
        rev_adj: Dict[str, List[DAGEdge]] = {n.id: [] for n in full_dag.nodes}
        for edge in full_dag.edges:
            if edge.target in rev_adj:
                rev_adj[edge.target].append(edge)

        visited_nodes: Set[str] = set()
        visited_edges: List[DAGEdge] = []
        queue = deque([target_id])

        while queue:
            curr = queue.popleft()
            if curr in visited_nodes:
                continue
            visited_nodes.add(curr)
            for edge in rev_adj.get(curr, []):
                visited_edges.append(edge)
                if edge.source not in visited_nodes:
                    queue.append(edge.source)

        sub_nodes = [node_map[nid] for nid in visited_nodes if nid in node_map]
        return CircuitDAG(nodes=sub_nodes, edges=visited_edges)

    def trace_downstream(self, source_id: str) -> CircuitDAG:
        """Trace all downstream constraints and signals affected by source_id."""
        full_dag = self.build_dag()
        node_map = {n.id: n for n in full_dag.nodes}

        fwd_adj: Dict[str, List[DAGEdge]] = {n.id: [] for n in full_dag.nodes}
        for edge in full_dag.edges:
            if edge.source in fwd_adj:
                fwd_adj[edge.source].append(edge)

        visited_nodes: Set[str] = set()
        visited_edges: List[DAGEdge] = []
        queue = deque([source_id])

        while queue:
            curr = queue.popleft()
            if curr in visited_nodes:
                continue
            visited_nodes.add(curr)
            for edge in fwd_adj.get(curr, []):
                visited_edges.append(edge)
                if edge.target not in visited_nodes:
                    queue.append(edge.target)

        sub_nodes = [node_map[nid] for nid in visited_nodes if nid in node_map]
        return CircuitDAG(nodes=sub_nodes, edges=visited_edges)
