"""ProofLens CLI interface built with Typer and Rich.

Provides command line utilities for inspecting R1CS circuits, checking witness vectors,
isolating unsatisfied constraints, auditing for under-constrained signals, solving witness
failures, computing witnesses forward, diffing circuits, and exporting test vectors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from prooflens import __version__
from prooflens.core.diff import CircuitDiffer
from prooflens.core.r1cs_parser import R1CSBinaryParser
from prooflens.core.witness import JSONWitnessParser, SymbolTableParser, WTNSBinaryParser, WTNSBinaryWriter, Witness
from prooflens.debugger.bitwidth import BitWidthScanner
from prooflens.debugger.dag import DAGEngine
from prooflens.debugger.engine import CircuitDebugger
from prooflens.debugger.evaluator import ForwardWitnessEvaluator
from prooflens.debugger.exporter import TestVectorExporter
from prooflens.debugger.solver import WitnessAutoFixer
from prooflens.debugger.sourcemap import CircomSourceMapper

app = typer.Typer(
    name="prooflens",
    help="ProofLens: Interactive Zero-Knowledge Proof Circuit Debugger & Witness Inspector",
    add_completion=False,
)
console = Console()


def _load_witness(path: Path) -> Witness:
    if path.suffix.lower() == ".json":
        return JSONWitnessParser.from_file(path)
    return WTNSBinaryParser.from_file(path)


@app.command()
def version() -> None:
    """Print the ProofLens version."""
    console.print(f"[bold cyan]ProofLens[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def inspect(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
) -> None:
    """Inspect R1CS circuit structure, header metadata, and constraints."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    summary = circuit.summary()

    table = Table(title="Circuit Header & Metric Overview", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", style="cyan")

    table.add_row("Total Wires (Signals)", str(summary["n_wires"]))
    table.add_row("Total Constraints", str(summary["n_constraints"]))
    table.add_row("Public Outputs", str(summary["n_public_outputs"]))
    table.add_row("Public Inputs", str(summary["n_public_inputs"]))
    table.add_row("Private Inputs", str(summary["n_private_inputs"]))
    table.add_row("Intermediate Wires", str(summary["n_intermediate"]))
    table.add_row("Field Size (Bytes)", str(summary["field_size_bytes"]))
    table.add_row("Field Modulus", summary["field_modulus"])

    console.print(Panel(table, title=f"[bold cyan]ProofLens Circuit Inspection: {circuit_path.name}[/bold cyan]"))

    preview_count = min(10, len(circuit.constraints))
    if preview_count > 0:
        c_table = Table(title=f"Constraint Preview (Showing first {preview_count} of {len(circuit.constraints)})", border_style="blue")
        c_table.add_column("ID", style="bold dim", width=6)
        c_table.add_column("Formula ( <A, w> * <B, w> == <C, w> )", style="green")

        for c in circuit.constraints[:preview_count]:
            c_table.add_row(str(c.id), c.format_formula(circuit.symbols))

        console.print(c_table)


@app.command()
def check(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    witness_path: Path = typer.Option(..., "--witness", "-w", help="Path to the witness file (.wtns or .json)", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
    circom_path: Optional[Path] = typer.Option(None, "--circom", "-c", help="Optional path to .circom source file", exists=True),
) -> None:
    """Verify constraint satisfaction for a witness and isolate mathematical failures."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    source_mapper = None
    if circom_path:
        source_mapper = CircomSourceMapper()
        source_mapper.load_source_file(circom_path)

    witness = _load_witness(witness_path)
    debugger = CircuitDebugger(circuit, witness)
    report = debugger.run_debug()

    if report.is_valid:
        status_panel = Panel(
            f"[bold green]CIRCUIT SATISFIED[/bold green]\n"
            f"All {report.total_constraints} constraints evaluated to 0 residual.\n"
            f"Constant 1 wire: [green]Valid[/green]",
            border_style="green",
            title="Verification Result",
        )
        console.print(status_panel)
    else:
        status_panel = Panel(
            f"[bold red]CIRCUIT UNSATISFIED[/bold red]\n"
            f"Satisfied: [green]{report.satisfied_count}[/green] / {report.total_constraints} constraints\n"
            f"Violations: [bold red]{report.unsatisfied_count}[/bold red] failing constraints\n"
            f"Constant 1 wire: {'[green]Valid[/green]' if report.constant_one_valid else '[red]CORRUPTED (w[0] != 1)[/red]'}",
            border_style="red",
            title="Verification Result",
        )
        console.print(status_panel)

        for f in report.failures:
            f_table = Table(title=f"Violation at Constraint C{f.constraint_id}", border_style="red")
            f_table.add_column("Property", style="bold white")
            f_table.add_column("Details", style="yellow")

            f_table.add_row("Formula", f.formula)
            f_table.add_row("A evaluated", str(f.val_a))
            f_table.add_row("B evaluated", str(f.val_b))
            f_table.add_row("Product (A * B)", str(f.product))
            f_table.add_row("C evaluated", str(f.val_c))
            f_table.add_row("Residual (A*B - C)", f"[bold red]{f.residual.to_signed_int()}[/bold red]")

            culprits_str = ", ".join(f"{c.name} (assigned: {c.assigned_value.to_signed_int()})" for c in f.culprit_candidates)
            f_table.add_row("Culprit Candidates", culprits_str or "None identified")

            console.print(f_table)

            if source_mapper:
                for c in f.culprit_candidates:
                    loc = source_mapper.get_signal_location(c.name)
                    if loc:
                        src_table = Table(title=f"Source Context for {c.name} ({loc.file_path}:{loc.line_number})", border_style="cyan")
                        src_table.add_column("Line", style="dim", width=6)
                        src_table.add_column("Source", style="white")
                        for b_line in loc.context_before:
                            src_table.add_row("", b_line)
                        src_table.add_row(str(loc.line_number), f"[bold yellow]{loc.line_text}[/bold yellow]")
                        for a_line in loc.context_after:
                            src_table.add_row("", a_line)
                        console.print(src_table)


@app.command()
def audit(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
) -> None:
    """Audit circuit for unconstrained signals and witness malleability risks."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    debugger = CircuitDebugger(circuit)
    findings = debugger.audit_circuit()

    if not findings:
        console.print(Panel("[bold green]Zero vulnerabilities detected.[/bold green] All signals appear properly constrained.", border_style="green"))
        return

    table = Table(title=f"Security Audit: Found {len(findings)} Potential Issues", border_style="yellow")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Signal", style="white", width=20)
    table.add_column("Description", style="yellow")

    for f in findings:
        sev_color = "red" if f.severity == "HIGH" else "yellow" if f.severity == "MEDIUM" else "blue"
        table.add_row(
            f"[{sev_color}]{f.severity}[/{sev_color}]",
            f.category,
            f.signal_name,
            f.description,
        )

    console.print(table)


@app.command()
def compute_witness(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    inputs_path: Path = typer.Option(..., "--inputs", "-i", help="Path to JSON file with input signals", exists=True),
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="Optional output path for computed .wtns file"),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
) -> None:
    """Forward-evaluate circuit from primary inputs and generate a full witness."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    with open(inputs_path, "r", encoding="utf-8") as f:
        inputs_data = json.load(f)

    evaluator = ForwardWitnessEvaluator(circuit)
    res = evaluator.evaluate_from_inputs(inputs_data)

    if res.is_complete:
        console.print(Panel(f"[bold green]Witness computed successfully![/bold green] All {circuit.header.n_wires} signals resolved.", border_style="green"))
    else:
        console.print(Panel(f"[bold yellow]Partial witness computed.[/bold yellow] {len(res.unsolved_wires)} wires remain unsolved.", border_style="yellow"))

    table = Table(title=f"Forward Derivation Steps ({len(res.steps)} steps executed)", border_style="cyan")
    table.add_column("Step", style="dim", width=6)
    table.add_column("Gate", style="bold cyan", width=8)
    table.add_column("Solved Signal", style="green", width=22)
    table.add_column("Value", style="yellow", width=16)
    table.add_column("Description", style="white")

    for s in res.steps:
        table.add_row(
            str(s.step_index),
            f"C{s.constraint_id}",
            s.solved_wire_name or "-",
            str(s.assigned_value.to_signed_int()) if s.assigned_value is not None else "-",
            s.description,
        )
    console.print(table)

    if output_path:
        WTNSBinaryWriter.to_file(res.witness, output_path)
        console.print(f"[bold green]Saved witness to:[/bold green] {output_path}")


@app.command()
def fix(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    witness_path: Path = typer.Option(..., "--witness", "-w", help="Path to the witness file", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
    apply: bool = typer.Option(False, "--apply", help="Automatically apply the highest-ranked fix and overwrite witness file"),
) -> None:
    """Find algebraic solutions over F_q to satisfy violated constraints."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    witness = _load_witness(witness_path)
    fixer = WitnessAutoFixer(circuit, witness)
    fixes = fixer.find_all_fixes()

    if not fixes:
        console.print("[green]No unsatisfied constraints found or no single-variable solutions available.[/green]")
        return

    table = Table(title=f"Witness Auto-Fixer: Found {len(fixes)} Candidate Fixes", border_style="green")
    table.add_column("Gate", style="bold cyan", width=8)
    table.add_column("Target Signal", style="white", width=20)
    table.add_column("Current Val", style="red", width=14)
    table.add_column("Suggested Val", style="bold green", width=16)
    table.add_column("Net Change", style="yellow", width=12)

    for f in fixes:
        table.add_row(
            f"C{f.constraint_id}",
            f.wire_name,
            str(f.current_value.to_signed_int()),
            str(f.suggested_value.to_signed_int()),
            f"{f.net_satisfied_change:+d} satisfied",
        )
    console.print(table)

    if apply and fixes:
        best_fix = fixes[0]
        witness[best_fix.wire_id] = best_fix.suggested_value
        if witness_path.suffix.lower() == ".json":
            with open(witness_path, "w", encoding="utf-8") as f:
                json.dump(witness.to_json_dict(circuit.symbols), f, indent=2)
        else:
            WTNSBinaryWriter.to_file(witness, witness_path)
        console.print(f"[bold green]Applied top fix to signal '{best_fix.wire_name}' in {witness_path}![/bold green]")


@app.command()
def diff(
    circuit_a: Path = typer.Argument(..., help="Baseline R1CS circuit file (*.r1cs)", exists=True),
    circuit_b: Path = typer.Argument(..., help="New R1CS circuit file (*.r1cs)", exists=True),
    sym_a: Optional[Path] = typer.Option(None, "--sym-a", help="Optional .sym symbol table for circuit A", exists=True),
    sym_b: Optional[Path] = typer.Option(None, "--sym-b", help="Optional .sym symbol table for circuit B", exists=True),
) -> None:
    """Compare two R1CS circuits and detect additions, removals, and security regressions."""
    cA = R1CSBinaryParser.from_file(circuit_a)
    cB = R1CSBinaryParser.from_file(circuit_b)

    if sym_a:
        cA.set_symbols(SymbolTableParser.from_file(sym_a))
    if sym_b:
        cB.set_symbols(SymbolTableParser.from_file(sym_b))

    differ = CircuitDiffer(cA, cB)
    diff_report = differ.compute_diff()

    # Structural Table
    table = Table(title=f"Circuit Diff: {circuit_a.name} -> {circuit_b.name}", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Circuit A", style="dim")
    table.add_column("Circuit B", style="dim")
    table.add_column("Delta", style="bold cyan")

    table.add_row("Wires (Signals)", str(cA.header.n_wires), str(cB.header.n_wires), f"{diff_report.wires_delta:+d}")
    table.add_row("Constraints", str(len(cA.constraints)), str(len(cB.constraints)), f"{diff_report.constraints_delta:+d}")
    table.add_row("Public Outputs", str(cA.header.n_pub_out), str(cB.header.n_pub_out), f"{diff_report.pub_out_delta:+d}")
    table.add_row("Public Inputs", str(cA.header.n_pub_in), str(cB.header.n_pub_in), f"{diff_report.pub_in_delta:+d}")
    table.add_row("Private Inputs", str(cA.header.n_prv_in), str(cB.header.n_prv_in), f"{diff_report.prv_in_delta:+d}")
    table.add_row("Intermediate", str(cA.header.n_intermediate), str(cB.header.n_intermediate), f"{diff_report.intermediate_delta:+d}")

    console.print(table)

    if diff_report.added_constraints:
        add_tbl = Table(title=f"Added Constraints (+{len(diff_report.added_constraints)})", border_style="green")
        add_tbl.add_column("ID", width=6)
        add_tbl.add_column("Formula", style="green")
        for c in diff_report.added_constraints:
            add_tbl.add_row(str(c.constraint_id_b), c.formula_b or "")
        console.print(add_tbl)

    if diff_report.removed_constraints:
        rem_tbl = Table(title=f"Removed Constraints (-{len(diff_report.removed_constraints)})", border_style="red")
        rem_tbl.add_column("ID", width=6)
        rem_tbl.add_column("Formula", style="red")
        for c in diff_report.removed_constraints:
            rem_tbl.add_row(str(c.constraint_id_a), c.formula_a or "")
        console.print(rem_tbl)

    if diff_report.security_regressions:
        for reg in diff_report.security_regressions:
            console.print(f"[bold red]REGRESSION ALERT:[/bold red] {reg}")


@app.command()
def scan_bits(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    witness_path: Optional[Path] = typer.Option(None, "--witness", "-w", help="Optional witness file", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional .sym symbol table", exists=True),
) -> None:
    """Scan circuit for bit-decomposition bugs, missing boolean checks, and field wrap-around."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    witness = _load_witness(witness_path) if witness_path else None
    scanner = BitWidthScanner(circuit, witness)
    findings = scanner.scan()

    if not findings:
        console.print(Panel("[bold green]Zero bit-width issues or field wrap-arounds detected.[/bold green]", border_style="green"))
        return

    table = Table(title=f"Bit-Width & Range Audit: Found {len(findings)} Findings", border_style="yellow")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Category", style="cyan", width=24)
    table.add_column("Signal", style="white", width=20)
    table.add_column("Description", style="yellow")

    for f in findings:
        sev_color = "red" if f.severity == "HIGH" else "yellow"
        table.add_row(f"[{sev_color}]{f.severity}[/{sev_color}]", f.category, f.signal_name, f.description)
    console.print(table)


@app.command()
def export_test(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    witness_path: Path = typer.Option(..., "--witness", "-w", help="Path to the witness file", exists=True),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
    format_type: str = typer.Option("foundry", "--format", "-f", help="Output format: 'foundry' (.t.sol) or 'json'"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Export verified test vectors for Foundry / Hardhat integration tests."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    witness = _load_witness(witness_path)
    exporter = TestVectorExporter(circuit, witness)

    default_out = Path("CircuitProofTest.t.sol") if format_type == "foundry" else Path("test_vectors.json")
    target_path = output or default_out

    exporter.write_to_file(target_path, format_type=format_type)
    console.print(f"[bold green]Successfully exported {format_type} test vector to:[/bold green] {target_path}")


@app.command()
def trace(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    signal: str = typer.Option(..., "--signal", help="Signal name (e.g. main.out) or wire ID (e.g. 1)"),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
    witness_path: Optional[Path] = typer.Option(None, "--witness", "-w", help="Optional path to witness file", exists=True),
) -> None:
    """Trace upstream provenance and input dependencies for a circuit signal."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    witness = _load_witness(witness_path) if witness_path else None
    dag_engine = DAGEngine(circuit, witness)

    if signal.isdigit():
        target_node = f"sig_{signal}"
    elif signal in circuit.symbol_to_wire:
        target_node = f"sig_{circuit.symbol_to_wire[signal]}"
    else:
        if signal.startswith("C") and signal[1:].isdigit():
            target_node = f"cons_{signal[1:]}"
        else:
            console.print(f"[bold red]Unknown signal:[/bold red] '{signal}'")
            raise typer.Exit(code=1)

    subgraph = dag_engine.trace_provenance(target_node)

    table = Table(title=f"Dependency Provenance Trace for '{signal}'", border_style="cyan")
    table.add_column("Type", style="bold cyan", width=12)
    table.add_column("Identifier", style="white", width=25)
    table.add_column("Value / Details", style="green")

    for node in sorted(subgraph.nodes, key=lambda n: n.depth):
        table.add_row(node.node_type.upper(), node.label, str(node.value or node.metadata.get("formula", "")))

    console.print(table)


@app.command()
def export_dag(
    circuit_path: Path = typer.Argument(..., help="Path to the binary .r1cs file", exists=True),
    output: Path = typer.Option(Path("circuit_dag.json"), "--output", "-o", help="Output JSON path"),
    sym_path: Optional[Path] = typer.Option(None, "--sym", "-s", help="Optional path to .sym symbol table", exists=True),
    witness_path: Optional[Path] = typer.Option(None, "--witness", "-w", help="Optional path to witness file", exists=True),
) -> None:
    """Export the circuit dependency DAG as Cytoscape.js compatible JSON."""
    circuit = R1CSBinaryParser.from_file(circuit_path)
    if sym_path:
        symbols = SymbolTableParser.from_file(sym_path)
        circuit.set_symbols(symbols)

    witness = _load_witness(witness_path) if witness_path else None
    dag_engine = DAGEngine(circuit, witness)
    dag = dag_engine.build_dag()
    elements = dag.to_cytoscape_elements()

    with open(output, "w", encoding="utf-8") as f:
        json.dump(elements, f, indent=2)

    console.print(f"[bold green]DAG exported successfully to:[/bold green] {output} ({len(elements)} graph elements)")


@app.command()
def studio(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
) -> None:
    """Launch the interactive ProofLens Web Studio dashboard."""
    console.print(f"[bold cyan]Launching ProofLens Web Studio on http://{host}:{port}[/bold cyan]")
    uvicorn.run("prooflens.studio.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
