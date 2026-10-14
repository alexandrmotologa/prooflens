"""ProofLens CLI interface built with Typer and Rich.

Provides command line utilities for inspecting R1CS circuits, checking witness vectors,
isolating unsatisfied constraints, auditing for under-constrained signals, tracing DAGs,
and launching the interactive Web Studio.
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
from prooflens.core.r1cs_parser import R1CSBinaryParser
from prooflens.core.witness import JSONWitnessParser, SymbolTableParser, WTNSBinaryParser, Witness
from prooflens.debugger.dag import DAGEngine
from prooflens.debugger.engine import CircuitDebugger
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

    h = circuit.header
    summary = circuit.summary()

    # Circuit Metadata Table
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

    # Constraint Preview Table (first 10 constraints)
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

    # Overall Status Panel
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

        # Failure Details
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

            # Display Circom source context if available
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

    # Resolve signal ID
    if signal.isdigit():
        target_node = f"sig_{signal}"
    elif signal in circuit.symbol_to_wire:
        target_node = f"sig_{circuit.symbol_to_wire[signal]}"
    else:
        # Check if user passed constraint ID
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
