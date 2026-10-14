"""ProofLens FastAPI interactive Web Studio backend."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from prooflens.core.field import FieldElement
from prooflens.core.r1cs import R1CSCircuit
from prooflens.core.r1cs_parser import R1CSBinaryParser
from prooflens.core.witness import JSONWitnessParser, SymbolTableParser, WTNSBinaryParser, Witness
from prooflens.debugger.dag import DAGEngine
from prooflens.debugger.engine import CircuitDebugger
from prooflens.debugger.sourcemap import CircomSourceMapper
from prooflens.studio.samples import SAMPLE_REGISTRY

app = FastAPI(
    title="ProofLens Studio",
    description="Interactive Zero-Knowledge Proof Circuit Debugger & Witness Inspector",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"


class StudioState:
    """In-memory state for the active debugging session."""

    def __init__(self) -> None:
        self.circuit_name: str = "multiplier"
        # Load default multiplier sample
        circ, wit, src = SAMPLE_REGISTRY["multiplier"](valid=True)
        self.circuit: R1CSCircuit = circ
        self.witness: Witness = wit
        self.circom_source: str = src
        self.source_mapper = CircomSourceMapper()
        self.source_mapper.load_source_text("circuit.circom", src)

    def load_sample(self, name: str, valid: bool = True) -> None:
        if name not in SAMPLE_REGISTRY:
            raise HTTPException(status_code=400, detail=f"Unknown sample '{name}'")
        gen_fn = SAMPLE_REGISTRY[name]
        if name == "underconstrained":
            circ, wit, src = gen_fn()
        else:
            circ, wit, src = gen_fn(valid=valid)

        self.circuit_name = name
        self.circuit = circ
        self.witness = wit
        self.circom_source = src
        self.source_mapper = CircomSourceMapper()
        self.source_mapper.load_source_text(f"{name}.circom", src)


state = StudioState()


# --- Pydantic Request Models ---
class MutateWitnessRequest(BaseModel):
    wire_id: int
    new_value: str


class LoadSampleRequest(BaseModel):
    sample_name: str
    valid: bool = True


# --- API Routes ---
@app.get("/api/circuit/stats")
def get_circuit_stats() -> Dict[str, Any]:
    """Get high-level circuit metrics and witness satisfaction state."""
    debugger = CircuitDebugger(state.circuit, state.witness)
    report = debugger.run_debug()

    return {
        "circuit_name": state.circuit_name,
        "n_wires": state.circuit.header.n_wires,
        "n_constraints": len(state.circuit.constraints),
        "n_public_outputs": state.circuit.header.n_pub_out,
        "n_public_inputs": state.circuit.header.n_pub_in,
        "n_private_inputs": state.circuit.header.n_prv_in,
        "n_intermediate": state.circuit.header.n_intermediate,
        "is_valid": report.is_valid,
        "satisfied_count": report.satisfied_count,
        "unsatisfied_count": report.unsatisfied_count,
        "constant_one_valid": report.constant_one_valid,
        "field_modulus": hex(state.circuit.header.prime),
    }


@app.get("/api/circuit/constraints")
def get_constraints() -> List[Dict[str, Any]]:
    """Return all constraints with evaluated satisfaction and residual metrics."""
    res = []
    witness_dict = state.witness.values

    for c in state.circuit.constraints:
        eval_res = c.evaluate(witness_dict, symbols=state.circuit.symbols)
        res.append({
            "id": c.id,
            "formula": eval_res.formula_repr,
            "is_satisfied": eval_res.is_satisfied,
            "val_a": str(eval_res.val_a.to_signed_int()),
            "val_b": str(eval_res.val_b.to_signed_int()),
            "product": str(eval_res.product.to_signed_int()),
            "val_c": str(eval_res.val_c.to_signed_int()),
            "residual": str(eval_res.residual.to_signed_int()),
            "wires": list(c.all_wires()),
            "unsatisfied_reason": eval_res.unsatisfied_reason,
        })
    return res


@app.get("/api/circuit/signals")
def get_signals() -> List[Dict[str, Any]]:
    """Return all wires with names, types, and active witness values."""
    res = []
    for wid, wire in sorted(state.circuit.wires.items()):
        val = state.witness[wid]
        res.append({
            "wire_id": wid,
            "name": wire.name,
            "wire_type": wire.wire_type.value,
            "value": str(val.to_signed_int()),
            "hex": hex(val.value),
        })
    return res


@app.get("/api/circuit/dag")
def get_circuit_dag() -> List[Dict[str, Any]]:
    """Export Cytoscape.js compatible graph elements."""
    dag_engine = DAGEngine(state.circuit, state.witness)
    dag = dag_engine.build_dag()
    return dag.to_cytoscape_elements()


@app.get("/api/circuit/provenance")
def get_provenance(node_id: str) -> List[Dict[str, Any]]:
    """Trace upstream provenance subgraph for a node."""
    dag_engine = DAGEngine(state.circuit, state.witness)
    subdag = dag_engine.trace_provenance(node_id)
    return subdag.to_cytoscape_elements()


@app.get("/api/circuit/audit")
def get_audit_findings() -> List[Dict[str, Any]]:
    """Run security audit on the active circuit."""
    debugger = CircuitDebugger(state.circuit, state.witness)
    findings = debugger.audit_circuit()
    return [
        {
            "severity": f.severity,
            "category": f.category,
            "wire_id": f.wire_id,
            "signal_name": f.signal_name,
            "wire_type": f.wire_type.value,
            "description": f.description,
        }
        for f in findings
    ]


@app.post("/api/witness/mutate")
def mutate_witness(req: MutateWitnessRequest) -> Dict[str, Any]:
    """Mutate a signal value in real time and re-evaluate constraint satisfaction."""
    try:
        val_int = int(req.new_value, 0)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid integer format for witness value")

    state.witness[req.wire_id] = val_int

    debugger = CircuitDebugger(state.circuit, state.witness)
    report = debugger.run_debug()

    return {
        "status": "success",
        "wire_id": req.wire_id,
        "new_value": str(state.witness[req.wire_id].to_signed_int()),
        "is_valid": report.is_valid,
        "satisfied_count": report.satisfied_count,
        "unsatisfied_count": report.unsatisfied_count,
    }


@app.post("/api/circuit/load-sample")
def load_sample(req: LoadSampleRequest) -> Dict[str, Any]:
    """Load a pre-configured sample circuit."""
    state.load_sample(req.sample_name, valid=req.valid)
    return get_circuit_stats()


@app.get("/api/circuit/source")
def get_circom_source() -> Dict[str, Any]:
    """Return the raw Circom source code."""
    return {
        "filename": f"{state.circuit_name}.circom",
        "content": state.circom_source,
    }


@app.post("/api/circuit/upload")
async def upload_circuit(
    r1cs_file: UploadFile = File(...),
    wtns_file: Optional[UploadFile] = File(None),
    sym_file: Optional[UploadFile] = File(None),
    circom_file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    """Upload custom circuit artifacts."""
    r1cs_bytes = await r1cs_file.read()
    circuit = R1CSBinaryParser.from_bytes(r1cs_bytes)

    if sym_file:
        sym_content = (await sym_file.read()).decode("utf-8", errors="replace")
        symbols = SymbolTableParser.from_string(sym_content)
        circuit.set_symbols(symbols)

    witness = Witness(modulus=circuit.header.prime)
    if wtns_file:
        wtns_bytes = await wtns_file.read()
        if wtns_file.filename and wtns_file.filename.endswith(".json"):
            witness = JSONWitnessParser.from_string(wtns_bytes.decode("utf-8"), modulus=circuit.header.prime)
        else:
            witness = WTNSBinaryParser.from_bytes(wtns_bytes)

    source_text = ""
    if circom_file:
        source_text = (await circom_file.read()).decode("utf-8", errors="replace")

    state.circuit = circuit
    state.witness = witness
    state.circuit_name = r1cs_file.filename or "uploaded_circuit"
    state.circom_source = source_text
    state.source_mapper = CircomSourceMapper()
    if source_text:
        state.source_mapper.load_source_text(state.circuit_name, source_text)

    return get_circuit_stats()


# Serve UI static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>ProofLens Studio static bundle not found</h1>")
    return FileResponse(index_file)
