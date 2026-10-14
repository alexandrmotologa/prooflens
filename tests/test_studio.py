"""Unit tests for FastAPI Web Studio endpoints."""

import pytest
from fastapi.testclient import TestClient
from prooflens.core.r1cs_parser import R1CSBinaryWriter
from prooflens.core.witness import WTNSBinaryWriter
from prooflens.studio.app import app, state
from prooflens.studio.samples import generate_multiplier_sample


@pytest.fixture
def client():
    return TestClient(app)


def test_studio_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "ProofLens Studio" in response.text


def test_circuit_stats(client):
    response = client.get("/api/circuit/stats")
    assert response.status_code == 200
    data = response.json()
    assert "n_wires" in data
    assert "n_constraints" in data
    assert "is_valid" in data


def test_get_constraints(client):
    response = client.get("/api/circuit/constraints")
    assert response.status_code == 200
    constraints = response.json()
    assert len(constraints) > 0
    assert "formula" in constraints[0]
    assert "is_satisfied" in constraints[0]


def test_get_signals(client):
    response = client.get("/api/circuit/signals")
    assert response.status_code == 200
    signals = response.json()
    assert len(signals) > 0
    assert "wire_id" in signals[0]
    assert "value" in signals[0]


def test_get_dag(client):
    response = client.get("/api/circuit/dag")
    assert response.status_code == 200
    elements = response.json()
    assert len(elements) > 0
    assert "data" in elements[0]


def test_get_provenance(client):
    response = client.get("/api/circuit/provenance?node_id=sig_1")
    assert response.status_code == 200
    elements = response.json()
    assert isinstance(elements, list)


def test_get_audit(client):
    response = client.get("/api/circuit/audit")
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list)


def test_mutate_witness(client):
    # Set wire 2 (a) to 10
    response = client.post("/api/witness/mutate", json={"wire_id": 2, "new_value": "10"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["wire_id"] == 2
    assert data["new_value"] == "10"


def test_load_sample(client):
    response = client.post("/api/circuit/load-sample", json={"sample_name": "pythagorean", "valid": True})
    assert response.status_code == 200
    data = response.json()
    assert data["circuit_name"] == "pythagorean"
    assert data["n_constraints"] == 4
    assert data["is_valid"] is True

    # Load invalid pythagorean
    response_inv = client.post("/api/circuit/load-sample", json={"sample_name": "pythagorean", "valid": False})
    assert response_inv.status_code == 200
    data_inv = response_inv.json()
    assert data_inv["is_valid"] is False


def test_upload_circuit(client):
    circ, wit, _ = generate_multiplier_sample(valid=True)
    r1cs_bytes = R1CSBinaryWriter.to_bytes(circ)
    wtns_bytes = WTNSBinaryWriter.to_bytes(wit)

    files = {
        "r1cs_file": ("test.r1cs", r1cs_bytes, "application/octet-stream"),
        "wtns_file": ("test.wtns", wtns_bytes, "application/octet-stream"),
    }
    response = client.post("/api/circuit/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["n_constraints"] == 1
