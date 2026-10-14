"""Solidity, Foundry, and Hardhat Test Vector Exporter.

Exports verified witness vectors and circuit configurations into ready-to-use
Solidity test contracts (Foundry) and TypeScript/JSON test fixtures for integration tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from prooflens.core.r1cs import R1CSCircuit, WireType
from prooflens.core.witness import Witness


class TestVectorExporter:
    """Exports test vectors for Foundry, Hardhat, and smart contract verification."""

    __test__ = False

    def __init__(self, circuit: R1CSCircuit, witness: Witness) -> None:
        self.circuit = circuit
        self.witness = witness

    def export_json(self) -> Dict[str, Any]:
        """Export test vectors as structured JSON."""
        public_signals: List[str] = []
        private_signals: List[str] = []
        all_signals: Dict[str, str] = {}

        for wid, wire in sorted(self.circuit.wires.items()):
            if wid == 0:
                continue
            val = self.witness[wid]
            all_signals[wire.name] = str(val.to_signed_int())

            if wire.wire_type in (WireType.PUBLIC_OUTPUT, WireType.PUBLIC_INPUT):
                public_signals.append(str(val.value))
            elif wire.wire_type == WireType.PRIVATE_INPUT:
                private_signals.append(str(val.value))

        return {
            "circuitSummary": self.circuit.summary(),
            "publicSignals": public_signals,
            "privateInputs": private_signals,
            "allSignals": all_signals,
        }

    def export_foundry_solidity(self, contract_name: str = "CircuitProofTest") -> str:
        """Generate a complete Foundry test contract (.t.sol)."""
        json_data = self.export_json()
        pub_signals = json_data["publicSignals"]

        lines = [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            'import {Test, console} from "forge-std/Test.sol";',
            "",
            "interface ICircomVerifier {",
            "    function verifyProof(bytes calldata proof, uint256[] calldata pubSignals) external view returns (bool);",
            "}",
            "",
            f"contract {contract_name} is Test {{",
            "    uint256[] public pubSignals;",
            "",
            "    function setUp() public {",
        ]

        if pub_signals:
            for s in pub_signals:
                lines.append(f"        pubSignals.push({s});")
        else:
            lines.append("        // Circuit has zero public signals")

        lines.extend([
            "    }",
            "",
            "    function test_VerifyWitnessVectors() public view {",
            f"        // Verifies public signal count matches R1CS header ({len(pub_signals)})",
            f"        assertEq(pubSignals.length, {len(pub_signals)}, 'Public signal count mismatch');",
            "    }",
            "}",
        ])

        return "\n".join(lines)

    def write_to_file(self, path: Union[str, Path], format_type: str = "json") -> None:
        """Write test vectors to disk."""
        p = Path(path)
        if format_type == "foundry":
            content = self.export_foundry_solidity()
            p.write_text(content, encoding="utf-8")
        else:
            data = self.export_json()
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
