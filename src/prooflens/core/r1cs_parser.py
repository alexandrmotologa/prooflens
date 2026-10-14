"""Binary R1CS parser and serializer conforming to the iden3 / Circom specification.

Official Circom binary R1CS format:
Magic: 4 bytes b'r1cs' (0x72316373)
Version: uint32 LE
Section count: uint32 LE

Section 1 (Header):
- field_size: uint32 LE (bytes per field element, 32 for BN254)
- prime: field_size bytes LE
- n_wires: uint32 LE
- n_pub_out: uint32 LE
- n_pub_in: uint32 LE
- n_prv_in: uint32 LE
- n_labels: uint64 LE
- n_constraints: uint32 LE

Section 2 (Constraints):
- Repeated n_constraints times:
  - Linear combination A:
    - n_terms: uint32 LE
    - Repeated n_terms: wire_id (uint32 LE), coeff (field_size bytes LE)
  - Linear combination B:
    - n_terms: uint32 LE
    - Repeated n_terms: wire_id (uint32 LE), coeff (field_size bytes LE)
  - Linear combination C:
    - n_terms: uint32 LE
    - Repeated n_terms: wire_id (uint32 LE), coeff (field_size bytes LE)

Section 3 (Wire-to-label map, optional):
- n_wires uint64 LE values mapping wire index to label index.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import BinaryIO, List, Optional, Union

from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.r1cs import Constraint, LinearCombination, R1CSCircuit, R1CSHeader

R1CS_MAGIC = b"r1cs"
R1CS_SUPPORTED_VERSIONS = [1, 2]

SECTION_HEADER = 1
SECTION_CONSTRAINTS = 2
SECTION_WIRE2LABEL = 3


class R1CSBinaryParser:
    """Parser for binary Circom/iden3 .r1cs files."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> R1CSCircuit:
        """Parse an R1CS circuit from a binary file on disk."""
        with open(path, "rb") as f:
            parser = cls(f)
            return parser.parse()

    @classmethod
    def from_bytes(cls, data: bytes) -> R1CSCircuit:
        """Parse an R1CS circuit from raw bytes."""
        return cls(io.BytesIO(data)).parse()

    def parse(self) -> R1CSCircuit:
        """Execute parsing and return an R1CSCircuit object."""
        # 1. Read Magic
        magic = self.stream.read(4)
        if magic != R1CS_MAGIC:
            raise ValueError(f"Invalid R1CS file magic: expected {R1CS_MAGIC!r}, got {magic!r}")

        # 2. Version and Section count
        version_bytes = self.stream.read(4)
        if len(version_bytes) < 4:
            raise ValueError("Unexpected EOF reading R1CS version")
        version = struct.unpack("<I", version_bytes)[0]
        if version not in R1CS_SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported R1CS version: {version}")

        num_sections_bytes = self.stream.read(4)
        num_sections = struct.unpack("<I", num_sections_bytes)[0]

        header: Optional[R1CSHeader] = None
        constraints: List[Constraint] = []

        # 3. Read Sections
        for _ in range(num_sections):
            sec_header_bytes = self.stream.read(12)
            if len(sec_header_bytes) < 12:
                break
            sec_type, sec_size = struct.unpack("<IQ", sec_header_bytes)

            sec_start = self.stream.tell()

            if sec_type == SECTION_HEADER:
                header = self._parse_header_section(sec_size)
            elif sec_type == SECTION_CONSTRAINTS:
                if header is None:
                    raise ValueError("R1CS Constraints section appeared before Header section")
                constraints = self._parse_constraints_section(sec_size, header)
            else:
                # Skip unknown or wire2label sections
                self.stream.seek(sec_start + sec_size)

        if header is None:
            raise ValueError("Malformed R1CS: Missing header section")

        return R1CSCircuit(header=header, constraints=constraints)

    def _parse_header_section(self, sec_size: int) -> R1CSHeader:
        field_size_bytes = self.stream.read(4)
        field_size = struct.unpack("<I", field_size_bytes)[0]

        prime_bytes = self.stream.read(field_size)
        prime = int.from_bytes(prime_bytes, byteorder="little")

        meta_bytes = self.stream.read(4 * 4 + 8 + 4)
        (
            n_wires,
            n_pub_out,
            n_pub_in,
            n_prv_in,
            n_labels,
            n_constraints,
        ) = struct.unpack("<IIIIQI", meta_bytes)

        return R1CSHeader(
            field_size=field_size,
            prime=prime,
            n_wires=n_wires,
            n_pub_out=n_pub_out,
            n_pub_in=n_pub_in,
            n_prv_in=n_prv_in,
            n_labels=n_labels,
            n_constraints=n_constraints,
        )

    def _parse_constraints_section(self, sec_size: int, header: R1CSHeader) -> List[Constraint]:
        constraints: List[Constraint] = []
        field_size = header.field_size
        prime = header.prime

        for cid in range(header.n_constraints):
            lc_a = self._parse_linear_combination(field_size, prime)
            lc_b = self._parse_linear_combination(field_size, prime)
            lc_c = self._parse_linear_combination(field_size, prime)

            constraints.append(Constraint(id=cid, a=lc_a, b=lc_b, c=lc_c))

        return constraints

    def _parse_linear_combination(self, field_size: int, prime: int) -> LinearCombination:
        n_terms_bytes = self.stream.read(4)
        if len(n_terms_bytes) < 4:
            raise ValueError("Unexpected EOF reading linear combination term count")
        n_terms = struct.unpack("<I", n_terms_bytes)[0]

        lc = LinearCombination(modulus=prime)
        for _ in range(n_terms):
            wire_id_bytes = self.stream.read(4)
            wire_id = struct.unpack("<I", wire_id_bytes)[0]
            coeff_bytes = self.stream.read(field_size)
            coeff_val = int.from_bytes(coeff_bytes, byteorder="little")
            coeff = FieldElement(coeff_val, modulus=prime)
            lc.add_term(wire_id, coeff)

        return lc


class R1CSBinaryWriter:
    """Serializes an R1CSCircuit into the official Circom binary R1CS format."""

    @classmethod
    def to_bytes(cls, circuit: R1CSCircuit) -> bytes:
        buf = io.BytesIO()
        writer = cls(circuit, buf)
        writer.write()
        return buf.getvalue()

    @classmethod
    def to_file(cls, circuit: R1CSCircuit, path: Union[str, Path]) -> None:
        with open(path, "wb") as f:
            writer = cls(circuit, f)
            writer.write()

    def __init__(self, circuit: R1CSCircuit, stream: BinaryIO) -> None:
        self.circuit = circuit
        self.stream = stream

    def write(self) -> None:
        # Magic
        self.stream.write(R1CS_MAGIC)
        # Version 1
        self.stream.write(struct.pack("<I", 1))
        # 2 sections: Header (1) and Constraints (2)
        self.stream.write(struct.pack("<I", 2))

        # --- Section 1: Header ---
        h = self.circuit.header
        header_buf = io.BytesIO()
        header_buf.write(struct.pack("<I", h.field_size))
        header_buf.write(h.prime.to_bytes(h.field_size, byteorder="little"))
        header_buf.write(
            struct.pack(
                "<IIIIQI",
                h.n_wires,
                h.n_pub_out,
                h.n_pub_in,
                h.n_prv_in,
                h.n_labels,
                len(self.circuit.constraints),
            )
        )
        header_data = header_buf.getvalue()

        # Write Section 1 Header
        self.stream.write(struct.pack("<IQ", SECTION_HEADER, len(header_data)))
        self.stream.write(header_data)

        # --- Section 2: Constraints ---
        cons_buf = io.BytesIO()
        for c in self.circuit.constraints:
            self._write_linear_combination(cons_buf, c.a, h.field_size)
            self._write_linear_combination(cons_buf, c.b, h.field_size)
            self._write_linear_combination(cons_buf, c.c, h.field_size)

        cons_data = cons_buf.getvalue()
        # Write Section 2 Header
        self.stream.write(struct.pack("<IQ", SECTION_CONSTRAINTS, len(cons_data)))
        self.stream.write(cons_data)

    def _write_linear_combination(self, buf: io.BytesIO, lc: LinearCombination, field_size: int) -> None:
        non_zero_terms = [(wid, coeff) for wid, coeff in lc.terms.items() if not coeff.is_zero()]
        buf.write(struct.pack("<I", len(non_zero_terms)))
        for wid, coeff in non_zero_terms:
            buf.write(struct.pack("<I", wid))
            buf.write(coeff.to_bytes(length=field_size, byteorder="little"))
