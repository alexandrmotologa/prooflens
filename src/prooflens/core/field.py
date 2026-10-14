"""Finite field arithmetic over BN254 and generic prime fields.

Zero-Knowledge Proof circuits compiled with Circom and snarkjs use finite field
arithmetic over the BN254 (alt_bn128) scalar field by default:
q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
"""

from __future__ import annotations

import sys
from typing import Any, Union

# BN254 (alt_bn128) scalar field order (the default prime modulus used by Circom/snarkjs)
BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# BLS12-381 scalar field order (for multi-curve circuit analysis)
BLS12_381_PRIME = 52435875175126190479447740508185965837690552500527637822603658699938581184513


class FieldElement:
    """An element of a prime finite field F_q.

    Supports canonical BN254 modular arithmetic, inverse calculation, signed integer
    representation (centered around 0 for Circom negative signals), and little-endian
    byte serialization compatible with the iden3 R1CS/WTNS format.
    """

    __slots__ = ("_value", "_modulus")

    def __init__(self, value: Union[int, str, bytes, FieldElement], modulus: int = BN254_PRIME) -> None:
        if modulus <= 1:
            raise ValueError(f"Modulus must be a prime > 1, got {modulus}")
        self._modulus = modulus

        if isinstance(value, FieldElement):
            self._value = value.value % modulus
        elif isinstance(value, int):
            self._value = value % modulus
        elif isinstance(value, str):
            value_str = value.strip()
            if value_str.startswith(("0x", "0X")):
                self._value = int(value_str, 16) % modulus
            else:
                self._value = int(value_str) % modulus
        elif isinstance(value, (bytes, bytearray)):
            self._value = int.from_bytes(value, byteorder="little") % modulus
        else:
            raise TypeError(f"Cannot initialize FieldElement from {type(value).__name__}")

    @property
    def value(self) -> int:
        """The canonical non-negative integer representation in [0, modulus - 1]."""
        return self._value

    @property
    def modulus(self) -> int:
        """The prime modulus q."""
        return self._modulus

    @classmethod
    def zero(cls, modulus: int = BN254_PRIME) -> FieldElement:
        """Additive identity element (0)."""
        return cls(0, modulus=modulus)

    @classmethod
    def one(cls, modulus: int = BN254_PRIME) -> FieldElement:
        """Multiplicative identity element (1)."""
        return cls(1, modulus=modulus)

    @classmethod
    def from_bytes(cls, data: bytes, modulus: int = BN254_PRIME, byteorder: str = "little") -> FieldElement:
        """Create a field element from raw bytes."""
        val = int.from_bytes(data, byteorder=byteorder)
        return cls(val, modulus=modulus)

    def to_bytes(self, length: int = 32, byteorder: str = "little") -> bytes:
        """Serialize field element into bytes, standard 32 bytes little-endian for BN254."""
        return self._value.to_bytes(length, byteorder=byteorder)

    def to_signed_int(self) -> int:
        """Convert to signed integer centered in [-modulus // 2, modulus // 2].

        In Circom, -1 is stored as q - 1. This converts q - 1 back to -1 for human
        readability when debugging circuit signals.
        """
        half = self._modulus // 2
        if self._value > half:
            return self._value - self._modulus
        return self._value

    def is_zero(self) -> bool:
        """Check if the element equals 0."""
        return self._value == 0

    def is_one(self) -> bool:
        """Check if the element equals 1."""
        return self._value == 1

    def inv(self) -> FieldElement:
        """Multiplicative inverse of the field element using Fermat's Little Theorem."""
        if self._value == 0:
            raise ZeroDivisionError("Cannot invert zero in finite field")
        # Fermat's Little Theorem: a^(p-2) === a^(-1) (mod p) for prime p
        inv_val = pow(self._value, self._modulus - 2, self._modulus)
        return FieldElement(inv_val, modulus=self._modulus)

    def __add__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, FieldElement):
            if self._modulus != other._modulus:
                raise ValueError("Cannot add elements from different fields")
            return FieldElement(self._value + other._value, modulus=self._modulus)
        if isinstance(other, int):
            return FieldElement(self._value + other, modulus=self._modulus)
        return NotImplemented

    def __radd__(self, other: Union[FieldElement, int]) -> FieldElement:
        return self.__add__(other)

    def __sub__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, FieldElement):
            if self._modulus != other._modulus:
                raise ValueError("Cannot subtract elements from different fields")
            return FieldElement(self._value - other._value, modulus=self._modulus)
        if isinstance(other, int):
            return FieldElement(self._value - other, modulus=self._modulus)
        return NotImplemented

    def __rsub__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, int):
            return FieldElement(other - self._value, modulus=self._modulus)
        return NotImplemented

    def __mul__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, FieldElement):
            if self._modulus != other._modulus:
                raise ValueError("Cannot multiply elements from different fields")
            return FieldElement(self._value * other._value, modulus=self._modulus)
        if isinstance(other, int):
            return FieldElement(self._value * other, modulus=self._modulus)
        return NotImplemented

    def __rmul__(self, other: Union[FieldElement, int]) -> FieldElement:
        return self.__mul__(other)

    def __truediv__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, int):
            other = FieldElement(other, modulus=self._modulus)
        if isinstance(other, FieldElement):
            if self._modulus != other._modulus:
                raise ValueError("Cannot divide elements from different fields")
            return self * other.inv()
        return NotImplemented

    def __rtruediv__(self, other: Union[FieldElement, int]) -> FieldElement:
        if isinstance(other, int):
            return FieldElement(other, modulus=self._modulus) * self.inv()
        return NotImplemented

    def __neg__(self) -> FieldElement:
        return FieldElement(-self._value, modulus=self._modulus)

    def __pow__(self, exponent: int) -> FieldElement:
        if not isinstance(exponent, int):
            raise TypeError("Exponent must be an integer")
        if exponent < 0:
            return self.inv() ** (-exponent)
        return FieldElement(pow(self._value, exponent, self._modulus), modulus=self._modulus)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, FieldElement):
            return self._value == other._value and self._modulus == other._modulus
        if isinstance(other, int):
            return self._value == (other % self._modulus)
        return False

    def __hash__(self) -> int:
        return hash((self._value, self._modulus))

    def __str__(self) -> str:
        # Display as small signed integer if within reasonable small bounds (e.g. [-1000, 1000])
        signed = self.to_signed_int()
        if abs(signed) <= 1000:
            return str(signed)
        # Otherwise show hex
        return f"0x{self._value:x}"

    def __repr__(self) -> str:
        signed = self.to_signed_int()
        if abs(signed) <= 1000:
            return f"Fq({signed})"
        return f"Fq(0x{self._value:x})"

    def format_full(self) -> str:
        """Format with both integer and hex representations."""
        signed = self.to_signed_int()
        if abs(signed) <= 1000 and signed != self._value:
            return f"{signed} (0x{self._value:x})"
        return f"0x{self._value:x} ({self._value})"
