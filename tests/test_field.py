"""Unit tests for BN254 finite field arithmetic."""

import pytest
from prooflens.core.field import BLS12_381_PRIME, BN254_PRIME, FieldElement


def test_field_initialization():
    zero = FieldElement.zero()
    one = FieldElement.one()
    assert zero.value == 0
    assert one.value == 1
    assert zero.is_zero()
    assert one.is_one()

    # From string decimal and hex
    f1 = FieldElement("123456")
    assert f1.value == 123456
    f2 = FieldElement("0x10")
    assert f2.value == 16

    # From bytes little-endian
    b = (42).to_bytes(32, byteorder="little")
    f_b = FieldElement.from_bytes(b)
    assert f_b.value == 42


def test_field_arithmetic_basic():
    a = FieldElement(7)
    b = FieldElement(3)

    assert (a + b).value == 10
    assert (a - b).value == 4
    assert (a * b).value == 21
    assert (a + 5).value == 12
    assert (5 + a).value == 12
    assert (a - 10).value == (7 - 10) % BN254_PRIME
    assert (10 - a).value == 3
    assert (a * 2).value == 14
    assert (2 * a).value == 14


def test_field_inversion_and_division():
    a = FieldElement(123456789)
    inv_a = a.inv()
    assert (a * inv_a).is_one()

    b = FieldElement(987654321)
    c = b / a
    assert (c * a) == b

    with pytest.raises(ZeroDivisionError):
        FieldElement.zero().inv()

    with pytest.raises(ZeroDivisionError):
        _ = a / 0


def test_field_powers_and_negation():
    a = FieldElement(5)
    assert (a**0).is_one()
    assert (a**1) == a
    assert (a**3).value == 125
    assert (a**(-1)) == a.inv()

    neg_a = -a
    assert (a + neg_a).is_zero()
    assert neg_a.value == BN254_PRIME - 5
    assert neg_a.to_signed_int() == -5


def test_field_signed_integer_conversion():
    # 0 -> 0
    assert FieldElement(0).to_signed_int() == 0
    # 1 -> 1
    assert FieldElement(1).to_signed_int() == 1
    # -1 in field -> BN254_PRIME - 1
    neg_one = FieldElement(-1)
    assert neg_one.value == BN254_PRIME - 1
    assert neg_one.to_signed_int() == -1

    # Large negative number
    neg_42 = FieldElement(-42)
    assert neg_42.to_signed_int() == -42


def test_field_serialization_roundtrip():
    elem = FieldElement(0x123456789ABCDEF0)
    data = elem.to_bytes(length=32, byteorder="little")
    assert len(data) == 32

    reconstructed = FieldElement.from_bytes(data)
    assert reconstructed == elem
    assert reconstructed.value == elem.value


def test_generic_modulus():
    elem = FieldElement(10, modulus=BLS12_381_PRIME)
    assert elem.modulus == BLS12_381_PRIME
    inv = elem.inv()
    assert (elem * inv).is_one()

    with pytest.raises(ValueError):
        _ = FieldElement(5, modulus=1)

    with pytest.raises(ValueError):
        # Mismatched fields
        _ = elem + FieldElement(5, modulus=BN254_PRIME)
