"""Unit tests for witness container, binary WTNS parser/writer, and symbol parsing."""

import pytest
from prooflens.core.field import BN254_PRIME, FieldElement
from prooflens.core.witness import JSONWitnessParser, SymbolTableParser, Witness, WTNSBinaryParser, WTNSBinaryWriter


def test_witness_container():
    w = Witness()
    w[0] = 1
    w[1] = 42
    w[2] = -5

    assert len(w) == 3
    assert w[0].is_one()
    assert w[1].value == 42
    assert w[2].to_signed_int() == -5
    assert w[99].is_zero()  # default zero

    cloned = w.clone()
    assert len(cloned) == 3
    assert cloned[1].value == 42
    cloned[1] = 100
    assert w[1].value == 42  # original unchanged

    w_list = w.to_list()
    assert len(w_list) == 3
    assert [x.to_signed_int() for x in w_list] == [1, 42, -5]


def test_wtns_binary_roundtrip():
    w = Witness(modulus=BN254_PRIME)
    w[0] = 1
    w[1] = 1337
    w[2] = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000  # q - 1 (-1)
    w[3] = 99999

    wtns_bytes = WTNSBinaryWriter.to_bytes(w)
    assert wtns_bytes.startswith(b"wtns")

    parsed = WTNSBinaryParser.from_bytes(wtns_bytes)
    assert len(parsed) == 4
    assert parsed[0].is_one()
    assert parsed[1].value == 1337
    assert parsed[2].to_signed_int() == -1
    assert parsed[3].value == 99999


def test_symbol_table_parser():
    sym_content = """
0,1,main
1,main.out,main
2,main.a,main
3,main.b,main
4,main.multiplier.product,main.multiplier
    """
    symbols = SymbolTableParser.from_string(sym_content)
    assert len(symbols) == 5
    assert symbols[0] == "1"
    assert symbols[1] == "main.out"
    assert symbols[2] == "main.a"
    assert symbols[3] == "main.b"
    assert symbols[4] == "main.multiplier.product"


def test_json_witness_parser():
    json_array = '["1", "10", "20", "200"]'
    w_arr = JSONWitnessParser.from_string(json_array)
    assert len(w_arr) == 4
    assert w_arr[0].is_one()
    assert w_arr[3].value == 200

    json_dict = '{"0": "1", "1": "15", "2": "-3"}'
    w_dict = JSONWitnessParser.from_string(json_dict)
    assert len(w_dict) == 3
    assert w_dict[1].value == 15
    assert w_dict[2].to_signed_int() == -3


def test_wtns_parser_invalid_magic():
    with pytest.raises(ValueError, match="Invalid WTNS file magic"):
        WTNSBinaryParser.from_bytes(b"badw\x02\x00\x00\x00")
