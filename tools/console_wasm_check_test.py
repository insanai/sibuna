"""Exercise the ABI gate against missing bounds, host imports and malformed metadata."""
import unittest
from console_wasm_check import contract, EXPORTS


def integer(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def section(kind, payload):
    return bytes([kind]) + integer(len(payload)) + payload


def exports(values):
    result = integer(len(values))
    for name, kind in values.items():
        text = name.encode()
        result += integer(len(text)) + text + bytes([kind, 0])
    return section(7, result)


class ContractTest(unittest.TestCase):
    def test_linker_contract_is_required_and_bounded(self):
        # These are metadata fixtures, not executable modules. The live UI exercises code.
        header = b"\x00asm\x01\x00\x00\x00"
        memory = section(5, bytes([1, 1, 64, 64]))
        names = exports(EXPORTS)
        valid = header + memory + names
        contract(valid)
        contract(header + section(2, b"\0") + memory + names)
        for length in range(len(valid)):
            with self.assertRaises(ValueError):
                contract(valid[:length])
        for invalid in (
            header + names,
            header + memory + memory + names,
            header + section(2, b"\1") + memory + names,
            header + section(5, bytes([1, 0, 64])) + names,
            header + section(5, bytes([1, 1, 64, 65])) + names,
            header + section(5, bytes([1, 1, 63, 64])) + names,
            header + section(5, bytes([1, 3, 64, 64])) + names,
            header + section(5, bytes([1, 1, 64, 64, 0])) + names,
            header + memory + exports(dict(EXPORTS, unexpected=0)),
            header + memory + exports(dict(EXPORTS, sb_event=2)),
            header + b"\5\x80\x80\x80\x80\x10",
        ):
            with self.assertRaises(ValueError):
                contract(invalid)


if __name__ == "__main__":
    unittest.main()
