"""Exercise the ABI gate against missing bounds, host imports and malformed metadata."""
import unittest
import contextlib
import io
from pathlib import Path
import tempfile
from console_wasm_check import contract, check, EXPORTS, MAX_BYTES, WARN_BYTES


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
    def test_only_validated_bytes_are_published_for_embedding(self):
        valid = (b"\x00asm\x01\x00\x00\x00" + section(5, bytes([1, 1, 64, 64])) +
                 exports(EXPORTS))
        with tempfile.TemporaryDirectory(prefix="sibuna-wasm-gate-") as directory:
            source, output = Path(directory) / "input.wasm", Path(directory) / "output.wasm"
            source.write_bytes(valid)
            with contextlib.redirect_stdout(io.StringIO()):
                check(source, output)
            self.assertEqual(output.read_bytes(), valid)
            for invalid in (valid[:-1], b"x" * (MAX_BYTES + 1)):
                source.write_bytes(invalid)
                with self.assertRaises(SystemExit):
                    check(source, output)
                self.assertEqual(output.read_bytes(), valid)

    def test_review_threshold_warns_without_rejecting_valid_artifacts(self):
        valid = (b"\x00asm\x01\x00\x00\x00" + section(5, bytes([1, 1, 64, 64])) +
                 exports(EXPORTS))
        with tempfile.TemporaryDirectory(prefix="sibuna-wasm-budget-") as directory:
            source, output = Path(directory) / "input.wasm", Path(directory) / "output.wasm"
            # A custom section holds inert padding; the ABI remains unchanged at each size.
            for total, warned in ((WARN_BYTES, False), (WARN_BYTES + 1, True), (MAX_BYTES, True)):
                padding = total - len(valid) - 4
                data = valid + section(0, b"\0" * padding)
                self.assertEqual(total, len(data))
                source.write_bytes(data)
                warning = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(warning):
                    check(source, output)
                self.assertEqual(warned, "warning:" in warning.getvalue())
                self.assertEqual(data, output.read_bytes())

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
