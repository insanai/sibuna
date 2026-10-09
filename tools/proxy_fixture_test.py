"""Independent RFC 6455 vectors and frame-length boundaries for the real origin fixture."""
import io
import unittest
from proxy_fixture import frame, masked_payload, receive


class MaskingTest(unittest.TestCase):
    def test_rfc6455_hello_vector(self):
        wire = bytes.fromhex('818537fa213d7f9f4d5158')
        self.assertEqual(receive(io.BytesIO(wire), True), (1, b'Hello', True))
        self.assertEqual(masked_payload(b'Hello', bytes.fromhex('37fa213d')),
                         bytes.fromhex('7f9f4d5158'))

    def test_mask_rotation_and_length_boundaries(self):
        mask = bytes.fromhex('1280fa01')
        for length in (0, 1, 2, 3, 4, 7, 125, 126, 65535, 65536, 2097152):
            payload = (bytes(range(256)) * (length // 256 + 1))[:length]
            with self.subTest(length=length):
                expected = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
                self.assertEqual(masked_payload(payload, mask), expected)
                for masked in (False, True):
                    self.assertEqual(receive(io.BytesIO(frame(2, payload, masked, False)), masked),
                                     (2, payload, False))


if __name__ == '__main__':
    unittest.main()
