import unittest

from local_tcp_frames import FRAME_BYTES, NonceFrames


class LocalTcpFramesTest(unittest.TestCase):
    fresh = b'krtek-m3-01234567-89ab-cdef-0123-456789abcdef'
    session = b'krtek-m3-0123456789abcdef0123456789abc-t-001f'

    def test_both_consumer_forms_are_decoded_across_every_split(self):
        for frame in (self.fresh, self.session):
            self.assertEqual(FRAME_BYTES, len(frame))
            for split in range(1, len(frame)):
                with self.subTest(frame=frame, split=split):
                    decoder = NonceFrames()
                    self.assertEqual([], decoder.feed(frame[:split]))
                    self.assertEqual([(0, frame)], decoder.feed(frame[split:]))
                    self.assertIsNone(decoder.incomplete())

    def test_bytewise_and_coalesced_frames_have_the_same_stream_offsets(self):
        body = self.fresh + self.session + self.fresh
        expected = [(0, self.fresh), (45, self.session), (90, self.fresh)]
        decoder = NonceFrames()
        self.assertEqual(expected, decoder.feed(body))
        decoder = NonceFrames()
        actual = []
        for byte in body:
            actual.extend(decoder.feed(bytes([byte])))
        self.assertEqual(expected, actual)

    def test_garbage_and_invalid_prefixes_do_not_fabricate_nonce_frames(self):
        decoder = NonceFrames()
        prefix = b'garbagekrtek-m3-' + b'x' * 45
        self.assertEqual([], decoder.feed(prefix))
        self.assertEqual([(len(prefix), self.fresh)], decoder.feed(self.fresh))
        self.assertIsNone(decoder.incomplete())

    def test_retained_parser_tail_is_bounded_by_one_incomplete_frame(self):
        decoder = NonceFrames()
        self.assertEqual([], decoder.feed(b'x' * 65535))
        self.assertLess(len(decoder.pending), FRAME_BYTES)
        decoder.feed(self.session[:44])
        self.assertLess(len(decoder.pending), FRAME_BYTES)
        self.assertEqual((65535, self.session[:44]), decoder.incomplete())

    def test_eof_partial_frame_is_explicit_and_not_a_payload_hit(self):
        decoder = NonceFrames()
        self.assertEqual([], decoder.feed(self.fresh[:20]))
        self.assertEqual((0, self.fresh[:20]), decoder.incomplete())


if __name__ == '__main__':
    unittest.main()
