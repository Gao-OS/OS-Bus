"""Offline FD09 actor validation with real descriptors and malformed inputs."""
import os
import unittest

from actor import packet, validate_full, validate_partial


class ActorValidationTest(unittest.TestCase):
    def setUp(self):
        self.fd = self.memfd('fanout-101', b'fanout-resource-101')
        self.raw = packet(101, sender=':1.6')

    def memfd(self, name, data):
        fd = os.memfd_create(name, os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.write(fd, data)
        return fd

    def test_full_frame_resource_is_independently_usable(self):
        result = validate_full(self.raw, [self.fd], 101, ':1.6')
        self.assertEqual(result['resource'], 'fanout-resource-101')
        self.assertEqual(result['resource_target'], '/memfd:fanout-101 (deleted)')
        self.assertEqual(result['fd_identity'], '%d:%d' %
                         (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino))
        self.assertEqual(os.pread(self.fd, 19, 0), b'fanout-resource-101')

    def test_full_frame_rejects_corruption_and_missing_or_extra_rights(self):
        for raw, fds, serial, sender in (
            (bytes([ord('B')]) + self.raw[1:], [self.fd], 101, ':1.6'),
            (self.raw[:-1] + bytes([self.raw[-1] ^ 1]), [self.fd], 101, ':1.6'),
            (self.raw, [self.fd], 102, ':1.6'),
            (self.raw, [self.fd], 101, ':1.7'),
            (self.raw, [], 101, ':1.6'),
            (self.raw, [self.fd, self.fd], 101, ':1.6'),
        ):
            with self.subTest(serial=serial, sender=sender, rights=len(fds)):
                with self.assertRaises(AssertionError):
                    validate_full(raw, fds, serial, sender)

    def test_partial_prefix_requires_exact_offset_bytes_and_rights(self):
        prefix = self.raw[:4480]
        self.assertTrue(validate_partial(prefix, [self.fd], 101, ':1.6', 4480)['partial'])
        for raw, fds, offset in (
            (prefix, [self.fd], 4481),
            (prefix[:-1] + bytes([prefix[-1] ^ 1]), [self.fd], 4480),
            (prefix, [], 4480),
            (prefix, [self.fd, self.fd], 4480),
            (self.raw, [self.fd], len(self.raw)),
            (self.raw[:16], [self.fd], 16),
        ):
            with self.subTest(offset=offset, rights=len(fds)):
                with self.assertRaises(AssertionError):
                    validate_partial(raw, fds, 101, ':1.6', offset)

    def test_resource_type_name_size_and_data_are_checked(self):
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        for fd in (
            reader,
            self.memfd('fanout-102', b'fanout-resource-101'),
            self.memfd('fanout-101', b'fanout-resource-101-extra'),
            self.memfd('fanout-101', b'fanout-resource-102'),
        ):
            with self.subTest(fd=fd):
                with self.assertRaises(AssertionError):
                    validate_full(self.raw, [fd], 101, ':1.6')


if __name__ == '__main__':
    unittest.main()
