from subprocess import Popen, PIPE, STDOUT
import unittest

def create_proc():
    p = Popen(["./build/hpacker"], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    return p

def hpack_equal(self, p, in_bytes, expected):
    self.assertEqual(expected, p.communicate(input=in_bytes)[0].decode())

class TestHpack(unittest.TestCase):
    def test_exe(self):
        p = create_proc()
        hpack_equal(self, p, b"\x65\x65\x65\x65", "\x65\x65\x65\x65")

if __name__ == "__main__":
    unittest.main()
