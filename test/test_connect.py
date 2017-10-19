import socket
import unittest
import hh

class TestConnect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hh.run_async()

    def test_connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 8000))
        self.assertTrue(True) # Connect didn't fail
        s.shutdown(socket.SHUT_RDWR)
        s.close()

if __name__ == "__main__":
    unittest.main()
