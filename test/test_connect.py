import socket
import unittest
import time

class TestConnect(unittest.TestCase):
    def test_connect(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", 8000))
            s.shutdown(socket.SHUT_RDWR)
        finally:
            s.close()

    def test_send(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", 8000))
            s.sendall("Hello libhh".encode())
            s.shutdown(socket.SHUT_RDWR)
        finally:
            s.close()

if __name__ == "__main__":
    unittest.main()
