import socket
import unittest
import time
import ssl

class TestConnect(unittest.TestCase):
    def test_connect_tls(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS)
        try:
            s.connect(("localhost", 8000))
            s.shutdown(socket.SHUT_RDWR)
        finally:
            s.close()

if __name__ == "__main__":
    unittest.main()
