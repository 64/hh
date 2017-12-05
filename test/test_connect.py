import socket
import unittest
import time
import ssl

def connect_tls():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS)
    try:
        s.connect(("localhost", 8000))
    except:
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    return s

def connect_h2():
    sock = connect_tls()
    sock.sendall(bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii"))
    return sock


class TestConnect(unittest.TestCase):
    def test_connection_preface(self):
        sock = connect_tls()
        sock.sendall(bytes("RRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii"))
        sock.close()

    def test_initial_settings(self):
        sock = connect_h2()
        sock.sendall(bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]))
        sock.close()

if __name__ == "__main__":
    unittest.main()
