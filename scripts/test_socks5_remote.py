"""Local protocol checks, without Docker, SSH, filesystem writes or network access."""
import unittest
from unittest.mock import patch
import socks5_remote as proxy


class Socket:
    def __init__(self, response=b'', reset=False):
        self.response = response
        self.reset = reset
        self.closed = False

    def sendall(self, data):
        pass

    def recv(self, size):
        if self.reset:
            raise ConnectionResetError()
        result, self.response = self.response[:size], self.response[size:]
        return result

    def close(self):
        self.closed = True


class AuthenticationTests(unittest.TestCase):
    def authenticate(self, sock, username=None, password=None):
        with patch.object(proxy.socket, 'create_connection', return_value=sock):
            return proxy.authenticate(54321, username, password)

    def test_anonymous_rejected_by_status(self):
        self.assertIsNone(self.authenticate(Socket(b'\x05\xff')))

    def test_anonymous_rejected_by_close(self):
        self.assertIsNone(self.authenticate(Socket()))
        self.assertIsNone(self.authenticate(Socket(reset=True)))

    def test_anonymous_acceptance_is_an_error(self):
        with self.assertRaises(ValueError):
            self.authenticate(Socket(b'\x05\x00'))

    def test_wrong_password_rejected(self):
        self.assertIsNone(self.authenticate(Socket(b'\x05\x02\x01\x01'), 'user', 'bad'))
        self.assertIsNone(self.authenticate(Socket(b'\x05\x02'), 'user', 'bad'))

    def test_correct_password_accepted(self):
        sock = Socket(b'\x05\x02\x01\x00')
        self.assertIs(self.authenticate(sock, 'user', 'correct'), sock)
        self.assertFalse(sock.closed)

    def test_docker_published_port_excluded(self):
        with patch.object(proxy, 'command', side_effect=['container-id', '{"54321/tcp":[{"HostPort":"54321"}]}']):
            with self.assertRaises(ValueError):
                proxy.choose_port(54321)


if __name__ == '__main__':
    unittest.main()
