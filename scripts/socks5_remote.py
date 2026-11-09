"""Executed over SSH by Socks5Proxy; stdout is a private JSON response, never a log."""
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

# PANEL_REQUEST

DIRECTORY = Path('/opt/amnezia/socks5')
CONFIG = DIRECTORY / 'config.json'
CONTAINER = 'amnezia-socks5'
LABEL = 'org.amnezia.panel.protocol'
stage = 'configuration'


def command(*args, timeout=30):
    # Never echo command lines, config contents or daemon errors containing credentials.
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout).stdout.decode()


def inspect_container():
    names = command('docker', 'ps', '-a', '--format', '{{.Names}}').splitlines()
    if CONTAINER not in names:
        return None
    info = json.loads(command('docker', 'inspect', CONTAINER))[0]
    if (info['Config'].get('Labels') or {}).get(LABEL) != 'socks5':
        raise ValueError('Container name already belongs to another service')
    return info


def choose_port(saved=None):
    occupied = set()
    ids = command('docker', 'ps', '-aq').split()
    if ids:
        for line in command('docker', 'inspect', '--format', '{{json .HostConfig.PortBindings}}', *ids).splitlines():
            for key, bindings in (json.loads(line) or {}).items():
                if key.endswith('/tcp'):
                    for binding in bindings or []:
                        value = binding.get('HostPort', '')
                        if value.isdigit():
                            occupied.add(int(value))
    candidates = [int(saved)] if saved else secrets.SystemRandom().sample(range(30000, 65001), 100)
    for port in candidates:
        if not 1 <= port <= 65535 or port in occupied:
            continue
        with socket.socket() as probe:
            try:
                probe.bind(('0.0.0.0', port))
            except OSError:
                continue
        return port
    raise ValueError('No free TCP port')


def receive(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('Truncated SOCKS response')
        data += part
    return data


def authenticate(port, username=None, password=None):
    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
    try:
        sock.sendall(b'\x05\x01' + (b'\x00' if username is None else b'\x02'))
        method = receive(sock, 2)
        if username is None:
            if method != b'\x05\xff':
                raise ValueError('Anonymous proxy access allowed')
            sock.close()
            return None
        if method != b'\x05\x02':
            raise ValueError('Password authentication required')
        user, password = username.encode(), password.encode()
        sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        status = receive(sock, 2)
        if status != b'\x01\x00':
            sock.close()
            return None
        return sock
    except (ConnectionResetError, BrokenPipeError, EOFError):
        # Xray may close the socket instead of sending a negative auth reply.
        sock.close()
        return None
    except Exception:
        sock.close()
        raise


def verify(profile):
    global stage
    stage = 'authentication'
    authenticate(profile['port'])
    wrong = authenticate(profile['port'], profile['username'], secrets.token_hex(24))
    if wrong is not None:
        wrong.close()
        raise ValueError('Incorrect credentials accepted')
    sock = authenticate(profile['port'], profile['username'], profile['password'])
    if sock is None:
        raise ValueError('Correct credentials rejected')
    stage = 'connectivity'
    with sock:
        host = b'example.com'
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', 443))
        reply = receive(sock, 4)
        if reply[:3] != b'\x05\x00\x00':
            raise ValueError('SOCKS CONNECT failed')
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = receive(sock, 1)[0]
        if size is None:
            raise ValueError('Invalid address type')
        receive(sock, size + 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname='example.com') as tls:
            tls.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            if not tls.recv(256).startswith(b'HTTP/'):
                raise ValueError('No HTTPS response through proxy')


def install():
    global stage
    stage = 'docker'
    command('docker', 'info')
    existing = inspect_container()
    stage = 'configuration'
    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DIRECTORY, 0o700)
    if CONFIG.exists():
        config = json.loads(CONFIG.read_text())
        inbound = config['inbounds'][0]
        settings = inbound['settings']
        if inbound['protocol'] != 'socks' or settings['auth'] != 'password' or settings.get('udp', False):
            raise ValueError('Unexpected existing configuration')
        users = settings.get('users', settings.get('accounts', []))
        if len(users) != 1:
            raise ValueError('Expected one shared account')
        profile = {'port': int(inbound['port']), 'username': users[0]['user'], 'password': users[0]['pass']}
    else:
        if existing:
            raise ValueError('Existing container configuration is missing')
        stage = 'port'
        profile = {'port': choose_port(REQUEST.get('port')), 'username': REQUEST['username'], 'password': REQUEST['password']}
        config = {
            'log': {'loglevel': 'warning', 'access': 'none'},
            'inbounds': [{'listen': '0.0.0.0', 'port': profile['port'], 'protocol': 'socks',
                          'settings': {'auth': 'password', 'users': [{'user': profile['username'], 'pass': profile['password']}], 'udp': False}}],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
        }
        temporary = DIRECTORY / 'config.json.new'
        temporary.write_text(json.dumps(config))
        os.chmod(temporary, 0o600)
        os.replace(temporary, CONFIG)
    # The official image runs as UID 65532. Only the file is mounted into it.
    os.chown(CONFIG, 65532, 65532)
    os.chmod(CONFIG, 0o600)
    stage = 'image'
    command('docker', 'pull', REQUEST['image'], timeout=600)
    command('docker', 'run', '--rm', '-v', str(CONFIG) + ':/etc/socks5.json:ro',
            REQUEST['image'], 'run', '-test', '-c', '/etc/socks5.json')
    stage = 'start'
    port = str(profile['port'])
    expected_binding = [{'HostIp': '0.0.0.0', 'HostPort': port}]
    if existing and (existing['Config']['Image'] != REQUEST['image'] or
                     (existing['HostConfig'].get('PortBindings') or {}).get(port + '/tcp') != expected_binding):
        command('docker', 'rm', '-f', CONTAINER)
        existing = None
    if existing:
        if not existing['State']['Running']:
            command('docker', 'start', CONTAINER)
    else:
        command('docker', 'run', '-d', '--name', CONTAINER, '--label', LABEL + '=socks5',
                '--restart', 'unless-stopped', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '-p', '0.0.0.0:' + port + ':' + port + '/tcp', '-v', str(CONFIG) + ':/etc/socks5.json:ro',
                REQUEST['image'], 'run', '-c', '/etc/socks5.json')
    for attempt in range(15):
        try:
            # A Docker port can accept TCP before Xray finishes starting.
            # Wait for an authenticated SOCKS handshake, not just a listening socket.
            ready = authenticate(profile['port'], profile['username'], profile['password'])
            if ready is not None:
                ready.close()
                break
        except (OSError, ValueError):
            pass
        time.sleep(1)
    else:
        raise ValueError('SOCKS authentication did not become ready')
    verify(profile)
    return {'success': True, 'profile': profile}


def uninstall():
    global stage
    stage = 'uninstall'
    if shutil.which('docker') and inspect_container():
        command('docker', 'rm', '-f', CONTAINER)
    if DIRECTORY.exists():
        shutil.rmtree(DIRECTORY)
    return {'success': True}


if __name__ == '__main__':
    try:
        result = install() if REQUEST['action'] == 'install' else uninstall()
        print(json.dumps(result))
    except Exception:
        print(json.dumps({'success': False, 'stage': stage}))
        sys.exit(1)
