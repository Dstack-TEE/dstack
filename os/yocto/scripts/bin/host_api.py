import os
import json
import struct
import socket
import urllib
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler


@dataclass
class ServerConfig:
    kp_address: str
    kp_port: int
    vm_dir: str


class QuoteError(Exception):
    pass


@dataclass
class QuoteResponse:
    encrypted_key: bytes
    provider_quote: bytes

    @classmethod
    def from_json(cls, data: dict) -> 'QuoteResponse':
        return cls(
            encrypted_key=bytes(data['encrypted_key']),
            provider_quote=bytes(data['provider_quote'])
        )


def get_key(quote: bytes, address: str, port: int) -> QuoteResponse:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((address, port))

    try:
        payload = {"quote": list(quote)}
        serialized = json.dumps(payload).encode()
        length = len(serialized)

        sock.sendall(struct.pack('>I', length))
        sock.sendall(serialized)

        response_length_bytes = sock.recv(4)
        response_length = struct.unpack('>I', response_length_bytes)[0]

        response_data = b''
        while len(response_data) < response_length:
            chunk = sock.recv(min(4096, response_length - len(response_data)))
            if not chunk:
                raise ConnectionError("Connection closed prematurely")
            response_data += chunk

        response_json = json.loads(response_data)
        return QuoteResponse.from_json(response_json)

    finally:
        sock.close()


class QuoteHandler(BaseHTTPRequestHandler):
    def __init__(self, config: ServerConfig, *args, **kwargs):
        self.config = config
        super().__init__(*args, **kwargs)

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)

        content_length = int(self.headers['Content-Length'])
        if content_length > 1024 * 128:
            self.respond(400, json.dumps({'error': 'Request body too large'}).encode())
            return

        body = self.rfile.read(content_length)

        match parsed_path.path:
            case "/api/GetSealingKey":
                quote = json.loads(body)
                response = get_key(bytes.fromhex(quote['quote']), self.config.kp_address, self.config.kp_port)
                response_data = {
                    'encrypted_key': response.encrypted_key.hex(),
                    'provider_quote': response.provider_quote.hex()
                }
                response_bytes = json.dumps(response_data).encode()
            case "/api/Notify":
                info = json.loads(body)
                if info['event'] == 'instance.info':
                    info_path = os.path.join(self.config.vm_dir, 'shared', '.instance_info')
                    open(info_path, 'w').write(info['payload'])
                response_bytes = b'null'
            case _:
                self.respond(404, b'null')
                return

        self.respond(200, response_bytes)

    def respond(self, status: int, data: bytes):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)


def create_http_server(config: ServerConfig):
    def handler(*args):
        QuoteHandler(config, *args)

    server = HTTPServer(('localhost', 0), handler)
    chosen_port = server.server_port
    return server, chosen_port

