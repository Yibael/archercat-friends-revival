#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import socketserver
import sys
import time


def utc_now():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def summarize(data, limit=4096):
    clipped = data[:limit]
    ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in clipped)
    return {
        "length": len(data),
        "captured": len(clipped),
        "ascii": ascii_text,
        "hex": " ".join(f"{b:02x}" for b in clipped),
        "truncated": len(data) > len(clipped),
    }


class JsonlLogger:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, kind, **payload):
        entry = {"t": utc_now(), "kind": kind, **payload}
        line = json.dumps(entry, ensure_ascii=False)
        print(line, flush=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def looks_http(data):
    prefixes = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
    return data.startswith(prefixes) or b"HTTP/" in data[:512]


def split_http_headers(data):
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        return None, None
    return data[: marker + 4], data[marker + 4 :]


def parse_http_headers(header_bytes):
    lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    method = parts[0] if len(parts) > 0 else ""
    path = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else ""
    headers = {}

    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    return {
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
    }


def header_value(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def read_until_headers(request, initial, max_probe_bytes):
    received = bytearray(initial)
    while b"\r\n\r\n" not in received and len(received) < max_probe_bytes:
        chunk = request.recv(65536)
        if not chunk:
            break
        received.extend(chunk)
    return received


def read_exact_body(request, initial_body, content_length, max_probe_bytes):
    body = bytearray(initial_body)
    while len(body) < content_length and len(body) < max_probe_bytes:
        chunk = request.recv(min(65536, content_length - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return body


def decode_json_body(body):
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def build_http_response(http_request, request_body):
    path = http_request.get("path", "")
    body_json = decode_json_body(request_body)

    if path.startswith("/GetKakaoIdsForFacebookIds/") or path.startswith("/LoginUser/"):
        # Encrypted game endpoints expect a raw base64 response body. The Frida
        # hook replaces the decrypted payload at the crypto boundary.
        body = b"AAAAAAAAAAAAAAAAAAAAAA=="
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n"
            + b"\r\n"
            + body
        )

    response = {
        "server": "archercat-local-mock",
        "ok": True,
        "path": path,
        "time": int(time.time()),
    }

    if path == "/GetServerStatus":
        response.update(
            {
                "status": "ok",
                "msg": "",
                "serverStatus": "ok",
                "maintenance": False,
                "notice": "",
            }
        )

    if path.startswith("/ExchangeKey/"):
        response["publicKey"] = ""

    if body_json is not None:
        response["echoKeys"] = sorted(body_json.keys()) if isinstance(body_json, dict) else []

    body = json.dumps(response, separators=(",", ":")).encode("utf-8")
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )


class MockHandler(socketserver.BaseRequestHandler):
    def handle(self):
        logger = self.server.logger
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        logger.write("connection_open", peer=peer)
        self.request.settimeout(self.server.read_timeout)

        received = bytearray()
        mode = "unknown"
        try:
            while True:
                try:
                    chunk = self.request.recv(65536)
                except TimeoutError:
                    break
                except socketserver.socket.timeout:
                    break

                if not chunk:
                    break

                received.extend(chunk)
                logger.write("received", peer=peer, data=summarize(chunk))

                if mode == "unknown" and looks_http(received):
                    mode = "http"
                    received = read_until_headers(self.request, received, self.server.max_probe_bytes)
                    header_bytes, initial_body = split_http_headers(received)
                    if header_bytes is None:
                        break

                    http_request = parse_http_headers(header_bytes)
                    headers = http_request["headers"]
                    content_length = int(header_value(headers, "Content-Length") or "0")
                    expect = header_value(headers, "Expect") or ""

                    if expect.lower() == "100-continue":
                        interim = b"HTTP/1.1 100 Continue\r\n\r\n"
                        self.request.sendall(interim)
                        logger.write("sent_continue", peer=peer, data=summarize(interim))

                    body = read_exact_body(
                        self.request,
                        initial_body,
                        content_length,
                        self.server.max_probe_bytes,
                    )
                    full_request = header_bytes + body
                    logger.write(
                        "http_request",
                        peer=peer,
                        request=http_request,
                        body=summarize(body),
                        json=decode_json_body(body),
                    )

                    response = build_http_response(http_request, body)
                    self.request.sendall(response)
                    logger.write("sent", peer=peer, mode=mode, data=summarize(response))
                    received = full_request
                    break

                if len(received) >= self.server.max_probe_bytes:
                    break

            if mode != "http":
                logger.write("no_response", peer=peer, mode=mode, totalReceived=len(received))
        except Exception as error:
            logger.write("connection_error", peer=peer, error=repr(error))
        finally:
            logger.write("connection_close", peer=peer, totalReceived=len(received))


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args():
    parser = argparse.ArgumentParser(description="ArcherCat local probe mock server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3001)
    parser.add_argument("--log", required=True)
    parser.add_argument("--read-timeout", type=float, default=2.0)
    parser.add_argument("--max-probe-bytes", type=int, default=262144)
    return parser.parse_args()


def main():
    args = parse_args()
    logger = JsonlLogger(args.log)

    with ThreadedServer((args.host, args.port), MockHandler) as server:
        server.logger = logger
        server.read_timeout = args.read_timeout
        server.max_probe_bytes = args.max_probe_bytes
        logger.write("server_start", host=args.host, port=args.port, log=args.log)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            logger.write("server_stop", reason="KeyboardInterrupt")
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
