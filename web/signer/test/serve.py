"""Serves a built signer bundle the way its host must: usage `serve.py <dist> <port> <platform.json>`."""

import http.server
import pathlib
import re
import sys

ASSET = re.compile(r"^[a-z_]+-[0-9a-f]{16}\.(js|wasm|css|woff2)$")
TYPES = {
    "js": "text/javascript",
    "wasm": "application/wasm",
    "css": "text/css",
    "woff2": "font/woff2",
}


def main():
    dist = pathlib.Path(sys.argv[1])
    port = int(sys.argv[2])
    platform = pathlib.Path(sys.argv[3])
    headers = [
        tuple(line.split(": ", 1))
        for line in (dist / "headers").read_text().splitlines()
        if line
    ]

    class Handler(http.server.BaseHTTPRequestHandler):
        def resolve(self):
            path = self.path.split("?", 1)[0]
            if path in ("/sign/claim", "/sign/approve"):
                return dist / "index.html", "text/html; charset=utf-8"
            if path == "/sign/platform.json":
                return platform, "application/json"
            name = path.removeprefix("/sign/")
            if path.startswith("/sign/") and ASSET.match(name) and (dist / name).is_file():
                return dist / name, TYPES[name.rsplit(".", 1)[1]]
            return None

        def answer(self, with_body):
            found = self.resolve()
            if found is None:
                status, body, kind = 404, b"not found\n", "text/plain"
            else:
                file, kind = found
                status, body = 200, file.read_bytes()
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if with_body:
                self.wfile.write(body)

        def do_GET(self):
            self.answer(True)

        def do_HEAD(self):
            self.answer(False)

        def log_message(self, *args):
            pass

    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
