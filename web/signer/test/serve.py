"""Serves a built signer bundle the way its host must: usage `serve.py <dist> <port> <platform.json>`."""

import http.server
import json
import pathlib
import re
import sys

ASSET = re.compile(r"^[a-z_]+-[0-9a-f]{16}\.(js|wasm|css|woff2)$")
# A serialized https origin, as alpha-core accepts in signer.embed_ancestors.
ORIGIN = re.compile(r"^https://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$")


def embed_ancestors(platform):
    """frame-ancestors for /sign/embed (PRD-03 S5, draft): the platform document's
    signer.embed_ancestors, or 'none'. A real host reads them from the document it verified;
    this one trusts the test file it was given, but still refuses anything but exact origins."""
    signer = json.loads(platform.read_text()).get("document", {}).get("signer") or {}
    origins = signer.get("embed_ancestors") or []
    if not all(isinstance(o, str) and ORIGIN.match(o) for o in origins):
        return "'none'"
    return " ".join(origins) or "'none'"
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
    def read_headers(name, fill=""):
        text = (dist / name).read_text().replace("@EMBED_ANCESTORS@", fill)
        return [tuple(line.split(": ", 1)) for line in text.splitlines() if line]

    headers = read_headers("headers")
    embed_headers = read_headers("headers-embed", embed_ancestors(platform))

    class Handler(http.server.BaseHTTPRequestHandler):
        def resolve(self):
            path = self.path.split("?", 1)[0]
            if path in ("/sign/claim", "/sign/approve", "/sign/embed"):
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
            embed = self.path.split("?", 1)[0] == "/sign/embed"
            for name, value in embed_headers if embed else headers:
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
