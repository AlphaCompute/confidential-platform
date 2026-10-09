"""Prints the DOM of a signer page once it has settled: usage `render.py <chrome> <profile> <url>`.

Chrome's `--dump-dom` fires on virtual time, which runs past wasm compiling on another thread, so
it sometimes prints the page before the page has run. This drives Chrome over its debugging pipe
instead and waits until `#main` leaves its loading text or Chrome reports a resource blocked by its
integrity attribute, after which nothing more will run. A block is printed as the first line,
`INTEGRITY_BLOCKED`; a page that does neither before the deadline is a failure. A page that ran
then waits for its three Public Sans faces, printed as `FONTS_LOADED` once all are loaded, and
every Content Security Policy violation the document reported is printed as a line
`CSP_VIOLATION <directive> <blocked URI>`, all before the DOM.
"""

import json
import os
import select
import subprocess
import sys
import time

LOADING = "Loading…"
DEADLINE = 30.0
FONT_FACES = 3

RECORD_VIOLATIONS = """
window.__violations = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__violations.push(`${e.effectiveDirective} ${e.blockedURI}`);
});
"""
FONTS_LOADED = """
[...document.fonts].filter(
  (f) => f.family.replace(/"/g, "") === "Public Sans" && f.status === "loaded"
).length
"""


class Browser:
    def __init__(self, chrome, profile):
        to_chrome_r, self.to_chrome = os.pipe()
        self.from_chrome, from_chrome_w = os.pipe()

        # Chrome reads commands on fd 3 and writes replies on fd 4; a dup2 onto the same number
        # keeps Python's close-on-exec flag, so both are made inheritable explicitly.
        def pipes():
            os.dup2(to_chrome_r, 3)
            os.dup2(from_chrome_w, 4)
            os.set_inheritable(3, True)
            os.set_inheritable(4, True)

        self.process = subprocess.Popen(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={profile}",
                "--remote-debugging-pipe",
                "about:blank",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=pipes,
            close_fds=False,
        )
        os.close(to_chrome_r)
        os.close(from_chrome_w)
        self.buffer = b""
        self.next_id = 0
        self.blocked = False

    def read(self, timeout):
        while b"\0" not in self.buffer:
            ready, _, _ = select.select([self.from_chrome], [], [], timeout)
            if not ready:
                raise TimeoutError("Chrome did not answer")
            chunk = os.read(self.from_chrome, 65536)
            if not chunk:
                raise EOFError("Chrome closed its pipe")
            self.buffer += chunk
        message, self.buffer = self.buffer.split(b"\0", 1)
        return json.loads(message)

    def call(self, method, params=None, session=None):
        self.next_id += 1
        message = {"id": self.next_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        os.write(self.to_chrome, json.dumps(message).encode() + b"\0")
        while True:
            reply = self.read(DEADLINE)
            if reply.get("id") == self.next_id:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error']}")
                return reply.get("result", {})
            if reply.get("method") == "Log.entryAdded":
                if "integrity" in reply["params"]["entry"].get("text", ""):
                    self.blocked = True

    def close(self):
        self.process.kill()
        self.process.wait()


def main():
    chrome, profile, url = sys.argv[1:4]
    browser = Browser(chrome, profile)
    try:
        target = browser.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        session = browser.call(
            "Target.attachToTarget", {"targetId": target, "flatten": True}
        )["sessionId"]
        browser.call("Log.enable", session=session)
        browser.call("Page.enable", session=session)
        browser.call(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": RECORD_VIOLATIONS},
            session=session,
        )
        browser.call("Page.navigate", {"url": url}, session=session)

        def evaluate(expression):
            result = browser.call(
                "Runtime.evaluate",
                {"expression": expression, "returnByValue": True},
                session=session,
            )
            return result.get("result", {}).get("value")

        end = time.monotonic() + DEADLINE
        while not browser.blocked:
            text = evaluate('document.getElementById("main")?.textContent')
            if text is not None and text != LOADING:
                break
            if time.monotonic() >= end:
                sys.exit("render.py: the page neither ran nor was blocked by integrity")
            time.sleep(0.1)
        if browser.blocked:
            print("INTEGRITY_BLOCKED")
        else:
            while evaluate(FONTS_LOADED) != FONT_FACES and time.monotonic() < end:
                time.sleep(0.1)
            if evaluate(FONTS_LOADED) == FONT_FACES:
                print("FONTS_LOADED")
        for violation in evaluate("window.__violations") or []:
            print(f"CSP_VIOLATION {violation}")
        print(evaluate("document.documentElement.outerHTML"))
    finally:
        browser.close()


if __name__ == "__main__":
    main()
