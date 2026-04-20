#!/usr/bin/env python3
"""One-off helper to get a Gmail-send OAuth refresh token.

Use this when you've created a Google Cloud OAuth client (desktop app)
and need the long-lived refresh token to put into GitHub Secrets.

Usage:
  1. Create an OAuth 2.0 client of type "Desktop app" in Google Cloud Console:
     https://console.cloud.google.com/apis/credentials
     Enable the Gmail API for the project while you're there.
  2. Download the client_secret JSON file.
  3. Run this script, passing the path to that file:
       python3 tools/get_refresh_token.py path/to/client_secret.json
  4. A browser window opens. Grant the "send email" permission.
  5. The script prints the refresh token to stdout (nothing else).

Pipe it straight into `gh secret set` so it never hits your clipboard:

  python3 tools/get_refresh_token.py client.json \\
    | gh secret set GOOGLE_REFRESH_TOKEN --repo you/claude-catcher

You'll also need to set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET as
secrets — both are in the same JSON file you passed in.
"""
import http.server
import json
import pathlib
import secrets as secrets_mod
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser

SCOPE = "https://www.googleapis.com/auth/gmail.send"
REDIRECT_HOST = "127.0.0.1"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    client = json.loads(pathlib.Path(sys.argv[1]).expanduser().read_text())
    block = client.get("installed") or client.get("web")
    if not block or "client_id" not in block or "client_secret" not in block:
        print("client secret JSON must contain 'installed' or 'web' with client_id and client_secret", file=sys.stderr)
        return 1
    client_id = block["client_id"]
    client_secret = block["client_secret"]

    state_token = secrets_mod.token_urlsafe(16)
    result: dict = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):
            q = urllib.parse.urlparse(self.path).query
            result.update(dict(urllib.parse.parse_qsl(q)))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = "<h2>Done.</h2><p>You can close this tab.</p>"
            if "error" in result:
                body = f"<h2>Error</h2><pre>{result['error']}</pre>"
            self.wfile.write(body.encode())
            done.set()

    server = http.server.HTTPServer((REDIRECT_HOST, 0), Handler)
    port = server.server_address[1]
    redirect_uri = f"http://{REDIRECT_HOST}:{port}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "state": state_token,
        "include_granted_scopes": "true",
    })

    print(f"Opening browser. If it does not open, visit:\n{auth_url}\n", file=sys.stderr)
    webbrowser.open(auth_url)

    if not done.wait(timeout=300):
        print("timed out waiting for OAuth callback", file=sys.stderr)
        return 1
    server.shutdown()

    if result.get("state") != state_token:
        print("state mismatch, aborting", file=sys.stderr)
        return 1
    if "error" in result:
        print(f"OAuth error: {result['error']}", file=sys.stderr)
        return 1
    code = result.get("code")
    if not code:
        print("no auth code returned", file=sys.stderr)
        return 1

    token_req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=urllib.parse.urlencode({
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(token_req, timeout=30) as r:
        tokens = json.loads(r.read())

    rt = tokens.get("refresh_token")
    if not rt:
        print(f"no refresh_token in response: {list(tokens.keys())}", file=sys.stderr)
        return 1

    print(rt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
