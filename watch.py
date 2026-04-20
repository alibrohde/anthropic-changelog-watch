#!/usr/bin/env python3
"""Watch Anthropic changelogs and email a digest when new items appear.

Detection is deterministic (sha256 of entry body vs state.json).

Email is sent via Gmail. Two auth paths, pick one:

  Easy (personal Gmail): SMTP with an app password
    GMAIL_USER           = your@gmail.com
    GMAIL_APP_PASSWORD   = 16 chars from myaccount.google.com/apppasswords

  Workspace or when app passwords are blocked: Gmail API via OAuth
    GMAIL_USER           = you@yourcompany.com
    GOOGLE_CLIENT_ID     = OAuth client id (desktop app)
    GOOGLE_CLIENT_SECRET = OAuth client secret
    GOOGLE_REFRESH_TOKEN = refresh token with gmail.send scope
                           (run tools/get_refresh_token.py to obtain)

Required either way:
  EMAIL_TO               = where to send the digest
"""
import base64
import hashlib
import json
import os
import re
import smtplib
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

HEARTBEAT_DAYS = 7

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "state.json"
LOG_PATH = ROOT / "watch.log"
USER_AGENT = "claude-catcher/0.1 (+https://github.com/alibrohde/claude-catcher)"

SOURCES = [
    {
        "name": "Claude Code",
        "url": "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md",
        "kind": "changelog_md",
        "id_prefix": "claude-code",
    },
    {
        "name": "Anthropic Python SDK",
        "url": "https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/CHANGELOG.md",
        "kind": "changelog_md",
        "id_prefix": "sdk-python",
    },
    {
        "name": "Anthropic news",
        "url": "https://www.anthropic.com/news",
        "kind": "link_index",
        "id_prefix": "news",
        "link_prefix": "/news/",
        "site": "https://www.anthropic.com",
    },
    {
        "name": "Anthropic engineering",
        "url": "https://www.anthropic.com/engineering",
        "kind": "link_index",
        "id_prefix": "engineering",
        "link_prefix": "/engineering/",
        "site": "https://www.anthropic.com",
    },
]


def log(msg: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    line = f"{ts} {msg}"
    with LOG_PATH.open("a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_changelog_md(text: str, src):
    entries = []
    sections = re.split(r"^## ", text, flags=re.MULTILINE)
    for section in sections[1:]:
        parts = section.split("\n", 1)
        title = parts[0].strip()
        body = parts[1].strip() if len(parts) > 1 else ""
        body = body[:3000]
        entries.append({
            "id": f"{src['id_prefix']}::{title}",
            "title": title,
            "body": body,
            "url": src["url"],
        })
    return entries


def parse_link_index(html: str, src):
    pattern = r'href="(' + re.escape(src["link_prefix"]) + r'[^"?#]+)"'
    slugs = sorted(set(re.findall(pattern, html)))
    entries = []
    for slug in slugs:
        url = f"{src['site']}{slug}"
        title = slug.rsplit("/", 1)[-1].replace("-", " ")
        entries.append({
            "id": f"{src['id_prefix']}::{slug}",
            "title": title,
            "body": "",
            "url": url,
        })
    return entries


def fetch_article_body(url: str) -> str:
    try:
        html = http_get(url)
    except Exception as e:
        return f"(failed to fetch: {e})"
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:4000]


def load_state():
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"seen": {}}


def save_state(state) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


def entry_hash(entry) -> str:
    payload = entry["body"] if entry["body"] else entry["title"]
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def format_entries(entries) -> str:
    by_source = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    parts = []
    for source, items in by_source.items():
        parts.append(f"## {source}\n")
        for e in items:
            body_preview = e["body"][:600].replace("\n", " ").strip()
            parts.append(f"- **[{e['title']}]({e['url']})**  \n  {body_preview}")
        parts.append("")
    return "\n".join(parts)


def markdown_to_html(md: str) -> str:
    pandoc = "/opt/homebrew/bin/pandoc"
    if not Path(pandoc).exists():
        pandoc = "pandoc"
    try:
        result = subprocess.run(
            [pandoc, "--from=markdown", "--to=html"],
            input=md, capture_output=True, text=True, check=True,
        )
        body = result.stdout
    except Exception:
        body = "<pre>" + md.replace("<", "&lt;").replace(">", "&gt;") + "</pre>"
    return (
        '<div style="font-family: -apple-system, system-ui, sans-serif; '
        'max-width: 680px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #1a1a1a;">'
        + body + "</div>"
    )


def _build_message(subject: str, markdown_body: str) -> EmailMessage:
    user = os.environ["GMAIL_USER"]
    to = os.environ["EMAIL_TO"]
    html = markdown_to_html(markdown_body)
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(markdown_body)
    msg.add_alternative(html, subtype="html")
    return msg


def _send_via_smtp(msg: EmailMessage) -> None:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as s:
        s.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        s.send_message(msg)


def _gmail_access_token() -> str:
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=urllib.parse.urlencode({
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "refresh_token": os.environ["GOOGLE_REFRESH_TOKEN"],
            "grant_type": "refresh_token",
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())["access_token"]


def _send_via_oauth(msg: EmailMessage) -> None:
    raw = base64.urlsafe_b64encode(bytes(msg)).decode("ascii").rstrip("=")
    token = _gmail_access_token()
    req = urllib.request.Request(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        data=json.dumps({"raw": raw}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def send_email(subject: str, markdown_body: str) -> None:
    msg = _build_message(subject, markdown_body)
    if os.environ.get("GMAIL_APP_PASSWORD"):
        _send_via_smtp(msg)
    elif os.environ.get("GOOGLE_REFRESH_TOKEN"):
        _send_via_oauth(msg)
    else:
        raise RuntimeError(
            "No email auth configured. Set GMAIL_APP_PASSWORD (easy path) "
            "or GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET + GOOGLE_REFRESH_TOKEN."
        )


def collect_new(state):
    seen = state.setdefault("seen", {})
    new_entries = []
    for src in SOURCES:
        try:
            raw = http_get(src["url"])
        except Exception as e:
            log(f"fetch failed for {src['name']}: {e}")
            continue
        if src["kind"] == "changelog_md":
            entries = parse_changelog_md(raw, src)
        elif src["kind"] == "link_index":
            entries = parse_link_index(raw, src)
        else:
            continue
        for e in entries:
            key = e["id"]
            if src["kind"] == "link_index":
                # Presence-only dedup: the URL is the identity, body is fetched
                # only when the slug is genuinely new. Skips editing-detection
                # on existing articles in exchange for stable dedup and 0 extra
                # HTTP on steady-state runs.
                if key in seen:
                    continue
                e["body"] = fetch_article_body(e["url"])
                h = "1"  # sentinel — any non-empty value is fine
            else:
                # changelog_md: body-hash dedup catches edits to an existing
                # version entry (e.g. a typo fix in a release note).
                h = entry_hash(e)
                if seen.get(key) == h:
                    continue
            e["source"] = src["name"]
            e["_key"] = key
            e["_hash"] = h
            new_entries.append(e)
    return new_entries


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def days_since(iso: str) -> float:
    try:
        t = datetime.fromisoformat(iso)
    except Exception:
        return 999.0
    return (datetime.now(timezone.utc) - t).total_seconds() / 86400


def maybe_send_heartbeat(state) -> bool:
    last_email = state.get("last_email_ts")
    if last_email and days_since(last_email) < HEARTBEAT_DAYS:
        return False
    last_activity = state.get("last_activity_ts") or "(never since watcher started)"
    body = (
        f"Nothing new across Anthropic's changelogs in the last {HEARTBEAT_DAYS} days.\n\n"
        f"Last actual change detected: {last_activity}\n\n"
        "Sources watched:\n"
        + "\n".join(f"- {s['name']}: {s['url']}" for s in SOURCES)
        + "\n\n(This is a weekly heartbeat so you know the watcher is alive.)"
    )
    send_email("Anthropic changelog: nothing new", body)
    state["last_email_ts"] = now_iso()
    save_state(state)
    log("sent heartbeat email")
    return True


def main() -> int:
    state = load_state()
    first_run = not state.get("seen")
    new_entries = collect_new(state)

    if not new_entries:
        log("no new entries")
        if not first_run:
            maybe_send_heartbeat(state)
        return 0

    log(f"found {len(new_entries)} new entries (first_run={first_run})")

    if first_run:
        for e in new_entries:
            state["seen"][e["_key"]] = e["_hash"]
        state["last_email_ts"] = now_iso()
        state["last_activity_ts"] = now_iso()
        save_state(state)
        body = (
            "Watcher is live. From now on you'll get an email when new entries appear in Anthropic's changelogs. "
            f"If nothing changes for {HEARTBEAT_DAYS} days you'll get a one-line heartbeat so you know it's still alive.\n\n"
            "Sources watched:\n"
            + "\n".join(f"- {s['name']}: {s['url']}" for s in SOURCES)
        )
        send_email("Anthropic changelog watcher is live", body)
        log("sent first-run baseline email")
        return 0

    digest = format_entries(new_entries)
    subject_count = f"{len(new_entries)} new update" + ("s" if len(new_entries) != 1 else "")
    subject = f"Anthropic changelog: {subject_count}"
    send_email(subject, digest)
    log(f"sent digest email ({subject_count})")

    for e in new_entries:
        state["seen"][e["_key"]] = e["_hash"]
    state["last_email_ts"] = now_iso()
    state["last_activity_ts"] = now_iso()
    save_state(state)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"FATAL: {type(e).__name__}: {e}")
        raise
