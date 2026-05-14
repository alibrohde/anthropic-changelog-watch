#!/usr/bin/env python3
"""Watch OpenAI + Anthropic changelogs and email a digest when new items appear.

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
import html
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
        "name": "Anthropic engineering",
        "url": "https://www.anthropic.com/engineering",
        "kind": "link_index",
        "id_prefix": "engineering",
        "link_prefix": "/engineering/",
        "site": "https://www.anthropic.com",
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
        "name": "OpenAI news",
        "url": "https://openai.com/news/rss.xml",
        "kind": "rss",
        "id_prefix": "openai-news",
    },
]

# Email output groups posts by source in this order. Anthropic first (most
# builder-critical day-to-day), then OpenAI.
SOURCE_ORDER = [
    "Anthropic engineering",
    "Anthropic news",
    "OpenAI news",
]

# Slug substrings that signal a geo/region-specific announcement.
# Matched against lowercased slug; any hit → drop the item.
# Add patterns here as noise crops up.
GEO_SKIP_PATTERNS = [
    "sydney", "australia", "australian", "canberra",
    "tokyo", "japan", "japanese",
    "seoul", "korea", "korean",
    "bengaluru", "bangalore", "india", "indian",
    "london", "uk-", "-uk-", "britain", "british",
    "paris", "france", "french",
    "berlin", "munich", "germany", "german",
    "dublin", "ireland", "irish",
    "singapore",
    "asia-pacific", "apac", "emea", "apj", "latam",
    "european-union", "brussels", "eu-ai-act",
    "mou-",  # memorandum of understanding slugs follow pattern "*-mou-*" or "mou-*"
    "-mou",
]


def _is_geo_irrelevant(slug: str) -> bool:
    s = slug.lower()
    return any(p in s for p in GEO_SKIP_PATTERNS)


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


def _rss_field(item_xml: str, tag: str) -> str:
    """Read a single tag's text out of an RSS <item> blob. Unwraps CDATA."""
    m = re.search(
        rf"<{tag}\b[^>]*>(?:<!\[CDATA\[(.*?)\]\]>|(.*?))</{tag}>",
        item_xml,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return ""
    raw = m.group(1) if m.group(1) is not None else (m.group(2) or "")
    return html.unescape(raw.strip())


def parse_rss(text: str, src):
    items = re.findall(r"<item\b[^>]*>(.*?)</item>", text, flags=re.DOTALL | re.IGNORECASE)
    entries = []
    skipped = []
    for item in items:
        link = _rss_field(item, "link")
        if not link:
            continue
        slug = urllib.parse.urlparse(link).path
        if _is_geo_irrelevant(slug):
            skipped.append(slug)
            continue
        entries.append({
            "id": f"{src['id_prefix']}::{slug}",
            "title": _rss_field(item, "title"),
            "summary": _rss_field(item, "description"),
            "body": "",
            "url": link,
        })
    if skipped:
        log(f"filtered {len(skipped)} geo-irrelevant {src['id_prefix']} slugs: "
            + ", ".join(s.rsplit('/', 1)[-1] for s in skipped[:6])
            + ("..." if len(skipped) > 6 else ""))
    return entries


def parse_link_index(html: str, src):
    pattern = r'href="(' + re.escape(src["link_prefix"]) + r'[^"?#]+)"'
    slugs = sorted(set(re.findall(pattern, html)))
    entries = []
    skipped = []
    for slug in slugs:
        if _is_geo_irrelevant(slug):
            skipped.append(slug)
            continue
        url = f"{src['site']}{slug}"
        entries.append({
            "id": f"{src['id_prefix']}::{slug}",
            "title": "",  # real title lifted from og:title at fetch time
            "summary": "",  # og:description one-liner
            "body": "",
            "url": url,
        })
    if skipped:
        log(f"filtered {len(skipped)} geo-irrelevant {src['id_prefix']} slugs: "
            + ", ".join(s.rsplit('/', 1)[-1] for s in skipped[:6])
            + ("..." if len(skipped) > 6 else ""))
    return entries


def _strip_anthropic_suffix(t: str) -> str:
    # Anthropic appends "| Anthropic" or "\ Anthropic" to og:title on some posts.
    return re.sub(r"\s*[\\|]\s*Anthropic\s*$", "", t).strip()


def _meta_content(page_html: str, name: str) -> str:
    """Extract content= from a <meta> tag by property= or name=, any attr order."""
    n = re.escape(name)
    patterns = [
        rf'<meta[^>]*\bproperty=["\']{n}["\'][^>]*\bcontent=["\']([^"\']+)["\']',
        rf'<meta[^>]*\bname=["\']{n}["\'][^>]*\bcontent=["\']([^"\']+)["\']',
        rf'<meta[^>]*\bcontent=["\']([^"\']+)["\'][^>]*\bproperty=["\']{n}["\']',
        rf'<meta[^>]*\bcontent=["\']([^"\']+)["\'][^>]*\bname=["\']{n}["\']',
    ]
    for p in patterns:
        m = re.search(p, page_html, re.IGNORECASE | re.DOTALL)
        if m:
            return html.unescape(m.group(1).strip())
    return ""


def _title_tag(page_html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", page_html, re.IGNORECASE)
    if not m:
        return ""
    return _strip_anthropic_suffix(html.unescape(m.group(1).strip()))


def _main_text(page_html: str) -> str:
    """Grab readable text from <main>...</main>; fall back to the whole body."""
    m = re.search(r"<main\b[^>]*>(.*?)</main>", page_html, flags=re.DOTALL | re.IGNORECASE)
    body = m.group(1) if m else page_html
    body = re.sub(r"<script[^>]*>.*?</script>", " ", body, flags=re.DOTALL)
    body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.DOTALL)
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body).strip()
    return html.unescape(body)


# og:description sometimes falls back to the site-wide boilerplate. When it
# does, lift the real first sentence out of the article body instead.
_GENERIC_DESC_MARKERS = (
    "Anthropic is an AI safety and research company",
)


def _is_useful_desc(desc: str, title: str) -> bool:
    if not desc:
        return False
    d = desc.strip()
    if d == title.strip():
        return False
    return not any(m in d for m in _GENERIC_DESC_MARKERS)


def _first_sentence_from_body(body: str, title: str) -> str:
    """Skip past breadcrumb/title/date and return the first real sentence(s)."""
    rest = body
    # Anthropic posts render "Mon D, YYYY" or "Month D, YYYY" right before the
    # article text. Slice after the date if present.
    m = re.search(
        r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}\s+",
        body,
    )
    if m:
        rest = body[m.end():]
    elif title and title in body[:400]:
        rest = body[body.index(title) + len(title):].lstrip()
    # Take first sentence(s) up to ~280 chars.
    out = ""
    for s in re.split(r"(?<=[.!?])\s+", rest):
        if not s:
            continue
        if out and len(out) + len(s) > 280:
            break
        out = (out + " " + s).strip() if out else s
        if len(out) > 140:
            break
    return out


def fetch_article_meta(url: str) -> dict:
    """Return {title, summary, body} using og tags when available,
    falling back to the article's first sentence when og:description is
    the site-wide boilerplate or a duplicate of the title."""
    try:
        page_html = http_get(url)
    except Exception as e:
        return {"title": "", "summary": f"(failed to fetch: {e})", "body": ""}
    title = _meta_content(page_html, "og:title") or _title_tag(page_html)
    title = _strip_anthropic_suffix(title)
    og_desc = _meta_content(page_html, "og:description") or _meta_content(page_html, "description")
    body = _main_text(page_html)[:2000]
    summary = og_desc if _is_useful_desc(og_desc, title) else _first_sentence_from_body(body, title)
    return {"title": title, "summary": summary, "body": body}


def load_state():
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"seen": {}}


def save_state(state) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


def entry_hash(entry) -> str:
    payload = entry["body"] if entry["body"] else entry["title"]
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _format_item(e) -> str:
    title = (e.get("title") or "(untitled)").strip()
    line = f"- **[{title}]({e['url']})**"
    summary = (e.get("summary") or "").strip()
    if summary:
        return f"{line}  \n  {summary}"
    body = (e.get("body") or "").replace("\n", " ").strip()
    if body:
        # Changelog-style entries (no og:description): keep a short body snippet.
        return f"{line}  \n  {body[:280]}"
    return line


def format_entries(entries) -> str:
    by_source = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    ordered = [s for s in SOURCE_ORDER if s in by_source] \
              + [s for s in by_source if s not in SOURCE_ORDER]
    parts = []
    for source in ordered:
        parts.append(f"## {source}\n")
        for e in by_source[source]:
            parts.append(_format_item(e))
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
    baselined = set(state.setdefault("baselined_prefixes", []))
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
        elif src["kind"] == "rss":
            entries = parse_rss(raw, src)
        else:
            continue
        # First time we've ever polled this source: silently absorb whatever's
        # currently published so the watcher doesn't dump a backlog into your
        # inbox. From the next run on, only new items surface.
        if src["id_prefix"] not in baselined:
            for e in entries:
                if src["kind"] == "changelog_md":
                    seen[e["id"]] = entry_hash(e)
                else:
                    seen[e["id"]] = "1"
            baselined.add(src["id_prefix"])
            state["baselined_prefixes"] = sorted(baselined)
            log(f"baselined new source '{src['id_prefix']}': absorbed {len(entries)} entries silently")
            continue
        for e in entries:
            key = e["id"]
            if src["kind"] in ("link_index", "rss"):
                # Presence-only dedup: the URL is the identity.
                if key in seen:
                    continue
                if src["kind"] == "link_index":
                    # Fetch article meta (og:title, og:description) only when the
                    # slug is genuinely new. RSS items already carry title/description.
                    meta = fetch_article_meta(e["url"])
                    e["title"] = meta["title"] or e["url"].rsplit("/", 1)[-1].replace("-", " ")
                    e["summary"] = meta["summary"]
                    e["body"] = meta["body"]
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
        f"Nothing new across OpenAI + Anthropic's changelogs in the last {HEARTBEAT_DAYS} days.\n\n"
        f"Last actual change detected: {last_activity}\n\n"
        "Sources watched:\n"
        + "\n".join(f"- {s['name']}: {s['url']}" for s in SOURCES)
        + "\n\n(This is a weekly heartbeat so you know the watcher is alive.)"
    )
    send_email("OAI + Anthropic changelog: nothing new", body)
    state["last_email_ts"] = now_iso()
    save_state(state)
    log("sent heartbeat email")
    return True


def smoke_test() -> int:
    """Verify each source's fetch + parse path. Prints 5 most recent items per source.

    Sends no email and writes no state. Run with: python3 watch.py --smoke-test
    """
    print("Smoke test - 5 most recent items per source. No email, no state changes.\n")
    ok = True
    for src in SOURCES:
        print(f"=== {src['name']} ===")
        print(f"  url: {src['url']}")
        try:
            raw = http_get(src["url"])
        except Exception as e:
            print(f"  FETCH FAILED: {e}\n")
            ok = False
            continue
        print(f"  fetched OK ({len(raw):,} bytes)")
        if src["kind"] == "changelog_md":
            entries = parse_changelog_md(raw, src)
        elif src["kind"] == "link_index":
            entries = parse_link_index(raw, src)
        elif src["kind"] == "rss":
            entries = parse_rss(raw, src)
        else:
            entries = []
        print(f"  parsed {len(entries)} entries")
        for e in entries[:5]:
            title = e.get("title") or "(title fetched at digest time)"
            print(f"    - {title[:90]}")
            print(f"      {e['url']}")
        if not entries:
            print("    (no entries parsed - parser may be broken)")
            ok = False
        print()
    return 0 if ok else 1


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
            "Watcher is live. From now on you'll get an email when new entries appear across OpenAI + Anthropic's changelogs. "
            f"If nothing changes for {HEARTBEAT_DAYS} days you'll get a one-line heartbeat so you know it's still alive.\n\n"
            "Sources watched:\n"
            + "\n".join(f"- {s['name']}: {s['url']}" for s in SOURCES)
        )
        send_email("OAI + Anthropic changelog watcher is live", body)
        log("sent first-run baseline email")
        return 0

    digest = format_entries(new_entries)
    subject_count = f"{len(new_entries)} new update" + ("s" if len(new_entries) != 1 else "")
    subject = f"OAI + Anthropic changelog: {subject_count}"
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
        if "--smoke-test" in sys.argv:
            sys.exit(smoke_test())
        sys.exit(main())
    except Exception as e:
        log(f"FATAL: {type(e).__name__}: {e}")
        raise
