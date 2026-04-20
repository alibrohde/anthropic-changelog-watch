# anthropic-changelog-watch

Watches Anthropic's changelogs and emails the raw entries when something new appears.

## What it watches

- Claude Code `CHANGELOG.md` (raw from GitHub)
- Anthropic Python SDK `CHANGELOG.md` (raw from GitHub)
- `anthropic.com/news`
- `anthropic.com/engineering`

Detection is a sha256 diff against `state.json`. No LLM calls.

## How it runs

GitHub Actions cron, every 2 hours (`.github/workflows/watch.yml`). `state.json` lives in the repo and is committed back by the `github-actions[bot]` when entries change.

- First run: records state as baseline, sends one "watcher is live" email.
- Runs with new entries: emails a digest of the new items.
- Runs with no new entries AND 7+ days since the last email: sends a heartbeat so you know it's still alive. Otherwise silent.

## Sources

| Source | Kind | Parser |
|---|---|---|
| Claude Code | GitHub raw CHANGELOG.md | `changelog_md` |
| Anthropic Python SDK | GitHub raw CHANGELOG.md | `changelog_md` |
| Anthropic news | HTML link index (`/news/<slug>`) | `link_index` |
| Anthropic engineering | HTML link index (`/engineering/<slug>`) | `link_index` |

## Secrets

Set in GitHub repo settings (Settings → Secrets and variables → Actions):

- `GMAIL_USER` — the Gmail address that sends and receives the emails.
- `GMAIL_APP_PASSWORD` — 16-char app password from [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).

## Manual run

Locally (needs `GMAIL_USER` and `GMAIL_APP_PASSWORD` in env):

```bash
python3 watch.py
```

Or trigger the workflow from the Actions tab in GitHub ("Run workflow").

## Adding a source

Append to the `SOURCES` list in `watch.py`. Supported kinds:
- `changelog_md` — raw markdown CHANGELOG.md where `## <version>` headings are entries.
- `link_index` — HTML page where article links follow a `/<prefix>/<slug>` pattern. Set `link_prefix` and `site`.

Each source needs a unique `id_prefix` (used to namespace state keys).
