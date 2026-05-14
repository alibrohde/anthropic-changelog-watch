# Claude Catcher

OpenAI and Anthropic both ship constantly. Claude Catcher is how I stopped missing it.

Fork this repo. Hand it to Claude Code with one prompt. Twenty minutes later you get a single daily email any time either lab drops a new news post or engineering write-up. Silent when nothing ships.

No servers. No cost. Runs on GitHub Actions. 100-ish lines of Python.

## What you get

- An email in your inbox every time something new appears on:
  - [anthropic.com/news](https://www.anthropic.com/news)
  - [anthropic.com/engineering](https://www.anthropic.com/engineering)
  - [openai.com/news](https://openai.com/news) (via RSS)
- A quiet weekly heartbeat so you know the watcher is still alive when nothing ships.
- A silent baseline the first time a new source is added — you absorb the current backlog, not get it dumped in your inbox.
- No LLM calls in the loop. Dedup is a sha256 check against a committed `state.json` — deterministic, auditable, free.

## Setup (for vibe coders)

1. **Fork this repo** (button top-right on GitHub).
2. **Clone your fork locally** and `cd` into it.
3. **Open Claude Code in the repo directory.**
4. **Paste the prompt in [SETUP_PROMPT.md](SETUP_PROMPT.md)** into Claude. It will ask you the two or three questions it genuinely needs and handle the rest.

That's it. Claude will ask you whether you have personal Gmail or Google Workspace, then walk you through the two-or-three-minute credential dance for whichever you have. When the first run succeeds you'll get a "watcher is live" email.

## What the setup actually does

- Sets these GitHub Actions secrets in your fork: `GMAIL_USER`, `EMAIL_TO`, and either `GMAIL_APP_PASSWORD` (personal Gmail) or `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` + `GOOGLE_REFRESH_TOKEN` (Workspace).
- Triggers the GitHub Actions workflow (`.github/workflows/watch.yml`), which runs once a day on GitHub's infrastructure. Your laptop can be closed; the watcher doesn't care.
- On the first run it records the current state of every source as a baseline and sends one confirmation email. From then on you only hear from it when something actually changes.

## Sources

| Source | Kind | Parser |
|---|---|---|
| Anthropic news | HTML link index (`/news/<slug>`) | `link_index` |
| Anthropic engineering | HTML link index (`/engineering/<slug>`) | `link_index` |
| OpenAI news | RSS feed (`openai.com/news/rss.xml`) | `rss` |

Add more in [watch.py](watch.py) — append to `SOURCES`. Three kinds supported: `changelog_md` (raw markdown where `## heading` entries are items), `link_index` (HTML page where links follow a `/<prefix>/<slug>` pattern), and `rss` (RSS 2.0 feed with `<item>` blocks). Any newly-added source absorbs its current backlog silently the first time it's polled, so you don't get a flood.

## Email paths

The script picks its email backend by which secrets are set:

- **`GMAIL_APP_PASSWORD` set** → SMTP to `smtp.gmail.com:465` with that app password. Simplest; works with any Google account that has 2-Step Verification on. Gets blocked on some Workspace tenants.
- **`GOOGLE_REFRESH_TOKEN` set** → Gmail API via OAuth, refreshing an access token on every run. Works on Workspace tenants that block app passwords. Run [tools/get_refresh_token.py](tools/get_refresh_token.py) once to generate the refresh token from your own Google Cloud OAuth client.

If neither is set, the run fails with a clear error.

## Running locally

```bash
export GMAIL_USER="you@gmail.com"
export EMAIL_TO="you@gmail.com"
export GMAIL_APP_PASSWORD="abcd efgh ijkl mnop"  # or the OAuth triple
python3 watch.py
```

To verify each source's fetch + parser before relying on the daily run:

```bash
python3 watch.py --smoke-test
```

Prints the 5 most recent items per source to stdout. Sends no email, writes no state.

Or just use the workflow — go to your fork's **Actions** tab, pick "watch", click **Run workflow**.

## Why this exists

OpenAI and Anthropic each publish across multiple surfaces (news, engineering, an RSS feed buried under `/news/rss.xml`) and ship fast. Anyone building on top — vibe coders, agent hackers, founders shipping AI-native products — pays a tax to keep up manually. A cron + diff + email pipeline solves it, but "set up a cron + diff + email pipeline" isn't something most people want to do on a Tuesday night. So here's the pipeline, pre-built; hand it to Claude to wire into your accounts.

## License

MIT. See [LICENSE](LICENSE).
