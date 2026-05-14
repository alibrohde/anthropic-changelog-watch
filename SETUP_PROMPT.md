# Setup prompt for Claude Code

Copy everything between the fences below, paste it into a new Claude Code session in your forked repo, and let Claude drive the setup.

```
You are setting up Claude Catcher (claude-catcher) for me. Repo cloned locally, I'm the owner on GitHub. Goal: get a GitHub Actions cron running once a day that emails me when OpenAI or Anthropic ships a new news post or engineering write-up.

Please do these steps, asking me only when you genuinely need input:

1. Confirm the repo is mine by running `gh repo view --json owner,name` and showing me the owner. If it's not my fork, stop and tell me.

2. Ask me: "Personal Gmail or Google Workspace?"
   - Personal Gmail → we use the easy path (app password).
   - Workspace → we use OAuth with my own Google Cloud project.

3a. If PERSONAL:
    - Walk me through generating an app password at https://myaccount.google.com/apppasswords (2-Step Verification must be on first).
    - Once I paste the 16-char password to you, set these GitHub secrets via `gh secret set`:
      GMAIL_USER            = my Gmail address
      GMAIL_APP_PASSWORD    = the 16-char password
      EMAIL_TO              = where the digest lands (default: same as GMAIL_USER)

3b. If WORKSPACE:
    - Walk me through creating a Google Cloud project, enabling the Gmail API, and creating an OAuth 2.0 client of type "Desktop app" at https://console.cloud.google.com/apis/credentials. I'll download the client_secret JSON file.
    - Run: `python3 tools/get_refresh_token.py <path-to-client-secret.json> | gh secret set GOOGLE_REFRESH_TOKEN`. A browser opens; I grant "send email" permission.
    - Set these GitHub secrets:
      GMAIL_USER            = my Workspace address
      GOOGLE_CLIENT_ID      = from the client_secret JSON
      GOOGLE_CLIENT_SECRET  = from the client_secret JSON
      (GOOGLE_REFRESH_TOKEN was set by the helper script above)
      EMAIL_TO              = where the digest lands

4. Commit the starter `state.json` I already have in the repo (it's the baseline — skip if already committed).

5. Trigger a manual run with `gh workflow run watch.yml` and watch the logs with `gh run watch`. Confirm the run succeeds.

6. Tell me to watch my inbox for a "watcher is live" email on the first run. From then on, I only get email when OpenAI or Anthropic ships something new, or a weekly heartbeat if things are quiet.

Show me each secret's name (but never its value) after you set it, so I know the list is complete. Don't print any secret value to the terminal — pipe straight into `gh secret set`.
```
