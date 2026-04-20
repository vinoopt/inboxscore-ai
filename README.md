# InboxScore.ai

[![CI](https://github.com/vinoopt/inboxscore-ai/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vinoopt/inboxscore-ai/actions/workflows/ci.yml)

Deliverability scoring SaaS — authentication checks, Google Postmaster + Microsoft SNDS sync, Hetrix IP monitoring, PDF reports.

## Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI (Python 3.11) |
| Scheduling | APScheduler (in-process) |
| Database | Supabase / Postgres |
| Observability | Sentry + structured JSON logs + heartbeat watchdog |
| Hosting | Render (srv-d6hufv7kijhs73fnlf8g, auto-deploy off) |

## Deploy pipeline

```
push to main  →  GitHub Actions CI  →  Render API deploy
                    │                      │
                    ├ pytest               └ only runs if tests pass
                    └ ruff (syntax + undefined names)
```

Render auto-deploy is **disabled** — deploys are triggered by CI via the Render API after tests pass. See `.github/workflows/ci.yml`.

## Local development

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt

# copy secrets from your password manager into a .env file
uvicorn app:app --reload --port 8000

pytest              # run tests
ruff check .        # run linter
```

## Health endpoints

| Path | Purpose |
|---|---|
| `/health` | Liveness (always 200 if the process is up) |
| `/api/monitoring/heartbeat-status` | Watchdog view — are the schedulers still ticking? |
