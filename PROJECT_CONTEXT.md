# Factora Project Context

This file is the portable project handoff for another AI tool or developer. Read it together with `AGENTS.md` (architecture and team rules), `PROGRESS.md` (team checklist), and the relevant directory `AGENTS.md` files before making changes.

## What this project is

Factora is a student and developer safety platform for checking suspicious recruitment messages, URLs, screenshots, and coding assessment repositories. It combines:

- **Analyzer (Agent 1):** sklearn/XGBoost classification plus P.R.I.M.E. rules, URL/domain checks, OCR helpers, institution checks, and GitHub repository inspection.
- **Correlator (Agent 2):** a trained random-forest model, TF-IDF similarity, historical incidents, and graph relationships.
- **Community Hub:** FastAPI routes backed by SQLite for incident reports, evidence uploads, community indicators, and reporting portal links.
- **Web UI:** React 18 JSX embedded in `frontend/index.html`, transformed in the browser by Babel Standalone and styled with Tailwind CDN. The FastAPI app serves the same file at `/` and `/ui`.
- **Browser extension:** Manifest V3 Chrome extension in `extension/`; it calls the Analyzer and Correlator APIs.
- **Telegram bot:** optional webhook integration in `backend/telegram_bot/router.py`; it sends private-chat text, image OCR, and text-based PDF content through the same Analyzer and Correlator, then replies in Telegram.

Shared request/response contracts live in `shared/schemas.py`. Keep those models stable unless the team agrees to a contract change.

## Important files

- `AGENTS.md` — architecture, roles, rules, and local server instructions.
- `PROGRESS.md` — team feature checklist; some old unchecked items may be stale, so confirm against code before relying on them.
- `backend/main.py` — unified FastAPI app, UI routes, and `/api/health`.
- `backend/main.py` — also provides `/extension/download`, a ZIP configured for the current public API host.
- `backend/agent1_analyzer/prime_scorer.py` — Analyzer orchestrator and trained model initialization.
- `backend/agent1_analyzer/train_real_model.py` — model class, inference wrapper, and separate training pipeline.
- `backend/agent1_analyzer/models/factora_agent1_model.joblib` — checked-in Analyzer model artifact.
- `backend/agent2_correlator/ai_correlator.py` — Correlator model and historical matching.
- `backend/agent2_correlator/models/correlator_rf_model.joblib` — checked-in Correlator model artifact.
- `backend/agent2_correlator/data/historical_incidents.json` — Correlator's historical catalog.
- `backend/community_hub/router.py` and `storage.py` — community API and SQLite operations.
- `backend/telegram_bot/router.py` — Telegram webhook, attachment handling, scan formatting, and public bot link endpoint.
- `frontend/index.html` — main user interface and API calls.
- `extension/manifest.json`, `background.js`, `content.js`, `popup.js` — extension entry points and scan flow.
- `requirements.txt` — unified backend/runtime dependencies used for deployment.

## Run locally

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/`. API documentation is at `/docs`; overall/model readiness is at `/api/health`. The frontend also has per-agent checks at `/api/analyzer/health` and `/api/correlator/health`.

The trained model artifacts are already checked in. **Do not run the training scripts just to start the app.** Training may download datasets and is a separate workflow. The runtime versions of scikit-learn and XGBoost are pinned in `requirements.txt` to match the checked-in serialized artifacts.

## Model behavior and health

- Analyzer model is loaded during app import; symbolic checks remain as a fallback if it cannot load.
- Correlator model is loaded on first health/correlation request and then cached as a singleton.
- `/api/health` reports each model's load status and an error string when initialization fails. `status: "degraded"` means an API is available but one or both learned models did not load.
- Gemini/Groq keys are optional: Correlator explanations use an offline explanation path if neither key is set. These keys do not enable the sklearn/XGBoost models.
- Current deployment requirements were missing the ML runtime packages. The root requirements now include the model inference dependencies; keep these installed when deploying from the repo root.

## Render deployment

Deploy one **Python Web Service** from the repository root; the FastAPI app serves both UI and API. Use:

- Root directory: repository root (leave blank if Render defaults to it)
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/api/health`
- Python version: `.python-version` selects Python 3.11

After deployment, open `https://<your-service>.onrender.com/`, then check `/api/health` and both per-agent health endpoints. If a model is unavailable, inspect its `ml_model_error` and Render deploy/runtime logs.

Render's free web service sleeps after 15 minutes idle and has an ephemeral filesystem. This means the first request after idling can be slow and uploaded evidence/local SQLite changes are not durable. Render's free service also has limited CPU/RAM; if logs show out-of-memory restarts or slow model inference, use a larger instance. Do not promise the free tier as durable production hosting.

### Optional Telegram bot

Create the bot with Telegram's `@BotFather`, then set these Render environment variables on the same web service (never commit or share the token):

- `TELEGRAM_BOT_TOKEN` — secret token from BotFather.
- `TELEGRAM_BOT_USERNAME` — public username without `@`; the UI uses it to show the `t.me` link.
- `TELEGRAM_WEBHOOK_SECRET` — a private random value using only letters, digits, `_`, or `-`.
- `TELEGRAM_WEBHOOK_URL` — `https://<your-service>.onrender.com/api/telegram/webhook`.

On service startup, Factora registers the HTTPS webhook with Telegram. `/api/telegram/health` reports whether required settings are present. Private chats support text, PNG/JPEG/WebP images, and text-based PDFs up to 20 MB. Image scans rely on the existing OCR runtime; image/PDF files with no readable text receive a request for clearer input instead of a fabricated verdict. PDFs must have selectable text. Bot handling uses the local models and does not send message contents to optional third-party LLM providers.

## Browser extension and deployed API

The source extension currently has local API host permissions for `localhost:8000` and `127.0.0.1:8000`. The website's `/extension/download` endpoint packages the required extension files and rewrites the API URL and exact host permission to match the site serving that download. Visitors must extract the ZIP, open `chrome://extensions`, enable Developer mode, and choose **Load unpacked** on the included `factora-extension` folder. The extension is not yet published in the Chrome Web Store, so installation is currently manual. Avoid broad backend host permissions.

## Current handoff status

- The Analyzer and Correlator artifacts exist in the repository. On the development machine during the Nov 2, 2026 handoff, both artifacts loaded; a sample Analyzer prediction returned `SCAM / MALICIOUS`, and Correlator loaded 25 historical incidents with 7 features.
- A previous test showed the extension rescan path, demo text, GitHub repo caution semantics, and correlated-evidence requirements were recently adjusted. Read the working tree and `PROGRESS.md` for the exact state; do not assume all changes have been committed.
- The dashboard no longer presents invented headline numbers as live totals; it gives first-time visitors a short scan introduction and shows model readiness. Dark-mode active states and shadows were toned down.
- Existing SQLite/uploads are user data. Preserve them while editing or deploying.

## Working rules for a future AI tool

1. Inspect `git status` and diffs before editing; keep existing user changes and untracked evidence intact.
2. Follow `AGENTS.md` and directory-specific instructions. Do not change `shared/schemas.py` casually.
3. Never treat demo/mock results as live model findings; label mock data clearly.
4. Report what was changed and what was actually verified. Don't claim deployment until a Render service has been created and checked.
