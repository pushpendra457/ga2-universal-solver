# TDS GA2 Universal Solver — Render Deploy

Single-file FastAPI server. Deploy as a Render Web Service via GitHub.

## Render settings (if NOT using render.yaml Blueprint)
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn universal_ga2_render_server:app --host 0.0.0.0 --port $PORT --workers 1`
- **Environment:** Python 3.11.9
- **Health Check Path:** `/`

## Use after deploy
1. Open `https://YOUR-APP.onrender.com/` — copy the 1-liner.
2. On the GA2 exam page, F12 → Console → paste it.
3. Run the printed `curl .../termlog.sh | bash` in your terminal after `termlog login`.
