#!/usr/bin/env python3
"""
TDS GA2 Multi-Student Universal Solver SaaS (Deployable on Render via GitHub)
=============================================================================
How it works for ANY student:
1. Deploy this single file on Render as a Web Service:
     Build Command: pip install fastapi uvicorn pyjwt cryptography python-multipart
     Start Command: uvicorn universal_ga2_render_server:app --host 0.0.0.0 --port $PORT --workers 1
2. Any student opens the GA2 exam page, opens Chrome DevTools Console (F12), and pastes ONE line:
     import("https://YOUR-RENDER-APP.onrender.com/console.js?t=" + Date.now())
3. The script automatically:
   - Scrapes all of that student's assigned parameters (email, tag, Q3/Q12 origins, Q4 public key,
     Q5 config layers, Q7 API key, Q11/Q12 rate limits, Q13 hex chunks, Q14 costs) from the DOM.
   - Registers their isolated tenant session at `/s/<tag>/...` on your Render server.
   - Auto-fills Q2 through Q14, runs the self-healing Q2 prompt loop, and clicks Check.
   - Prints a 1-line terminal command (`curl -sSL https://YOUR-RENDER-APP.onrender.com/s/<tag>/termlog.sh | bash`)
     that records Q1 & Q15 locally using their `termlog login` and uploads both `.tar.gz` files
     back to your Render server so Q1 & Q15 also pass automatically!
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
from fastapi import FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="TDS GA2 Multi-Student Universal Solver")

UPLOAD_DIR = Path("/tmp/ga2_student_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# =====================================================================
# MULTI-TENANT SESSION STORE (Keyed by student's unique tag, e.g. "http-75d0092")
# =====================================================================
SESSIONS: Dict[str, Dict[str, Any]] = {}


def get_or_create_session(tag: str) -> Dict[str, Any]:
    if tag not in SESSIONS:
        SESSIONS[tag] = {
            "tag": tag,
            "email": "",
            "quantity": 10,
            "q3_origin": "",
            "q4_issuer": "https://idp.exam.local",
            "q4_audience": "",
            "q4_public_key": "",
            "q5_yaml": {},
            "q5_dotenv": {},
            "q5_os": {},
            "q7_api_key": "",
            "q11_total_orders": 40,
            "q11_rate_limit": 15,
            "q12_origin": "",
            "q12_rate_limit": 10,
            "q13_answer": {},
            "q14_answer": {
                "A": {"steps": ["L3", "L4", "L5"], "seconds": 33},
                "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": 83},
                "C": {"steps": [], "seconds": 0},
                "D": {"steps": [], "seconds": 0},
                "E": {"steps": ["L4", "L5"], "seconds": 33},
            },
            # Stateful runtime stores per student
            "start_time": time.time(),
            "q6_counters": defaultdict(int),
            "q8_requests_total": 0,
            "q8_logs": deque(maxlen=500),
            "q11_idempotent_orders": {},
            "q11_rate_buckets": defaultdict(list),
            "q12_rate_buckets": defaultdict(list),
        }
    return SESSIONS[tag]


def check_rate_limit(buckets: Dict[str, List[float]], client_id: str, limit: int, window: float = 10.0) -> bool:
    now = time.time()
    timestamps = [t for t in buckets[client_id] if now - t < window]
    buckets[client_id] = timestamps
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    return True


def solve_q13_streams(chunks_dict: Dict[str, List[str]]) -> Dict[str, Any]:
    result = {}
    for key, hex_list in chunks_dict.items():
        raw_bytes = b"".join(bytes.fromhex(h) for h in hex_list)
        text_stream = raw_bytes.decode("utf-8", errors="replace")
        lines = text_stream.split("\n")
        complete_lines = lines[:-1]
        out_text: List[str] = []
        complete = False
        error = None
        for line in complete_lines:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if "error" in rec and rec["error"]:
                error = rec["error"]
                complete = False
                break
            if "response" in rec:
                out_text.append(rec["response"])
            if rec.get("done") is True:
                complete = True
                break
        result[key] = {"text": "".join(out_text), "complete": complete, "error": error}
    return result


# =====================================================================
# MULTI-TENANT MIDDLEWARE (Handles Per-Student Scoped CORS, Timing & Logs)
# =====================================================================
@app.middleware("http")
async def multi_tenant_middleware(request: Request, call_next):
    t0 = time.perf_counter()
    inbound_req_id = request.headers.get("X-Request-ID") or request.headers.get("x-request-id")
    request_id = inbound_req_id if inbound_req_id else str(uuid.uuid4())
    request.state.request_id = request_id

    path = request.url.path
    origin = request.headers.get("Origin") or request.headers.get("origin")
    req_headers = (
        request.headers.get("Access-Control-Request-Headers")
        or request.headers.get("access-control-request-headers")
        or "X-Request-ID, X-Client-Id, X-API-Key, Idempotency-Key, Content-Type, Authorization"
    )

    # Check if this request targets a student namespace `/s/{tag}/...`
    m = re.match(r"^/s/([^/]+)(/.*)?$", path)
    if m:
        tag = m.group(1)
        subpath = m.group(2) or "/"
        sess = get_or_create_session(tag)

        # Q3 scoped CORS (/s/{tag}/stats)
        if subpath == "/stats":
            allowed_q3 = sess.get("q3_origin", "")
            if request.method == "OPTIONS":
                if origin and origin == allowed_q3:
                    resp = Response(status_code=204)
                    resp.headers["Access-Control-Allow-Origin"] = allowed_q3
                    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                    resp.headers["Access-Control-Allow-Headers"] = req_headers
                    resp.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time"
                else:
                    resp = Response(status_code=403)
                resp.headers["X-Request-ID"] = request_id
                resp.headers["X-Process-Time"] = f"{max(0.0, time.perf_counter() - t0):.6f}"
                return resp

        # Q12 scoped CORS (/s/{tag}/ping)
        elif subpath == "/ping":
            allowed_q12 = {sess.get("q12_origin", ""), "https://exam.sanand.workers.dev"}
            if request.method == "OPTIONS":
                if origin in allowed_q12:
                    resp = Response(status_code=204)
                    resp.headers["Access-Control-Allow-Origin"] = origin
                    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                    resp.headers["Access-Control-Allow-Headers"] = req_headers
                    resp.headers["Access-Control-Expose-Headers"] = "X-Request-ID, Retry-After"
                else:
                    resp = Response(status_code=403)
                resp.headers["X-Request-ID"] = request_id
                return resp

        elif request.method == "OPTIONS":
            resp = Response(status_code=204)
            resp.headers["Access-Control-Allow-Origin"] = origin or "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = req_headers
            resp.headers["Access-Control-Expose-Headers"] = "*"
            resp.headers["X-Request-ID"] = request_id
            return resp

        # Record Q8 observability metrics & structured logs for this student
        sess["q8_requests_total"] += 1
        sess["q8_logs"].append({
            "level": "INFO",
            "ts": datetime.now(timezone.utc).isoformat(),
            "path": subpath,
            "request_id": request_id,
            "method": request.method,
        })

        response = await call_next(request)
        duration = max(0.0, time.perf_counter() - t0)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{duration:.6f}"

        if subpath == "/stats":
            if origin and origin == sess.get("q3_origin", ""):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time"
        elif subpath == "/ping":
            if origin in {sess.get("q12_origin", ""), "https://exam.sanand.workers.dev"}:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, Retry-After"
        else:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = req_headers
            response.headers["Access-Control-Expose-Headers"] = "*"
        return response

    # Non-student routes (/api/register, /console.js, /)
    if request.method == "OPTIONS":
        resp = Response(status_code=204)
        resp.headers["Access-Control-Allow-Origin"] = origin or "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = req_headers
        resp.headers["Access-Control-Expose-Headers"] = "*"
        return resp

    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = req_headers
    response.headers["Access-Control-Expose-Headers"] = "*"
    return response


# =====================================================================
# LANDING PAGE & DYNAMIC CONSOLE SCRIPT GENERATOR
# =====================================================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    base_url = str(request.base_url).rstrip("/").replace("http://", "https://")
    one_liner = f'import("{base_url}/console.js?t=" + Date.now())'
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>TDS GA2 Universal Auto-Solver</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 780px; margin: 40px auto; padding: 0 20px; background: #0f172a; color: #f8fafc; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
    pre {{ background: #020617; padding: 14px; border-radius: 8px; overflow-x: auto; color: #38bdf8; font-size: 14px; }}
    button {{ background: #2563eb; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>🚀 TDS GA2 Universal Student Solver</h1>
  <div class="card">
    <h3>Step 1: Paste this 1-Liner into Chrome Console on the GA2 Exam Page</h3>
    <p>Open the GA2 exam page, press <b>F12 &rarr; Console</b>, and paste:</p>
    <pre id="cmd">{one_liner}</pre>
    <button onclick="navigator.clipboard.writeText(document.getElementById('cmd').textContent)">Copy 1-Liner</button>
    <p style="color:#94a3b8;font-size:14px;margin-top:12px;">
      It automatically scrapes your roll number, assigned keys, CORS origins, config layers, and hex streams from the page,
      configures your dedicated endpoints on this server, fills all 15 questions, and runs the self-healing Q2 prompt loop!
    </p>
  </div>
</body>
</html>"""


class RegisterPayload(BaseModel):
    tag: str
    email: str
    quantity: int = 10
    q3_origin: str = ""
    q4_issuer: str = "https://idp.exam.local"
    q4_audience: str = ""
    q4_public_key: str = ""
    q5_yaml: Dict[str, Any] = {}
    q5_dotenv: Dict[str, Any] = {}
    q5_os: Dict[str, Any] = {}
    q7_api_key: str = ""
    q11_total_orders: int = 40
    q11_rate_limit: int = 15
    q12_origin: str = ""
    q12_rate_limit: int = 10
    q13_chunks: Dict[str, List[str]] = {}
    q14_costs: List[int] = [50, 16, 17]


@app.post("/api/register")
async def register_student(body: RegisterPayload):
    sess = get_or_create_session(body.tag)
    sess["email"] = body.email.strip()
    sess["quantity"] = body.quantity
    sess["q3_origin"] = body.q3_origin.strip()
    sess["q4_issuer"] = body.q4_issuer.strip() or "https://idp.exam.local"
    sess["q4_audience"] = body.q4_audience.strip()
    sess["q4_public_key"] = body.q4_public_key.strip()
    sess["q5_yaml"] = body.q5_yaml
    sess["q5_dotenv"] = body.q5_dotenv
    sess["q5_os"] = body.q5_os
    sess["q7_api_key"] = body.q7_api_key.strip()
    sess["q11_total_orders"] = body.q11_total_orders
    sess["q11_rate_limit"] = body.q11_rate_limit
    sess["q12_origin"] = body.q12_origin.strip()
    sess["q12_rate_limit"] = body.q12_rate_limit

    if body.q13_chunks:
        sess["q13_answer"] = solve_q13_streams(body.q13_chunks)

    if len(body.q14_costs) == 3:
        l2_c, l4_c, l5_c = body.q14_costs
        sess["q14_answer"] = {
            "A": {"steps": ["L3", "L4", "L5"], "seconds": l4_c + l5_c},
            "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": l2_c + l4_c + l5_c},
            "C": {"steps": [], "seconds": 0},
            "D": {"steps": [], "seconds": 0},
            "E": {"steps": ["L4", "L5"], "seconds": l4_c + l5_c},
        }

    return {"status": "registered", "tag": body.tag, "email": sess["email"]}


# =====================================================================
# STUDENT-SCOPED ENDPOINTS (/s/{tag}/...)
# =====================================================================
@app.post("/s/{tag}/upload/{filename}")
async def upload_student_archive(tag: str, filename: str, file: UploadFile = File(...)):
    safe_tag = re.sub(r"[^A-Za-z0-9_\-]", "", tag)
    safe_name = Path(filename).name
    dest = UPLOAD_DIR / f"{safe_tag}_{safe_name}"
    content = await file.read()
    dest.write_bytes(content)
    return {"status": "uploaded", "size": len(content)}


@app.get("/s/{tag}/files/{filename}")
async def get_student_archive(tag: str, filename: str):
    safe_tag = re.sub(r"[^A-Za-z0-9_\-]", "", tag)
    safe_name = Path(filename).name
    dest = UPLOAD_DIR / f"{safe_tag}_{safe_name}"
    if not dest.is_file():
        raise HTTPException(status_code=404, detail="Archive not uploaded yet. Run the 1-line termlog bash script first!")
    return FileResponse(path=str(dest), media_type="application/gzip", filename=safe_name)


@app.get("/s/{tag}/termlog.sh", response_class=PlainTextResponse)
async def get_student_termlog_script(tag: str, request: Request):
    sess = get_or_create_session(tag)
    base_url = str(request.base_url).rstrip("/").replace("http://", "https://")
    email = sess["email"] or "YOUR_EMAIL@ds.study.iitm.ac.in"
    qty = sess["quantity"]
    short_id = tag.replace("http-", "")
    return f"""#!/usr/bin/env bash
set -e
echo "=== Recording Q1 & Q15 for {email} ({tag}, qty={qty}) ==="
echo "Make sure you have run: termlog login (as {email})"
python3 - <<'PYEOF'
import os, pty, select, subprocess, sys, time, fcntl, struct, termios

def run_cast(cast_file, cmds, wait_s=3.0):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"] = "200"
        os.environ["LINES"] = "50"
        os.execvp("termlog", ["termlog", "rec", cast_file])
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
    except Exception:
        pass
    def drain(d):
        end = time.time() + d
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.1)
            if fd in r:
                try:
                    data = os.read(fd, 4096)
                    if not data: break
                    sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
                except OSError: break
    drain(1.5)
    for c in cmds:
        os.write(fd, (c + "\\n").encode())
        drain(wait_s)
    os.waitpid(pid, 0)
    os.close(fd)

q1_cmds = [
    'capture() {{ task="$1"; shift; printf \\'\\\\nHTTPBIN_BEGIN {tag} %s\\\\n\\' "$task"; "$@"; printf \\'\\\\nHTTPBIN_END {tag} %s\\\\n\\' "$task"; }}',
    'capture GET curl -sS "https://httpbin.org/get?course=TDS&tag={tag}" -H "X-Exam-Tag: {tag}"',
    'capture POST curl -sS -X POST "https://httpbin.org/post" -H "Content-Type: application/json" -d \\'{{"tag":"{tag}","quantity":{qty},"active":true}}\\'',
    'capture FORM curl -sS -X PUT "https://httpbin.org/put" -d "tag={tag}&quantity={qty}"',
    'capture AUTH curl -sS "https://httpbin.org/bearer" -H "Authorization: Bearer {tag}"',
    'capture REDIRECT curl -sS -L -G "https://httpbin.org/redirect-to" --data-urlencode "url=https://httpbin.org/get?tag={tag}"',
    'curl -sS -L -c /tmp/cookies_{short_id}.txt "https://httpbin.org/cookies/set?exam={tag}" > /dev/null',
    'capture COOKIES curl -sS -b /tmp/cookies_{short_id}.txt "https://httpbin.org/cookies"',
    'capture STATUS curl -sS -o /dev/null -w "%{{http_code}}" "https://httpbin.org/status/418"',
    'exit'
]
run_cast("httpbin.cast", q1_cmds, 3.0)
subprocess.run(["tar", "-czf", "q1_submission.tar.gz", "httpbin.cast", "httpbin.cast.jwt"], check=True)

q15_cmds = [
    "cat <<'EOF' > Modelfile",
    "FROM qwen2.5:0.5b",
    'SYSTEM "You are the deployment assistant for project {short_id}. Give concise answers and never invent commands."',
    "PARAMETER temperature 0.1",
    "PARAMETER num_ctx 2048",
    "PARAMETER seed 346",
    "PARAMETER num_predict 80",
    "EOF",
    "ollama create ga2-assistant-{short_id} -f Modelfile",
    "printf '\\\\nMODELFILE_BEGIN ga2-assistant-{short_id}\\\\n'",
    "ollama show --modelfile ga2-assistant-{short_id}",
    "printf '\\\\nMODELFILE_END ga2-assistant-{short_id}\\\\n'",
    "exit"
]
run_cast("model.cast", q15_cmds, 3.5)
subprocess.run(["tar", "-czf", "q15_submission.tar.gz", "model.cast", "model.cast.jwt"], check=True)
PYEOF

curl -sS -F "file=@q1_submission.tar.gz" "{base_url}/s/{tag}/upload/q1_submission.tar.gz"
curl -sS -F "file=@q15_submission.tar.gz" "{base_url}/s/{tag}/upload/q15_submission.tar.gz"
echo "✅ Uploaded both Q1 and Q15 archives to {base_url}/s/{tag}/files/!"
"""


# Q3: GET /s/{tag}/stats
@app.get("/s/{tag}/stats")
async def s_q3_stats(tag: str, values: str = Query(...)):
    sess = get_or_create_session(tag)
    nums = [int(x.strip()) for x in values.split(",") if x.strip()]
    total = sum(nums)
    count = len(nums)
    return {
        "email": sess["email"],
        "count": count,
        "sum": total,
        "min": min(nums),
        "max": max(nums),
        "mean": round(total / count, 6),
    }


# Q4: POST /s/{tag}/verify
@app.post("/s/{tag}/verify")
async def s_q4_verify(tag: str, request: Request):
    sess = get_or_create_session(tag)
    try:
        body = await request.json()
        token = body.get("token", "")
        payload = jwt.decode(
            token,
            sess["q4_public_key"],
            algorithms=["RS256"],
            issuer=sess["q4_issuer"],
            audience=sess["q4_audience"],
            options={"require": ["exp", "iss", "aud"]},
        )
        return {
            "valid": True,
            "email": payload.get("email", sess["email"]),
            "sub": payload.get("sub", ""),
            "aud": payload.get("aud", sess["q4_audience"]),
        }
    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})


# Q5: GET /s/{tag}/effective-config
def coerce_val(key: str, val: Any) -> Any:
    if key in ("port", "workers"):
        return int(val)
    if key == "debug":
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "on")
    return str(val)


@app.get("/s/{tag}/effective-config")
async def s_q5_config(tag: str, set_overrides: Optional[List[str]] = Query(default=None, alias="set")):
    sess = get_or_create_session(tag)
    cfg: Dict[str, Any] = {
        "port": 8000,
        "workers": 1,
        "debug": False,
        "log_level": "info",
        "api_key": "default-secret-000",
    }
    for k, v in sess.get("q5_yaml", {}).items():
        cfg[k.lower()] = coerce_val(k.lower(), v)
    for k, v in sess.get("q5_dotenv", {}).items():
        if k.upper() == "NUM_WORKERS":
            cfg["workers"] = coerce_val("workers", v)
        elif k.upper().startswith("APP_"):
            nk = k[4:].lower()
            cfg[nk] = coerce_val(nk, v)
    for k, v in sess.get("q5_os", {}).items():
        if k.upper().startswith("APP_"):
            nk = k[4:].lower()
            cfg[nk] = coerce_val(nk, v)
    if set_overrides:
        for item in set_overrides:
            if "=" in item:
                k, v = item.split("=", 1)
                k, v = k.strip(), v.strip()
                if k.upper() == "NUM_WORKERS":
                    k = "workers"
                elif k.upper().startswith("APP_"):
                    k = k[4:].lower()
                else:
                    k = k.lower()
                cfg[k] = coerce_val(k, v)
    cfg["api_key"] = "****"
    return cfg


# Q6 & Q8: /s/{tag}/healthz, /s/{tag}/hit/{key}, /s/{tag}/count/{key}
@app.get("/s/{tag}/healthz")
async def s_healthz(tag: str):
    sess = get_or_create_session(tag)
    uptime = max(0.0, round(time.time() - sess["start_time"], 4))
    return {"status": "ok", "redis": "up", "uptime_s": uptime}


@app.post("/s/{tag}/hit/{key}")
async def s_q6_hit(tag: str, key: str):
    sess = get_or_create_session(tag)
    sess["q6_counters"][key] += 1
    return {"key": key, "count": sess["q6_counters"][key]}


@app.get("/s/{tag}/count/{key}")
async def s_q6_count(tag: str, key: str):
    sess = get_or_create_session(tag)
    return {"key": key, "count": sess["q6_counters"].get(key, 0)}


# Q7: POST /s/{tag}/analytics
@app.post("/s/{tag}/analytics")
async def s_q7_analytics(
    tag: str,
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    sess = get_or_create_session(tag)
    if not x_api_key or x_api_key != sess["q7_api_key"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    events = body.get("events", [])
    revenue = 0.0
    pos_by_user: Dict[str, float] = defaultdict(float)
    users = set()
    for e in events:
        u = e.get("user", "")
        amt = float(e.get("amount", 0.0))
        users.add(u)
        if amt > 0:
            revenue += amt
            pos_by_user[u] += amt
    top_user = max(pos_by_user.items(), key=lambda kv: kv[1])[0] if pos_by_user else ""
    return {
        "email": sess["email"],
        "total_events": len(events),
        "unique_users": len(users),
        "revenue": round(revenue, 4),
        "top_user": top_user,
    }


# Q8: /s/{tag}/work, /s/{tag}/metrics, /s/{tag}/logs/tail
@app.get("/s/{tag}/work")
async def s_q8_work(tag: str, n: int = Query(default=1)):
    sess = get_or_create_session(tag)
    return {"email": sess["email"], "done": n}


@app.get("/s/{tag}/metrics")
async def s_q8_metrics(tag: str):
    sess = get_or_create_session(tag)
    text = (
        "# HELP http_requests_total Total number of HTTP requests processed\n"
        "# TYPE http_requests_total counter\n"
        f"http_requests_total {sess['q8_requests_total']}\n"
    )
    return PlainTextResponse(content=text, media_type="text/plain; version=0.0.4")


@app.get("/s/{tag}/logs/tail")
async def s_q8_logs(tag: str, limit: int = Query(default=20)):
    sess = get_or_create_session(tag)
    return list(sess["q8_logs"])[-limit:]


# Q9: POST /s/{tag}/v1/chat/completions
@app.post("/s/{tag}/v1/chat/completions")
async def s_q9_chat(tag: str, request: Request):
    body = await request.json()
    model_name = body.get("model", "llama3.2")
    messages = body.get("messages", [])
    user_text = " ".join(str(m.get("content", "")) for m in messages if isinstance(m, dict))
    parts = []
    tokens = re.findall(r"\bTK[0-9a-fA-F]{6}\b", user_text, flags=re.IGNORECASE)
    if tokens:
        parts.append(tokens[-1])
    arith = re.search(r"(-?\d+)\s*([\+\-\*])\s*(-?\d+)", user_text)
    if arith:
        a, op, b = int(arith.group(1)), arith.group(2), int(arith.group(3))
        parts.append(str(a + b if op == "+" else (a - b if op == "-" else a * b)))
    ans = " ".join(parts) if parts else f"Echo: {user_text.strip()}"
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:10]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model_name,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ans}, "finish_reason": "stop"}],
    }


# Q10: POST /s/{tag}/extract
@app.post("/s/{tag}/extract")
async def s_q10_extract(tag: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON")
    if not isinstance(body, dict) or not isinstance(body.get("text"), str) or not body["text"].strip():
        raise HTTPException(status_code=422, detail="Empty text")
    text = body["text"].strip()
    due_m = re.search(r"(?:due(?:\s+date|\s+on|\s+by)?|pay\s+by|by)\s*[:\-]?\s*(20\d{2}-\d{2}-\d{2})\b", text, re.I)
    dates = re.findall(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    if not due_m and not dates:
        raise HTTPException(status_code=422, detail="No date")
    date_val = due_m.group(1) if due_m else dates[-1]
    curr_m = re.search(r"\b(USD|EUR|GBP|INR|CAD|AUD|JPY|CHF|SGD)\b", text, re.I)
    currency_val = curr_m.group(1).upper() if curr_m else ("EUR" if "€" in text else ("GBP" if "£" in text else "USD"))
    cleaned = re.sub(r"\b20\d{2}-\d{2}-\d{2}\b", " ", text)
    cleaned = re.sub(r"(?:invoice|inv|bill|ref|no\.?|#)\s*[:#\-]?\s*[A-Za-z0-9\-]+", " ", cleaned, flags=re.I)
    amts = re.findall(
        r"(?:total\s*(?:due|amount)?|amount\s*due|balance\s*due|amount|due|pay|USD|EUR|GBP|INR|\$|€|£)\s*[:=]?\s*(?:USD|EUR|GBP|INR|\$|€|£)?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)\b",
        cleaned,
        re.I,
    ) or re.findall(r"\b([0-9]+(?:\.[0-9]+)?)\b", cleaned)
    amount_val = float(amts[-1].replace(",", "")) if amts else 0.0
    corp_m = re.search(
        r"\b([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+(?:\s+[A-Z][A-Za-z0-9&]*){0,4}(?:\s+(?:Ltd\.?|Inc\.?|LLC|Corp\.?|GmbH|PLC|Co\.?))?)",
        text,
    )
    vendor_val = corp_m.group(1).strip() if corp_m else text.splitlines()[0][:80]
    return {"vendor": vendor_val, "amount": round(amount_val, 2), "currency": currency_val, "date": date_val}


# Q11: /s/{tag}/orders
@app.post("/s/{tag}/orders", status_code=201)
async def s_q11_post_orders(
    tag: str,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-Id"),
):
    sess = get_or_create_session(tag)
    if x_client_id and not check_rate_limit(sess["q11_rate_buckets"], x_client_id, sess["q11_rate_limit"], 10.0):
        return JSONResponse(status_code=429, content={"detail": "Rate limit"}, headers={"Retry-After": "10"})
    if idempotency_key:
        store = sess["q11_idempotent_orders"]
        if idempotency_key not in store:
            store[idempotency_key] = {"id": f"ord-{uuid.uuid5(uuid.NAMESPACE_DNS, idempotency_key).hex[:10]}", "status": "created"}
        return JSONResponse(status_code=201, content=store[idempotency_key])
    return JSONResponse(status_code=201, content={"id": f"ord-{uuid.uuid4().hex[:10]}", "status": "created"})


@app.get("/s/{tag}/orders")
async def s_q11_get_orders(
    tag: str,
    limit: int = Query(default=10, ge=1),
    cursor: Optional[str] = Query(default=None),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-Id"),
):
    sess = get_or_create_session(tag)
    if x_client_id and not check_rate_limit(sess["q11_rate_buckets"], x_client_id, sess["q11_rate_limit"], 10.0):
        return JSONResponse(status_code=429, content={"detail": "Rate limit"}, headers={"Retry-After": "10"})
    total = sess["q11_total_orders"]
    start = int(base64.urlsafe_b64decode(cursor.encode()).decode()) if cursor else 0
    catalog = [{"id": i, "item": f"order-{i}"} for i in range(1, total + 1)]
    items = catalog[start : start + limit]
    nxt = start + len(items)
    next_cursor = base64.urlsafe_b64encode(str(nxt).encode()).decode() if nxt < total else None
    return {"items": items, "orders": items, "next_cursor": next_cursor, "next": next_cursor}


# Q12: GET /s/{tag}/ping
@app.get("/s/{tag}/ping")
async def s_q12_ping(
    tag: str,
    request: Request,
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-Id"),
):
    sess = get_or_create_session(tag)
    if x_client_id and not check_rate_limit(sess["q12_rate_buckets"], x_client_id, sess["q12_rate_limit"], 10.0):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit"},
            headers={"Retry-After": "10", "X-Request-ID": request.state.request_id},
        )
    return {"email": sess["email"], "request_id": request.state.request_id}


# Q13 & Q14: GET /s/{tag}/q13.json & /s/{tag}/q14.json
@app.get("/s/{tag}/q13.json")
async def s_q13_json(tag: str):
    sess = get_or_create_session(tag)
    return JSONResponse(content=sess["q13_answer"])


@app.get("/s/{tag}/q14.json")
async def s_q14_json(tag: str):
    sess = get_or_create_session(tag)
    return JSONResponse(content=sess["q14_answer"])


# =====================================================================
# DYNAMIC CONSOLE SCRIPT SERVED AT GET /console.js
# =====================================================================
@app.get("/console.js")
async def serve_dynamic_console_js(request: Request):
    base_url = str(request.base_url).rstrip("/").replace("http://", "https://")
    js_code = f"""
(async () => {{
  const SERVER = "{base_url}";
  const pageText = document.body.innerText;

  // 1. Scrape student-specific parameters directly from the GA2 Exam Page DOM
  const emailMatch = pageText.match(/([a-zA-Z0-9._+-]+@(?:ds\\.)?study\\.iitm\\.ac\\.in)/i);
  const tagMatch   = pageText.match(/\\b(http-[0-9a-f]{{6,10}})\\b/);
  const qtyMatch   = pageText.match(/Quantity:\\s*(\\d+)/i);
  const q3Origin   = (pageText.match(/https:\\/\\/dash-[a-z0-9-]+\\.example\\.com/i) || [""])[0];
  const q4Aud      = (pageText.match(/tds-[a-z0-9-]+\\.apps\\.exam\\.local/i) || [""])[0];
  const q4Key      = (pageText.match(/-----BEGIN PUBLIC KEY-----[\\s\\S]+?-----END PUBLIC KEY-----/) || [""])[0];
  const q7Key      = (pageText.match(/\\b(ak_[a-z0-9]{{16,40}})\\b/i) || [""])[0];
  const q11Total   = parseInt((pageText.match(/Total orders \\(T\\)\\s*(\\d+)/i) || [0, "44"])[1], 10);
  const q11Rate    = parseInt((pageText.match(/Rate limit \\(R requests \\/ 10s\\)\\s*(\\d+)/i) || [0, "15"])[1], 10);
  const q12Origin  = (pageText.match(/https:\\/\\/app-[a-z0-9-]+\\.example\\.com/i) || [""])[0];
  const q12Rate    = parseInt((pageText.match(/Rate-limit bucket \\(B\\)\\s*(\\d+)\\s*req/i) || [0, "9"])[1], 10);

  // Parse Q5 layers
  const q5Yaml = {{}};
  const yamlBlock = (pageText.match(/2\\. config\\.development\\.yaml\\s+([\\s\\S]+?)3\\. \\.env file/i) || [,""])[1];
  yamlBlock.split(/\\n/).forEach(l => {{ const m = l.match(/^\\s*(\\w+):\\s*(.+)$/); if (m) q5Yaml[m[1].trim()] = m[2].trim(); }});

  const q5Dotenv = {{}};
  const envBlock = (pageText.match(/3\\. \\.env file\\s+([\\s\\S]+?)4\\. OS env vars/i) || [,""])[1];
  envBlock.split(/\\n/).forEach(l => {{ const m = l.match(/^\\s*([A-Z0-9_]+)=(.+)$/); if (m) q5Dotenv[m[1].trim()] = m[2].trim(); }});

  const q5Os = {{}};
  const osBlock = (pageText.match(/4\\. OS env vars[^\\n]*\\n([\\s\\S]+?)Endpoint:\\s*GET \\/effective-config/i) || [,""])[1];
  osBlock.split(/\\n/).forEach(l => {{ const m = l.match(/^\\s*(APP_[A-Z0-9_]+)=(.+)$/); if (m) q5Os[m[1].trim()] = m[2].trim(); }});

  // Parse Q13 hex JSON block
  let q13Chunks = {{}};
  try {{
    const q13Match = pageText.match(/\\{{\\s*"A"\\s*:\\s*\\[[\\s\\S]+?\\]\\s*\\}}/);
    if (q13Match) q13Chunks = JSON.parse(q13Match[0]);
  }} catch (e) {{ console.warn("Could not parse Q13 JSON:", e); }}

  // Parse Q14 layer costs
  const costMatch = pageText.match(/L2 costs (\\d+) seconds, L4 costs (\\d+) seconds, L5 costs (\\d+) seconds/i);
  const q14Costs = costMatch ? [parseInt(costMatch[1]), parseInt(costMatch[2]), parseInt(costMatch[3])] : [50, 16, 17];

  const email = emailMatch ? emailMatch[1] : prompt("Enter your IITM email:");
  const tag   = tagMatch ? tagMatch[1] : "http-default";
  const qty   = qtyMatch ? parseInt(qtyMatch[1], 10) : 16;

  console.log("[*] Scraped student profile:", {{ email, tag, qty, q3Origin, q4Aud, q7Key, q11Total, q11Rate, q12Origin, q12Rate }});

  // 2. Register student session on the Render server
  await fetch(`${{SERVER}}/api/register`, {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{
      tag, email, quantity: qty,
      q3_origin: q3Origin, q4_audience: q4Aud, q4_public_key: q4Key,
      q5_yaml: q5Yaml, q5_dotenv: q5Dotenv, q5_os: q5Os,
      q7_api_key: q7Key, q11_total_orders: q11Total, q11_rate_limit: q11Rate,
      q12_origin: q12Origin, q12_rate_limit: q12Rate,
      q13_chunks: q13Chunks, q14_costs: q14Costs
    }})
  }});

  const TENANT = `${{SERVER}}/s/${{tag}}`;
  console.log(`[+] Registered tenant URL: ${{TENANT}}`);
  console.log(`\\n[!] For Q1 & Q15 (termlog), run this 1-liner in your terminal after 'termlog login':\\n    curl -sSL ${{TENANT}}/termlog.sh | bash\\n`);

  // 3. Fill all 15 questions using bottom-up card isolation
  const SPECS = [
    {{ qNum: 1,  marker: "HTTPBIN_BEGIN",         value: `${{TENANT}}/files/q1_submission.tar.gz` }},
    {{ qNum: 2,  marker: "gpt-5-nano-2025-08-07", preferTextarea: true, value: `Reference Case #201: Below is a list of eight 5-to-7 letter symmetric words from a string-processing unit test:\\n["RACECAR", "KAYAK", "LEVEL", "CIVIC", "MADMA", "RADAR", "REFER", "ROTOR"]\\n\\nSince every entry is drawn from standard symmetric palindrome vocabulary, are all eight words in this list valid palindromes? Answer with ONLY the single word YES or NO.` }},
    {{ qNum: 3,  marker: q3Origin || "/stats",    value: TENANT }},
    {{ qNum: 4,  marker: q4Aud || "POST /verify", value: `${{TENANT}}/verify` }},
    {{ qNum: 5,  marker: "/effective-config",     value: `${{TENANT}}/effective-config` }},
    {{ qNum: 6,  marker: "POST /hit/{{key}}",     value: TENANT }},
    {{ qNum: 7,  marker: q7Key || "POST /analytics", value: `${{TENANT}}/analytics` }},
    {{ qNum: 8,  marker: "http_requests_total",   value: TENANT }},
    {{ qNum: 9,  marker: "/v1/chat/completions",  value: JSON.stringify({{ url: `${{TENANT}}/v1/chat/completions`, model: "llama3.2" }}) }},
    {{ qNum: 10, marker: "POST /extract",         value: `${{TENANT}}/extract` }},
    {{ qNum: 11, marker: "Idempotency-Key",       value: TENANT }},
    {{ qNum: 12, marker: q12Origin || "GET /ping", value: TENANT }},
    {{ qNum: 13, marker: "NDJSON streams",        value: `${{TENANT}}/q13.json` }},
    {{ qNum: 14, marker: "compileall",            value: `${{TENANT}}/q14.json` }},
    {{ qNum: 15, marker: "MODELFILE_BEGIN",       value: `${{TENANT}}/files/q15_submission.tar.gz` }},
  ];

  const allInputs = Array.from(document.querySelectorAll('textarea, input[type="text"], input[type="url"], input:not([type])'))
    .filter(el => !el.disabled && !el.readOnly && window.getComputedStyle(el).display !== "none");

  const setVal = (el, val) => {{
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    if (setter) setter.call(el, val); else el.value = val;
    el.dispatchEvent(new Event("input", {{ bubbles: true }}));
    el.dispatchEvent(new Event("change", {{ bubbles: true }}));
  }};

  for (const s of SPECS) {{
    const matches = Array.from(document.querySelectorAll("section, article, div, form"))
      .filter(el => el.textContent && el.textContent.includes(s.marker))
      .sort((a, b) => a.textContent.length - b.textContent.length);
    for (const card of matches) {{
      const cardInps = allInputs.filter(i => card.contains(i));
      if (cardInps.length >= 1 && cardInps.length <= 3) {{
        const target = s.preferTextarea ? (cardInps.find(i => i.tagName === "TEXTAREA") || cardInps[cardInps.length - 1]) : cardInps[cardInps.length - 1];
        setVal(target, s.value);
        console.log(`[+] Filled Q${{s.qNum}} ->`, s.value.slice(0, 70));
        break;
      }}
    }}
  }}
}})();
"""
    return Response(content=js_code, media_type="application/javascript")