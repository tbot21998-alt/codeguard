# Exposing a Local FastAPI Service with Uvicorn + ngrok

This guide walks through running any FastAPI service locally and exposing it as a
public HTTPS URL, so an external caller (a grader, a webhook provider, a teammate,
a third-party API) can reach it over the internet.

---

## 1. Prerequisites

- Python 3.10+
- A free [ngrok](https://ngrok.com) account (sign up, it's free)

---

## 2. Set up your Python environment

```bash
mkdir my-service && cd my-service
python -m venv .venv

# Activate it:
source .venv/bin/activate        # macOS/Linux
.venv\Scripts\activate           # Windows (PowerShell/cmd)

pip install fastapi uvicorn pydantic
```

---

## 3. Create `main.py`

A minimal example — replace the request/response models and logic with your own:

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class RequestBody(BaseModel):
    # define your input fields here
    text: str

class ResponseBody(BaseModel):
    # define your output fields here
    result: str

@app.post("/your-route", response_model=ResponseBody)
def handle(req: RequestBody):
    try:
        return process(req)
    except Exception as e:
        # fail safe instead of crashing with a 500
        return {"result": f"error: {e}"}

def process(req: RequestBody) -> dict:
    # TODO: your actual logic
    return {"result": req.text.upper()}
```

---

## 4. Run the service locally

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Verify it works before exposing it publicly:

```bash
curl -X POST http://localhost:8000/your-route \
  -H "Content-Type: application/json" \
  -d '{"text": "hello"}'
```

Leave this terminal window running.

---

## 5. Install ngrok

Download from https://ngrok.com/download and follow the install steps for your OS
(installers for Windows/macOS/Linux, or a package manager like `brew install ngrok` /
`choco install ngrok`).

---

## 6. Authenticate ngrok (one-time setup)

1. Log in to https://dashboard.ngrok.com
2. Copy your authtoken from the dashboard
3. Run:

```bash
ngrok config add-authtoken <YOUR_AUTHTOKEN>
```

---

## 7. Expose your local server

In a **new** terminal window (keep uvicorn running in the first one):

```bash
ngrok http 8000
```

ngrok will print something like:

```
Forwarding   https://abcd1234.ngrok-free.app -> http://localhost:8000
```

Your public endpoint is:

```
https://abcd1234.ngrok-free.app/your-route
```

**Note the path** — anyone calling your service needs the full URL including the
route, not just the base domain.

---

## 8. Test the public URL end-to-end

Don't just trust that it works — hit the public URL, not `localhost`:

```bash
curl -X POST https://abcd1234.ngrok-free.app/your-route \
  -H "Content-Type: application/json" \
  -d '{"text": "hello"}'
```

If you get a browser warning page instead of JSON (ngrok's free-tier interstitial),
add this header to bypass it:

```bash
curl -X POST https://abcd1234.ngrok-free.app/your-route \
  -H "Content-Type: application/json" \
  -H "ngrok-skip-browser-warning: true" \
  -d '{"text": "hello"}'
```

Make sure whoever calls your endpoint knows to send that header too, if needed.

---

## 9. Keep it alive while others depend on it

- **Do not close either terminal** (uvicorn or ngrok) while the URL is in use.
- **Do not restart ngrok** once you've shared the URL — the free tier assigns a new
  random URL every time it restarts, which breaks anyone who saved the old link.
- **Disable your laptop's sleep/screen-lock** for the period it needs to stay up:
  - Windows: Settings → System → Power & sleep → set "Sleep" to Never (temporarily)
  - macOS: run `caffeinate` in a spare terminal, or adjust Lock Screen settings
- Stay on a stable network connection — ngrok tunnels break if your laptop changes
  networks (e.g. switching Wi-Fi) or goes to sleep.

---

## 10. Share the URL

Give whoever needs it the full URL including the path, e.g.:

```
https://abcd1234.ngrok-free.app/your-route
```

---

## Troubleshooting

"Fix on" tells you which side needs to act: the **creator** (the person running
`uvicorn`/`ngrok`, hosting the endpoint) or the **caller** (the person/script sending
requests to it). If an issue is on the caller's side, the creator usually can't fix
it from their own machine — it needs a message back to whoever is calling the URL.

| Symptom | Likely cause | Fix | Fix on |
|---|---|---|---|
| ngrok shows "ERR_NGROK_..." | Auth token not set | Re-run `ngrok config add-authtoken ...` | Creator |
| Public URL returns HTML, not JSON | ngrok browser-warning interstitial | Add `ngrok-skip-browser-warning: true` header to requests | Caller (creator should tell them to add it) |
| Connection refused on public URL | uvicorn not running, or wrong port in `ngrok http` | Confirm uvicorn is up on the same port you passed to ngrok | Creator |
| URL changed after a restart | Free ngrok rotates URLs each session | Don't restart ngrok once shared; share the new URL if it did change | Creator (must re-share URL); Caller (must update it) |
| Works on `localhost` but not via ngrok | Host header / CORS issue | Try `ngrok http --host-header=rewrite 8000` | Creator |
| Caller gets a 422 / validation error | Request body doesn't match the service's expected schema | Caller fixes the JSON payload to match the documented fields | Caller |
| Caller gets a 500 | Unhandled exception in service logic | Add try/except and fail-safe defaults in the handler | Creator |
| Caller gets a timeout | Service is slow, laptop went to sleep, or network dropped | Creator checks the service/tunnel is alive and responsive; disable sleep | Creator |
| Caller can't reach the URL at all | Wrong URL, typo, or creator's tunnel/service is down | Caller re-confirms the exact URL they were given; creator confirms both processes are running | Both — verify independently |
