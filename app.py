import asyncio
from contextlib import asynccontextmanager
from threading import Thread
from pathlib import Path
from time import perf_counter

from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from guard.detector import inspect_code
from guard.file_reports import MAX_UPLOAD_BYTES, FileReport, build_report, parse_records, records_from_value, shutdown_pool, stream_report, warm_pool
from guard.ml_model import load_model, probabilities
from guard.schema import BatchRequest, CodeRequest, Verdict

AUDIT_LOG = Path(__file__).parent / "reports" / "command-audit.jsonl"


class IndexedVerdict(Verdict):
    idx: int | str


def mitre_header(references):
    return ",".join(dict.fromkeys(reference.technique_id for reference in references))


@asynccontextmanager
async def lifespan(app):
    probabilities("print('warmup')")
    Thread(target=warm_pool, daemon=True).start()
    yield
    shutdown_pool()


app = FastAPI(title="CodeGuard", version="0.1.0", lifespan=lifespan)


@app.exception_handler(ValueError)
async def inspection_unavailable(request, error):
    return JSONResponse(status_code=503, content={"detail": "Inspection unavailable: classifier or analysis failed. Execution must remain blocked."})


@app.post("/", response_model=IndexedVerdict, response_model_exclude={"confidence_score"})
@app.post("/guard", response_model=IndexedVerdict, response_model_exclude={"confidence_score"})
@app.post("/evaluate", response_model=IndexedVerdict, response_model_exclude={"confidence_score"})
def evaluate_request(request: CodeRequest, response: Response):
    started = perf_counter()
    inspection = inspect_code(request.code)
    response.headers["X-CodeGuard-Latency-Ms"] = f"{(perf_counter() - started) * 1000:.4f}"
    response.headers["X-CodeGuard-MITRE-IDs"] = mitre_header(inspection.mitre_techniques)
    if inspection.confidence_score is not None:
        response.headers["X-CodeGuard-Confidence"] = f"{inspection.confidence_score:.4f}"
    return IndexedVerdict(**inspection.verdict.model_dump(), idx=request.idx if request.idx is not None else 0)


@app.post("/batch_evaluate", response_model=list[IndexedVerdict], response_model_exclude={"confidence_score"})
def batch_evaluate(request: BatchRequest, response: Response):
    started = perf_counter()
    inspections = [inspect_code(snippet.code) for snippet in request.snippets]
    response.headers["X-CodeGuard-Latency-Ms"] = f"{(perf_counter() - started) * 1000:.4f}"
    response.headers["X-CodeGuard-MITRE-IDs"] = mitre_header([ref for inspection in inspections for ref in inspection.mitre_techniques])
    return [IndexedVerdict(**inspection.verdict.model_dump(), idx=snippet.idx if snippet.idx is not None else index) for index, (snippet, inspection) in enumerate(zip(request.snippets, inspections))]


@app.post("/evaluate_file", response_model=FileReport)
async def evaluate_file(file: UploadFile, stream: bool = False):
    started = perf_counter()
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    allowed_extensions = (".json", ".jsonl", ".jsonl.gz", ".json.gz", ".csv")
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(415, "Upload a .json, .jsonl, .jsonl.gz, or .csv file")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Upload exceeds the 500 MiB file limit")
    try:
        records = parse_records(data, filename)
    except ValidationError as error:
        raise HTTPException(422, [{"location": list(item["loc"]), "message": item["msg"]} for item in error.errors()]) from error
    except (ValueError, RecursionError, OSError, EOFError) as error:
        raise HTTPException(422, "Invalid UTF-8 JSON/JSONL or record count; expected code records") from error
    if stream:
        return StreamingResponse(stream_report(records, filename, started), media_type='application/x-ndjson', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})
    return await run_in_threadpool(build_report, records, filename, started)


@app.post("/evaluate_json", response_model=FileReport)
async def evaluate_json(payload: Any = Body(...)):
    started = perf_counter()
    try:
        records = records_from_value(payload)
    except ValidationError as error:
        raise HTTPException(422, [{"location": list(item["loc"]), "message": item["msg"]} for item in error.errors()]) from error
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(422, "Expected a code record, a list of records, or {\"snippets\": [...]}") from error
    return await run_in_threadpool(build_report, records, "request.json", started)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": load_model() is not None, "execution_enabled": False}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "demo" / "dashboard.html").read_text(encoding="utf-8")


@app.get("/audit", response_class=HTMLResponse)
def audit_viewer():
    return (Path(__file__).parent / "demo" / "audit.html").read_text(encoding="utf-8")


@app.get("/audit/stream")
async def audit_stream(request: Request):
    """Server-Sent Events stream that tails the command-audit.jsonl file live."""
    async def event_generator():
        path = AUDIT_LOG
        offset = 0
        # Seek to end so we only stream new events (not history)
        if path.exists():
            offset = path.stat().st_size
        # Send a heartbeat comment immediately so the browser knows the connection is live
        yield "event: connected\ndata: {}\n\n"
        while True:
            if await request.is_disconnected():
                break
            if path.exists():
                size = path.stat().st_size
                if size > offset:
                    try:
                        with path.open("r", encoding="utf-8") as f:
                            f.seek(offset)
                            for line in f:
                                line = line.strip()
                                if line:
                                    yield f"data: {line}\n\n"
                        offset = path.stat().st_size
                    except OSError:
                        pass
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/audit/history")
def audit_history(limit: int = 200):
    """Return the last N audit log entries as JSON."""
    if not AUDIT_LOG.exists():
        return []
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
        import json as _json
        return [_json.loads(line) for line in lines[-limit:] if line.strip()]
    except (OSError, ValueError):
        return []
