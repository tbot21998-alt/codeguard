import csv
import gzip
import io
import json
from collections import Counter
from time import perf_counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guard.detector import inspect_code
from guard.explain import explanations_for
from guard.metrics import classification_metrics
from guard.mitre import MITRE_MAPPING
from guard.schema import Category, CodeRequest, Language, MitreReference, Verdict

MAX_UPLOAD_BYTES = 500 * 1024 * 1024
MAX_RECORDS = 500000


class UploadRecord(CodeRequest):
    model_config = ConfigDict(extra="ignore", strict=True)
    idx: int | str | None = None
    id: str | None = Field(default=None, max_length=512)
    path: str | None = Field(default=None, max_length=4096)
    label: int | None = Field(default=None, ge=0, le=1)

    @field_validator("label", mode="before")
    @classmethod
    def reject_boolean_label(cls, value):
        if isinstance(value, bool):
            raise ValueError("label must be integer 0 or 1, not a boolean")
        return value


class Evidence(BaseModel):
    category: Category
    reason: str
    line: int | None
    source_line: str | None
    confidence_score: float | None
    model_score: float | None = None
    analyzer: str
    mitre: MitreReference | None = None


class FileVerdict(Verdict):
    idx: int | str
    record_index: int
    id: str | None
    path: str
    status: Literal["Allow", "Block"]
    category: list[Category]
    language: Language
    code: str
    confidence_score: float | None = Field(ge=0, le=1)
    confidence_basis: str
    latency_ms: float = Field(ge=0)
    findings: list[Evidence]
    mitre_techniques: list[MitreReference]
    explanations: list[dict] = []


class UploadMetrics(BaseModel):
    labeled_count: int
    tp: int
    fp: int
    fn: int
    tn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    meets_accuracy_target: bool


class MitreSummaryItem(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    cwe_id: str
    category: Category
    count: int


class FileReport(BaseModel):
    filename: str
    total: int
    allowed: int
    blocked: int
    latency_ms: float
    metrics: UploadMetrics | None
    mitre_summary: list[MitreSummaryItem] = []
    results: list[FileVerdict]


def parse_records(data: bytes, filename: str):
    """Parse uploaded bytes into a list of UploadRecord objects.

    Supported formats
    -----------------
    .jsonl.gz   gzip-compressed JSONL (one JSON object per line)
    .jsonl      plain JSONL
    .json       JSON array, single record, or {"snippets":[...]}
    .csv        CSV with a required 'code' column; optional 'id', 'path', 'label'
    """
    name = filename.lower()
    if name.endswith(".jsonl.gz") or name.endswith(".json.gz"):
        with gzip.open(io.BytesIO(data), "rb") as gz:
            raw = gz.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError('Expanded upload exceeds the 500 MiB limit; split large datasets into smaller files')
        return parse_records(raw, filename[:-3])  # strip .gz to detect inner extension
    if name.endswith(".jsonl"):
        with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8-sig", newline=None) as lines:
            value = [json.loads(line) for line in lines if line.strip()]
    elif name.endswith(".csv"):
        with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8-sig", newline="") as text:
            reader = csv.DictReader(text)
            if reader.fieldnames is None or "code" not in reader.fieldnames:
                raise ValueError("CSV must contain a 'code' column")
            value = [
                {
                    "code": row["code"],
                    **({"idx": row["idx"]} if row.get("idx") else {}),
                    **({"id": row["id"]} if "id" in row and row["id"] else {}),
                    **({"path": row["path"]} if "path" in row and row["path"] else {}),
                    **({"label": int(row["label"])} if "label" in row and row["label"].strip() in ("0", "1") else {}),
                }
                for row in reader
                if row.get("code", "").strip()
            ]
    else:
        value = json.loads(data.decode("utf-8-sig"))
    return records_from_value(value)


def records_from_value(value):
    if isinstance(value, dict):
        value = value["snippets"] if "snippets" in value else [value]
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RECORDS:
        raise ValueError(f"Upload must contain between 1 and {MAX_RECORDS} code records")
    return [UploadRecord.model_validate(record) for record in value]


def inspect_record(record, filename, index, cache=None):
    started = perf_counter()
    inspection = cache.get(record.code) if cache is not None else None
    if inspection is None:
        inspection = inspect_code(record.code)
        if cache is not None:
            cache[record.code] = inspection
    lines = record.code.splitlines()
    findings = [Evidence(category=item.category, reason=item.reason, line=item.line, source_line=lines[item.line - 1] if 1 <= item.line <= len(lines) else None, confidence_score=inspection.confidence_score, model_score=item.score, analyzer="static", mitre=item.mitre) for item in dict.fromkeys(inspection.findings)]
    if inspection.verdict.verdict == "block" and not findings:
        findings = [Evidence(category=category, reason=inspection.verdict.reason, line=None, source_line=None, confidence_score=inspection.confidence_score, analyzer="local_ml", mitre=next((ref for ref in inspection.mitre_techniques if ref.category == category), None)) for category in inspection.verdict.categories]
    explanations = explanations_for(list(dict.fromkeys(inspection.findings)), lines, inspection.verdict.categories, inspection.verdict.reason) if inspection.verdict.verdict == "block" else []
    return FileVerdict(**inspection.verdict.model_dump(exclude={"confidence_score"}), idx=record.idx if record.idx is not None else index - 1, record_index=index, status=inspection.verdict.verdict.capitalize(), category=inspection.verdict.categories, language=inspection.verdict.code_language, code=record.code, id=record.id, path=record.path or f"{filename}#record-{index}", confidence_score=inspection.confidence_score, confidence_basis=inspection.confidence_basis, latency_ms=round((perf_counter() - started) * 1000, 4), findings=findings, mitre_techniques=inspection.mitre_techniques, explanations=explanations)


def mitre_items(counts):
    items = [MitreSummaryItem(count=count, **{key: MITRE_MAPPING[category][key] for key in ("technique_id", "technique_name", "tactic", "tactic_id", "cwe_id")}, category=category) for category, count in counts.items()]
    return sorted(items, key=lambda item: (-item.count, item.technique_id))


def mitre_summary(results):
    return mitre_items(Counter(reference.category for result in results for reference in result.mitre_techniques))

PARALLEL_MIN_RECORDS = 200
CHUNK_RECORDS = 20


def _worker_init():
    from guard.ml_model import probabilities
    probabilities("print('warmup')")


def _inspect_chunk(job):
    filename, start, items = job
    cache = {}
    return [inspect_record(UploadRecord.model_construct(code=code, id=identifier, path=path, idx=idx, label=None), filename, start + offset, cache) for offset, (code, identifier, path, idx) in enumerate(items)]


_POOL = None
_POOL_LOCK = __import__("threading").Lock()


def _pool_workers():
    import os
    cores = os.cpu_count() or 1
    return 0 if cores < 3 else min(cores - 1, 6)


def _noop():
    return None


def get_pool():
    """Shared process pool, created once and kept warm so uploads do not pay process start-up and model load."""
    global _POOL
    from concurrent.futures import ProcessPoolExecutor
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = ProcessPoolExecutor(max_workers=_pool_workers(), initializer=_worker_init)
        return _POOL


def warm_pool():
    if _pool_workers():
        try:
            pool = get_pool()
            for _ in range(_pool_workers()):
                pool.submit(_noop)
        except RuntimeError:
            # Server shut down or reloaded while the background warm-up thread was submitting
            pass


def shutdown_pool():
    global _POOL
    with _POOL_LOCK:
        pool, _POOL = _POOL, None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


def inspect_many(records, filename):
    """Yield FileVerdicts in order. Large inputs are spread across CPU cores; small ones run in-process."""
    workers = _pool_workers()
    if len(records) < PARALLEL_MIN_RECORDS or not workers:
        cache = {}
        for index, record in enumerate(records, 1):
            yield inspect_record(record, filename, index, cache)
        return
    from collections import deque
    from concurrent.futures.process import BrokenProcessPool
    pool = get_pool()
    pending, position = deque(), 0

    def submit():
        nonlocal position
        if position >= len(records):
            return
        batch = records[position:position + CHUNK_RECORDS]
        pending.append(pool.submit(_inspect_chunk, (filename, position + 1, [(r.code, r.id, r.path, r.idx) for r in batch])))
        position += len(batch)

    try:
        for _ in range(workers * 3):
            submit()
        while pending:
            chunk = pending.popleft().result()
            submit()
            yield from chunk
    except BrokenProcessPool:
        shutdown_pool()
        raise
    finally:
        for future in pending:
            future.cancel()

def build_report(records, filename, started, results=None):
    if results is None:
        results = list(inspect_many(records, filename))
    labeled = [(record.label == 1, result.verdict == "block") for record, result in zip(records, results) if record.label is not None]
    blocked = sum(result.verdict == "block" for result in results)
    metrics = classification_metrics([wanted for wanted, _ in labeled], [actual for _, actual in labeled]) if labeled else None
    return FileReport(filename=filename, total=len(results), allowed=len(results) - blocked, blocked=blocked, latency_ms=round((perf_counter() - started) * 1000, 4), metrics=metrics, mitre_summary=mitre_summary(results), results=results)


def stream_report(records, filename, started):
    yield json.dumps({'type': 'start', 'total': len(records), 'filename': filename}) + '\n'
    completed, blocked, mitre, pairs = 0, 0, Counter(), []
    try:
        for result in inspect_many(records, filename):
            completed += 1
            blocked += result.verdict == 'block'
            mitre.update(reference.category for reference in result.mitre_techniques)
            if records[completed - 1].label is not None:
                pairs.append((records[completed - 1].label == 1, result.verdict == 'block'))
            yield json.dumps({'type': 'result', 'completed': completed, 'result': result.model_dump()}) + '\n'
        metrics = classification_metrics([w for w, _ in pairs], [a for _, a in pairs]) if pairs else None
        summary = FileReport.model_construct(filename=filename, total=completed, allowed=completed - blocked, blocked=blocked, latency_ms=round((perf_counter() - started) * 1000, 4), metrics=metrics, mitre_summary=mitre_items(mitre), results=[]).model_dump(exclude={'results'})
        yield json.dumps({'type': 'complete', 'report': summary}) + '\n'
    except GeneratorExit:
        raise
    except Exception:
        yield json.dumps({'type': 'error', 'message': 'Inspection failed. Remaining records were not evaluated.', 'completed': completed}) + '\n'
