import argparse
import json
import platform
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter

from guard.detector import evaluate
from guard.ml_model import MODEL_PATH, probabilities
from guard.metrics import classification_metrics


def expected_categories(sample):
    value = sample["category"]
    return set(value if isinstance(value, list) else [part.strip() for part in value.split(",")]) - {"benign"}


def measure(samples, use_model, repeats):
    latencies = []
    records = []
    for sample in samples:
        started = perf_counter()
        result = evaluate(sample["code"], use_model=use_model)
        latencies.append((perf_counter() - started) * 1000)
        wanted = expected_categories(sample)
        records.append({"id": sample["id"], "expected_block": bool(sample["label"]), "predicted_block": result.verdict == "block", "expected_categories": sorted(wanted), "category_recall_match": wanted.issubset(result.categories), "category_exact_match": wanted == set(result.categories), "language_match": result.code_language == sample["language"], "response": result.model_dump()})
    for _ in range(repeats - 1):
        for sample in samples:
            started = perf_counter()
            evaluate(sample["code"], use_model=use_model)
            latencies.append((perf_counter() - started) * 1000)
    metrics = classification_metrics([row["expected_block"] for row in records], [row["predicted_block"] for row in records])
    return {"samples": len(samples), **metrics, "category_recall_matches": sum(row["category_recall_match"] for row in records), "category_exact_matches": sum(row["category_exact_match"] for row in records), "language_matches": sum(row["language_match"] for row in records), "p50_ms": round(median(latencies), 3), "p95_ms": round(quantiles(latencies, n=100)[94], 3), "max_ms": round(max(latencies), 3), "timed_calls": len(latencies), "records": records}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent / "data" / "codeguard_dev.jsonl")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "reports" / "dev-evaluation.json")
    parser.add_argument("--repeats", type=int, default=20)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    samples = [json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    started = perf_counter()
    probabilities("print('warmup')")
    cold_ms = (perf_counter() - started) * 1000
    metadata_path = MODEL_PATH.with_suffix(".json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
    report = {"platform": platform.platform(), "python": platform.python_version(), "model_training": metadata, "model_bytes": MODEL_PATH.stat().st_size if MODEL_PATH.exists() else 0, "model_load_and_first_inference_ms": round(cold_ms, 3), "method": "Public development regression only. Consult model_training.includes_dev for training overlap. Static rules were developed with public samples visible. Timings are in-process, exclude startup, and include no response cache.", "rules_only": measure(samples, False, args.repeats), "cascade": measure(samples, True, args.repeats)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for row in report["cascade"]["records"]:
        passed = row["expected_block"] == row["predicted_block"] and row["category_recall_match"]
        print(f"{'PASS' if passed else 'FAIL'} {row['id']} categories={row['response']['categories']} exact={row['category_exact_match']}")
    print(json.dumps({name: {key: value for key, value in report[name].items() if key != "records"} for name in ["rules_only", "cascade"]}, indent=2))
    print(f"Report: {args.output}")
    if report["cascade"]["fp"] or report["cascade"]["fn"] or report["cascade"]["category_recall_matches"] != len(samples):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
