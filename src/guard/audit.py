import json
from datetime import datetime, timezone
from pathlib import Path


def write_audit(report, path):
    if path is None:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **report}
    with target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=True) + "\n")
