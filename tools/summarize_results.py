#!/usr/bin/env python3
"""Summarize validated hits and bounded negative result files."""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")


def main():
    hits = []
    files = 0
    for name in sorted(os.listdir(RESULTS)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(RESULTS, name)
        try:
            with open(path) as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        files += 1
        if not isinstance(data, dict):
            continue
        direct_hits = data.get("hits")
        if isinstance(direct_hits, list) and direct_hits:
            hits.append((name, len(direct_hits), "direct"))
        for score in data.get("scores", []):
            if score.get("exact") and score.get("candidate_repeats", 0) >= 4:
                hits.append((name, 1, f"pattern start={score.get('start')}"))
    print(f"readable_result_files={files}")
    print(f"validated_hit_records={len(hits)}")
    for name, count, kind in hits:
        print(f"{kind}: {name}: {count}")


if __name__ == "__main__":
    main()
