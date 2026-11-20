#!/usr/bin/env python3
"""Inventory dangerous operations and auth markers in recovered XWEB PHP code."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path


OPERATIONS = re.compile(r"\b(exec|system|popen|passthru|shell_exec|proc_open|move_uploaded_file|unlink|rename|copy|file_put_contents|mysql_query|mysqli_query)\s*\(", re.I)
INPUTS = re.compile(r"HTTP_(?:GET|POST|SERVER)_VARS|_FILES|\$_(?:GET|POST|REQUEST|FILES|SERVER)")
AUTH = re.compile(r"session_id|_SESSION|WrongAccess|AutenticationMask", re.I)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("webroot", type=Path)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    files = []
    operation_counts = Counter()
    auth_counts = Counter()
    for path in sorted(args.webroot.rglob("*.php")):
        text = path.read_text(encoding="utf-8", errors="replace")
        inputs = sorted(set(INPUTS.findall(text)))
        auth_markers = sorted(set(AUTH.findall(text)))
        operations = []
        for number, line in enumerate(text.splitlines(), 1):
            for match in OPERATIONS.finditer(line):
                name = match.group(1).lower()
                operation_counts[name] += 1
                operations.append({
                    "line": number,
                    "function": name,
                    "text": line.strip(),
                    "direct_input_on_line": bool(INPUTS.search(line)),
                })
        if operations:
            auth_class = "auth-markers-present" if auth_markers else "no-auth-markers"
            auth_counts[auth_class] += 1
            files.append({
                "path": str(path.relative_to(args.webroot)),
                "auth_class": auth_class,
                "auth_markers": auth_markers,
                "input_markers": inputs,
                "operations": operations,
            })
    result = {
        "webroot": str(args.webroot),
        "limitations": "Static inventory only. Auth markers do not prove enforcement; comments and data flow require review.",
        "summary": {
            "files_with_dangerous_operations": len(files),
            "operations": sum(operation_counts.values()),
            "by_function": dict(sorted(operation_counts.items())),
            "by_auth_class": dict(sorted(auth_counts.items())),
            "direct_input_lines": sum(operation["direct_input_on_line"] for file in files for operation in file["operations"]),
        },
        "files": files,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
