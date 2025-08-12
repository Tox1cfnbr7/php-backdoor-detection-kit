#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP Backdoor Detection Kit – defensiver Scanner
Scant rekursiv nach verdächtigen Mustern in PHP-Dateien.
Erkennt keine Exploits, sondern liefert nur Hinweise.

Benutzung:
  python3 scanner.py --path /pfad/zum/projekt [--json report.json]
Exit-Codes:
  0 - keine Funde
  1 - Funde vorhanden
"""
import argparse, json, os, re, sys
from pathlib import Path

DEFAULT_EXTS = {".php", ".phtml", ".php5", ".inc"}
SKIP_DIRS = {".git", "vendor", "node_modules", ".idea", ".vscode"}

def load_rules(rule_path: Path):
    with rule_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Compile regexes
    for r in data["rules"]:
        r["compiled"] = re.compile(r["regex"], re.IGNORECASE | re.MULTILINE)
    return data["rules"]

def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip noisy/third-party dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in DEFAULT_EXTS:
                yield p

def scan_file(path: Path, rules):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [], str(e)

    findings = []
    for rule in rules:
        for m in rule["compiled"].finditer(text):
            # Compute line number and a short snippet
            start = m.start()
            line_no = text.count("\n", 0, start) + 1
            snippet_start = max(0, start - 60)
            snippet_end = min(len(text), m.end() + 60)
            snippet = text[snippet_start:snippet_end].replace("\n", "\\n")
            findings.append({
                "file": str(path),
                "line": line_no,
                "rule": rule["name"],
                "severity": rule.get("severity", "medium"),
                "description": rule.get("description", ""),
                "match": m.group(0),
                "snippet": snippet
            })
    return findings, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".", help="Wurzelpfad des zu scannenden Projekts")
    ap.add_argument("--json", dest="json_out", default=None, help="Optional: Report als JSON-Datei schreiben")
    ap.add_argument("--ext", nargs="*", default=None, help="Zusätzliche Dateiendungen (inkl. Punkt), z.B. .phps .module")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    rule_file = Path(__file__).parent / "rules" / "regexes.json"
    rules = load_rules(rule_file)

    if args.ext:
        for e in args.ext:
            DEFAULT_EXTS.add(e.lower())

    all_findings = []
    errors = []

    for p in iter_files(root):
        fnds, err = scan_file(p, rules)
        if err:
            errors.append({"file": str(p), "error": err})
        if fnds:
            all_findings.extend(fnds)

    # Output
    if all_findings:
        print(f"[!] Verdächtige Muster gefunden: {len(all_findings)} Treffer")
        # Print concise table
        for f in all_findings[:200]:  # cap console spam
            print(f" - {f['file']}:{f['line']} [{f['severity']}] {f['rule']} -> {f['match']!r}")
        if len(all_findings) > 200:
            print(f" ... weitere {len(all_findings)-200} Treffer unterdrückt (siehe JSON-Report).")
    else:
        print("[✓] Keine verdächtigen Muster gefunden.")

    if errors:
        print("\n[Hinweis] Lesefehler bei einigen Dateien:")
        for e in errors[:50]:
            print(f" - {e['file']}: {e['error']}")
        if len(errors) > 50:
            print(f" ... weitere {len(errors)-50} Fehler unterdrückt.")

    # JSON report
    if args.json_out:
        out = {
            "root": str(root),
            "findings": all_findings,
            "errors": errors
        }
        try:
            Path(args.json_out).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\n[✓] JSON-Report geschrieben: {args.json_out}")
        except Exception as e:
            print(f"[x] Konnte JSON-Report nicht schreiben: {e}", file=sys.stderr)

    # Exit non-zero if findings exist
    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
