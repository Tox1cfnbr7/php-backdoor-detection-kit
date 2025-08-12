# PHP Backdoor Detection Kit (defensiv)

Dieses Repository enthält **nur** Werkzeuge und Hinweise zur **Erkennung** verdächtiger PHP-Muster. 
Es liefert **keine** funktionierenden Backdoors oder Exploits.

## Inhalte
- `scanner.py`: Ein einfacher statischer Scanner, der typische riskante Konstrukte in PHP-Dateien meldet (z.B. `eval(`, `assert(`, `shell_exec`, base64-Ketten, etc.).
- `rules/regexes.json`: Die konfigurierbaren Regex-Regeln mit Kurzbeschreibung.
- GitHub Actions Workflow (`.github/workflows/php-security-scan.yml`), der den Scanner bei jedem Push/PR ausführt.

## Verwendung (lokal)
```bash
python3 scanner.py --path /pfad/zum/php-projekt
# Optional: JSON-Report schreiben
python3 scanner.py --path . --json report.json
```

Exit-Codes:
- `0`: Keine Funde
- `1`: Verdächtige Funde erkannt (CI bricht absichtlich ab)

## Typische riskante Muster (nicht vollständig)
- Dynamische Codeausführung: `eval(`, `assert(`, `preg_replace` mit `e`-Modifier (veraltet), `create_function(`
- Verschleierung/Entschleierung: `base64_decode(`, `gzinflate(`, `str_rot13(`, verschachtelte Kombinationen
- Systemaufrufe: `` `cmd` ``, `system(`, `shell_exec(`, `passthru(`, `popen(`, `proc_open(`
- Remote Includes / Inkludieren über HTTP
- Direkte Verwendung von `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` in obigen Kontexten

> Hinweis: Nicht jeder Fund ist automatisch bösartig. Der Scanner liefert **Hinweise**, die von Menschen bewertet werden müssen.

## GitHub Actions
Der Workflow führt den Scanner in Pull Requests aus und schlägt bei Funden fehl. So können unerwünschte Muster früh auffallen.

## Rechtliches / Ethik
Dieser Code ist ausschließlich zu **Verteidigungs- und Prüfzwecken** gedacht (z.B. Security Audits, CI-Gates). 
Verwende ihn nicht, um Systeme anderer ohne Zustimmung zu analysieren. Keine Garantie.
