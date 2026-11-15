#!/usr/bin/env python3
"""Sammelt alle Oberflächentexte von SnitchBox und prüft die Übersetzungen.

Quellen: Loc.T/Loc.F("deutsch", "english") im C#-Code, {l:L de='…', en='…'} in XAML, L.T/L.F im Installer.
Schreibt src/SnitchBox.Core/Lang/_source.json (englischer Text → deutscher Text, Vorlage für Übersetzungen) und
prüft jede Sprachdatei Lang/<code>.json (englischer Text → Übersetzung): fehlende, überzählige und leere Einträge,
abweichende Platzhalter {0} … und Zeilenumbrüche.

  python3 scripts/extract_strings.py          # Vorlage schreiben, Bericht ausgeben
  python3 scripts/extract_strings.py --check  # zusätzlich mit Fehlercode enden, wenn etwas fehlt (für die Build-Skripte)
"""
import html
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG_DIR = os.path.join(ROOT, "src", "SnitchBox.Core", "Lang")
CALL = re.compile(r"(?<![\w.])(Loc|L)\.(T|F)\(")
XAML = re.compile(r"\{l:L\s+(de|en)='([^']*)',\s*(de|en)='([^']*)'\s*\}")
PLACEHOLDER = re.compile(r"\{(\d+)(?:[,:][^}]*)?\}")
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}


class NotLiteral(Exception):
    pass


def skip_ws(s, i):
    while i < len(s) and s[i] in " \t\r\n":
        i += 1
    return i


def read_literal(s, i):
    """Liest ein C#-String-Literal ab i; gibt (Wert, Ende) zurück."""
    if s.startswith('@"', i):
        i += 2
        out = []
        while True:
            if s[i] == '"':
                if i + 1 < len(s) and s[i + 1] == '"':
                    out.append('"'); i += 2; continue
                return "".join(out), i + 1
            out.append(s[i]); i += 1
    if s[i] != '"':
        raise NotLiteral(s[i:i + 40])
    i += 1
    out = []
    while s[i] != '"':
        if s[i] == "\\":
            c = s[i + 1]
            if c == "u":
                out.append(chr(int(s[i + 2:i + 6], 16))); i += 6; continue
            out.append(ESCAPES.get(c, c)); i += 2; continue
        out.append(s[i]); i += 1
    return "".join(out), i + 1


def read_concat(s, i):
    """Liest "a" + "b" + … bis zum nächsten Komma oder zur schließenden Klammer."""
    parts = []
    i = skip_ws(s, i)
    while True:
        value, i = read_literal(s, i)
        parts.append(value)
        i = skip_ws(s, i)
        if s[i] == "+":
            i = skip_ws(s, i + 1)
            continue
        if s[i] in ",)":
            return "".join(parts), i
        raise NotLiteral(s[i:i + 40])


def source_files():
    for base in ("src", "installer"):
        for dirpath, dirnames, files in os.walk(os.path.join(ROOT, base)):
            dirnames[:] = [d for d in dirnames if d not in ("bin", "obj")]
            for f in files:
                if f.endswith((".cs", ".xaml")):
                    yield os.path.join(dirpath, f)


def collect():
    entries, problems, origins = {}, [], {}
    for path in sorted(source_files()):
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        text = open(path, encoding="utf-8-sig").read()
        found = []
        if path.endswith(".xaml"):
            for m in XAML.finditer(text):
                vals = {m.group(1): html.unescape(m.group(2)), m.group(3): html.unescape(m.group(4))}
                found.append((vals["de"], vals["en"], text.count("\n", 0, m.start()) + 1))
        else:
            for m in CALL.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if m.group(1) == "L" and not rel.startswith("installer/"):
                    continue
                if text.startswith("de, en)", m.end()):
                    continue  # reine Weiterreichung (Markup-Erweiterung {l:L}), die Texte stehen im XAML
                try:
                    de, i = read_concat(text, m.end())
                    if text[i] != ",":
                        raise NotLiteral("nur ein Argument")
                    en, i = read_concat(text, i + 1)
                    found.append((de, en, line))
                except NotLiteral as e:
                    problems.append(f"{rel}:{line}: kein reines Literal ({str(e).strip()!r})")
        for de, en, line in found:
            if en not in entries:
                entries[en] = de
            origins.setdefault(en, set()).add(rel)
    return entries, problems, origins


def check_language(code, source):
    path = os.path.join(LANG_DIR, code + ".json")
    table = json.load(open(path, encoding="utf-8-sig"))
    issues = []
    for en in source:
        if en not in table:
            issues.append(f"fehlt: {en!r}")
            continue
        t = table[en]
        if not t.strip():
            issues.append(f"leer: {en!r}")
        if sorted(PLACEHOLDER.findall(en)) != sorted(PLACEHOLDER.findall(t)):
            issues.append(f"Platzhalter: {en!r} → {t!r}")
        if en.count("\n") != t.count("\n"):
            issues.append(f"Zeilenumbrüche: {en!r} → {t!r}")
        if en.startswith("_") != ("_" in t) and "_" in en[:2]:
            issues.append(f"Zugriffstaste (_): {en!r} → {t!r}")
    for en in table:
        if en not in source:
            issues.append(f"überzählig (nicht mehr im Code): {en!r}")
    return issues


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    entries, problems, origins = collect()
    if "--installer-subset" in sys.argv:
        # Nur die Texte des Installers je Sprache (hält SnitchBox-Setup.exe klein): --installer-subset <Zielordner>
        out = sys.argv[sys.argv.index("--installer-subset") + 1]
        os.makedirs(out, exist_ok=True)
        keys = [en for en in entries if "installer/Setup.cs" in origins[en]]
        for name in sorted(os.listdir(LANG_DIR)):
            if re.fullmatch(r"[a-z]{2}\.json", name):
                table = json.load(open(os.path.join(LANG_DIR, name), encoding="utf-8-sig"))
                with open(os.path.join(out, name), "w", encoding="utf-8") as f:
                    json.dump({k: table[k] for k in keys if k in table}, f, ensure_ascii=False)
        print(f"Installer: {len(keys)} Texte je Sprache → {out}")
        return
    os.makedirs(LANG_DIR, exist_ok=True)
    with open(os.path.join(LANG_DIR, "_source.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"{len(entries)} Texte → Lang/_source.json")
    bad = bool(problems)
    for p in problems:
        print("PROBLEM", p)
    for name in sorted(os.listdir(LANG_DIR)):
        if re.fullmatch(r"[a-z]{2}\.json", name):
            issues = check_language(name[:2], entries)
            print(f"{name}: {'vollständig' if not issues else str(len(issues)) + ' Probleme'}")
            for i in issues[:40]:
                print("   ", i)
            bad |= bool(issues)
    if "--check" in sys.argv and bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
