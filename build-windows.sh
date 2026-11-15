#!/bin/bash
# Baut SnitchBox für Windows x64 nach dist/ (unter Windows: build-windows.ps1).
# Zählt BUILD_NUMBER hoch (NOBUMP=1 verhindert das). Vorher laufen die Kern-Tests (NOTEST=1 überspringt sie).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
DOTNET="$HOME/.dotnet/dotnet"
VERSION=$(cat "$ROOT/VERSION")

# Der eingebettete Treiber muss genau der aus dem offiziellen WinDivert-2.2.2-Release sein.
check() { [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$2" ] || { echo "Falsche Prüfsumme: $1"; exit 1; }; }
check "$ROOT/third_party/windivert/WinDivert.dll" c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
check "$ROOT/third_party/windivert/WinDivert64.sys" 8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2

if [ -z "${NOTEST:-}" ]; then
  "$DOTNET" run --project "$ROOT/tests/SnitchBox.Tests" -v q 2>&1 | grep -vE "warning|^$" | tail -3
  [ "${PIPESTATUS[0]}" = 0 ] || { echo "Kern-Tests fehlgeschlagen"; exit 1; }
fi
# Übersetzungen: Vorlage neu erzeugen, jede Sprache muss vollständig sein.
python3 "$ROOT/scripts/extract_strings.py" --check | tail -14 || { echo "Übersetzungen unvollständig (scripts/extract_strings.py)"; exit 1; }
if [ -z "${NOBUMP:-}" ]; then echo $(( $(cat "$ROOT/BUILD_NUMBER") + 1 )) > "$ROOT/BUILD_NUMBER"; fi
BUILD=$(cat "$ROOT/BUILD_NUMBER")
B="$ROOT/build"; mkdir -p "$B"
rm -rf "$B/icon"
xcrun swift "$ROOT/scripts/make_win_icon.swift" "$B/icon" >/dev/null
python3 "$ROOT/scripts/make_ico.py" "$B/icon" "$ROOT/src/SnitchBox/app.ico"
VER_ARGS=(-p:Version="$VERSION.$BUILD" -p:FileVersion="$VERSION.$BUILD" -p:InformationalVersion="$VERSION (Build $BUILD)")
# publish <Ausgabeordner> [weitere Argumente]
publish() {
  local out="$B/$1"; shift
  rm -rf "$out"
  if ! "$DOTNET" publish "$ROOT/src/SnitchBox" -c Release -r win-x64 -p:PublishSingleFile=true "${VER_ARGS[@]}" "$@" -o "$out" -v q > "$B/publish.log" 2>&1; then
    grep -E "error" "$B/publish.log" | sort -u | head -40; exit 1
  fi
}
mkdir -p "$ROOT/dist"
# Nichts wird beim Start ausgepackt. Früher entpackte die eigenständige Fassung („IncludeAllContentForSelfExtract“) bei jedem
# Build rund 116 MB nach %TEMP%\.net und lud sie von dort – jedes Programm hätte diese Dateien austauschen können, die
# SnitchBox dann mit Administratorrechten ausführt.
# SnitchBox.exe: eine Datei, braucht die „.NET Desktop Runtime“ 10 oder neuer (fehlt sie, bietet Windows den Download an).
publish publish-net --self-contained false -p:RollForward=LatestMajor
cp "$B/publish-net/SnitchBox.exe" "$ROOT/dist/SnitchBox.exe"
# SnitchBox-Standalone/: läuft ohne .NET-Installation; die WPF-Bibliotheken liegen neben der .exe statt in %TEMP%.
# Bewusst ungekürzt (kein Trimming) – bei einer Firewall zählt Verlässlichkeit vor Größe.
publish publish --self-contained true -p:EnableCompressionInSingleFile=true
rm -rf "$ROOT/dist/SnitchBox-Standalone" "$ROOT/dist/SnitchBox-NET.exe"
mkdir -p "$ROOT/dist/SnitchBox-Standalone"
cp "$B/publish/SnitchBox.exe" "$B/publish/"*.dll "$ROOT/dist/SnitchBox-Standalone/"
ls -la "$ROOT/dist/SnitchBox.exe" "$ROOT/dist/SnitchBox-Standalone/"
echo "Erstellt: SnitchBox für Windows $VERSION (Build $BUILD) → dist/SnitchBox.exe (braucht .NET 10 Desktop Runtime), dist/SnitchBox-Standalone/ (ohne .NET)"
