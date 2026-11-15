# Baut SnitchBox unter Windows nach dist/ – wie build-windows.sh auf dem Mac, nur ohne neu gezeichnetes Symbol (app.ico bleibt).
# Zählt BUILD_NUMBER hoch (-NoBump verhindert das). Vorher laufen die Kern-Tests (-NoTest überspringt sie).
# .NET-10-SDK: Parameter -Dotnet, sonst Umgebungsvariable SNITCHBOX_DOTNET, ~\.dotnet, ..\optimizerDuck-src\dotnet-sdk-10.0.404 oder dotnet im PATH.
param([switch]$NoBump, [switch]$NoTest, [string]$Dotnet)
# Jeder Fehler (auch beim Kopieren nach dist) bricht ab; dotnet selbst wird über $LASTEXITCODE geprüft.
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

function Test-Sdk([string]$Exe) {
    try { return [bool]((& $Exe --list-sdks) -match '^10\.') } catch { return $false }
}
if (-not $Dotnet) {
    foreach ($c in @($env:SNITCHBOX_DOTNET, "$env:USERPROFILE\.dotnet\dotnet.exe", (Join-Path $Root '..\optimizerDuck-src\dotnet-sdk-10.0.404\dotnet.exe'), 'dotnet')) {
        if ($c -and (Test-Sdk $c)) { $Dotnet = $c; break }
    }
}
if (-not $Dotnet) { Write-Host 'Kein .NET-10-SDK gefunden (Parameter -Dotnet oder Umgebungsvariable SNITCHBOX_DOTNET).'; exit 1 }

# Der eingebettete Treiber muss genau der aus dem offiziellen WinDivert-2.2.2-Release sein.
$sums = @{
    'third_party\windivert\WinDivert.dll'   = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'third_party\windivert\WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($f in $sums.Keys) {
    if ((Get-FileHash -Algorithm SHA256 (Join-Path $Root $f)).Hash -ne $sums[$f]) { Write-Host "Falsche Prüfsumme: $f"; exit 1 }
}

if (-not $NoTest) {
    & $Dotnet run --project (Join-Path $Root 'tests\SnitchBox.Tests') -v q | Where-Object { $_ -and $_ -notmatch 'warning' } | Select-Object -Last 3
    if ($LASTEXITCODE -ne 0) { Write-Host 'Kern-Tests fehlgeschlagen'; exit 1 }
}

# Übersetzungen: Vorlage aus dem Code neu erzeugen und prüfen, dass jede Sprache vollständig ist (braucht Python).
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    & $python.Source -I (Join-Path $Root 'scripts\extract_strings.py') --check | Select-Object -Last 14
    if ($LASTEXITCODE -ne 0) { Write-Host 'Übersetzungen unvollständig (scripts\extract_strings.py)'; exit 1 }
} else { Write-Host 'Python fehlt – Prüfung der Übersetzungen übersprungen' }
$Version = (Get-Content (Join-Path $Root 'VERSION') -Raw).Trim()
$buildFile = Join-Path $Root 'BUILD_NUMBER'
if (-not $NoBump) { [IO.File]::WriteAllText($buildFile, "$([int](Get-Content $buildFile -Raw).Trim() + 1)`n", [Text.Encoding]::ASCII) }
$Build = (Get-Content $buildFile -Raw).Trim()
$B = Join-Path $Root 'build'
New-Item -ItemType Directory -Force $B | Out-Null
# Ohne „+<Commit>“ hinter der Version (das .NET-SDK hängt ihn in einem git-Repository sonst an; der Installer zeigt die Angabe).
$VerArgs = @("-p:Version=$Version.$Build", "-p:FileVersion=$Version.$Build", "-p:InformationalVersion=$Version (Build $Build)", "-p:IncludeSourceRevisionInInformationalVersion=false")

function Publish([string]$Out, [string[]]$Extra) {
    $dir = Join-Path $B $Out
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    $log = Join-Path $B 'publish.log'
    & $Dotnet publish (Join-Path $Root 'src\SnitchBox') -c Release -r win-x64 -p:PublishSingleFile=true @VerArgs @Extra -o $dir -v q | Out-File -Encoding utf8 $log
    if ($LASTEXITCODE -ne 0) { Get-Content $log | Select-String 'error' | Select-Object -Unique -First 40; exit 1 }
}

$dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
# Nichts wird beim Start ausgepackt (Begründung in build-windows.sh).
# SnitchBox.exe: eine Datei, braucht die .NET Desktop Runtime 10 oder neuer.
Publish 'publish-net' @('--self-contained', 'false', '-p:RollForward=LatestMajor')
Copy-Item (Join-Path $B 'publish-net\SnitchBox.exe') (Join-Path $dist 'SnitchBox.exe') -Force
# SnitchBox-Standalone\: ohne .NET-Installation, die WPF-Bibliotheken liegen neben der .exe.
Publish 'publish' @('--self-contained', 'true', '-p:EnableCompressionInSingleFile=true')
$sa = Join-Path $dist 'SnitchBox-Standalone'
foreach ($old in @($sa, (Join-Path $dist 'SnitchBox-NET.exe'))) { if (Test-Path $old) { Remove-Item -Recurse -Force $old } }
New-Item -ItemType Directory $sa | Out-Null
Copy-Item -Path @((Join-Path $B 'publish\SnitchBox.exe'), (Join-Path $B 'publish\*.dll')) -Destination $sa

# SnitchBoxStart.exe: nativer Starter, der SnitchBox ohne die Umgebungsvariablen der .NET-Laufzeit startet (launcher\).
# Braucht den C++-Compiler von Visual Studio (Arbeitslast „Desktopentwicklung mit C++“).
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = if (Test-Path $vswhere) { & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath } else { $null }
$vcvars = if ($vsPath) { Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat' } else { $null }
if (-not $vcvars -or -not (Test-Path $vcvars)) { Write-Host 'C++-Compiler von Visual Studio fehlt (für SnitchBoxStart.exe)'; exit 1 }
$v = $Version.Split('.')
& cmd /c "`"$(Join-Path $Root 'launcher\build-launcher.cmd')`" `"$vcvars`" `"$dist`" `"$(Join-Path $B 'launcher')`" $($v[0]) $($v[1]) $($v[2]) $Build" | Where-Object { $_ -and $_ -notmatch 'vswhere|falsch geschrieben|gefunden werden|SnitchBoxStart\.cpp' }
if ($LASTEXITCODE -ne 0) { Write-Host 'Starter ließ sich nicht übersetzen'; exit 1 }
Copy-Item (Join-Path $dist 'SnitchBoxStart.exe') $sa

# SnitchBox-Setup.exe: kleiner Installer für andere PCs. Für das .NET Framework 4.x (auf jedem Windows 10/11 vorhanden),
# übersetzt mit dem in Windows mitgelieferten csc.exe (C# 5); enthält dist\SnitchBox.exe.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$setupVersion = Join-Path $B 'SetupVersion.cs'
[IO.File]::WriteAllText($setupVersion, @"
[assembly: System.Reflection.AssemblyVersion("$Version.$Build")]
[assembly: System.Reflection.AssemblyFileVersion("$Version.$Build")]
[assembly: System.Reflection.AssemblyInformationalVersion("$Version (Build $Build)")]
namespace SnitchBoxSetup { internal static class Info { public const string Version = "$Version (Build $Build)"; } }
"@, (New-Object Text.UTF8Encoding($true)))
$setup = Join-Path $dist 'SnitchBox-Setup.exe'
# Sprachen des Installers: nur seine eigenen Texte je Sprache (ohne Python: die vollständigen Tabellen).
$langDir = Join-Path $Root 'src\SnitchBox.Core\Lang'
$setupLang = Join-Path $B 'setup-lang'
if (Test-Path $setupLang) { Remove-Item -Recurse -Force $setupLang }
if ($python) { & $python.Source -I (Join-Path $Root 'scripts\extract_strings.py') --installer-subset $setupLang | Out-Null }
$langSource = if ($python -and (Test-Path $setupLang)) { $setupLang } else { $langDir }
$langResources = Get-ChildItem $langSource -Filter '??.json' | ForEach-Object { "/resource:$($_.FullName),Lang.$($_.Name)" }
& $csc /nologo /noconfig /target:winexe /platform:anycpu /optimize+ /codepage:65001 "/out:$setup" `
    "/win32icon:$(Join-Path $Root 'src\SnitchBox\app.ico')" "/win32manifest:$(Join-Path $Root 'installer\setup.manifest')" `
    "/resource:$(Join-Path $dist 'SnitchBox.exe'),SnitchBox.exe" "/resource:$(Join-Path $dist 'SnitchBoxStart.exe'),SnitchBoxStart.exe" `
    "/resource:$(Join-Path $Root 'src\SnitchBox\app.ico'),app.ico" @langResources `
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Runtime.Serialization.dll /r:System.Xml.dll `
    (Join-Path $Root 'installer\Setup.cs') $setupVersion
if ($LASTEXITCODE -ne 0) { Write-Host 'Installer ließ sich nicht übersetzen'; exit 1 }

Get-ChildItem (Join-Path $dist 'SnitchBox.exe'), (Join-Path $dist 'SnitchBoxStart.exe'), $setup, $sa | Format-Table Name, Length -AutoSize
Write-Host "Erstellt: SnitchBox für Windows $Version (Build $Build) → dist\SnitchBox.exe (braucht .NET 10 Desktop Runtime) mit Starter dist\SnitchBoxStart.exe, dist\SnitchBox-Setup.exe (Installer), dist\SnitchBox-Standalone\ (ohne .NET)"
